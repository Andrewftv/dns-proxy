use std::net::{Ipv4Addr, TcpListener};
use std::io::{prelude::*, Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Local};
use rusqlite::Connection;

use crate::confdb::sqldb_get_local_names;
use crate::confdb::sqldb_get_rejected_names;
use crate::confdb::LocalName;

use crate::{log_error, log_debug, log_info};
use crate::filter::{FilterConfig, FilterUpdateStatus};
use crate::config::LocalConfig;
use crate::filter::FilterRow;

use crate::filter::{BLOCKLIST_FILE_NAME};

struct PostParams {
    name: String,
    value: String
}

impl PostParams {
    pub fn new(name: String, value: String) -> PostParams {
        PostParams
        {
            name: name,
            value: value
        }
    }
}

pub struct UiServer {
    pub running: Arc<AtomicBool>,
    status_code: String,
    response_hdrs: Vec<String>,
    start_time: SystemTime,
    last_filter_update_check: SystemTime,
    show_popup: bool,
    update_status: FilterUpdateStatus
}

impl UiServer {
    const TAG_FILTER_ENTRIES: &str = "{#ENTRIES}";
    const TAG_LISTEN_ADDRESS: &str = "{#LISTEN}";
    const TAG_DNS_ADDR_PORT: &str = "{#DNSSRV}";
    const TAG_LAST_FILTER_UPDATE: &str = "{#UPDATE_DATE}";
    const TAG_DNS_TYPE: &str = "{#USE_DOH}";
    const TAG_REJECTED_NAMES: &str = "{#REJECT_STATISTICS}";
    const TAG_VERSION: &str = "{#VERSION}";
    const TAG_UPTIME: &str = "{#UPTIME}";
    const TAG_TPOOL_STAT: &str = "{#TPOOL_STAT_TABLE}";
    const TAG_FILTER_STATUS: &str = "{#FILTER_STATUS}";
    const TAG_UPDATE_CHECK: &str = "{#UPDATE_CHECK}";
    const TAG_HIDE_POPUP: &str = "{#HIDE_POPUP}";
    const TAG_LOCAL_DNS: &str = "{#LOCAL_DNS_STATUS}";
    const TAG_LOCAL_DOMAIN_NAME: &str = "{#LOCAL_DOMAIN_NAME}";
    const TAG_LOCAL_DNS_NAMES: &str = "{#LOCAL_DNS_NAMES}";
    const MSG_FILTER_UP_TO_DATE: &str = "<strong>Filter is up to date</strong>";
    const MSG_FILTER_UPDATED: &str = "<strong>Filter was updated</strong>";
    const MSG_FILTER_RELOADED: &str = "<strong>Filter was reloaded</strong>";
    const MSG_FILTER_ERROR: &str = "<strong style=\"color:red;\">Download error</strong>";

    pub fn new() -> UiServer {
        UiServer
        {
            running: Arc::new(AtomicBool::new(true)),
            status_code: Default::default(),
            response_hdrs: vec![],
            start_time: SystemTime::now(),
            last_filter_update_check: SystemTime::now(),
            show_popup: false,
            update_status: FilterUpdateStatus::Unchanged
        }
    }

    fn set_update_status(&mut self, status: FilterUpdateStatus) {
        self.update_status = status;
    }

    fn is_updated(&self) -> bool {
        return self.update_status == FilterUpdateStatus::Updated;
    }

    fn is_reloaded(&self) -> bool {
        return self.update_status == FilterUpdateStatus::Reloaded;
    }

    fn is_error(&self) -> bool {
        return self.update_status == FilterUpdateStatus::DownloadError;
    }

    fn get_uptime_sec(&self) -> u64 {
        let now = SystemTime::now();
        let res = now.duration_since(self.start_time);
        if res.is_err() {
            return 0;
        }
        let duration = res.unwrap();

        return duration.as_secs();
    }

    fn get_data_by_tag(&mut self, tag: &str, srv_cfg: &mut LocalConfig) -> String {
        let ret_string: String = match tag {
            UiServer::TAG_FILTER_ENTRIES => {
                let entries = FilterConfig::get_num_entries(srv_cfg.get_db_connection());
                entries.to_string()
            }
            UiServer::TAG_LISTEN_ADDRESS => {
                let listen_addr = srv_cfg.get_bind_addr();
                listen_addr.to_string()
            }
            UiServer::TAG_DNS_ADDR_PORT => {
                let use_doh = srv_cfg.get_use_doh();
                let dns_srv_addr = srv_cfg.get_dns_srv_addr();
                
                if use_doh {
                    dns_srv_addr.ip().to_string() + ":DoH"
                } else {
                    dns_srv_addr.to_string()
                }
            }
            UiServer::TAG_LAST_FILTER_UPDATE => {
                let mut update_str: String = Default::default();
                let res = std::fs::metadata(BLOCKLIST_FILE_NAME);
                if res.is_ok() {
                    let metadata = res.unwrap();
                    let res = metadata.modified();
                    if res.is_ok() {
                        let system_time = res.unwrap();
                        let datetime: DateTime<Local> = system_time.into();
                        update_str = datetime.format("%Y/%m/%d %T").to_string();
                    }
                }
                update_str
            }
            UiServer::TAG_UPDATE_CHECK => {
                let datetime: DateTime<Local> = self.last_filter_update_check.into();
                datetime.format("%Y/%m/%d %T").to_string()
            }
            UiServer::TAG_DNS_TYPE => {
                let use_doh = srv_cfg.get_use_doh();
                if use_doh {
                    "checked".to_string()
                } else {
                    "unchecked".to_string()
                }
            }
            UiServer::TAG_REJECTED_NAMES => {
                let stat_str = Self::prepare_stat_data(srv_cfg.get_db_connection());
                stat_str
            }
            UiServer::TAG_VERSION => {
                LocalConfig::get_version_string()
            }
            UiServer::TAG_UPTIME => {
                let total_secs = self.get_uptime_sec();
                let seconds = total_secs % 60;
                let minutes = (total_secs % 3600) / 60;
                let hours = (total_secs % 86400) / 3600;
                let days = total_secs / 86400;
                format!("{} days {:02}:{:02}:{:02}", days, hours, minutes, seconds)
            }
            UiServer::TAG_TPOOL_STAT => {
                let mut stat_table: String = Default::default();
                let workers = srv_cfg.get_tpool_workers();
                for id in 0..workers {
                    stat_table += "<tr>\n";
                    stat_table += "<td>";
                    stat_table += &id.to_string();
                    stat_table += "</td>\n";
                    stat_table += "<td>";
                    stat_table += &srv_cfg.is_busy(id).to_string();
                    stat_table += "</td>\n";
                    stat_table += "<td>";
                    stat_table += &srv_cfg.get_jobs(id).to_string();
                    stat_table += "</td>\n";
                    stat_table += "</tr>\n";
                }
                stat_table
            }
            UiServer::TAG_HIDE_POPUP => {
                let mut hide_popup: String = Default::default();
                if self.show_popup == false {
                    hide_popup = "hidden".to_string();
                } else {
                    self.show_popup = false;
                }
                hide_popup
            }
            UiServer::TAG_FILTER_STATUS => {
                //let mut filter = mfilter.lock().unwrap();
                let mut status_str = UiServer::MSG_FILTER_UP_TO_DATE;
                if self.is_updated() {
                    status_str = UiServer::MSG_FILTER_UPDATED;
                } else if self.is_reloaded() {
                    status_str = UiServer::MSG_FILTER_RELOADED;
                } else if self.is_error() {
                    status_str = UiServer::MSG_FILTER_ERROR;
                }
                self.set_update_status(FilterUpdateStatus::Unchanged);
                //drop(filter);

                status_str.to_string()
            }
            UiServer::TAG_LOCAL_DNS => {
                if srv_cfg.get_local_dns_enable() {
                    "checked".to_string()
                } else {
                    "unchecked".to_string()
                }
            }
            UiServer::TAG_LOCAL_DNS_NAMES => {
                let names = Self::prepare_local_dns_table(srv_cfg.get_db_connection());
                names
            }
            UiServer::TAG_LOCAL_DOMAIN_NAME => {
                srv_cfg.get_local_domain_name()
            }
            _=> Default::default(),
        };

        return ret_string;
    }

    fn prepare_stat_data(conn: &Connection) -> String {
        let mut ret_str: String = Default::default();
        let res = sqldb_get_rejected_names(conn);
        if res.is_err() {
            return ret_str;
        }
        let filter_rows: Vec<FilterRow> = res.unwrap(); 
        /* Table contant */
        for filter_row in filter_rows.iter() {
            ret_str += "<tr><td><label class=\"switch\">\n";
            ret_str += "<input type=\"checkbox\" id=\"enable_name_id\" name=\"";
            ret_str += &filter_row.name;
            ret_str += "\" ";
            if filter_row.enable {
                ret_str += "checked";
            } else {
                ret_str += "unchecked";
            }
            ret_str += ">\n";
            ret_str += "<span class=\"slider round\"></span></label>";
            ret_str += "</td>\n";
            ret_str += "<td>\n";
            ret_str += if filter_row.filter_type == 0 {
                "Global"
            } else if filter_row.filter_type == 1 {
                "Local"
            } else {
                ""
            };
            ret_str += "</td>\n<td>";
            ret_str += &filter_row.name;
            ret_str += "</td>\n<td>";
            ret_str += &filter_row.requests.to_string();
            ret_str += "</td>\n";
            ret_str += "</tr>\n";
        }
        
        return ret_str;
    }

    fn prepare_local_dns_table(conn: &Connection) -> String {
        let mut ret_str: String = Default::default();

        let res = sqldb_get_local_names(conn);
        if res.is_err() {
            log_error!("Unable to get local names. Error: {}\n", res.err().unwrap());
            return ret_str;
        }
        let names: Vec<LocalName> = res.unwrap();

        for local_name in names.iter() {
            ret_str += "<tr><td>";
            ret_str += &local_name.address;
            ret_str += "</td><td>";
            ret_str += &local_name.name;
            ret_str += "</td><td>";
            ret_str += "<div style=\"display: flex; justify-content: flex-end; width: 100%; background-color: inherit;\">";
            ret_str += "<button type=\"button\" class=\"imgbutton\" name=\"";
            ret_str += &local_name.name;
            ret_str += "\" onclick=\"handle_edit_name(this)\">";
            ret_str += "<img src=\"images/edit_button.png\" alt=\"Edit\" width=\"30\" height=\"30\"></button>";

            ret_str += "<button type=\"button\" class=\"imgbutton\" name=\"";
            ret_str += &local_name.name;
            ret_str += "\" onclick=\"handle_delete_name(this)\">";
            ret_str += "<img src=\"images/delete_button.png\" alt=\"Delete\" width=\"30\" height=\"30\"></button>";
            ret_str += "</div>";
            ret_str +="</td></tr>";
        }

        return ret_str;
    }

    fn replace_tag(&mut self, tag: &String, contents: &String, srv_cfg: &mut LocalConfig) -> String {
        let mut new_contents: String;
        let opt = contents.find(tag);
        if opt.is_some() {
            let offset = opt.unwrap();
            new_contents = contents[0..offset].to_string();
            new_contents += &self.get_data_by_tag(tag, srv_cfg);
            new_contents += &contents[offset + tag.len()..contents.len()].to_string();
        } else {
            new_contents = contents.to_string();
        }
        return new_contents;
    }

    fn find_tag(contents: &String) -> Option<String> {
        let opt = contents.find("{#");
        if opt.is_some() {
            let start_pos = opt.unwrap();
            let opt = contents[start_pos..contents.len()].find("}");
            if opt.is_some() {
                let end_pos = opt.unwrap();
                let tag = contents[start_pos..start_pos + end_pos + 1].to_string();

                return Some(tag);
            }
        }

        return None;
    }

    fn read_image(filename: &str) -> Option<Vec<u8>> {
        let res = std::fs::read(filename);
        if res.is_err() {
            let error_kind: ErrorKind = res.as_ref().err().unwrap().kind();
            log_error!("error = {}\n", error_kind);
            return None;
        }
        let bytes = res.unwrap();

        return Some(bytes);
    }

    fn prepare_bin_context(&mut self, length: usize) -> Vec<u8> {
        let mut response: String;
        let contents_len_hdr = format!("Content-Length: {}", length);
        self.set_response_hdr(&contents_len_hdr);
        response = self.get_status_code().to_string();
        response += "\r\n";
        for hdr in self.response_hdrs.iter() {
            response += hdr;
            response += "\r\n";
        }
        response += "\r\n";

        return response.into_bytes();
    }

    fn prepare_error_content(err: u32) -> Vec<u8> {
        let mut response: String;
        let mut contents: String = "<html><head><title>Error</title></head><body><p>Something went wrong</p><p>Error: ".to_string();
        contents += &err.to_string();
        contents += "</p></body></html>";

        response = "HTTP/1.1 ".to_string();
        response += &err.to_string();
        response += " Internal server error\r\n";
        response += "Content-Length: ";
        response += &contents.len().to_string();
        response += "\r\n\r\n";
        response += &contents;

        return response.into_bytes();
    }

    fn prepare_content(&mut self, filename: Option<&str>, post_process: bool, mcfg: &Arc<Mutex<LocalConfig>>) -> Result<Vec<u8>, u32> {

        let mut response: String;
        let mut contents: String = Default::default();
        if filename.is_some() {
            let name: &str = filename.unwrap();
            let cont_res = std::fs::read_to_string(name);
            if cont_res.is_err() {
                log_error!("Unable to open {}\n", name);
                return Err(500);
            }

            let mut contents_temp = cont_res.unwrap();
            if post_process {
                loop {
                    let tag_opt = UiServer::find_tag(&contents_temp);
                    if tag_opt.is_none() {
                        break;
                    }
                    let tag = tag_opt.unwrap();
                    let mut cfg = mcfg.lock().unwrap();
                    contents_temp = self.replace_tag(&tag, &contents_temp, &mut cfg);
                    drop(cfg);
                }
            }
            contents = contents_temp;
            let length = contents.len();
            let contents_len_hdr = format!("Content-Length: {}", length);
            self.set_response_hdr(&contents_len_hdr);
        }
        if self.status_code.is_empty() {
            log_error!("HTTP status code not set\n");
        }
        response = self.get_status_code().to_string();
        response += "\r\n";
        for hdr in self.response_hdrs.iter() {
            response += hdr;
            response += "\r\n";
        }
        response += "\r\n";
        response += &contents;

        return Ok(response.into_bytes());
    } 

    fn get_request_tags(request: &String) -> Vec<String> {
        let mut tags: Vec<String> = vec![];

        for line in request.lines() {
            if line.is_empty() {
                break;
            }
            tags.push(line.to_string());
        }

        return tags;
    }

    fn get_post_data(request: &String, mut buff: &mut [u8]) -> Result<usize, std::io::Error> {
        let opt = request.find("\r\n\r\n");
        if opt.is_none() {
            return Err(Error::new(ErrorKind::NotFound, "Post data anavailable"));
        }
        let mut offset = opt.unwrap();
        offset += 4;
        let bytes: &[u8] = &request[offset..].as_bytes();
        let _ = buff.write_all(bytes);

        return Ok(bytes.len());
    }

    fn get_status_code(&self) -> &String {
        return &self.status_code;
    }

    fn set_status_code(&mut self, status: &str) {
        self.status_code = status.to_string();
    }

    fn set_response_hdr(&mut self, value: &str) {
        self.response_hdrs.push(value.to_string());
    }

    fn clear_response_hdrs(&mut self) {
        self.response_hdrs.clear();
    }

    fn parse_post_params(data: &Vec<u8>) -> Option<Vec<PostParams>> {
        let mut start_offset = 0;
        let mut end_offset = 0;
        let mut opt;
        let mut ret_vec: Vec<PostParams> = Vec::new();
        let data_str: String = String::from_utf8(data.to_vec()).unwrap();
        while end_offset < data_str.len() {
            opt = data_str[start_offset..data_str.len()].find('&');
            if opt.is_some() {
                end_offset = opt.unwrap();
            } else {
                end_offset = data_str.len();
            }
            let name_value = &data_str[start_offset..end_offset];
            let opt = name_value.find('=');
            if opt.is_none() {
                continue;
            }
            let eq_offset = opt.unwrap();
            let param = PostParams::new(name_value[0..eq_offset].to_string(),
                name_value[eq_offset + 1..name_value.len()].to_string());
            ret_vec.push(param);
            start_offset = end_offset + 1;
        }
        if ret_vec.is_empty() {
            return None;
        }

        return Some(ret_vec);
    }

    fn set_post_param(params: &Vec<PostParams>, mcfg: &Arc<Mutex<LocalConfig>>) -> bool {
        for param in params.iter() {
            log_debug!("PARAM: {} VALUE: {}\n", param.name, param.value);

            match &param.name[..] {
                "dns_ipaddr" => {
                    let res = param.value.parse::<std::net::Ipv4Addr>();
                    if res.is_err() {
                        log_error!("Error parsing IP address string\n");
                        return false;
                    }
                    let addr: std::net::SocketAddr = std::net::SocketAddr::new(std::net::IpAddr::V4(res.unwrap()), 53);
                    let mut cfg = mcfg.lock().unwrap();
                    cfg.set_dns_srv_addr(addr);
                    drop(cfg);
                }
                "use_doh" => {
                    let res = param.value.parse::<bool>();
                    if res.is_err() {
                        log_error!("Error parsing use_doh\n");
                        return false;
                    }
                    let mut cfg = mcfg.lock().unwrap();
                    cfg.set_use_doh(res.unwrap());
                    drop(cfg);
                }
                "local_dns_enable" => {
                    let res = param.value.parse::<bool>();
                    if res.is_err() {
                        log_error!("Error parsing use local DNS\n");
                        return false;
                    }
                    let mut cfg = mcfg.lock().unwrap();
                    cfg.set_local_dns_enable(res.unwrap());
                    drop(cfg);
                }
                "domain_name" => {
                    if param.value.is_empty() {
                        log_error!("Empty domain name\n");
                        return false;
                    }
                    let mut cfg = mcfg.lock().unwrap();
                    cfg.set_local_domain_name(&param.value);
                    drop(cfg);
                }
                _ => {
                    log_error!("Unexpected parameter: {}\n", param.name);
                    return false;
                }
            };
        }

        return true;
    }

    fn set_all_disable(mcfg: &Arc<Mutex<LocalConfig>>) -> bool {
        let mut config = mcfg.lock().unwrap();
        FilterConfig::clear_enable(config.get_db_connection());
        drop(config);

        return true;
    }

    fn set_names_enable(params: &Vec<PostParams>, mcfg: &Arc<Mutex<LocalConfig>>) -> bool {
        let mut config = mcfg.lock().unwrap();
        for param in params.iter() {
            let mut enable = false;
            log_debug!("PARAM: {} VALUE: {}\n", param.name, param.value);
            if param.value == "on" {
                enable = true;
            } else if param.value == "off" {
                enable = false;
            }
            FilterConfig::set_enable(config.get_db_connection(), &param.name, enable);
        }
        drop(config);

        return true;
    }

    fn get_requested_file(tag: String) -> String {
        let mut name: String = Default::default();
        let rc = tag.find(' ');
        if rc.is_none() {
            return name;
        }
        let start = rc.unwrap() + 1;
        let rc = tag[start..].find(' ');
        if rc.is_none() {
            return name;
        }
        let end = rc.unwrap() + start;
        name = tag[start..end].to_string();
        if name == "/" {
            name = "html/start_page.html".to_string();
        } else {
            name = "html".to_string() + &name;
        }

        return name;
    }

    fn get_post_params(&self, request: &String) -> Option<Vec<PostParams>> {
        let mut data = Vec::with_capacity(1024);
        data.resize(1024, 0); 
        let res = UiServer::get_post_data(&request, &mut data);
        if res.is_ok() {
            data.truncate(res.unwrap());
            log_debug!("DATA: {}\n", String::from_utf8(data.to_vec()).unwrap());
            let opt: Option<Vec<PostParams>> = UiServer::parse_post_params(&data);
            return opt;
        }
        return None;
    }

    pub fn start_gui_server(&mut self, mcfg: &Arc<Mutex<LocalConfig>>) -> Result<(), std::io::Error> {
        // DNS server already srarted. Check blocklist.txt for update
        self.last_filter_update_check = SystemTime::now();
        let status = FilterConfig::check_update();
        if status == FilterUpdateStatus::Updated {
            let mut config = mcfg.lock().unwrap();
            let _ = FilterConfig::reload_filter(config.get_db_connection());
            drop(config);
        }
        // Start HTTP server
        let res = TcpListener::bind("0.0.0.0:8080");
        if res.is_err() {
            log_error!("Unable to bind TCP socket\n");
            return Err(res.err().unwrap());
        }
        let listener = res.unwrap();
        let _ = listener.set_nonblocking(true);
        for stream in listener.incoming() {   
            if !self.running.load(Ordering::Relaxed) {
                log_info!("UI server stoped by user\n");
                return Err(Error::new(std::io::ErrorKind::Other, "Stoped by user"));
            }
            if stream.is_err() {
                let err_kind = stream.as_ref().err().unwrap().kind();
                if err_kind == ErrorKind::WouldBlock {
                    let now = SystemTime::now();
                    let res = now.duration_since(self.last_filter_update_check);
                    if res.is_err() {
                        continue;
                    }
                    let durution = res.unwrap();
                    /* Check one time per day */
                    if durution.as_secs() >= Duration::from_hours(24).as_secs() {
                        log_info!("Check filter update\n");
                        self.last_filter_update_check = SystemTime::now();
                        let status = FilterConfig::check_update();
                        if status == FilterUpdateStatus::Updated {
                            let mut config = mcfg.lock().unwrap();
                            let _ = FilterConfig::reload_filter(config.get_db_connection());
                            drop(config);
                        }
                    } else {
                        thread::sleep(Duration::from_millis(100));
                    }
                    continue;
                }
                log_error!("Tcp stream failed\n");
                return Err(stream.err().unwrap());
            }
            let mut stream = stream.unwrap();
            let _ = stream.set_nonblocking(true); /* Fix strange behaviour of linux chromium */
            // Read request contents
            let mut buff = Vec::with_capacity(1024);
            buff.resize(1024, 0);
            let res = stream.read(&mut buff);
            if res.is_err() {
                let error = res.err().unwrap();
                if error.kind() == ErrorKind::WouldBlock {
                    continue;
                }
                log_error!("Read TCP stream failed\n");
                return Err(error);
            }
            let size = res.unwrap();
            buff.truncate(size);
            // TODO: Validation
            log_debug!("Peer address: {}\n", stream.peer_addr().unwrap());
            let request = String::from_utf8(buff.to_vec()).unwrap();
            drop(buff);
            // Get request tags
            let tags = UiServer::get_request_tags(&request);
            if tags.len() == 0 {
                continue;
            }
            log_debug!("Request for: {}\n", tags[0]);

            let response: Vec<u8> = match &tags[0][..] {
                "GET / HTTP/1.1" |
                "GET /tpool_stats.html HTTP/1.1" |
                "GET /statistics.html HTTP/1.1" |
                "GET /about.html HTTP/1.1" |
                "GET /change_ip.html HTTP/1.1" |
                "GET /local_dns.html HTTP/1.1" |
                "GET /classes.css HTTP/1.1" => {
                    let name = UiServer::get_requested_file(tags[0][..].to_string());
                    self.set_status_code("HTTP/1.1 200 OK");
                    let opt = name.rfind('.');
                    if opt.is_some() {
                        let pos = opt.unwrap() + 1;
                        if &name[pos..] == "css" {
                            self.set_response_hdr("Content-Type: text/css");
                        } else if &name[pos..] == "html" {
                            self.set_response_hdr("Content-Type: text/html");
                        }
                    }
                    let rc = self.prepare_content(Some(&name), true, mcfg);
                    if rc.is_ok() {
                        rc.unwrap()
                    } else {
                        UiServer::prepare_error_content(rc.unwrap_err())
                    }
                }
                "GET /favicon.ico HTTP/1.1" |
                "GET /images/delete_button.png HTTP/1.1" |
                "GET /images/add_button.png HTTP/1.1" |
                "GET /images/edit_button.png HTTP/1.1" |
                "GET /images/banner.png HTTP/1.1" => {
                    let name = UiServer::get_requested_file(tags[0][..].to_string());
                    let res = UiServer::read_image(&name);
                    if res.is_some() {
                        let bin_data = res.unwrap();
                        self.set_status_code("HTTP/1.1 200 OK");
                        self.set_response_hdr("Cache-Control: max-age=604800");
                        self.set_response_hdr("Content-Type: image/png");
                        let mut response = self.prepare_bin_context(bin_data.len());
                        response.extend(bin_data);
                        response
                    } else {
                        "".to_string().into_bytes()
                    }
                }
                "POST /delete_dns_name HTTP/1.1" => {
                    let opt = self.get_post_params(&request);
                    if opt.is_some() {
                        let params = opt.unwrap();
                        if params.len() == 1 && params[0].name == "delete_dns_name" {
                            let mut cfg = mcfg.lock().unwrap();
                            FilterConfig::remove_local_name(cfg.get_db_connection(), &params[0].value);
                            drop(cfg);
                        }
                    }
                    self.set_status_code("HTTP/1.1 200 OK");
                    self.prepare_content(None, false, mcfg).unwrap()
                }
                "POST /new_dns_name HTTP/1.1" => {
                    let opt = self.get_post_params(&request);
                    if opt.is_some() {
                        let params = opt.unwrap();
                        if params.len() == 2 && params[0].name == "local_dns_name" && params[1].name == "local_ip_addr" {
                            let res = params[1].value.parse::<Ipv4Addr>();
                            if res.is_ok() {
                                let mut cfg = mcfg.lock().unwrap();
                                FilterConfig::set_local_name(cfg.get_db_connection(), &params[0].value, res.unwrap());
                                drop(cfg);
                            }
                        }
                    }
                    self.set_status_code("HTTP/1.1 200 OK");
                    self.prepare_content(None, false, mcfg).unwrap()
                }
                "POST /set_domain_name HTTP/1.1" |
                "POST /local_dns HTTP/1.1" => {
                    let opt = self.get_post_params(&request);
                    if opt.is_some() {
                        UiServer::set_post_param(&opt.unwrap(), mcfg);
                    }
                    self.set_status_code("HTTP/1.1 200 OK");
                    self.prepare_content(None, false, mcfg).unwrap()
                }
                "POST /dns_change_ip HTTP/1.1" => {
                    let opt = self.get_post_params(&request);
                    if opt.is_some() {
                        UiServer::set_post_param(&opt.unwrap(), mcfg);
                    }
                    self.set_status_code("HTTP/1.1 301 Redirect");
                    self.set_response_hdr("Cache-Control: no-cache");
                    self.set_response_hdr("Location: /");
                    self.prepare_content(None, false, mcfg).unwrap()
                }
                "POST /reload_filter HTTP/1.1" => {
                    //let mut filter = mfilter.lock().unwrap();
                    let mut config = mcfg.lock().unwrap();
                    let _ = FilterConfig::reload_filter(config.get_db_connection());
                    drop(config);
                    self.set_update_status(FilterUpdateStatus::Reloaded);
                    //drop(filter);
                    self.show_popup = true;
                    self.set_status_code("HTTP/1.1 301 Redirect");
                    self.set_response_hdr("Cache-Control: no-cache");
                    self.set_response_hdr("Location: /");
                    self.prepare_content(None, false, mcfg).unwrap()
                }
                "POST /update_filter HTTP/1.1" => {
                    self.last_filter_update_check = SystemTime::now();
                    let status = FilterConfig::check_update();
                    //let mut filter = mfilter.lock().unwrap();
                    if status == FilterUpdateStatus::Updated {
                        let mut config = mcfg.lock().unwrap();
                        let _ = FilterConfig::reload_filter(config.get_db_connection());
                        drop(config);
                        self.set_update_status(status);
                    } else if status == FilterUpdateStatus::DownloadError {
                        self.set_update_status(status);
                    }
                    //drop(filter);
                    self.show_popup = true;
                    self.set_status_code("HTTP/1.1 301 Redirect");
                    self.set_response_hdr("Cache-Control: no-cache");
                    self.set_response_hdr("Location: /");
                    self.prepare_content(None, false, mcfg).unwrap()
                }
                "POST /enable_names HTTP/1.1" => {
                    let mut data = Vec::with_capacity(1024 * 10);
                    data.resize(1024 * 10, 0); 
                    let res = UiServer::get_post_data(&request, &mut data);
                    if res.is_ok() {
                        data.truncate(res.unwrap());
                        let opt = UiServer::parse_post_params(&data);
                        if opt.is_some() {
                            UiServer::set_names_enable(&opt.unwrap(), mcfg);
                        } else {
                            UiServer::set_all_disable(mcfg);
                        }
                    }
                    self.set_status_code("HTTP/1.1 301 Redirect");
                    self.set_response_hdr("Cache-Control: no-cache");
                    self.set_response_hdr("Location: /statistics.html");
                    self.prepare_content(None, false, mcfg).unwrap()
                }
                _ => {
                    self.set_status_code("HTTP/1.1 404 NOT FOUND");
                    let rc = self.prepare_content(Some("html/404.html"), false, mcfg) ;
                    if rc.is_ok() {
                        rc.unwrap()
                    } else {
                        UiServer::prepare_error_content(rc.unwrap_err())
                    }
                }
            };
            self.status_code.clear();
            self.clear_response_hdrs();
            let mut sent: usize = 0;
            while sent < response.len() {
                let res = stream.write(&response[sent..]);
                if res.is_err() {
                    let error = res.err().unwrap();
                    if error.kind() == ErrorKind::WouldBlock {
                        thread::sleep(Duration::from_millis(10)); // Use epool
                        continue;
                    }
                    log_error!("Send failed\n");
                    break;
                }
                sent += res.unwrap();
            }
        }

        Ok(())
    }
}
