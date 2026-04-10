use std::net::TcpListener;
use std::io::{prelude::*, Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Local};

use crate::{log_error, log_debug, log_info};
use crate::filter::{FilterConfig, FilterUpdateStatus};
use crate::config::LocalConfig;

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
    start_time: SystemTime
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

    pub fn new() -> UiServer {
        UiServer
        {
            running: Arc::new(AtomicBool::new(true)),
            status_code: Default::default(),
            response_hdrs: vec![],
            start_time: SystemTime::now()
        }
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

    fn get_data_by_tag(&self, tag: &str, mfilter: &Arc<Mutex<FilterConfig>>, srv_cfg: &LocalConfig) -> String {
        let ret_string: String = match tag {
            UiServer::TAG_FILTER_ENTRIES => {
                let filter = mfilter.lock().unwrap();
                let entries = filter.get_num_entries();
                drop(filter);
                entries.to_string()
            }
            UiServer::TAG_LISTEN_ADDRESS => {
                let listen_addr = srv_cfg.get_bind_addr();
                listen_addr.to_string()
            }
            UiServer::TAG_DNS_ADDR_PORT => {
                let use_doh = srv_cfg.get_use_doh();
                let dns_srv_addr = srv_cfg.get_dns_srv_addr();
                
                let addr_port_str = if use_doh {
                    dns_srv_addr.ip().to_string() + ":DNS over HTTPS"
                } else {
                    dns_srv_addr.to_string()    
                };
                addr_port_str
            }
            UiServer::TAG_LAST_FILTER_UPDATE => {
                let mut update_str: String = Default::default();
                let res = std::fs::metadata("blocklist.txt");
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
            UiServer::TAG_DNS_TYPE => {
                let use_doh = srv_cfg.get_use_doh();
                let use_doh_str = if use_doh {
                    "checked".to_string()
                } else {
                    "unchecked".to_string()
                };
                use_doh_str
            }
            UiServer::TAG_REJECTED_NAMES => {
                let filter = mfilter.lock().unwrap();
                let stat_str = filter.prepare_stat_data();
                drop(filter);
                stat_str
            }
            UiServer::TAG_VERSION => {
                let ver_str: String = "1.1".to_string();
                ver_str
            }
            UiServer::TAG_UPTIME => {
                let total_secs = self.get_uptime_sec();
                let seconds = total_secs % 60;
                let minutes = (total_secs % 3600) / 60;
                let hours = (total_secs % 86400) / 3600;
                let days = total_secs / 86400;
                let uptime_str = format!("{} days {:02}:{:02}:{:02}", days, hours, minutes, seconds);

                uptime_str
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
            UiServer::TAG_FILTER_STATUS => {
                let mut filter = mfilter.lock().unwrap();
                let mut status_str = "<strong>Filter up to date</strong>";
                if filter.is_updated() {
                    status_str = "<strong>Filter updated</strong>";
                }
                filter.set_update_status(FilterUpdateStatus::Unchanged);
                drop(filter);

                status_str.to_string()
            }
            _=> Default::default(),
        };

        return ret_string;
    }

    fn replace_tag(&self, tag: &String, contents: &String, mfilter: &Arc<Mutex<FilterConfig>>, srv_cfg: &LocalConfig) -> String {
        let mut new_contents: String;
        let opt = contents.find(tag);
        if opt.is_some() {
            let offset = opt.unwrap();
            new_contents = contents[0..offset].to_string();
            new_contents += &self.get_data_by_tag(tag, mfilter, srv_cfg);
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

    fn prepare_content(&mut self, filename: Option<&str>, post_process: bool, mfilter: &Arc<Mutex<FilterConfig>>,
        mcfg: &Arc<Mutex<LocalConfig>>) -> Result<Vec<u8>, u32> {

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
                    let cfg = mcfg.lock().unwrap();
                    contents_temp = self.replace_tag(&tag, &contents_temp, mfilter, &cfg);
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
                _ => {
                    log_error!("Unexpected parameter: {}\n", param.name);
                }
            };
        }

        let cfg = mcfg.lock().unwrap();
        cfg.write_config();
        drop(cfg);

        return true;
    }

    fn set_all_disable(mfilter: &Arc<Mutex<FilterConfig>>) -> bool {
        let mut filter = mfilter.lock().unwrap();
        filter.clear_enable();
        drop(filter);

        return true;
    }

    fn set_names_enable(params: &Vec<PostParams>, mfilter: &Arc<Mutex<FilterConfig>>) -> bool {
        let mut filter = mfilter.lock().unwrap();
        filter.clear_enable();
        for param in params.iter() {
            log_debug!("PARAM: {} VALUE: {}\n", param.name, param.value);

            filter.set_enable(&param.name);
        }
        drop(filter);

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

    pub fn start_gui_server(&mut self, mfilter: &Arc<Mutex<FilterConfig>>, mcfg: &Arc<Mutex<LocalConfig>>) -> Result<(), std::io::Error> {
        // DNS server already srarted. Check blocklist.txt for update
        let res = FilterConfig::check_update();
        if res.is_ok() && res.unwrap() == FilterUpdateStatus::Updated {
            let mut filter = mfilter.lock().unwrap();
            let _ = filter.reload_filter();
            drop(filter);
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
                    thread::sleep(Duration::from_millis(100));
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
                "GET /update_filter_result.html HTTP/1.1" |
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
                    let rc = self.prepare_content(Some(&name), true, mfilter, mcfg);
                    if rc.is_ok() {
                        rc.unwrap()
                    } else {
                        UiServer::prepare_error_content(rc.unwrap_err())
                    }
                }
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
                    }
                    else {
                        "".to_string().into_bytes()
                    }
                }
                "POST /dns_change_ip HTTP/1.1" => {
                    let mut data = Vec::with_capacity(1024);
                    data.resize(1024, 0); 
                    let res = UiServer::get_post_data(&request, &mut data);
                    if res.is_ok() {
                        data.truncate(res.unwrap());
                        log_debug!("DATA: {}\n", String::from_utf8(data.to_vec()).unwrap());
                        let opt = UiServer::parse_post_params(&data);
                        if opt.is_some() {
                            UiServer::set_post_param(&opt.unwrap(), mcfg);
                        }
                    }
                    self.set_status_code("HTTP/1.1 301 Redirect");
                    self.set_response_hdr("Cache-Control: no-cache");
                    self.set_response_hdr("Location: /");
                    self.prepare_content(None, false, mfilter, mcfg).unwrap()
                }
                "POST /reload_filter HTTP/1.1" => {
                    let mut filter = mfilter.lock().unwrap();
                    let _ = filter.reload_filter();
                    drop(filter);
                    self.set_status_code("HTTP/1.1 301 Redirect");
                    self.set_response_hdr("Cache-Control: no-cache");
                    self.set_response_hdr("Location: /");
                    self.prepare_content(None, false, mfilter, mcfg).unwrap()
                }
                "POST /update_filter HTTP/1.1" => {
                    let res = FilterConfig::check_update();
                    if res.is_ok() && res.unwrap() == FilterUpdateStatus::Updated {
                        let mut filter = mfilter.lock().unwrap();
                        let _ = filter.reload_filter();
                        filter.set_update_status(FilterUpdateStatus::Updated);
                        drop(filter);
                    }
                    self.set_status_code("HTTP/1.1 301 Redirect");
                    self.set_response_hdr("Cache-Control: no-cache");
                    self.set_response_hdr("Location: /update_filter_result.html");
                    self.prepare_content(None, false, mfilter, mcfg).unwrap()
                }
                "POST /enable_names HTTP/1.1" => {
                    let mut data = Vec::with_capacity(1024 * 10);
                    data.resize(1024 * 10, 0); 
                    let res = UiServer::get_post_data(&request, &mut data);
                    if res.is_ok() {
                        data.truncate(res.unwrap());
                        let opt = UiServer::parse_post_params(&data);
                        if opt.is_some() {
                            UiServer::set_names_enable(&opt.unwrap(), mfilter);
                        } else {
                            UiServer::set_all_disable(mfilter);
                        }
                    }
                    self.set_status_code("HTTP/1.1 301 Redirect");
                    self.set_response_hdr("Cache-Control: no-cache");
                    self.set_response_hdr("Location: /statistics.html");
                    self.prepare_content(None, false, mfilter, mcfg).unwrap()
                }
                _ => {
                    self.set_status_code("HTTP/1.1 404 NOT FOUND");
                    let rc = self.prepare_content(Some("html/404.html"), false, mfilter, mcfg) ;
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
