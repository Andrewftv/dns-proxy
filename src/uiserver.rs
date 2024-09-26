use std::net::TcpListener;
use std::io::{prelude::*, Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use chrono::{DateTime, Local};

use crate::{log_error, log_debug, log_info};
use crate::filter::{FilterConfig, FilterUpdateStatus};

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
    response_hdrs: Vec<String>
}

impl UiServer {
    pub fn new() -> UiServer {
        UiServer
        {
            running: Arc::new(AtomicBool::new(true)),
            response_hdrs: vec![]
        }
    }

    fn get_data_by_tag(tag: &str, filter_prot: &Arc<Mutex<FilterConfig>>) -> String {
        let ret_string: String = match tag {
            "{#ENTRIES}" => {
                let filter = filter_prot.lock().unwrap();
                let entries = filter.get_num_entries();
                drop(filter);
                entries.to_string()
            }
            "{#LISTEN}" => {
                let filter = filter_prot.lock().unwrap();
                let listen_addr = filter.get_bind_addr();
                drop(filter);
                listen_addr.to_string()
            }
            "{#DNSSRV}" => {
                let filter = filter_prot.lock().unwrap();
                let use_doh = filter.get_use_doh();
                let dns_srv_addr = filter.get_dns_srv_addr();
                drop(filter);
                
                let addr_port_str = if use_doh {
                    dns_srv_addr.ip().to_string() + ":DNS over HTTPS"
                } else {
                    dns_srv_addr.to_string()    
                };
                addr_port_str
            }
            "{#UPDATE_DATE}" => {
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
            "{#USE_DOH}" => {
                let filter = filter_prot.lock().unwrap();
                let use_doh = filter.get_use_doh();
                drop(filter);
                let use_doh_str = if use_doh {
                    "checked".to_string()
                } else {
                    "unchecked".to_string()
                };
                use_doh_str
            }
            "{#REJECT_STATISTICS}" => {
                let filter = filter_prot.lock().unwrap();
                let stat_str = filter.prepare_stat_data();
                drop(filter);
                stat_str
            }
            _=> Default::default(),
        };

        return ret_string;
    }

    fn replace_tag(tag: &String, contents: &String, filter_prot: &Arc<Mutex<FilterConfig>>) -> String {
        let mut new_contents: String;
        let opt = contents.find(tag);
        if opt.is_some() {
            let offset = opt.unwrap();
            new_contents = contents[0..offset].to_string();
            new_contents += &UiServer::get_data_by_tag(tag, filter_prot);
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

    fn prepare_content(&mut self, filename: Option<String>, post_process: bool,
        filter_prot: &Arc<Mutex<FilterConfig>>) -> String {
            
        let mut response: String = Default::default();
        let mut contents: String = Default::default();
        if filename.is_some() {
            let name: &String = &filename.unwrap();
            let cont_res = std::fs::read_to_string(name);
            if cont_res.is_err() {
                log_error!("Unable to open {}\n", name);
                return response;
            }

            let mut contents_temp = cont_res.unwrap();
            if post_process {
                loop {
                    let tag_opt = UiServer::find_tag(&contents_temp);
                    if tag_opt.is_none() {
                        break;
                    }
                    let tag = tag_opt.unwrap();
                    contents_temp = UiServer::replace_tag(&tag, &contents_temp, filter_prot);
                }
            }
            contents = contents_temp;
            let length = contents.len();
            let contents_len_hdr = format!("Content-Length: {}", length);
            self.set_response_hdr(contents_len_hdr);
        }

        for hdr in self.response_hdrs.iter() {
            response += hdr;
            response += "\r\n";
        }
        response += "\r\n";
        response += &contents;

        return response;
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

    fn set_response_hdr(&mut self, value: String) {
        self.response_hdrs.push(value);
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

    fn set_post_param(params: &Vec<PostParams>, filter_prot: &Arc<Mutex<FilterConfig>>) -> bool {
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
                    let mut filter = filter_prot.lock().unwrap();
                    filter.set_dns_srv_addr(addr);
                    drop(filter);
                }
                "use_doh" => {
                    let res = param.value.parse::<bool>();
                    if res.is_err() {
                        log_error!("Error parsing use_doh\n");
                        return false;
                    }
                    let mut filter = filter_prot.lock().unwrap();
                    filter.set_use_doh(res.unwrap());
                    drop(filter);
                }
                _ => {
                    log_error!("Unexpected parameter: {}\n", param.name);
                }
            };
        }

        return true;
    }

    pub fn start_gui_server(&mut self, filter_prot: &Arc<Mutex<FilterConfig>>) -> Result<(), std::io::Error> {
        let res = TcpListener::bind("127.0.0.1:8080");
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
            let _ = stream.set_nonblocking(true);
            // Read request contents
            let mut buff = Vec::with_capacity(1024);
            buff.resize(1024, 0);
            let res = stream.read(&mut buff);
            if res.is_err() {
                continue;
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

            let response = match &tags[0][..] {
                "GET / HTTP/1.1" => {
                    self.set_response_hdr("HTTP/1.1 200 OK".to_string());
                    self.prepare_content(Some("html/start_page.html".to_string()), true, filter_prot)
                }
                "GET /change_ip.html HTTP/1.1" => {
                    self.set_response_hdr("HTTP/1.1 200 OK".to_string());
                    self.prepare_content(Some("html/change_ip.html".to_string()), true, filter_prot)
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
                            UiServer::set_post_param(&opt.unwrap(), filter_prot);
                        }
                    }
                    self.set_response_hdr("HTTP/1.1 301 Redirect".to_string());
                    self.set_response_hdr("Location: /".to_string());
                    self.prepare_content(None, false, filter_prot)
                }
                "GET /statistics.html HTTP/1.1" => {
                    self.set_response_hdr("HTTP/1.1 200 OK".to_string());
                    self.prepare_content(Some("html/statistics.html".to_string()), true, filter_prot)
                }
                "GET /reload_filter HTTP/1.1" => {
                    let mut filter = filter_prot.lock().unwrap();
                    let _ = filter.reload_filter();
                    drop(filter);
                    self.set_response_hdr("HTTP/1.1 301 Redirect".to_string());
                    self.set_response_hdr("Location: /".to_string());
                    self.prepare_content(None, false, filter_prot)
                }
                "GET /update_filter HTTP/1.1" => {
                    let mut filter = filter_prot.lock().unwrap();
                    let res = filter.check_update();
                    if res.is_ok() && res.unwrap() == FilterUpdateStatus::Updated {
                        let _ = filter.reload_filter();
                    }
                    drop(filter);
                    self.set_response_hdr("HTTP/1.1 301 Redirect".to_string());
                    self.set_response_hdr("Location: /".to_string());
                    self.prepare_content(None, false, filter_prot)
                }
                _ => {
                    self.set_response_hdr("HTTP/1.1 404 NOT FOUND".to_string());
                    self.prepare_content(Some("html/404.html".to_string()), false, filter_prot) 
                }
            };
            self.clear_response_hdrs();
            stream.write_all(response.as_bytes()).unwrap();
        }

        Ok(())
    }
}
