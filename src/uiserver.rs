use std::net::TcpListener;
use std::io::{prelude::*, Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::{log_error, log_debug, log_info};
use crate::filter::FilterConfig;

pub struct UiServer {
    pub running: Arc<AtomicBool>,
}

impl UiServer {
    pub fn new() -> UiServer {
        UiServer
        {
            running: Arc::new(AtomicBool::new(true)),
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
                let dns_srv_addr = filter.get_dns_srv_addr();
                drop(filter);
                dns_srv_addr.to_string()
            }
            _=> Default::default(),
        };

        return ret_string;
    }

    fn replace_tag(tag: &str, contents: &String, filter_prot: &Arc<Mutex<FilterConfig>>) -> String {
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

    fn prepare_content(status: &str, filename: &str, post_process: bool, filter_prot: &Arc<Mutex<FilterConfig>>) -> String {
        let mut response: String = Default::default();
        if !filename.is_empty() {
            let cont_res = std::fs::read_to_string(filename);
            if cont_res.is_err() {
                log_error!("Unable to open {}\n", filename);
                return response;
            }

            let mut contents_temp = cont_res.unwrap();
            if post_process {
                contents_temp = UiServer::replace_tag("{#ENTRIES}", &contents_temp, filter_prot);
                contents_temp = UiServer::replace_tag("{#LISTEN}", &contents_temp, filter_prot);
                contents_temp = UiServer::replace_tag("{#DNSSRV}", &contents_temp, filter_prot);
            }
            let contents = contents_temp;
            let length = contents.len();
            response = format!("{status}\r\nContent-Length: {length}\r\n\r\n{contents}");

            return response;
        } else {
            response = format!("{status}\r\n\r\n");
        }

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

    fn set_dns_server(data: &Vec<u8>, filter_prot: &Arc<Mutex<FilterConfig>>) -> bool {
        let mut data_str: String = String::from_utf8(data.to_vec()).unwrap();
        let mut opt = data_str.find("dns_ipaddr");
        if opt.is_none() {
            return false;
        }
        opt = data_str.find("=");
        if opt.is_none() {
            return false;
        }
        let mut offset = opt.unwrap();
        offset += 1;
        let param = data_str.split_off(offset);
        log_debug!("PARAM: {}\n", param);

        let temp = param.parse::<std::net::Ipv4Addr>();
        if temp.is_err() {
            log_error!("Error parsing IP address string\n");
            return false;
        }

        let addr: std::net::SocketAddr = std::net::SocketAddr::new(std::net::IpAddr::V4(temp.unwrap()), 53);
        let mut filter = filter_prot.lock().unwrap();

        filter.set_dns_srv_addr(addr);

        return true;
    }

    pub fn start_gui_server(&self, filter_prot: &Arc<Mutex<FilterConfig>>) -> Result<(), std::io::Error> {
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
                "GET / HTTP/1.1" => 
                    UiServer::prepare_content("HTTP/1.1 200 OK", "html/start_page.tmpl", true, filter_prot),
                "GET /change_ip.html HTTP/1.1" =>
                    UiServer::prepare_content("HTTP/1.1 200 OK", "html/change_ip.html", false, filter_prot),
                "POST /dns_change_ip HTTP/1.1" => {
                    let mut data = Vec::with_capacity(1024);
                    data.resize(1024, 0); 
                    let res = UiServer::get_post_data(&request, &mut data);
                    if res.is_ok() {
                        data.truncate(res.unwrap());
                        log_debug!("DATA: {}\n", String::from_utf8(data.to_vec()).unwrap());
                        UiServer::set_dns_server(&data, filter_prot);
                    }
                    UiServer::prepare_content("HTTP/1.1 301 Redirect\r\nLocation: /", "html/start_page.tmpl", true, filter_prot)
                }
                _ =>
                    UiServer::prepare_content("HTTP/1.1 404 NOT FOUND", "html/404.html", false, filter_prot) 
            };

            stream.write_all(response.as_bytes()).unwrap();
        }

        Ok(())
    }
}