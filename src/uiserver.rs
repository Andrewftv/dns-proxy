use std::net::TcpListener;
use std::io::{prelude::*, BufReader, Error, ErrorKind};
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
            log_debug!("Peer address: {}\n", stream.peer_addr().unwrap());
            let buf_reader = BufReader::new(&mut stream);

            let res = buf_reader.lines().next();
            if res.is_none() {
                log_debug!("NONE\n");
                continue;
            }
            let res = res.unwrap();
            if res.is_err() {
                log_debug!("ERROR\n");
                continue;
            }
            let request_line = res.unwrap();
            log_debug!("Request for: {}\n", request_line);
            let (status, filename, post_process) = match &request_line[..] {
                "GET / HTTP/1.1" => ("HTTP/1.1 200 OK", "html/start_page.tmpl", true),
                _ => ("HTTP/1.1 404 NOT FOUND", "html/404.html", false),
            };
            let cont_res = std::fs::read_to_string(filename);
            if cont_res.is_err() {
                log_error!("Unable to open {}\n", filename);
                return Err(cont_res.err().unwrap());
            }

            let filter = filter_prot.lock().unwrap();
            let entries = filter.get_num_entries();
            drop(filter);

            log_debug!("Filter has {} entries\n", entries);

            let contents_temp = cont_res.unwrap();
            let mut contents: String = "".to_owned();
            if post_process {
                let opt = contents_temp.find("{}");
                if opt.is_some() {
                    let size = opt.unwrap();
                    contents = contents_temp[0..size].to_string();
                    contents += &entries.to_string();
                    contents += &contents_temp[size + 2..contents_temp.len()].to_string();
                }
            } else {
                contents = contents_temp;
            }
            let length = contents.len();
            let response = format!("{status}\r\nContent-Length: {length}\r\n\r\n{contents}");

            stream.write_all(response.as_bytes()).unwrap();
        }

        Ok(())
    }
}