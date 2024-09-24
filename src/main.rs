mod utils;
mod filter;
mod tpool;
mod uiserver;

use std::{io::{Error, ErrorKind}, net::UdpSocket, str, thread::{self, JoinHandle}, time::Duration};
#[allow(unused_imports)]
use utils::print_dump;
use filter::FilterConfig;
use tpool::ThreadPool;
use std::sync::Mutex;
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use curl::easy::{Easy, List};
use std::io::Read;
use uiserver::UiServer;

struct DnsProxy {
    pub running: Arc<AtomicBool>,
    pub curl: Arc<Mutex<Easy>>,
}

impl DnsProxy {
    pub fn new() -> DnsProxy {
        let mut curl = Easy::new();
        let _ = curl.post(true);
        let mut list = List::new();
        let _ = list.append("content-type: application/dns-message");
        let _ = curl.http_headers(list);
        let curl_guard = Arc::new(Mutex::new(curl));
        DnsProxy
        {
            running: Arc::new(AtomicBool::new(true)),
            curl: curl_guard,
        }
    }
     
    fn lookup_https(dns_server: std::net::SocketAddr, dns_req_pack : &Vec<u8>, shared_curl: &Arc<Mutex<Easy>>) -> Result<Vec<u8>, std::io::Error> {
        let mut curl = shared_curl.lock().unwrap();
        let url = format!("https://{}/dns-query", dns_server.ip().to_string());
        let mut res = curl.url(&url);
        if res.is_err() {
            return Err(res.err().unwrap().into());
        }
        res = curl.post_field_size(dns_req_pack.len() as u64);
        if res.is_err() {
            return Err(res.err().unwrap().into());
        }
        let mut data: &[u8] = dns_req_pack.as_slice();
        let mut transfer = curl.transfer();

        let dns_response_guard  = Arc::new(Mutex::new(Vec::<u8>::new()));
        dns_response_guard.lock().unwrap().resize(512, 0);
        
        transfer.read_function(|buff| {
            Ok(data.read(buff).unwrap_or(0))
        }).unwrap();
        let dns_response: Arc<Mutex<Vec<u8>>> = Arc::clone(&dns_response_guard);
        transfer.write_function(move |data| {
            *dns_response.lock().unwrap() = data.to_vec();
            Ok(data.len())
        }).unwrap();
        res = transfer.perform();
        if res.is_err() {
            return Err(res.err().unwrap().into());
        }

        let ret = dns_response_guard.lock().unwrap(); 

        Ok(ret.to_vec())
    }

    fn lookup(dns_server: std::net::SocketAddr, dns_req_pack : &Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
        let socket = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        if socket.send_to(&dns_req_pack, dns_server).is_err() {
            return Err(Error::new(ErrorKind::AddrNotAvailable, "Unable to send request to DNS server"));
        }
        let mut dns_response = Vec::with_capacity(512);
        dns_response.resize(512, 0);
        if socket.set_read_timeout(Some(Duration::new(3, 0))).is_err() {
            return Err(Error::new(ErrorKind::Other, "Unable to set socket timeout"));
        }
        let answer_result = socket.recv_from(&mut dns_response);
        if answer_result.is_err() {
            return Err(answer_result.err().unwrap());
        }
        let (answer_size, _) = answer_result.unwrap();
        dns_response.truncate(answer_size);
        
        Ok(dns_response)
    }

    fn get_asked_string(dns_req_pack : &Vec<u8>) -> String {
        let mut offset: usize = 12;
        let mut len : u8 = dns_req_pack[offset];
        let mut name : &str;
        let mut ask_name : String = Default::default();
        while len != 0 {
            name = std::str::from_utf8(&dns_req_pack[offset + 1..offset + 1 + len as usize]).unwrap();
            ask_name = ask_name + name;
            offset = offset + len as usize + 1;
            if offset >= dns_req_pack.len() {
                // Something to wrong
                ask_name.clear();
                log_error!("Unable to get asked name\n");
                break;
            }
            len = dns_req_pack[offset];
            if len != 0 {
                ask_name = ask_name + ".";
            }
        }

        return ask_name;
    }

    fn resolve_request(dns_req_pack : &Vec<u8>, socket : &Arc<UdpSocket>, ip_addr : std::net::SocketAddr, 
        shared_filter : &Arc<Mutex<FilterConfig>>, shared_curl: &Arc<Mutex<Easy>>) -> Result<(), std::io::Error> {
        let asked_name = DnsProxy::get_asked_string(dns_req_pack);
        let mut filter_config = shared_filter.lock().unwrap();
        let dns_srv_addr = filter_config.get_dns_srv_addr();
        let use_doh = filter_config.get_use_doh();
        let dns_response : Vec<u8>;
        let (is_found, reject_count) = filter_config.search(&asked_name);
        let mut log_string: String = Default::default();
        if !is_found || reject_count == 1 {
            //log_info!("Ask for: {}", asked_name);
            log_string = format!("Ask for: {}", asked_name);
        }
        drop(filter_config);
        if is_found {
            let mut reject_buff : [u8; 12] = [0; 12];
            // Copy ID field
            reject_buff[0] = dns_req_pack[0];
            reject_buff[1] = dns_req_pack[1];
            // Set bit response
            reject_buff[2] = 1 << 7;
            // Set error code
            reject_buff[3] = 3; /* NOT EXIST */

            dns_response = reject_buff.to_vec();
            if reject_count == 1 {
                //log_print!("   \x1b[31m[rejected]\x1b[0m\n");
                log_string += "   \x1b[31m[rejected]\x1b[0m\n";
            }
        } else {
            let lookup_result: Result<Vec<u8>, Error>;
            if use_doh {
                lookup_result = DnsProxy::lookup_https(dns_srv_addr, dns_req_pack, shared_curl);
            } else {
                lookup_result = DnsProxy::lookup(dns_srv_addr, dns_req_pack);
            }

            if lookup_result.is_err() {
                return Err(lookup_result.err().unwrap());
            }
            dns_response = lookup_result.unwrap();
            if !is_found {
                //log_print!("   \x1b[32m[allowed]\x1b[0m\n");
                log_string += "   \x1b[32m[allowed]\x1b[0m\n";
            }
        }
        if !is_found || reject_count == 1 {
            log_info!(&log_string);
        }
        //log_debug!("Sending {} bytes\n", dns_response.len());
        let send_result = socket.send_to(&dns_response, ip_addr);
        if send_result.is_err() {
            return Err(send_result.err().unwrap());
        }

        Ok(())
    }

    pub fn listen(&self, socket : &Arc<UdpSocket>) -> Result<(Vec<u8>, std::net::SocketAddr), std::io::Error> {
        let mut dns_req_pack : [u8; 512] = [0; 512];
        if socket.set_read_timeout(Some(Duration::new(1, 0))).is_err() {
            return Err(Error::new(ErrorKind::Other, "Unable to set socket read timeout"));
        }
        let remote_ip_addr: std::net::SocketAddr;

        loop {
            let recv_result = socket.recv_from(&mut dns_req_pack);
            if recv_result.is_err() {
                let error_kind: ErrorKind = recv_result.as_ref().err().unwrap().kind();

                if !self.running.load(Ordering::Relaxed) {
                    log_info!("DNS proxy stoped by user\n");
                    return Err(Error::new(std::io::ErrorKind::Other, "Stoped by user"));
                }

                if error_kind == ErrorKind::WouldBlock || error_kind == ErrorKind::TimedOut {
                    continue;
                }
                log_error!("Listener failed. Error: {}\n", error_kind);
                return Err(recv_result.err().unwrap());
            }
            let (_, ip_addr) = recv_result.unwrap();
            remote_ip_addr = ip_addr;
            break;
        }
        let dns_req_vec = dns_req_pack.to_vec();

        Ok((dns_req_vec, remote_ip_addr))
    }

    pub fn start_dns_filter(&self, filter_prot: &Arc<Mutex<FilterConfig>>) -> Result<(), std::io::Error> {
        let tpool = ThreadPool::new(4);
        let cfg = filter_prot.lock().unwrap();
        let bind_addr = cfg.get_bind_addr();
        drop(cfg); 
        let bind_result = UdpSocket::bind(bind_addr);
        if bind_result.is_err() {
            return Err(bind_result.err().unwrap());
        }
        let sock = Arc::new(bind_result.unwrap());
        
        loop {
            let socket = Arc::clone(&sock);
            // Waiting for DNS request
            let listen_result = self.listen(&socket);
            if listen_result.is_err() {
                return Err(listen_result.err().unwrap());
            }
            let (dns_req_pack, ip_addr) = listen_result.unwrap();
            let shared_filter = Arc::clone(filter_prot);
            let shared_curl = Arc::clone(&self.curl);
            tpool.execute(move || {
                // Handle the request
                let query_result = DnsProxy::resolve_request(&dns_req_pack, &socket, ip_addr, &shared_filter, &shared_curl);
                // Not sure if we realy need this call
                drop(dns_req_pack);
                if query_result.is_err() {
                    log_warn!("Handling error: {}\n", query_result.err().unwrap());
                }
            });
        }
    }
}

fn set_ctrlc_handle(dns_proxy: &DnsProxy, ui_server: &UiServer) -> bool {
    let running_ui = Arc::clone(&ui_server.running);
    let running = Arc::clone(&dns_proxy.running);

    let res = ctrlc::set_handler(move || {
        running_ui.store(false, Ordering::Relaxed);
        running.store(false, Ordering::Relaxed);
    });

    if res.is_err() {
        return false;
    }

    return true;
}

fn wait_threads(proxy_thread: &JoinHandle<()>, proxy_run: &Arc<AtomicBool>, ui_thread: &JoinHandle<()>, ui_run: &Arc<AtomicBool>) {
    while !proxy_thread.is_finished() && !ui_thread.is_finished() {
        thread::sleep(Duration::from_millis(100));
    }
    if proxy_thread.is_finished() {
        ui_run.store(false, Ordering::Relaxed);
    }
    if ui_thread.is_finished() {
        proxy_run.store(false, Ordering::Relaxed);
    }
}

fn main() -> Result<(), std::io::Error>
{
    // Thread parameter example
    //let thread_param = 100;
    //let start_dns_proxy_handle = move |data: i32| {
    //    let data = start_dns_proxy();
    //};
    //let dns_proxy_thread = thread::spawn(move || {
    //    start_dns_proxy_handle(thread_param)
    //});
    let (tx_proxy, rx_proxy) = mpsc::channel();
    let (tx_ui, rx_ui) = mpsc::channel();
    let dns_proxy_server = DnsProxy::new();
    let ui_server = UiServer::new();
    let mut filter_cfg: FilterConfig = FilterConfig::new();

    #[cfg(feature = "filter_update")]
    log_info!("Check for updates...\n");
    #[cfg(feature = "filter_update")]
    filter_cfg.check_update();
    #[cfg(feature = "filter_update")]
    log_debug!("Check finished\n");

    let cfg_result = filter_cfg.create_black_list_map();
    if cfg_result.is_err() {
        return Err(cfg_result.err().unwrap());
    }
    log_info!("Filter was created\n");
    let filter_prot = Arc::new(Mutex::new(filter_cfg));
    let ui_filter_prot = Arc::clone(&filter_prot);

    let running_ui = Arc::clone(&ui_server.running);
    let running_proxy = Arc::clone(&dns_proxy_server.running);
    // Set ^C handler
    if !set_ctrlc_handle(&dns_proxy_server, &ui_server) {
        log_error!("Unable to set ^C handle\n");
    }
    // Start DNS proxy thread
    let proxy_thread = thread::spawn(move || {
        let res = dns_proxy_server.start_dns_filter(&filter_prot);
        tx_proxy.send(res).unwrap();
    });
    // Start UI thread
    let ui_thread = thread::spawn(move || {
        let res: Result<(), Error> = ui_server.start_gui_server(&ui_filter_prot);
        tx_ui.send(res).unwrap();
    });
    // Wait for finish
    wait_threads(&proxy_thread, &running_proxy,&ui_thread, &running_ui);
    let _ = ui_thread.join();
    let _ = proxy_thread.join();
    // Finished. Read results
    let proxy_res = rx_proxy.recv().unwrap();
    let ui_res = rx_ui.recv().unwrap();
    // Print error if exist
    if proxy_res.is_err() {
        let err_kind = proxy_res.as_ref().err().unwrap().kind();
        if err_kind != ErrorKind::Other {
            log_info!("DNS proxy thread abnormal terminated: {}\n", proxy_res.err().unwrap());
        }
    }
    if ui_res.is_err() {
        let err_kind = ui_res.as_ref().err().unwrap().kind();
        if err_kind != ErrorKind::Other {
            log_info!("UI thread abnormal terminated: {}\n", ui_res.err().unwrap());
        }
    }

    return Ok(())
}
