mod utils;
mod filter;
mod tpool;

use std::{io::{Error, ErrorKind}, net::UdpSocket, str, thread, time::Duration};
#[allow(unused_imports)]
use utils::print_dump;
use filter::FilterConfig;
use tpool::ThreadPool;
use std::sync::Mutex;
use std::sync::Arc;

fn lookup(dns_req_pack : &Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    let dns_server = ("192.168.0.1", 53);
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
    
    //log_info!("answer size: {} vector capacity: {} server IP: {}\n", answer_size, dns_response.capacity(), server_ip);
    //print_dump(&dns_response, answer_size);

    Ok(dns_response)
}

fn get_asked_string(dns_req_pack : &Vec<u8>) -> String {
    let mut offset: usize = 12;
    let mut len : u8 = dns_req_pack[offset];
    let mut name : &str;
    let mut ask_name : String = "".to_owned();
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
    shared_filter : &Arc<Mutex<FilterConfig>>) -> Result<(), std::io::Error> {
    let asked_name = get_asked_string(dns_req_pack);
    let mut filter_config = shared_filter.lock().unwrap();

    log_info!("Ask for: {}", asked_name);

    let dns_response : Vec<u8>;
    if filter_config.search(&asked_name) {
        let mut reject_buff : [u8; 12] = [0; 12];
        // Copy ID field
        reject_buff[0] = dns_req_pack[0];
        reject_buff[1] = dns_req_pack[1];
        // Set bit response
        reject_buff[2] = 1 << 7;
        // Set error code
        reject_buff[3] = 3; /* NOT EXIST */

        dns_response = reject_buff.to_vec();
        log_print!("   \x1b[31m[rejected]\x1b[0m\n");
    } else {
        let lookup_result = lookup(dns_req_pack);
        if lookup_result.is_err() {
            return Err(lookup_result.err().unwrap());
        }
        dns_response = lookup_result.unwrap();
        log_print!("   \x1b[32m[allowed]\x1b[0m\n");
    }

    //log_debug!("Sending {} bytes\n", dns_response.len());
    let send_result = socket.send_to(&dns_response, ip_addr);
    if send_result.is_err() {
        return Err(send_result.err().unwrap());
    }

    drop(dns_response);

    //let send_size = send_result.unwrap();
    //log_debug!("Sent {} bytes\n", send_size);

    Ok(())
}

fn listen(socket : &Arc<UdpSocket>) -> Result<(Vec<u8>, std::net::SocketAddr), std::io::Error> {
    let mut dns_req_pack : [u8; 512] = [0; 512];
    if socket.set_read_timeout(Some(Duration::new(1, 0))).is_err() {
        return Err(Error::new(ErrorKind::Other, "Unable to set socket read timeout"));
    }
    let remote_ip_addr: std::net::SocketAddr;

    loop {
        let recv_result = socket.recv_from(&mut dns_req_pack);
        if recv_result.is_err() {
            let error_kind: ErrorKind = recv_result.as_ref().err().unwrap().kind();
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

    //log_debug!("usize={} ip_addr={}\n", size, ip_addr);
    //print_dump(&dns_req_pack, size);

    let dns_req_vec = dns_req_pack.to_vec();

    Ok((dns_req_vec, remote_ip_addr))
}

fn start_dns_filter() -> Result<(), std::io::Error> {
    let mut filter_cfg: FilterConfig = FilterConfig::new();

    log_info!("Check for updates...\n");
    filter_cfg.check_update();
    log_debug!("Check finished\n");

    let cfg_result = filter_cfg.create_black_list_map();
    if cfg_result.is_err() {
        return Err(cfg_result.err().unwrap());
    }
    log_info!("Filter was created\n");
    let tpool = ThreadPool::new(4);
    let filter_prot = Arc::new(Mutex::new(filter_cfg));
    log_info!("Filter created\n");

    let bind_result = UdpSocket::bind("127.0.0.1:2053");
    if bind_result.is_err() {
        return Err(bind_result.err().unwrap());
    }
    let sock = Arc::new(bind_result.unwrap());
    
    loop {
        let socket = Arc::clone(&sock);
        // Waiting for DNS request
        let listen_result = listen(&socket);
        if listen_result.is_err() {
            return Err(listen_result.err().unwrap());
        }
        let (dns_req_pack, ip_addr) = listen_result.unwrap();
        let shared_filter = Arc::clone(&filter_prot);
        tpool.execute(move || {
            // Handle the request
            let query_result = resolve_request(&dns_req_pack, &socket, ip_addr, &shared_filter);
            // Not sure if we realy need this call
            drop(dns_req_pack);
            if query_result.is_err() {
                log_warn!("Handling error: {}\n", query_result.err().unwrap());
            }
        });
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

    let dns_filter_thread = thread::spawn(move || {
        let _ = start_dns_filter();
    });
    let _ = dns_filter_thread.join();

    return Ok(())
}
