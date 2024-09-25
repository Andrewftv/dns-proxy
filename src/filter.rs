use std::io;
use std::io::{BufRead, Error, ErrorKind};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, IpAddr};
use std::str;
use crate::log_info;
use crate::log_debug;
#[cfg(feature = "filter_update")]
use crate::log_error;
#[cfg(feature = "filter_update")]
use curl::easy::Easy;
#[cfg(feature = "filter_update")]
use std::io::Write;
#[cfg(feature = "filter_update")]
use std::fs::File;
#[cfg(feature = "filter_update")]
use std::sync::{Arc, Mutex};

#[derive(Clone, PartialEq)]
pub enum FilterType {
    Global,
    Local
}

#[derive(Clone)]
struct Statistics {
    requests : u64,
    #[allow(dead_code)]
    filter_type: FilterType,
}

impl Statistics {
    fn new(ftype: FilterType) -> Self {
        Statistics { requests : 0, filter_type: ftype }
    }

    pub fn inc_request_count(&mut self) -> u64 {
        self.requests += 1;
        return self.requests;
    }
    #[allow(dead_code)]
    pub fn get_filter_type(&self) -> &FilterType {
        return &self.filter_type;
    }
}

pub enum FilterUpdateStatus {
    Unchanged,
    Updated
}

pub struct FilterConfig {
    ads_provider_list: BTreeMap<String, Statistics>,
    bind_addr: std::net::SocketAddr,
    dns_srv_addr: std::net::SocketAddr,
    use_doh: bool
}

impl FilterConfig {
    pub fn new() -> FilterConfig {
        log_info!("Create new filter\n");
        FilterConfig
        {
            ads_provider_list: BTreeMap::new(),
            bind_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2053),
            /* Default google DNS */
            dns_srv_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            /* Use DNS over HTTPS */
            use_doh: true
        }
    }

    pub fn prepare_stat_data(&self) -> String {
        let mut ret_str: String = Default::default();
        for (key, value) in self.ads_provider_list.iter() {
            if value.requests > 0 {
                ret_str += key;
                ret_str += ": ";
                ret_str += &value.requests.to_string();
                ret_str += "<br>";
            }
        }
        return ret_str;
    }

    pub fn get_use_doh(&self) -> bool {
        return self.use_doh;
    }

    pub fn set_use_doh(&mut self, value: bool) {
        self.use_doh = value;
    }

    pub fn get_dns_srv_addr(&self) -> std::net::SocketAddr {
        return self.dns_srv_addr;
    }

    pub fn set_dns_srv_addr(&mut self, addr: std::net::SocketAddr) -> bool {
        self.dns_srv_addr = addr;
        return true;
    }

    pub fn get_bind_addr(&self) -> std::net::SocketAddr {
        return self.bind_addr;
    }

    pub fn get_num_entries(&self) -> usize {
        return self.ads_provider_list.len();
    }

    #[cfg(feature = "filter_update")]
    fn get_remote_file_length(&self, curl: &mut Easy) -> Result<u64, curl::Error> {
        let rlen: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

        let len = Arc::clone(&rlen);
        curl.header_function(move |header| {
            let hlen = "Content-Length";
            let mut hstr = String::from_utf8(header.to_vec()).unwrap();
            let mut opt_pos = hstr.find(hlen);
            if opt_pos.is_some() {
                opt_pos = hstr.find(":");
                if opt_pos.is_some() {
                    let mut pos = opt_pos.unwrap();
                    pos += 1;
                    while hstr.chars().nth(pos).unwrap() == ' ' {
                        pos += 1;
                    }
                    let mut str_file_len = hstr.split_off(pos);
                    str_file_len.truncate(str_file_len.len() - 2);
                    let file_len_res = str_file_len.parse::<u64>();
                    if file_len_res.is_ok() {
                        let mut value = len.lock().unwrap();
                        *value = file_len_res.unwrap();
                    }
                }
            }

            true
        }).unwrap();
        let res = curl.perform();
        if res.is_err() {
            log_error!("Unanle to get headers\n");
            return Err(res.err().unwrap());
        }
        let value = rlen.lock().unwrap();
        Ok(*value)
    }

    #[cfg(feature = "filter_update")]
    fn get_local_file_length(&self) -> Result<u64, std::io::Error> {
        let res = File::open("blocklist.txt");
        if res.is_err() {
            log_error!("Unable to open blocklist.txt\n");
            return Err(res.err().unwrap());
        }
        let file = res.unwrap();
        let metadata = file.metadata().unwrap();

        Ok(metadata.len())
    }

    #[cfg(feature = "filter_update")]
    pub fn check_update(&self) -> Result<FilterUpdateStatus, curl::Error> {
        // Get remote file length
        let mut curl = Easy::new();
        let res = curl.url("https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt"); 
        if res.is_err() {
            log_error!("Invalid URL\n");
            return Err(res.err().unwrap());
        }
        let res = self.get_remote_file_length(&mut curl);
        if res.is_err() {
            log_error!("Unable to get remote file length\n");
            return Err(res.err().unwrap());
        }
        let remote_size = res.unwrap();
        log_info!("Remote file length: {}\n", remote_size);
        //drop(curl);

        let res = self.get_local_file_length();
        if res.is_ok() {
            let local_size = res.unwrap();
            if local_size == remote_size {
                log_info!("Remote file unchanged\n");
                return Ok(FilterUpdateStatus::Unchanged);
            }
        }
        // Get content
        //let mut curl = Easy::new();
        //if curl.url("https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt").is_err() {
        //    log_error!("Invalid URL\n");
        //    return false;
        //}
        log_info!("Download new file\n");
        let mut file = File::create("blocklist.txt");
        if file.is_err() {
            log_error!("Unable to create file\n");
            return Err(curl::Error::new(file.err().unwrap().kind() as u32));
        }

        curl.write_function(move |data| {
            //log_debug!("File size: {}\n", data.len());
            file.as_mut().unwrap().write_all(data).unwrap();

            Ok(data.len())
        }).unwrap();
        let res = curl.perform();
        if res.is_err() {
            log_error!("Unanle to get content\n");
            return Err(res.err().unwrap());
        }

        return Ok(FilterUpdateStatus::Updated);
    }

    pub fn search(&mut self, key : &String) -> (bool, u64) {
        let stat_opt = self.ads_provider_list.get_mut(key);
        if stat_opt.is_none() {
            return (false, 0);
        }
        let stat  = stat_opt.unwrap();
        let reject_count = stat.inc_request_count();

        return (true, reject_count);
    }

    pub fn reload_filter(&mut self) -> Result<(), std::io::Error> {
        self.ads_provider_list.clear();

        return self.create_black_list_map();
    }

    pub fn create_black_list_map(&mut self) -> Result<(), std::io::Error> {
        let remove_param : &str = "$removeparam";
        let bad_filter : &str = "$badfilter";
        let third_party : &str = "$third-party";
        let filter_files: Vec<&str> = Vec::from(["blocklist.txt", "local-blocklist.txt"]);

        for index in 0..filter_files.capacity() {
            log_info!("Parse {} block list\n", filter_files[index]);
            let open_result = std::fs::File::open(filter_files[index]);
            if open_result.is_err() {
                return Err(Error::new(ErrorKind::NotFound, format!("Unable to open {}", filter_files[index])));
            }
            let file = open_result.unwrap();
            let reader = io::BufReader::new(file);

            let mut total_lines = 0;
            let mut single_line : String;
            for line in reader.lines() {
                if line.is_err() {
                    continue;
                }
                single_line = line.unwrap();
                if single_line.is_empty() {
                    continue;
                }
                if single_line.len() > 2 && single_line.chars().nth(0).unwrap() != '|' && 
                    single_line.chars().nth(1).unwrap() != '|' {
                    continue;
                } 
                // Remove "||" in start of line
                single_line.remove(0);
                single_line.remove(0);
                let find_end = single_line.find('^');
                if find_end.is_none() {
                    continue;
                }
                let pos = find_end.unwrap();
                let mut second_part = single_line.split_off(pos);
                // Remove "^"
                second_part.remove(0);
                if second_part.contains(bad_filter) {
                    continue;
                }
                if second_part.contains(remove_param) {
                    continue;
                }
                if second_part.contains(third_party) {
                    continue;
                }
                single_line.truncate(pos);
                // Skip invalid DNS name
                if single_line.find('/').is_some() {
                    continue;
                }
                // TODO: Use wildcard
                if single_line.find('*').is_some() {
                    continue;
                }

                let ftype = if index == 0 {
                    FilterType::Global
                } else {
                    FilterType::Local
                };

                if self.ads_provider_list.insert(single_line.clone(), Statistics::new(ftype)).is_some() {
                    log_info!("Dublicated key {}\n", single_line);
                } else {
                    total_lines += 1;
                }
            }

            log_info!("Total {} lines\n", total_lines);
            log_info!("List size: {}\n", self.ads_provider_list.len());
        }

        Ok(())
    }
}

impl Drop for FilterConfig {
    fn drop(&mut self) {
        log_debug!("Drop filter\n");
        self.ads_provider_list.clear();
    }
}
