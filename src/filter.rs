use std::io;
use std::io::{BufRead, Error, ErrorKind};
use std::collections::BTreeMap;
use std::str;
use crate::log_info;
use crate::log_debug;
use crate::log_error;
use curl::easy::Easy;
use std::io::Write;
use std::fs::File;
use std::sync::{Arc, Mutex};

pub const BLOCKLIST_FILE_NAME: &str = "blocklist.txt";
const LOCAL_BLOCKLIST_FILE_NAME: &str = "local-blocklist.txt";
pub const LOCAL_WHITELIST_FILE_NAME: &str = "local-whitelist.txt";

#[derive(Clone, PartialEq, Copy)]
enum FilterType {
    Global,
    Local,
    None
}

#[derive(Clone)]
struct Statistics {
    requests : u64,
    enable : bool,
    filter_type: FilterType,
}

impl Statistics {
    fn new(ftype: FilterType) -> Self {
        Statistics { requests: 0, enable: false, filter_type: ftype }
    }

    pub fn set_enable(&mut self, enable: bool) {
        self.enable = enable;
    }
    pub fn inc_request_count(&mut self) -> u64 {
        self.requests += 1;
        return self.requests;
    }
    #[allow(dead_code)]
    pub fn get_filter_type(&self) -> FilterType {
        return self.filter_type;
    }
}

#[derive(PartialEq)]
pub enum FilterUpdateStatus {
    Unchanged,
    Updated,
    Reloaded,
    DownloadError
}

pub struct FilterConfig {
    ads_provider_list: BTreeMap<String, Statistics>,
    ads_provider_wildcard: BTreeMap<String, Statistics>,
    update_status: FilterUpdateStatus
}

impl FilterConfig {
    const URL_BLOCKLIST: &str = "https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt";
    const REMOVE_PARAM_TAG: &str = "$removeparam";
    const BAD_PARAM_TAG: &str = "$badfilter";
    const THIRD_PARTY_TAG: &str = "$third-party";
    const DOMAIN_TAG: &str = "$domain";

    pub fn new() -> FilterConfig {
        log_info!("Create new filter\n");
        FilterConfig
        {
            ads_provider_list: BTreeMap::new(),
            ads_provider_wildcard: BTreeMap::new(),
            update_status: FilterUpdateStatus::Unchanged
        }
    }

    fn get_remote_blocklist_length(curl: &mut Easy) -> Result<u64, curl::Error> {
        let rlen: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

        let len = Arc::clone(&rlen);
        curl.header_function(move |header| {
            let hlen = "content-length";
            let mut hstr = String::from_utf8(header.to_vec()).unwrap().to_lowercase();
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

    fn get_local_blocklist_length() -> Result<u64, std::io::Error> {
        let res = File::open(BLOCKLIST_FILE_NAME);
        if res.is_err() {
            log_error!("Unable to open blocklist.txt\n");
            return Err(res.err().unwrap());
        }
        let file = res.unwrap();
        let metadata = file.metadata().unwrap();

        Ok(metadata.len())
    }

    pub fn set_update_status(&mut self, status: FilterUpdateStatus) {
        self.update_status = status;
    }

    pub fn is_updated(&self) -> bool {
        return self.update_status == FilterUpdateStatus::Updated;
    }

    pub fn is_reloaded(&self) -> bool {
        return self.update_status == FilterUpdateStatus::Reloaded;
    }

    pub fn is_error(&self) -> bool {
        return self.update_status == FilterUpdateStatus::DownloadError;
    }

    pub fn prepare_stat_data(&self) -> String {
        let mut ret_str: String;
        let mut ads_prov: Vec<&BTreeMap<String, Statistics>> = vec![];
        ads_prov.push(&self.ads_provider_list);
        ads_prov.push(&self.ads_provider_wildcard);
        /* Table header */
        ret_str = "<tr>\n<th>Enable</th>\n<th>Filter</th>\n<th>Name</th>\n<th>Count</th></tr>\n".to_string();
        /* Table contant */
        for i in 0..ads_prov.len() {
            let prov = ads_prov[i];
            for (key, value) in prov.iter() {
                if value.requests > 0 {
                    ret_str += "<tr>\n";
                    ret_str += "<td><input type=\"checkbox\" name=\"";
                    ret_str += key;
                    ret_str += "\" ";
                    if value.enable {
                        ret_str += "checked";
                    } else {
                        ret_str += "unchecked";
                    }
                    ret_str += "></td>\n";
                    ret_str += "<td>\n";
                    ret_str += if value.get_filter_type() == FilterType::Global {
                        "Global"
                    } else if value.get_filter_type() == FilterType::Local {
                        "Local"
                    } else {
                        ""
                    };
                    ret_str += "</td>\n<td>";
                    ret_str += key;
                    ret_str += "</td>\n<td>";
                    ret_str += &value.requests.to_string();
                    ret_str += "</td>\n";
                    ret_str += "</tr>\n";
                }
            }
        }
        
        return ret_str;
    }

    pub fn get_num_entries(&self) -> usize {
        return self.ads_provider_list.len();
    }

    pub fn check_update() -> FilterUpdateStatus {
        // Get remote file length
        let mut curl = Easy::new();
        let res = curl.url(FilterConfig::URL_BLOCKLIST);
        if res.is_err() {
            log_error!("Invalid URL\n");
            return FilterUpdateStatus::DownloadError;
        }
        let res = FilterConfig::get_remote_blocklist_length(&mut curl);
        if res.is_err() {
            log_error!("Unable to get remote file length\n");
            return FilterUpdateStatus::DownloadError;
        }
        let remote_size = res.unwrap();
        log_info!("Remote file length: {}\n", remote_size);

        let res = FilterConfig::get_local_blocklist_length();
        if res.is_ok() {
            let local_size = res.unwrap();
            if local_size == remote_size {
                log_info!("Remote file unchanged\n");
                return FilterUpdateStatus::Unchanged;
            }
        }
        // Get content
        log_info!("Download new file\n");
        let mut file = File::create(BLOCKLIST_FILE_NAME);
        if file.is_err() {
            log_error!("Unable to create file\n");
            return FilterUpdateStatus::DownloadError;
        }

        curl.write_function(move |data| {
            file.as_mut().unwrap().write_all(data).unwrap();

            Ok(data.len())
        }).unwrap();
        let res = curl.perform();
        if res.is_err() {
            log_error!("Unanle to get content\n");
            return FilterUpdateStatus::DownloadError;
        }

        return FilterUpdateStatus::Updated;
    }

    pub fn set_enable(&mut self, key : &String) -> bool {
        log_debug!("Key: '{}'\n", key);
        let stat_opt = self.ads_provider_list.get_mut(key);
        if stat_opt.is_none() {
            return false;
        }
        let stat  = stat_opt.unwrap();
        stat.set_enable(true);

        return true;
    }

    pub fn clear_enable(&mut self) {
        for (_key, value) in self.ads_provider_list.iter_mut() {
            value.set_enable(false);
        }
    }

    pub fn search_wildcard(&mut self, name: &String) -> (bool, u64) {
        for (key, stat) in self.ads_provider_wildcard.iter_mut() {
            let parts: Vec<&str> = key.split('*').collect();
            let first_star: bool = if key.chars().nth(0).unwrap() == '*' {true} else {false};
            let mut index: usize = 0;
            let mut found: bool = true;
            for i in 0..parts.len() {
                if i == 0 {
                    if first_star {
                        let opt = name.find(parts[0]);
                        if opt.is_none() {
                            found = false;
                            break;
                        }
                        index = opt.unwrap() + parts[0].len();
                    } else {
                        if !name.starts_with(parts[0]) {
                            found = false;
                            break;
                        }
                        index = parts[0].len();
                    }
                } else {
                    if parts[i].len() == 0 {
                        continue;
                    }
                    let opt = name[index..].find(parts[i]);
                    if opt.is_none() {
                        found = false;
                        break;
                    }
                    index += opt.unwrap() + parts[i].len();
                }
            }
            if !found {
                continue;
            }
            if index == name.len() || key.chars().nth(key.len() - 1).unwrap() == '*' {
                if stat.enable {
                    return (false, 0);            
                }
                log_debug!("FOUND: wildcard: {} name: {}\n", key, name);
                let reject_count = stat.inc_request_count();
                return (true, reject_count);
            }
        }

        return (false, 0);
    }

    pub fn search(&mut self, key : &String) -> (bool, u64) {
        let stat_opt = self.ads_provider_list.get_mut(key);
        if stat_opt.is_none() {
            return self.search_wildcard(key)
        }
        let stat  = stat_opt.unwrap();
        if stat.enable {
            return (false, 0);
        }
        let reject_count = stat.inc_request_count();

        return (true, reject_count);
    }

    pub fn reload_filter(&mut self) -> Result<(), std::io::Error> {
        self.ads_provider_list.clear();
        self.ads_provider_wildcard.clear();

        return self.create_black_list_map();
    }

    pub fn create_black_list_map(&mut self) -> Result<(), std::io::Error> {
        let filter_files: Vec<&str> = Vec::from([BLOCKLIST_FILE_NAME, LOCAL_BLOCKLIST_FILE_NAME, LOCAL_WHITELIST_FILE_NAME]);

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
                if single_line.len() > 2 && single_line.chars().nth(0).unwrap() != '|' || 
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
                if second_part.contains(FilterConfig::BAD_PARAM_TAG) {
                    continue;
                }
                if second_part.contains(FilterConfig::REMOVE_PARAM_TAG) {
                    continue;
                }
                if second_part.contains(FilterConfig::THIRD_PARTY_TAG) {
                    continue;
                }
                if second_part.contains(FilterConfig::DOMAIN_TAG) {
                    continue;
                }
                single_line.truncate(pos);
                if single_line.is_empty() {
                    log_info!("Empty string\n");
                    continue;
                }
                // Skip invalid DNS name
                if single_line.find('/').is_some() {
                    continue;
                }
                let ftype = match index {
                    0 => FilterType::Global,
                    1 => FilterType::Local,
                    _ => FilterType::None
                };
                // TODO: Use wildcard
                if single_line.find('*').is_some() {
                    //log_debug!("Wild card found: {}\n", single_line);
                    if single_line.contains("[") {
                        continue;
                    }
                    log_debug!("Add wildcard: {}\n", single_line);
                    if self.ads_provider_wildcard.insert(single_line.clone(), Statistics::new(ftype)).is_some() {
                        log_info!("Dublicated wildcard {}\n", single_line);
                    }
                    continue;
                }

                if ftype == FilterType::Global || ftype == FilterType::Local {
                    if self.ads_provider_list.insert(single_line.clone(), Statistics::new(ftype)).is_some() {
                        log_info!("Dublicated key {}\n", single_line);
                    } else {
                        total_lines += 1;
                    }
                } else {
                    // White list
                    log_debug!("White list entry: {}\n", single_line);
                    let opt = self.ads_provider_list.get_mut(&single_line);
                    if opt.is_none() {
                        log_debug!("Entry not found\n");
                        continue;
                    }
                    let stat = opt.unwrap();
                    stat.set_enable(true);
                    stat.inc_request_count();
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
