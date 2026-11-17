use std::{io};
use std::io::{BufRead, Error, ErrorKind};
use std::str::{self};
use std::net::Ipv4Addr;
use crate::log_info;
use crate::log_debug;
use crate::log_error;
use curl::easy::Easy;
use std::io::Write;
use std::fs::File;
use std::sync::{Arc, Mutex};
use rusqlite::Connection;

use crate::confdb::{sqldb_get_ip_for_local_name, sqldb_remove_local_name, sqldb_insert_local_name, sqldb_update_local_name,
    sqldb_insert_filter_entry, sqldb_clean_filter, sqldb_get_filter_rows_count, sqldb_set_name_enable, sqldb_clear_all_enable,
    sqldb_is_name_blocked};

pub const BLOCKLIST_FILE_NAME: &str = "blocklist.txt";
const LOCAL_BLOCKLIST_FILE_NAME: &str = "local-blocklist.txt";

#[derive(Clone, PartialEq, Copy)]
pub enum FilterType {
    Global,
    Local,
    None
}

#[derive(PartialEq)]
pub enum SearchResult {
    Found,
    NotFound,
    LocalName
}

#[derive(Clone)]
pub struct FilterRow {
    pub name: String,
    pub requests : u64,
    pub enable : bool,
    pub filter_type: i32,
}

#[derive(PartialEq)]
pub enum FilterUpdateStatus {
    Unchanged,
    Updated,
    Reloaded,
    DownloadError
}

pub struct FilterConfig {
}

impl FilterConfig {
    const URL_BLOCKLIST: &str = "https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt";
    const REMOVE_PARAM_TAG: &str = "$removeparam";
    const BAD_PARAM_TAG: &str = "$badfilter";
    const THIRD_PARTY_TAG: &str = "$third-party";
    const DOMAIN_TAG: &str = "$domain";

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

    //pub fn set_update_status(&mut self, status: FilterUpdateStatus) {
    //    self.update_status = status;
    //}

    //pub fn is_updated(&self) -> bool {
    //    return self.update_status == FilterUpdateStatus::Updated;
    //}

    //pub fn is_reloaded(&self) -> bool {
    //    return self.update_status == FilterUpdateStatus::Reloaded;
    //}

    //pub fn is_error(&self) -> bool {
    //    return self.update_status == FilterUpdateStatus::DownloadError;
    //}

    pub fn get_num_entries(conn: &Connection) -> usize {
        return sqldb_get_filter_rows_count(conn);
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

    pub fn set_enable(conn: &Connection, name: &String, enable: bool) -> bool {
        log_debug!("Enable name: '{}' status: {}\n", name, enable);
        let res = sqldb_set_name_enable(conn, name, enable);
        if res.is_err() {
            return false;
        }

        return true;
    }

    pub fn clear_enable(conn: &Connection) {
        let _ = sqldb_clear_all_enable(conn);
    }
    /*
    pub fn search_wildcard(&mut self, name: &String) -> (SearchResult, u64) {
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
                    return (SearchResult::NotFound, 0);            
                }
                log_debug!("FOUND: wildcard: {} name: {}\n", key, name);
                let reject_count = stat.inc_request_count();
                return (SearchResult::Found, reject_count);
            }
        }

        return (SearchResult::NotFound, 0);
    }
    */

    pub fn get_local_name(conn_db: &Connection, key: &String) -> Option<Ipv4Addr> {
        let res = sqldb_get_ip_for_local_name(conn_db, key);
        if res.is_err() {
            return None;
        }
        return Some(res.unwrap());
    }

    pub fn set_local_name(conn_db: &Connection, name: &String, ip_addr: Ipv4Addr) {
        let res = sqldb_insert_local_name(conn_db, name, &ip_addr.to_string());
        if res.is_err() {
            let e: rusqlite::Error = res.err().unwrap();
            if e.sqlite_error_code().unwrap() == rusqlite::ErrorCode::ConstraintViolation {
                let res = sqldb_update_local_name(conn_db, name, &ip_addr.to_string());
                if res.is_err() {
                    log_error!("Unable to update local name: {}\n", e);    
                }
            } else {
                log_error!("Unable to insert local name: {}\n", e);
            }
        }
    }

    pub fn remove_local_name(conn_db: &Connection, name: &String) {
        let res = sqldb_remove_local_name(conn_db, name);
        if res.is_err() {
            log_error!("Unable to delete local name: {}\n", res.err().unwrap());
        }
    }

    pub fn search(conn: &Connection, name: &String, resolve_local: bool, local_domain: &String) -> (SearchResult, u64) {
        if resolve_local {
            let parts: Vec<&str> = name.split('.').collect();
            if parts[parts.len() - 1] == local_domain {
                return (SearchResult::LocalName, 0);
            }
        }

        let res = sqldb_is_name_blocked(conn, name);
        if res.is_err() {
            return (SearchResult::NotFound, 0);
        }
        let reject_count = res.unwrap();

        return (SearchResult::Found, reject_count);
    }

    pub fn reload_filter(conn: &mut Connection) -> Result<(), std::io::Error> {
        log_debug!("Filter: Clean filter table\n");
        let res = sqldb_clean_filter(conn);
        if res.is_err() {
            log_error!("Filter: Unable to clean filter table. Stop update filter\n");
            return Err(Error::new(ErrorKind::InvalidData, "Unable to clean filter table"));
        }

        return FilterConfig::create_black_list_map(conn);
    }

    pub fn create_black_list_map(conn_db: &mut Connection) -> Result<(), std::io::Error> {
        let filter_files: Vec<&str> = Vec::from([BLOCKLIST_FILE_NAME, LOCAL_BLOCKLIST_FILE_NAME]);

        for index in 0..filter_files.capacity() {
            log_info!("Parse {} block list\n", filter_files[index]);
            let open_result = std::fs::File::open(filter_files[index]);
            if open_result.is_err() {
                return Err(Error::new(ErrorKind::NotFound, format!("Unable to open {}", filter_files[index])));
            }
            let file = open_result.unwrap();
            let reader = io::BufReader::new(file);

            let res = conn_db.transaction();
            if res.is_err() {
                return Err(Error::new(ErrorKind::InvalidData, "Unable to create transaction"));
            }
            let transact = res.unwrap();

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
                if single_line.find('*').is_some() && index != 2 {
                    log_debug!("Wild card found: {}\n", single_line);
                    //if single_line.contains("[") {
                    //    continue;
                    //}
                    //log_debug!("Add wildcard: {}\n", single_line);
                    //if self.ads_provider_wildcard.insert(single_line.clone(), Statistics::new(ftype)).is_some() {
                    //    log_info!("Dublicated wildcard {}\n", single_line);
                    //}
                    continue;
                }

                if ftype == FilterType::Global || ftype == FilterType::Local {
                    let res = sqldb_insert_filter_entry(&transact, &single_line, ftype);
                    if res.is_ok() {
                        total_lines += 1;
                    }
                } 
            }
            let res = transact.commit();
            if res.is_err() {
                log_error!("Filter: Transaction failed\n");
            }

            log_info!("Total {} lines\n", total_lines);
        }
        log_info!("Full list size: {}\n", sqldb_get_filter_rows_count(conn_db));

        Ok(())
    }
}

impl Drop for FilterConfig {
    fn drop(&mut self) {
        log_debug!("Drop filter\n");
    }
}
