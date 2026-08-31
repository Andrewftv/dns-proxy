use std::collections::BTreeMap;
use std::net::{SocketAddr, IpAddr};
use crate::log_debug;

pub struct DNSActyvityMonitor {
    activity_list: BTreeMap<String, Vec<IpAddr>>
}

impl DNSActyvityMonitor {
    pub fn new() -> DNSActyvityMonitor {
        DNSActyvityMonitor {
            activity_list: BTreeMap::new()
        }
    }

    pub fn add_requested_name(&self, name: &String, ip_addr: &SocketAddr) {
        log_debug!("Name: {} asked by {}\n", name, ip_addr.ip().to_string());
        let opt = self.activity_list.get(name);
        if opt.is_none() {
            
        }
    }
}
