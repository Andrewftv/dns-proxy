use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use crate::{log_error, log_debug, log_info};
use crate::tpool::TPoolStat;

pub struct LocalConfig {
    /* Config part */
    bind_addr: std::net::SocketAddr,
    dns_srv_addr: std::net::SocketAddr,
    use_doh: bool,
    /* Statistics part */
    tpool_stat: TPoolStat
}

impl LocalConfig {
    const CFG_FILE_NAME: &str = "config.json";
    const LISTEN_ADDR_NAME: &str = "listen_address";
    const LISTEN_PORT_NAME: &str = "listen_port";
    const DNS_SERVER_NAME: &str = "DNS_server";
    const USE_DOH_NAME: &str = "use_DoH";
    const YES_VALUE: &str = "yes";
    const NO_VALUE: &str = "no";

    pub fn new() -> LocalConfig {
        /* Default config */
        let tpool_stat =  TPoolStat::new(4);

        LocalConfig
        {
            bind_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53),
            /* Default google DNS */
            dns_srv_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            /* Use DNS over HTTPS */
            use_doh: true,
            tpool_stat
        }
    }

    pub fn set_tpool_stat(&mut self, stat: &TPoolStat) {
        self.tpool_stat = stat.clone();
    }

    pub fn get_tpool_workers(&self) -> usize {
        return self.tpool_stat.get_workers();
    }

    pub fn is_busy(&self, id:usize) -> bool {
        return self.tpool_stat.get_busy(id);
    }

    pub fn get_jobs(&self, id: usize) -> u64 {
        return self.tpool_stat.get_jobs(id);
    }

    pub fn write_config(&self) -> bool {

        let mut data: String = "{\n".to_string();
        data += "    \"listen_address\": ";
        data += "\"";
        data += &self.bind_addr.ip().to_string();
        data += "\",\n";

        data += "    \"listen_port\": ";
        data += "\"";
        data += &self.bind_addr.port().to_string();
        data += "\",\n";

        data += "    \"DNS_server\": ";
        data += "\"";
        data += &self.dns_srv_addr.ip().to_string();
        data += "\",\n";

        data += "    \"use_DoH\": ";
        data += "\"";
        data += if self.use_doh == true {LocalConfig::YES_VALUE} else {LocalConfig::NO_VALUE};
        data += "\"\n"; 

        data += "}";

        log_debug!("{}\n", data);

        let res = fs::write(LocalConfig::CFG_FILE_NAME, data);
        if res.is_err() {
            log_error!("Error write configuration file\n");
            return false;
        }

        return true;
    }

    fn set_config_values(&mut self, name: &str, value: &str) -> bool {
        match name {
            LocalConfig::LISTEN_ADDR_NAME => {
                let res = Ipv4Addr::from_str(value);
                if res.is_err() {
                    log_error!("Invalid IP address: {}\n", value);
                    return false;
                }
                let ip = res.unwrap();
                self.bind_addr.set_ip(IpAddr::V4(ip));
            },
            LocalConfig::LISTEN_PORT_NAME => {
                let res = value.parse::<u16>();
                if res.is_err() {
                    log_error!("Invalid port: {}\n", value);
                    return false;
                }
                let port = res.unwrap();
                self.bind_addr.set_port(port);
            },
            LocalConfig::DNS_SERVER_NAME => {
                let res = Ipv4Addr::from_str(value);
                if res.is_err() {
                    log_error!("Invalid DNS server IP address: {}\n", value);
                    return false;
                }
                let ip = res.unwrap();
                self.dns_srv_addr.set_ip(IpAddr::V4(ip));
                self.dns_srv_addr.set_port(53);
            },
            LocalConfig::USE_DOH_NAME => {
                if value == LocalConfig::YES_VALUE {
                    self.use_doh = true;
                } else if value == LocalConfig::NO_VALUE {
                    self.use_doh = false;
                } else {
                    log_error!("Invalid value\n");
                }
            },
            _ => {
                log_error!("Unknown config: {}\n", name);
            }
        }
        return true;
    }

    pub fn read_config(&mut self) -> bool {
        log_debug!("Reading configuration\n");
        let res = fs::read_to_string("config.json");
        if res.is_err() {
            log_error!("Unable to open configuration file\n");
            return false;
        }
        let cfg_file = res.unwrap();
        let mut opt = cfg_file.find('{');
        if opt.is_none() {
            log_error!("Invalid json file. There is no \"{\"\n");
            return false;
        }
        let mut name: &str;
        let mut value: &str;
        let mut curr_pos = opt.unwrap() + 1;

        while let Some(pos) = cfg_file[curr_pos..].find('"') {
            let begin = pos + curr_pos + 1;
            opt = cfg_file[begin..].find('"');
            if opt.is_none() {
                log_error!("Invalid json file\n");
                return false;
            }
            let end = opt.unwrap() + begin;
            name = &cfg_file[begin..end];

            curr_pos = end + 1;

            if cfg_file[curr_pos..].find(':').is_none() {
                log_error!("Delimeter is not found\n");
                return false;
            }
            opt = cfg_file[curr_pos..].find('"');
            if opt.is_none() {
                log_error!("Invalid json file\n");
                return false;
            }
            let begin = opt.unwrap() + curr_pos + 1;
            opt = cfg_file[begin..].find('"');
            if opt.is_none() {
                log_error!("Invalid json file\n");
                return false;
            }
            let end = opt.unwrap() + begin;
            value = &cfg_file[begin..end];

            log_info!("name: {} value: {}\n", name, value);

            curr_pos = end + 1;

            self.set_config_values(name, value);
        }
        log_debug!("Reading configuration done\n");
        return true;
    }

    pub fn get_bind_addr(&self) -> std::net::SocketAddr {
        return self.bind_addr;
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

    pub fn set_dns_srv_addr(&mut self, addr: std::net::SocketAddr) {
        self.dns_srv_addr = addr;
    }
}