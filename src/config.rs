use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use rusqlite::Connection;
use crate::confdb::{sqldb_init_conf_db, sqldb_get_global_config_value, sqldb_update_global_config_value};
use crate::{log_error, log_debug, log_info};
use crate::tpool::TPoolStat;
use crate::DnsProxy;

pub struct LocalConfig {
    /* Config part */
    bind_addr: std::net::SocketAddr,
    dns_srv_addr: std::net::SocketAddr,
    use_doh: bool,
    local_dns_enable: bool,
    local_domain_name: String,
    db_conn: Connection,
    /* Statistics part */
    tpool_stat: TPoolStat
}

impl LocalConfig {
    const PRODUCT_VERSION: &str = "1.2";
    pub const LISTEN_ADDR_NAME: &str = "listen_address";
    pub const LISTEN_PORT_NAME: &str = "listen_port";
    pub const DNS_SERVER_NAME: &str = "DNS_server";
    pub const USE_DOH_NAME: &str = "use_DoH";
    pub const YES_VALUE: &str = "yes";
    pub const NO_VALUE: &str = "no";
    pub const LOCAL_DNS_NAME: &str = "local_dns_enable";
    pub const LOCAL_DOMAIN_NAME: &str = "domain_name";
    pub const DNS_PORT_VALUE: u16 = 53;

    pub fn new() -> Result<Self, rusqlite::Error> {
        let res = sqldb_init_conf_db();
        if res.is_err() {
            return Err(res.err().unwrap());
        }
        let conn = res.unwrap();
        Ok(LocalConfig
        {
            bind_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), LocalConfig::DNS_PORT_VALUE),
            /* Default google DNS */
            dns_srv_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), LocalConfig::DNS_PORT_VALUE),
            /* Use DNS over HTTPS */
            use_doh: true,
            local_dns_enable: true,
            local_domain_name: Default::default(),
            tpool_stat: TPoolStat::new(DnsProxy::THREAD_POOL_SIZE),
            db_conn: conn
        })
    }

    pub fn get_db_connection(&mut self) -> &mut Connection {
        return &mut self.db_conn;
    }

    pub fn parse_cmd_params(&mut self) {
        let args: Vec<String> = env::args().collect();
        if args.len() >= 3 {
        for i in 1..args.len() {
            if args[i] == "--port" {
                if i + 1 < args.len() {
                    let res = args[i + 1].parse::<u16>();
                    if res.is_ok() {
                        let port_no: u16 = res.unwrap();
                        log_info!("Set DNS port from command line parameter: {}\n", port_no);
                        self.set_bind_port(port_no, false);
                    }
                    break;
                }
            }
        }
    }
    }

    pub fn get_version_string() -> String {
        return LocalConfig::PRODUCT_VERSION.to_string();
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
            }
            LocalConfig::LISTEN_PORT_NAME => {
                let res = value.parse::<u16>();
                if res.is_err() {
                    log_error!("Invalid port: {}\n", value);
                    return false;
                }
                let port = res.unwrap();
                self.bind_addr.set_port(port);
            }
            LocalConfig::DNS_SERVER_NAME => {
                let res = Ipv4Addr::from_str(value);
                if res.is_err() {
                    log_error!("Invalid DNS server IP address: {}\n", value);
                    return false;
                }
                let ip = res.unwrap();
                self.dns_srv_addr.set_ip(IpAddr::V4(ip));
                self.dns_srv_addr.set_port(53);
            }
            LocalConfig::USE_DOH_NAME => {
                if value == LocalConfig::YES_VALUE {
                    self.use_doh = true;
                } else if value == LocalConfig::NO_VALUE {
                    self.use_doh = false;
                } else {
                    log_error!("Invalid value\n");
                }
            }
            LocalConfig::LOCAL_DNS_NAME => {
                if value == LocalConfig::YES_VALUE {
                    self.local_dns_enable = true;
                } else if value == LocalConfig::NO_VALUE {
                    self.local_dns_enable = false;
                } else {
                    log_error!("Invalid value\n");
                }
            }
            LocalConfig::LOCAL_DOMAIN_NAME => {
                self.local_domain_name = value.to_string();
            }
            _ => {
                log_error!("Unknown config: {}\n", name);
            }
        }
        return true;
    }

    pub fn read_config(&mut self) -> bool {
        log_debug!("Reading configuration\n");
        let mut val: String = Default::default();
        if sqldb_get_global_config_value(&self.db_conn, &LocalConfig::LISTEN_ADDR_NAME.to_string(), &mut val) {
            log_debug!("Read parameter {} value {}\n", LocalConfig::LISTEN_ADDR_NAME, val);
            self.set_config_values(LocalConfig::LISTEN_ADDR_NAME, &val);
        }
        if sqldb_get_global_config_value(&self.db_conn, &LocalConfig::LISTEN_PORT_NAME.to_string(), &mut val) {
            log_debug!("Read parameter {} value {}\n", LocalConfig::LISTEN_PORT_NAME, val);
            self.set_config_values(LocalConfig::LISTEN_PORT_NAME, &val);
        }
        if sqldb_get_global_config_value(&self.db_conn, &LocalConfig::DNS_SERVER_NAME.to_string(), &mut val) {
            log_debug!("Read parameter {} value {}\n", LocalConfig::DNS_SERVER_NAME, val);
            self.set_config_values(LocalConfig::DNS_SERVER_NAME, &val);
        }
        if sqldb_get_global_config_value(&self.db_conn, &LocalConfig::USE_DOH_NAME.to_string(), &mut val) {
            log_debug!("Read parameter {} value {}\n", LocalConfig::USE_DOH_NAME, val);
            self.set_config_values(LocalConfig::USE_DOH_NAME, &val);
        }
        if sqldb_get_global_config_value(&self.db_conn, &LocalConfig::LOCAL_DNS_NAME.to_string(), &mut val) {
            log_debug!("Read parameter {} value {}\n", LocalConfig::LOCAL_DNS_NAME, val);
            self.set_config_values(LocalConfig::LOCAL_DNS_NAME, &val);
        }
        if sqldb_get_global_config_value(&self.db_conn, &LocalConfig::LOCAL_DOMAIN_NAME.to_string(), &mut val) {
            log_debug!("Read parameter {} value {}\n", LocalConfig::LOCAL_DOMAIN_NAME, val);
            self.set_config_values(LocalConfig::LOCAL_DOMAIN_NAME, &val);
        }
        return true;
    }

    pub fn set_bind_port(&mut self, port: u16, keep_it: bool) {
        self.bind_addr.set_port(port);
        if keep_it {
            log_debug!("Set param {} to {}\n", LocalConfig::LISTEN_PORT_NAME, port);
            sqldb_update_global_config_value(&self.db_conn, &LocalConfig::LISTEN_PORT_NAME.to_string(), &port.to_string());
        }
    }

    pub fn get_bind_addr(&self) -> std::net::SocketAddr {
        return self.bind_addr;
    }

    pub fn get_use_doh(&self) -> bool {
        return self.use_doh;
    }

    pub fn set_use_doh(&mut self, value: bool) {
        self.use_doh = value;
        let val = if value {"yes"} else {"no"};
        log_debug!("Set param {} to {}\n", LocalConfig::USE_DOH_NAME, val);
        sqldb_update_global_config_value(&self.db_conn, &LocalConfig::USE_DOH_NAME.to_string(), &val.to_string());
    }

    pub fn get_dns_srv_addr(&self) -> std::net::SocketAddr {
        return self.dns_srv_addr;
    }

    pub fn set_dns_srv_addr(&mut self, addr: std::net::SocketAddr) {
        self.dns_srv_addr = addr;
        log_debug!("Set param {} to {}\n", LocalConfig::DNS_SERVER_NAME, addr.to_string());
        sqldb_update_global_config_value(&self.db_conn, &LocalConfig::DNS_SERVER_NAME.to_string(), &addr.to_string());
    }

    pub fn set_local_dns_enable(&mut self, enable: bool) {
        self.local_dns_enable = enable;
        let val = if enable {"yes"} else {"no"};
        log_debug!("Set param {} to {}\n", LocalConfig::LOCAL_DNS_NAME, val);
        sqldb_update_global_config_value(&self.db_conn, &LocalConfig::LOCAL_DNS_NAME.to_string(), &val.to_string());
    }

    pub fn get_local_dns_enable(&self) -> bool {
        return self.local_dns_enable;
    }

    pub fn set_local_domain_name(&mut self, domain_name: &String) {
        self.local_domain_name = domain_name.to_string();
        sqldb_update_global_config_value(&self.db_conn, &LocalConfig::LOCAL_DOMAIN_NAME.to_string(), domain_name);
    }

    pub fn get_local_domain_name(&self) -> String {
        return self.local_domain_name.clone();
    }
}