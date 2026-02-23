use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy)]
pub struct LocalConfig {
    bind_addr: std::net::SocketAddr,
    dns_srv_addr: std::net::SocketAddr,
    use_doh: bool,
}

impl LocalConfig {
    pub fn new() -> LocalConfig {
        LocalConfig
        {
            bind_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 2053),
            //bind_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53),
            /* Default google DNS */
            dns_srv_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            /* Use DNS over HTTPS */
            use_doh: true,
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
    }

    pub fn get_dns_srv_addr(&self) -> std::net::SocketAddr {
        return self.dns_srv_addr;
    }

    pub fn set_dns_srv_addr(&mut self, addr: std::net::SocketAddr) -> bool {
        self.dns_srv_addr = addr;
        return true;
    }
}