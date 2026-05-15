use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct ForwarderConfig {
    pub port: u16,
    pub ifaces: Vec<String>,
    pub peers: Vec<Ipv4Addr>,
    pub verbose: bool,
}

impl ForwarderConfig {
    pub fn new(port: u16, ifaces: Vec<String>) -> Self {
        Self {
            port,
            ifaces,
            peers: Vec::new(),
            verbose: false,
        }
    }
}
