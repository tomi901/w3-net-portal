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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WC3_PORT;

    #[test]
    fn config_basics() {
        let ifaces = vec!["enp42s0".to_string()];
        let c = ForwarderConfig::new(WC3_PORT, ifaces.clone());
        assert_eq!(c.port, WC3_PORT);
        assert_eq!(c.ifaces, ifaces);
        assert!(c.peers.is_empty());
    }
}
