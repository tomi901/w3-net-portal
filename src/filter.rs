use std::{collections::HashSet, net::Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Relay,
    SkipNotBroadcast,
    SkipRemoteOrigin,
    SkipWrongPort,
}

impl Decision {
    pub fn should_skip(&self) -> bool {
        !matches!(self, Decision::Relay)
    }
}

pub fn decide_relay(
    pkt_src: Ipv4Addr,
    pkt_dst: Ipv4Addr,
    dst_port: u16,
    expected_port: u16,
    iface_bcast: Ipv4Addr,
    local_ips: &HashSet<Ipv4Addr>,
) -> Decision {
    if dst_port != expected_port {
        return Decision::SkipWrongPort;
    }

    // Only relay broadcast-destined packets — these are the WC3 discovery
    // announcements we want to rewrite to unicast. Skip unicasts; those
    // are already addressed to a specific host and Wine handles them.
    if !pkt_dst.is_broadcast() && pkt_dst != iface_bcast {
        return Decision::SkipNotBroadcast;
    }

    // Only relay broadcasts that originated on this host. Broadcasts from
    // a remote peer's WC3 will also cross our wire (the AP bridges them);
    // their own portal already unicasts them to us, so re-relaying would
    // double-deliver.
    if !local_ips.contains(&pkt_src) {
        return Decision::SkipRemoteOrigin;
    }

    Decision::Relay
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 1);
    const TEST_REMOTE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 100);
    const TEST_IFACE_BROADCAST: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 255);
    const TEST_LIMITED_BROADCAST: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);
    const TEST_LOCAL_IPS: [Ipv4Addr; 3] = [
        Ipv4Addr::new(192, 168, 100, 1),
        Ipv4Addr::new(192, 168, 100, 2),
        Ipv4Addr::new(192, 168, 100, 3),
    ];
    const TEST_PORT: u16 = 10_000;

    fn local_ips() -> HashSet<Ipv4Addr> {
        TEST_LOCAL_IPS.into_iter().collect()
    }

    fn run(src: Ipv4Addr, dst: Ipv4Addr, port: u16) -> Decision {
        decide_relay(src, dst, port, TEST_PORT, TEST_IFACE_BROADCAST, &local_ips())
    }

    #[test]
    fn relays_with_correct_data() {
        let decision = run(TEST_LOCAL_IP, TEST_IFACE_BROADCAST, TEST_PORT);
        assert_eq!(decision, Decision::Relay);
    }

    #[test]
    fn skips_non_tracked_port() {
        let decision = run(TEST_LOCAL_IP, TEST_IFACE_BROADCAST, TEST_PORT + 1);
        assert_eq!(decision, Decision::SkipWrongPort);
    }

    #[test]
    fn skips_non_broadcast_port() {
        let decision = run(TEST_LOCAL_IP, TEST_REMOTE_IP, TEST_PORT);
        assert_eq!(decision, Decision::SkipNotBroadcast);
    }

    #[test]
    fn relays_limited_broadcast() {
        let decision = run(TEST_LOCAL_IP, TEST_LIMITED_BROADCAST, TEST_PORT);
        assert_eq!(decision, Decision::Relay);
    }

    #[test]
    fn skips_remote_origin_bcast() {
        let decision = run(TEST_REMOTE_IP, TEST_IFACE_BROADCAST, TEST_PORT);
        assert_eq!(decision, Decision::SkipRemoteOrigin);
    }

    #[test]
    fn skips_remote_origin_limited_bcast() {
        let decision = run(TEST_REMOTE_IP, TEST_LIMITED_BROADCAST, TEST_PORT);
        assert_eq!(decision, Decision::SkipRemoteOrigin);
    }
}
