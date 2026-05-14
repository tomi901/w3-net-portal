//! Warcraft III LAN-discovery relay.
//!
//! Wine's winsock does not reliably deliver UDP broadcasts to WC3's bound
//! socket, even when broadcasts physically reach the host's NIC. The standard
//! workaround (Lancraft, udp-broadcast-relay) is to rewrite the destination:
//! capture each local WC3 broadcast on the wire and re-emit it as a regular
//! UDP **unicast** addressed at the other player's IP. Wine on the receiving
//! host happily reads it via its normal `0.0.0.0:6112` socket — unicasts are
//! delivered straight up the stack with no broadcast handling involved.
//!
//! Implementation:
//! - AF_PACKET on `cfg.iface` to sniff every UDP/<port> frame on the wire,
//!   in both directions, without binding the port (no Wine conflict).
//! - pnet "Layer 4" raw IPv4/UDP socket to emit the unicast — lets us
//!   preserve the original source port (WC3 expects source 6112).
//!
//! Requires `CAP_NET_RAW` (sudo, or `setcap cap_net_raw+ep` on the binary).

use std::collections::HashSet;
use std::{io, thread};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use pnet::datalink::{self, Channel, DataLinkReceiver, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::transport::{
    TransportChannelType, TransportProtocol, TransportSender, transport_channel,
};

pub const WC3_PORT: u16 = 6112;

const UDP_HDR_LEN: usize = 8;

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

pub struct Forwarder {
    cfg: ForwarderConfig,
}

impl Forwarder {
    pub fn new(cfg: ForwarderConfig) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &ForwarderConfig {
        &self.cfg
    }

    pub fn run(self) -> io::Result<()> {
        run(self.cfg)
    }
}

struct InterfaceInfo {
    iface: NetworkInterface,
    src_ip: Ipv4Addr,
    bcast_ip: Ipv4Addr,
}

impl InterfaceInfo {
    pub fn new(iface: NetworkInterface) -> io::Result<Self> {
        let (src_ip, bcast_ip) = iface.ips
            .iter()
            .find_map(|n| match n {
                IpNetwork::V4(v4) => Some((v4.ip(), v4.broadcast())),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("interface {:?} has no IPv4 address", &iface.name),
                )
            })?;

        Ok(Self {
            iface,
            src_ip,
            bcast_ip,
        })
    }

    pub fn name(&self) -> &str {
        &self.iface.name
    }
}

pub fn run(cfg: ForwarderConfig) -> io::Result<()> {
    if cfg.peers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "need at least one --peer to forward to",
        ));
    }

    let ifaces = get_ifaces(&cfg.ifaces, cfg.verbose)?;
    if ifaces.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "No interfaces available to connect"));
    }

    let ifaces_data: Vec<InterfaceInfo> = ifaces
        .into_iter()
        .map(InterfaceInfo::new)
        .collect::<io::Result<_>>()?;

    // Ensure we get ALL local ips, since other interfaces can bridge to others
    let local_ips: Arc<HashSet<Ipv4Addr>> = Arc::new(datalink::interfaces()
        .iter()
        .flat_map(|i| {
            i.ips.iter().filter_map(|n| match n {
                IpNetwork::V4(v4) => Some(v4.ip()),
                _ => None,
            })
        })
        .collect());

    let mut thread_handles = vec![];
    let cfg = Arc::new(cfg);
    for iface in ifaces_data.into_iter() {
        let (_eth_tx, rx) = match datalink::channel(&iface.iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("interface {:?} returned a non-ethernet channel", iface.name()),
                ));
            }
            Err(e) => return Err(e),
        };

        // Keep _udp_rx in scope: TransportSender / TransportReceiver share an
        // underlying raw socket and dropping the receiver may close it.
        let (udp_tx, _udp_rx) = transport_channel(
            4096,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp)),
        )?;

        if cfg.verbose {
            eprintln!(
                "(Thread) w3-portal: sniffing UDP/{} on {} (local {}, bcast {})",
                cfg.port, iface.name(), iface.src_ip, iface.bcast_ip
            );
        }

        let cfg = Arc::clone(&cfg);
        let local_ips_ref = Arc::clone(&local_ips);
        let handle = thread::spawn(move || {
            sniff_loop(rx, udp_tx, &cfg, iface.src_ip, iface.bcast_ip, &local_ips_ref)
        });
        thread_handles.push(handle);
    }

    eprintln!(" -> peers {:?}", cfg.peers);

    for handle in thread_handles {
        handle.join()
            .map_err(|e| io::Error::new(
                io::ErrorKind::Other,
                format!("Thread panicked: {:?}", e)
            ))??;
    }

    Ok(())
}

fn get_ifaces(filter: &[String], verbose: bool) -> Result<Vec<NetworkInterface>, io::Error> {
    let mut ifaces = datalink::interfaces();
    if filter.is_empty() {
        ifaces.retain(is_interface_valid);
        return Ok(ifaces);
    }

    let mut faces_to_include: HashSet<&str> = filter
        .iter()
        .map(|t| t.as_str())
        .collect();
    let mut result = vec![];
    for iface in ifaces {
        let iface_name = &iface.name[..];
        if !faces_to_include.contains(iface_name) {
            continue;
        }

        if !is_interface_valid(&iface) {
            if verbose {
                eprintln!(
                    "Invalid --iface ({}) has to be up, not loopback, not point-to-point and ipv4. Only include your ethernet or wi-fi",
                    iface_name
                );
            }
            continue;
        }

        faces_to_include.remove(iface_name);
        result.push(iface);
    }

    if !faces_to_include.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("invalid interface/s: {:?}", faces_to_include)
        ))
    }

    Ok(result)
}

fn is_interface_valid(iface: &NetworkInterface) -> bool {
    iface.is_up()
        && !iface.is_loopback()
        && !iface.is_point_to_point()
        && iface.ips.iter().any(|ip| ip.is_ipv4())
        && !is_interface_bridge(iface)
}

fn is_interface_bridge(iface: &NetworkInterface) -> bool {
    std::path::Path::new("/sys/class/net").join(&iface.name).join("bridge").exists()
}

fn sniff_loop(
    mut rx: Box<dyn DataLinkReceiver>,
    mut udp_tx: TransportSender,
    cfg: &ForwarderConfig,
    src_ip: Ipv4Addr,
    iface_bcast: Ipv4Addr,
    local_ips: &HashSet<Ipv4Addr>,
) -> io::Result<()> {
    loop {
        let frame = rx.next()?;
        let Some(eth) = EthernetPacket::new(frame) else { continue };
        if eth.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }
        let Some(ip) = Ipv4Packet::new(eth.payload()) else { continue };
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            continue;
        }
        let Some(udp) = UdpPacket::new(ip.payload()) else { continue };
        if udp.get_destination() != cfg.port {
            continue;
        }

        let pkt_src = ip.get_source();
        let pkt_dst = ip.get_destination();
        let src_port = udp.get_source();
        let dst_port = udp.get_destination();

        // Only relay broadcast-destined packets — these are the WC3 discovery
        // announcements we want to rewrite to unicast. Skip unicasts; those
        // are already addressed to a specific host and Wine handles them.
        let is_broadcast = pkt_dst.is_broadcast() || pkt_dst == iface_bcast;
        if !is_broadcast {
            continue;
        }

        // Only relay broadcasts that originated on this host. Broadcasts from
        // a remote peer's WC3 will also cross our wire (the AP bridges them);
        // their own portal already unicasts them to us, so re-relaying would
        // double-deliver.
        if !local_ips.contains(&pkt_src) {
            if cfg.verbose {
                eprintln!(
                    "skip remote-origin {pkt_src}:{src_port} -> {pkt_dst}:{dst_port}"
                );
            }
            continue;
        }

        let payload = udp.payload();
        if cfg.verbose {
            eprintln!(
                "capture {pkt_src}:{src_port} -> {pkt_dst}:{dst_port} ({} bytes)",
                payload.len()
            );
        }

        for peer in &cfg.peers {
            match send_unicast(&mut udp_tx, payload, src_ip, src_port, *peer, dst_port)
            {
                Ok(n) => {
                    if cfg.verbose {
                        eprintln!(
                            " -> {peer}:{dst_port} unicast ({n} bytes, src port {src_port})"
                        );
                    }
                }
                Err(e) => eprintln!(" send {peer}: {e}"),
            }
        }
    }
}

fn send_unicast(
    tx: &mut TransportSender,
    payload: &[u8],
    src_ip: Ipv4Addr,
    src_port: u16,
    peer: Ipv4Addr,
    dst_port: u16,
) -> io::Result<usize> {
    let total = UDP_HDR_LEN + payload.len();
    let mut buf = vec![0u8; total];
    {
        let mut udp = MutableUdpPacket::new(&mut buf).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(total as u16);
        udp.set_payload(payload);
        // Source IP for the checksum is what the kernel will pick when
        // routing to `peer`. For a peer on `iface`'s subnet that is `src_ip`;
        // if the user gives a peer on a different subnet the kernel may pick
        // a different source IP and this checksum will mismatch — same-subnet
        // is the only documented configuration.
        let cksum =
            pnet::packet::udp::ipv4_checksum(&udp.to_immutable(), &src_ip, &peer);
        udp.set_checksum(cksum);
    }
    let pkt = UdpPacket::new(&buf).unwrap();
    tx.send_to(pkt, IpAddr::V4(peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_basics() {
        let ifaces = vec!["enp42s0".to_string()];
        let c = ForwarderConfig::new(WC3_PORT, ifaces.clone());
        assert_eq!(c.port, WC3_PORT);
        assert_eq!(c.ifaces, ifaces);
        assert!(c.peers.is_empty());
    }
}
