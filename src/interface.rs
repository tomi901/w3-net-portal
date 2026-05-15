use pnet::{datalink, ipnetwork::IpNetwork};

use std::{collections::HashSet, io, net::Ipv4Addr};

use pnet::datalink::NetworkInterface;

pub(crate) struct InterfaceInfo {
    pub(crate) iface: NetworkInterface,
    pub(crate) src_ip: Ipv4Addr,
    pub(crate) bcast_ip: Ipv4Addr,
}

impl InterfaceInfo {
    pub fn new(iface: NetworkInterface) -> io::Result<Self> {
        let (src_ip, bcast_ip) = iface
            .ips
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

pub fn get_ifaces(filter: &[String], verbose: bool) -> Result<Vec<NetworkInterface>, io::Error> {
    let mut ifaces = datalink::interfaces();
    if filter.is_empty() {
        ifaces.retain(is_interface_valid);
        return Ok(ifaces);
    }

    let mut faces_to_include: HashSet<&str> = filter.iter().map(|t| t.as_str()).collect();
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
            format!("invalid interface/s: {:?}", faces_to_include),
        ));
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
    std::path::Path::new("/sys/class/net")
        .join(&iface.name)
        .join("bridge")
        .exists()
}
