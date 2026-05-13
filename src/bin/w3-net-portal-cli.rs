//! CLI entry point: sniff WC3 LAN broadcasts on a local interface and
//! re-emit each one as a UDP unicast to one or more peer IPs.

use std::net::Ipv4Addr;

use clap::Parser;
use w3_portal::{Forwarder, ForwarderConfig, WC3_PORT};

#[derive(Parser, Debug)]
#[command(
    name = "w3-net-portal-cli",
    about = "WC3 LAN-discovery relay (broadcast -> unicast)",
    long_about = "Sniffs UDP/6112 broadcasts on --iface and forwards each one \
                  as a UDP unicast (same payload, same source port) to every \
                  --peer. Runs on every host that participates in the LAN \
                  game. Wine on the peer machine receives the resulting \
                  unicast on its normal 0.0.0.0:6112 socket — no port \
                  binding here, so no conflict with Wine. Requires \
                  CAP_NET_RAW (sudo, or `setcap cap_net_raw+ep` on the binary).",
    version,
)]
struct Cli {
    /// UDP port (Warcraft III uses 6112).
    #[arg(short, long, default_value_t = WC3_PORT)]
    port: u16,

    /// Local interface to sniff broadcasts on (e.g. enp42s0, wlan0).
    #[arg(short, long, value_name = "NAME")]
    iface: String,

    /// Peer IP to relay broadcasts to. Repeatable; must be reachable via the
    /// same subnet as --iface. Example: --peer 192.168.100.102
    #[arg(short = 'P', long = "peer", value_name = "IP", required = true, num_args = 1..)]
    peers: Vec<Ipv4Addr>,

    /// Verbose logging: print every captured / skipped / forwarded packet.
    #[arg(short, long)]
    verbose: bool,
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let cfg = ForwarderConfig {
        port: cli.port,
        iface: cli.iface,
        peers: cli.peers,
        verbose: cli.verbose,
    };
    Forwarder::new(cfg).run().map_err(|e| format!("forwarder: {e}"))
}

fn main() -> Result<(), String> {
    run()
}
