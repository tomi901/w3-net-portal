cargo build --release
sudo setcap cap_net_raw,cap_net_admin+ep ./target/release/w3-net-portal-cli
