#!/usr/bin/env bash
set -euo pipefail

BIN="$(dirname "$0")/w3-net-portal-cli"

cat <<EOF

This will grant CAP_NET_RAW to:
  $BIN
This lets the binary open raw network sockets (sniff frames, send raw
UDP) without running as root each time. It does NOT make the binary
setuid; the capability is bound to this specific file and disappears
if the file is moved, replaced, or rebuilt.

Equivalent of running:
  sudo setcap cap_net_raw+ep "$BIN"

EOF

read -rp "Proceed? [y/N] " ans
[[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }

sudo setcap cap_net_raw+ep "$BIN"
echo "Done. Verify with: getcap '$BIN'"