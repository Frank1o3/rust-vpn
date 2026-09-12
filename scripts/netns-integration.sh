#!/usr/bin/env bash
# Requires root, iproute2, /dev/net/tun, ping, and nft (only for NAT coverage).
# It models a laptop server and desktop client on separate Linux hosts.
set -euo pipefail

server_ns="rvpn-it-server"
client_ns="rvpn-it-client"
server_cfg="$(mktemp)"
client_cfg="$(mktemp)"
psk="3e0f85e0f68e241b1b52d2c5429bf41a6c85845b6f0aa7b8c8d905723f917cc6"
server_pid=""
client_pid=""

cleanup() {
  [[ -n "$client_pid" ]] && kill "$client_pid" 2>/dev/null || true
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
  ip netns del "$client_ns" 2>/dev/null || true
  ip netns del "$server_ns" 2>/dev/null || true
  rm -f "$server_cfg" "$client_cfg"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
command -v ip >/dev/null
command -v ping >/dev/null
[[ -c /dev/net/tun ]] || { echo "/dev/net/tun is unavailable" >&2; exit 1; }

cargo build --quiet -p rvpn-server -p rvpn-client
ip netns add "$server_ns"
ip netns add "$client_ns"
ip link add rvpn-it-s type veth peer name rvpn-it-c
ip link set rvpn-it-s netns "$server_ns"
ip link set rvpn-it-c netns "$client_ns"
ip -n "$server_ns" addr add 192.0.2.1/24 dev rvpn-it-s
ip -n "$client_ns" addr add 192.0.2.2/24 dev rvpn-it-c
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$server_ns" link set rvpn-it-s up
ip -n "$client_ns" link set rvpn-it-c up

cat >"$server_cfg" <<EOF
bind = "192.0.2.1:9000"
pre_shared_key = "$psk"
[interface]
name = "rvpn-server0"
address = "10.42.0.1/24"
[[peers]]
name = "desktop"
pre_shared_key = "$psk"
allowed_ips = ["10.42.0.2/32"]
EOF
cat >"$client_cfg" <<EOF
server = "192.0.2.1:9000"
pre_shared_key = "$psk"
[interface]
name = "rvpn-client0"
address = "10.42.0.2/24"
EOF

ip netns exec "$server_ns" target/debug/rvpn-server "$server_cfg" & server_pid=$!
sleep 0.2
ip netns exec "$client_ns" target/debug/rvpn-client "$client_cfg" & client_pid=$!
sleep 3
ip netns exec "$client_ns" ping -c 3 -W 1 10.42.0.1
echo "netns integration test passed"
