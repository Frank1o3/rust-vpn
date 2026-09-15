#!/usr/bin/env bash

cd ~/rust-vpn || exit 1

# Remove existing rvpn tmux session if it exists
if tmux has-session -t rvpn 2>/dev/null; then
    tmux kill-session -t rvpn
fi

# Start the VPN server in a fresh tmux session
tmux new-session -d -s rvpn -c ~/rust-vpn \
    "sudo ./target/release/rvpn-server server.toml"