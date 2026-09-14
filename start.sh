#!/usr/bin/env bash

cd ~/rust-vpn || exit 1

# Create the tmux session and start the RVPN server
tmux new-session -s rvpn -c ~/rust-vpn "sudo ./target/release/rvpn-server server.toml"
