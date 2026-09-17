#!/usr/bin/env bash

cargo build --release -p rvpn-client
sudo setcap cap_net_admin,cap_net_raw+eip ./target/release/rvpn-client
./target/release/rvpn-client