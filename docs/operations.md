# Deployment and operations

## Privileges and build

Linux TUN/TAP creation needs `CAP_NET_ADMIN`. The server also needs permission
to configure forwarding and firewall rules when forwarding is enabled.

```sh
cargo build --release -p rvpn-server -p rvpn-client
sudo ./target/release/rvpn-server server.toml
sudo ./target/release/rvpn-client rvpn-setup/client-pc-laptop.toml
```

Stop with `Ctrl-C` and wait for `restoring host network state` before starting
another instance.

## Verify a connection

```sh
ping -c 3 10.42.0.1
ping -6 -c 3 fd42::1
ip route get 1.1.1.1
```

In IPv4 default-route mode, the last command should select the RVPN device and
show the client tunnel address, such as `src 10.42.0.2`. The server's UDP route
must stay on the physical interface.

## MTU and tray behavior

An MTU-clamp startup warning is expected when configured MTU plus worst-case
wire overhead would exceed a standard path. Do not manually set an
IPv6-capable Linux tunnel below MTU 1280.

Tray mode uses the desktop user's StatusNotifierItem/D-Bus session. It cannot
reliably run from `sudo`; a production design needs an unprivileged tray UI and
a privileged VPN service communicating over authenticated local IPC.
