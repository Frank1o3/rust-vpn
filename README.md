# RVPN

RVPN is an experimental Rust VPN implementation with an authenticated,
encrypted UDP data plane, Linux TUN/TAP support, a multi-peer server, and an
Android client. It is a learning and development project, not an audited or
production-ready security product.

## Documentation

- [Architecture](docs/architecture.md) — components, packet flow, and security boundaries.
- [Configuration](docs/configuration.md) — server and client TOML reference.
- [Deployment and operations](docs/operations.md) — build, launch, routing, and verification.
- [Android client](docs/android.md) — Android-specific setup and limits.
- [Troubleshooting](docs/troubleshooting.md) — MTU, routing, firewall, and tray diagnostics.

## Quick start

```sh
cargo build --release -p rvpn-server -p rvpn-client
sudo ./target/release/rvpn-server server.toml
sudo ./target/release/rvpn-client rvpn-setup/client-pc-laptop.toml
```

Then verify tunnel reachability:

```sh
ping 10.42.0.1
ping -6 fd42::1
```

RVPN creates non-persistent interfaces and restores routes and firewall state
on a graceful SIGINT or SIGTERM shutdown. See [operations](docs/operations.md)
before using it on a host with important existing network configuration.

## Important security notes

- Do not commit real `local_identity_seed`, `pre_shared_key`, or
  `obfuscation_key` values. Treat them as passwords; rotate values exposed in
  logs, chats, or screenshots.
- Server `allowed_ips` are anti-spoofing policy. Each peer should receive only
  its own tunnel addresses, for example `10.42.0.2/32` and `fd42::2/128`.
- The current tray UI must run as the desktop user, while interface and route
  creation require elevated privileges. A production tray design should use an
  unprivileged UI communicating with a privileged service over authenticated
  local IPC.
