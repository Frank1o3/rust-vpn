# RVPN

RVPN is an experimental Rust VPN project. It is being built incrementally to
explore a custom VPN protocol and UDP networking stack while relying on
established cryptographic primitives rather than home-grown cryptography.

## Workspace layout

- `crates/rvpn-core`: shared identifiers and errors.
- `crates/rvpn-protocol`: packet framing and protocol validation.
- `crates/rvpn-crypto`: secret-material boundary implementing the ephemeral,
  PSK-authenticated key establishment and AEAD packet protection primitives.
- `crates/rvpn-transport`: reusable, unencrypted UDP datagram transport.
- `crates/rvpn-config`: TOML parsing and validation.
- `apps/rvpn-client` and `apps/rvpn-server`: application entry points.

The lower-level crates do not depend on either application. In particular,
transport only moves opaque bytes and never encrypts or decrypts them.

Run the current checks with:

```sh
cargo test --workspace
```

## Resilient sessions and routing

The client retransmits handshake initiation and finish flights; the server
retransmits its response while waiting for a finish. Defaults are a 500 ms
interval and five attempts, configurable on either endpoint:

```toml
[handshake]
retry_interval_ms = 500
retry_limit = 5

[rekey]
# A client starts a new PSK-authenticated ephemeral exchange before this many
# packets; zero disables automatic rotation.
packet_limit = 1048576
```

Rekeys retain the session ID, advance `key_phase`, derive fresh keys, and reset
per-phase packet counters. The server also issues an authenticated rekey request
when its outbound limit is reached. A valid AEAD-protected data packet from a
new UDP source updates the server's peer address, so NAT rebinding works without
trusting an unauthenticated source address.

On SIGINT or SIGTERM each endpoint sends an authenticated `Close` packet before
dropping its non-persistent virtual device.

For an opt-in internet gateway, RVPN configures firewall and NAT rules
automatically using either `iptables` or `nftables` (with auto-detection)—no
manual network commands or external firewall scripts are required. RVPN
configures TUN/TAP addresses and routes, brings interfaces up automatically,
enables kernel IP forwarding, and installs isolated NAT/masquerade rules. For
example:

```toml
# server.toml
[interface]
name = "rvpn-server0"
mode = "tun" # or "tap" (Layer 2) or "both" (TUN + TAP concurrently)
mtu = 1400
address = "10.42.0.1/24"
addresses = ["fd42::1/64"]

[forwarding]
enabled = true
backend = "auto" # "auto", "iptables", or "nftables"
external_interface = "eth0"
tunnel_cidr = "10.42.0.0/24"
tunnel_cidr_v6 = "fd42::/64" # optional NAT66
```

```toml
# client.toml
[interface]
name = "rvpn-client0"
mode = "tun" # or "tap" or "both"
mtu = 1400
address = "10.42.0.2/24"
addresses = ["fd42::2/64"]

[routing]
default_route = true
gateway = "10.42.0.1"
endpoint_gateway = "192.168.88.1" # keeps the UDP server route off the tunnel
# Or use routes = ["10.0.0.0/8"] for split tunnelling.
```

### TUN, TAP, and Both modes

- **`tun`** (default): Operates at Layer 3 (raw IPv4 and IPv6 packets). Provides maximum MTU efficiency without Ethernet header overhead.
- **`tap`**: Operates at Layer 2 (Ethernet frames). Carries ARP, DHCP, broadcast, and multicast discovery protocols, functioning like a virtual Ethernet switch with MAC learning.
- **`both`**: Instantiates both a TUN interface (for high-efficiency IP traffic) and a TAP interface (for L2 Ethernet frames) concurrently over the same encrypted VPN session.

IPv6 packets are protected exactly like IPv4 packets. Add IPv6 prefixes to a
peer's `allowed_ips`, such as `fd42::2/128`, and use `addresses` for additional
interface addresses. `default_route_v6` and `gateway_v6` provide dual-stack
default routing through the tunnel even when connecting to an IPv4 server endpoint.

All firewall rules and kernel forwarding settings are cleanly restored during a
graceful RVPN shutdown.

## Multi-device deployment and testing

`server.toml` and `client.toml` are pre-configured to test between two physical
devices on a local network: a laptop server (LAN IP `10.0.0.91`) and a desktop PC.

### 1. On the laptop (Server at 10.0.0.91):
Run:
```sh
sudo cargo run -p rvpn-server -- server.toml
```

### 2. On the main PC (Client):
Run:
```sh
sudo cargo run -p rvpn-client -- client.toml
```

### 3. Verify connectivity:
From the main PC:
```sh
ping 10.42.0.1
ping -6 fd42::1
```
