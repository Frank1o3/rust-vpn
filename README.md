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
dropping its non-persistent TUN device.

For an opt-in IPv4 internet gateway, RVPN uses the host `ip` and `nft` tools;
no Rust firewall library is required. These privileged commands configure the
TUN address/routes, enable IPv4 forwarding, and install an isolated `inet rvpn`
NAT table. For example:

```toml
# server.toml
[interface]
name = "rvpn-server0"
mtu = 1400
address = "10.42.0.1/24"

[forwarding]
enabled = true
external_interface = "eth0"
tunnel_cidr = "10.42.0.0/24"
```

```toml
# client.toml
[interface]
name = "rvpn-client0"
mtu = 1400
address = "10.42.0.2/24"

[routing]
default_route = true
gateway = "10.42.0.1"
endpoint_gateway = "192.0.2.254" # keeps the UDP server route off the tunnel
# Or use routes = ["10.0.0.0/8"] for split tunnelling.
```

Run the processes with the capabilities needed to create TUN devices and change
network state. The forwarding table and the prior IPv4-forwarding setting are
restored during a graceful RVPN shutdown.

## Multi-client provisioning and integration test

Use `[[peers]]` on the server to give every client a distinct PSK and the
tunnel CIDR(s) it owns. `allowed_ips` is enforced both as a source-address
anti-spoofing policy and as the return-traffic routing table.

```toml
[[peers]]
name = "desktop"
pre_shared_key = "...64 hexadecimal characters..."
allowed_ips = ["10.42.0.2/32"]
```

The client uses that peer's PSK and configures its assigned address locally.
The legacy top-level `pre_shared_key` remains supported only for a single
unrestricted peer.

`scripts/netns-integration.sh` is a two-host simulation: it creates isolated
server/client namespaces, starts both binaries, and pings across the encrypted
TUN link. Run it from the repository root with `sudo`; it is suitable for a
privileged Linux CI job as well.

### Laptop-server smoke test

On the laptop, replace `192.168.1.10` with its LAN address and use:

```toml
# server.toml
bind = "0.0.0.0:9000"
pre_shared_key = "<the 64-hex-character shared key>" # legacy fallback

[interface]
name = "rvpn-server0"
address = "10.42.0.1/24"

[[peers]]
name = "main-pc"
pre_shared_key = "<the 64-hex-character shared key>"
allowed_ips = ["10.42.0.2/32"]
```

```toml
# client.toml on the main PC
server = "192.168.1.10:9000"
pre_shared_key = "<the same 64-hex-character shared key>"

[interface]
name = "rvpn-client0"
address = "10.42.0.2/24"
```

Generate the shared key once with `openssl rand -hex 32`, copy it to both
files, then run `sudo cargo run -p rvpn-server -- server.toml` on the laptop
and `sudo cargo run -p rvpn-client -- client.toml` on the PC. Finally, from the
PC, run `ping 10.42.0.1`. Permit UDP port 9000 through the laptop firewall if
one is active.
