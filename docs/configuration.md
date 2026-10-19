# Configuration

Both endpoints use TOML. Keep secrets out of source control and replace all
placeholder credentials below.

## Server

```toml
bind = "0.0.0.0:9000"
obfuscation_key = "<optional 64-hex key>"

[limits]
# MiB per second per peer; zero leaves that direction unlimited.
tx_mib_per_sec = 0
rx_mib_per_sec = 0

[usage_history]
enabled = false
# Required when enabled. Prefer an owner-only directory such as /var/lib/rvpn.
path = "/var/lib/rvpn/usage-history.json"
retention_days = 30 # 1 to 3650 daily buckets

[interface]
name = "rvpn-server0"
mode = "tun"
mtu = 1400
address = "10.42.0.1/24"
addresses = ["fd42::1/64"]

[dns]
upstreams = ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]
timeout_ms = 2000
attempts = 2
cache_entries = 1024 # zero disables the TTL-aware response cache

[forwarding]
enabled = true
backend = "auto" # auto, iptables, or nftables
external_interface = "eth0"
tunnel_cidr = "10.42.0.0/24"
tunnel_cidr_v6 = "fd42::/64"

[[peers]]
name = "laptop"
allowed_ips = ["10.42.0.2/32", "fd42::2/128"]

[peers.auth]
mode = "pinned-key"
local_identity_seed = "<server seed>"
peer_public_key = "<client public key>"
```

`allowed_ips` is both the assigned address set and the anti-spoofing allowlist.
Give every peer its own host prefixes.

`[limits]` rates use 1 MiB = 1,048,576 bytes and apply independently to each
peer. `rx_mib_per_sec` polices authenticated peer-to-server payload after
source validation. `tx_mib_per_sec` shapes server-to-peer encrypted datagrams
in the fair outbound queue, including internet-forwarded and peer-to-peer
traffic. Handshakes, rekeys, and keepalives are outside both limits. The
outbound bucket allows up to one second of burst (or one maximum UDP payload
for rates below a packet's size); queued data remains subject to the bounded
per-peer queue.

When `[dns].upstreams` is set, the server runs a DNS forwarder on UDP and TCP
port 53 at each configured tunnel interface address. It accepts requests from
the configured tunnel networks and forwards them to the listed upstream
servers. Upstream requests time out after `timeout_ms` and are retried up to
`attempts` times. Validated ranges are 100–30000 ms and 1–5 retries. The
TTL-aware response cache holds up to `cache_entries` responses (maximum 65536);
set it to zero to disable caching. Keep the DNS listener on tunnel addresses;
do not expose it on the server's public address.

The server reloads peer authentication, peer links, DNS settings, and rate
limits on `SIGHUP` after parsing and validating the complete configuration.
Changes to bind, interfaces, forwarding, handshake/rekey/liveness settings,
obfuscation, or usage-history storage require a restart. A peer authentication
change closes active sessions so peers must authenticate under the new policy.
DNS listeners restart when DNS settings change; if the new listener cannot be
started, RVPN attempts to restore the previous DNS configuration.

`[usage_history]` is disabled by default. When enabled, `path` is required;
RVPN writes daily per-peer packet, payload-byte, and drop totals, retaining at
most `retention_days` UTC days. The file is written atomically with owner-only
permissions on Unix. To reset it, stop the server, remove the configured file,
and start the server again. Keep the file in a directory writable only by the
server account because it records peer usage over time.

## Linux client

`server` may be a hostname or numeric IP address. The client resolves it before
installing the bootstrap kill switch and before setting up VPN routes. Set
`dns_replace = true` to write the resolved IP back to the client config after
resolution; the default is `false`, which keeps the hostname and resolves it
again on each new connection. This is useful with dynamic DNS when the server's
public address can change.

```toml
server = "vpn.example.net:9000"
dns_replace = false
obfuscation_key = "<same optional key>"

[interface]
name = "rvpn-client0"
mode = "tun"
mtu = 1400
address = "10.42.0.2/24"
addresses = ["fd42::2/64"]
dns_servers = "10.42.0.1, fd42::1"

[routing]
default_route = true
gateway = "10.42.0.1"
endpoint_gateway = "192.168.1.1"
default_route_v6 = true
gateway_v6 = "fd42::1"

[auth]
mode = "pinned-key"
local_identity_seed = "<client seed>"
peer_public_key = "<server public key>"
```

For IPv4 default-route mode, `endpoint_gateway` keeps the server's UDP route
on the physical network. Use `routes` instead of `default_route` for split
tunnelling. RVPN assigns the matching tunnel address as the source for default
routes, preventing LAN addresses from entering the tunnel.

Client `[interface].dns_servers` configures which resolver the device uses.
Server `[dns].upstreams` configures where the server-side tunnel DNS forwarder
sends queries; it does not set DNS on client devices by itself.

## Handshake and rekey

```toml
[handshake]
retry_interval_ms = 500
retry_limit = 5

[rekey]
packet_limit = 1048576   # rotate after this many sent packets; 0 disables the packet trigger
time_limit_secs = 120    # rotate after this session age; 0 disables the time trigger
grace_period_secs = 15   # seconds the previous key phase stays valid after a rekey; 0 disables it

[liveness]
timeout_secs = 90        # 0 disables; otherwise >= 60
```

### Peer-to-peer links

By default peers are isolated: they can reach the server and the internet
(when forwarding is on) but not each other. Use `between` for symmetric access:

```toml
    [[links]]
    between = ["laptop", "phone"]
```

For one-way access, list the allowed receivers and transmitters. The example
allows laptop and tablet to send to Android, but does not authorize replies from
Android to those peers:

```toml
    [[links]]
    receivers = ["android"]
    transmitters = ["laptop", "tablet"]
```

Each transmitter-to-receiver pair is a direct authorization edge; permissions
do not become transitive. One-way means packets in only that direction, so
ordinary request/reply protocols need a separate reverse edge. For TAP, a
broadcast or multicast frame is delivered only to receivers authorized for its
sender. Server-originated local traffic follows normal server routing and is
not restricted by peer link edges. Names must match `[[peers]]` entries (or
`cert:<subject-prefix>` when using a certificate authority). Packets are
checked against the sender's `allowed_ips` before delivery, and forwarded IP
packets lose one TTL/hop-limit. Peer-to-peer traffic is forwarded inside RVPN
and never touches the server's firewall.
