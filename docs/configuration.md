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

[interface]
name = "rvpn-server0"
mode = "tun"
mtu = 1400
address = "10.42.0.1/24"
addresses = ["fd42::1/64"]

[dns]
upstreams = ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]

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
servers. Keep the DNS listener on tunnel addresses; do not expose it on the
server's public address.

## Linux client

When either default route is enabled, configure `server` with a numeric IP
address (for example, `203.0.113.10:51820`). Endpoint resolution happens before
the VPN routes and Linux kill switch are active, so a hostname would require a
DNS lookup over the physical network. While the Linux kill switch is active,
plain UDP and TCP DNS on physical interfaces is blocked; DNS through loopback
or the tunnel interface remains available.

```toml
server = "203.0.113.10:9000"
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
(when forwarding is on) but not each other. To let peers talk directly, add
link groups. Each group is symmetric and every member can reach every other:

```toml
    [[links]]
    between = ["laptop", "phone"]
```

Names must match `[[peers]]` entries (or `cert:<subject-prefix>` when using a
certificate authority). Packets are checked against the sender's `allowed_ips`
before delivery, and forwarded IP packets lose one TTL/hop-limit. Peer-to-peer
traffic is forwarded inside RVPN and never touches the server's firewall.
