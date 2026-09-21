# Configuration

Both endpoints use TOML. Keep secrets out of source control and replace all
placeholder credentials below.

## Server

```toml
bind = "0.0.0.0:9000"
obfuscation_key = "<optional 64-hex key>"

[interface]
name = "rvpn-server0"
mode = "tun"
mtu = 1400
address = "10.42.0.1/24"
addresses = ["fd42::1/64"]

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

## Linux client

```toml
server = "vpn.example.net:9000"
obfuscation_key = "<same optional key>"

[interface]
name = "rvpn-client0"
mode = "tun"
mtu = 1400
address = "10.42.0.2/24"
addresses = ["fd42::2/64"]

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
packet_limit = 1048576 # zero disables automatic rotation
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
