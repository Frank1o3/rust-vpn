# Architecture

```text
application IP packet
        │
        ▼
  Linux/Android TUN or TAP
        │
        ▼
 rvpn-client / rvpn-server tunnel loop
        │  authenticated session, AEAD, optional obfuscation
        ▼
       UDP socket ───────────── Internet/LAN ───────────── UDP socket
```

On Linux, `rvpn-client` normally runs as an unprivileged-launch daemon
controlled over a local IPC socket, with `rvpn-tray` acting as its UI:

```text
 rvpn-tray (per-user, no privileges) ──IPC (rvpn-ipc)──► rvpn-client --daemon
                                                              │
                                                    CAP_NET_ADMIN / CAP_NET_RAW
                                                    (granted by systemd, not setcap)
                                                              │
                                                          TUN/TAP + UDP
```

## Components

- `rvpn-core`: shared identifiers, errors, and GUI/tray state snapshots.
- `rvpn-protocol`: packet framing, handshake messages, and validation.
- `rvpn-crypto`: authenticated ephemeral exchange, traffic keys, AEAD, and optional obfuscation.
- `rvpn-transport`: UDP I/O, queueing, keepalives, metrics, and adaptive MTU tracking.
- `rvpn-config`: TOML parsing and validation for server and client configs.
- `rvpn-interface`: platform TUN/TAP implementation (Linux, Windows via Wintun).
- `rvpn-net`: native (non-shell-out) network configuration — routes, addresses, DNS, and the Linux kill switch — via rtnetlink/nftnl instead of `ip`/`nft`/`resolvectl`.
- `rvpn-routing`: server-side peer-to-peer packet routing and MAC learning for `[[links]]` groups, in both TUN and TAP modes.
- `rvpn-ipc`: the control protocol and local socket (`rvpn-client` daemon ↔ `rvpn-tray`/systemd), plus the wire-friendly `StatusSnapshot`.
- `rvpn-client`, `rvpn-server`, `rvpn-android`, and `rvpn-tray`: endpoint applications. `rvpn-tray` is a thin UI shell with no networking privileges of its own; it drives `rvpn-client` entirely through `rvpn-ipc`.

Transport moves opaque datagrams only; encryption belongs above it.
Outbound datagrams use bounded per-endpoint queues and deficit round-robin
scheduling, with a 1500-byte quantum and a maximum of 256 queued datagrams per
endpoint. This keeps a busy peer from occupying the entire server queue and
lets smaller packets from other peers proceed while a large packet consumes
multiple scheduling rounds.

## Sessions and peers

The version 3 handshake authenticates peers with pinned Ed25519 keys or
certificate authority-issued Ed25519 identities. The server can update a
peer's UDP endpoint only after a valid authenticated packet, which allows NAT
rebinding without trusting unauthenticated traffic. Rekey and liveness
settings are configurable independently of the peer authentication mode.

Each peer has `allowed_ips`. Incoming packets whose inner source address is not
in that peer's list are dropped. This is intentional anti-spoofing policy.

## Peer-to-peer routing

By default, peers can reach the server (and the internet, if forwarding is
enabled) but not each other. `rvpn-routing` implements symmetric `between`
groups and directed `receivers` / `transmitters` groups. Directed links grant
only the configured transmitter-to-receiver edges; permissions do not become
transitive. Both forms work in TUN (IP-routed) and TAP (Ethernet/MAC-learned)
mode, with TAP broadcast and multicast filtered for each sender. Forwarded IP
packets lose one TTL/hop-limit, same as a normal router hop. Peer-to-peer
traffic is routed inside RVPN and never touches the server's own
firewall/forwarding rules.

## DNS and operations

The optional server DNS forwarder listens on configured tunnel addresses over
UDP and TCP port 53. It supports numeric upstreams, bounded retries and
timeouts, and an optional TTL-aware response cache. Linux clients can install
DNS through NetworkManager, systemd-resolved, or a backed-up resolver-file
fallback; cleanup restores the prior resolver state.

Server operators can configure independent per-peer ingress policing and
egress shaping, optional daily usage history, a local peer-status socket, and
a loopback-only token-authenticated metrics endpoint. A validated `SIGHUP`
reload applies peer authentication, link, DNS, and traffic-limit changes;
interface, forwarding, and transport-security settings require restart. See
[configuration](configuration.md) and [operations](operations.md).

## Interface modes and MTU

- `tun` carries IPv4 and IPv6 packets at layer 3.
- `tap` carries Ethernet frames, including ARP and broadcast traffic.
- `both` creates TUN and TAP interfaces for the same encrypted session.

RVPN accounts for protocol, AEAD, and optional obfuscation overhead before
sending outer UDP. The logged effective interface MTU can be lower than the
TOML request so a worst-case packet fits a standard 1500-byte path. With
obfuscation and an IPv4 endpoint, a requested 1400-byte MTU currently becomes
1317 bytes. IPv6-capable Linux links must remain at least MTU 1280.

Path MTU is also adaptive at runtime (`rvpn-transport::AdaptiveMtu`): sustained
send failures step the effective MTU down, and sustained success gradually
probes it back up toward the configured target.
