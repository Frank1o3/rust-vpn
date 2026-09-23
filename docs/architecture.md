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

## Sessions and peers

The handshake authenticates with PSK, pinned keys, or certificates. The server
can update a peer's UDP endpoint only after a valid authenticated packet, which
allows NAT rebinding without trusting unauthenticated traffic.

Each peer has `allowed_ips`. Incoming packets whose inner source address is not
in that peer's list are dropped. This is intentional anti-spoofing policy.

## Peer-to-peer routing

By default, peers can reach the server (and the internet, if forwarding is
enabled) but not each other. `rvpn-routing` implements symmetric `[[links]]`
groups: any two peers named in the same group can exchange traffic directly,
in either TUN (IP-routed) or TAP (Ethernet/MAC-learned) mode. Forwarded IP
packets lose one TTL/hop-limit, same as a normal router hop. Peer-to-peer
traffic never touches the server's own firewall/forwarding rules — it's
routed inside RVPN before it would reach them.

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
