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

## Components

- `rvpn-core`: shared identifiers and errors.
- `rvpn-protocol`: packet framing and validation.
- `rvpn-crypto`: authenticated ephemeral exchange, traffic keys, AEAD, and optional obfuscation.
- `rvpn-transport`: UDP I/O, queueing, keepalives, metrics, and MTU tracking.
- `rvpn-config`: TOML parsing and validation.
- `rvpn-interface`: platform TUN/TAP implementation.
- `rvpn-client`, `rvpn-server`, and `rvpn-android`: endpoint applications.

Transport moves opaque datagrams only; encryption belongs above it.

## Sessions and peers

The handshake authenticates with PSK, pinned keys, or certificates. The server
can update a peer's UDP endpoint only after a valid authenticated packet, which
allows NAT rebinding without trusting unauthenticated traffic.

Each peer has `allowed_ips`. Incoming packets whose inner source address is not
in that peer's list are dropped. This is intentional anti-spoofing policy.

## Interface modes and MTU

- `tun` carries IPv4 and IPv6 packets at layer 3.
- `tap` carries Ethernet frames, including ARP and broadcast traffic.
- `both` creates TUN and TAP interfaces for the same encrypted session.

RVPN accounts for protocol, AEAD, and optional obfuscation overhead before
sending outer UDP. The logged effective interface MTU can be lower than the
TOML request so a worst-case packet fits a standard 1500-byte path. With
obfuscation and an IPv4 endpoint, a requested 1400-byte MTU currently becomes
1317 bytes. IPv6-capable Linux links must remain at least MTU 1280.
