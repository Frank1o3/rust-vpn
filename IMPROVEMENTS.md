# RVPN Improvements

RVPN has moved from its implementation phase into ongoing improvement. Core
networking, peer controls, DNS backends, and local operations are in place. The
work below focuses on collecting stronger evidence, measuring performance, and
improving long-term operations.

## Delivered capabilities

- Per-peer authenticated payload and wire-byte accounting, configurable
  transmit shaping and receive policing, bounded queues, and deficit
  round-robin outbound scheduling.
- Server peer status over a local Unix socket and a loopback-only,
  token-authenticated metrics portal. Metrics include traffic, drops, shaping,
  queue delay, rekeys, and activity age; they are in-memory and reset when the
  server restarts.
- Linux kill-switch bootstrap rules, atomic rule replacement, IPv4 and IPv6
  endpoint exceptions, DNS leak blocking, and cleanup of absent rules/tables.
- Linux DNS configuration through NetworkManager or systemd-resolved, with a
  backed-up `/etc/resolv.conf` fallback. The selected path depends on host DNS
  configuration and service availability.
- Server-side limits for unauthenticated cookie challenges, routing source
  validation, replay windows, and parser fuzz targets.
- Tunnel-bound DNS forwarding with configurable retries and timeouts, optional
  bounded TTL-aware caching, and local operations documentation.
- Recovery for stale local status sockets after an unclean server exit.
- Directed transmitter-to-receiver peer links, with symmetric `between`
  groups retained as shorthand. TAP broadcast and multicast forwarding uses the
  same per-sender receiver authorization.

## New control and policy improvements

### Directional peer links — implemented

`[[links]]` accepts directed receiver/transmitter lists so operators can allow
one-way communication without treating every group member as equally trusted.
`between` remains a symmetric shorthand for compatibility. Each
transmitter-to-receiver pair is an explicit authorization edge, rules do not
become transitive, and TAP broadcast/multicast is filtered per sender. These
are policy and configuration changes; they do not alter the wire protocol.

For example, this grants laptops and tablets permission to send to Android,
without granting Android permission to send back:

```toml
[[links]]
receivers = ["android"]
transmitters = ["laptop", "tablet"]
```

An edge authorizes packets only in its configured direction. Ordinary
request/response protocols therefore need an explicit reverse edge. Server-
originated local traffic follows server routing and is not restricted by peer
link edges. Unmatched peer-to-peer traffic remains denied.

### DNS forwarder controls

The server currently exposes upstream addresses, request timeout, retry count,
and cache capacity. Consider per-upstream settings and status, deterministic
failover or parallel queries, configurable positive and negative cache
behavior, and optional encrypted upstream transports such as DNS-over-TLS or
DNS-over-HTTPS. Add controls only with clear privacy, routing, certificate
validation, and fallback semantics; retain the current bounded defaults.

### Liveness controls

The client exposes an authenticated-packet timeout (90 seconds by default,
zero disables it), while keepalive interval and jitter use fixed transport
defaults (25 seconds with 20% jitter). The scheduler is shared by the UDP
transport and resets on any socket activity, so traffic from one peer—or even
unauthenticated datagrams—can defer keepalives for other idle peers on a server.
Consider per-peer probe scheduling based on authenticated activity, configurable
intervals and jitter, a separate dead-peer timeout, and explicit recovery
behavior after missed probes. Keep NAT maintenance, dead-link detection, and
rekey scheduling as distinct settings because they serve different purposes.
Account for mobile power use and never treat unauthenticated or replayed
traffic as proof that a peer is alive.

## Active improvement priorities

### 1. Design and implement a post-quantum protocol version

Treat this as the leading security upgrade. Specify a new, intentionally
incompatible protocol version (target 3.2) with mandatory hybrid X25519 and
ML-KEM key establishment. Combine both secrets using a reviewed construction
and bind the algorithm suite, both key shares, identities, roles, and version
into the authenticated transcript and key derivation. Fail the handshake if
either component fails. A new binary must not negotiate or fall back to 3.1;
the existing exact-version packet check should remain fail-closed.

The KEM adds bytes to initial handshakes and rekeys, not to ordinary data
packets. Measure the resulting datagram sizes with the configured obfuscation
padding and representative IPv4/IPv6 path MTUs. Design bounded handshake
fragmentation or a handshake-specific padding policy rather than relying on IP
fragmentation. Keep reassembly bounded by size, count, time, and peer/source so
large unauthenticated handshakes cannot become a resource-exhaustion path.

As part of the protocol design, decide whether 3.2 also requires hybrid
Ed25519 plus ML-DSA peer authentication. Key establishment protects captured
traffic against future decryption; hybrid signatures address future quantum
forgery of peer identities. Treat those as separate security properties and
include identity, certificate, revocation, and enrollment format impacts in
the decision. Use maintained, reviewed implementations and obtain an
independent protocol review before release. Add downgrade, transcript-binding,
key-separation, packet-size, loss, replay, and malformed-fragment regression
coverage. Do not ship a classical-only fallback in the new protocol.

### 5. Validate kill-switch replacement failure behavior (issue #7)

The replacement is submitted as one nftables batch so a failed update should
leave the installed policy intact. Confirm that behavior with failure
injection against a Linux kernel.

### 7. Improve long-running operations

- Add validated live reload for peer configuration, DNS upstreams, and limits.
- Offer optional persistent usage history with explicit retention and reset
  behavior; current counters reset on restart.
- Add clear startup diagnostics for the selected Linux DNS backend and why
  NetworkManager, systemd-resolved, or the resolv.conf fallback was chosen.

## Product directions

- Per-peer rolling or monthly usage quotas with warnings and a documented
  reset policy.
- Named peer enrollment profiles with expiry and revocation, reusing the
  existing QR/import format.
- Optional server-side DNS policy profiles with per-peer opt-in and visible
  block counts.
- Connection diagnostics for endpoint reachability, DNS path, MTU, handshake
  stage, and kill-switch state, without exposing keys.

These are future directions, not claims of parity with other VPN products.
Prioritize features that improve reliability, verifiability, and ease of
operation while keeping protocol and key management conservative.
