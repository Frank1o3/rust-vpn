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
- Validated `SIGHUP` reload for peer authentication, links, DNS settings, and
  traffic limits. Authentication changes close active sessions so peers must
  reconnect under the updated policy.
- Optional persistent daily peer usage history with a configured file path,
  UTC-day retention, atomic writes, and a documented reset procedure. It is
  disabled by default.
- Linux DNS startup logs identify the selected NetworkManager,
  systemd-resolved, or `/etc/resolv.conf` path and explain fallback decisions.

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

## Deferred security considerations

Post-quantum protocol work is deferred until it is a practical requirement and
mature, independently reviewed algorithms and implementation guidance are
available. Do not design a bespoke cryptographic protocol for it in advance.

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
