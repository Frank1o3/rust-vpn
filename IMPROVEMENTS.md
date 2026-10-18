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

## Active improvement priorities

### 1. Verify leak prevention on Linux (issues #13 and #15)

Turn the existing nftables model checks into repeatable integration checks.
Capture traffic during bootstrap, endpoint changes, reconnects, tunnel loss,
and shutdown; cover DNS plus IPv4 and IPv6. Current manual use behind a
MikroTik that rejects traffic with an unexpected LAN source address has shown
no observed leaks. Keep that as useful environment evidence, while adding
captures that directly establish which packets reached the physical network.

### 2. Complete protocol assurance (issues #11, #12, and #14)

Audit nonce uniqueness across every handshake, rekey, reconnect, and key-phase
transition. Expand replay-window tests for reordering and transitions. Maintain
the routing parser fuzz corpus and run sustained fuzzing as part of release
hardening.

### 3. Measure the packet hot path

The existing Criterion benchmark covers transport buffer-pool and adaptive
MTU operations. Add measurements for packet authentication, routing, queue
scheduling, and TUN/TAP injection at small and near-MTU sizes. Record throughput
and tail latency before changing copies, locks, or batching.

### 4. Validate kill-switch replacement failure behavior (issue #7)

The replacement is submitted as one nftables batch so a failed update should
leave the installed policy intact. Confirm that behavior with failure
injection against a Linux kernel.

### 5. Improve congestion diagnosis

The transport already records MTU changes, send errors, oversized packets,
backpressure, and per-peer queue delay and drops. Improve attribution so
operators can distinguish path congestion from local queue pressure and
receiver-side overload. Keep the existing bounded queue behavior.

### 6. Improve long-running operations

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
