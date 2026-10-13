# RVPN Improvements

Ideas for making RVPN fairer, easier to operate, and faster. This is a planning
document; entries here are proposals, not implemented features. Security work
already tracked in `ISSUES.md` remains the source of truth for those issues.

## 1. Per-peer bandwidth accounting and fair limits

Give the server per-peer byte and packet counters, plus optional rate limits in
`server.toml`. The current transport metrics are server-wide, so they cannot
identify a peer that is using a disproportionate share.

Suggested configuration:

```toml
[limits]
# MiB per second, per peer. Zero means unlimited.
tx_mib_per_sec = 0
rx_mib_per_sec = 0
```

Define direction from the server's point of view to avoid ambiguity:

- `rx_mib_per_sec` limits authenticated data received from each peer (peer to
  server traffic).
- `tx_mib_per_sec` limits data sent by the server to each peer, including
  internet-forwarded and peer-to-peer traffic.
- One MiB is 1,048,576 bytes. These are rates, not monthly or session traffic
  quotas. Zero disables that direction's limit.

Independent per-peer caps prevent one peer from exceeding its configured
maximum, but do not by themselves guarantee equal speeds when peers compete for
bandwidth. For that, schedule queued outbound packets fairly across peers, for
example with Deficit Round Robin, and apply a token bucket to each peer and
direction. Idle peers should leave their unused share available to active
peers. Bound each peer's queue so a slow receiver cannot consume unbounded
memory.

Count data after authentication and source-address validation; keep handshake,
rekey, keepalive, and close traffic outside the data limits. Track both inner
packet bytes and encrypted wire bytes so the server can report payload usage
and actual tunnel bandwidth separately. Consider separate counters for data
forwarded to the internet, delivered to the server, and forwarded to another
peer.

Inbound limits need careful semantics: the server cannot stop packets from
reaching its network interface. It can police or drop excess authenticated
traffic after receipt, which limits server work and downstream delivery. A
fair outbound queue directly controls the rate at which the server sends to
each peer. Report drops and queue delay so operators can tell shaping apart
from path loss.

Expose per-peer rates, totals, and shaping drops through a server status or
admin interface; the current client IPC status does not report server peer
traffic. Add tests for zero/unlimited values, bursts, sustained rates, fair
sharing under contention, queue bounds, reconnect resets, and both IPv4 and
IPv6 data.

## 2. Finish network leak and firewall verification

Add Linux integration checks that observe real traffic while the kill switch is
installed, the endpoint changes, the tunnel reconnects, and the tunnel goes
down. Model-level rule tests are useful, but packet-capture checks can verify
that the installed nftables rules have the expected effect on DNS, IPv4, and
IPv6 traffic. Continue tracking this work under issues 13 and 15 in
`ISSUES.md`.

## 3. Complete routing and parser hardening

Expand adversarial coverage for malformed IPv4/IPv6 packets, fragments,
extension headers, Ethernet/IP source mismatches, unsupported EtherTypes, and
empty effective `allowed_ips`. Keep the parser and router invariants covered by
unit tests and the existing fuzz targets. See issues 6 and 14 in `ISSUES.md`.

## 4. Add server-side abuse controls and peer observability

Finish rate limiting unauthenticated cookie challenges, then add per-peer
statistics for authenticated bytes, packets, last activity, queue drops, and
rekey state. Keep unauthenticated traffic counters separate from peer usage so
spoofed source addresses cannot affect a peer's limits or reported totals. See
issue 8 in `ISSUES.md` for cookie challenge controls.

## 5. Measure and improve the packet hot path

Add repeatable benchmarks for packet authentication, routing, queueing, and
TUN/TAP injection at small and near-MTU packet sizes. Use the results to guide
buffer reuse, copies, lock contention, and batching work. Preserve bounded
memory use and measure tail latency as well as peak throughput.

## 6. Strengthen congestion and queue behavior

Use the existing MTU and transport metrics to distinguish path-MTU problems,
socket errors, local queue pressure, and network congestion. Add a fair
per-peer queue before adding more aggressive retransmission or congestion
behavior, so one busy or slow peer cannot stall unrelated peers.

## 7. Make DNS operations easier to manage

Build on the tunnel-bound DNS forwarder with upstream health checks, bounded
timeouts, optional caching, and clear per-upstream failure metrics. Keep the
listener restricted to tunnel addresses and networks. Document which DNS
settings are local client configuration and which are server-side forwarding
settings.

## 8. Improve live operations

Consider safe configuration reloads for peer links, DNS upstreams, and rate
limits, with validation before applying a change. Add a status view that shows
per-peer rates and shaping state alongside the existing transport counters.
Keep key material and private peer configuration out of status output.

## Current implementation progress

- The server now keeps authenticated per-peer payload and wire-byte totals,
  packet/drop counts, activity age, and completed rekeys in memory and logs
  them once a minute. They reset on restart and are not exposed through an API.
- Outbound datagrams use bounded per-endpoint queues with deficit
  round-robin scheduling. The queue has a global capacity and caps each
  endpoint at 256 pending datagrams.
- Configurable rate limits, live reload, persistent history, and the analytics
  portal remain future work. The portal should follow an authenticated local
  status interface so it does not need to expose peer data on the public VPN
  endpoint.
