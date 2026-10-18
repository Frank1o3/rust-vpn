# RVPN Issue Triage

This file tracks security and robustness work against the current checkout. The
issue numbers refer to the existing `Frank1o3/rust-vpn` GitHub issues. Remote
issue statuses were not checked or changed during this review; entries below
describe local implementation and remaining work.

Last local review: 2026-10-18.

## Active verification work

### #15 — Verify kill-switch UID, interface, endpoint, and IPv6 behavior

- **Local state:** The Linux kill switch has model-level tests for UID and
  interface rules, IPv4 and IPv6 endpoint exceptions, DNS blocking, and
  fail-closed bootstrap behavior. Replacement is submitted as one nftables
  transaction.
- **Remaining:** Exercise the installed rules under endpoint changes,
  reconnects, interface changes, tunnel loss, and IPv6 traffic. Capture on the
  physical interface to confirm the expected packets are blocked or permitted.
- **Risk:** A stale or overly broad exception could allow protected traffic to
  escape the tunnel or break recovery.

### #14 — Fuzz IP and Ethernet routing parsers

- **Local state:** The parser validates IPv4 lengths and checksums, bounded
  IPv6 extension chains, ARP structure, and Ethernet/IP version consistency.
  Parser/router tests and the `routing_parse` fuzz target exist.
- **Remaining:** Expand adversarial seeds and run sustained fuzzing, especially
  around fragments, extension chains, source mismatches, unsupported
  EtherTypes, and empty effective peer prefixes.
- **Risk:** Parser edge cases could crash the daemon or bypass source-validation
  assumptions.

### #13 — Verify DNS and endpoint-resolution leak behavior

- **Local state:** Linux installs the bootstrap kill switch before endpoint
  resolution and permits only loopback plus the numeric VPN endpoint until the
  tunnel is ready. Existing checks cover the modeled policy.
- **Observed:** Manual use behind a MikroTik that rejects outbound traffic
  with an unexpected LAN source address has shown no observed leaks.
- **Remaining:** Add packet-capture checks during bootstrap, reconnect, tunnel
  loss, DNS queries, and shutdown. The MikroTik behavior is useful evidence,
  but does not directly show which packets reached the physical interface.
- **Risk:** DNS or endpoint traffic could escape the encrypted path in an
  untested transition.

### #12 — Expand replay-window transition verification

- **Local state:** Replay windows reject duplicate and stale packets, allow
  valid out-of-order packets within the window, and keep previous-key-phase
  replay state separate during the grace period. Unit coverage exists.
- **Remaining:** Extend tests across reordering, rekey overlap, reconnect, and
  boundary sequence values; retain these cases as protocol regression tests.
- **Risk:** A replay bypass could accept a previously authenticated packet or
  confuse state across key transitions.

### #11 — Audit AEAD nonce uniqueness across session lifecycles

- **Local state:** Packet nonces derive from key phase and sequence number.
  Tests check key/nonce separation across reconnect and rekey derivations.
- **Remaining:** Review every client and server session-establishment path and
  document the invariant alongside the regression coverage.
- **Risk:** Reusing a nonce with the same AEAD key could compromise traffic
  confidentiality and integrity.

### #7 — Validate kill-switch replacement failure behavior

- **Local state:** Replacement is submitted as a single nftables batch so a
  failed update should leave the previous policy installed.
- **Remaining:** Add or run failure-injection verification against a Linux
  kernel and confirm the prior rules remain active after rejected updates.
- **Risk:** A failed update that removes the old policy could expose traffic
  outside the tunnel.

## Implemented locally; review for upstream closure

### #10 — Recover stale Unix control sockets safely

The IPC layer probes an existing listener and preserves a live socket instead
of unlinking it. The server status socket also recovers stale socket files
after an unclean exit while refusing to remove active sockets or non-socket
files. Regression coverage exists for IPC stale-socket handling.

### #9 — Bound IPC control-message and connection resources

IPC reads have a 64 KiB message cap, a 30-second idle timeout, and a
128-connection semaphore bound. Regression coverage exists.

### #8 — Rate-limit unauthenticated UDP cookie challenges

Cookie challenges are limited per source IP and globally per second, using a
bounded source table. Regression coverage exists; production tuning under
handshake floods is operational follow-up rather than missing implementation.

### #6 — Fail closed for empty effective `allowed_ips`

Static configuration rejects empty peer prefixes. Certificate-authenticated
peers are rejected before session activation if their effective prefixes are
empty, and the router independently denies empty-prefix peers.

## Other recent fixes

- Linux DNS teardown checks that `systemd-resolved` currently owns its D-Bus
  name before asking it to revert per-link state. A missing or inactive
  resolver no longer causes an activation attempt during teardown.
- Linux kill-switch teardown treats an absent per-UID RVPN table as already
  cleaned up.
