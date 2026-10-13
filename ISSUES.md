# GitHub Issues for rust-vpn

Repository: `Frank1o3/rust-vpn`
Last checked: 2026-10-12

Total open issues: 10
Total closed issues: 0

---

## 1) #15 — [Security][Medium] Test kill-switch UID, interface, endpoint and IPv6 fail-closed behavior

- Status: Open
- Created: 2026-10-10
- Summary: Validate that Linux kill-switch rules for a protected UID only allow the required loopback, tunnel, and endpoint traffic and fail closed under reconnects, endpoint changes, and IPv6 conditions.
- Risk: A stale or overly broad exception could allow protected traffic to escape the tunnel or break reconnect behavior.
- Classification: Defense-in-depth security test issue.
- Local progress (2026-10-12): Added model-level checks for exact IPv4/IPv6 endpoint exceptions, DNS on physical versus tunnel interfaces, bootstrap fail-closed behavior, and endpoint replacement. Runtime nftables behavior during reconnect and interface changes still needs integration verification.
- Implementation review (2026-10-13): The Linux client installs the bootstrap policy before endpoint resolution and replaces rules in one nftables transaction. Code is in place; packet-capture verification during reconnect and interface changes remains open.

## 2) #14 — [Security][Medium] Fuzz IP and Ethernet routing parsers and validate source/destination consistency

- Status: Open
- Created: 2026-10-10
- Summary: Add adversarial parsing and routing tests for malformed IPv4/IPv6, fragmentation, extension headers, ARP, Ethernet/IP mismatch, and unsupported EtherTypes.
- Risk: Parser edge cases could crash the daemon or bypass source-validation assumptions.
- Classification: Network parser hardening and fuzzing issue.
- Implementation review (2026-10-13): The routing parser validates IPv4 lengths/checksums, bounded IPv6 extension chains, ARP structure, and Ethernet/IP version consistency. The `routing_parse` fuzz target and parser/router unit coverage are present. Broader adversarial corpus and sustained fuzzing remain open.

## 3) #13 — [Security][Medium] Test DNS bootstrap and endpoint-resolution leaks against kill-switch expectations

- Status: Open
- Created: 2026-10-10
- Summary: Verify whether DNS resolution for the VPN endpoint or application traffic can leak outside the tunnel during bootstrap, reconnect, or tunnel loss.
- Risk: DNS or endpoint lookups may escape the encrypted path and violate privacy or expected fail-closed behavior.
- Classification: Privacy and traffic-leak validation issue.
- Local progress (2026-10-12): Linux now installs the bootstrap kill switch before endpoint resolution and permits only loopback plus the numeric VPN endpoint until the tunnel interface is ready. A regression check covers this policy and ensures tunnel DNS settings do not make hostname endpoints valid for full-tunnel bootstrap. Packet-capture verification across bootstrap, reconnect, and tunnel loss is still outstanding.
- Implementation review (2026-10-13): Bootstrap rule installation precedes endpoint resolution in the client startup path. Runtime packet-capture verification across bootstrap, reconnect, and tunnel loss remains open.

## 4) #12 — [Security][High impact if violated] Strengthen replay-window tests across reordering and key transitions

- Status: Open
- Created: 2026-10-10
- Summary: Ensure the protocol's sliding replay window rejects duplicate packets and does not allow replay across reordering, rekeying, or key-phase transitions.
- Risk: Replay bypass could enable an attacker to resend valid encrypted packets and trigger undesired actions or protocol confusion.
- Classification: Cryptographic protocol hardening.
- Implementation review (2026-10-13): Replay windows reject duplicates and stale packets, preserve out-of-order packets within the window, and keep previous-key-phase replay state separate during the grace period. Unit coverage is present; expanded transition/reordering verification remains open.

## 5) #11 — [Security][High impact if violated] Verify AEAD nonce uniqueness across rekey and reconnect paths

- Status: Open
- Created: 2026-10-10
- Summary: Confirm the system never reuses an AEAD `(key, nonce)` pair across rekey, reconnect, or session reestablishment events.
- Risk: Nonce reuse under the same key could compromise confidentiality and integrity of encrypted traffic.
- Classification: High-impact cryptographic invariant review.
- Implementation review (2026-10-13): Session nonces derive from key phase and sequence number, and rekey/reconnect derivation coverage checks independently derived session keys. A broader audit of every session-establishment path remains open.

## 6) #10 — [Security][Medium] Remove stale Unix control sockets without unlinking a live listener

- Status: Open
- Created: 2026-10-10
- Summary: Fix stale-socket recovery in the IPC layer so a second daemon cannot delete a still-running listener's socket path by mistake.
- Risk: Instance confusion or control-plane takeover could occur if a live listener is replaced by a different daemon instance.
- Classification: Local control-plane availability and instance-confusion issue.
- Local implementation status: **Implemented** (2026-10-13). Stale-socket recovery probes the existing listener and compares inode identity before unlinking; a live listener is preserved. Regression coverage is present.

## 7) #9 — [Security][Medium] Bound IPC control-message size and connection resources

- Status: Open
- Created: 2026-10-10
- Summary: Limit IPC socket message size, number of in-flight connections, and idle connection lifetime to avoid memory exhaustion or daemon unresponsiveness.
- Risk: An attacker with local socket access could send oversized or never-terminated messages and degrade or stall the daemon.
- Classification: Local denial-of-service hardening issue.
- Local implementation status: **Implemented** (2026-10-13). IPC reads have a 64 KiB message cap, 30-second idle timeout, and 128-connection semaphore bound. Regression coverage is present.

## 8) #8 — [Security][Medium-High] Rate-limit unauthenticated UDP cookie challenges

- Status: Open
- Created: 2026-10-10
- Summary: Add source-aware and global rate limiting around unauthenticated UDP cookie challenges to reduce CPU and bandwidth abuse during handshake floods.
- Risk: A flood of spoofed UDP initiation packets could consume resources and produce reflection or amplification problems.
- Classification: Remote denial-of-service risk assessment.
- Local implementation status: **Implemented** (2026-10-13). Cookie challenges are limited per source IP and globally per second, with a bounded source table. Regression coverage is present; operational tuning under real handshake floods remains open.

## 9) #7 — [Security][High] Preserve kill-switch rules if replacement installation fails

- Status: Open
- Created: 2026-10-10
- Summary: Ensure nftables kill-switch updates are atomic or rollback-safe so a failed reinstall does not delete an active protection policy and leave the system fail-open.
- Risk: A failed update may remove the old rules while the replacement is invalid, exposing traffic outside the tunnel.
- Classification: Conditional security issue tied to host firewall state.
- Local implementation status: **Implemented** (2026-10-13). Client kill-switch replacement is submitted as one nftables batch; failed replacement leaves the installed policy in place. Runtime failure-injection verification remains open.

## 10) #6 — [Security][High] Fail closed when a peer has an empty effective allowed_ips list

- Status: Open
- Created: 2026-10-10
- Summary: Investigate whether `allowed_ips` can resolve to an empty list and implicitly allow all source addresses for a peer; reject that case or require an explicit unrestricted opt-in.
- Risk: A peer with valid credentials but no effective source prefix may be able to inject unauthorized traffic or spoof source addresses.
- Classification: High-risk routing and authorization validation issue.
- Local implementation status: **Implemented** (2026-10-13). Static peer configuration rejects empty prefixes. The server now also rejects certificate-authenticated peers whose effective prefix list resolves empty, before activating the session. Router source validation independently denies empty-prefix peers.

---

## Notes

- The repository currently has no closed issues on GitHub.
- The issue list is populated from the GitHub issue tracker for `Frank1o3/rust-vpn` and reflects the active security and robustness work items currently tracked there.
- The per-issue implementation notes above describe this checkout; GitHub issue statuses remain open until their outstanding verification and tracker follow-up are completed.
