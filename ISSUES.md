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

## 2) #14 — [Security][Medium] Fuzz IP and Ethernet routing parsers and validate source/destination consistency

- Status: Open
- Created: 2026-10-10
- Summary: Add adversarial parsing and routing tests for malformed IPv4/IPv6, fragmentation, extension headers, ARP, Ethernet/IP mismatch, and unsupported EtherTypes.
- Risk: Parser edge cases could crash the daemon or bypass source-validation assumptions.
- Classification: Network parser hardening and fuzzing issue.

## 3) #13 — [Security][Medium] Test DNS bootstrap and endpoint-resolution leaks against kill-switch expectations

- Status: Open
- Created: 2026-10-10
- Summary: Verify whether DNS resolution for the VPN endpoint or application traffic can leak outside the tunnel during bootstrap, reconnect, or tunnel loss.
- Risk: DNS or endpoint lookups may escape the encrypted path and violate privacy or expected fail-closed behavior.
- Classification: Privacy and traffic-leak validation issue.

## 4) #12 — [Security][High impact if violated] Strengthen replay-window tests across reordering and key transitions

- Status: Open
- Created: 2026-10-10
- Summary: Ensure the protocol's sliding replay window rejects duplicate packets and does not allow replay across reordering, rekeying, or key-phase transitions.
- Risk: Replay bypass could enable an attacker to resend valid encrypted packets and trigger undesired actions or protocol confusion.
- Classification: Cryptographic protocol hardening.

## 5) #11 — [Security][High impact if violated] Verify AEAD nonce uniqueness across rekey and reconnect paths

- Status: Open
- Created: 2026-10-10
- Summary: Confirm the system never reuses an AEAD `(key, nonce)` pair across rekey, reconnect, or session reestablishment events.
- Risk: Nonce reuse under the same key could compromise confidentiality and integrity of encrypted traffic.
- Classification: High-impact cryptographic invariant review.

## 6) #10 — [Security][Medium] Remove stale Unix control sockets without unlinking a live listener

- Status: Open
- Created: 2026-10-10
- Summary: Fix stale-socket recovery in the IPC layer so a second daemon cannot delete a still-running listener's socket path by mistake.
- Risk: Instance confusion or control-plane takeover could occur if a live listener is replaced by a different daemon instance.
- Classification: Local control-plane availability and instance-confusion issue.

## 7) #9 — [Security][Medium] Bound IPC control-message size and connection resources

- Status: Open
- Created: 2026-10-10
- Summary: Limit IPC socket message size, number of in-flight connections, and idle connection lifetime to avoid memory exhaustion or daemon unresponsiveness.
- Risk: An attacker with local socket access could send oversized or never-terminated messages and degrade or stall the daemon.
- Classification: Local denial-of-service hardening issue.

## 8) #8 — [Security][Medium-High] Rate-limit unauthenticated UDP cookie challenges

- Status: Open
- Created: 2026-10-10
- Summary: Add source-aware and global rate limiting around unauthenticated UDP cookie challenges to reduce CPU and bandwidth abuse during handshake floods.
- Risk: A flood of spoofed UDP initiation packets could consume resources and produce reflection or amplification problems.
- Classification: Remote denial-of-service risk assessment.

## 9) #7 — [Security][High] Preserve kill-switch rules if replacement installation fails

- Status: Open
- Created: 2026-10-10
- Summary: Ensure nftables kill-switch updates are atomic or rollback-safe so a failed reinstall does not delete an active protection policy and leave the system fail-open.
- Risk: A failed update may remove the old rules while the replacement is invalid, exposing traffic outside the tunnel.
- Classification: Conditional security issue tied to host firewall state.

## 10) #6 — [Security][High] Fail closed when a peer has an empty effective allowed_ips list

- Status: Open
- Created: 2026-10-10
- Summary: Investigate whether `allowed_ips` can resolve to an empty list and implicitly allow all source addresses for a peer; reject that case or require an explicit unrestricted opt-in.
- Risk: A peer with valid credentials but no effective source prefix may be able to inject unauthorized traffic or spoof source addresses.
- Classification: High-risk routing and authorization validation issue.

---

## Notes

- The repository currently has no closed issues on GitHub.
- The issue list is populated from the GitHub issue tracker for `Frank1o3/rust-vpn` and reflects the active security and robustness work items currently tracked there.
