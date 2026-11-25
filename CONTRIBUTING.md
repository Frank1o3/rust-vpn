# Contributing to RVPN

RVPN is a Rust workspace containing the Linux client and server, Android client, tray application, and shared protocol, crypto, routing, transport, interface, DNS, configuration, and networking crates.

## Before opening an issue

- Search existing issues and pull requests.
- Include the exact commit/release, OS/kernel, client/server platform, and reproducible steps.
- For networking reports, include redacted route, interface, forwarding, and firewall diagnostics where relevant.
- Never post private keys, identity seeds, certificates containing private material, obfuscation keys, credentials, public server IPs you do not want disclosed, or unredacted configs/logs.

## Development setup

Use a current stable Rust toolchain (edition 2024). Linux development also requires the native networking dependencies used by the workspace, including libmnl and libnftnl development headers. Android work additionally uses the Gradle/Android NDK toolchain documented under `apps/rvpn-android/android`.

Clone and validate:

~~~sh
git clone https://github.com/Frank1o3/rust-vpn.git
cd rust-vpn
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
~~~

The fuzz workspace is separate. Follow [fuzz/README.md](fuzz/README.md) and use the pinned cargo-fuzz/nightly toolchain before changing parser or protocol fuzz targets.

## Networking changes

Changes to TUN/TAP setup, routes, DNS, forwarding, firewall rules, NAT, kill-switch policy, endpoint protection, and teardown must be reviewed as host-networking changes, not just application logic.

- Preserve existing host routes and firewall policy; do not flush global firewall tables.
- Keep forwarding/NAT rules scoped to configured tunnel CIDRs and the selected egress interface.
- Test IPv4 and IPv6 independently.
- Verify both traffic directions and teardown after normal shutdown and process failure.
- Do not silently claim internet forwarding works merely because the tunnel handshake or server-address ping succeeds.
- Document required sysctls, capabilities, firewall backend, and configuration changes.
- Add tests for failure paths and cleanup; use an isolated network namespace or disposable VM for privileged integration tests.

## Protocol and cryptography changes

Do not invent cryptographic primitives or alter nonce construction, key derivation, replay protection, authentication, rekeying, or packet framing without a written invariant and focused tests. Avoid logging packet secrets, private keys, credentials, or full authentication material. Fuzz parsers and untrusted packet boundaries.

## Pull requests

- Keep changes focused and explain externally visible behavior.
- Add or update unit, integration, or fuzz tests.
- Update configuration and operational documentation when behavior changes.
- Include exact verification commands and results; state what was not run.
- Preserve upstream attribution and license notices.
- Avoid unrelated dependency or lockfile churn.
