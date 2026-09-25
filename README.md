# RVPN

RVPN is a Rust VPN implementation with an authenticated, encrypted UDP data
plane, Linux TUN/TAP support, a multi-peer server, and an Android client. It
has moved past its original experimental/learning-project phase and is
functionally complete for its supported platforms — handshake, data
transport, rekeying, obfuscation, and peer roaming all work in real-world
testing, including against networks running active VPN scanning and deep
packet inspection.

That said, RVPN has **not been independently security-audited**. Treat it as
pre-beta: solid enough for personal and small-group use, not yet something
to stake critical infrastructure on. Community review of the handshake and
crypto is welcome and encouraged.

## Documentation

- [Architecture](docs/architecture.md) — components, packet flow, and security boundaries.
- [Configuration](docs/configuration.md) — server and client TOML reference.
- [Deployment and operations](docs/operations.md) — build, launch, routing, and verification.
- [Android client](docs/android.md) — Android-specific setup and limits.
- [Troubleshooting](docs/troubleshooting.md) — MTU, routing, firewall, and tray diagnostics.

## Platform support

- **Linux** — primary, fully supported target (server and client).
- **Android** — fully supported client, TUN-only.
- **Windows** — client build exists but is considered experimental/unofficial; not part of the current stabilization effort.
- macOS is a possible future target given its shared Unix/Linux lineage, but is not currently worked on.

## Validation

The repository supports stable checks, unit/integration tests, Clippy, Criterion
benchmarks, and coverage-guided fuzzing.

    cargo check --workspace --all-targets
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo bench --workspace

Fuzz targets live in the detached fuzz workspace. Install nightly and the
pinned cargo-fuzz version described in [fuzz/README.md](fuzz/README.md), then
run:

    cargo +nightly fuzz list
    cargo +nightly fuzz run packet_decode
    cargo +nightly fuzz run handshake_decode
    cargo +nightly fuzz run handshake_accept
    cargo +nightly fuzz run obfuscation_unwrap
    cargo +nightly fuzz run certificate_decode_verify
    cargo +nightly fuzz run session_aead_open

## Quick start

```sh
cargo build --release -p rvpn-server -p rvpn-client
sudo ./target/release/rvpn-server server.toml
sudo ./target/release/rvpn-client rvpn-setup/client-pc-laptop.toml
```

Then verify tunnel reachability:

```sh
ping 10.42.0.1
ping -6 fd42::1
```

RVPN creates non-persistent interfaces and restores routes and firewall state
on a graceful SIGINT or SIGTERM shutdown. See [operations](docs/operations.md)
before using it on a host with important existing network configuration.

## Authentication modes

RVPN supports two peer authentication modes, in increasing order of
strength: pinned Ed25519 key and certificate authority-issued identity.
Certificate auth is the intended primary mode going forward; see
[configuration](docs/configuration.md) for setup of each. (Pre-shared-key
"psk" mode was removed in v3.1)

## Important security notes

- RVPN has not undergone an independent security audit. Review the handshake
  and crypto code yourself, or wait for community review, before relying on
  it for anything sensitive.
- Do not commit real `local_identity_seed`, `pre_shared_key`, or
  `obfuscation_key` values. Treat them as passwords; rotate values exposed in
  logs, chats, or screenshots.
- Server `allowed_ips` are anti-spoofing policy. Each peer should receive only
  its own tunnel addresses, for example `10.42.0.2/32` and `fd42::2/128`.
- The current tray UI must run as the desktop user, while interface and route
  creation require elevated privileges. A production tray design should use an
  unprivileged UI communicating with a privileged service over authenticated
  local IPC.
