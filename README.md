# RVPN

RVPN is an experimental Rust VPN project. It is being built incrementally to
explore a custom VPN protocol and UDP networking stack while relying on
established cryptographic primitives rather than home-grown cryptography.

## Workspace layout

- `crates/rvpn-core`: shared identifiers and errors.
- `crates/rvpn-protocol`: packet framing and protocol validation.
- `crates/rvpn-crypto`: secret-material boundary; cryptographic construction is
  deferred until the threat model and handshake are designed.
- `crates/rvpn-transport`: reusable, unencrypted UDP datagram transport.
- `crates/rvpn-config`: TOML parsing and validation.
- `apps/rvpn-client` and `apps/rvpn-server`: application entry points.

The lower-level crates do not depend on either application. In particular,
transport only moves opaque bytes and never encrypts or decrypts them.

Run the current checks with:

```sh
cargo test --workspace
```
