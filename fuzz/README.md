# RVPN fuzzing

RVPN uses cargo-fuzz with LLVM libFuzzer for coverage-guided fuzzing. The fuzz
workspace is intentionally detached from the normal workspace, so regular
stable-toolchain validation remains separate from fuzzing.

## Prerequisites

    cargo install --locked cargo-fuzz --version 0.13.2
    rustup toolchain install nightly

## Targets

packet_decode exercises the untrusted VPN packet parser.

handshake_decode exercises handshake framing and length validation.

handshake_accept feeds decoded initiation frames into the responder handshake,
covering parser-to-crypto integration.

obfuscation_unwrap exercises ChaCha20-based obfuscation decoding against
arbitrary datagrams.

certificate_decode_verify exercises fixed-width certificate decoding and
Ed25519 verification against arbitrary certificate bytes.

session_aead_open exercises the ChaCha20-Poly1305 session decryption path with
arbitrary nonce, AAD, and ciphertext inputs.

## Commands

    cargo fuzz list

    cargo fuzz run packet_decode

    cargo fuzz run packet_decode -- -max_total_time=30

    for target in $(cargo fuzz list); do cargo fuzz build "$target"; done

## Normal workspace validation

    cargo check --workspace --all-targets
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo bench --workspace

Fuzzing uses nightly; the normal workspace commands remain available with the
stable toolchain.
