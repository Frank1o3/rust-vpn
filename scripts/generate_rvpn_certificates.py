#!/usr/bin/env python3
"""
Generate RVPN certificate-mode Ed25519 credentials.

This matches the certificate implementation in:
    crates/rvpn-crypto/src/identity.rs

RVPN's certificate is NOT X.509. It is a custom 112-byte value:

    subject_public_key (32 bytes)
    not_before         (8 bytes, big-endian Unix seconds)
    not_after          (8 bytes, big-endian Unix seconds)
    issuer_signature   (64 bytes, Ed25519 signature)

The complete certificate is therefore 112 bytes / 224 hex characters.

The Rust project already contains an equivalent generator example:
    cargo run -p rvpn-crypto --example gen_ca_and_cert

Install:
    python -m pip install cryptography

Usage:
    python generate_rvpn_certificates.py 3
    python generate_rvpn_certificates.py 3 --days 3650 -o rvpn-certificates.txt

For each peer this script generates:
    CA:
        ca_seed
        ca_public_key

    Peer:
        local_identity_seed
        local_certificate
        peer_public_key

The server should keep the CA seed offline. Clients receive their own
local_identity_seed + local_certificate + ca_public_key.

The server uses the peer public key as the certificate-authority peer
override / identity binding, according to the project's certificate mode.
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    print(
        "Missing dependency: cryptography\n"
        "Install it with:\n"
        "  python -m pip install cryptography",
        file=sys.stderr,
    )
    raise SystemExit(1)


CERTIFICATE_LENGTH = 112


@dataclass(frozen=True)
class Identity:
    seed: bytes
    public_key: bytes


def generate_identity() -> Identity:
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Raw Ed25519 private seed: exactly 32 bytes.
    seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Raw Ed25519 public key: exactly 32 bytes.
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    if len(seed) != 32:
        raise RuntimeError(f"unexpected Ed25519 seed size: {len(seed)}")

    if len(public_key) != 32:
        raise RuntimeError(f"unexpected Ed25519 public-key size: {len(public_key)}")

    return Identity(seed=seed, public_key=public_key)


def signed_fields(subject_public_key: bytes, not_before: int, not_after: int) -> bytes:
    if len(subject_public_key) != 32:
        raise ValueError("subject public key must be exactly 32 bytes")

    return (
        subject_public_key
        + int(not_before).to_bytes(8, "big", signed=False)
        + int(not_after).to_bytes(8, "big", signed=False)
    )


def issue_certificate(
    ca: Identity,
    subject: Identity,
    not_before: int,
    not_after: int,
) -> bytes:
    fields = signed_fields(subject.public_key, not_before, not_after)

    ca_private = ed25519.Ed25519PrivateKey.from_private_bytes(ca.seed)
    signature = ca_private.sign(fields)

    certificate = fields + signature

    if len(certificate) != CERTIFICATE_LENGTH:
        raise RuntimeError(
            f"unexpected certificate size: {len(certificate)} "
            f"(expected {CERTIFICATE_LENGTH})"
        )

    return certificate


def verify_certificate(
    ca_public_key: bytes,
    certificate: bytes,
    now: int,
) -> bool:
    if len(certificate) != CERTIFICATE_LENGTH:
        return False

    subject = certificate[:32]
    not_before = int.from_bytes(certificate[32:40], "big")
    not_after = int.from_bytes(certificate[40:48], "big")
    signature = certificate[48:]

    if now < not_before or now > not_after:
        return False

    fields = signed_fields(subject, not_before, not_after)

    try:
        ca_public = ed25519.Ed25519PublicKey.from_public_bytes(ca_public_key)
        ca_public.verify(signature, fields)
        return True
    except Exception:
        return False


def generate_output(peer_count: int, validity_days: int) -> str:
    now = int(time.time())
    not_before = now - 60
    not_after = now + validity_days * 24 * 60 * 60

    ca = generate_identity()

    lines: list[str] = [
        "# RVPN certificate-mode credentials",
        "# Generated from the same custom certificate layout used by RVPN.",
        "#",
        "# CA secret:",
        f'ca_seed = "{ca.seed.hex()}"',
        "",
        "# Server/public CA value:",
        f'ca_public_key = "{ca.public_key.hex()}"',
        "",
        f"# Certificate validity: {not_before} .. {not_after} (Unix seconds)",
        "",
    ]

    for index in range(1, peer_count + 1):
        peer = generate_identity()
        certificate = issue_certificate(
            ca=ca,
            subject=peer,
            not_before=not_before,
            not_after=not_after,
        )

        assert verify_certificate(
            ca_public_key=ca.public_key,
            certificate=certificate,
            now=now,
        ), "internal certificate verification failed"

        tunnel_ip = f"10.42.0.{index + 1}"

        lines.extend(
            [
                f"==================== PEER {index} ====================",
                "",
                f"# Peer {index} identity",
                f'local_identity_seed = "{peer.seed.hex()}"',
                f'local_certificate = "{certificate.hex()}"',
                f'peer_public_key = "{peer.public_key.hex()}"',
                "",
                "# Client-side [auth] example:",
                "[auth]",
                'mode = "certificate"',
                f'local_identity_seed = "{peer.seed.hex()}"',
                f'local_certificate = "{certificate.hex()}"',
                f'ca_public_key = "{ca.public_key.hex()}"',
                "",
                "# Server-side peer identity/override information:",
                f'peer_name = "peer-{index}"',
                f'allowed_ip = "{tunnel_ip}/32"',
                f'peer_public_key = "{peer.public_key.hex()}"',
                "",
                f"# Example client tunnel address: {tunnel_ip}/24",
                "",
                "",
            ]
        )

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate matching RVPN certificate-mode credentials."
    )
    parser.add_argument(
        "peers",
        type=int,
        help="number of peer/client identities to generate",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=3650,
        help="certificate validity period in days (default: 3650)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("rvpn-certificates.txt"),
        help="output file (default: rvpn-certificates.txt)",
    )

    args = parser.parse_args()

    if args.peers < 1:
        parser.error("peers must be at least 1")

    if args.peers > 1000:
        parser.error("peers must not exceed 1000")

    if args.days < 1:
        parser.error("--days must be at least 1")

    output = generate_output(args.peers, args.days)
    args.output.write_text(output, encoding="utf-8")

    print(f"Generated one CA and {args.peers} peer certificate(s).")
    print(f"Written to: {args.output}")
    print()
    print("Secret values:")
    print("  - ca_seed")
    print("  - every peer local_identity_seed")
    print()
    print("Values that can be distributed:")
    print("  - ca_public_key")
    print("  - each peer local_certificate")
    print("  - each peer public key")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())