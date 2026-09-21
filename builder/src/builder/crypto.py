from __future__ import annotations

import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


CERTIFICATE_LENGTH = 112


@dataclass(frozen=True)
class KeyPair:
    seed: str
    public_key: str


def generate_keypair() -> KeyPair:
    private_key = ed25519.Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return KeyPair(seed.hex(), public_key.hex())


def generate_hex_secret(num_bytes: int = 32) -> str:
    return os.urandom(num_bytes).hex()


def signed_fields(subject_public_key: bytes, not_before: int, not_after: int) -> bytes:
    return (
        subject_public_key
        + int(not_before).to_bytes(8, "big")
        + int(not_after).to_bytes(8, "big")
    )


def issue_certificate(ca_seed_hex: str, subject_public_key_hex: str, days: int) -> str:
    ca_private = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(ca_seed_hex)
    )
    subject_public_key = bytes.fromhex(subject_public_key_hex)
    now = int(time.time())
    not_before = now - 60
    not_after = now + days * 24 * 60 * 60
    fields = signed_fields(subject_public_key, not_before, not_after)
    signature = ca_private.sign(fields)
    certificate = fields + signature
    assert len(certificate) == CERTIFICATE_LENGTH
    return certificate.hex()
