"""Data model and Ed25519/certificate helpers for the RVPN setup generator."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

CERTIFICATE_LENGTH = 112


# --- crypto -----------------------------------------------------------


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


# --- setup model --------------------------------------------------------


@dataclass
class SecurityPolicy:
    retry_interval_ms: int = 500
    retry_limit: int = 5
    retry_jitter_ms: int = 150
    rekey_packet_limit: int = 1 << 20
    rekey_time_limit_secs: int = 120
    liveness_timeout_secs: int = 90


@dataclass
class ClientOptions:
    interface_name: str
    mode: str
    mtu: int
    tap_name: Optional[str]
    dns_servers: str
    default_route: bool
    gateway: Optional[str]
    endpoint_gateway: Optional[str]
    default_route_v6: bool
    gateway_v6: Optional[str]
    endpoint_gateway_v6: Optional[str]
    routes: list[str] = field(default_factory=list)


@dataclass
class SetupConfig:
    bind_address: str
    bind_port: int
    client_server_address: str
    endpoint_external: str
    server_interface_name: str
    server_mode: str
    server_mtu: int
    server_tap_name: Optional[str]
    server_v4: str
    ipv6_enabled: bool
    server_v6: str
    forwarding_enabled: bool
    forwarding_backend: str
    external_interface: str
    tunnel_cidr: str
    tunnel_cidr_v6: str
    obfuscation_enabled: bool
    obfuscation_key: str
    auth_mode: str
    security: SecurityPolicy
    ca_name: str = ""
    ca: Optional[KeyPair] = None
    server_identity: Optional[KeyPair] = None
    cert_valid_days: int = 3650
    ca_default_allowed_ips: list[str] = field(default_factory=list)
    revoked_subjects: list[str] = field(default_factory=list)


@dataclass
class PeerSetup:
    name: str
    platform: str
    tunnel_v4: str
    tunnel_v6: str
    client: ClientOptions
    server_psk: str = ""
    server_seed_hex: str = ""
    server_pub_hex: str = ""
    client_seed_hex: str = ""
    client_pub_hex: str = ""
    client_certificate_hex: str = ""

    @property
    def certificate_link_name(self) -> str:
        return f"cert:{self.client_pub_hex[:16]}"