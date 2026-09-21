from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .crypto import KeyPair


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
