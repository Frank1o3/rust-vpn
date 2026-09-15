#!/usr/bin/env python3
"""
Interactive RVPN setup generator.

Walks through the same decisions server.toml / client.toml require and
writes out:

    server.toml
    client-<peer-name>.toml   (one per peer)

The per-peer client files are meant to be copied verbatim into the "Config"
tab of the RVPN Android app (paste the whole file contents there), the same
way a WireGuard client.conf is imported.

Requires only the standard library plus `cryptography` (already a
dependency of the other generator scripts in this repo):

    python -m pip install cryptography

Usage:
    python generate_rvpn_setup.py
    python generate_rvpn_setup.py --output-dir ./rvpn-setup
"""

from __future__ import annotations

import argparse
import ipaddress
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    print(
        "Missing dependency: cryptography\nInstall with: python -m pip install cryptography",
        file=sys.stderr,
    )
    raise SystemExit(1)


# --------------------------------------------------------------------------
# Small prompt helpers
# --------------------------------------------------------------------------

def prompt(text: str, default: Optional[str] = None, required: bool = False) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        value = input(f"{text}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if not value and required:
            print("  this value is required.")
            continue
        return value


def prompt_bool(text: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        value = input(f"{text} [{suffix}]: ").strip().lower()
        if not value:
            return default
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False
        print("  please answer y or n.")


def prompt_int(text: str, default: int) -> int:
    while True:
        value = input(f"{text} [{default}]: ").strip()
        if not value:
            return default
        try:
            return int(value)
        except ValueError:
            print("  please enter a whole number.")


def prompt_choice(text: str, choices: list[str], default: str) -> str:
    options = "/".join(c if c != default else c.upper() for c in choices)
    while True:
        value = input(f"{text} ({options}): ").strip().lower()
        if not value:
            return default
        if value in choices:
            return value
        print(f"  please choose one of: {', '.join(choices)}")


# --------------------------------------------------------------------------
# Key / secret generation
# --------------------------------------------------------------------------

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
    import os
    return os.urandom(num_bytes).hex()


CERTIFICATE_LENGTH = 112


def signed_fields(subject_public_key: bytes, not_before: int, not_after: int) -> bytes:
    return (
        subject_public_key
        + int(not_before).to_bytes(8, "big")
        + int(not_after).to_bytes(8, "big")
    )


def issue_certificate(ca_seed_hex: str, subject_public_key_hex: str, days: int) -> str:
    ca_private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ca_seed_hex))
    subject_public_key = bytes.fromhex(subject_public_key_hex)
    now = int(time.time())
    not_before = now - 60
    not_after = now + days * 24 * 60 * 60
    fields = signed_fields(subject_public_key, not_before, not_after)
    signature = ca_private.sign(fields)
    certificate = fields + signature
    assert len(certificate) == CERTIFICATE_LENGTH
    return certificate.hex()


# --------------------------------------------------------------------------
# Network helpers
# --------------------------------------------------------------------------

def detect_external_interface() -> Optional[str]:
    """Best-effort detection of the interface carrying the default route.

    Tries `ip route get` first (matches how the rest of this project shells
    out to `ip`), and falls back to `psutil` if it happens to be installed.
    """
    if shutil.which("ip"):
        try:
            output = subprocess.check_output(
                ["ip", "route", "get", "8.8.8.8"], text=True, timeout=3
            )
            fields = output.split()
            if "dev" in fields:
                return fields[fields.index("dev") + 1]
        except Exception:
            pass

    try:
        import psutil  # type: ignore

        gateways = psutil.net_if_stats()
        # psutil has no direct "default route interface" API; fall back to
        # the first interface that is up and not loopback as a rough guess.
        for name, stats in gateways.items():
            if stats.isup and name != "lo":
                return name
    except Exception:
        pass

    return None


def network_cidr(address_with_prefix: str) -> str:
    """'10.42.0.1/24' -> '10.42.0.0/24' (also works for IPv6)."""
    interface = ipaddress.ip_interface(address_with_prefix)
    return str(interface.network)


def host_at_offset(address_with_prefix: str, offset: int) -> str:
    """Nth host address in the same network as `address_with_prefix`."""
    interface = ipaddress.ip_interface(address_with_prefix)
    host = ipaddress.ip_address(int(interface.network.network_address) + offset)
    return str(host)


def prefix_length(address_with_prefix: str) -> int:
    return ipaddress.ip_interface(address_with_prefix).network.prefixlen


# --------------------------------------------------------------------------
# TOML formatting (hand-rolled to avoid a non-stdlib TOML writer dependency)
# --------------------------------------------------------------------------

def toml_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def toml_list(values: list[str]) -> str:
    return "[" + ", ".join(toml_str(v) for v in values) + "]"


# --------------------------------------------------------------------------
# Config model
# --------------------------------------------------------------------------

@dataclass
class SetupConfig:
    bind_address: str
    bind_port: int
    client_server_address: str  # host:port as reached by clients
    interface_name: str
    mode: str
    mtu: int
    server_v4: str  # e.g. 10.42.0.1/24
    ipv6_enabled: bool
    server_v6: str  # e.g. fd42::1/64, empty if disabled
    forwarding_enabled: bool
    forwarding_backend: str
    external_interface: str
    tunnel_cidr: str
    tunnel_cidr_v6: str
    obfuscation_enabled: bool
    obfuscation_key: str
    auth_mode: str  # psk | pinned-key | certificate
    ca: Optional[KeyPair] = None
    ca_cert_days: int = 3650
    endpoint_gateway: str = ""


@dataclass
class PeerSetup:
    name: str
    platform: str  # "pc" or "android"
    tunnel_v4: str
    tunnel_v6: str
    # server-side auth material
    server_psk: str = ""
    server_seed_hex: str = ""       # server's local identity for this peer (pinned-key)
    server_pub_hex: str = ""
    # client-side auth material
    client_seed_hex: str = ""
    client_pub_hex: str = ""
    client_certificate_hex: str = ""


def gather_setup() -> SetupConfig:
    print("== RVPN interactive setup ==\n")

    bind_address = prompt("Bind address", default="0.0.0.0")
    bind_port = prompt_int("Bind port", default=9000)

    default_client_addr = None if bind_address == "0.0.0.0" else bind_address
    client_server_address = prompt(
        "Server address as reached by clients (host or IP)",
        default=default_client_addr,
        required=default_client_addr is None,
    )

    interface_name = prompt("Server interface name", default="rvpn-server0")
    mode = prompt_choice("Interface mode", ["tun", "tap", "both"], default="tun")
    mtu = prompt_int("MTU", default=1400)

    server_v4 = prompt("Server interface IPv4 address (CIDR)", default="10.42.0.1/24")
    ipv6_enabled = prompt_bool("Enable IPv6", default=True)
    server_v6 = ""
    if ipv6_enabled:
        server_v6 = prompt("Server interface IPv6 address (CIDR)", default="fd42::1/64")

    tunnel_cidr = network_cidr(server_v4)
    tunnel_cidr_v6 = network_cidr(server_v6) if ipv6_enabled else ""
    print(f"  -> derived IPv4 tunnel_cidr: {tunnel_cidr}")
    if ipv6_enabled:
        print(f"  -> derived IPv6 tunnel_cidr: {tunnel_cidr_v6}")

    forwarding_enabled = prompt_bool("Enable internet gateway / NAT forwarding", default=True)
    forwarding_backend = "auto"
    external_interface = ""
    if forwarding_enabled:
        forwarding_backend = prompt_choice(
            "Firewall backend", ["auto", "iptables", "nftables"], default="auto"
        )
        detected = detect_external_interface()
        external_interface = prompt(
            "External (internet-facing) interface",
            default=detected,
            required=detected is None,
        )

    obfuscation_enabled = prompt_bool("Enable packet obfuscation", default=False)
    obfuscation_key = generate_hex_secret(32) if obfuscation_enabled else ""

    auth_mode = prompt_choice(
        "Peer authentication mode", ["psk", "pinned-key", "certificate"], default="pinned-key"
    )

    ca = None
    ca_cert_days = 3650
    if auth_mode == "certificate":
        print("Generating a certificate authority for this setup...")
        ca = generate_keypair()
        ca_cert_days = prompt_int("Certificate validity (days)", default=3650)

    endpoint_gateway = ""
    if prompt_bool(
        "Are clients on the same LAN as the server (set endpoint_gateway to the server's LAN IP)?",
        default=True,
    ):
        endpoint_gateway = client_server_address

    return SetupConfig(
        bind_address=bind_address,
        bind_port=bind_port,
        client_server_address=f"{client_server_address}:{bind_port}",
        interface_name=interface_name,
        mode=mode,
        mtu=mtu,
        server_v4=server_v4,
        ipv6_enabled=ipv6_enabled,
        server_v6=server_v6,
        forwarding_enabled=forwarding_enabled,
        forwarding_backend=forwarding_backend,
        external_interface=external_interface,
        tunnel_cidr=tunnel_cidr,
        tunnel_cidr_v6=tunnel_cidr_v6,
        obfuscation_enabled=obfuscation_enabled,
        obfuscation_key=obfuscation_key,
        auth_mode=auth_mode,
        ca=ca,
        ca_cert_days=ca_cert_days,
        endpoint_gateway=endpoint_gateway,
    )


def gather_peers(setup: SetupConfig) -> list[PeerSetup]:
    pc_count = prompt_int("How many PC peers to generate", default=0)
    android_count = prompt_int("How many Android peers to generate", default=1)

    if pc_count < 0 or android_count < 0:
        raise ValueError("Peer counts cannot be negative.")

    peer_specs: list[tuple[str, int]] = (
        [("pc", index) for index in range(1, pc_count + 1)]
        + [("android", index) for index in range(1, android_count + 1)]
    )

    peers: list[PeerSetup] = []

    for global_index, (platform, platform_index) in enumerate(peer_specs, start=1):
        print(f"\n-- {platform.capitalize()} peer {platform_index} --")

        default_name = f"{platform}-{platform_index}"
        name = prompt("Peer name", default=default_name)

        # Offset 1 is the server's own address; peers start at offset 2.
        # Every generated peer receives a unique address regardless of platform.
        tunnel_v4 = host_at_offset(setup.server_v4, global_index + 1)
        tunnel_v6 = (
            host_at_offset(setup.server_v6, global_index + 1)
            if setup.ipv6_enabled
            else ""
        )

        peer = PeerSetup(
            name=name,
            platform=platform,
            tunnel_v4=tunnel_v4,
            tunnel_v6=tunnel_v6,
        )

        if setup.auth_mode == "psk":
            peer.server_psk = generate_hex_secret(32)
        elif setup.auth_mode == "pinned-key":
            server_side = generate_keypair()
            client_side = generate_keypair()
            peer.server_seed_hex = server_side.seed
            peer.server_pub_hex = server_side.public_key
            peer.client_seed_hex = client_side.seed
            peer.client_pub_hex = client_side.public_key
        elif setup.auth_mode == "certificate":
            assert setup.ca is not None
            client_identity = generate_keypair()
            peer.client_seed_hex = client_identity.seed
            peer.client_pub_hex = client_identity.public_key
            peer.client_certificate_hex = issue_certificate(
                setup.ca.seed,
                client_identity.public_key,
                setup.ca_cert_days,
            )

        peers.append(peer)

    return peers


# --------------------------------------------------------------------------
# File rendering
# --------------------------------------------------------------------------

def render_server_toml(setup: SetupConfig, peers: list[PeerSetup]) -> str:
    lines = ["# RVPN Server configuration (generated)", ""]
    lines.append(f"bind={toml_str(f'{setup.bind_address}:{setup.bind_port}')}")
    if setup.obfuscation_enabled:
        lines.append(f"obfuscation_key={toml_str(setup.obfuscation_key)}")
    lines.append("")

    lines.append("[interface]")
    lines.append(f"    address={toml_str(setup.server_v4)}")
    if setup.ipv6_enabled:
        lines.append(f"    addresses={toml_list([setup.server_v6])}")
    lines.append(f"    mode={toml_str(setup.mode)}")
    lines.append(f"    mtu={setup.mtu}")
    lines.append(f"    name={toml_str(setup.interface_name)}")
    lines.append("")

    if setup.forwarding_enabled:
        lines.append("[forwarding]")
        lines.append("    enabled=true")
        lines.append(f"    backend={toml_str(setup.forwarding_backend)}")
        lines.append(f"    external_interface={toml_str(setup.external_interface)}")
        lines.append(f"    tunnel_cidr={toml_str(setup.tunnel_cidr)}")
        if setup.ipv6_enabled:
            lines.append(f"    tunnel_cidr_v6={toml_str(setup.tunnel_cidr_v6)}")
        lines.append("")

    if setup.auth_mode == "certificate":
        assert setup.ca is not None
        lines.append("[certificate_authority]")
        lines.append(f"    name={toml_str('rvpn-ca')}")
        lines.append(f"    ca_public_key={toml_str(setup.ca.public_key)}")
        # The server's own identity/cert under the CA -- reuse the CA's key
        # as a self-issued identity is unnecessary; server verifies clients
        # by CA public key only, so no local identity is required here.
        lines.append("")

    for peer in peers:
        allowed_ips = [f"{peer.tunnel_v4}/32"]
        if setup.ipv6_enabled:
            allowed_ips.append(f"{peer.tunnel_v6}/128")

        lines.append("[[peers]]")
        lines.append(f"    allowed_ips={toml_list(allowed_ips)}")
        lines.append(f"    name={toml_str(peer.name)}")
        lines.append("")
        lines.append("    [peers.auth]")
        if setup.auth_mode == "psk":
            lines.append(f"        mode={toml_str('psk')}")
            lines.append(f"        pre_shared_key={toml_str(peer.server_psk)}")
        elif setup.auth_mode == "pinned-key":
            lines.append(f"        mode={toml_str('pinned-key')}")
            lines.append(f"        local_identity_seed={toml_str(peer.server_seed_hex)}")
            lines.append(f"        peer_public_key={toml_str(peer.client_pub_hex)}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_client_toml(setup: SetupConfig, peer: PeerSetup) -> str:
    lines = [f"# RVPN Client configuration for '{peer.name}' (generated)", ""]
    lines.append(f"server={toml_str(setup.client_server_address)}")
    if setup.obfuscation_enabled:
        lines.append(f"obfuscation_key={toml_str(setup.obfuscation_key)}")
    lines.append("")

    addresses = []
    if setup.ipv6_enabled:
        addresses.append(f"{peer.tunnel_v6}/{prefix_length(setup.server_v6)}")

    lines.append("[interface]")
    lines.append(f"    address={toml_str(f'{peer.tunnel_v4}/{prefix_length(setup.server_v4)}')}")
    if addresses:
        lines.append(f"    addresses={toml_list(addresses)}")
    # Client peers use TUN. Android's VpnService exposes a TUN interface,
    # and the desktop client is also intended to use the virtual TUN device.
    lines.append(f"    mode={toml_str('tun')}")
    lines.append(f"    mtu={setup.mtu}")
    lines.append(f"    name={toml_str(f"rvpn-{peer.platform}-{slugify(peer.name)}")}")
    lines.append("")

    lines.append("[routing]")
    lines.append("    default_route=true")
    if setup.ipv6_enabled:
        lines.append("    default_route_v6=true")
    if setup.endpoint_gateway:
        lines.append(f"    endpoint_gateway={toml_str(setup.endpoint_gateway)}")
    lines.append(f"    gateway={toml_str(setup.server_v4.split('/')[0])}")
    if setup.ipv6_enabled:
        lines.append(f"    gateway_v6={toml_str(setup.server_v6.split('/')[0])}")
    lines.append("")

    lines.append("[auth]")
    if setup.auth_mode == "psk":
        lines.append(f"    mode={toml_str('psk')}")
        lines.append(f"    pre_shared_key={toml_str(peer.server_psk)}")
    elif setup.auth_mode == "pinned-key":
        lines.append(f"    mode={toml_str('pinned-key')}")
        lines.append(f"    local_identity_seed={toml_str(peer.client_seed_hex)}")
        lines.append(f"    peer_public_key={toml_str(peer.server_pub_hex)}")
    elif setup.auth_mode == "certificate":
        assert setup.ca is not None
        lines.append(f"    mode={toml_str('certificate')}")
        lines.append(f"    local_identity_seed={toml_str(peer.client_seed_hex)}")
        lines.append(f"    local_certificate={toml_str(peer.client_certificate_hex)}")
        lines.append(f"    ca_public_key={toml_str(setup.ca.public_key)}")
    lines.append("")
    lines.append("[handshake]")
    lines.append("    retry_interval_ms=150")
    lines.append("    retry_limit=5")
    lines.append("")
    lines.append("[rekey]")
    lines.append("    packet_limit=1000000")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def slugify(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in name.strip().lower())


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive RVPN setup generator")
    parser.add_argument(
        "-o", "--output-dir", type=Path, default=Path("rvpn-setup"),
        help="directory to write server.toml and client-*.toml into (default: ./rvpn-setup)",
    )
    args = parser.parse_args()

    setup = gather_setup()
    peers = gather_peers(setup)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    server_path = args.output_dir / "server.toml"
    server_path.write_text(render_server_toml(setup, peers), encoding="utf-8")
    print(f"\nWrote {server_path}")

    for peer in peers:
        client_path = (
            args.output_dir
            / f"client-{peer.platform}-{slugify(peer.name)}.toml"
        )
        client_path.write_text(render_client_toml(setup, peer), encoding="utf-8")
        print(f"Wrote {client_path}")

    print(
        "\nDone. PC and Android client TOML files were generated separately."
    )
    print(
        "Android files can be pasted into the Android app's Config tab; "
        "PC files can be used as desktop client configurations."
    )
    if setup.auth_mode == "certificate":
        print("Keep the CA seed offline -- it was not written to any file above.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
