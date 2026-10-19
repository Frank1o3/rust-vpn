"""Certificate peer enrollment, renewal, and revocation commands."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
import tomllib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .models import generate_keypair, issue_certificate, signed_fields
from .render import emit_android_qr, toml_list, toml_str

CERTIFICATE_LENGTH = 112


def _read_toml(path: Path) -> tuple[str, dict]:
    text = path.read_text(encoding="utf-8")
    return text, tomllib.loads(text)


def _load_ca_seed(path: Path, server_config: dict) -> str:
    seed = path.read_text(encoding="ascii").strip().lower()
    if len(seed) != 64:
        raise ValueError(f"CA seed file {path} must contain 64 hexadecimal characters")
    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    except ValueError as error:
        raise ValueError(f"CA seed file {path} is not valid hexadecimal key material") from error
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    expected = _certificate_authority(server_config)["ca_public_key"].lower()
    if public_key != expected:
        raise ValueError("CA seed does not match certificate_authority.ca_public_key")
    return seed


def _certificate_authority(config: dict) -> dict:
    ca = config.get("certificate_authority")
    if not isinstance(ca, dict):
        raise ValueError("server config does not contain [certificate_authority]")
    required = ("ca_public_key", "local_identity_seed", "local_certificate")
    if any(key not in ca for key in required):
        raise ValueError("server certificate authority config is incomplete")
    if any(not isinstance(ca[key], str) for key in required):
        raise ValueError("server certificate authority key and certificate values must be strings")
    ca.setdefault("peer_overrides", {})
    ca.setdefault("revoked_subjects", [])
    if not isinstance(ca["peer_overrides"], dict) or not isinstance(ca["revoked_subjects"], list):
        raise ValueError("server certificate authority peer records are invalid")
    if any(
        not isinstance(subject, str)
        or not isinstance(prefixes, list)
        or any(not isinstance(prefix, str) for prefix in prefixes)
        for subject, prefixes in ca["peer_overrides"].items()
    ) or any(not isinstance(subject, str) for subject in ca["revoked_subjects"]):
        raise ValueError("server certificate authority peer records are invalid")
    return ca


def _decode_certificate(value: str) -> bytes:
    try:
        certificate = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("client certificate must be hexadecimal") from error
    if len(certificate) != CERTIFICATE_LENGTH:
        raise ValueError("client certificate must be 112 bytes encoded as hexadecimal")
    return certificate


def _verify_certificate(value: str, ca_public_key: str) -> bytes:
    certificate = _decode_certificate(value)
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(ca_public_key))
        public_key.verify(
            certificate[48:],
            signed_fields(certificate[:32], int.from_bytes(certificate[32:40], "big"), int.from_bytes(certificate[40:48], "big")),
        )
    except (ValueError, TypeError) as error:
        raise ValueError("certificate authority public key is invalid") from error
    except Exception as error:
        raise ValueError("client certificate was not signed by the configured certificate authority") from error
    return certificate


def _read_certificate_client(path: Path, server_config: dict) -> tuple[str, dict, dict, bytes]:
    text, client = _read_toml(path)
    auth = client.get("auth")
    if not isinstance(auth, dict) or auth.get("mode") != "certificate":
        raise ValueError(f"{path} is not a certificate-authenticated client config")
    ca = _certificate_authority(server_config)
    client_ca = auth.get("ca_public_key")
    if not isinstance(client_ca, str) or client_ca.lower() != ca["ca_public_key"].lower():
        raise ValueError("client config trusts a different certificate authority")
    client_certificate = auth.get("local_certificate")
    if not isinstance(client_certificate, str):
        raise ValueError("client config does not contain a certificate")
    certificate = _verify_certificate(client_certificate, ca["ca_public_key"])
    return text, client, auth, certificate


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _toml_header(line: str) -> bool:
    value = line.split("#", 1)[0].strip()
    return value.startswith("[") and value.endswith("]") and "=" not in value


def _section_bounds(lines: list[str], section: str) -> tuple[int, int] | None:
    header = f"[{section}]"
    start = next((index for index, line in enumerate(lines) if line.strip() == header), None)
    if start is None:
        return None
    end = next((index for index in range(start + 1, len(lines)) if _toml_header(lines[index])), len(lines))
    return start, end


def _set_section_key(text: str, section: str, key: str, value: str) -> str:
    lines = text.splitlines()
    bounds = _section_bounds(lines, section)
    assignment = f"    {key}={value}"
    if bounds is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend([f"[{section}]", assignment])
    else:
        start, end = bounds
        key_pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
        existing = next((index for index in range(start + 1, end) if key_pattern.match(lines[index])), None)
        if existing is None:
            lines.insert(end, assignment)
        else:
            lines[existing] = assignment
    return "\n".join(lines).rstrip() + "\n"


def _remove_section_key(text: str, section: str, key: str) -> str:
    lines = text.splitlines()
    bounds = _section_bounds(lines, section)
    if bounds is None:
        return text
    start, end = bounds
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    lines = [line for index, line in enumerate(lines) if not (start < index < end and pattern.match(line))]
    return "\n".join(lines).rstrip() + "\n"


def _write_new_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_private_replace(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o600)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)


def _slug(value: str) -> str:
    slug = "".join(char if char.isalnum() or char in "-_" else "-" for char in value.strip().lower())
    return slug or "peer"


def _endpoint(value: str) -> str:
    value = value.strip()
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or value[closing + 1 : closing + 2] != ":":
            raise ValueError("server endpoint must use [IPv6]:port form")
        host, port_text = value[1:closing], value[closing + 2 :]
        if not isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            raise ValueError("bracketed server endpoint must contain an IPv6 address")
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator or ":" in host or not host:
            raise ValueError("server endpoint must use host:port or [IPv6]:port form")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
                raise ValueError("server endpoint host must be an IP address or hostname")
    try:
        port = int(port_text)
    except ValueError as error:
        raise ValueError("server endpoint port must be a number") from error
    if not 1 <= port <= 65535:
        raise ValueError("server endpoint port must be between 1 and 65535")
    return value


def _interface_addresses(config: dict) -> tuple[ipaddress.IPv4Interface, ipaddress.IPv6Interface | None]:
    interface = config.get("interface", {})
    entries = ([interface["address"]] if interface.get("address") else []) + interface.get("addresses", [])
    parsed = [ipaddress.ip_interface(value) for value in entries]
    ipv4 = next((address for address in parsed if isinstance(address, ipaddress.IPv4Interface)), None)
    ipv6 = next((address for address in parsed if isinstance(address, ipaddress.IPv6Interface)), None)
    if ipv4 is None:
        raise ValueError("server interface must have an IPv4 address to enroll a peer")
    return ipv4, ipv6


def _used_networks(ca: dict, interface_addresses: tuple) -> list[ipaddress._BaseNetwork]:
    values: list[str] = []
    for prefixes in ca.get("peer_overrides", {}).values():
        values.extend(prefixes)
    values.extend(str(address.ip) for address in interface_addresses if address is not None)
    return [ipaddress.ip_network(value, strict=False) for value in values]


def _next_address(interface: ipaddress.IPv4Interface | ipaddress.IPv6Interface, used: list) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    for candidate in interface.network.hosts():
        if candidate != interface.ip and not any(
            candidate.version == network.version and candidate in network for network in used
        ):
            return candidate
    raise ValueError(f"no free addresses remain in tunnel subnet {interface.network}")


def _format_enrolled_client(
    *,
    endpoint: str,
    ca_public_key: str,
    identity_seed: str,
    certificate: str,
    ipv4: ipaddress.IPv4Interface,
    ipv4_peer: ipaddress.IPv4Address,
    ipv6: ipaddress.IPv6Interface | None,
    ipv6_peer: ipaddress.IPv6Address | None,
    server_config: dict,
    name: str,
) -> str:
    server_interface = server_config.get("interface", {})
    server_v4 = ipv4.ip
    server_v6 = ipv6.ip if ipv6 else None
    interface_name = f"rvpn-{_slug(name)}"[:15]
    dns_enabled = bool(server_config.get("dns", {}).get("upstreams"))
    dns_servers = [str(server_v4)] if dns_enabled else []
    if dns_enabled and server_v6:
        dns_servers.append(str(server_v6))
    forwarding = server_config.get("forwarding", {})
    route_v4 = bool(forwarding.get("enabled", False))
    route_v6 = route_v4 and ipv6_peer is not None and bool(forwarding.get("tunnel_cidr_v6"))
    lines = [f"# RVPN Client configuration for '{name}' (enrolled)", "", f"server={toml_str(endpoint)}"]
    if server_config.get("obfuscation_key"):
        lines.append(f"obfuscation_key={toml_str(server_config['obfuscation_key'])}")
    lines.extend([
        "",
        "[interface]",
        f"    address={toml_str(f'{ipv4_peer}/{ipv4.network.prefixlen}')}",
        '    mode="tun"',
        f"    mtu={int(server_interface.get('mtu') or 1400)}",
        f"    name={toml_str(interface_name)}",
    ])
    if ipv6_peer is not None and ipv6 is not None:
        lines.append(f"    addresses={toml_list([f'{ipv6_peer}/{ipv6.network.prefixlen}'])}")
    if dns_servers:
        lines.append(f"    dns_servers={toml_str(', '.join(dns_servers))}")
    lines.extend([
        "",
        "[routing]",
        f"    default_route={'true' if route_v4 else 'false'}",
        f"    default_route_v6={'true' if route_v6 else 'false'}",
    ])
    if route_v4:
        lines.append(f"    gateway={toml_str(str(server_v4))}")
    if route_v6 and server_v6:
        lines.append(f"    gateway_v6={toml_str(str(server_v6))}")
    lines.extend([
        "",
        "[auth]",
        '    mode="certificate"',
        f"    local_identity_seed={toml_str(identity_seed)}",
        f"    local_certificate={toml_str(certificate)}",
        f"    ca_public_key={toml_str(ca_public_key)}",
    ])
    for section in ("handshake", "rekey", "liveness"):
        values = server_config.get(section, {})
        if values:
            lines.extend(["", f"[{section}]"])
            lines.extend(f"    {key}={json.dumps(value)}" for key, value in values.items())
    return "\n".join(lines).rstrip() + "\n"


def enroll_peer(
    *,
    server_config_path: Path,
    ca_seed_path: Path | None,
    name: str,
    endpoint: str,
    output_path: Path | None,
    valid_days: int,
    android: bool = False,
) -> tuple[Path, Path]:
    if not name.strip():
        raise ValueError("peer name must not be empty")
    if not 1 <= valid_days <= 36500:
        raise ValueError("certificate validity must be between 1 and 36500 days")
    endpoint = _endpoint(endpoint)
    server_text, server = _read_toml(server_config_path)
    ca = _certificate_authority(server)
    seed_path = ca_seed_path or server_config_path.parent / "ca-private-seed.hex"
    ca_seed = _load_ca_seed(seed_path, server)
    ipv4, ipv6 = _interface_addresses(server)
    used = _used_networks(ca, (ipv4, ipv6))
    peer_v4 = _next_address(ipv4, used)
    peer_v6 = _next_address(ipv6, used) if ipv6 else None
    identity = generate_keypair()
    if identity.public_key in ca["peer_overrides"] or identity.public_key in ca["revoked_subjects"]:
        raise ValueError("generated identity already exists in certificate authority records")
    certificate = issue_certificate(ca_seed, identity.public_key, valid_days)
    client_text = _format_enrolled_client(
        endpoint=endpoint,
        ca_public_key=ca["ca_public_key"],
        identity_seed=identity.seed,
        certificate=certificate,
        ipv4=ipv4,
        ipv4_peer=peer_v4,
        ipv6=ipv6,
        ipv6_peer=peer_v6,
        server_config=server,
        name=name,
    )
    allowed = [f"{peer_v4}/32"]
    if peer_v6 is not None:
        allowed.append(f"{peer_v6}/128")
    updated_server = _set_section_key(
        server_text,
        "certificate_authority.peer_overrides",
        _quote(identity.public_key),
        toml_list(allowed),
    )
    client_path = output_path or server_config_path.parent / f"client-{_slug(name)}.toml"
    client_path = client_path.resolve()
    server_config_path = server_config_path.resolve()
    if client_path == server_config_path:
        raise ValueError("client output path must differ from the server config path")
    _write_new_private(client_path, client_text)
    try:
        _atomic_private_replace(server_config_path, updated_server)
    except Exception:
        client_path.unlink(missing_ok=True)
        raise
    if android:
        emit_android_qr(name, client_text, client_path.with_suffix(".png"))
    return server_config_path, client_path


def renew_peer(
    *, server_config_path: Path, ca_seed_path: Path | None, client_config_path: Path, valid_days: int
) -> Path:
    if not 1 <= valid_days <= 36500:
        raise ValueError("certificate validity must be between 1 and 36500 days")
    server_config_path = server_config_path.resolve()
    client_config_path = client_config_path.resolve()
    if server_config_path == client_config_path:
        raise ValueError("client config path must differ from the server config path")
    server_text, server = _read_toml(server_config_path)
    ca = _certificate_authority(server)
    seed_path = ca_seed_path or server_config_path.parent / "ca-private-seed.hex"
    ca_seed = _load_ca_seed(seed_path, server)
    client_text, _, auth, certificate = _read_certificate_client(client_config_path, server)
    subject = certificate[:32].hex()
    try:
        identity_seed = auth["local_identity_seed"]
        if not isinstance(identity_seed, str):
            raise ValueError
        client_private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(identity_seed))
    except (ValueError, KeyError) as error:
        raise ValueError("client identity seed is invalid") from error
    client_public = client_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    if client_public != subject:
        raise ValueError("client identity seed does not match its certificate")
    if any(subject.lower() == revoked.lower() for revoked in ca["revoked_subjects"]):
        raise ValueError("cannot renew a revoked peer identity; enroll a new peer instead")
    renewed = issue_certificate(ca_seed, subject, valid_days)
    updated_client = _set_section_key(client_text, "auth", "local_certificate", toml_str(renewed))
    _atomic_private_replace(client_config_path, updated_client)
    return client_config_path


def revoke_peer(*, server_config_path: Path, client_config_path: Path) -> Path:
    server_config_path = server_config_path.resolve()
    client_config_path = client_config_path.resolve()
    if server_config_path == client_config_path:
        raise ValueError("client config path must differ from the server config path")
    server_text, server = _read_toml(server_config_path)
    ca = _certificate_authority(server)
    _, _, _, certificate = _read_certificate_client(client_config_path, server)
    subject = certificate[:32].hex()
    if any(subject.lower() == revoked.lower() for revoked in ca["revoked_subjects"]):
        raise ValueError("peer is already revoked")
    revoked = [*ca["revoked_subjects"], subject]
    updated = _set_section_key(server_text, "certificate_authority", "revoked_subjects", toml_list(revoked))
    updated = _remove_section_key(updated, "certificate_authority.peer_overrides", _quote(subject))
    _atomic_private_replace(server_config_path, updated)
    return server_config_path
