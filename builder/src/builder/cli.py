"""Interactive RVPN configuration generator: prompts for a server + peer set,
then writes server.toml and one client-*.toml per peer."""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import (
    ClientOptions,
    PeerSetup,
    SecurityPolicy,
    SetupConfig,
    generate_hex_secret,
    generate_keypair,
    issue_certificate,
)
from .prompts import (
    console,
    derive_dns_from_endpoint_external,
    detect_external_interface,
    prompt,
    prompt_bool,
    prompt_cidr_list,
    prompt_choice,
    prompt_dns_servers,
    prompt_endpoint_host,
    prompt_index_group,
    prompt_int,
    prompt_interface_name,
    prompt_ip,
    prompt_network,
    prompt_hex_list,
)
from .render import render_client_toml, render_server_toml, emit_android_qr


def network_cidr(address_with_prefix: str) -> str:
    return str(ipaddress.ip_interface(address_with_prefix).network)


def host_at_offset(address_with_prefix: str, offset: int) -> str:
    interface = ipaddress.ip_interface(address_with_prefix)
    host = ipaddress.ip_address(int(interface.network.network_address) + offset)
    if host not in interface.network:
        raise ValueError(
            f"not enough addresses in {interface.network} for generated peer #{offset - 1}"
        )
    return str(host)


def format_endpoint(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def slugify(name: str) -> str:
    value = "".join(
        c if c.isalnum() or c in "-_" else "-" for c in name.strip().lower()
    )
    return value or "peer"


def section(title: str) -> None:
    console.print(Panel(title, style="cyan", expand=False))


def ask_security() -> SecurityPolicy:
    section("Handshake / session security")
    retry_interval_ms = prompt_int(
        "Handshake retry interval (ms)", 500, minimum=1, maximum=86_400_000
    )
    retry_limit = prompt_int("Handshake retry limit", 5, minimum=1, maximum=1_000)
    retry_jitter_ms = prompt_int(
        "Handshake retry jitter (ms)", 150, minimum=0, maximum=86_400_000
    )
    rekey_packet_limit = prompt_int("Rekey packet limit (0 disables)", 1 << 20, minimum=0)
    rekey_time_limit_secs = prompt_int(
        "Rekey time limit (seconds, 0 disables)", 120, minimum=0
    )
    rekey_grace_period_secs = prompt_int(
        "Rekey previous-key grace period (seconds, 0 disables)", 15, minimum=0
    )

    while True:
        liveness_timeout_secs = prompt_int(
            "Liveness timeout (seconds, 0 disables; otherwise >= 60)", 90, minimum=0
        )
        if liveness_timeout_secs == 0 or liveness_timeout_secs >= 60:
            break
        console.print("  [red]RVPN requires liveness.timeout_secs to be 0 or at least 60.[/red]")

    return SecurityPolicy(
        retry_interval_ms=retry_interval_ms,
        retry_limit=retry_limit,
        retry_jitter_ms=retry_jitter_ms,
        rekey_packet_limit=rekey_packet_limit,
        rekey_time_limit_secs=rekey_time_limit_secs,
        rekey_grace_period_secs=rekey_grace_period_secs,
        liveness_timeout_secs=liveness_timeout_secs,
    )


def ask_server() -> SetupConfig:
    console.rule("[bold]RVPN interactive setup")

    bind_address = prompt_ip("Server bind address", "0.0.0.0")
    bind_port = prompt_int("Server bind port", 9000, minimum=1, maximum=65535)

    endpoint_external = prompt_endpoint_host(
        "External endpoint IP/hostname used by clients",
        default=(bind_address if bind_address not in ("0.0.0.0", "::") else None),
    )
    client_server_address = format_endpoint(endpoint_external, bind_port)

    server_interface_name = prompt_interface_name("Server interface name", "rvpn-server0")
    server_mode = prompt_choice("Server interface mode", ["tun", "tap", "both"], "tun")
    server_tap_name = None
    if server_mode == "both":
        server_tap_name = prompt_interface_name(
            "Server TAP interface name", "rvpn-server0-tap"
        )

    server_mtu = prompt_int("Server interface MTU", 1400, minimum=576, maximum=65535)
    server_v4 = prompt_network("Server interface IPv4 address (CIDR)", "10.42.0.1/24")
    ipv6_enabled = prompt_bool("Enable IPv6", True)
    server_v6 = ""
    if ipv6_enabled:
        server_v6 = prompt_network("Server interface IPv6 address (CIDR)", "fd42::1/64")

    console.print(f"  [dim]-> IPv4 tunnel CIDR: {network_cidr(server_v4)}[/dim]")
    if ipv6_enabled:
        console.print(f"  [dim]-> IPv6 tunnel CIDR: {network_cidr(server_v6)}[/dim]")

    forwarding_enabled = prompt_bool("Enable internet gateway / NAT forwarding", True)
    forwarding_backend = "auto"
    external_interface = ""
    if forwarding_enabled:
        forwarding_backend = prompt_choice(
            "Firewall backend", ["auto", "iptables", "nftables"], "auto"
        )
        detected = detect_external_interface()
        external_interface = prompt(
            "External (internet-facing) interface",
            default=detected,
            required=detected is None,
        )

    obfuscation_enabled = prompt_bool("Enable packet obfuscation", False)
    obfuscation_key = generate_hex_secret() if obfuscation_enabled else ""
    if obfuscation_enabled:
        console.print("  [dim]-> generated a new 32-byte obfuscation key for all generated clients[/dim]")

    auth_mode = prompt_choice(
        "Peer authentication mode", ["pinned-key", "certificate"], "pinned-key"
    )

    security = ask_security()

    ca_name = ""
    ca = None
    server_identity = None
    cert_valid_days = 3650
    ca_default_allowed_ips: list[str] = []
    revoked_subjects: list[str] = []

    if auth_mode == "certificate":
        section("Certificate authority")
        ca_name = prompt("Certificate authority name", "rvpn-ca", required=True)
        cert_valid_days = prompt_int(
            "Certificate validity (days)", 3650, minimum=1, maximum=36500
        )
        ca_default_allowed_ips = prompt_cidr_list(
            "Default certificate allowed IPs (usually leave blank for per-peer restrictions)",
            "",
        )
        revoked_subjects = prompt_hex_list(
            "Revoked certificate subjects (64-hex fingerprints, comma-separated; optional)"
        )
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True
        ) as progress:
            progress.add_task("Generating CA and server keypairs...", total=None)
            ca = generate_keypair()
            server_identity = generate_keypair()

    return SetupConfig(
        bind_address=bind_address,
        bind_port=bind_port,
        client_server_address=client_server_address,
        endpoint_external=endpoint_external,
        server_interface_name=server_interface_name,
        server_mode=server_mode,
        server_mtu=server_mtu,
        server_tap_name=server_tap_name,
        server_v4=server_v4,
        ipv6_enabled=ipv6_enabled,
        server_v6=server_v6,
        forwarding_enabled=forwarding_enabled,
        forwarding_backend=forwarding_backend,
        external_interface=external_interface,
        tunnel_cidr=network_cidr(server_v4),
        tunnel_cidr_v6=network_cidr(server_v6) if ipv6_enabled else "",
        obfuscation_enabled=obfuscation_enabled,
        obfuscation_key=obfuscation_key,
        auth_mode=auth_mode,
        security=security,
        ca_name=ca_name,
        ca=ca,
        server_identity=server_identity,
        cert_valid_days=cert_valid_days,
        ca_default_allowed_ips=ca_default_allowed_ips,
        revoked_subjects=revoked_subjects,
    )


def ask_client_options(setup: SetupConfig, peer_name: str, platform: str) -> ClientOptions:
    console.print(f"\n  [bold]-- {peer_name}: client interface / routing --[/bold]")

    default_name = f"rvpn-{platform}-{slugify(peer_name)}"[:15]
    interface_name = prompt_interface_name("Client interface name", default_name)

    if platform == "android":
        mode = "tun"
        console.print("  [dim]Android clients are generated as TUN-only.[/dim]")
    else:
        mode = prompt_choice("Client interface mode", ["tun", "tap", "both"], "tun")

    tap_name = None
    if mode == "both":
        tap_name = prompt_interface_name(
            "Client TAP interface name", f"{interface_name[:10]}-tap"
        )

    mtu = prompt_int("Client interface MTU", setup.server_mtu, minimum=576, maximum=65535)
    dns_default = derive_dns_from_endpoint_external(setup.endpoint_external)
    dns_servers = prompt_dns_servers("Client DNS server(s)", dns_default)

    gateway_v4 = setup.server_v4.split("/")[0]
    gateway_v6 = setup.server_v6.split("/")[0] if setup.ipv6_enabled else None

    default_route = prompt_bool("Route IPv4 default traffic through RVPN", True)
    gateway = prompt_ip("IPv4 tunnel gateway", gateway_v4) if default_route else None

    endpoint_gateway_raw = prompt_endpoint_host(
        "Legacy IPv4 endpoint gateway (optional; currently ignored by RVPN)",
        default="",
        required=False,
    )

    default_route_v6 = False
    gateway_v6_value = None
    endpoint_gateway_v6_raw = ""
    if setup.ipv6_enabled:
        default_route_v6 = prompt_bool("Route IPv6 default traffic through RVPN", True)
        if default_route_v6:
            gateway_v6_value = prompt_ip("IPv6 tunnel gateway", gateway_v6 or "fd42::1")
        endpoint_gateway_v6_raw = prompt_endpoint_host(
            "Legacy IPv6 endpoint gateway (optional; currently ignored by RVPN)",
            default="",
            required=False,
        )

    routes = prompt_cidr_list(
        "Additional split-tunnel routes (comma/space-separated; optional)", ""
    )

    return ClientOptions(
        interface_name=interface_name,
        mode=mode,
        mtu=mtu,
        tap_name=tap_name,
        dns_servers=dns_servers,
        default_route=default_route,
        gateway=gateway,
        endpoint_gateway=endpoint_gateway_raw or None,
        default_route_v6=default_route_v6,
        gateway_v6=gateway_v6_value,
        endpoint_gateway_v6=endpoint_gateway_v6_raw or None,
        routes=routes,
    )


def gather_peers(setup: SetupConfig) -> list[PeerSetup]:
    pc_count = prompt_int("How many PC peers to generate", 0, minimum=0)
    android_count = prompt_int("How many Android peers to generate", 1, minimum=0)

    peer_specs: list[tuple[str, int]] = [
        ("pc", index) for index in range(1, pc_count + 1)
    ] + [("android", index) for index in range(1, android_count + 1)]

    peers: list[PeerSetup] = []
    names: set[str] = set()

    for global_index, (platform, platform_index) in enumerate(peer_specs, start=1):
        section(f"{platform.capitalize()} peer {platform_index}")
        default_name = f"{platform}-{platform_index}"
        while True:
            name = prompt("Peer name", default_name, required=True)
            if name in names:
                console.print("  [red]peer names must be unique.[/red]")
                continue
            names.add(name)
            break

        tunnel_v4 = host_at_offset(setup.server_v4, global_index + 1)
        tunnel_v6 = (
            host_at_offset(setup.server_v6, global_index + 1) if setup.ipv6_enabled else ""
        )
        console.print(f"  [dim]-> assigned IPv4: {tunnel_v4}[/dim]")
        if setup.ipv6_enabled:
            console.print(f"  [dim]-> assigned IPv6: {tunnel_v6}[/dim]")

        peer = PeerSetup(
            name=name,
            platform=platform,
            tunnel_v4=tunnel_v4,
            tunnel_v6=tunnel_v6,
            client=ask_client_options(setup, name, platform),
        )

        if setup.auth_mode == "pinned-key":
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
                setup.ca.seed, client_identity.public_key, setup.cert_valid_days
            )

        peers.append(peer)

    return peers


def gather_links(setup: SetupConfig, peers: list[PeerSetup]) -> list[list[str]]:
    if len(peers) < 2:
        return []

    count = prompt_int("How many peer-to-peer link groups", 0, minimum=0)
    if count == 0:
        return []

    labels = [
        peer.certificate_link_name if setup.auth_mode == "certificate" else peer.name
        for peer in peers
    ]
    console.print("\n[bold]Available peers:[/bold]")
    for index, peer in enumerate(peers, start=1):
        console.print(f"  {index}. {peer.name} -> {labels[index - 1]}")

    groups: list[list[str]] = []
    seen: set[frozenset[str]] = set()
    for group_index in range(1, count + 1):
        while True:
            indexes = prompt_index_group(
                f"Link group {group_index} members (peer numbers)", len(peers)
            )
            group = [labels[index - 1] for index in indexes]
            identity = frozenset(group)
            if identity in seen:
                console.print("  [red]that link group is already configured.[/red]")
                continue
            seen.add(identity)
            groups.append(group)
            break
    return groups


def generate(output_dir: Path) -> tuple[Path, list[Path]]:
    setup = ask_server()
    peers = gather_peers(setup)
    links = gather_links(setup, peers)

    output_dir.mkdir(parents=True, exist_ok=True)
    server_path = output_dir / "server.toml"
    server_path.write_text(render_server_toml(setup, peers, links), encoding="utf-8")

    client_paths: list[Path] = []
    for peer in peers:
        path = output_dir / f"client-{peer.platform}-{slugify(peer.name)}.toml"
        client_text = render_client_toml(setup, peer)
        path.write_text(client_text, encoding="utf-8")
        client_paths.append(path)
        if peer.platform == "android":
            emit_android_qr(peer.name, client_text, path.with_suffix(".png"))

    return server_path, client_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interactive RVPN setup generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("rvpn-setup"),
        help="directory to write server.toml and client-*.toml into",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        server_path, client_paths = generate(args.output_dir)
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled.[/yellow]")
        return 130
    except (OSError, ValueError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        return 1

    console.print(f"\n[green]Wrote[/green] {server_path}")
    for path in client_paths:
        console.print(f"[green]Wrote[/green] {path}")
    console.print(
        "\nDone. The generated files include the current RVPN server/client options."
    )
    console.print(
        "[yellow]Keep generated private keys, PSKs, certificates, and obfuscation keys "
        "out of source control.[/yellow]"
    )
    return 0