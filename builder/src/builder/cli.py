"""Interactive RVPN configuration generator: prompts for a server + peer set,
then writes server.toml and one client-*.toml per peer."""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from pathlib import Path

from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import (
    ClientOptions,
    DnsOptions,
    LinkGroup,
    PeerSetup,
    SecurityPolicy,
    SetupConfig,
    generate_hex_secret,
    generate_keypair,
    issue_certificate,
)
from .prompts import (
    console,
    derive_dns_from_tunnel,
    detect_external_interface,
    prompt,
    prompt_bool,
    prompt_cidr_list,
    prompt_choice,
    prompt_dns_servers,
    prompt_dns_upstreams,
    prompt_endpoint_host,
    prompt_index_group,
    prompt_index_list,
    prompt_int,
    prompt_interface_name,
    prompt_ip,
    prompt_network,
)
from .render import render_client_toml, render_server_toml, emit_android_qr


def network_cidr(address_with_prefix: str) -> str:
    return str(ipaddress.ip_interface(address_with_prefix).network)


def first_host(subnet: str) -> str:
    network = ipaddress.ip_interface(subnet).network
    if network.num_addresses < 3:
        raise ValueError(f"tunnel subnet {network} needs room for a server and peers")
    return f"{network[1]}/{network.prefixlen}"


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


def write_private_text(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(content)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(path, 0o600)


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

    auth_mode = prompt_choice(
        "Peer authentication protocol", ["pinned-key", "certificate"], "pinned-key"
    )

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
    server_v4_subnet = prompt_network("IPv4 tunnel subnet (CIDR)", "10.42.0.0/24")
    server_v4 = first_host(server_v4_subnet)
    ipv6_enabled = prompt_bool("Enable IPv6", True)
    server_v6 = ""
    if ipv6_enabled:
        server_v6_subnet = prompt_network("IPv6 tunnel subnet (CIDR)", "fd42::/64")
        server_v6 = first_host(server_v6_subnet)

    console.print(f"  [dim]-> IPv4 tunnel CIDR: {network_cidr(server_v4)}[/dim]")
    if ipv6_enabled:
        console.print(f"  [dim]-> IPv6 tunnel CIDR: {network_cidr(server_v6)}[/dim]")

    dns_enabled = prompt_bool("Enable tunnel DNS forwarding on the server", True)
    dns = DnsOptions()
    if dns_enabled:
        dns.upstreams = prompt_dns_upstreams(
            "Upstream DNS server(s) (numeric IP:port)",
            "1.1.1.1:53, 1.0.0.1:53",
        )
        if dns.upstreams:
            dns.timeout_ms = prompt_int(
                "DNS upstream timeout (ms)", 2000, minimum=100, maximum=30000
            )
            dns.attempts = prompt_int("DNS retries (1-5)", 2, minimum=1, maximum=5)
            dns.cache_entries = prompt_int(
                "DNS cache entries (0 disables)", 1024, minimum=0, maximum=65536
            )

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

    security = ask_security()

    tx_mib_per_sec = prompt_int("Server-to-peer rate limit per peer (MiB/s; 0 unlimited)", 0, minimum=0)
    rx_mib_per_sec = prompt_int("Peer-to-server rate limit per peer (MiB/s; 0 unlimited)", 0, minimum=0)

    usage_history_enabled = prompt_bool("Save daily per-peer usage history", False)
    usage_history_path = "/var/lib/rvpn/usage-history.json"
    usage_history_retention_days = 30
    if usage_history_enabled:
        usage_history_path = prompt("Usage history file path", usage_history_path, required=True)
        usage_history_retention_days = prompt_int(
            "Usage history retention (days)", 30, minimum=1, maximum=3650
        )

    ca_name = ""
    ca = None
    server_identity = None
    cert_valid_days = 3650

    if auth_mode == "certificate":
        section("Certificate authority")
        ca_name = prompt("Certificate authority name", "rvpn-ca", required=True)
        cert_valid_days = prompt_int(
            "Certificate validity (days)", 3650, minimum=1, maximum=36500
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
        dns=dns,
        tx_mib_per_sec=tx_mib_per_sec,
        rx_mib_per_sec=rx_mib_per_sec,
        usage_history_enabled=usage_history_enabled,
        usage_history_path=usage_history_path,
        usage_history_retention_days=usage_history_retention_days,
        ca_name=ca_name,
        ca=ca,
        server_identity=server_identity,
        cert_valid_days=cert_valid_days,
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
    dns_replace = prompt_bool(
        "Replace the server hostname with its resolved IP in this client config",
        False,
    )
    dns_default = derive_dns_from_tunnel(
        setup.server_v4,
        setup.server_v6 if setup.ipv6_enabled else "",
        enabled=bool(setup.dns.upstreams),
    )
    dns_servers = prompt_dns_servers("Client DNS server(s)", dns_default)

    default_route = prompt_bool("Route IPv4 default traffic through RVPN", True)
    gateway = setup.server_v4.split("/")[0] if default_route else None

    default_route_v6 = False
    gateway_v6_value = None
    if setup.ipv6_enabled:
        default_route_v6 = prompt_bool("Route IPv6 default traffic through RVPN", True)
        if default_route_v6:
            gateway_v6_value = setup.server_v6.split("/")[0]

    routes = prompt_cidr_list(
        "Additional split-tunnel routes (comma/space-separated; optional)", ""
    )

    return ClientOptions(
        interface_name=interface_name,
        mode=mode,
        mtu=mtu,
        tap_name=tap_name,
        dns_replace=dns_replace,
        dns_servers=dns_servers,
        default_route=default_route,
        gateway=gateway,
        default_route_v6=default_route_v6,
        gateway_v6=gateway_v6_value,
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
        platform_label = "PC" if platform == "pc" else "Android"
        default_name = platform_label if platform_index == 1 else f"{platform_label}-{platform_index}"
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


def gather_links(setup: SetupConfig, peers: list[PeerSetup]) -> list[LinkGroup]:
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

    groups: list[LinkGroup] = []
    seen: set[tuple[str, ...]] = set()
    for group_index in range(1, count + 1):
        while True:
            kind = prompt_choice(
                f"Link group {group_index} direction",
                ["symmetric", "one-way"],
                "symmetric",
            )
            if kind == "symmetric":
                indexes = prompt_index_group(
                    f"Link group {group_index} peers (peer numbers)", len(peers)
                )
                group = LinkGroup(between=[labels[index - 1] for index in indexes])
                identity = ("symmetric", *sorted(group.between))
            else:
                console.print(
                    "  [dim]One-way links authorize traffic only from transmitters to receivers; "
                    "add a reverse link if replies should pass.[/dim]"
                )
                receiver_indexes = prompt_index_list(
                    f"Link group {group_index} receivers (peer numbers)", len(peers)
                )
                transmitter_indexes = prompt_index_list(
                    f"Link group {group_index} transmitters (peer numbers)", len(peers)
                )
                if set(receiver_indexes) & set(transmitter_indexes):
                    console.print("  [red]a peer cannot be both receiver and transmitter in one group.[/red]")
                    continue
                group = LinkGroup(
                    receivers=[labels[index - 1] for index in receiver_indexes],
                    transmitters=[labels[index - 1] for index in transmitter_indexes],
                )
                identity = (
                    "one-way",
                    *sorted(group.receivers),
                    "->",
                    *sorted(group.transmitters),
                )
            if identity in seen:
                console.print("  [red]that link group is already configured.[/red]")
                continue
            seen.add(identity)
            groups.append(group)
            break
    return groups


def generate(output_dir: Path) -> tuple[Path, list[Path], Path | None]:
    setup = ask_server()
    peers = gather_peers(setup)
    links = gather_links(setup, peers)

    output_dir.mkdir(parents=True, exist_ok=True)
    server_path = output_dir / "server.toml"
    write_private_text(server_path, render_server_toml(setup, peers, links))

    ca_seed_path = None
    if setup.ca is not None:
        ca_seed_path = output_dir / "ca-private-seed.hex"
        write_private_text(ca_seed_path, setup.ca.seed + "\n")

    client_paths: list[Path] = []
    used_filenames: set[str] = set()
    for peer in peers:
        base_name = f"client-{slugify(peer.name)}"
        filename = base_name
        suffix = 1
        while f"{filename}.toml".casefold() in used_filenames:
            filename = f"{base_name}-{suffix}"
            suffix += 1
        used_filenames.add(f"{filename}.toml".casefold())
        path = output_dir / f"{filename}.toml"
        client_text = render_client_toml(setup, peer)
        write_private_text(path, client_text)
        client_paths.append(path)
        if peer.platform == "android":
            emit_android_qr(peer.name, client_text, path.with_suffix(".png"))

    return server_path, client_paths, ca_seed_path


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
        server_path, client_paths, ca_seed_path = generate(args.output_dir)
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled.[/yellow]")
        return 130
    except (OSError, ValueError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        return 1

    console.print(f"\n[green]Wrote[/green] {server_path}")
    if ca_seed_path is not None:
        console.print(
            f"[yellow]CA signing seed saved to {ca_seed_path}; back it up offline. "
            "It is required to issue certificates later.[/yellow]"
        )
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
