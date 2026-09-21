from __future__ import annotations

from .models import PeerSetup, SetupConfig


def toml_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def toml_list(values: list[str]) -> str:
    return "[" + ", ".join(toml_str(value) for value in values) + "]"


def render_security(lines: list[str], setup: SetupConfig) -> None:
    security = setup.security
    lines.extend(
        [
            "[handshake]",
            f"    retry_interval_ms={security.retry_interval_ms}",
            f"    retry_limit={security.retry_limit}",
            f"    retry_jitter_ms={security.retry_jitter_ms}",
            "",
            "[rekey]",
            f"    packet_limit={security.rekey_packet_limit}",
            f"    time_limit_secs={security.rekey_time_limit_secs}",
            "",
            "[liveness]",
            f"    timeout_secs={security.liveness_timeout_secs}",
            "",
        ]
    )


def render_server_toml(
    setup: SetupConfig,
    peers: list[PeerSetup],
    links: list[list[str]],
) -> str:
    lines = ["# RVPN Server configuration (generated)", ""]
    lines.append(f"bind={toml_str(f'{setup.bind_address}:{setup.bind_port}')}")
    if setup.obfuscation_enabled:
        lines.append(f"obfuscation_key={toml_str(setup.obfuscation_key)}")
    lines.append("")

    lines.extend(
        [
            "[interface]",
            f"    address={toml_str(setup.server_v4)}",
            f"    mode={toml_str(setup.server_mode)}",
            f"    mtu={setup.server_mtu}",
            f"    name={toml_str(setup.server_interface_name)}",
        ]
    )
    if setup.server_tap_name:
        lines.append(f"    tap_name={toml_str(setup.server_tap_name)}")
    if setup.ipv6_enabled:
        lines.append(f"    addresses={toml_list([setup.server_v6])}")
    lines.append("")

    render_security(lines, setup)

    if setup.forwarding_enabled:
        lines.extend(
            [
                "[forwarding]",
                "    enabled=true",
                f"    backend={toml_str(setup.forwarding_backend)}",
                f"    external_interface={toml_str(setup.external_interface)}",
                f"    tunnel_cidr={toml_str(setup.tunnel_cidr)}",
            ]
        )
        if setup.ipv6_enabled:
            lines.append(f"    tunnel_cidr_v6={toml_str(setup.tunnel_cidr_v6)}")
        lines.append("")

    if setup.auth_mode == "certificate":
        assert setup.ca is not None and setup.server_identity is not None
        lines.extend(
            [
                "[certificate_authority]",
                f"    name={toml_str(setup.ca_name)}",
                f"    ca_public_key={toml_str(setup.ca.public_key)}",
                f"    local_identity_seed={toml_str(setup.server_identity.seed)}",
                f"    local_certificate={toml_str(issue_server_certificate(setup))}",
                f"    default_allowed_ips={toml_list(setup.ca_default_allowed_ips)}",
                f"    revoked_subjects={toml_list(setup.revoked_subjects)}",
                "",
                "    # Per-peer certificate subjects are restricted to their assigned tunnel addresses.",
                "",
                "[certificate_authority.peer_overrides]",
            ]
        )
        for peer in peers:
            allowed = [f"{peer.tunnel_v4}/32"]
            if setup.ipv6_enabled:
                allowed.append(f"{peer.tunnel_v6}/128")
            lines.append(
                f"    {toml_str(peer.client_pub_hex)}={toml_list(allowed)}"
            )
            lines.append(f"    # {peer.name} -> {peer.certificate_link_name}")
        lines.append("")
    else:
        for peer in peers:
            allowed_ips = [f"{peer.tunnel_v4}/32"]
            if setup.ipv6_enabled:
                allowed_ips.append(f"{peer.tunnel_v6}/128")

            lines.extend(
                [
                    "[[peers]]",
                    f"    allowed_ips={toml_list(allowed_ips)}",
                    f"    name={toml_str(peer.name)}",
                    "",
                    "    [peers.auth]",
                    f"        mode={toml_str(setup.auth_mode)}",
                ]
            )
            if setup.auth_mode == "psk":
                lines.append(f"        pre_shared_key={toml_str(peer.server_psk)}")
            elif setup.auth_mode == "pinned-key":
                lines.append(
                    f"        local_identity_seed={toml_str(peer.server_seed_hex)}"
                )
                lines.append(
                    f"        peer_public_key={toml_str(peer.client_pub_hex)}"
                )
            lines.append("")

    if links:
        for group in links:
            lines.extend(
                [
                    "[[links]]",
                    f"    between={toml_list(group)}",
                    "",
                ]
            )

    return "\n".join(lines).rstrip() + "\n"


def issue_server_certificate(setup: SetupConfig) -> str:
    from .crypto import issue_certificate

    assert setup.ca is not None and setup.server_identity is not None
    return issue_certificate(
        setup.ca.seed,
        setup.server_identity.public_key,
        setup.cert_valid_days,
    )


def render_client_toml(setup: SetupConfig, peer: PeerSetup) -> str:
    lines = [
        f"# RVPN Client configuration for '{peer.name}' (generated)",
        "",
    ]
    lines.append(f"server={toml_str(setup.client_server_address)}")
    if setup.obfuscation_enabled:
        lines.append(f"obfuscation_key={toml_str(setup.obfuscation_key)}")
    lines.append("")

    interface = peer.client
    lines.extend(
        [
            "[interface]",
            f"    address={toml_str(f'{peer.tunnel_v4}/{setup.server_v4.split('/')[-1]}')}",
            f"    mode={toml_str(interface.mode)}",
            f"    mtu={interface.mtu}",
            f"    name={toml_str(interface.interface_name)}",
        ]
    )
    if interface.tap_name:
        lines.append(f"    tap_name={toml_str(interface.tap_name)}")
    if setup.ipv6_enabled:
        lines.append(
            f"    addresses={toml_list([f'{peer.tunnel_v6}/{setup.server_v6.split('/')[-1]}'])}"
        )
    if interface.dns_servers:
        lines.append(f"    dns_servers={toml_str(interface.dns_servers)}")
    lines.append("")

    lines.append("[routing]")
    lines.append(
        f"    default_route={'true' if interface.default_route else 'false'}"
    )
    if interface.gateway:
        lines.append(f"    gateway={toml_str(interface.gateway)}")
    if interface.endpoint_gateway:
        lines.append(
            f"    endpoint_gateway={toml_str(interface.endpoint_gateway)}"
        )
    lines.append(
        f"    default_route_v6={'true' if interface.default_route_v6 else 'false'}"
    )
    if interface.gateway_v6:
        lines.append(f"    gateway_v6={toml_str(interface.gateway_v6)}")
    if interface.endpoint_gateway_v6:
        lines.append(
            f"    endpoint_gateway_v6={toml_str(interface.endpoint_gateway_v6)}"
        )
    if interface.routes:
        lines.append(f"    routes={toml_list(interface.routes)}")
    lines.append("")

    lines.append("[auth]")
    if setup.auth_mode == "psk":
        lines.append(f"    mode={toml_str('psk')}")
        lines.append(f"    pre_shared_key={toml_str(peer.server_psk)}")
    elif setup.auth_mode == "pinned-key":
        lines.append(f"    mode={toml_str('pinned-key')}")
        lines.append(
            f"    local_identity_seed={toml_str(peer.client_seed_hex)}"
        )
        lines.append(
            f"    peer_public_key={toml_str(peer.server_pub_hex)}"
        )
    elif setup.auth_mode == "certificate":
        assert setup.ca is not None
        lines.append(f"    mode={toml_str('certificate')}")
        lines.append(
            f"    local_identity_seed={toml_str(peer.client_seed_hex)}"
        )
        lines.append(
            f"    local_certificate={toml_str(peer.client_certificate_hex)}"
        )
        lines.append(f"    ca_public_key={toml_str(setup.ca.public_key)}")
    lines.append("")

    render_security(lines, setup)
    return "\n".join(lines).rstrip() + "\n"
