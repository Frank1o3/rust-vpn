"""Interactive prompts, built on rich, plus small validators the plain
Prompt/Confirm/IntPrompt widgets don't cover (IPs, CIDRs, interface names)."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from typing import Optional

from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt

console = Console()

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def prompt(text: str, default: Optional[str] = None, required: bool = False) -> str:
    while True:
        value = (
            Prompt.ask(text, default=default, console=console)
            if default is not None
            else Prompt.ask(text, console=console)
        ).strip()
        if not value and default is not None:
            return default
        if not value and required:
            console.print("  [red]this value is required.[/red]")
            continue
        return value


def prompt_bool(text: str, default: bool) -> bool:
    return Confirm.ask(text, default=default, console=console)


def prompt_int(
    text: str,
    default: int,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    while True:
        value = IntPrompt.ask(text, default=default, console=console)
        if minimum is not None and value < minimum:
            console.print(f"  [red]please enter a value >= {minimum}.[/red]")
            continue
        if maximum is not None and value > maximum:
            console.print(f"  [red]please enter a value <= {maximum}.[/red]")
            continue
        return value


def prompt_choice(text: str, choices: list[str], default: str) -> str:
    return Prompt.ask(
        text, choices=choices, default=default, console=console, case_sensitive=False
    ).lower()


def prompt_ip(text: str, default: str) -> str:
    while True:
        value = prompt(text, default=default, required=True)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            console.print("  [red]please enter a valid IPv4 or IPv6 address.[/red]")
            continue
        return value


def prompt_network(text: str, default: str) -> str:
    while True:
        value = prompt(text, default=default, required=True)
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            console.print(
                "  [red]please enter a valid tunnel subnet with CIDR prefix, "
                "e.g. 10.42.0.0/24.[/red]"
            )
            continue
        if network.num_addresses < 3:
            console.print("  [red]the subnet must have room for a server and at least one peer.[/red]")
            continue
        return str(network)


def prompt_interface_name(text: str, default: str) -> str:
    while True:
        value = prompt(text, default=default, required=True)
        if not value or len(value.encode()) > 15 or "\x00" in value:
            console.print(
                "  [red]interface names must be 1-15 bytes and contain no NUL bytes.[/red]"
            )
            continue
        return value


def prompt_endpoint_host(
    text: str,
    default: Optional[str] = None,
    required: bool = True,
) -> str:
    while True:
        value = prompt(text, default=default, required=required)
        if not value:
            return value
        candidate = value.strip("[]")
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            if len(candidate) <= 253 and HOSTNAME_RE.fullmatch(candidate):
                return candidate
            console.print("  [red]please enter an IP address or hostname.[/red]")


def prompt_dns_servers(text: str, default: str) -> str:
    while True:
        value = prompt(text, default=default)
        if not value:
            return ""
        parts = [part for part in re.split(r"[,\s]+", value) if part]
        try:
            for part in parts:
                ipaddress.ip_address(part)
        except ValueError:
            console.print(
                "  [red]DNS servers must be a comma/space-separated list of IP addresses.[/red]"
            )
            continue
        return ", ".join(parts)


def prompt_dns_upstreams(text: str, default: str) -> list[str]:
    while True:
        value = prompt(text, default=default)
        if not value:
            return []
        try:
            return [
                _normalize_dns_upstream(part)
                for part in re.split(r"[,\s]+", value)
                if part
            ]
        except ValueError as error:
            console.print(f"  [red]{error}[/red]")


def _normalize_dns_upstream(value: str) -> str:
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or value[closing + 1 : closing + 2] != ":":
            raise ValueError("IPv6 DNS upstreams must use [address]:port format.")
        host = value[1:closing]
        port_text = value[closing + 2 :]
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator or ":" in host:
            raise ValueError("Use IP:port for IPv4 and [IPv6]:port for IPv6 DNS upstreams.")
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError as error:
        raise ValueError("DNS upstreams must be numeric IP:port addresses.") from error
    if not 1 <= port <= 65535:
        raise ValueError("DNS upstream ports must be between 1 and 65535.")
    if isinstance(address, ipaddress.IPv6Address):
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def prompt_cidr_list(text: str, default: str = "") -> list[str]:
    while True:
        value = prompt(text, default=default)
        if not value:
            return []
        parts = [part for part in re.split(r"[,\s]+", value) if part]
        try:
            normalized = [
                str(ipaddress.ip_network(part, strict=False)) for part in parts
            ]
        except ValueError:
            console.print(
                "  [red]please enter a comma/space-separated list of valid CIDR networks.[/red]"
            )
            continue
        return normalized


def prompt_hex_list(text: str, *, item_bytes: int = 32) -> list[str]:
    expected = item_bytes * 2
    while True:
        value = prompt(text)
        if not value:
            return []
        parts = [part.strip().lower() for part in value.split(",") if part.strip()]
        invalid = [part for part in parts if len(part) != expected or _not_hex(part)]
        if invalid:
            console.print(
                f"  [red]each entry must be exactly {expected} hexadecimal characters.[/red]"
            )
            continue
        return parts


def prompt_index_group(text: str, count: int) -> list[int]:
    while True:
        value = prompt(text, required=True)
        parts = [part.strip() for part in value.split(",") if part.strip()]
        try:
            indexes = [int(part) for part in parts]
        except ValueError:
            console.print("  [red]enter peer numbers separated by commas, e.g. 1,2,3.[/red]")
            continue
        if len(set(indexes)) != len(indexes) or len(indexes) < 2:
            console.print("  [red]choose at least two distinct peers.[/red]")
            continue
        if any(index < 1 or index > count for index in indexes):
            console.print(f"  [red]peer numbers must be between 1 and {count}.[/red]")
            continue
        return indexes


def prompt_index_list(text: str, count: int) -> list[int]:
    while True:
        value = prompt(text, required=True)
        parts = [part.strip() for part in value.split(",") if part.strip()]
        try:
            indexes = [int(part) for part in parts]
        except ValueError:
            console.print("  [red]enter peer numbers separated by commas, e.g. 1,2.[/red]")
            continue
        if not indexes or len(set(indexes)) != len(indexes):
            console.print("  [red]choose one or more distinct peers.[/red]")
            continue
        if any(index < 1 or index > count for index in indexes):
            console.print(f"  [red]peer numbers must be between 1 and {count}.[/red]")
            continue
        return indexes


def detect_external_interface() -> Optional[str]:
    if shutil.which("ip"):
        try:
            output = subprocess.check_output(
                ["ip", "route", "get", "8.8.8.8"],
                text=True,
                timeout=3,
            )
            fields = output.split()
            if "dev" in fields:
                return fields[fields.index("dev") + 1]
        except Exception:
            pass

    try:
        import psutil  # type: ignore

        for name, stats in psutil.net_if_stats().items():
            if stats.isup and name != "lo":
                return name
    except Exception:
        pass

    return None


def derive_dns_from_tunnel(
    server_v4: str, server_v6: str = "", *, enabled: bool
) -> str:
    if not enabled:
        return ""
    addresses = [str(ipaddress.ip_interface(server_v4).ip)]
    if server_v6:
        addresses.append(str(ipaddress.ip_interface(server_v6).ip))
    return ", ".join(addresses)


def _not_hex(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return True
    return False
