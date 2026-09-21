from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from typing import Optional


HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]+$")


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


def prompt_int(
    text: str,
    default: int,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    while True:
        value = input(f"{text} [{default}]: ").strip()
        if not value:
            return default
        try:
            result = int(value)
        except ValueError:
            print("  please enter a whole number.")
            continue
        if minimum is not None and result < minimum:
            print(f"  please enter a value >= {minimum}.")
            continue
        if maximum is not None and result > maximum:
            print(f"  please enter a value <= {maximum}.")
            continue
        return result


def prompt_choice(text: str, choices: list[str], default: str) -> str:
    options = "/".join(c if c != default else c.upper() for c in choices)
    while True:
        value = input(f"{text} ({options}): ").strip().lower()
        if not value:
            return default
        if value in choices:
            return value
        print(f"  please choose one of: {', '.join(choices)}")


def prompt_ip(text: str, default: str) -> str:
    while True:
        value = prompt(text, default=default, required=True)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            print("  please enter a valid IPv4 or IPv6 address.")
            continue
        return value


def prompt_network(text: str, default: str) -> str:
    while True:
        value = prompt(text, default=default, required=True)
        try:
            ipaddress.ip_interface(value)
        except ValueError:
            print(
                "  please enter a valid IP address with CIDR prefix, "
                "e.g. 10.42.0.1/24."
            )
            continue
        return str(ipaddress.ip_interface(value))


def prompt_interface_name(text: str, default: str) -> str:
    while True:
        value = prompt(text, default=default, required=True)
        if not value or len(value.encode()) > 15 or "\x00" in value:
            print(
                "  interface names must be 1-15 bytes and contain no NUL bytes."
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
            print("  please enter an IP address or hostname.")


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
            print(
                "  DNS servers must be a comma/space-separated list of IP addresses."
            )
            continue
        return ", ".join(parts)


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
            print(
                "  please enter a comma/space-separated list of valid CIDR networks."
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
        invalid = [
            part for part in parts if len(part) != expected or _not_hex(part)
        ]
        if invalid:
            print(
                f"  each entry must be exactly {expected} hexadecimal characters."
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
            print("  enter peer numbers separated by commas, e.g. 1,2,3.")
            continue
        if len(set(indexes)) != len(indexes) or len(indexes) < 2:
            print("  choose at least two distinct peers.")
            continue
        if any(index < 1 or index > count for index in indexes):
            print(f"  peer numbers must be between 1 and {count}.")
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


def derive_dns_from_endpoint_external(endpoint_external: str) -> str:
    try:
        address = ipaddress.ip_address(endpoint_external)
        if isinstance(address, ipaddress.IPv4Address) and address.is_private:
            octets = endpoint_external.split(".")
            return ".".join(octets[:3] + ["1"])
    except ValueError:
        pass
    return "1.1.1.1"


def _not_hex(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return True
    return False
