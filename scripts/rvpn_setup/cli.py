from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .generator import generate


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
        print("\nSetup cancelled.", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"\nWrote {server_path}")
    for path in client_paths:
        print(f"Wrote {path}")
    print("\nDone. The generated files include the current RVPN server/client options.")
    print(
        "Keep generated private keys, PSKs, certificates, and obfuscation keys "
        "out of source control."
    )
    return 0
