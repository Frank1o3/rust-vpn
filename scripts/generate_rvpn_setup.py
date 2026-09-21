#!/usr/bin/env python3
"""Interactive RVPN configuration generator.

Generates a complete server.toml and one client-*.toml per peer using the
current rvpn-config schema, including handshake, rekey, liveness, forwarding,
peer-to-peer links, routing, and all supported authentication modes.

Requires Python 3.10+ and the ``cryptography`` package.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rvpn_setup.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
