#!/usr/bin/env python3
"""Interactive RVPN configuration generator — thin entry point.

See builder.cli for the implementation. Kept as a standalone script because
the Android app's config screen points users at
`scripts/generate_rvpn_setup.py`.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())