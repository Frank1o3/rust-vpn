"""QR-code output for Android client configs.

The Android app's "Load from QR code" button scans a QR code whose payload is
the full text of a client TOML file. This module turns a rendered client TOML
into that payload and writes/prints the QR code.

``segno`` is an optional, pure-Python dependency (``pip install segno``). If it
is missing the setup generator still works; it just skips the QR output.
"""

from __future__ import annotations

import shutil
from pathlib import Path

try:  # optional dependency
    import segno
except ImportError:  # pragma: no cover - exercised only without segno
    segno = None

# Terminal QR codes are only scannable if the whole symbol fits on one line.
TERMINAL_BORDER = 2
PNG_SCALE = 8
PNG_BORDER = 4


def qr_available() -> bool:
    return segno is not None


def compact_toml(text: str) -> str:
    """Strip comments, blank lines, and indentation.

    The Android TOML reader trims every line, so this changes nothing about
    the parsed config but shrinks the payload, which keeps the QR code
    lower-density (easier to scan off a screen).
    """
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines) + "\n"


def build_qr(payload: str):
    """Build the smallest QR code for ``payload``.

    Tries error-correction level M first for reliable scanning, then falls
    back to L if the config is too large for M.
    """
    if segno is None:
        raise RuntimeError("segno is not installed (pip install segno)")
    for level in ("m", "l"):
        try:
            return segno.make(payload, error=level, micro=False, boost_error=False)
        except segno.DataOverflowError:
            continue
    raise ValueError("client config is too large to fit in a single QR code")


def emit_android_qr(peer_name: str, client_toml: str, png_path: Path) -> Path | None:
    """Write a PNG QR code for an Android peer and print it if it fits.

    Never raises: QR output is a convenience and must not break config
    generation. Returns the PNG path on success, otherwise ``None``.
    """
    if not qr_available():
        print(
            f"  (skipping QR code for {peer_name}: "
            "run `pip install segno` to enable it)"
        )
        return None

    try:
        payload = compact_toml(client_toml)
        qr = build_qr(payload)
        qr.save(str(png_path), kind="png", scale=PNG_SCALE, border=PNG_BORDER)
    except Exception as exc:  # noqa: BLE001 - convenience feature, never fatal
        print(f"  (could not create QR code for {peer_name}: {exc})")
        return None

    print(
        f"\n  QR code for {peer_name} "
        f"(version {qr.version}, error correction {qr.error}, "
        f"{len(payload.encode())} bytes)"
    )
    print(f"  Saved {png_path}")
    print("  The QR code contains this peer's private key material. "
          "Do not share or commit it.")

    width, _height = qr.symbol_size(border=TERMINAL_BORDER)
    if width <= shutil.get_terminal_size((80, 24)).columns:
        print()
        qr.terminal(compact=True, border=TERMINAL_BORDER)
        print()
    else:
        print(
            f"  (terminal is narrower than the {width}-column QR code; "
            "open the PNG instead)"
        )
    return png_path