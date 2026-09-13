#!/usr/bin/env python3
from __future__ import annotations
import argparse, sys
from dataclasses import dataclass
from pathlib import Path
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    print('Missing dependency: cryptography\nInstall with: python -m pip install cryptography', file=sys.stderr)
    raise SystemExit(1)

@dataclass(frozen=True)
class KeyPair:
    seed: str
    public_key: str

def generate_keypair() -> KeyPair:
    private_key = ed25519.Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if len(seed) != 32 or len(public_key) != 32:
        raise RuntimeError('Unexpected Ed25519 key size')
    return KeyPair(seed.hex(), public_key.hex())

def generate_output(peer_count: int) -> str:
    lines = [
        '# RVPN pinned-key credentials',
        '# Each peer pair has an independent server identity and client identity.',
        '# Keep every local_identity_seed secret.', '',
    ]
    for index in range(1, peer_count + 1):
        server = generate_keypair()
        client = generate_keypair()
        tunnel_ip = f'10.42.0.{index + 1}'
        lines += [
            f'==================== PEER {index} ====================', '',
            f'[server.peer.{index}]',
            f'name="peer-{index}"',
            f'allowed_ips=["{tunnel_ip}/32"]',
            'mode="pinned-key"',
            f'local_identity_seed="{server.seed}"',
            f'peer_public_key="{client.public_key}"', '',
            f'[client.peer.{index}]',
            f'name="peer-{index}"',
            'mode="pinned-key"',
            f'local_identity_seed="{client.seed}"',
            f'peer_public_key="{server.public_key}"',
            f'tunnel_address="{tunnel_ip}/24"', '', '',
        ]
    return '\n'.join(lines)

def main() -> int:
    parser = argparse.ArgumentParser(description='Generate matching RVPN pinned-key credentials.')
    parser.add_argument('peers', type=int, help='number of server/client peer pairs')
    parser.add_argument('-o', '--output', type=Path, default=Path('rvpn-pinned-keys.txt'))
    args = parser.parse_args()
    if not 1 <= args.peers <= 1000:
        parser.error('peers must be between 1 and 1000')
    args.output.write_text(generate_output(args.peers), encoding='utf-8')
    print(f'Generated {args.peers} peer pair(s).')
    print(f'Written to: {args.output}')
    print('Keep every local_identity_seed secret.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
