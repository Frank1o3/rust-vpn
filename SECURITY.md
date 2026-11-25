# Security Policy

## Project security status

RVPN is a pre-beta VPN implementation and has **not** received an independent security audit. The existence of encryption, authentication, fuzz targets, or CI checks is not a certification of security. Do not rely on RVPN for high-risk or safety-critical use without an independent review.

The default branch, `main`, is the active development line. Reports should identify the affected commit or release.

## Reporting a vulnerability

Do not disclose exploitable details in a public issue or pull request. Use GitHub's private vulnerability reporting option on the repository's Security tab when available. If it is unavailable, contact [@Frank1o3](https://github.com/Frank1o3) and request a private reporting channel before sending technical details.

Reports are especially important for:

- Handshake authentication, key derivation, AEAD nonce uniqueness, replay protection, and rekey state.
- UDP parsing, obfuscation framing, packet routing, peer isolation, and allowed-IP enforcement.
- Linux/Windows kill switches, firewall/NAT setup, route preservation, and traffic leaks.
- Android `VpnService`, socket protection, TUN descriptor ownership, and DNS behavior.
- DNS forwarding, IPC, status/metrics endpoints, privilege boundaries, and service hardening.
- Secret handling, logs, config permissions, dependency and release supply-chain integrity.

Include impact, affected version/commit, and concise reproduction steps. Use a private channel for proof-of-concept material. Redact private keys, identity seeds, certificates with private material, obfuscation keys, credentials, and personal data.

There is no bug bounty or guaranteed response-time commitment. Please do not submit real user credentials or VPN private keys.
