# RVPN documentation

1. [Architecture](architecture.md)
2. [Configuration](configuration.md)
3. [Deployment and operations](operations.md)
4. [Android client](android.md)
5. [Troubleshooting](troubleshooting.md)

RVPN is functionally complete for its supported platforms (Linux and
Android) but has not been independently security-audited — treat it as
pre-beta. Test in an isolated environment before enabling default routing
or forwarding on a host you depend on, and review the crypto/handshake code
yourself if you plan to rely on it for anything sensitive.
