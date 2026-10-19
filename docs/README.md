# RVPN documentation

1. [Architecture](architecture.md)
2. [Configuration](configuration.md)
3. [Deployment and operations](operations.md)
4. [Android client](android.md)
5. [Troubleshooting](troubleshooting.md)
6. [Interactive setup builder](../builder/README.md)

RVPN is functionally complete for its supported platforms (Linux and
Android) but has not been independently security-audited — treat it as
pre-beta. Test in an isolated environment before enabling default routing
or forwarding on a host you depend on, and review the crypto/handshake code
yourself if you plan to rely on it for anything sensitive.

The configuration reference covers server DNS forwarding, routing links,
traffic limits, usage history, interface modes, handshake/rekey/liveness
controls, and both supported authentication formats. The operations guide
covers daemon setup, Linux capabilities, metrics, live reload, and persistent
usage accounting.
