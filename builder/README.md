# RVPN setup builder

The interactive builder generates one server config and one client config per
peer. From the repository root:

```sh
cd builder
uv sync
uv run builder --output-dir ../rvpn-setup
```

## Authentication

The first prompt chooses the peer authentication protocol. Choose `certificate` to generate
an Ed25519 CA, a server identity and certificate, and a client identity and
certificate for each peer. The generated server config trusts the CA and maps
each certificate subject to that peer's assigned tunnel addresses. Clients
trust the CA and present their own certificates.

The builder writes `ca-private-seed.hex` with mode 0600. Keep it backed up
offline: it is needed to issue certificates for additional peers later. The
CA seed is not included in `server.toml`. The current wizard creates a fresh
CA on each run; it does not yet import an existing CA or enroll a peer into an
existing server config. The server and client configs, the CA seed, and
Android QR images are written with mode 0600 because they contain private
credentials.

`pinned-key` remains available for small fixed deployments. Certificate mode
uses one CA identity to authenticate multiple peers. Both modes generate
private key material, so protect all generated files the same way. Config file
size depends on the credential format and peer count; certificate mode includes
signed certificate data for each peer.

## Network and peer links

The builder asks for IPv4 and IPv6 tunnel subnets, then assigns the first
address to the server and subsequent addresses to peers. With the defaults,
that means `10.42.0.1/24` and `fd42::1/64` for the server, and `.2` / `::2`
for the first peer. The CIDR is derived from the subnet, so the server address
does not need a separate prompt.

Peer-to-peer links can be symmetric or one-way. Symmetric groups allow traffic
in both directions between every pair. One-way groups ask for receivers and
transmitters separately; add a reverse group when protocols need replies.
Obsolete endpoint-gateway prompts are omitted because RVPN no longer uses
those values.

## Tunnel DNS

The builder can enable the server's tunnel-bound DNS forwarder and asks for
numeric upstream `IP:port` addresses, timeout, retry count, and cache size.
When enabled, generated clients default
to the server's tunnel interface address or addresses, such as
`10.20.43.1, fd42::1`. The client resolver uses standard DNS port 53; the
builder does not append a port to `dns_servers`. The server forwards those
queries to the configured upstreams. If tunnel DNS is disabled, client DNS
defaults to empty and can be entered manually.

Generated server configs that enable internet forwarding also require the
host forwarding sysctls described in [operations](../docs/operations.md).
