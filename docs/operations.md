# Deployment and operations

## Two ways to run the client

**Direct (foreground, one config):**

```sh
sudo ./target/release/rvpn-client rvpn-setup/client-pc-laptop.toml
```

Runs in the foreground against the given config path. Requires root (or
equivalent capabilities) since the binary does not self-elevate.

**Daemon + tray (normal desktop use):**

```sh
rvpn-client --daemon &          # or, normally, the systemd service below
rvpn-tray
```

With no config argument (or explicitly `--daemon`), `rvpn-client` starts an
IPC server instead of connecting immediately, and waits for a `Connect`
request. `rvpn-tray` is the reference controller: it sends `Connect` with the
default client config path, polls `Status`, and sends `Disconnect`. Any other
tool can drive the daemon the same way by speaking the `rvpn-ipc` protocol
(`Connect { config_path }`, `Disconnect`, `Status`, `Ping`) over the local
control socket.

The daemon only accepts a `config_path` that resolves inside the RVPN config
directory (`~/.config/rvpn/` on Linux, or `$XDG_CONFIG_HOME/rvpn/` if set) —
it will refuse an IPC `Connect` for a path outside that directory.

## Privileges and build

Linux TUN/TAP creation needs `CAP_NET_ADMIN`, plus `CAP_NET_RAW` for raw
network operations; the server additionally needs permission to configure
forwarding and firewall rules when forwarding is enabled.

```sh
cargo build --release -p rvpn-server -p rvpn-client
```

The client binary is **not** given `setcap` file capabilities and does not
raise capabilities itself. Two supported ways to get them:

- Run it manually with `sudo` (fine for one-off/manual use, but then it's
  fully root rather than scoped to just the two capabilities it needs).
- Install `rvpn-client@<user>.service` (see below), which grants
  `CAP_NET_ADMIN`/`CAP_NET_RAW` via systemd `AmbientCapabilities` — the
  process runs as the normal user, not root, with only those two
  capabilities.

The server runs under the dedicated, non-login `rvpn` system user and group.
`rvpn-server.service` grants it only `CAP_NET_ADMIN`, which it uses for TUN/TAP,
routes, and firewall management. It does not need `CAP_NET_RAW`.

When server forwarding is enabled, set the required host-wide forwarding
sysctls persistently before starting the service. The unit protects kernel
tunables and does not run a root `sysctl` helper:

```ini
# /etc/sysctl.d/90-rvpn.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
```

Apply with `sudo sysctl --system`. Enable only the address families RVPN will
forward. These settings affect the host globally.

The server logs authenticated per-peer traffic totals once a minute. The
totals include accepted inner packet bytes, encrypted UDP payload bytes,
packets dropped by routing, rate enforcement, or outbound queue pressure, and
completed rekeys.
Outbound totals count packets admitted to the bounded send queue.
Handshake and keepalive packets are excluded. These counters reset when the
server process restarts and are currently available in the service journal;
there is no server status API or web portal yet.

## Installing as systemd services (recommended)

Use `./build.sh` rather than hand-editing the unit files — it builds the
binary, installs it, and offers to install/enable the matching service:

```sh
./build.sh server   # rvpn-server.service, dedicated `rvpn` system user
./build.sh client    # rvpn-client@<you>.service (instance = your username)
./build.sh tray      # rvpn-tray.service, per-user, ~/.local/bin/rvpn-tray
./build.sh all       # all three
```

`rvpn-client@.service` is a template; the instance name is the Linux
username running the daemon, e.g. `rvpn-client@alice.service`. `rvpn-tray`
is a *user* systemd unit under `~/.config/systemd/user/` and needs no
elevated privileges — it only ever talks to the daemon over the control
socket.

To remove any of them: `./uninstall.sh server|client|tray|all`.

## Config locations

- Server service: `/var/lib/rvpn/.config/rvpn/server.toml`.
- Client: `~/.config/rvpn/client.toml` for the daemon/tray flow. A directly
  invoked `rvpn-client <path>` (foreground mode above) can point at any
  readable path.

Config files must not be group- or world-readable (`chmod 0600`); RVPN
refuses to read an insecurely-permissioned config file. Install the generated
server config for the service account with:

```sh
sudo install -d -o rvpn -g rvpn -m 0700 /var/lib/rvpn/.config/rvpn
sudo install -o rvpn -g rvpn -m 0600 rvpn-setup/server.toml \
  /var/lib/rvpn/.config/rvpn/server.toml
```

## Verify a connection

```sh
ping -c 3 10.42.0.1
ping -6 -c 3 fd42::1
ip route get 1.1.1.1
```

In IPv4 default-route mode, the last command should select the RVPN device and
show the client tunnel address, such as `src 10.42.0.2`. The server's UDP route
must stay on the physical interface.

## MTU and tray behavior

An MTU-clamp startup warning is expected when configured MTU plus worst-case
wire overhead would exceed a standard path. Do not manually set an
IPv6-capable Linux tunnel below MTU 1280.

`rvpn-tray` uses the desktop user's StatusNotifierItem/D-Bus session and
needs no networking privileges of its own — it only talks to the daemon over
IPC. It cannot reliably run from `sudo` (root has no XDG_RUNTIME_DIR/D-Bus
session), which is one more reason the daemon+IPC split exists: privileged
tunnel work stays in `rvpn-client`, and the UI stays fully unprivileged.
