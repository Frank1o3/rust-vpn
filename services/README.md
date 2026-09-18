# RVPN systemd services

- `rvpn-server.service` — system unit running under the dedicated `rvpn`
  system user. It receives `CAP_NET_ADMIN` and `CAP_NET_RAW` through
  systemd ambient capabilities so it can create the VPN interface and manage
  the host network.
- `rvpn-client@.service` — system unit template. The instance name is the
  Linux username, for example `rvpn-client@alice.service`. The service runs
  `rvpn-client --daemon` as that user and receives
  `CAP_NET_ADMIN`/\`CAP_NET_RAW` only from systemd. The client executable
  itself is not installed with file capabilities.
- `rvpn-tray.service` — user systemd service installed under
  `~/.config/systemd/user/`. It runs as the logged-in user and talks to the
  client daemon over the same per-user control socket. It does not need
  networking capabilities or root privileges.

## Installation

Use the repository's `build.sh` instead of editing the service files for a
particular username.

For the client, the installer determines the current user automatically and
enables an instance such as:

```sh
sudo systemctl enable --now rvpn-client@alice.service
```

For the tray, the installer uses the current user's systemd manager:

```sh
systemctl --user enable --now rvpn-tray.service
```

## Privileges

The client needs `CAP_NET_ADMIN` and `CAP_NET_RAW` to create/configure the
VPN interface and perform raw network operations.

Those capabilities are granted only by `rvpn-client@.service` through:

```ini
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
```

The client binary is deliberately not given `setcap` file capabilities,
and the client no longer raises capabilities itself. This keeps a manually
executed `rvpn-client` unprivileged; the required capabilities exist only
when the binary is started by its systemd service.

## Config locations

`rvpn-server` defaults to
`$XDG_CONFIG_HOME/rvpn/server.toml` (normally
`~/.config/rvpn/server.toml` for the `rvpn` service user).

The client daemon starts without a config file and waits for IPC requests.
The tray sends a config path with its `Connect` request, so the client reads
the selected user's configuration without requiring root-owned config files.

## Uninstallation

Use:

```sh
./uninstall.sh server
./uninstall.sh client
./uninstall.sh tray
./uninstall.sh all
```

Client removal stops and disables all `rvpn-client@<user>.service` instances
before removing the template and binary.

## Packaging

A package should install:

- `rvpn-server` and `rvpn-client` into a system-wide binary directory.
- `rvpn-tray` into the user's `~/.local/bin` when installed for a user.
- `rvpn-server.service` and `rvpn-client@.service` into the systemd system
  unit directory.
- `rvpn-tray.service` into the user's systemd unit directory.

Do not modify the service files to insert a hard-coded username. The client
template is instantiated with the target user's account name.
