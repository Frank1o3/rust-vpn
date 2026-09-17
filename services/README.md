# RVPN systemd services

- `rvpn-server.service` — system unit, runs under a dedicated `rvpn` system
  user with `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` (needed for TUN
  creation and the `ip`/`nft`/`iptables` commands it shells out to). Reads
  `~/.config/rvpn/server.toml` for that user unless a path is given on the
  `ExecStart` line.
- `rvpn-client.service` — **user** unit. Runs `rvpn-client --daemon`, which
  idles until it gets a `Connect` command over `$XDG_RUNTIME_DIR/rvpn/control.sock`.
  Grant it networking capabilities at install time instead of relying on
  ambient caps on a user unit:

```sh
  sudo setcap cap_net_admin,cap_net_raw+eip /usr/local/bin/rvpn-client
```

- `rvpn-tray` has no service file — it's a normal desktop app you run
  yourself (add it to your session autostart if you want it running on
  login). It talks to `rvpn-client.service` over the same control socket
  and has no networking code of its own.

## Config locations

Both `rvpn-server` and `rvpn-client` default to
`$XDG_CONFIG_HOME/rvpn/{server,client}.toml` (normally `~/.config/rvpn/...`),
so you can edit them without root. Pass a path as the first CLI argument to
override this for the server, or as part of the `Connect` command for the
client daemon (which `rvpn-tray` does automatically).

## Packaging (Rivet)

A package should install:
- the `rvpn-server`, `rvpn-client`, `rvpn-tray` binaries onto `PATH`
- these `.service` files under the distro's systemd unit search path
  (system units for `rvpn-server.service`, user units for
  `rvpn-client.service`)
- nothing under `~/.config/rvpn/` — leave that for the user, or a first-run
  step driven by `scripts/generate_rvpn_setup.py`