# Troubleshooting

## `discarding packet with unauthorized source address`

This is server anti-spoofing protection. Compare the logged source with the
peer's `allowed_ips`. A peer assigned `10.42.0.2` and `fd42::2` needs
`10.42.0.2/32` and `fd42::2/128` on the server.

If the logged source is a LAN or public address, inspect routing:

```sh
ip route get 1.1.1.1
ip -6 route get 2606:4700:4700::1111
```

Default RVPN routes should show the tunnel address in `src`. Rebuild both ends
if they predate source-address routing support.

## `effective MTU reduced` or slow transfer

The outer UDP packet was too large. Confirm both sides use current binaries and
look for the startup MTU-clamp warning. PPPoE, mobile, and other smaller paths
may require a lower configured MTU.

## `RTNETLINK answers: Invalid argument` when adding IPv6

Linux rejects IPv6 configuration below MTU 1280. Use current binaries, which
retain that minimum while accounting for RVPN overhead.

## Tunnel ping works, internet access does not

Check that `forwarding.external_interface` is the actual egress interface and
that the server installed forwarding/NAT rules. Also ensure the server's UDP
endpoint retains a physical route.

## Tray D-Bus `Broken pipe`

Do not start tray mode with `sudo`. Root is not part of the logged-in desktop
user's D-Bus session.

## `org.freedesktop.resolve1` activation fails with `unknown unit`

This means the system D-Bus activation entry exists, but systemd cannot start
the `systemd-resolved` service. Check whether the unit is installed and
running:

```sh
systemctl status systemd-resolved
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus \
  org.freedesktop.DBus NameHasOwner s org.freedesktop.resolve1
```

If the unit exists, start and enable it with:

```sh
sudo systemctl enable --now systemd-resolved
```

If `systemctl` reports that the unit is missing, install the distribution's
`systemd-resolved` package first; package names and installation commands vary
by distribution. Do not replace `/etc/resolv.conf` with a systemd-resolved
symlink unless you intend systemd-resolved to be the host's resolver. Its
stub-file symlink is one supported mode, but other network managers may own
that file. See the [systemd-resolved documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html)
for the supported `/etc/resolv.conf` modes.

When RVPN logs that it configured DNS through NetworkManager, systemd-resolved
is not required for that connection. RVPN teardown now checks that
systemd-resolved currently owns its D-Bus name before asking it to revert
per-link state, so a missing or inactive unit does not cause a spurious
activation failure.

## `server status socket failed` after an unclean exit

The status socket is removed during graceful shutdown. If the process is killed
or crashes, the socket file can remain even though no server is listening.
Current RVPN startup checks an existing socket and removes it only when it is a
stale Unix socket; an active listener or a non-socket file is left untouched.
