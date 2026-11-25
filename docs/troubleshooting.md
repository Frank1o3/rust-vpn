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

A successful ping to the tunnel gateway proves only that the client can reach
the server's tunnel interface. It does not prove that the server routes packets
to the internet. DNS configuration is independent of IP forwarding.

1. Confirm the server config explicitly enables forwarding. It is **disabled
   by default**:

   ```toml
   [forwarding]
   enabled = true
   backend = "auto"
   external_interface = "eth0" # replace with the real internet-facing interface
   tunnel_cidr = "10.42.0.0/24"
   # Include only if IPv6 is configured for the tunnel:
   tunnel_cidr_v6 = "fd42::/64"
   ```

   The tunnel CIDRs must match the addresses assigned to RVPN peers. Find the
   server's actual egress interface with `ip route get 1.1.1.1`; use the
   interface shown after `dev`, not the RVPN tunnel interface.

2. Enable forwarding on the server. The systemd unit intentionally protects
   kernel tunables, so configure these persistently and apply them before
   starting RVPN:

   ```sh
   sudo sysctl -w net.ipv4.ip_forward=1
   # Only if forwarding IPv6:
   sudo sysctl -w net.ipv6.conf.all.forwarding=1
   ```

   For persistence, add the enabled settings to a file under
   `/etc/sysctl.d/` and run `sudo sysctl --system`.

3. Check that the service installed its firewall/NAT rules:

   ```sh
   sudo nft list table inet rvpn
   sudo iptables -S FORWARD
   sudo iptables -t nat -S POSTROUTING
   ```

   The configured backend determines which ruleset is active. With nftables,
   expect a forward chain allowing traffic from the tunnel interface to the
   configured external interface, established return traffic, and a
   postrouting masquerade rule for the tunnel CIDR. With iptables, check the
   equivalent FORWARD and POSTROUTING rules. Do not flush unrelated host
   firewall rules while diagnosing.

4. Test by IP before testing DNS. From the client, ping the tunnel gateway,
   then ping a public IP such as `1.1.1.1`. If the gateway responds but the
   public IP does not, the failure is forwarding, firewall/NAT, or upstream
   routing—not DNS. If the public IP works but domain names fail, inspect the
   configured DNS server and the server-side DNS forwarder separately.

5. Verify that the server's route to the VPN client's public UDP endpoint still
   uses the physical network. A full-tunnel client must not route its own VPN
   transport packets back into the tunnel.

If forwarding is enabled and all of the above appear correct, capture traffic
on both interfaces while pinging a public IP:

```sh
sudo tcpdump -ni <tunnel-interface> icmp
sudo tcpdump -ni <external-interface> icmp
```

Packets visible on the tunnel interface but absent from the external interface
point to server forwarding/firewall policy. Packets leaving externally without
replies point toward upstream routing, provider filtering, or return-path NAT.

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
