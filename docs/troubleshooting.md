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
