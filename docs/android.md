# Android client

The Android app creates a TUN device with `VpnService` and transfers its file
descriptor to the Rust tunnel library. The outer UDP socket is protected through
`VpnService.protect` so it cannot loop back into the VPN interface.

The server peer's `allowed_ips` must contain the Android device's assigned IPv4
and optional IPv6 tunnel addresses. Authentication and the optional
obfuscation key must match the server configuration.

The Android service clamps the requested MTU before it creates the TUN device,
so the device's actual MTU may be lower than the configured preference.

Check the Rust library with:

```sh
cargo check -p rvpn-android
```

Build the app with the Gradle project in `apps/rvpn-android/android`.
