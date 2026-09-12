# RVPN Android Client

Android 10+ (API 29+) VPN client for the RVPN protocol.

## Architecture

```
┌────────────────────────────────────────────────────────┐
│               Android UI (MainActivity)                │
│  - Connect/Disconnect toggle                           │
│  - Server, PSK, tunnel IP, DNS configuration           │
│  - Requests VPN permission via VpnService.prepare()    │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│              RvpnService (Android VpnService)          │
│  - Builds virtual L3 TUN interface                     │
│  - Calls protect(socketFd) to prevent routing loops    │
│  - Passes detached TUN fd to native Rust runtime       │
└───────────────────────────┬────────────────────────────┘
                            │ JNI (RvpnNative)
┌───────────────────────────▼────────────────────────────┐
│           Rust Native Core (librvpn_android.so)        │
│  - Wraps TUN fd via TunDevice::from_raw_fd()           │
│  - Runs Tokio event loop (handshake, seal/open, rekey) │
│  - Handles graceful shutdown via watch channel         │
└────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **Rust toolchain** with Android targets:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   ```
2. **Android NDK** (r25+ recommended) and `cargo-ndk`:
   ```bash
   cargo install cargo-ndk
   ```
3. **Android Studio** or Android SDK command-line tools.

## Building the Native Library

From the workspace root or `apps/rvpn-android`:

```bash
# Build 64-bit ARM (standard for modern Android phones)
cargo ndk -t arm64-v8a -o apps/rvpn-android/android/app/src/main/jniLibs build --package rvpn-android --release

# Build x86_64 (for Android emulator)
cargo ndk -t x86_64 -o apps/rvpn-android/android/app/src/main/jniLibs build --package rvpn-android --release

# Build 32-bit ARM (optional for older devices)
cargo ndk -t armeabi-v7a -o apps/rvpn-android/android/app/src/main/jniLibs build --package rvpn-android --release
```

## Running the Android App

1. Open `apps/rvpn-android/android` in Android Studio.
2. Ensure the native libraries are placed in `app/src/main/jniLibs/<abi>/librvpn_android.so`.
3. Build and deploy to an Android 10+ device or emulator:
   ```bash
   ./gradlew assembleDebug
   adb install app/build/outputs/apk/debug/app-debug.apk
   ```
4. Enter the RVPN server IP:port and the 64-hex-character PSK, then tap **Connect**.
