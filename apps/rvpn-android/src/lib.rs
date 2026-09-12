//! RVPN Android client native library.
//!
//! Provides JNI bindings, live telemetry, and the tunnel runtime for Android's `VpnService`.

pub mod jni;
pub mod stats;
pub mod tunnel;

pub use stats::{StatsSnapshot, TunnelStats};
pub use tunnel::{AndroidTunnelConfig, run_tunnel};
