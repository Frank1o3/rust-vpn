#[cfg(any(target_os = "linux"))]
mod linux_network;
pub use linux_network::{configure_client_network, teardown_client_network};

#[cfg(any(target_os = "windows"))]
mod windows_network;
