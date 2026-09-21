#[cfg(target_os = "linux")]
mod linux_network;

#[cfg(target_os = "linux")]
pub use linux_network::{configure_client_network, refresh_client_endpoint, teardown_client_network};

#[cfg(target_os = "windows")]
mod windows_network;

#[cfg(target_os = "windows")]
pub use windows_network::{configure_client_network, refresh_client_endpoint, teardown_client_network};
