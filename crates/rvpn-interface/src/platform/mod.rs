#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::TunDevice;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::TunDevice;

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
pub use unsupported::TunDevice;
