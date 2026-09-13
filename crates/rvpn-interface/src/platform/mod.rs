#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::VirtualInterface;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::VirtualInterface;

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
pub use unsupported::VirtualInterface;
