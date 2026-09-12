#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::TunDevice;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use unsupported::TunDevice;

