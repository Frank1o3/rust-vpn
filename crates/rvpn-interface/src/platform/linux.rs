//! Linux `/dev/net/tun` implementation.

use crate::{InterfaceError, TunConfig};
use bytes::Bytes;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
};
use tokio::io::unix::AsyncFd;

const TUN_PATH: &str = "/dev/net/tun";
const IFREQ_UNION_SIZE: usize = 24;

/// Linux's `ifreq` layout for `TUNSETIFF` and `SIOCSIFMTU`.
///
/// Only `ifr_name`, the flags (`data[..2]`), and MTU (`data[..4]`) are used.
/// Keeping this local confines the platform ABI and its unsafe ioctl boundary.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    data: [u8; IFREQ_UNION_SIZE],
}

impl IfReq {
    fn new(name: Option<&str>) -> Self {
        let mut request = Self {
            name: [0; libc::IFNAMSIZ],
            data: [0; IFREQ_UNION_SIZE],
        };
        if let Some(name) = name {
            for (to, from) in request.name.iter_mut().zip(name.bytes()) {
                *to = from as libc::c_char;
            }
        }
        request
    }

    fn assigned_name(&self) -> Result<String, InterfaceError> {
        let bytes: Vec<u8> = self
            .name
            .iter()
            .map(|byte| *byte as u8)
            .take_while(|byte| *byte != 0)
            .collect();
        String::from_utf8(bytes).map_err(|_| InterfaceError::InvalidInterfaceName)
    }
}

/// Asynchronous Linux TUN device carrying raw IPv4/IPv6 packets only.
pub struct TunDevice {
    file: AsyncFd<File>,
    name: String,
    mtu: u16,
}

impl TunDevice {
    /// Creates a non-persistent Linux TUN device. Closing/dropping this object
    /// closes its descriptor; Linux then removes a non-persistent device.
    pub async fn create(config: TunConfig) -> Result<Self, InterfaceError> {
        config.validate()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(TUN_PATH)?;
        let mut request = IfReq::new(config.name.as_deref());
        let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
        request.data[..2].copy_from_slice(&flags.to_ne_bytes());
        // SAFETY: `request` is repr(C), initialized, and valid for the kernel
        // to read/write for the duration of this ioctl.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let name = request.assigned_name()?;
        set_mtu(&name, config.mtu)?;
        tracing::info!(interface = %name, mtu = config.mtu, "created Linux TUN device");
        Ok(Self {
            file: AsyncFd::new(file)?,
            name,
            mtu: config.mtu,
        })
    }

    /// Kernel-assigned interface name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Configured maximum IP packet size.
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Receives one raw IP packet. Only one receive strategy should be active.
    pub async fn recv(&self) -> Result<Bytes, InterfaceError> {
        let mut buffer = vec![0; self.mtu as usize + 1];
        loop {
            let mut ready = self.file.readable().await?;
            match ready.try_io(|file| {
                let mut file = file.get_ref();
                file.read(&mut buffer)
            }) {
                Ok(Ok(length)) => {
                    if length > self.mtu as usize {
                        return Err(InterfaceError::PacketTooLarge {
                            size: length,
                            mtu: self.mtu,
                        });
                    }
                    buffer.truncate(length);
                    validate_packet(&buffer, self.mtu)?;
                    return Ok(Bytes::from(buffer));
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => continue,
            }
        }
    }

    /// Writes one raw IP packet to the operating system through the TUN device.
    pub async fn send(&self, packet: &[u8]) -> Result<(), InterfaceError> {
        validate_packet(packet, self.mtu)?;
        loop {
            let mut ready = self.file.writable().await?;
            match ready.try_io(|file| {
                let mut file = file.get_ref();
                file.write(packet)
            }) {
                Ok(Ok(written)) if written == packet.len() => return Ok(()),
                Ok(Ok(written)) => {
                    return Err(InterfaceError::PartialWrite {
                        written,
                        expected: packet.len(),
                    });
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => continue,
            }
        }
    }
}

fn validate_packet(packet: &[u8], mtu: u16) -> Result<(), InterfaceError> {
    if packet.len() > mtu as usize {
        return Err(InterfaceError::PacketTooLarge {
            size: packet.len(),
            mtu,
        });
    }
    match packet.first().map(|byte| byte >> 4) {
        Some(4 | 6) => Ok(()),
        _ => Err(InterfaceError::InvalidIpPacket),
    }
}

fn set_mtu(name: &str, mtu: u16) -> Result<(), InterfaceError> {
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut request = IfReq::new(Some(name));
    request.data[..4].copy_from_slice(&(mtu as libc::c_int).to_ne_bytes());
    // SAFETY: the socket and `ifreq` are valid for this ioctl call.
    let result = unsafe { libc::ioctl(socket, libc::SIOCSIFMTU, &mut request) };
    let error = if result < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: `socket` was returned by libc::socket and is closed exactly once.
    unsafe { libc::close(socket) };
    error.map_or(Ok(()), |error| Err(error.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_only_ip_version_and_packet_bound() {
        assert!(validate_packet(&[0x45], 1400).is_ok());
        assert!(validate_packet(&[0x60], 1400).is_ok());
        assert!(matches!(
            validate_packet(&[], 1400),
            Err(InterfaceError::InvalidIpPacket)
        ));
        assert!(matches!(
            validate_packet(&[0x45; 4], 3),
            Err(InterfaceError::PacketTooLarge { .. })
        ));
    }

    #[tokio::test]
    #[ignore = "requires /dev/net/tun plus CAP_NET_ADMIN; run with cargo test -p rvpn-interface -- --ignored"]
    async fn creates_a_real_tun_device() {
        let tun = TunDevice::create(TunConfig::default()).await.unwrap();
        assert!(!tun.name().is_empty());
        assert_eq!(tun.mtu(), crate::DEFAULT_MTU);
    }
}
