//! Linux `/dev/net/tun` implementation.

use crate::{DeviceMode, InterfaceError, TunConfig};
use bytes::{Bytes, BytesMut};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
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

/// Asynchronous Linux TUN/TAP virtual device.
pub struct TunDevice {
    file: AsyncFd<File>,
    name: String,
    mtu: u16,
    mode: DeviceMode,
}

impl TunDevice {
    /// Creates a non-persistent Linux TUN/TAP device and brings it up.
    /// Closing/dropping this object closes its descriptor; Linux then removes
    /// a non-persistent device.
    pub async fn create(config: TunConfig) -> Result<Self, InterfaceError> {
        config.validate()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(TUN_PATH)?;
        let mut request = IfReq::new(config.name.as_deref());
        let flags = match config.mode {
            DeviceMode::Tap => (libc::IFF_TAP | libc::IFF_NO_PI) as i16,
            DeviceMode::Tun | DeviceMode::Both => (libc::IFF_TUN | libc::IFF_NO_PI) as i16,
        };
        request.data[..2].copy_from_slice(&flags.to_ne_bytes());
        // SAFETY: `request` is repr(C), initialized, and valid for the kernel
        // to read/write for the duration of this ioctl.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let name = request.assigned_name()?;
        set_mtu(&name, config.mtu)?;
        // Automatically activate the link (IFF_UP | IFF_RUNNING) via ioctl.
        let _ = set_up(&name);
        tracing::info!(interface = %name, mtu = config.mtu, mode = ?config.mode, "created Linux virtual device");
        Ok(Self {
            file: AsyncFd::new(file)?,
            name,
            mtu: config.mtu,
            mode: config.mode,
        })
    }

    /// Wraps an existing, already opened TUN file descriptor (such as one
    /// supplied by Android's `VpnService.Builder.establish()`).
    ///
    /// The descriptor will be set to non-blocking mode (`O_NONBLOCK`).
    pub fn from_raw_fd(
        fd: RawFd,
        name: String,
        mtu: u16,
        mode: DeviceMode,
    ) -> Result<Self, InterfaceError> {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self {
            file: AsyncFd::new(file)?,
            name,
            mtu,
            mode,
        })
    }

    /// Kernel-assigned interface name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Configured maximum IP packet payload size.
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }
    /// Operating mode (TUN or TAP).
    pub const fn mode(&self) -> DeviceMode {
        self.mode
    }

    /// Receives one raw packet or Ethernet frame. Only one receive strategy should be active.
    pub async fn recv(&self) -> Result<Bytes, InterfaceError> {
        let max_packet_len = if self.mode == DeviceMode::Tap {
            self.mtu as usize + 18
        } else {
            self.mtu as usize
        };
        // +1 sentinel: if the kernel reports more than max_packet_len bytes the
        // packet is oversized.  We never observe the extra byte's content.
        let capacity = max_packet_len + 1;
        let mut buffer = BytesMut::with_capacity(capacity);
        loop {
            let mut ready = self.file.readable().await?;
            match ready.try_io(|file| {
                // SAFETY: bytes are written by the kernel's read before we slice them.
                unsafe { buffer.set_len(capacity) };
                let result = file.get_ref().read(&mut buffer);
                if let Ok(n) = result {
                    unsafe { buffer.set_len(n) };
                }
                result
            }) {
                Ok(Ok(length)) => {
                    if length > max_packet_len {
                        return Err(InterfaceError::PacketTooLarge {
                            size: length,
                            mtu: max_packet_len as u16,
                        });
                    }
                    // buffer is already truncated to `length` in the closure above.
                    let bytes = buffer.split().freeze();
                    validate_packet(&bytes, self.mtu, self.mode)?;
                    return Ok(bytes);
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    // AsyncFd signals WouldBlock; reset the length and retry.
                    unsafe { buffer.set_len(0) };
                    continue;
                }
            }
        }
    }

    /// Writes one raw packet or Ethernet frame to the operating system through the device.
    pub async fn send(&self, packet: &[u8]) -> Result<(), InterfaceError> {
        validate_packet(packet, self.mtu, self.mode)?;
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

fn validate_packet(packet: &[u8], mtu: u16, mode: DeviceMode) -> Result<(), InterfaceError> {
    match mode {
        DeviceMode::Tun => {
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
        DeviceMode::Tap | DeviceMode::Both => {
            if packet.len() < 14 {
                return Err(InterfaceError::InvalidEthernetFrame);
            }
            if packet.len() > mtu as usize + 18 {
                return Err(InterfaceError::PacketTooLarge {
                    size: packet.len(),
                    mtu: mtu + 18,
                });
            }
            Ok(())
        }
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
    let result = unsafe { libc::ioctl(socket, libc::SIOCSIFMTU as libc::Ioctl, &mut request) };
    let error = if result < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: `socket` was returned by libc::socket and is closed exactly once.
    unsafe { libc::close(socket) };
    error.map_or(Ok(()), |error| Err(error.into()))
}

fn set_up(name: &str) -> Result<(), InterfaceError> {
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut request = IfReq::new(Some(name));
    // SAFETY: the socket and `ifreq` are valid for this ioctl call.
    if unsafe { libc::ioctl(socket, libc::SIOCGIFFLAGS as libc::Ioctl, &mut request) } < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(socket) };
        return Err(error.into());
    }
    let mut flags = i16::from_ne_bytes(request.data[..2].try_into().unwrap());
    flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    request.data[..2].copy_from_slice(&flags.to_ne_bytes());
    let result = unsafe { libc::ioctl(socket, libc::SIOCSIFFLAGS as libc::Ioctl, &mut request) };
    let error = if result < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe { libc::close(socket) };
    error.map_or(Ok(()), |error| Err(error.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_tun_packets() {
        assert!(validate_packet(&[0x45], 1400, DeviceMode::Tun).is_ok());
        assert!(validate_packet(&[0x60], 1400, DeviceMode::Tun).is_ok());
        assert!(matches!(
            validate_packet(&[], 1400, DeviceMode::Tun),
            Err(InterfaceError::InvalidIpPacket)
        ));
        assert!(matches!(
            validate_packet(&[0x45; 4], 3, DeviceMode::Tun),
            Err(InterfaceError::PacketTooLarge { .. })
        ));
    }

    #[test]
    fn validates_tap_ethernet_frames() {
        let frame_14 = [0u8; 14];
        assert!(validate_packet(&frame_14, 1400, DeviceMode::Tap).is_ok());
        let small_frame = [0u8; 13];
        assert!(matches!(
            validate_packet(&small_frame, 1400, DeviceMode::Tap),
            Err(InterfaceError::InvalidEthernetFrame)
        ));
        let oversized = vec![0u8; 1400 + 19];
        assert!(matches!(
            validate_packet(&oversized, 1400, DeviceMode::Tap),
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

    #[tokio::test]
    async fn wraps_raw_fd_into_tun_device() {
        let mut fds = [0; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let dev = TunDevice::from_raw_fd(fds[0], "test-tun".into(), 1400, DeviceMode::Tun).unwrap();
        assert_eq!(dev.name(), "test-tun");
        assert_eq!(dev.mtu(), 1400);
        assert_eq!(dev.mode(), DeviceMode::Tun);

        // Send a valid IPv4 packet header across the pair
        let packet = [0x45, 0x00, 0x00, 0x14];
        let written = unsafe { libc::write(fds[1], packet.as_ptr() as *const _, packet.len()) };
        assert_eq!(written as usize, packet.len());

        let received = dev.recv().await.unwrap();
        assert_eq!(&received[..], &packet[..]);

        // Clean up peer socket
        unsafe { libc::close(fds[1]) };
    }
}
