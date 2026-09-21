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

pub struct VirtualInterface {
    file: AsyncFd<File>,
    name: String,
    mtu: u16,
    mode: DeviceMode,
}

impl VirtualInterface {
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

        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                libc::TUNSETIFF as libc::Ioctl,
                &mut request,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let name = request.assigned_name()?;
        set_mtu(&name, config.mtu)?;

        let _ = set_up(&name);
        tracing::info!(interface = %name, mtu = config.mtu, mode = ?config.mode, "created Linux virtual device");
        Ok(Self {
            file: AsyncFd::new(file)?,
            name,
            mtu: config.mtu,
            mode: config.mode,
        })
    }

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

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    pub const fn mode(&self) -> DeviceMode {
        self.mode
    }

    pub async fn recv(&self) -> Result<Bytes, InterfaceError> {
        let max_packet_len = if self.mode == DeviceMode::Tap {
            self.mtu as usize + 18
        } else {
            self.mtu as usize
        };

        let capacity = max_packet_len + 1;
        let mut buffer = BytesMut::with_capacity(capacity);
        loop {
            let mut ready = self.file.readable().await?;
            match ready.try_io(|file| {
                buffer.resize(capacity, 0);
                let result = file.get_ref().read(&mut buffer);
                if let Ok(n) = result {
                    buffer.truncate(n);
                } else {
                    buffer.clear();
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

                    let bytes = buffer.split().freeze();
                    validate_packet(&bytes, self.mtu, self.mode)?;
                    return Ok(bytes);
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    buffer.clear();
                    continue;
                }
            }
        }
    }

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
    let result = unsafe { libc::ioctl(socket, libc::SIOCSIFMTU as libc::Ioctl, &mut request) };
    let error = if result < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };

    unsafe { libc::close(socket) };
    error.map_or(Ok(()), |error| Err(error.into()))
}

fn set_up(name: &str) -> Result<(), InterfaceError> {
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut request = IfReq::new(Some(name));
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
        let tun = VirtualInterface::create(TunConfig::default())
            .await
            .unwrap();
        assert!(!tun.name().is_empty());
        assert_eq!(tun.mtu(), crate::DEFAULT_MTU);
    }

    #[tokio::test]
    async fn wraps_raw_fd_into_tun_device() {
        let mut fds = [0; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let dev = VirtualInterface::from_raw_fd(fds[0], "test-tun".into(), 1400, DeviceMode::Tun)
            .unwrap();
        assert_eq!(dev.name(), "test-tun");
        assert_eq!(dev.mtu(), 1400);
        assert_eq!(dev.mode(), DeviceMode::Tun);

        let packet = [0x45, 0x00, 0x00, 0x14];
        let written = unsafe { libc::write(fds[1], packet.as_ptr() as *const _, packet.len()) };
        assert_eq!(written as usize, packet.len());

        let received = dev.recv().await.unwrap();
        assert_eq!(&received[..], &packet[..]);

        unsafe { libc::close(fds[1]) };
    }
}
