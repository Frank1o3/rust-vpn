use crate::{DeviceMode, InterfaceError, TunConfig};
use bytes::Bytes;
use std::{sync::Arc, thread};
use tokio::sync::{Mutex, mpsc};

const DEFAULT_ADAPTER_NAME: &str = "RVPN";
const TUNNEL_TYPE: &str = "RVPN";
const SESSION_CAPACITY: u32 = wintun::MAX_RING_CAPACITY;

pub struct VirtualInterface {
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    name: String,
    mtu: u16,
    mode: DeviceMode,
    receive_rx: Mutex<mpsc::Receiver<Result<Bytes, InterfaceError>>>,
    reader: Option<thread::JoinHandle<()>>,
}

impl VirtualInterface {
    pub async fn create(config: TunConfig) -> Result<Self, InterfaceError> {
        config.validate()?;

        if config.mode != DeviceMode::Tun {
            return Err(InterfaceError::UnsupportedMode(config.mode));
        }

        let name = config
            .name
            .clone()
            .unwrap_or_else(|| DEFAULT_ADAPTER_NAME.to_owned());
        let mtu = config.mtu;

        let (adapter, _wintun) = tokio::task::spawn_blocking({
            let name = name.clone();
            move || -> Result<(Arc<wintun::Adapter>, wintun::Wintun), InterfaceError> {
                let wintun = unsafe { wintun::load() }.map_err(wintun_error)?;
                let adapter = match wintun::Adapter::open(&wintun, &name) {
                    Ok(adapter) => adapter,
                    Err(_) => wintun::Adapter::create(&wintun, &name, TUNNEL_TYPE, None)
                        .map_err(wintun_error)?,
                };

                adapter.set_mtu(usize::from(mtu)).map_err(wintun_error)?;
                Ok((adapter, wintun))
            }
        })
        .await
        .map_err(join_error)??;

        let session = Arc::new(
            adapter
                .start_session(SESSION_CAPACITY)
                .map_err(wintun_error)?,
        );

        let (receive_tx, receive_rx) = mpsc::channel(256);
        let reader_session = Arc::clone(&session);
        let reader = thread::Builder::new()
            .name(format!("rvpn-wintun-rx-{name}"))
            .spawn(move || {
                loop {
                    match reader_session.receive_blocking() {
                        Ok(packet) => {
                            let bytes = Bytes::copy_from_slice(packet.bytes());
                            let result = validate_packet(&bytes, mtu).map(|_| bytes);
                            if receive_tx.blocking_send(result).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = receive_tx.blocking_send(Err(wintun_error(error)));
                            break;
                        }
                    }
                }
            })
            .map_err(|error| InterfaceError::Io(std::io::Error::other(error)))?;

        tracing::info!(interface = %name, mtu, "created Windows Wintun virtual device");

        Ok(Self {
            adapter,
            session,
            name,
            mtu,
            mode: DeviceMode::Tun,
            receive_rx: Mutex::new(receive_rx),
            reader: Some(reader),
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
        let mut receive_rx = self.receive_rx.lock().await;
        receive_rx.recv().await.unwrap_or_else(|| {
            Err(InterfaceError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Wintun receive thread stopped",
            )))
        })
    }

    pub async fn send(&self, packet: &[u8]) -> Result<(), InterfaceError> {
        validate_packet(packet, self.mtu)?;

        let session = Arc::clone(&self.session);
        let packet = packet.to_vec();

        tokio::task::spawn_blocking(move || {
            let packet_size =
                u16::try_from(packet.len()).map_err(|_| InterfaceError::PacketTooLarge {
                    size: packet.len(),
                    mtu: u16::MAX,
                })?;

            let mut wintun_packet = session
                .allocate_send_packet(packet_size)
                .map_err(wintun_error)?;
            wintun_packet.bytes_mut().copy_from_slice(&packet);
            session.send_packet(wintun_packet);
            Ok::<(), InterfaceError>(())
        })
        .await
        .map_err(join_error)?
    }
}

impl Drop for VirtualInterface {
    fn drop(&mut self) {
        if let Err(error) = self.session.shutdown() {
            tracing::debug!(%error, "failed to shut down Wintun session during device drop");
        }

        if let Some(reader) = self.reader.take() {
            if let Err(error) = reader.join() {
                tracing::debug!(
                    ?error,
                    "failed to join Wintun receive thread during device drop"
                );
            }
        }

        let _ = &self.adapter;
    }
}

fn validate_packet(packet: &[u8], mtu: u16) -> Result<(), InterfaceError> {
    if packet.len() > usize::from(mtu) {
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

fn wintun_error(error: wintun::Error) -> InterfaceError {
    InterfaceError::Io(std::io::Error::other(error.to_string()))
}

fn join_error(error: tokio::task::JoinError) -> InterfaceError {
    InterfaceError::Io(std::io::Error::other(error.to_string()))
}
