use crate::{
    AdaptiveMtu, BufferPool, DeliveryMode, KeepaliveScheduler, MetricsSnapshot, MtuSnapshot,
    ReceivedDatagram, RecvMeta, SendOptions, TransportConfig, TransportError, TransportMetrics,
};
use bytes::{Bytes, BytesMut};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

#[derive(Clone, Debug)]
pub struct TransportTuning {
    pub minimum_mtu: Option<usize>,
    pub keepalive_interval: Duration,
    pub receive_pool_size: usize,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            minimum_mtu: None,
            keepalive_interval: Duration::from_secs(25),
            receive_pool_size: 8,
        }
    }
}

#[derive(Debug)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    config: TransportConfig,
    pub(crate) metrics: Arc<TransportMetrics>,
    pub(crate) mtu: Arc<AdaptiveMtu>,
    pub(crate) recv_pool: Arc<BufferPool>,
    pub(crate) keepalive: Arc<KeepaliveScheduler>,
}

impl UdpTransport {
    pub async fn open(config: TransportConfig) -> Result<Self, TransportError> {
        Self::open_with_tuning(config, TransportTuning::default()).await
    }

    pub async fn open_with_tuning(
        config: TransportConfig,
        tuning: TransportTuning,
    ) -> Result<Self, TransportError> {
        config.validate()?;
        let socket = UdpSocket::bind(config.local_address).await?;
        if let Some(peer) = config.remote_address {
            socket.connect(peer).await?;
        }
        let target_mtu = config.max_datagram_size;
        let minimum_mtu = tuning.minimum_mtu.unwrap_or_else(|| target_mtu.min(576));
        let recv_capacity = target_mtu + 1;
        Ok(Self {
            socket: Arc::new(socket),
            config,
            metrics: Arc::new(TransportMetrics::new()),
            mtu: Arc::new(AdaptiveMtu::new(target_mtu, minimum_mtu)),
            recv_pool: Arc::new(BufferPool::new(
                recv_capacity,
                tuning.receive_pool_size.max(1),
            )),
            keepalive: Arc::new(KeepaliveScheduler::new(tuning.keepalive_interval)),
        })
    }

    pub async fn bind(address: SocketAddr) -> Result<Self, TransportError> {
        Self::open(TransportConfig::new(address)).await
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    pub fn effective_mtu(&self) -> usize {
        self.mtu.effective_mtu()
    }

    pub fn mtu_snapshot(&self) -> MtuSnapshot {
        self.mtu.snapshot()
    }

    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn keepalive(&self) -> &KeepaliveScheduler {
        &self.keepalive
    }

    pub fn report_path_failure(&self) {
        self.mtu.record_path_failure();
    }

    /// Sends opaque bytes to the configured remote peer.
    pub async fn send(
        &self,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<usize, TransportError> {
        self.validate_outbound(&payload)?;
        self.ensure_supported(options)?;
        if self.config.remote_address.is_none() {
            return Err(TransportError::MissingRemoteAddress);
        }
        let attempted = payload.len();
        match self.socket.send(&payload).await {
            Ok(sent) => {
                self.on_send_success(sent);
                Ok(sent)
            }
            Err(error) => Err(self.on_send_error(error, attempted)),
        }
    }

    /// Sends opaque bytes to `peer`, without changing the configured default peer.
    pub async fn send_to(
        &self,
        peer: SocketAddr,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<usize, TransportError> {
        self.validate_outbound(&payload)?;
        self.ensure_supported(options)?;
        let attempted = payload.len();
        match self.socket.send_to(&payload, peer).await {
            Ok(sent) => {
                self.on_send_success(sent);
                Ok(sent)
            }
            Err(error) => Err(self.on_send_error(error, attempted)),
        }
    }

    fn on_send_success(&self, sent: usize) {
        self.metrics.record_sent(sent);
        self.keepalive.record_activity();
        if self.mtu.record_success().is_some() {
            self.metrics.record_mtu_change();
            tracing::debug!(
                target_mtu = self.mtu.target_mtu(),
                effective_mtu = self.mtu.effective_mtu(),
                "adaptive MTU probe advanced"
            );
        }
    }

    fn on_send_error(&self, error: std::io::Error, attempted: usize) -> TransportError {
        self.metrics.record_send_error();
        if is_message_too_long(&error) {
            self.metrics.record_dropped_oversized();
            if self.mtu.record_oversized(attempted).is_some() {
                self.metrics.record_mtu_change();
                tracing::info!(
                    target_mtu = self.mtu.target_mtu(),
                    effective_mtu = self.mtu.effective_mtu(),
                    reason = "path rejected datagram size",
                    "effective MTU reduced"
                );
            }
            return TransportError::PathMtuExceeded {
                attempted,
                effective: self.mtu.effective_mtu(),
            };
        }
        error.into()
    }

    pub async fn receive(&self) -> Result<ReceivedDatagram, TransportError> {
        let datagram = receive_from(&self.socket, &self.recv_pool, &self.metrics).await?;
        self.keepalive.record_activity();
        Ok(datagram)
    }

    pub async fn receive_into(&self, buf: &mut BytesMut) -> Result<RecvMeta, TransportError> {
        let maximum = self.config.max_datagram_size;
        let capacity = maximum + 1;
        if buf.capacity() < capacity {
            buf.reserve(capacity - buf.capacity());
        }
        buf.clear();

        unsafe { buf.set_len(capacity) };
        let (length, peer) = self.socket.recv_from(&mut buf[..capacity]).await?;
        if length > maximum {
            buf.clear();
            self.metrics.record_dropped_oversized();
            return Err(TransportError::DatagramTooLarge {
                size: length,
                maximum,
            });
        }
        buf.truncate(length);
        self.metrics.record_received(length);
        self.keepalive.record_activity();
        Ok(RecvMeta {
            peer,
            len: length,
            received_at: Instant::now(),
        })
    }

    fn validate_outbound(&self, payload: &[u8]) -> Result<(), TransportError> {
        if payload.len() > self.config.max_datagram_size {
            return Err(TransportError::DatagramTooLarge {
                size: payload.len(),
                maximum: self.config.max_datagram_size,
            });
        }
        Ok(())
    }

    fn ensure_supported(&self, options: SendOptions) -> Result<(), TransportError> {
        // Options are accepted from day one so a caller must state semantics;
        // unimplemented promises fail explicitly instead of silently degrading.
        if options.delivery != DeliveryMode::UNRELIABLE {
            return Err(TransportError::UnsupportedDeliveryMode);
        }
        Ok(())
    }

    pub(crate) fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Returns the underlying raw socket file descriptor.
    ///
    /// On Android, callers must pass this descriptor to `VpnService.protect(fd)`
    /// so outbound UDP datagrams are excluded from the VPN tunnel.
    #[cfg(unix)]
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.socket.as_raw_fd()
    }
}

pub(crate) async fn receive_from(
    socket: &UdpSocket,
    pool: &BufferPool,
    metrics: &TransportMetrics,
) -> Result<ReceivedDatagram, TransportError> {
    let capacity = pool.capacity();
    let maximum = capacity.saturating_sub(1);
    let mut buffer = pool.acquire();
    debug_assert!(buffer.capacity() >= capacity);

    unsafe { buffer.set_len(capacity) };
    let (length, peer) = socket.recv_from(&mut buffer[..capacity]).await?;
    if length > maximum {
        pool.release(buffer);
        metrics.record_dropped_oversized();
        return Err(TransportError::DatagramTooLarge {
            size: length,
            maximum,
        });
    }
    buffer.truncate(length);
    metrics.record_received(length);
    Ok(ReceivedDatagram {
        peer,
        payload: buffer.freeze(),
        received_at: Instant::now(),
    })
}

#[cfg(unix)]
fn is_message_too_long(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMSGSIZE)
}

#[cfg(windows)]
fn is_message_too_long(error: &std::io::Error) -> bool {
    // WSAEMSGSIZE. The `libc` crate does not expose Winsock error
    // constants under POSIX names, so this is spelled out explicitly.
    const WSAEMSGSIZE: i32 = 10040;
    error.raw_os_error() == Some(WSAEMSGSIZE)
}

#[cfg(not(any(unix, windows)))]
fn is_message_too_long(_error: &std::io::Error) -> bool {
    false
}
