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
        // Best-effort: enable DF-bit so the kernel emits EMSGSIZE when the
        // path rejects a datagram rather than silently fragmenting it. This
        // makes the adaptive MTU logic trigger reliably on IPv4. Failures are
        // logged at debug level and do not prevent the socket from being used.
        set_path_mtu_discovery(&socket);
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

/// Enables the "Don't Fragment" bit on the socket so that the OS emits
/// `EMSGSIZE` when a datagram exceeds the path MTU rather than silently
/// fragmenting it. This is best-effort: failures are logged but do not abort
/// the connection setup.
///
/// * **Linux** – sets `IP_MTU_DISCOVER = IP_PMTUDISC_DO` (IPv4) and
///   `IPV6_DONTFRAG = 1` (IPv6) via `socket2`.
/// * **macOS/BSDs** – sets `IP_DONTFRAG` (IPv4) via `socket2`.
/// * **Windows / other** – no-op; EMSGSIZE is still raised by Winsock when
///   the Winsock send buffer limit is hit, so the adaptive MTU still works,
///   just less reliably on IPv4.
fn set_path_mtu_discovery(socket: &tokio::net::UdpSocket) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let local = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(%e, "could not read local address to set DF-bit; skipping");
                return;
            }
        };
        // IP_PMTUDISC_DO = 2 on Linux. For IPv6 we set IPV6_DONTFRAG = 1.
        let (level, optname, val): (libc::c_int, libc::c_int, libc::c_int) = if local.is_ipv6() {
            (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1)
        } else {
            (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, 2 /* IP_PMTUDISC_DO */)
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                level,
                optname,
                &val as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            tracing::debug!("enabled DF-bit on UDP socket (IP_PMTUDISC_DO / IPV6_DONTFRAG)");
        } else {
            let e = std::io::Error::last_os_error();
            tracing::debug!(%e, "failed to enable DF-bit; EMSGSIZE may be unreliable on IPv4");
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let local = match socket.local_addr() {
            Ok(a) => a,
            Err(_) => return,
        };
        if local.is_ipv4() {
            // IP_DONTFRAG available on macOS/BSDs.
            let val: libc::c_int = 1;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_DONTFRAG,
                    &val as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if ret == 0 {
                tracing::debug!("enabled IP_DONTFRAG on UDP socket");
            } else {
                let e = std::io::Error::last_os_error();
                tracing::debug!(%e, "failed to enable IP_DONTFRAG; EMSGSIZE may be unreliable");
            }
        }
    }
    // Windows/Winsock: WSAEMSGSIZE is raised based on the send-buffer limits;
    // no portable socket option to force DF-bit without socket2 WSA extensions.
    #[cfg(not(unix))]
    {
        let _ = socket;
    }
}
