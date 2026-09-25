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
    pub keepalive_jitter_pct: u8,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            minimum_mtu: None,
            keepalive_interval: Duration::from_secs(25),
            receive_pool_size: 8,
            keepalive_jitter_pct: 20,
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
            keepalive: Arc::new(KeepaliveScheduler::with_jitter(
                tuning.keepalive_interval,
                tuning.keepalive_jitter_pct,
            )),
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

    pub fn record_dropped_backpressure(&self) {
        self.metrics.record_dropped_backpressure();
    }

    fn drop_if_oversized(&self, payload: &[u8]) -> bool {
        let limit = self.mtu.effective_mtu();
        if payload.len() <= limit {
            return false;
        }
        self.metrics.record_dropped_oversized();
        if self.mtu.record_oversized(payload.len()).is_some() {
            self.metrics.record_mtu_change();
        }
        tracing::warn!(
            attempted = payload.len(),
            effective_mtu = limit,
            configured_maximum = self.config.max_datagram_size,
            "dropping outbound datagram that exceeds the current effective MTU instead of sending it"
        );
        true
    }

    pub async fn send(
        &self,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<usize, TransportError> {
        self.ensure_supported(options)?;
        if self.config.remote_address.is_none() {
            return Err(TransportError::MissingRemoteAddress);
        }
        if self.drop_if_oversized(&payload) {
            return Ok(0);
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

    pub async fn send_to(
        &self,
        peer: SocketAddr,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<usize, TransportError> {
        self.ensure_supported(options)?;
        if self.drop_if_oversized(&payload) {
            return Ok(0);
        }
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
        loop {
            match receive_from(&self.socket, &self.recv_pool, &self.metrics).await {
                Ok(datagram) => {
                    self.keepalive.record_activity();
                    return Ok(datagram);
                }
                Err(TransportError::DatagramTooLarge { size, maximum }) => {
                    tracing::warn!(
                        size,
                        maximum,
                        "dropping oversized inbound datagram instead of failing the receive loop"
                    );
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn receive_into(&self, buf: &mut BytesMut) -> Result<RecvMeta, TransportError> {
        let maximum = self.config.max_datagram_size;
        let capacity = maximum + 1;
        if buf.capacity() < capacity {
            buf.reserve(capacity - buf.capacity());
        }
        loop {
            buf.clear();
            unsafe { buf.set_len(capacity) };
            let (length, peer) = self.socket.recv_from(&mut buf[..capacity]).await?;
            if length > maximum {
                buf.clear();
                self.metrics.record_dropped_oversized();
                tracing::warn!(
                    size = length,
                    maximum,
                    %peer,
                    "dropping oversized inbound datagram instead of failing receive_into"
                );
                continue;
            }
            buf.truncate(length);
            self.metrics.record_received(length);
            self.keepalive.record_activity();
            return Ok(RecvMeta {
                peer,
                len: length,
                received_at: Instant::now(),
            });
        }
    }

    fn ensure_supported(&self, options: SendOptions) -> Result<(), TransportError> {
        if options.delivery != DeliveryMode::UNRELIABLE {
            return Err(TransportError::UnsupportedDeliveryMode);
        }
        Ok(())
    }

    pub(crate) fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

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
    const WSAEMSGSIZE: i32 = 10040;
    error.raw_os_error() == Some(WSAEMSGSIZE)
}

#[cfg(not(any(unix, windows)))]
fn is_message_too_long(_error: &std::io::Error) -> bool {
    false
}

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
        let (level, optname, val): (libc::c_int, libc::c_int, libc::c_int) = if local.is_ipv6() {
            (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1)
        } else {
            (
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                2,
            )
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
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let local = match socket.local_addr() {
            Ok(a) => a,
            Err(_) => return,
        };

        if local.is_ipv4() {
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
                tracing::debug!(
                    %e,
                    "failed to enable IP_DONTFRAG; EMSGSIZE may be unreliable"
                );
            }
        }
    }

    #[cfg(any(
        target_os = "android",
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))
    ))]
    {
        let _ = socket;
    }
    #[cfg(not(unix))]
    {
        let _ = socket;
    }
}

#[cfg(test)]
mod effective_mtu_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn localhost() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test]
    async fn outbound_oversize_check_uses_effective_mtu() {
        let receiver = UdpSocket::bind(localhost()).await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let mut config = TransportConfig::new(localhost());
        config.max_datagram_size = 64;
        let transport = UdpTransport::open(config).await.unwrap();
        assert_eq!(transport.effective_mtu(), 64);

        let at_limit = Bytes::from(vec![0u8; 64]);
        let sent = transport
            .send_to(receiver_addr, at_limit, SendOptions::default())
            .await
            .unwrap();
        assert_eq!(sent, 64);

        let mut received = [0u8; 64];
        let received_len = receiver.recv(&mut received).await.unwrap();
        assert_eq!(received_len, 64);

        let over_limit = Bytes::from(vec![0u8; 65]);
        let sent = transport
            .send_to(receiver_addr, over_limit, SendOptions::default())
            .await
            .unwrap();
        assert_eq!(sent, 0, "payload over effective_mtu must be dropped, not sent");
        assert_eq!(transport.metrics_snapshot().packets_dropped_oversized, 1);
    }

    #[test]
    fn effective_mtu_can_never_exceed_configured_maximum() {
        let mtu = AdaptiveMtu::new(1400, 576);
        assert!(mtu.effective_mtu() <= 1400);
        assert_eq!(mtu.maximum_mtu(), 1400);
    }
}