use crate::{DeliveryMode, ReceivedDatagram, SendOptions, TransportConfig, TransportError};
use bytes::Bytes;
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::net::UdpSocket;

/// An asynchronous UDP endpoint for opaque byte payloads.
#[derive(Clone, Debug)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    config: TransportConfig,
}

impl UdpTransport {
    /// Binds an endpoint using the supplied bounded transport configuration.
    pub async fn open(config: TransportConfig) -> Result<Self, TransportError> {
        config.validate()?;
        let socket = UdpSocket::bind(config.local_address).await?;
        if let Some(peer) = config.remote_address {
            socket.connect(peer).await?;
        }
        Ok(Self {
            socket: Arc::new(socket),
            config,
        })
    }

    /// Binds an endpoint with the default transport configuration.
    pub async fn bind(address: SocketAddr) -> Result<Self, TransportError> {
        Self::open(TransportConfig::new(address)).await
    }

    /// Returns the bound local address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.socket.local_addr()?)
    }

    /// Returns this endpoint's configuration.
    pub fn config(&self) -> &TransportConfig {
        &self.config
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
        Ok(self.socket.send(&payload).await?)
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
        Ok(self.socket.send_to(&payload, peer).await?)
    }

    /// Receives one bounded opaque UDP datagram.
    pub async fn receive(&self) -> Result<ReceivedDatagram, TransportError> {
        receive_from(&self.socket, self.config.max_datagram_size).await
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
}

pub(crate) async fn receive_from(
    socket: &UdpSocket,
    maximum: usize,
) -> Result<ReceivedDatagram, TransportError> {
    let mut buffer = vec![0; maximum];
    let (length, peer) = socket.recv_from(&mut buffer).await?;
    buffer.truncate(length);
    Ok(ReceivedDatagram {
        peer,
        payload: Bytes::from(buffer),
        received_at: Instant::now(),
    })
}
