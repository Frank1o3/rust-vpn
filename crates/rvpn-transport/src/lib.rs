//! Reusable, asynchronous transport for opaque UDP datagrams.
//!
//! This crate neither parses RVPN packets nor protects them cryptographically.
//! It currently implements bounded UDP I/O and received-packet events. Reliable
//! delivery, acknowledgements, retransmission, and ordered receive buffers are
//! intentionally future work.

mod config;
mod delivery;
mod error;
mod events;
mod packet;
mod transport;

pub use config::{MAX_UDP_PAYLOAD_SIZE, TransportConfig};
pub use delivery::{DeliveryMode, Ordering, Priority, Reliability, SendOptions};
pub use error::TransportError;
pub use events::{EventTransport, TransportEvent, TransportEvents};
pub use packet::{PacketId, ReceivedDatagram, TransportPacket};
pub use transport::UdpTransport;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, timeout};

    fn localhost() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn delivery_dimensions_are_independent() {
        assert_eq!(DeliveryMode::ORDERED.reliability, Reliability::Unreliable);
        assert_eq!(DeliveryMode::RELIABLE.ordering, Ordering::Unordered);
        assert!(Priority::High > Priority::Normal);
    }

    #[test]
    fn rejects_invalid_datagram_limit() {
        let mut config = TransportConfig::new(localhost());
        config.max_datagram_size = 0;
        assert!(matches!(
            config.validate(),
            Err(TransportError::InvalidDatagramSize { .. })
        ));
    }

    #[tokio::test]
    async fn sends_and_receives_opaque_bytes_over_udp() {
        let receiver = UdpTransport::bind(localhost()).await.unwrap();
        let sender = UdpTransport::bind(localhost()).await.unwrap();
        sender
            .send_to(
                receiver.local_addr().unwrap(),
                Bytes::from_static(b"opaque"),
                SendOptions::default(),
            )
            .await
            .unwrap();
        let received = timeout(Duration::from_secs(1), receiver.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.payload, Bytes::from_static(b"opaque"));
        assert_eq!(received.peer, sender.local_addr().unwrap());
    }

    #[tokio::test]
    async fn emits_received_packet_events() {
        let receiver = UdpTransport::bind(localhost()).await.unwrap();
        let receiver_address = receiver.local_addr().unwrap();
        let (_transport, mut events) = EventTransport::new(receiver, 4).unwrap();
        let sender = UdpTransport::bind(localhost()).await.unwrap();
        sender
            .send_to(
                receiver_address,
                Bytes::from_static(b"event"),
                SendOptions::default(),
            )
            .await
            .unwrap();
        let event = timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(event, TransportEvent::PacketReceived(packet) if packet.payload == b"event"[..])
        );
    }

    #[tokio::test]
    async fn configured_peer_and_size_limit_are_enforced() {
        let receiver = UdpTransport::bind(localhost()).await.unwrap();
        let mut config = TransportConfig::new(localhost());
        config.remote_address = Some(receiver.local_addr().unwrap());
        config.max_datagram_size = 3;
        let sender = UdpTransport::open(config).await.unwrap();

        assert!(matches!(
            sender
                .send(Bytes::from_static(b"four"), SendOptions::default())
                .await,
            Err(TransportError::DatagramTooLarge { .. })
        ));
        assert!(matches!(
            sender
                .send(
                    Bytes::from_static(b"ok"),
                    SendOptions {
                        delivery: DeliveryMode::RELIABLE,
                        ..SendOptions::default()
                    }
                )
                .await,
            Err(TransportError::UnsupportedDeliveryMode)
        ));

        sender
            .send(Bytes::from_static(b"ok"), SendOptions::default())
            .await
            .unwrap();
        assert_eq!(receiver.receive().await.unwrap().payload, b"ok"[..]);
    }

    #[tokio::test]
    async fn oversized_inbound_datagram_is_rejected_without_truncation() {
        let mut config = TransportConfig::new(localhost());
        config.max_datagram_size = 3;
        let receiver = UdpTransport::open(config).await.unwrap();
        let sender = UdpTransport::bind(localhost()).await.unwrap();
        sender
            .send_to(
                receiver.local_addr().unwrap(),
                Bytes::from_static(b"four"),
                SendOptions::default(),
            )
            .await
            .unwrap();
        assert!(matches!(
            receiver.receive().await,
            Err(TransportError::DatagramTooLarge {
                size: 4,
                maximum: 3
            })
        ));
    }

    #[tokio::test]
    async fn oversized_event_does_not_stop_event_loop() {
        let mut config = TransportConfig::new(localhost());
        config.max_datagram_size = 3;
        let receiver = UdpTransport::open(config).await.unwrap();
        let receiver_address = receiver.local_addr().unwrap();
        let (_transport, mut events) = EventTransport::new(receiver, 4).unwrap();
        let sender = UdpTransport::bind(localhost()).await.unwrap();
        for payload in [Bytes::from_static(b"four"), Bytes::from_static(b"ok")] {
            sender
                .send_to(receiver_address, payload, SendOptions::default())
                .await
                .unwrap();
        }
        let first = events.recv().await.unwrap();
        let second = events.recv().await.unwrap();
        assert!(
            matches!(&first, TransportEvent::DatagramDropped { .. })
                || matches!(&second, TransportEvent::DatagramDropped { .. })
        );
        assert!(
            matches!(&first, TransportEvent::PacketReceived(packet) if packet.payload == b"ok"[..])
                || matches!(&second, TransportEvent::PacketReceived(packet) if packet.payload == b"ok"[..])
        );
    }
}
