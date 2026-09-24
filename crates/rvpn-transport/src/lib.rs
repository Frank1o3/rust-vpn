mod buffer_pool;
mod config;
mod congestion;
mod delivery;
mod error;
mod events;
mod keepalive;
mod metrics;
mod mtu;
mod packet;
mod transport;

pub use buffer_pool::BufferPool;
pub use config::{MAX_UDP_PAYLOAD_SIZE, TransportConfig};
pub use congestion::{OutboundQueue, OutboundQueueReceiver, QueuedDatagram};
pub use delivery::{DeliveryMode, Ordering, Priority, Reliability, SendOptions};
pub use error::TransportError;
pub use events::{EventTransport, TransportEvent, TransportEvents};
pub use keepalive::{KeepaliveScheduler, random_keepalive_len, random_keepalive_payload};
pub use metrics::{MetricsSnapshot, TransportMetrics};
pub use mtu::{AdaptiveMtu, MtuChangeReason, MtuSnapshot, default_udp_payload_mtu};
pub use packet::{PacketId, ReceivedDatagram, RecvMeta, TransportPacket};
pub use transport::{TransportTuning, UdpTransport};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
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
        assert!(received.age() < Duration::from_secs(2));
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

    #[tokio::test]
    async fn effective_mtu_starts_at_configured_maximum() {
        let mut config = TransportConfig::new(localhost());
        config.max_datagram_size = 1400;
        let transport = UdpTransport::open(config).await.unwrap();
        assert_eq!(transport.effective_mtu(), 1400);
        let snapshot = transport.mtu_snapshot();
        assert_eq!(snapshot.target_mtu, 1400);
        assert_eq!(snapshot.maximum_mtu, 1400);
        assert!(snapshot.minimum_mtu <= 1400);
    }

    #[tokio::test]
    async fn metrics_track_successful_sends_and_receives() {
        let receiver = UdpTransport::bind(localhost()).await.unwrap();
        let receiver_address = receiver.local_addr().unwrap();
        let sender = UdpTransport::bind(localhost()).await.unwrap();
        sender
            .send_to(
                receiver_address,
                Bytes::from_static(b"metrics"),
                SendOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(sender.metrics_snapshot().packets_sent, 1);
        assert_eq!(sender.metrics_snapshot().bytes_sent, 7);

        receiver.receive().await.unwrap();
        assert_eq!(receiver.metrics_snapshot().packets_received, 1);
        assert_eq!(receiver.metrics_snapshot().bytes_received, 7);
    }

    #[tokio::test]
    async fn receive_into_reuses_the_callers_buffer() {
        let receiver = UdpTransport::bind(localhost()).await.unwrap();
        let receiver_address = receiver.local_addr().unwrap();
        let sender = UdpTransport::bind(localhost()).await.unwrap();

        let mut buf = BytesMut::new();
        for payload in [&b"first"[..], &b"second-longer"[..]] {
            sender
                .send_to(
                    receiver_address,
                    Bytes::copy_from_slice(payload),
                    SendOptions::default(),
                )
                .await
                .unwrap();
            let meta = timeout(Duration::from_secs(1), receiver.receive_into(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..meta.len], payload);
        }
    }

    #[tokio::test]
    async fn concurrent_receives_do_not_corrupt_buffers() {
        let receiver = std::sync::Arc::new(UdpTransport::bind(localhost()).await.unwrap());
        let receiver_address = receiver.local_addr().unwrap();
        let sender = UdpTransport::bind(localhost()).await.unwrap();

        let a = tokio::spawn({
            let receiver = std::sync::Arc::clone(&receiver);
            async move { receiver.receive().await }
        });
        let b = tokio::spawn({
            let receiver = std::sync::Arc::clone(&receiver);
            async move { receiver.receive().await }
        });

        for payload in [&b"one"[..], &b"two"[..]] {
            sender
                .send_to(
                    receiver_address,
                    Bytes::copy_from_slice(payload),
                    SendOptions::default(),
                )
                .await
                .unwrap();
        }

        let (first, second) = tokio::join!(a, b);
        let mut payloads: Vec<Bytes> = vec![
            first.unwrap().unwrap().payload,
            second.unwrap().unwrap().payload,
        ];
        payloads.sort();
        assert_eq!(
            payloads,
            vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")]
        );
    }
}
