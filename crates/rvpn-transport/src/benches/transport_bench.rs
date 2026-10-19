use bytes::{Bytes, BytesMut};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rvpn_crypto::{EphemeralKeyPair, PacketNonce, SessionKeys, SessionRole, transcript_hash};
use rvpn_routing::{Links, Router, Verdict};
use rvpn_transport::{AdaptiveMtu, BufferPool, OutboundQueue};
use std::{hint::black_box, net::SocketAddr};

fn bench_buffer_pool(c: &mut Criterion) {
    let pool = BufferPool::new(1500, 32);
    c.bench_function("buffer_pool_acquire_release", |b| {
        b.iter(|| {
            let buf = pool.acquire();
            pool.release(black_box(buf));
        });
    });

    c.bench_function("raw_bytesmut_allocation", |b| {
        b.iter(|| {
            let buf = BytesMut::with_capacity(1500);
            black_box(buf);
        });
    });
}

fn bench_adaptive_mtu(c: &mut Criterion) {
    let mtu = AdaptiveMtu::new(1400, 576);
    c.bench_function("adaptive_mtu_record_success", |b| {
        b.iter(|| black_box(mtu.record_success()));
    });
    c.bench_function("adaptive_mtu_effective_mtu_read", |b| {
        b.iter(|| black_box(mtu.effective_mtu()));
    });
}

fn session_keys() -> (SessionKeys, SessionKeys) {
    let initiator = EphemeralKeyPair::generate().expect("generate initiator key");
    let responder = EphemeralKeyPair::generate().expect("generate responder key");
    let initiator_shared = initiator
        .agree(responder.public_key())
        .expect("initiator key agreement");
    let responder_shared = responder
        .agree(initiator.public_key())
        .expect("responder key agreement");
    let transcript = transcript_hash(b"rvpn transport benchmark transcript");
    (
        SessionKeys::derive(&initiator_shared, &transcript, SessionRole::Initiator)
            .expect("derive initiator keys"),
        SessionKeys::derive(&responder_shared, &transcript, SessionRole::Responder)
            .expect("derive responder keys"),
    )
}

fn bench_packet_authentication(c: &mut Criterion) {
    let (sender, receiver) = session_keys();
    let mut group = c.benchmark_group("packet_authentication");
    for size in [64usize, 1400] {
        let plaintext = vec![0x5a; size];
        let aad = b"rvpn packet header";
        group.bench_with_input(BenchmarkId::new("seal", size), &size, |b, _| {
            b.iter(|| {
                black_box(
                    sender
                        .seal(PacketNonce::from_sequence(1, 42), aad, &plaintext)
                        .expect("seal packet"),
                )
            });
        });
        let ciphertext = sender
            .seal(PacketNonce::from_sequence(1, 42), aad, &plaintext)
            .expect("prepare ciphertext");
        group.bench_with_input(BenchmarkId::new("open", size), &size, |b, _| {
            b.iter(|| {
                black_box(
                    receiver
                        .open(PacketNonce::from_sequence(1, 42), aad, &ciphertext)
                        .expect("authenticate packet"),
                )
            });
        });
    }
    group.finish();
}

fn ipv4_packet(payload_len: usize) -> Vec<u8> {
    let total_len = 20 + payload_len;
    assert!(total_len <= usize::from(u16::MAX));
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 42, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 42, 0, 3]);
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let sum = header.chunks_exact(2).fold(0u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes([pair[0], pair[1]]))
    });
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

fn routing_fixture() -> (Router, rvpn_core::SessionId, Vec<u8>) {
    let first = rvpn_core::SessionId::new([1; 16]);
    let second = rvpn_core::SessionId::new([2; 16]);
    let links = Links::from_directed_pairs([(String::from("a"), String::from("b"))]);
    let mut router = Router::new(links);
    router.register(first, "a", vec!["10.42.0.2/32".parse().unwrap()]);
    router.register(second, "b", vec!["10.42.0.3/32".parse().unwrap()]);
    (router, first, ipv4_packet(44))
}

fn bench_routing(c: &mut Criterion) {
    let (mut router, sender, packet) = routing_fixture();
    c.bench_function("routing_ipv4_authorized_forward", |b| {
        b.iter(|| {
            assert!(matches!(
                black_box(router.route_ip(sender, black_box(&packet))),
                Verdict::Forward(_)
            ));
        });
    });

    let large_packet = ipv4_packet(1380);
    c.bench_function("routing_ipv4_near_mtu_forward", |b| {
        b.iter(|| {
            assert!(matches!(
                black_box(router.route_ip(sender, black_box(&large_packet))),
                Verdict::Forward(_)
            ));
        });
    });
}

fn bench_queue_scheduling(c: &mut Criterion) {
    let peer: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    let peer_key = [7; 16];
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build queue benchmark runtime");
    let mut group = c.benchmark_group("queue_schedule_enqueue_dequeue");
    for size in [64usize, 1400] {
        let payload = Bytes::from(vec![0xa5; size]);
        group.bench_with_input(BenchmarkId::new("single_peer", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let (queue, receiver) = OutboundQueue::new(64);
                    (queue, receiver)
                },
                |(queue, mut receiver)| {
                    queue
                        .try_enqueue_for_peer(peer_key, peer, payload.clone())
                        .expect("enqueue datagram");
                    let datagram = runtime.block_on(receiver.recv()).expect("dequeue datagram");
                    black_box(datagram);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_buffer_pool,
    bench_adaptive_mtu,
    bench_packet_authentication,
    bench_routing,
    bench_queue_scheduling
);
criterion_main!(benches);
