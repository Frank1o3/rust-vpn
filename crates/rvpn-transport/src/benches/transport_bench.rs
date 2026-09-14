use bytes::BytesMut;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rvpn_transport::{AdaptiveMtu, BufferPool};

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
        b.iter(|| {
            black_box(mtu.record_success());
        });
    });
    c.bench_function("adaptive_mtu_effective_mtu_read", |b| {
        b.iter(|| {
            black_box(mtu.effective_mtu());
        });
    });
}

criterion_group!(benches, bench_buffer_pool, bench_adaptive_mtu);
criterion_main!(benches);
