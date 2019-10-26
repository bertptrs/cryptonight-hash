use criterion::{Bencher, black_box, Criterion, criterion_group, criterion_main};
use criterion::measurement::WallTime;
use digest::Digest;

use cryptonight_hash::CryptoNight;

fn bench_buffer_reuse(b: &mut Bencher<WallTime>) {
    let mut scratchpad = CryptoNight::allocate_scratchpad();

    b.iter(|| CryptoNight::digest_with_buffer(black_box(b""), scratchpad.as_mut()));
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Hash with allocator", |b| {
        b.iter(|| CryptoNight::digest(black_box(b"")));
    });

    c.bench_function("Hash with external buffer", bench_buffer_reuse);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
