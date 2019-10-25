use criterion::{black_box, Criterion, criterion_group, criterion_main};
use digest::Digest;

use cryptonight_hash::CryptoNight;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Empty hash", |b| {
        b.iter(|| CryptoNight::digest(black_box(b"")));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
