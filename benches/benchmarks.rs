use std::alloc::{alloc, Layout};

use criterion::{Bencher, black_box, Criterion, criterion_group, criterion_main};
use criterion::measurement::WallTime;
use digest::Digest;

use cryptonight_hash::CryptoNight;

fn bench_buffer_reuse(b: &mut Bencher<WallTime>) {
    let mut scratchpad = unsafe {
        let buffer = alloc(Layout::from_size_align_unchecked(CryptoNight::SP_SIZE, CryptoNight::SP_ALIGNMENT));
        Vec::from_raw_parts(buffer, CryptoNight::SP_SIZE, CryptoNight::SP_SIZE)
    };

    b.iter(|| CryptoNight::digest_with_buffer(black_box(b""), &mut scratchpad));
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Empty hash", |b| {
        b.iter(|| CryptoNight::digest(black_box(b"")));
    });

    c.bench_function("Reuse buffer", bench_buffer_reuse);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
