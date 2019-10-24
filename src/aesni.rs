//! Module implementing the main digest functions using AES and SSE primitives.
//!
//! This module implements the same digest_main function as the aes module does, but explicitly
//! uses AES and SSE instructions in order to improve performance.
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::mem::{size_of, transmute};

use slice_cast::{cast, cast_mut};

use crate::aes::derive_key;
use crate::ROUNDS;
use crate::u64p::U64p;

pub unsafe fn digest_main(keccac: &mut [u8], scratch_pad: &mut [u8]) {
    init_scratchpad(keccac, scratch_pad);

    let a = U64p::from(&keccac[..16]) ^ U64p::from(&keccac[32..48]);
    let b = U64p::from(&keccac[16..32]) ^ U64p::from(&keccac[48..64]);

    main_loop(a, b, scratch_pad);

    finalize_state(keccac, &scratch_pad);
}

unsafe fn init_scratchpad(keccac: &[u8], scratchpad: &mut [u8]) {
    let round_keys_buffer: [__m128i; 10] = transmute(derive_key(&keccac[..32]));

    let mut blocks = [0u8; 128];
    blocks.copy_from_slice(&keccac[64..192]);

    let mut blocks: [__m128i; 8] = transmute(blocks);
    let scratchpad: &mut [__m128i] = cast_mut(scratchpad);

    for scratchpad_chunk in scratchpad.chunks_exact_mut(blocks.len()) {
        for block in blocks.iter_mut() {
            for key in round_keys_buffer.iter() {
                *block = _mm_aesenc_si128(*block, *key);
            }
        }

        scratchpad_chunk.copy_from_slice(&blocks);
    }
}

unsafe fn main_loop(a: U64p, b: U64p, scratchpad: &mut [u8]) {
    let scratchpad: &mut [__m128i] = cast_mut(scratchpad);

    let mut a: __m128i = transmute(a);
    let mut b: __m128i = transmute(b);

    for _ in 0..ROUNDS {
        // First transfer
        let address = to_sp_index(a);
        scratchpad[address] = _mm_aesenc_si128(scratchpad[address], a);
        let tmp = b;
        b = scratchpad[address];
        scratchpad[address] = _mm_xor_si128(scratchpad[address], tmp);

        // Second transfer
        let address = to_sp_index(b);
        let tmp = cn_8byte_add(a, cn_8byte_mul(b, scratchpad[address]));
        a = _mm_xor_si128(scratchpad[address], tmp);
        scratchpad[address] = tmp;
    }
}

#[inline]
unsafe fn to_sp_index(a: __m128i) -> usize {
    let a = _mm_extract_epi32(a, 0) as u32;

    // Take the lowest 21 bits (2MB) and divide by the length of a slice.
    (a & 0x1F_FFFF) as usize / size_of::<__m128i>()
}

#[inline(always)]
unsafe fn cn_8byte_add(a: __m128i, b: __m128i) -> __m128i {
    _mm_add_epi64(a, b)
}

#[inline]
unsafe fn cn_8byte_mul(a: __m128i, b: __m128i) -> __m128i {
    let a = _mm_extract_epi64(a, 0) as u64;
    let b = _mm_extract_epi64(b, 0) as u64;
    let c = u128::from(a) * u128::from(b);

    _mm_set_epi64x(c as i64, (c >> 64) as i64)
}

unsafe fn finalize_state(keccac: &mut [u8], scratchpad: &[u8]) {
    let round_keys_buffer: [__m128i; 10] = transmute(derive_key(&keccac[32..64]));
    let final_block: &mut [__m128i] = cast_mut(&mut keccac[64..192]);
    let scratchpad: &[__m128i] = cast(scratchpad);

    for scratchpad_chunk in scratchpad.chunks_exact(final_block.len()) {
        for (block, sp_slice) in final_block.iter_mut().zip(scratchpad_chunk.iter()) {
            *block = _mm_xor_si128(*block, *sp_slice);
            for key in round_keys_buffer.iter() {
                *block = _mm_aesenc_si128(*block, *key);
            }
        }
    }
}
