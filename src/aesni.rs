//! Module implementing the main digest functions using AES and SSE primitives.
//!
//! This module implements the same digest_main function as the aes module does, but explicitly
//! uses AES and SSE instructions in order to improve performance.
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::mem::{MaybeUninit, size_of, transmute};

use slice_cast::cast_mut;

use crate::aes::derive_key;
use crate::ROUNDS;

/// Type for a set of explode/implode AES keys.
type KeysType = [__m128i; 10];

pub unsafe fn digest_main(keccac: &mut [u8], scratchpad: &mut [u8]) {
    let scratchpad: &mut [__m128i] = cast_mut(scratchpad);
    // TODO: implement key derivation with aesni.
    let explode_keys: KeysType = transmute(derive_key(&keccac[..32]));
    let implode_keys: KeysType = transmute(derive_key(&keccac[32..64]));
    // Now we can cast keccac since it's not needed as u8 anymore
    let keccac: &mut [__m128i] = cast_mut(&mut keccac[..192]);

    init_scratchpad(explode_keys, keccac, scratchpad);
    main_loop(keccac, scratchpad);
    finalize_state(implode_keys, keccac, &scratchpad);
}

unsafe fn init_scratchpad(keys: KeysType, keccac: &[__m128i], scratchpad: &mut [__m128i]) {
    let mut blocks: [__m128i; 8] =MaybeUninit::uninit().assume_init();
    blocks.copy_from_slice(&keccac[4..]);

    for scratchpad_chunk in scratchpad.chunks_exact_mut(blocks.len()) {
        for block in blocks.iter_mut() {
            for key in keys.iter() {
                *block = _mm_aesenc_si128(*block, *key);
            }
        }

        scratchpad_chunk.copy_from_slice(&blocks);
    }
}

unsafe fn main_loop(keccac: &[__m128i], scratchpad: &mut [__m128i]) {
    let mut a = _mm_xor_si128(keccac[0], keccac[2]);
    let mut b = _mm_xor_si128(keccac[1], keccac[3]);

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
    // TODO: implement this using sse2
    let a = _mm_extract_epi64(a, 0) as u64;
    let b = _mm_extract_epi64(b, 0) as u64;
    let c = u128::from(a) * u128::from(b);

    _mm_set_epi64x(c as i64, (c >> 64) as i64)
}

unsafe fn finalize_state(keys: KeysType, keccac: &mut [__m128i], scratchpad: &[__m128i]) {
    let final_block: &mut [__m128i] = cast_mut(&mut keccac[4..]);

    for scratchpad_chunk in scratchpad.chunks_exact(final_block.len()) {
        for (block, sp_slice) in final_block.iter_mut().zip(scratchpad_chunk.iter()) {
            *block = _mm_xor_si128(*block, *sp_slice);
            for key in keys.iter() {
                *block = _mm_aesenc_si128(*block, *key);
            }
        }
    }
}
