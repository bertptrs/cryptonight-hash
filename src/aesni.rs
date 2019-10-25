//! Module implementing the main digest functions using AES and SSE primitives.
//!
//! This module implements the same digest_main function as the aes module does, but explicitly
//! uses AES and SSE instructions in order to improve performance.
//!
//! This module currently requires the following CPU extensions to work:
//!
//! * AES
//! * SSE2 (for most vector operations)
//! * SSE4.1 (for extracting 64bit integers from vectors)
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::mem::size_of;

use slice_cast::cast_mut;

use crate::ROUNDS;

/// Type for a set of explode/implode AES keys.
type KeysType = [__m128i; 10];

#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn digest_main(keccac: &mut [u8], scratchpad: &mut [u8]) {
    // Cast to SSE types
    let scratchpad: &mut [__m128i] = cast_mut(scratchpad);
    let keccac: &mut [__m128i] = cast_mut(&mut keccac[..192]);

    init_scratchpad(keccac, scratchpad);
    main_loop(keccac, scratchpad);
    finalize_state(keccac, &scratchpad);
}

/// Derive 10 round keys based on two initial keys.
///
/// This implementation is based on the whitepaper "Intel® Advanced
/// Encryption Standard (AES) New Instructions Set", figure 26.
///
/// This is pretty much rustified C-code.
///
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
unsafe fn derive_key(mut temp1: __m128i, mut temp3: __m128i) -> KeysType {
    let mut keys = [_mm_setzero_si128(); 10];
    keys[0] = temp1;
    keys[1] = temp3;

    #[inline(always)]
    unsafe fn key_256_assist_1(temp1: &mut __m128i, mut temp2: __m128i) {
        temp2 = _mm_shuffle_epi32(temp2, 0xff);
        let mut temp4 = _mm_slli_si128(*temp1, 0x4);
        *temp1 = _mm_xor_si128(*temp1, temp4);
        temp4 = _mm_slli_si128(temp4, 0x4);
        *temp1 = _mm_xor_si128(*temp1, temp4);
        temp4 = _mm_slli_si128(temp4, 0x4);
        *temp1 = _mm_xor_si128(*temp1, temp4);
        *temp1 = _mm_xor_si128(*temp1, temp2);
    }

    #[inline(always)]
    unsafe fn key_256_assist_2(temp1: &__m128i, temp3: &mut __m128i) {
        let mut temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
        let temp2 = _mm_shuffle_epi32(temp4, 0xaa);
        temp4 = _mm_slli_si128(*temp3, 0x4);
        *temp3 = _mm_xor_si128(*temp3, temp4);
        temp4 = _mm_slli_si128(temp4, 0x4);
        *temp3 = _mm_xor_si128(*temp3, temp4);
        temp4 = _mm_slli_si128(temp4, 0x4);
        *temp3 = _mm_xor_si128(*temp3, temp4);
        *temp3 = _mm_xor_si128(*temp3, temp2);
    }

    key_256_assist_1(&mut temp1, _mm_aeskeygenassist_si128(temp3, 0x01));
    keys[2] = temp1;
    key_256_assist_2(&temp1, &mut temp3);
    keys[3] = temp3;

    key_256_assist_1(&mut temp1, _mm_aeskeygenassist_si128(temp3, 0x02));
    keys[4] = temp1;
    key_256_assist_2(&temp1, &mut temp3);
    keys[5] = temp3;

    key_256_assist_1(&mut temp1, _mm_aeskeygenassist_si128(temp3, 0x04));
    keys[6] = temp1;
    key_256_assist_2(&temp1, &mut temp3);
    keys[7] = temp3;

    key_256_assist_1(&mut temp1, _mm_aeskeygenassist_si128(temp3, 0x08));
    keys[8] = temp1;
    key_256_assist_2(&temp1, &mut temp3);
    keys[9] = temp3;

    keys
}

#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
unsafe fn init_scratchpad(keccac: &[__m128i], scratchpad: &mut [__m128i]) {
    let keys = derive_key(keccac[0], keccac[1]);
    let mut blocks: [__m128i; 8] = *(keccac[4..].as_ptr() as *const [__m128i; 8]);

    for scratchpad_chunk in scratchpad.chunks_exact_mut(blocks.len()) {
        for block in blocks.iter_mut() {
            for key in keys.iter() {
                *block = _mm_aesenc_si128(*block, *key);
            }
        }

        scratchpad_chunk.copy_from_slice(&blocks);
    }
}

#[target_feature(enable = "aes")]
#[target_feature(enable = "sse4.1")]
unsafe fn main_loop(keccac: &[__m128i], scratchpad: &mut [__m128i]) {
    let mut a = _mm_xor_si128(keccac[0], keccac[2]);
    let mut b = _mm_xor_si128(keccac[1], keccac[3]);

    for _ in 0..ROUNDS {
        // First transfer
        let address = scratchpad.get_unchecked_mut(to_sp_index(a));
        *address = _mm_aesenc_si128(*address, a);
        let tmp = b;
        b = *address;
        *address = _mm_xor_si128(*address, tmp);

        // Second transfer
        let address = scratchpad.get_unchecked_mut(to_sp_index(b));
        let tmp = cn_8byte_add(a, cn_8byte_mul(b, *address));
        a = _mm_xor_si128(*address, tmp);
        *address = tmp;
    }
}

#[inline(always)]
unsafe fn to_sp_index(a: __m128i) -> usize {
    let a = _mm_extract_epi32(a, 0) as u32;

    // Take the lowest 21 bits (2MB) and divide by the length of a slice.
    (a & 0x1F_FFFF) as usize / size_of::<__m128i>()
}

#[inline(always)]
unsafe fn cn_8byte_add(a: __m128i, b: __m128i) -> __m128i {
    _mm_add_epi64(a, b)
}

#[inline(always)]
unsafe fn cn_8byte_mul(a: __m128i, b: __m128i) -> __m128i {
    let a = _mm_extract_epi64(a, 0) as u64;
    let b = _mm_extract_epi64(b, 0) as u64;
    let c = u128::from(a) * u128::from(b);

    _mm_set_epi64x(c as i64, (c >> 64) as i64)
}

#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
unsafe fn finalize_state(keccac: &mut [__m128i], scratchpad: &[__m128i]) {
    let keys = derive_key(keccac[2], keccac[3]);
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
