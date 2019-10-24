//! Module implementing the main digest functions using AES and SSE primitives.
//!
//! This module implements the same digest_main function as the aes module does, but explicitly
//! uses AES and SSE instructions in order to improve performance.
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::intrinsics::transmute;

use slice_cast::{cast, cast_mut};

use crate::aes::{aes_round, derive_key};
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

fn main_loop(mut a: U64p, mut b: U64p, scratch_pad: &mut [u8]) {
    // Cast to u128 for easier handling. Scratch pad is only used in 16 byte blocks
    let scratch_pad: &mut [U64p] = unsafe { cast_mut(scratch_pad) };

    for _ in 0..ROUNDS {
        // First transfer
        let address: usize = a.into();
        aes_round(&mut scratch_pad[address].as_mut(), a.as_ref());
        let tmp = b;
        b = scratch_pad[address];
        scratch_pad[address] = scratch_pad[address] ^ tmp;

        // Second transfer
        let address: usize = b.into();
        let tmp = a + b * scratch_pad[address];
        a = scratch_pad[address] ^ tmp;
        scratch_pad[address] = tmp;
    }
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
