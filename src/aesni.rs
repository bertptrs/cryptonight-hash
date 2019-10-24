//! Module implementing the main digest functions using AES and SSE primitives.
//!
//! This module implements the same digest_main function as the aes module does, but explicitly
//! uses AES and SSE instructions in order to improve performance.
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use slice_cast::cast_mut;

use crate::aes::{aes_round, derive_key, xor};
use crate::ROUNDS;
use crate::u64p::U64p;

pub unsafe fn digest_main(keccac: &mut [u8], scratch_pad: &mut [u8]) {
    init_scratchpad(keccac, scratch_pad);

    let a = U64p::from(&keccac[..16]) ^ U64p::from(&keccac[32..48]);
    let b = U64p::from(&keccac[16..32]) ^ U64p::from(&keccac[48..64]);

    main_loop(a, b, scratch_pad);

    finalize_state(keccac, &scratch_pad);
}

fn init_scratchpad(keccac: &[u8], scratchpad: &mut [u8]) {
    let round_keys_buffer = derive_key(&keccac[..32]);

    let mut blocks = [0u8; 128];
    blocks.copy_from_slice(&keccac[64..192]);

    for scratchpad_chunk in scratchpad.chunks_exact_mut(blocks.len()) {
        for block in blocks.chunks_exact_mut(16) {
            for key in round_keys_buffer.chunks_exact(16) {
                aes_round(block, key);
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

fn finalize_state(keccac: &mut [u8], scratch_pad: &[u8]) {
    let round_keys_buffer = derive_key(&keccac[32..64]);
    let final_block = &mut keccac[64..192];
    for scratchpad_chunk in scratch_pad.chunks_exact(128) {
        xor(final_block, scratchpad_chunk);
        for block in final_block.chunks_exact_mut(16) {
            for key in round_keys_buffer.chunks_exact(16) {
                aes_round(block, key);
            }
        }
    }
}
