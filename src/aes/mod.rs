//! Portable Rust AES and hashing implementation for CryptoNight.
use std::ops::BitXor;

use slice_cast::cast_mut;

use constants::*;

use crate::aes::u64p::U64p;
use crate::ROUNDS;

mod constants;
mod u64p;

pub fn digest_main(keccac: &mut [u8], scratchpad: &mut [u8]) {
    init_scratchpad(keccac, scratchpad);

    let a = U64p::from(&keccac[..16]) ^ U64p::from(&keccac[32..48]);
    let b = U64p::from(&keccac[16..32]) ^ U64p::from(&keccac[48..64]);

    main_loop(a, b, scratchpad);

    finalize_state(keccac, &scratchpad);
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

fn main_loop(mut a: U64p, mut b: U64p, scratchpad: &mut [u8]) {
    // Cast to u128 for easier handling. Scratch pad is only used in 16 byte blocks
    let scratchpad: &mut [U64p] = unsafe { cast_mut(scratchpad) };

    for _ in 0..ROUNDS {
        // First transfer
        let address: usize = a.into();
        aes_round(&mut scratchpad[address].as_mut(), a.as_ref());
        let tmp = b;
        b = scratchpad[address];
        scratchpad[address] = scratchpad[address] ^ tmp;

        // Second transfer
        let address: usize = b.into();
        let tmp = a + b * scratchpad[address];
        a = scratchpad[address] ^ tmp;
        scratchpad[address] = tmp;
    }
}

fn finalize_state(keccac: &mut [u8], scratchpad: &[u8]) {
    let round_keys_buffer = derive_key(&keccac[32..64]);
    let final_block = &mut keccac[64..192];
    for scratchpad_chunk in scratchpad.chunks_exact(128) {
        xor(final_block, scratchpad_chunk);
        for block in final_block.chunks_exact_mut(16) {
            for key in round_keys_buffer.chunks_exact(16) {
                aes_round(block, key);
            }
        }
    }
}

fn multiplicative_inverse(b: u8) -> u8 {
    if b <= 1 {
        b
    } else {
        ANTI_LOG_LOOKUP[255 - LOG_LOOKUP[b as usize] as usize]
    }
}

fn s_box(c: u8) -> u8 {
    let b = multiplicative_inverse(c);
    b.bitxor(b.rotate_left(1))
        .bitxor(b.rotate_left(2))
        .bitxor(b.rotate_left(3))
        .bitxor(b.rotate_left(4))
        .bitxor(0x63)
}

/// Optimized version of gmul for multiplying by two
#[inline]
fn gmul2(a: u8) -> u8 {
    let h = !(a >> 7).wrapping_sub(1);

    (a << 1) ^ (0x1B & h)
}

/// SubBytes step
fn sub_bytes(block: &mut [u8]) {
    for c in block.iter_mut() {
        *c = s_box(*c)
    }
}

/// ShiftRows step
fn shift_rows(block: &mut [u8]) {
    // Row 0 doesn't move
    // Swap row 1
    let tmp = block[1];
    for col in 0..3 {
        let index = 1 + 4 * col;
        block[index] = block[index + 4];
    }
    block[13] = tmp;

    // Swap row 2
    block.swap(2, 10);
    block.swap(6, 14);

    // Swap row 3
    let tmp = block[15];
    for col in (1..4).rev() {
        block[col * 4 + 3] = block[col * 4 - 1];
    }
    block[3] = tmp;
}

fn mix_column(slice: &mut [u8]) {
    let mut a = [0u8; 4];
    let mut b = [0u8; 4];

    a.copy_from_slice(slice);

    for (c, db) in slice.iter().zip(b.iter_mut()) {
        *db = gmul2(*c);
    }

    for (i, dest) in slice.iter_mut().enumerate() {
        *dest = b[i] ^ a[(i + 3) % 4] ^ a[(i + 2) % 4] ^ a[(i + 1) % 4] ^ b[(i + 1) % 4];
    }
}

fn mix_columns(block: &mut [u8]) {
    for column in block.chunks_exact_mut(4) {
        mix_column(column);
    }
}

pub fn xor(block: &mut [u8], round_key: &[u8]) {
    for (c, k) in block.iter_mut().zip(round_key.iter()) {
        *c ^= *k;
    }
}

pub fn aes_round(block: &mut [u8], round_key: &[u8]) {
    sub_bytes(block);
    shift_rows(block);
    mix_columns(block);
    xor(block, round_key);
}

fn schedule_core(new_key: &mut [u8], rcon: u8) {
    new_key.rotate_left(1);
    sub_bytes(new_key);
    new_key[0] ^= rcon;
}

pub fn derive_key(main: &[u8]) -> [u8; 160] {
    let mut key_buffer = [0u8; 160];
    key_buffer[..32].copy_from_slice(main);

    let mut rcon = 1;

    for offset in (32..key_buffer.len()).step_by(4) {
        let (finished, in_progress) = key_buffer.split_at_mut(offset);
        let previous = &finished[offset - 4..];
        let next = &mut in_progress[..4];
        next.copy_from_slice(previous);

        if offset % 32 == 0 {
            schedule_core(next, rcon);
            rcon = gmul2(rcon);
        } else if offset % 32 == 16 {
            sub_bytes(next);
        }

        xor(next, &finished[(offset - 32)..]);
    }

    key_buffer
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_multiplicative_inverse() {
        assert_eq!(1, multiplicative_inverse(1));
        assert_eq!(0, multiplicative_inverse(0));
        // Samples taken from
        assert_eq!(0x53, multiplicative_inverse(0xCA));
        assert_eq!(0xCA, multiplicative_inverse(0x53));
    }

    #[test]
    fn test_s_box() {
        // Sample values taken from https://en.wikipedia.org/wiki/Rijndael_S-box#Forward_S-box
        assert_eq!(0x63, s_box(0x00));
        assert_eq!(0x7c, s_box(0x01));
        assert_eq!(0x70, s_box(0xd0));
        assert_eq!(0x38, s_box(0x76));
    }

    #[test]
    fn test_shift_rows() {
        let mut input = [
            0x0, 0x1, 0x2, 0x3,
            0x4, 0x5, 0x6, 0x7,
            0x8, 0x9, 0xA, 0xB,
            0xC, 0xD, 0xE, 0xF,
        ];

        shift_rows(&mut input);
        let expected_outcome: [u8; 16] = [
            0x0, 0x5, 0xA, 0xF,
            0x4, 0x9, 0xE, 0x3,
            0x8, 0xD, 0x2, 0x7,
            0xC, 0x1, 0x6, 0xB,
        ];
        assert_eq!(input, expected_outcome);
    }

    #[test]
    fn test_mix_column() {
        let mut input = hex!("db 13 53 45");
        mix_column(&mut input);
        assert_eq!(input, hex!("8e 4d a1 bc"));
    }

    #[test]
    fn test_derive_key() {
        let primary = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
        let expected = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                             10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
                             a5 73 c2 9f a1 76 c4 98 a9 7f ce 93 a5 72 c0 9c
                             16 51 a8 cd 02 44 be da 1a 5d a4 c1 06 40 ba de
                             ae 87 df f0 0f f1 1b 68 a6 8e d5 fb 03 fc 15 67
                             6d e1 f1 48 6f a5 4f 92 75 f8 eb 53 73 b8 51 8d
                             c6 56 82 7f c9 a7 99 17 6f 29 4c ec 6c d5 59 8b
                             3d e2 3a 75 52 47 75 e7 27 bf 9e b4 54 07 cf 39
                             0b dc 90 5f c2 7b 09 48 ad 52 45 a4 c1 87 1c 2f
                             45 f5 a6 60 17 b2 d3 87 30 0d 4d 33 64 0a 82 0a");
        let result = derive_key(&primary);
        assert_eq!(result.as_ref(), expected.as_ref());
    }
}
