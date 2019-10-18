use std::intrinsics::transmute;

use blake_hash::Blake256;
use digest::{Digest, FixedOutput, Input, Reset};
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::U32;
use groestl::Groestl256;
use itertools::multizip;
use jh_x86_64::Jh256;
use skein_hash::Skein256;

use aes::aes_round;
use aes::derive_key;
use aes::xor;

mod aes;

const SCRATCH_PAD_SIZE: usize = 1 << 21;

type ScratchBlock = [u8; 16];

#[derive(Default, Clone)]
pub struct CryptoNight {
    internal_hasher: sha3::Keccak256Full,
}

fn to_u128(a: ScratchBlock) -> u128 {
    unsafe { transmute(a) }
}

fn to_scratch_pad_address(a: ScratchBlock) -> usize {
    let a = to_u128(a);
    // Take the lowest 21 bits, and zero the lowest 4 for alignment
    (a & 0x1F_FFF0) as usize
}

fn scratch_mul(a: ScratchBlock, b: ScratchBlock) -> ScratchBlock {
    const MASK: u128 = 0xFFFF_FFFF_FFFF_FFFF;
    let a = to_u128(a) & MASK;
    let b = to_u128(b) & MASK;

    unsafe { transmute(a * b) }
}

fn scratch_add(a: ScratchBlock, b: ScratchBlock) -> ScratchBlock {
    let (a, b): ([u64; 2], [u64; 2]) = unsafe { (transmute(a), transmute(b)) };
    let result = [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])];

    unsafe { transmute(result) }
}

impl CryptoNight {
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

    fn main_loop(mut a: [u8; 16], mut b: [u8; 16], scratch_pad: &mut [u8]) {
        // Cast to u128 for easier handling. Scratch pad is only used in 16 byte blocks

        for _ in 0..524_288 {
            // First transfer
            let address = to_scratch_pad_address(a);
            let end = address + 16;
            aes_round(&mut scratch_pad[address..end], &a);
            let tmp = b;
            b.copy_from_slice(&scratch_pad[address..end]);
            xor(&mut scratch_pad[address..end], &tmp);

            // Second transfer
            let address = to_scratch_pad_address(b);
            let end = address + 16;
            let mut c: ScratchBlock = Default::default();
            c.copy_from_slice(&scratch_pad[address..end]);
            let tmp = scratch_add(a, scratch_mul(b, c));
            a.copy_from_slice(&scratch_pad[address..end]);
            xor(&mut scratch_pad[address..end], &tmp);
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

    fn hash_final_state(state: &[u8]) -> GenericArray<u8, <Self as FixedOutput>::OutputSize> {
        match state[0] & 3 {
            0 => Blake256::digest(&state),
            1 => Groestl256::digest(&state),
            2 => Jh256::digest(&state),
            3 => Skein256::digest(&state),
            _ => unreachable!("Invalid output option")
        }
    }
}

impl Input for CryptoNight {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        Input::input(&mut self.internal_hasher, data);
    }
}

impl Reset for CryptoNight {
    fn reset(&mut self) {
        Reset::reset(&mut self.internal_hasher);
    }
}

impl FixedOutput for CryptoNight {
    type OutputSize = U32;

    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
        let mut keccac = self.internal_hasher.fixed_result();

        let mut scratch_pad = Vec::<u8>::with_capacity(SCRATCH_PAD_SIZE);
        unsafe { scratch_pad.set_len(SCRATCH_PAD_SIZE) };

        Self::init_scratchpad(&keccac, &mut scratch_pad);

        let mut a = [0u8; 16];
        let mut b = [0u8; 16];

        for (dest, a, b) in multizip((a.iter_mut().chain(b.iter_mut()), &keccac, &keccac[32..])) {
            *dest = *a ^ *b;
        }

        CryptoNight::main_loop(a, b, &mut scratch_pad);

        CryptoNight::finalize_state(&mut keccac, &mut scratch_pad);
        tiny_keccak::keccakf(unsafe { transmute(&mut keccac) });

        Self::hash_final_state(&keccac)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_samples() {
        // Samples taken from
        validate_sample(
            b"",
            b"eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11",
        );
        validate_sample(
            b"This is a test",
            b"a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605",
        );
    }

    fn validate_sample(input: &[u8], hash: &[u8]) {
        let hash = hex::decode(hash).unwrap();

        let actual_result = CryptoNight::digest(input);

        assert_eq!(actual_result.as_slice(), hash.as_slice())
    }

    #[test]
    fn test_8byte_add() {
        unsafe {
            let a: ScratchBlock = transmute([42u64, 12u64]);
            let b: ScratchBlock = transmute([42u64, 36u64]);
            let r = scratch_add(a, b);
            assert_eq!(r, transmute::<_, ScratchBlock>([84u64, 48u64]))
        }
    }

    #[test]
    fn test_8byte_mul() {
        unsafe {
            let a: ScratchBlock = transmute(6u128);
            let b: ScratchBlock = transmute(7u128);
            let r = scratch_mul(a, b);
            assert_eq!(r, transmute::<_, ScratchBlock>(42u128))
        }
    }
}