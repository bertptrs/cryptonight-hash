//! An implementation of the [CryptoNight][1] digest algorithm.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # fn main() {
//! use cryptonight_hash::{CryptoNight, Digest};
//!
//! // Create the CryptoNight hasher
//! let mut hasher = CryptoNight::new();
//!
//! // Input some data into the hasher
//! hasher.input(b"This is ");
//!
//! // Insert more data as needed.
//! hasher.input("a test");
//!
//! // Finalize the result. This will temporary allocate a 2MB buffer.
//! let result = hasher.result();
//!
//! assert_eq!(result[..], hex!("a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605")[..]);
//!
//! # }
//! ```
//!
//! Be sure to refer to the [RustCrypto/hashes][2] readme for more more
//! information about the Digest traits.
//!
//! [1]: https://cryptonote.org/cns/cns008.txt
//! [2]: https://github.com/RustCrypto/hashes
use std::alloc::{alloc, Layout};

use blake_hash::Blake256;
pub use digest::{BlockInput, Digest, FixedOutput, Input, Reset};
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{U200, U32};
use groestl::Groestl256;
use jh_x86_64::Jh256;
use skein_hash::Skein256;

mod aes;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod aesni;

const SCRATCH_PAD_SIZE: usize = 1 << 21;
const ROUNDS: usize = 524_288;

#[repr(align(16))]
/// Helper to enforce 16 byte alignment
struct A16<T>(pub T);

/// CryptoNight version 0 implementation.
#[derive(Debug, Default, Clone)]
pub struct CryptoNight {
    internal_hasher: sha3::Keccak256Full,
}


impl CryptoNight {
    fn digest_main(keccac: &mut [u8], scratchpad: &mut [u8]) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
                    return unsafe { aesni::digest_main(keccac, scratchpad) };
                }
            }

        aes::digest_main(keccac, scratchpad);
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

impl BlockInput for CryptoNight {
    type BlockSize = <sha3::Keccak256Full as BlockInput>::BlockSize;
}

impl FixedOutput for CryptoNight {
    type OutputSize = U32;

    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
        let mut keccac = A16(self.internal_hasher.fixed_result());
        let keccac = &mut keccac.0;

        let mut scratch_pad = unsafe {
            let buffer = alloc(Layout::from_size_align_unchecked(SCRATCH_PAD_SIZE, 16));
            Vec::from_raw_parts(buffer, SCRATCH_PAD_SIZE, SCRATCH_PAD_SIZE)
        };

        Self::digest_main(keccac, &mut scratch_pad);

        #[allow(clippy::cast_ptr_alignment)]
            tiny_keccak::keccakf(unsafe { &mut *(keccac as *mut GenericArray<u8, U200> as *mut [u64; 25]) });

        Self::hash_final_state(&keccac)
    }
}
