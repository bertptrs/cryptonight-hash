//! An implementation of the [CryptoNight][1] digest algorithm.
//!
//! # Usage
//!
//! ```
//! # use hex_literal::hex;
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
use skein_hash::Skein512;

mod aes;
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))]
mod aesni;

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
    /// Alignment requirement for the scratch pad.
    pub const SP_ALIGNMENT: usize = 16;
    /// Scratch pad size.
    pub const SP_SIZE: usize = 1 << 21;

    /// Compute a digest with a provided buffer.
    ///
    /// This method performs no allocations.
    ///
    /// This method performs no allocations, as opposed to the
    /// `fixed_result` method. However, the scratchpad should be of
    /// proper length and alignment. See the `SP_ALIGNMENT` and `SP_SIZE`
    /// constants for the exact requirements.
    ///
    /// See also: `Digest::fixed_result()`.
    ///
    /// # Panics
    ///
    /// If the buffer provided is not acceptable, this method will panic.
    pub fn fixed_result_with_buffer(self, scratchpad: &mut [u8]) -> GenericArray<u8, <Self as FixedOutput>::OutputSize> {
        // Ensure that our alignment requirements are met.
        assert_eq!(scratchpad.as_ptr() as usize & (Self::SP_ALIGNMENT - 1), 0);
        assert_eq!(scratchpad.len(), Self::SP_SIZE);

        let mut keccac = A16(self.internal_hasher.fixed_result());
        let keccac = &mut keccac.0;

        Self::digest_main(keccac, scratchpad);

        #[allow(clippy::cast_ptr_alignment)]
            tiny_keccak::keccakf(unsafe { &mut *(keccac as *mut GenericArray<u8, U200> as *mut [u64; 25]) });

        Self::hash_final_state(&keccac)
    }

    /// Compute a digest with a provided buffer.
    ///
    /// This method performs no allocations.
    ///
    /// This method performs no allocations, as opposed to the
    /// `fixed_result` method. However, the scratchpad should be of
    /// proper length and alignment. See the `SP_ALIGNMENT` and `SP_SIZE`
    /// constants for the exact requirements.
    ///
    /// See also: `Digest::digest()`.
    ///
    /// # Panics
    ///
    /// If the buffer provided is not acceptable, this method will panic.
    pub fn digest_with_buffer<B>(data: B, scratchpad: &mut [u8]) -> GenericArray<u8, <Self as FixedOutput>::OutputSize>
        where B: AsRef<[u8]> {
        let mut hasher: Self = Default::default();
        Input::input(&mut hasher, data);
        hasher.fixed_result_with_buffer(scratchpad)
    }

    /// Allocate a reusable scratchpad for use with the `_with_buffer` methods.
    ///
    /// The resulting buffer is guaranteed to be on the heap. Its contents are undefinded.
    ///
    /// # Usage
    /// ```
    /// # use cryptonight_hash::CryptoNight;
    /// let mut buffer = CryptoNight::allocate_scratchpad();
    ///
    /// CryptoNight::digest_with_buffer(b"Your data", buffer.as_mut());
    /// ```
    pub fn allocate_scratchpad() -> impl AsMut<[u8]> {
        unsafe {
            let buffer = alloc(Layout::from_size_align_unchecked(Self::SP_SIZE, Self::SP_ALIGNMENT));
            Vec::from_raw_parts(buffer, Self::SP_SIZE, Self::SP_SIZE)
        }
    }

    fn digest_main(keccac: &mut [u8], scratchpad: &mut [u8]) {
        #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))]
            {
                if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse4.1") {
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
            3 => Skein512::digest(&state),
            x => unreachable!("Invalid output option {}", x)
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
        let mut scratchpad = Self::allocate_scratchpad();

        self.fixed_result_with_buffer(scratchpad.as_mut())
    }
}
