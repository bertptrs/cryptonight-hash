use std::intrinsics::{copy_nonoverlapping, transmute};
use std::mem::{MaybeUninit, size_of};
use std::ops::{Add, Mul, BitXor};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A pair of 64 bit unsigned integers
///
/// This type is used to implement the operations on the scratch pad in CryptoNight's main loop. It
/// doesn't make any sense in any other context.
#[repr(C)]
pub struct U64p(u64, u64);

impl From<&[u8]> for U64p {
    fn from(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() == size_of::<U64p>());
        let mut tmp: MaybeUninit<Self> = MaybeUninit::uninit();
        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), tmp.as_mut_ptr() as *mut u8, size_of::<U64p>());
            tmp.assume_init()
        }
    }
}

impl AsRef<[u8]> for U64p {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            let data: &[u8; 16] = &*(self as *const Self as *const [u8; 16]);
            data.as_ref()
        }
    }
}

impl AsMut<[u8]> for U64p {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe {
            let data: &mut[u8; 16] = &mut *(self as *mut Self as *mut [u8; 16]);
            data.as_mut()
        }
    }
}

/// Convert a 16 bit slice into a scratch pad address.
impl From<U64p> for usize {
    fn from(data: U64p) -> Self {
        (data.0 & 0x1F_FFF0) as usize / 16
    }
}

impl From<U64p> for [u8; 16] {
    fn from(data: U64p) -> Self {
        unsafe {
            transmute(data)
        }
    }
}
/// Perform the 8byte addition for
impl Add for U64p {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        U64p(self.0.wrapping_add(rhs.0), self.1.wrapping_add(rhs.1))
    }
}

impl Mul for U64p {
    type Output = U64p;

    fn mul(self, rhs: Self) -> Self::Output {
        let a = u128::from(self.0);
        let b = u128::from(rhs.0);

        let r = a * b;

        U64p((r >> 64) as u64, r as u64)
    }
}

impl BitXor for U64p {
    type Output = U64p;

    fn bitxor(self, rhs: Self) -> Self::Output {
        U64p (self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}