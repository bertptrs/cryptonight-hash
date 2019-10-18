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
            let data: &[u8; 16] = transmute(self);
            data.as_ref()
        }
    }
}

/// Convert a 16 bit slice into a scratch pad address.
impl From<U64p> for usize {
    fn from(data: U64p) -> Self {
        (data.0 & 0x1F_FFF0) as usize
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
        let a = self.0 as u128;
        let b = rhs.0 as u128;

        unsafe { transmute(a * b) }
    }
}

impl BitXor for U64p {
    type Output = U64p;

    fn bitxor(self, rhs: Self) -> Self::Output {
        unsafe {
            let a: u128 = transmute(self);
            let b: u128 = transmute(rhs);
            transmute(a ^ b)
        }
    }
}