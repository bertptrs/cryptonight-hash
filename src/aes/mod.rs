use std::ops::{BitXor, Shl};

use constants::*;

mod constants;

fn multiplicative_inverse(b: u8) -> u8 {
    if b <= 1 {
        b
    } else {
        return ANTI_LOG_LOOKUP[255 - LOG_LOOKUP[b as usize] as usize];
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

#[cfg(test)]
mod tests {
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
}
