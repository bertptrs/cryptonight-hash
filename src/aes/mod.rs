use std::ops::BitXor;

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

/// Multiply A and B according to the Galois field
fn gmul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        let s = LOG_LOOKUP[a as usize] as usize + LOG_LOOKUP[b as usize] as usize;
        ANTI_LOG_LOOKUP[s % 255]
    }
}

/// SubBytes step
fn sub_bytes(block: &mut [u8]) {
    for c in block.iter_mut() {
        *c = s_box(*c)
    }
}

/// ShiftRows step
fn shift_rows(block: &mut [u8; 16]) {
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
        // Trick for faster gmul(c, 2)
        let h =  if *c >= 0x80  { 0xff } else { 0x00 };
        *db = (*c << 1) ^ (h & 0x1B);
    }

    for (i, dest) in slice.iter_mut().enumerate() {
        *dest = b[i] ^ a[(i + 3) % 4] ^ a[(i + 2) % 4] ^ a[(i + 1) % 4] ^ b[(i + 1) % 4];
    }
}

fn mix_columns(block: &mut [u8; 16]) {
    for offset in (0..16).step_by(4) {
        mix_column(&mut block[offset..(offset + 4)]);
    }
}

fn add_round_key(block: &mut [u8], round_key: &[u8]) {
    for (c, k) in block.iter_mut().zip(round_key.iter()) {
        *c ^= *k;
    }
}

pub fn aes_round(block: &mut [u8; 16], round_key: &[u8]) {
    sub_bytes(block);
    shift_rows(block);
    mix_columns(block);
    add_round_key(block, round_key);
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
    fn test_gmul() {
        assert_eq!(9, gmul(3, 7));

        for i in 0..=255 {
            // Validate all doubles since we have a simple method for it.
            let direct = i << 1;
            let direct = if i >= 0x80 { direct ^ 0x1B } else { direct };
            assert_eq!(gmul(i, 2), direct);
        }
    }
}
