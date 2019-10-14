use sha3::Digest;

use aes::aes_round;
use aes::derive_key;

mod aes;

pub type CryptoNoteDigest = [u8; 32];

const SCRATCH_PAD_SIZE: usize = 1 << 21;

pub fn digest(input: &[u8]) -> CryptoNoteDigest {
    let mut keccac = sha3::Keccak256Full::digest(input);

    let round_keys_buffer = derive_key(&keccac[..32]);

    let blocks = &mut keccac[64..192];

    let mut scratch_pad = Vec::<u8>::with_capacity(SCRATCH_PAD_SIZE);
    // TODO: don't actually initialize the data.
    scratch_pad.resize(SCRATCH_PAD_SIZE, 0);

    for scratchpad_chunk in scratch_pad.chunks_exact_mut(blocks.len()) {
        for block in blocks.chunks_exact_mut(16) {
            for key in round_keys_buffer.chunks_exact(16) {
                aes_round(block, key);
            }
        }

        scratchpad_chunk.copy_from_slice(blocks);
    }

    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_samples() {
        // Samples taken from
        validate_sample(b"", b"eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11");
        validate_sample(b"This is a test", b"a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605");
    }

    fn validate_sample(input: &[u8], hash: &[u8]) {
        let hash = hex::decode(hash).unwrap();

        let actual_result = digest(input);

        assert_eq!(&hash, &actual_result)
    }
}
