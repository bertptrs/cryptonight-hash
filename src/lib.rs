use std::mem::MaybeUninit;
use sha3::Digest;

pub type CryptoNoteDigest = [u8; 32];

pub fn digest(input: &[u8]) -> CryptoNoteDigest {
    let keccac = get_keccac(input);
    unimplemented!()
}

fn get_keccac(input: &[u8]) -> [u8; 200] {
    let digest = sha3::Keccak256Full::digest(input);

    let mut digest_buffer: [u8; 200] = unsafe { MaybeUninit::uninit().assume_init()};

    digest_buffer.copy_from_slice(digest.as_slice());
    digest_buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_samples() {
        validate_sample(b"", b"eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11");
        validate_sample(b"This is a test", b"a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605");
    }

    fn validate_sample(input: &[u8], hash: &[u8]) {
        let hash = hex::decode(hash).unwrap();

        let actual_result = digest(input);

        assert_eq!(&hash, &actual_result)
    }
}
