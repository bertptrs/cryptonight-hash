use cryptonight_hash::CryptoNight;
use digest::Digest;

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
