use digest::Digest;
use hex_literal::hex;

use cryptonight_hash::CryptoNight;

const INPUTS: &[&[u8]] = &[
    b"",
    b"This is a test",
    &hex!("6465206f6d6e69627573206475626974616e64756d"),
    &hex!("6162756e64616e732063617574656c61206e6f6e206e6f636574"),
    &hex!("63617665617420656d70746f72"),
    &hex!("6578206e6968696c6f206e6968696c20666974"),
];

const OUTPUTS: &[[u8; 32]] = &[
    hex!("eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11"),
    hex!("a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605"),
    hex!("2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5"),
    hex!("722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4"),
    hex!("bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87"),
    hex!("b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05"),
];

#[test]
fn validate_samples() {
    for (i, (&input, &output)) in INPUTS.iter().zip(OUTPUTS.iter()).enumerate() {
        println!("{}: {}", i, hex::encode(input));
        let result = CryptoNight::digest(input);

        assert_eq!(result[..], output[..]);
    }
}

#[test]
fn validate_with_buffer() {
    let mut scratchpad = CryptoNight::allocate_scratchpad();

    for (i, (&input, &output)) in INPUTS.iter().zip(OUTPUTS.iter()).enumerate() {
        println!("{}: {}", i, hex::encode(input));
        let result = CryptoNight::digest_with_buffer(input, scratchpad.as_mut());

        assert_eq!(result[..], output[..]);
    }
}
