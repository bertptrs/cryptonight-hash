# cryptonight-hash

[![Build Status](https://travis-ci.org/bertptrs/cryptonight-hash.svg?branch=master)](https://travis-ci.org/bertptrs/cryptonight-hash)
[![Crates.io](https://img.shields.io/crates/v/cryptonight-hash)](https://crates.io/crates/cryptonight-hash)
[![Documentation](https://docs.rs/cryptonight-hash/badge.svg)](https://docs.rs/cryptonight-hash/)
![Crates.io](https://img.shields.io/crates/l/cryptonight-hash)


A pure-rust implementation of the CryptoNight digest algorithm. The
implementation is based on the specification in
[CryptoNote standard 8](https://cryptonote.org/cns/cns008.txt).

The crate is compiled with support for AES CPU extensions if the
platform supports it, currently only on x86 and x86_64. It is possible
to disable this by disabling the default features.

## Features

- [`digest`](https://crates.io/crates/digest)-compatible implementation
  of the CryptoNight digest.
- No non-rust dependencies.
- Support for SSE2 and AES CPU extensions.
- Full fallback implementation for other platforms.
- Performance comparable to competing implementations.

## Compared to others

There are already different crates that also implement this digest
algorithm, but there are some differences. In decreasing order of
downloads (as of 2019-10-25):

- [cryptonight-rs](https://crates.io/crates/cryptonight-rs) simply
  wraps the function from the original Monero C code. It also claims
  to be unstable.
- [yellowsun](https://crates.io/crates/yellowsun) implements the digest
  completely in Rust but does so in a way that requires using AES CPU
  extensions. If your platform doesn't have those, you can't use it.
- [cryptonight](https://crates.io/crates/cryptonight) requires SSE (but
  not AES) extensions for the hash. It indirectly depends on some C-code
  to implement the secondary hashes.
  
Aside from the differences above, this crate is the only one that can
easily compute hashes incrementally and that can operate with the
traits in the `digest` crate.

## Wish list

- [ ] Support CPU extensions for key generation
- [ ] `nostd` support
