# v0.1.?

- Added new methods to reuse external buffers instead of allocating.
  - `CryptoNight::fixed_result_with_buffer` extends `Digest::fixed_result`.
  - `CryptoNight::digest_with_buffer` extends `Digest::digest`.
  - Both methods will panic if provided with bad buffers.
  - Use `CryptoNight::allocate_scratchpad` to get a suitable buffer.

# v0.1.2

- Fixed the version of the Skein algorithm used.
