# Reiven authenticated envelope v6

This describes the implemented format, not an independent security certification. Browser and CLI use `public/envelope.mjs`. Older v4/v5 envelopes are rejected; senders must re-encrypt originals. Do not add a silent legacy fallback.

## Parameters and wire layout

All integers are unsigned big-endian. AES-GCM tags are 128 bits. The maximum plaintext length is 512 MiB; the API's encrypted-size limit includes overhead. Standard Argon2id uses 4 passes, 65,536 KiB, one lane; Paranoid uses 6 passes, 131,072 KiB, one lane. Only these canonical tuples are accepted.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 7 | UTF-8 `ESHARE1` |
| 7 | 1 | Version 6 |
| 8 | 1 | Argon2 passes |
| 9 | 1 | Argon2 lanes |
| 10 | 4 | Argon2 memory KiB |
| 14 | 4 | Plain chunk size, exactly 8,388,608 |
| 18 | 8 | Total plaintext bytes |
| 26 | 2 | Encrypted metadata bytes, including tag |
| 28 | 16 | Random salt |
| 44 | 4 | Random payload nonce prefix |
| 48 | 12 | Random wrapping IV |
| 60 | 1088 | ML-KEM-768 ciphertext |
| 1148 | 48 | Wrapped 32-byte DEK and tag |
| 1196 | variable | Encrypted JSON metadata and tag |
| after metadata | variable | Ordered encrypted chunks, each with its tag |

The metadata is UTF-8 JSON with exactly one `name` string, nonblank and at most 255 JavaScript string code units. Its encoded plaintext is bounded at 2048 bytes. Decoding uses strict UTF-8. Header probes are bounded at 4096 bytes before KDF work. Malformed sizes/profiles/versions are rejected rather than clamped.

## Keys, nonces and authentication

`D(role)` is UTF-8 `REIVEN_V6_` followed by the role and a NUL byte. `||` denotes byte concatenation. The public prefix is bytes 0 through 1147 inclusive.

1. Argon2id derives 32 bytes from UTF-8 `password || NUL || decimal PIM`, the header salt and selected profile. PIM defaults to 100; it is not an iteration multiplier.
2. SHA-512 of `D(MLKEM_SEED) || Argon2-output` supplies the deterministic 64-byte ML-KEM-768 key-generation seed.
3. Encapsulation uses fresh library CSPRNG randomness. HKDF-SHA-256 derives an AES-256-GCM wrapping key from the shared secret, with the header salt and `D(WRAP_KEY)` as info.
4. A fresh random 32-byte DEK is encrypted with the wrapping IV and AAD `D(WRAP) || public-prefix`.
5. Metadata uses the DEK, nonce `nonce-prefix || uint64(0)` and AAD `D(METADATA) || public-prefix || wrapped-DEK`.
6. Chunk index `index` starts at zero. Its nonce is `nonce-prefix || uint64(index+1)`. Its AAD is `D(CHUNK) || SHA-256(entire-header) || uint64(index) || uint64(expected-plaintext-chunk-size) || final-byte`. The last byte is 1 for the last chunk and 0 otherwise.

The authenticated total plaintext length determines `max(1, ceil(length/chunk-size))` chunks and their exact lengths. An empty file contains one authenticated empty chunk. No chunk is optional. Receivers require the exact ciphertext length, ordered chunk indices and a successful session finish before displaying/saving a complete result. The worker prohibits parallel operations and validates mode/session/index state. Metadata and chunks have disjoint nonces and record-type AAD; wrapping uses a different key and domain.

Raw temporary key arrays are cleared where practical, but JavaScript does not guarantee forensic erasure. Password entropy remains critical. A compromised client or server-delivered script remains outside the protection of this format. ML-KEM does not authenticate sender identity, and this password-derived construction does not provide independent entropy or forward secrecy beyond its secret input.

## Release verification

The remediation was exercised with local adversarial fixtures, real browser workers, CLI interoperability, bounded API race tests, and NIST ACVP ML-KEM-768 key-generation/encapsulation/decapsulation vectors. Re-run the private assessment harnesses when changing the format or dependencies. Independent protocol review, wider fuzzing, and platform coverage remain required before stronger assurances. Primitive test vectors alone do not validate the application protocol.
