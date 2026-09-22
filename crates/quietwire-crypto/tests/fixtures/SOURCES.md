<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Test vector sources

## Published vector sets

Every file in this section is an unmodified copy of a published vector set,
pinned to a commit. Refreshing one means changing the commit and the digest
together.

| File | Upstream, at commit | SHA-256 |
|---|---|---|
| `wycheproof/hkdf_sha512_test.json` | [C2SP/wycheproof `testvectors_v1/`](https://github.com/C2SP/wycheproof/tree/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1) | `bb9a21f4e86041caf5d7792b030349f8ff289087f195b2fbc0fc0afc39deca6f` |
| `wycheproof/hmac_sha512_test.json` | same | `b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab34718abaa6cabd71cc2ba1207` |
| `wycheproof/xchacha20_poly1305_test.json` | same | `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9` |
| `wycheproof/x25519_test.json` | same | `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d` |
| `wycheproof/ed25519_test.json` | same | `752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536` |
| `blake3/test_vectors.json` | [BLAKE3-team/BLAKE3 `test_vectors/`, tag 1.8.7](https://github.com/BLAKE3-team/BLAKE3/tree/f3149ec5bb5449af877ba20377a11008ff499fa2/test_vectors) | `dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624` |
| `acvp/ml_kem_key_gen.json` | [usnistgov/ACVP-Server `ML-KEM-keyGen-FIPS203/internalProjection.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json) | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` |
| `acvp/ml_kem_encap_decap.json` | [usnistgov/ACVP-Server `ML-KEM-encapDecap-FIPS203/internalProjection.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json) | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |
| `speccheck/cases.json` | [novifinancial/ed25519-speccheck `cases.json`](https://github.com/novifinancial/ed25519-speccheck/blob/65519336fda78a3d016e947df6d82848aca0c9da/cases.json) | `08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450` |

RFC 5869 publishes HKDF vectors for SHA-256 and SHA-1 only, so HKDF-SHA512
(`QW-U-CRY-006`) is checked against Wycheproof, and so is HMAC-SHA512, the
Double Ratchet chain function (§5.4). The BLAKE3 vectors are
available under CC0-1.0, Apache-2.0 or Apache-2.0 WITH LLVM-exception; they are
used here under CC0-1.0.

The ACVP files are the internal projections, which carry the expected results
next to the inputs; only the ML-KEM-768 groups are used (`QW-U-CRY-009`,
`QW-U-CRY-010`). `speccheck/cases.json` holds the edge cases of *Taming the
many EdDSAs*; `verify_strict` is expected to accept only case 3, as the
upstream results table lists for dalek's strict mode (`QW-U-CRY-004`).

## Transcribed from a specification

These files are copied field by field into JSON, with nothing computed.

| File | Source |
|---|---|
| `rfc9106/argon2id.json` | [RFC 9106 §5.3](https://www.rfc-editor.org/rfc/rfc9106#section-5.3), the Argon2id vector (`QW-U-CRY-008`) |
| `rfc7748/x25519.json` | [RFC 7748 §5.2](https://www.rfc-editor.org/rfc/rfc7748#section-5.2) and [§6.1](https://www.rfc-editor.org/rfc/rfc7748#section-6.1), X25519 only (`QW-U-CRY-001`, `QW-U-CRY-002`) |
| `rfc8032/ed25519.json` | [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1), TEST 1, 2, 3, 1024 and SHA(abc) (`QW-U-CRY-003`) |
| `libsodium/x25519_small_order.json` | the `blocklist` of [libsodium `x25519_ref10.c`](https://github.com/jedisct1/libsodium/blob/57d44b954969b859ce8cf6aeeabb06ef28e65548/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c) (SHA-256 `d7a95b188c4a64b66ff354e3368227417ed7fb450f4ac05f007d23cbc8d6801b`), the seven X25519 public keys of small order (`QW-U-CRY-002`) |

## Derived from independent implementations

`derived/` holds vectors for QUIETWIRE-specific constructions that no published
set covers. `derived/generate.py` produces them without touching the Rust
crates under test: HKDF-SHA512 from the Python standard library `hmac` module
and Argon2id from argon2-cffi 25.1.0, which wraps the reference C
implementation.

| File | Checks |
|---|---|
| `derived/argon2id_kek.json` | `derive_kek`: Argon2id v1.3 with no secret or associated data |
| `derived/dek_subkeys.json` | `Dek::subkey`: HKDF-SHA512, empty salt, info `QUIETWIRE-DEK-v1 ‖ label` |

Regenerating them must give byte-identical files; a difference means one side
changed.
