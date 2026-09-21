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
| `wycheproof/xchacha20_poly1305_test.json` | same | `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9` |
| `blake3/test_vectors.json` | [BLAKE3-team/BLAKE3 `test_vectors/`, tag 1.8.7](https://github.com/BLAKE3-team/BLAKE3/tree/f3149ec5bb5449af877ba20377a11008ff499fa2/test_vectors) | `dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624` |

RFC 5869 publishes HKDF vectors for SHA-256 and SHA-1 only, so HKDF-SHA512
(`QW-U-CRY-006`) is checked against Wycheproof. The BLAKE3 vectors are
available under CC0-1.0, Apache-2.0 or Apache-2.0 WITH LLVM-exception; they are
used here under CC0-1.0.

## Transcribed from an RFC

`rfc9106/argon2id.json` holds the Argon2id vector of
[RFC 9106 §5.3](https://www.rfc-editor.org/rfc/rfc9106#section-5.3), copied
field by field into JSON (`QW-U-CRY-008`).

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
