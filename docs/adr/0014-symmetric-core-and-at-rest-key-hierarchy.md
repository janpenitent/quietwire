<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0014: Symmetric core and at-rest key hierarchy

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §5.7, §16 (`QW-U-CRY-005` to `QW-U-CRY-008`)

## Context

PROTOCOL.md §5.7 fixes the shape of the at-rest hierarchy (Argon2id KEK, one
random DEK, one HKDF subkey per purpose) but not the byte-level choices an
implementation needs: HKDF salt and info, the AAD and layout of the wrapped
DEK, and how a key is held in memory. Two known-answer requirements also name
vector sources that do not cover the construction used.

## Decision

1. **Subkeys.** `subkey = HKDF-SHA512(ikm = DEK, salt = empty,
   info = "QUIETWIRE-DEK-v1" ‖ label, L = 32)`, with the labels `db`, `field`,
   `identity`, `sessions` and `meta`. The version sits in the info string so a
   future hierarchy derives unrelated keys from the same DEK.
2. **Wrapped DEK.** XChaCha20-Poly1305 under the KEK with a fresh random
   192-bit nonce and AAD `"QUIETWIRE-DEK-WRAP-v1"`. Stored as 72 bytes:
   `nonce (24) ‖ ciphertext (32) ‖ tag (16)`. Changing the password rewraps
   the DEK and leaves the data untouched.
3. **KEK.** Argon2id v1.3 (0x13), 32-byte output, no secret and no associated
   data, 32-byte random salt. Only the two §5.7 profiles are constructible:
   mobile 262 144 KiB / 4 passes / 2 lanes, desktop 1 048 576 KiB / 4 / 2.
4. **`SecretKey`.** Every long-lived symmetric key sits alone at the start of
   its own 16 KiB-aligned allocation. The allocation is `mlock`ed when the OS
   page size divides 16 KiB and the lock limit allows it; a larger OS page
   would also lock, and on drop unlock, unrelated heap data, so it is left
   unlocked instead. `is_memory_locked` reports the outcome. The key is wiped
   on drop, compares in constant time and implements neither `Debug`,
   `Display` nor `Clone`. `Kek` and `Dek` wrap it as distinct types so one
   cannot be passed where the other is expected.
5. **Vector sources.**
   - `QW-U-CRY-005` and `QW-U-CRY-006` use Wycheproof, pinned by commit and
     digest. RFC 5869 has no HKDF-SHA512 vectors, and the XChaCha draft
     publishes a single AEAD vector where Wycheproof adds invalid-tag and
     edge-length cases.
   - `QW-U-CRY-008` uses the RFC 9106 §5.3 vector, transcribed into
     `tests/fixtures/rfc9106/`.
   - The QUIETWIRE-specific constructions (`derive_kek`, `Dek::subkey`) have no
     published vectors. `tests/fixtures/derived/generate.py` produces them with
     the Python standard library and argon2-cffi, which wraps the reference C
     implementation, so neither side shares code with the Rust crates.
   - Every expected value lives under `tests/fixtures/`, because the secret
     scanner flags high-entropy hex anywhere else in the source tree.

## Consequences

Changing a label, the AAD, the wrapped layout or an Argon2id profile makes
existing databases unreadable, so each is a storage-format change under §19.2.

Wiping on drop is not covered by mutation testing yet: observing it needs the
custom test allocator of `QW-U-CRY-050`, and `.cargo/mutants.toml` excludes
that one mutant until it exists.

## Rejected alternatives

- A random HKDF salt stored beside the DEK: the DEK is already uniformly
  random, so a salt adds storage without adding strength.
- Deriving subkeys with BLAKE3 `derive_key`: §5 names HKDF-SHA512 for key
  derivation and one KDF is easier to review than two.
- `zeroize::Zeroizing<[u8; 32]>` on the ordinary heap: it cannot be locked
  without locking whatever shares its page.
