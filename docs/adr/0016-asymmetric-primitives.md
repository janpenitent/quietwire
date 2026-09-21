<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0016: Asymmetric primitives

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3, §16 (`QW-U-CRY-001` to `QW-U-CRY-004`, `QW-U-CRY-009`, `QW-U-CRY-010`, `QW-U-CRY-050`), ADR-0010, ADR-0014

## Context

ADR-0010 names `ed25519-dalek` v2, `x25519-dalek` and `ml-kem` for signatures
and key agreement. ADR-0014 requires every long-lived secret to live in a
`SecretKey`: its own locked page, wiped on drop. The libraries keep their
private keys in ordinary structs instead, and some of them carry derived
material that is as sensitive as the key itself.

`ed25519-dalek` v2 depends on `curve25519-dalek` 4, which uses `sha2` 0.10
and `digest` 0.10. The symmetric core already pins `sha2` 0.11 for
HKDF-SHA512, and `cargo-deny` rejects duplicate versions.

## Decision

1. **dalek v3, a deviation from ADR-0010.** `ed25519-dalek` 3.0.0 and
   `x25519-dalek` 3.0.0 on `curve25519-dalek` 5.0.0, which share `sha2` 0.11
   and `digest` 0.11 with the symmetric core. ADR-0010 and the plan now say
   v3. `ml-kem` is 0.3.2. All three are pinned exactly.
2. **X25519.** The private scalar is a `SecretKey`. A shared secret of all
   zeros, which every low-order peer key produces, is refused with
   `InvalidPublicKey` after a constant-time comparison; the result is copied
   into a new `SecretKey` and the library's copy wiped.
3. **Ed25519.** Only the 32-byte seed is kept, in a `SecretKey`. The
   expanded key, whose hash half alone is enough to sign, is rebuilt for each
   `sign` or `verifying_key` call and dropped (and wiped by the library) at
   the end of it. Verification is `verify_strict`: non-canonical and
   small-order keys and signatures are refused.
4. **ML-KEM-768.** The decapsulation key is kept as its FIPS 203 seed, `d`
   and `z`, in two `SecretKey`s, and re-expanded per operation. The public
   API never takes or returns the 2400-byte expanded form. Decapsulation is
   infallible: a malformed ciphertext yields the implicit-rejection key.
5. **`hazmat` for known-answer tests only.** The feature exposes
   deterministic encapsulation, which the ACVP encapsulation vectors need.
   It is reached only through a private function; the public `encapsulate`
   always draws its randomness from the operating system RNG.

## Consequences

Each signature and each decapsulation pays for a key expansion: a SHA-512
for Ed25519, a matrix expansion for ML-KEM. Both are small next to the
operation itself and far below any rate the transport can carry.

The ACVP `decapsulationKeyCheck` vectors do not apply, since no expanded
decapsulation key is ever parsed. Of the ML-KEM-768 vectors, 25 key
generation, 25 encapsulation, 10 decapsulation and 10 encapsulation key
check run; the expanded-key vectors run as unit tests inside the module.

`QW-U-CRY-050` covers the new keys, the Ed25519 nonce prefix and the shared
secrets on the heap. Transient copies on the stack, made inside the
libraries during an operation, are outside what the test allocator sees;
`QW-U-CRY-052` covers the process image.

## Rejected alternatives

- `ed25519-dalek` v2: a second `sha2` and `digest` in the tree.
- Storing the library key types directly: they sit in ordinary memory, and
  the expanded forms keep derived secrets resident for the key's lifetime.
- Storing the expanded ML-KEM key: 2400 bytes that do not fit a
  `SecretKey` page and hold nothing the seed does not.
- Accepting low-order X25519 keys and relying on the protocol layer: an
  all-zero secret must never reach a KDF.
