<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0019: Independent protocol test vectors

- Status: Accepted
- Date: 2026-09-22
- Source: project plan §5.3, §5.4, Phase 1 exit criterion, §16 (`QW-U-E2E-011`, `QW-U-E2E-012`), ADR-0007

## Context

ADR-0007 and the plan required every Signal test vector to pass. The Signal
X3DH and Double Ratchet specifications publish no test vectors. The only
vectors that exist are the internal tests of `libsignal`, which is AGPL and
already rejected in ADR-0007.

Even if they were available, they would not apply byte for byte. QUIETWIRE's
X3DH adds an ML-KEM-768 leg and uses a BLAKE3 transcript as the HKDF salt
(§5.3). Its ratchet uses HKDF-SHA512 and HMAC-SHA512 with its own labels and
XChaCha20-Poly1305 (§5.4). No published vector covers these constructions.

## Decision

1. **Vectors derived from independent implementations.** Each protocol
   construction is recomputed by a script beside the vectors,
   `tests/fixtures/derived/generate.py` in the crate that implements it. The
   script uses implementations that share no code with the crates under
   test, pinned to exact versions, and every input is derived from a label.
   Regenerating must give byte-identical files.
2. **A dependency that is not independently trusted is checked first.**
   kyber-py, the only pure-Python ML-KEM-768 available, must reproduce the
   pinned ACVP key generation and encapsulation vectors before the script
   writes anything.
3. **Both sides of each exchange are checked.** Vectors fix every private
   input, so the initiator path is compared through a deterministic private
   entry point and the responder path through the public API.
4. **Behaviour that vectors cannot show is tested directly.** Fresh
   sessions agree; a stripped one-time prekey, a forged KEM ciphertext or a
   claimed identity gives a different key; a low-order key is refused.
5. The Phase 1 exit criterion and the `QW-U-E2E-011` and `QW-U-E2E-012`
   sources in §16 now name these vectors instead of Signal's.

## Consequences

A vector proves agreement with a second implementation of the plan's
formulas, not with Signal. A mistake in the formulas themselves would pass
both; that is what the design review (AUD-1) and `PROTOCOL.md` are for.

Changing a label, a field order or a length in the protocol requires
regenerating the vectors, which is visible in review as a changed fixture.

## Rejected alternatives

- Porting `libsignal`'s internal tests: AGPL, and they test Signal's
  constructions, not these.
- Vectors produced by the Rust crates themselves: they would only prove the
  code agrees with itself.
- Dropping the vector requirement and relying on round-trip tests: two
  parties sharing the same bug still agree with each other.
