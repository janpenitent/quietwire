<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0020: One nonce per message, shared by the frame and the cell

- Status: Accepted
- Date: 2026-09-22
- Source: project plan §5.4, §6.1, §6.2, §18.6 (`A023`, `A026`), §16 (`QW-U-E2E-012`)

## Context

§5.4 encrypts every ratchet frame with XChaCha20-Poly1305 under a random
24-byte nonce. The ratchet frame layout in §6.2 has no room for that nonce:
40 bytes of header, 396 of ciphertext and 16 of tag fill all 452 bytes. The
only 24-byte nonce on the wire is the cell's, at offset 20 in §6.1, and the
cell layer seals its own 452-byte body with it.

The receiver needs the frame's nonce to open it. It has to travel somewhere,
or be something the receiver can compute.

## Decision

1. **One nonce per message, drawn from the OS CSPRNG.** The ratchet draws a
   fresh 24-byte nonce for every frame and returns it with the frame.
   `quietwire_e2e::ratchet::SealedFrame` carries both.
2. **The cell carries that nonce at offset 20.** The cell layer seals the
   frame under the same nonce with its own key. It does not draw a second
   nonce.
3. **The two keys are independent (`A023`).** The frame is sealed under a
   message key `MK` that the ratchet uses exactly once. The cell key is never
   derived from `MK` or from any ratchet state. That rule binds the cell
   layer when it is specified.
4. **Collision probability (`A026`).** Under `MK` a collision cannot happen,
   because each `MK` seals one frame. Under a long-lived cell key, `n`
   random 192-bit nonces collide with probability below `n² / 2¹⁹³`. At
   2⁴⁰ messages under one key, far beyond any device's lifetime, that is
   below 2⁻¹¹³.
5. §5.4, §6.1 and §6.2 cite this record.

## Consequences

The ratchet is tested with the nonce as an explicit input and output, and
the cell layer takes it from the ratchet instead of generating one.

The nonce is public and covered by the cell's AAD (§6.1). The frame does not
authenticate it separately, but it is still bound: a different nonce opens
the frame to a different keystream and tag, and authentication fails.

Using one nonce under two different keys is safe for XChaCha20-Poly1305. A
nonce only breaks the construction when it repeats under the same key.

## Rejected alternatives

- Deriving the nonce from `MK`, for example with a third HMAC label. It is
  safe while `MK` is single-use, but `A026` forbids nonces derived from
  state. It would also turn a key-reuse bug into a nonce-reuse bug with no
  second line of defence.
- A 24-byte nonce field inside the frame. The ciphertext would shrink from
  396 to 372 bytes and the application body from 365 to 341: every cell
  would lose 24 bytes of text to carry a value the cell already carries.
- A counter nonce. `A026` forbids it, and a device restored from a backup
  would repeat counters.
