<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Test vector sources

## Derived from independent implementations

Signal publishes no test vectors for X3DH or the Double Ratchet, and the
QUIETWIRE constructions differ from Signal's in any case (ADR-0019).
`derived/generate.py` produces the vectors here without touching the Rust
crates under test: X25519 and Ed25519 from cryptography 50.0.1 (OpenSSL),
BLAKE3 from blake3 1.0.9, ML-KEM-768 from kyber-py 1.2.0 and HKDF-SHA512 from
the Python standard library `hmac` module.

kyber-py is a pure-Python FIPS 203 implementation. Before it produces
anything, the script checks it against the ML-KEM-768 key generation and
encapsulation vectors that `quietwire-crypto` pins from ACVP.

Every private input is `SHA-256("QUIETWIRE test vector " ‖ label)`, so each
key can be traced back to its label in the script.

| File | Checks |
|---|---|
| `derived/x3dh.json` | `QW-U-E2E-011`: hybrid X3DH (plan §5.3), with and without a one-time prekey. Transcript and `SK` for the initiator; `SK` for the responder |

Regenerating them must give byte-identical files; a difference means one side
changed.
