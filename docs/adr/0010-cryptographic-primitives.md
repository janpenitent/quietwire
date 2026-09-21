<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0010: Cryptographic primitives

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

The primitive set must be standard, constant-time, safe on cheap ARM without AES hardware, and free of nonce fragility.

## Decision

Argon2id (m=256 MiB, t=4, p=2; desktop m=1 GiB) for passwords; XChaCha20-Poly1305 (`chacha20poly1305`) for AEAD; Ed25519 (`ed25519-dalek` v3, see ADR-0016) for signatures; X25519 + ML-KEM-768 (`x25519-dalek`, `ml-kem`) for key agreement; BLAKE3 for hashing and HKDF-SHA512 for key derivation.

## Consequences

`cargo-deny` rejects duplicate versions of any of these crates. Changing a primitive is a wire-format change under §19.2.

## Rejected alternatives

PBKDF2, bcrypt, scrypt; AES-GCM (catastrophic nonce reuse, needs hardware); ECDSA (nonce fragility); X25519 alone; SHA-1, MD5.
