// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Primitives and key hierarchy: X25519, Ed25519, ML-KEM-768, XChaCha20-Poly1305, Argon2id, BLAKE3, zeroization and constant-time helpers.
//!
//! This crate is the only one in the workspace that talks to cryptographic
//! libraries directly (ADR-0014). Everything else goes through the types here.

pub mod aead;
pub mod ed25519;
mod error;
pub mod hash;
pub mod hierarchy;
pub mod kdf;
pub mod mlkem;
pub mod password;
mod rng;
mod secret;
pub mod x25519;

pub use error::Error;
pub use secret::SecretKey;
