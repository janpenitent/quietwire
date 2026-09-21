// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! The at-rest key hierarchy of PROTOCOL.md §5.7.
//!
//! A password-derived [`Kek`] wraps one random [`Dek`]; the DEK never
//! encrypts data itself but yields one subkey per [`Purpose`].

use std::array;

use crate::{
    aead::{self, Nonce, NONCE_LEN, TAG_LEN},
    kdf,
    secret::KEY_LEN,
    Error, SecretKey,
};

/// Length of a [`WrappedDek`]: nonce, encrypted DEK, tag.
pub const WRAPPED_DEK_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

const WRAP_AAD: &[u8] = b"QUIETWIRE-DEK-WRAP-v1";
const SUBKEY_LABEL: &[u8] = b"QUIETWIRE-DEK-v1";

/// Key-encryption key: its only job is wrapping the [`Dek`].
pub struct Kek(SecretKey);

impl From<SecretKey> for Kek {
    fn from(key: SecretKey) -> Self {
        Self(key)
    }
}

/// Data-encryption key: the root of every at-rest subkey.
///
/// Changing the password rewraps it; the data it protects is untouched.
pub struct Dek(SecretKey);

impl From<SecretKey> for Dek {
    fn from(key: SecretKey) -> Self {
        Self(key)
    }
}

impl Dek {
    /// Draws a fresh DEK from the operating system RNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn generate() -> Result<Self, Error> {
        SecretKey::random().map(Self)
    }

    /// Seals this DEK under `kek` with a fresh random nonce.
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn wrap_with(&self, kek: &Kek) -> Result<WrappedDek, Error> {
        let nonce = Nonce::random()?;
        let sealed = aead::seal(&kek.0, &nonce, WRAP_AAD, self.0.expose_secret())?;
        let mut bytes = [0; WRAPPED_DEK_LEN];
        bytes[..NONCE_LEN].copy_from_slice(nonce.as_bytes());
        bytes[NONCE_LEN..].copy_from_slice(&sealed);
        Ok(WrappedDek(bytes))
    }

    /// HKDF-SHA512 of the DEK with no salt and info `QUIETWIRE-DEK-v1 ‖ label`.
    ///
    /// # Errors
    /// None in practice; the signature follows [`kdf::hkdf_sha512`].
    pub fn subkey(&self, purpose: Purpose) -> Result<SecretKey, Error> {
        let info = [SUBKEY_LABEL, purpose.label()].concat();
        let okm = kdf::hkdf_sha512(self.0.expose_secret(), &[], &info, KEY_LEN)?;
        SecretKey::from_slice(&okm)
    }
}

/// What a DEK subkey protects. Each purpose gets an independent key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Whole-database encryption.
    Db,
    /// Field-level encryption inside the database.
    Field,
    /// The long-term identity key material.
    Identity,
    /// Ratchet session state.
    Sessions,
    /// Metadata such as contact lists and settings.
    Meta,
}

impl Purpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Db => b"db",
            Self::Field => b"field",
            Self::Identity => b"identity",
            Self::Sessions => b"sessions",
            Self::Meta => b"meta",
        }
    }
}

/// A DEK sealed under a KEK: `nonce ‖ ciphertext ‖ tag`, safe to store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrappedDek([u8; WRAPPED_DEK_LEN]);

impl WrappedDek {
    /// A wrapped DEK read back from storage.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; WRAPPED_DEK_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes to store.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; WRAPPED_DEK_LEN] {
        self.0
    }

    /// Opens the DEK under `kek`.
    ///
    /// # Errors
    /// [`Error::Authentication`] for a wrong KEK or any altered byte.
    pub fn unwrap_with(&self, kek: &Kek) -> Result<Dek, Error> {
        let nonce = Nonce::from_bytes(array::from_fn(|i| self.0[i]));
        let dek = aead::open(&kek.0, &nonce, WRAP_AAD, &self.0[NONCE_LEN..])?;
        SecretKey::from_slice(&dek).map(Dek)
    }
}
