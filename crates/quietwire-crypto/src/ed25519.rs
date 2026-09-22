// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 signatures (RFC 8032), verified strictly: non-canonical and
//! small-order keys and signatures are refused.

use ed25519_dalek::Signer;

use crate::{stack, Error, SecretKey};

/// Length of a [`VerifyingKey`] in bytes.
pub const VERIFYING_KEY_LEN: usize = 32;
/// Length of a [`Signature`] in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 seed, held in locked memory and wiped on drop.
pub struct SigningKey(SecretKey);

impl SigningKey {
    /// Draws a fresh seed from the operating system RNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn generate() -> Result<Self, Error> {
        SecretKey::random().map(Self)
    }

    /// The public key matching this seed.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        stack::scrubbed(|| VerifyingKey(self.expanded().verifying_key()))
    }

    /// Signs `message` deterministically.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        stack::scrubbed(|| Signature(self.expanded().sign(message).to_bytes()))
    }

    /// The seed is expanded per operation so that its hash, which alone
    /// suffices to sign, never outlives the call.
    fn expanded(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(self.0.expose_secret())
    }
}

impl From<SecretKey> for SigningKey {
    fn from(seed: SecretKey) -> Self {
        Self(seed)
    }
}

/// An Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Parses a public key received from a peer.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if `bytes` do not encode a curve point.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Result<Self, Error> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    /// The public key bytes, for sending.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Checks `signature` over `message`.
    ///
    /// # Errors
    /// [`Error::InvalidSignature`] if it does not verify, including when the
    /// key or the signature is small-order or not canonically encoded.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.0
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature.0))
            .map_err(|_| Error::InvalidSignature)
    }
}

/// An Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// A signature received from a peer; it is only checked by
    /// [`VerifyingKey::verify`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The signature bytes, for sending.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}
