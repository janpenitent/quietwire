// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! X25519 Diffie-Hellman (RFC 7748).

use subtle::ConstantTimeEq;
use x25519_dalek::X25519_BASEPOINT_BYTES;
use zeroize::Zeroizing;

use crate::{Error, SecretKey};

/// Length of a [`PublicKey`] in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// An X25519 private scalar, held in locked memory and wiped on drop.
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Draws a fresh private key from the operating system RNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn generate() -> Result<Self, Error> {
        SecretKey::random().map(Self)
    }

    /// The public key matching this private key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::x25519(
            *self.0.expose_secret(),
            X25519_BASEPOINT_BYTES,
        ))
    }

    /// The shared secret with `peer`.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if `peer` is a low-order point, which would
    /// make the shared secret all zero whatever this private key is.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> Result<SecretKey, Error> {
        let shared = Zeroizing::new(x25519_dalek::x25519(*self.0.expose_secret(), peer.0));
        if bool::from(shared.ct_eq(&[0; PUBLIC_KEY_LEN])) {
            return Err(Error::InvalidPublicKey);
        }
        Ok(SecretKey::from_array(&shared))
    }
}

impl From<SecretKey> for PrivateKey {
    fn from(key: SecretKey) -> Self {
        Self(key)
    }
}

/// An X25519 public key: the Montgomery u-coordinate, as sent on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    /// A public key received from a peer. Every 32-byte string is a valid
    /// encoding; low-order points are refused by [`PrivateKey::diffie_hellman`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The public key bytes, for sending.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
}
