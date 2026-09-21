// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! XChaCha20-Poly1305 authenticated encryption.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305,
};
use zeroize::Zeroizing;

use crate::{rng, Error, SecretKey};

/// Length of a [`Nonce`] in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of the Poly1305 tag appended to every sealed message.
pub const TAG_LEN: usize = 16;

/// A 192-bit nonce, long enough to be drawn at random for every message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Draws a fresh nonce from the operating system RNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn random() -> Result<Self, Error> {
        let mut bytes = [0; NONCE_LEN];
        rng::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// A nonce read back from storage or the wire.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// The nonce bytes, for storage or the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// Encrypts `plaintext` and authenticates it together with `aad`.
///
/// Returns the ciphertext followed by the tag.
///
/// # Errors
/// [`Error::InvalidLength`] if `plaintext` is beyond the cipher's limit.
pub fn seal(
    key: &SecretKey,
    nonce: &Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    cipher(key)
        .encrypt(
            nonce.as_bytes().into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::InvalidLength)
}

/// Authenticates `sealed` (ciphertext followed by tag) with `aad`, then decrypts it.
///
/// # Errors
/// [`Error::Authentication`] if anything differs from what was sealed.
pub fn open(
    key: &SecretKey,
    nonce: &Nonce,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    cipher(key)
        .decrypt(nonce.as_bytes().into(), Payload { msg: sealed, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

fn cipher(key: &SecretKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.expose_secret().into())
}
