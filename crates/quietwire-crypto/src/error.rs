// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Why a cryptographic operation did not produce a result.
///
/// Deliberately coarse: callers never learn more about a failed decryption
/// than that it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An input or requested output had a length the operation does not accept.
    InvalidLength,
    /// Sealed data did not authenticate under the given key, nonce and associated data.
    Authentication,
    /// The operating system random number generator failed.
    Rng,
    /// The password KDF rejected its parameters or could not allocate its memory.
    Kdf,
    /// A peer public key was malformed, or would force a predictable shared secret.
    InvalidPublicKey,
    /// A signature did not verify under the given key and message.
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid length",
            Self::Authentication => "authentication failed",
            Self::Rng => "random number generator unavailable",
            Self::Kdf => "password key derivation failed",
            Self::InvalidPublicKey => "invalid public key",
            Self::InvalidSignature => "invalid signature",
        })
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_has_its_own_non_empty_message() {
        let messages = [
            Error::InvalidLength,
            Error::Authentication,
            Error::Rng,
            Error::Kdf,
            Error::InvalidPublicKey,
            Error::InvalidSignature,
        ]
        .map(|error| error.to_string());

        for (i, message) in messages.iter().enumerate() {
            assert!(!message.is_empty());
            assert!(!messages[i + 1..].contains(message), "{message}");
        }
    }
}
