// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Argon2id password key derivation (RFC 9106), producing the [`Kek`].

use argon2::{Algorithm, Argon2, Params, Version};

use crate::{hierarchy::Kek, rng, secret::KEY_LEN, Error, SecretKey};

/// Length of a [`Salt`] in bytes.
pub const SALT_LEN: usize = 32;

/// Argon2id cost parameters. Only the profiles of PROTOCOL.md §5.7 exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfParams {
    /// 256 MiB, 4 passes, 2 lanes.
    pub const MOBILE: Self = Self {
        memory_kib: 262_144,
        iterations: 4,
        parallelism: 2,
    };

    /// 1 GiB, 4 passes, 2 lanes.
    pub const DESKTOP: Self = Self {
        memory_kib: 1_048_576,
        iterations: 4,
        parallelism: 2,
    };

    /// Memory cost in KiB.
    #[must_use]
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Number of passes over memory.
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Number of lanes.
    #[must_use]
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }
}

/// A per-installation random salt, stored next to the wrapped DEK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    /// Draws a fresh salt from the operating system RNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn random() -> Result<Self, Error> {
        let mut bytes = [0; SALT_LEN];
        rng::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// A salt read back from storage.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// The salt bytes, for storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

/// Argon2id v1.3 of `password` and `salt` into a 32-byte [`Kek`].
///
/// # Errors
/// [`Error::Kdf`] if the parameters are rejected or memory cannot be allocated.
pub fn derive_kek(password: &[u8], salt: &Salt, params: &KdfParams) -> Result<Kek, Error> {
    argon2id(password, salt, params).map(Kek::from)
}

fn argon2id(password: &[u8], salt: &Salt, params: &KdfParams) -> Result<SecretKey, Error> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Kdf)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    SecretKey::build_in_place(|key| {
        argon2
            .hash_password_into(password, salt.as_bytes(), key)
            .map_err(|_| Error::Kdf)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fmt::Write;

    use super::*;

    impl KdfParams {
        const fn custom(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
            Self {
                memory_kib,
                iterations,
                parallelism,
            }
        }
    }

    #[derive(serde::Deserialize)]
    struct ReferenceVector {
        password: String,
        salt: String,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        tag: String,
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").unwrap();
            out
        })
    }

    fn unhex(encoded: &str) -> Vec<u8> {
        (0..encoded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn argon2id_matches_reference_implementation_vectors() {
        let vectors: Vec<ReferenceVector> =
            serde_json::from_str(include_str!("../tests/fixtures/derived/argon2id_kek.json"))
                .unwrap();

        assert!(!vectors.is_empty());
        for vector in vectors {
            let salt = Salt::from_bytes(unhex(&vector.salt).try_into().unwrap());
            let params =
                KdfParams::custom(vector.memory_kib, vector.iterations, vector.parallelism);

            let key = argon2id(&unhex(&vector.password), &salt, &params).unwrap();

            assert_eq!(hex(key.expose_secret()), vector.tag);
        }
    }

    #[test]
    fn derive_kek_rejects_memory_below_eight_kib_per_lane() {
        let salt = Salt::from_bytes([0; SALT_LEN]);

        let result = derive_kek(b"pw", &salt, &KdfParams::custom(8, 1, 2));

        assert!(matches!(result, Err(Error::Kdf)));
    }
}
