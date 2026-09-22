// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-768 key encapsulation (FIPS 203).

use ml_kem::{ml_kem_768, Decapsulate, KeyExport, B32};
use zeroize::Zeroizing;

use crate::{rng, stack, Error, SecretKey};

/// Length of an [`EncapsulationKey`] in bytes.
pub const ENCAPSULATION_KEY_LEN: usize = 1184;
/// Length of a [`Ciphertext`] in bytes.
pub const CIPHERTEXT_LEN: usize = 1088;

const SEED_HALF_LEN: usize = 32;

/// An ML-KEM-768 decapsulation key, kept as its FIPS 203 seed `(d, z)` in
/// locked memory and wiped on drop.
pub struct DecapsulationKey {
    d: SecretKey,
    z: SecretKey,
}

impl DecapsulationKey {
    /// Draws a fresh seed from the operating system RNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_seed(SecretKey::random()?, SecretKey::random()?))
    }

    /// The key FIPS 203 `ML-KEM.KeyGen_internal` derives from `d` and `z`.
    #[must_use]
    pub fn from_seed(d: SecretKey, z: SecretKey) -> Self {
        Self { d, z }
    }

    /// The public key matching this key.
    #[must_use]
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        stack::scrubbed(|| EncapsulationKey(self.expand().encapsulation_key().clone()))
    }

    /// The shared key sent in `ciphertext`. A ciphertext that was not produced
    /// for this key yields an unrelated key (implicit rejection), never an error.
    #[must_use]
    pub fn decapsulate(&self, ciphertext: &Ciphertext) -> SecretKey {
        stack::scrubbed(|| decapsulate_with(&self.expand(), ciphertext))
    }

    /// The expanded key is rebuilt per operation so that only the 64-byte
    /// seed stays resident, in locked memory.
    fn expand(&self) -> ml_kem_768::DecapsulationKey {
        let mut seed = Zeroizing::new(ml_kem::Seed::default());
        let (d, z) = seed.split_at_mut(SEED_HALF_LEN);
        d.copy_from_slice(self.d.expose_secret());
        z.copy_from_slice(self.z.expose_secret());
        ml_kem_768::DecapsulationKey::from_seed(*seed)
    }
}

fn decapsulate_with(key: &ml_kem_768::DecapsulationKey, ciphertext: &Ciphertext) -> SecretKey {
    let shared = Zeroizing::new(key.decapsulate(&ciphertext.0.into()));
    SecretKey::from_array(&shared.0)
}

/// An ML-KEM-768 encapsulation key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapsulationKey(ml_kem_768::EncapsulationKey);

impl EncapsulationKey {
    /// Parses a public key received from a peer.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if it fails the FIPS 203 modulus check.
    pub fn from_bytes(bytes: &[u8; ENCAPSULATION_KEY_LEN]) -> Result<Self, Error> {
        ml_kem_768::EncapsulationKey::new(&(*bytes).into())
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    /// The public key bytes, for sending.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ENCAPSULATION_KEY_LEN] {
        self.0.to_bytes().into()
    }

    /// A fresh shared key and the ciphertext that carries it to the holder of
    /// the matching [`DecapsulationKey`].
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn encapsulate(&self) -> Result<(Ciphertext, SecretKey), Error> {
        let mut randomness = Zeroizing::new(B32::default());
        rng::fill(&mut randomness)?;
        Ok(stack::scrubbed(|| self.encapsulate_with(&randomness)))
    }

    fn encapsulate_with(&self, randomness: &B32) -> (Ciphertext, SecretKey) {
        let (ciphertext, shared) = self.0.encapsulate_deterministic(randomness);
        let shared = Zeroizing::new(shared);
        (
            Ciphertext(ciphertext.into()),
            SecretKey::from_array(&shared.0),
        )
    }
}

/// An ML-KEM-768 ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext([u8; CIPHERTEXT_LEN]);

impl Ciphertext {
    /// A ciphertext received from a peer. Every byte string of this length is
    /// accepted; see [`DecapsulationKey::decapsulate`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CIPHERTEXT_LEN]) -> Self {
        Self(bytes)
    }

    /// The ciphertext bytes, for sending.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CIPHERTEXT_LEN] {
        &self.0
    }
}

/// `QW-U-CRY-009`: the ACVP vectors that fix the encapsulation randomness or
/// give only the expanded decapsulation key, which the public API never takes.
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::support::{hex, hex_array, load_fixture};
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    use serde::Deserialize;

    use super::*;

    const ML_KEM_768: &str = "ML-KEM-768";

    #[derive(Deserialize)]
    struct AcvpFile {
        #[serde(rename = "testGroups")]
        groups: Vec<AcvpGroup>,
    }

    #[derive(Deserialize)]
    struct AcvpGroup {
        #[serde(rename = "parameterSet")]
        parameter_set: String,
        #[serde(default)]
        function: String,
        tests: Vec<AcvpVector>,
    }

    #[derive(Deserialize)]
    struct AcvpVector {
        #[serde(rename = "tcId")]
        id: u32,
        #[serde(default)]
        d: String,
        #[serde(default)]
        z: String,
        #[serde(default)]
        ek: String,
        #[serde(default)]
        dk: String,
        #[serde(default)]
        c: String,
        #[serde(default)]
        k: String,
        #[serde(default)]
        m: String,
    }

    fn ml_kem_768_vectors(fixture: &str, function: &str) -> Vec<AcvpVector> {
        let file: AcvpFile = load_fixture(fixture);
        file.groups
            .into_iter()
            .filter(|group| group.parameter_set == ML_KEM_768 && group.function == function)
            .flat_map(|group| group.tests)
            .collect()
    }

    fn secret(encoded: &str) -> SecretKey {
        SecretKey::from_slice(&hex(encoded)).unwrap()
    }

    #[test]
    #[allow(deprecated)]
    fn key_generation_matches_every_acvp_expanded_decapsulation_key() {
        let vectors = ml_kem_768_vectors("acvp/ml_kem_key_gen.json", "");
        assert_eq!(vectors.len(), 25);

        for vector in vectors {
            let key = DecapsulationKey::from_seed(secret(&vector.d), secret(&vector.z));

            assert_eq!(
                key.expand().to_expanded_bytes().to_vec(),
                hex(&vector.dk),
                "tcId {}",
                vector.id
            );
        }
    }

    #[test]
    fn encapsulation_matches_every_acvp_vector() {
        let vectors = ml_kem_768_vectors("acvp/ml_kem_encap_decap.json", "encapsulation");
        assert_eq!(vectors.len(), 25);

        for vector in vectors {
            let key = EncapsulationKey::from_bytes(&hex_array(&vector.ek)).unwrap();

            let (ciphertext, shared) = key.encapsulate_with(&hex_array::<32>(&vector.m).into());

            assert_eq!(
                ciphertext.as_bytes().to_vec(),
                hex(&vector.c),
                "tcId {}",
                vector.id
            );
            assert_eq!(
                shared.expose_secret().to_vec(),
                hex(&vector.k),
                "tcId {}",
                vector.id
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn decapsulation_matches_every_acvp_vector() {
        let vectors = ml_kem_768_vectors("acvp/ml_kem_encap_decap.json", "decapsulation");
        assert_eq!(vectors.len(), 10);

        for vector in vectors {
            let key =
                ml_kem_768::DecapsulationKey::from_expanded(&hex_array(&vector.dk).into()).unwrap();

            let shared = decapsulate_with(&key, &Ciphertext::from_bytes(hex_array(&vector.c)));

            assert_eq!(
                shared.expose_secret().to_vec(),
                hex(&vector.k),
                "tcId {}",
                vector.id
            );
        }
    }
}
