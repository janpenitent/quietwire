// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-CRY-005`: XChaCha20-Poly1305 against the Wycheproof vectors.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::{
    aead::{open, seal, Nonce},
    Error, SecretKey,
};
use serde::Deserialize;
use support::{hex, load_fixture};

const NONCE_BITS: u32 = 192;

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "testGroups")]
    groups: Vec<VectorGroup>,
}

#[derive(Deserialize)]
struct VectorGroup {
    #[serde(rename = "ivSize")]
    nonce_bits: u32,
    tests: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "tcId")]
    id: u32,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

impl Vector {
    fn key(&self) -> SecretKey {
        SecretKey::from_slice(&hex(&self.key)).expect("32-byte key")
    }

    fn nonce(&self) -> Nonce {
        let bytes: [u8; 24] = hex(&self.iv).try_into().expect("24-byte nonce");
        Nonce::from_bytes(bytes)
    }

    fn sealed(&self) -> Vec<u8> {
        [hex(&self.ct), hex(&self.tag)].concat()
    }

    fn open(&self) -> Result<Vec<u8>, Error> {
        open(&self.key(), &self.nonce(), &hex(&self.aad), &self.sealed())
            .map(|plaintext| plaintext.to_vec())
    }
}

fn groups() -> Vec<VectorGroup> {
    let file: VectorFile = load_fixture("wycheproof/xchacha20_poly1305_test.json");
    file.groups
}

fn full_nonce_vectors_with_result(result: &str) -> Vec<Vector> {
    groups()
        .into_iter()
        .filter(|group| group.nonce_bits == NONCE_BITS)
        .flat_map(|group| group.tests)
        .filter(|vector| vector.result == result)
        .collect()
}

#[test]
fn qw_u_cry_005_seal_matches_every_valid_wycheproof_vector() {
    let valid = full_nonce_vectors_with_result("valid");
    assert_eq!(valid.len(), 246);

    for vector in valid {
        let sealed = seal(
            &vector.key(),
            &vector.nonce(),
            &hex(&vector.aad),
            &hex(&vector.msg),
        )
        .unwrap_or_else(|error| panic!("tcId {}: {error}", vector.id));

        assert_eq!(sealed, vector.sealed(), "tcId {}", vector.id);
    }
}

#[test]
fn qw_u_cry_005_open_recovers_every_valid_wycheproof_vector() {
    for vector in full_nonce_vectors_with_result("valid") {
        let plaintext = vector
            .open()
            .unwrap_or_else(|error| panic!("tcId {}: {error}", vector.id));

        assert_eq!(plaintext, hex(&vector.msg), "tcId {}", vector.id);
    }
}

#[test]
fn qw_u_cry_005_open_rejects_every_invalid_wycheproof_vector() {
    let invalid = full_nonce_vectors_with_result("invalid");
    assert_eq!(invalid.len(), 60);

    for vector in invalid {
        assert!(
            matches!(vector.open(), Err(Error::Authentication)),
            "tcId {}",
            vector.id
        );
    }
}

#[test]
fn qw_u_cry_005_other_nonce_sizes_are_all_invalid_and_unrepresentable() {
    let short_or_long: Vec<Vector> = groups()
        .into_iter()
        .filter(|group| group.nonce_bits != NONCE_BITS)
        .flat_map(|group| group.tests)
        .collect();
    assert_eq!(short_or_long.len(), 9);

    for vector in short_or_long {
        assert_eq!(vector.result, "invalid", "tcId {}", vector.id);
        assert!(
            <[u8; 24]>::try_from(hex(&vector.iv)).is_err(),
            "tcId {}",
            vector.id
        );
    }
}
