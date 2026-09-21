// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-CRY-009` and `QW-U-CRY-010`: ML-KEM-768 against the NIST ACVP
//! vectors of FIPS 203, through the public API.
//!
//! Encapsulation and decapsulation vectors fix the encapsulation randomness or
//! give the expanded decapsulation key, neither of which the public API takes;
//! the unit tests of `mlkem` run those.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::{
    mlkem::{Ciphertext, DecapsulationKey, EncapsulationKey, CIPHERTEXT_LEN},
    SecretKey,
};
use serde::{de::DeserializeOwned, Deserialize};
use support::{hex, hex_array, load_fixture};

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
    tests: serde_json::Value,
}

#[derive(Deserialize)]
struct KeyGenVector {
    #[serde(rename = "tcId")]
    id: u32,
    d: String,
    z: String,
    ek: String,
}

#[derive(Deserialize)]
struct KeyCheckVector {
    #[serde(rename = "tcId")]
    id: u32,
    #[serde(rename = "testPassed")]
    passed: bool,
    ek: String,
}

fn ml_kem_768_tests<T: DeserializeOwned>(fixture: &str, function: &str) -> Vec<T> {
    let file: AcvpFile = load_fixture(fixture);
    file.groups
        .into_iter()
        .filter(|group| group.parameter_set == ML_KEM_768 && group.function == function)
        .flat_map(|group| serde_json::from_value::<Vec<T>>(group.tests).unwrap())
        .collect()
}

fn secret(encoded: &str) -> SecretKey {
    SecretKey::from_slice(&hex(encoded)).unwrap()
}

#[test]
fn qw_u_cry_009_key_generation_matches_every_acvp_vector() {
    let vectors: Vec<KeyGenVector> = ml_kem_768_tests("acvp/ml_kem_key_gen.json", "");
    assert_eq!(vectors.len(), 25);

    for vector in vectors {
        let key = DecapsulationKey::from_seed(secret(&vector.d), secret(&vector.z));

        assert_eq!(
            key.encapsulation_key().to_bytes().to_vec(),
            hex(&vector.ek),
            "tcId {}",
            vector.id
        );
    }
}

#[test]
fn qw_u_cry_009_encapsulation_key_check_matches_every_acvp_verdict() {
    let vectors: Vec<KeyCheckVector> =
        ml_kem_768_tests("acvp/ml_kem_encap_decap.json", "encapsulationKeyCheck");
    assert_eq!(vectors.len(), 10);

    for vector in vectors {
        let accepted = EncapsulationKey::from_bytes(&hex_array(&vector.ek)).is_ok();

        assert_eq!(accepted, vector.passed, "tcId {}", vector.id);
    }
}

#[test]
fn qw_u_cry_009_both_sides_agree_on_the_shared_key() {
    let key = DecapsulationKey::generate().unwrap();

    let (ciphertext, sent) = key.encapsulation_key().encapsulate().unwrap();
    let received = key.decapsulate(&ciphertext);

    assert!(sent == received);
}

#[test]
fn qw_u_cry_009_encapsulation_key_round_trips_through_its_bytes() {
    let key = DecapsulationKey::generate().unwrap().encapsulation_key();

    let parsed = EncapsulationKey::from_bytes(&key.to_bytes()).unwrap();

    assert_eq!(parsed.to_bytes(), key.to_bytes());
}

#[test]
fn qw_u_cry_010_a_malformed_ciphertext_yields_the_implicit_rejection_key() {
    let key = DecapsulationKey::generate().unwrap();
    let (ciphertext, sent) = key.encapsulation_key().encapsulate().unwrap();
    let mut malformed = *ciphertext.as_bytes();
    malformed[0] ^= 1;
    let malformed = Ciphertext::from_bytes(malformed);

    let rejected = key.decapsulate(&malformed);

    assert!(rejected != sent);
    assert!(rejected == key.decapsulate(&malformed));
}

#[test]
fn qw_u_cry_010_the_rejection_key_depends_on_the_decapsulation_key() {
    let zero = Ciphertext::from_bytes([0; CIPHERTEXT_LEN]);

    let alice = DecapsulationKey::generate().unwrap().decapsulate(&zero);
    let bob = DecapsulationKey::generate().unwrap().decapsulate(&zero);

    assert!(alice != bob);
}
