// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-CRY-003` and `QW-U-CRY-004`: Ed25519 against RFC 8032, Wycheproof
//! and the edge cases of Chalkias et al., *Taming the many `EdDSAs`*.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::{
    ed25519::{Signature, SigningKey, VerifyingKey},
    Error, SecretKey,
};
use serde::Deserialize;
use support::{hex, load_fixture};

const ONLY_CASE_A_STRICT_VERIFIER_ACCEPTS: usize = 3;

#[derive(Deserialize)]
struct Rfc8032Vector {
    name: String,
    secret_key: String,
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Deserialize)]
struct WycheproofFile {
    #[serde(rename = "testGroups")]
    groups: Vec<WycheproofGroup>,
}

#[derive(Deserialize)]
struct WycheproofGroup {
    #[serde(rename = "publicKey")]
    public_key: WycheproofKey,
    tests: Vec<WycheproofVector>,
}

#[derive(Deserialize)]
struct WycheproofKey {
    pk: String,
}

#[derive(Deserialize)]
struct WycheproofVector {
    #[serde(rename = "tcId")]
    id: u32,
    msg: String,
    sig: String,
    result: String,
}

#[derive(Deserialize)]
struct SpeccheckCase {
    message: String,
    pub_key: String,
    signature: String,
}

fn verifies(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (
        <[u8; 32]>::try_from(public_key),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    VerifyingKey::from_bytes(&public_key).is_ok_and(|key| {
        key.verify(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

#[test]
fn qw_u_cry_003_signing_and_verifying_match_rfc_8032_section_7_1() {
    let vectors: Vec<Rfc8032Vector> = load_fixture("rfc8032/ed25519.json");
    assert_eq!(vectors.len(), 5);

    for vector in vectors {
        let key = SigningKey::from(SecretKey::from_slice(&hex(&vector.secret_key)).unwrap());
        let message = hex(&vector.message);

        let signature = key.sign(&message);

        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            hex(&vector.public_key),
            "{}",
            vector.name
        );
        assert_eq!(
            signature.as_bytes().to_vec(),
            hex(&vector.signature),
            "{}",
            vector.name
        );
        assert!(
            key.verifying_key().verify(&message, &signature).is_ok(),
            "{}",
            vector.name
        );
    }
}

#[test]
fn qw_u_cry_004_verification_matches_every_wycheproof_verdict() {
    let file: WycheproofFile = load_fixture("wycheproof/ed25519_test.json");
    let vectors: Vec<(String, WycheproofVector)> = file
        .groups
        .into_iter()
        .flat_map(|group| {
            let public_key = group.public_key.pk;
            group
                .tests
                .into_iter()
                .map(move |vector| (public_key.clone(), vector))
        })
        .collect();
    assert_eq!(vectors.len(), 151);

    for (public_key, vector) in vectors {
        let accepted = verifies(&hex(&public_key), &hex(&vector.msg), &hex(&vector.sig));

        assert_eq!(accepted, vector.result == "valid", "tcId {}", vector.id);
    }
}

#[test]
fn qw_u_cry_004_only_the_canonical_edge_case_passes_strict_verification() {
    let cases: Vec<SpeccheckCase> = load_fixture("speccheck/cases.json");
    assert_eq!(cases.len(), 12);

    for (index, case) in cases.iter().enumerate() {
        let accepted = verifies(
            &hex(&case.pub_key),
            &hex(&case.message),
            &hex(&case.signature),
        );

        assert_eq!(
            accepted,
            index == ONLY_CASE_A_STRICT_VERIFIER_ACCEPTS,
            "case {index}"
        );
    }
}

#[test]
fn a_tampered_message_fails_verification() {
    let key = SigningKey::generate().unwrap();
    let signature = key.sign(b"attack at dawn");

    let result = key.verifying_key().verify(b"attack at dusk", &signature);

    assert_eq!(result, Err(Error::InvalidSignature));
}

#[test]
fn some_encodings_are_not_curve_points_and_are_rejected() {
    let rejected = (0..=u8::MAX).filter(|&y| {
        let mut encoding = [0; 32];
        encoding[0] = y;
        VerifyingKey::from_bytes(&encoding) == Err(Error::InvalidPublicKey)
    });

    assert!(rejected.count() > 0);
}

#[test]
fn verifying_key_and_signature_round_trip_through_their_bytes() {
    let key = SigningKey::generate().unwrap();
    let signature = key.sign(b"round trip");

    let verifying_key = VerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    let signature = Signature::from_bytes(*signature.as_bytes());

    assert!(verifying_key.verify(b"round trip", &signature).is_ok());
}
