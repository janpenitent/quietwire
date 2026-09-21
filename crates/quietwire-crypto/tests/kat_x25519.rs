// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-CRY-001` and `QW-U-CRY-002`: X25519 against RFC 7748, Wycheproof and
//! the small-order points libsodium blocks.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::{
    x25519::{PrivateKey, PublicKey},
    Error, SecretKey,
};
use serde::Deserialize;
use support::{hex, hex_array, load_fixture};

const HIGH_BIT: u8 = 0x80;

#[derive(Deserialize)]
struct Rfc7748 {
    function_vectors: Vec<FunctionVector>,
    iterated: Iterated,
    diffie_hellman: DiffieHellman,
}

#[derive(Deserialize)]
struct FunctionVector {
    scalar: String,
    u: String,
    output: String,
}

#[derive(Deserialize)]
struct Iterated {
    start: String,
    after_1: String,
    after_1000: String,
    after_1000000: String,
}

#[derive(Deserialize)]
struct DiffieHellman {
    alice_private: String,
    alice_public: String,
    bob_private: String,
    bob_public: String,
    shared_secret: String,
}

#[derive(Deserialize)]
struct SmallOrderPoint {
    comment: String,
    u: String,
}

#[derive(Deserialize)]
struct WycheproofFile {
    #[serde(rename = "testGroups")]
    groups: Vec<WycheproofGroup>,
}

#[derive(Deserialize)]
struct WycheproofGroup {
    tests: Vec<WycheproofVector>,
}

#[derive(Deserialize)]
struct WycheproofVector {
    #[serde(rename = "tcId")]
    id: u32,
    flags: Vec<String>,
    public: String,
    private: String,
    shared: String,
    result: String,
}

fn rfc7748() -> Rfc7748 {
    load_fixture("rfc7748/x25519.json")
}

fn private_key(encoded: &str) -> PrivateKey {
    PrivateKey::from(SecretKey::from_slice(&hex(encoded)).expect("32-byte scalar"))
}

fn public_key(encoded: &str) -> PublicKey {
    PublicKey::from_bytes(hex_array(encoded))
}

fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> Result<[u8; 32], Error> {
    let private = PrivateKey::from(SecretKey::from_slice(scalar).unwrap());
    private
        .diffie_hellman(&PublicKey::from_bytes(*u))
        .map(|shared| *shared.expose_secret())
}

fn iterate(start: &str, iterations: u32) -> [u8; 32] {
    let mut k: [u8; 32] = hex_array(start);
    let mut u = k;
    for _ in 0..iterations {
        let output = x25519(&k, &u).unwrap();
        u = k;
        k = output;
    }
    k
}

#[test]
fn qw_u_cry_001_diffie_hellman_matches_the_rfc_7748_function_vectors() {
    let vectors = rfc7748().function_vectors;
    assert_eq!(vectors.len(), 2);

    for vector in vectors {
        let shared = private_key(&vector.scalar)
            .diffie_hellman(&public_key(&vector.u))
            .unwrap();

        assert_eq!(shared.expose_secret().to_vec(), hex(&vector.output));
    }
}

#[test]
fn qw_u_cry_001_one_iteration_matches_rfc_7748() {
    let iterated = rfc7748().iterated;

    assert_eq!(iterate(&iterated.start, 1).to_vec(), hex(&iterated.after_1));
}

#[test]
fn qw_u_cry_001_a_thousand_iterations_match_rfc_7748() {
    let iterated = rfc7748().iterated;

    assert_eq!(
        iterate(&iterated.start, 1000).to_vec(),
        hex(&iterated.after_1000)
    );
}

#[test]
#[ignore = "about a minute; run by the nightly workflow"]
fn qw_u_cry_001_a_million_iterations_match_rfc_7748() {
    let iterated = rfc7748().iterated;

    assert_eq!(
        iterate(&iterated.start, 1_000_000).to_vec(),
        hex(&iterated.after_1000000)
    );
}

#[test]
fn qw_u_cry_002_public_keys_and_shared_secret_match_rfc_7748_section_6_1() {
    let vector = rfc7748().diffie_hellman;
    let alice = private_key(&vector.alice_private);
    let bob = private_key(&vector.bob_private);

    assert_eq!(alice.public_key(), public_key(&vector.alice_public));
    assert_eq!(bob.public_key(), public_key(&vector.bob_public));
    for shared in [
        alice.diffie_hellman(&bob.public_key()).unwrap(),
        bob.diffie_hellman(&alice.public_key()).unwrap(),
    ] {
        assert_eq!(shared.expose_secret().to_vec(), hex(&vector.shared_secret));
    }
}

#[test]
fn qw_u_cry_002_every_small_order_point_is_rejected_with_and_without_the_high_bit() {
    let points: Vec<SmallOrderPoint> = load_fixture("libsodium/x25519_small_order.json");
    assert_eq!(points.len(), 7);
    let alice = PrivateKey::generate().unwrap();

    for point in points {
        let u: [u8; 32] = hex_array(&point.u);
        let mut high_bit_set = u;
        high_bit_set[31] |= HIGH_BIT;

        for bytes in [u, high_bit_set] {
            assert!(
                matches!(
                    alice.diffie_hellman(&PublicKey::from_bytes(bytes)),
                    Err(Error::InvalidPublicKey)
                ),
                "{}",
                point.comment
            );
        }
    }
}

fn wycheproof_vectors() -> Vec<WycheproofVector> {
    let file: WycheproofFile = load_fixture("wycheproof/x25519_test.json");
    file.groups
        .into_iter()
        .flat_map(|group| group.tests)
        .collect()
}

#[test]
fn qw_u_cry_002_diffie_hellman_matches_wycheproof_and_rejects_every_zero_secret() {
    let vectors = wycheproof_vectors();
    assert_eq!(vectors.len(), 518);

    let mut zero_secrets = 0;
    for vector in vectors {
        assert_ne!(vector.result, "invalid", "tcId {}", vector.id);
        let result = x25519(&hex_array(&vector.private), &hex_array(&vector.public));

        if vector.flags.iter().any(|flag| flag == "ZeroSharedSecret") {
            zero_secrets += 1;
            assert_eq!(result, Err(Error::InvalidPublicKey), "tcId {}", vector.id);
        } else {
            let shared = result.unwrap_or_else(|error| panic!("tcId {}: {error}", vector.id));
            assert_eq!(shared.to_vec(), hex(&vector.shared), "tcId {}", vector.id);
        }
    }
    assert!(zero_secrets > 0);
}

#[test]
fn generated_keys_agree_on_a_shared_secret() {
    let alice = PrivateKey::generate().unwrap();
    let bob = PrivateKey::generate().unwrap();

    let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();

    assert!(alice_shared == bob_shared);
}

#[test]
fn public_key_round_trips_through_its_bytes() {
    let public = PrivateKey::generate().unwrap().public_key();

    assert_eq!(PublicKey::from_bytes(*public.as_bytes()), public);
}
