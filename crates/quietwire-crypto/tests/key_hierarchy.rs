// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! The at-rest key hierarchy of PROTOCOL.md §5.7: DEK wrapping under the KEK
//! and the per-purpose subkeys derived from the DEK.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;

use quietwire_crypto::{
    aead::{open, Nonce},
    hierarchy::{Dek, Kek, Purpose, WrappedDek, WRAPPED_DEK_LEN},
    Error, SecretKey,
};
use serde::Deserialize;
use support::{hex_array, load_fixture};

const WRAP_AAD: &[u8] = b"QUIETWIRE-DEK-WRAP-v1";
const NONCE_LEN: usize = 24;

const PURPOSES: [Purpose; 5] = [
    Purpose::Db,
    Purpose::Field,
    Purpose::Identity,
    Purpose::Sessions,
    Purpose::Meta,
];

fn counting_bytes(first: u8) -> [u8; 32] {
    std::array::from_fn(|i| first + u8::try_from(i).expect("below 32"))
}

fn key_from(bytes: [u8; 32]) -> SecretKey {
    SecretKey::from_slice(&bytes).expect("32 bytes")
}

fn random_kek() -> Kek {
    Kek::from(SecretKey::random().expect("RNG available"))
}

fn assert_same_dek(left: &Dek, right: &Dek) {
    for purpose in PURPOSES {
        assert!(
            left.subkey(purpose).unwrap() == right.subkey(purpose).unwrap(),
            "{purpose:?}"
        );
    }
}

#[test]
fn wrapped_dek_unwraps_to_the_same_dek_under_the_same_kek() {
    let kek = random_kek();
    let dek = Dek::generate().unwrap();

    let unwrapped = dek.wrap_with(&kek).unwrap().unwrap_with(&kek).unwrap();

    assert_same_dek(&dek, &unwrapped);
}

#[test]
fn wrapped_dek_does_not_unwrap_under_another_kek() {
    let wrapped = Dek::generate().unwrap().wrap_with(&random_kek()).unwrap();

    assert!(matches!(
        wrapped.unwrap_with(&random_kek()),
        Err(Error::Authentication)
    ));
}

#[test]
fn wrapped_dek_rejects_a_flipped_bit_in_every_byte() {
    let kek = random_kek();
    let bytes = Dek::generate().unwrap().wrap_with(&kek).unwrap().to_bytes();

    for index in 0..WRAPPED_DEK_LEN {
        let mut tampered = bytes;
        tampered[index] ^= 0x01;

        assert!(
            matches!(
                WrappedDek::from_bytes(tampered).unwrap_with(&kek),
                Err(Error::Authentication)
            ),
            "byte {index}"
        );
    }
}

#[test]
fn wrapped_dek_survives_a_byte_round_trip() {
    let kek = random_kek();
    let dek = Dek::generate().unwrap();
    let bytes = dek.wrap_with(&kek).unwrap().to_bytes();

    let unwrapped = WrappedDek::from_bytes(bytes).unwrap_with(&kek).unwrap();

    assert_eq!(bytes.len(), 72);
    assert_same_dek(&dek, &unwrapped);
}

#[test]
fn wrapping_twice_uses_fresh_nonces() {
    let kek = random_kek();
    let dek = Dek::generate().unwrap();

    let first = dek.wrap_with(&kek).unwrap().to_bytes();
    let second = dek.wrap_with(&kek).unwrap().to_bytes();

    assert_ne!(first[..NONCE_LEN], second[..NONCE_LEN]);
}

#[test]
fn wrapped_dek_is_nonce_then_xchacha20_poly1305_sealed_under_the_wrap_label() {
    let kek_bytes = counting_bytes(100);
    let dek_bytes = counting_bytes(0);
    let bytes = Dek::from(key_from(dek_bytes))
        .wrap_with(&Kek::from(key_from(kek_bytes)))
        .unwrap()
        .to_bytes();
    let nonce = Nonce::from_bytes(bytes[..NONCE_LEN].try_into().unwrap());
    let sealed = &bytes[NONCE_LEN..];

    let opened = open(&key_from(kek_bytes), &nonce, WRAP_AAD, sealed).unwrap();

    assert_eq!(*opened, dek_bytes);
    assert!(open(&key_from(kek_bytes), &nonce, b"", sealed).is_err());
}

#[test]
fn every_purpose_derives_a_distinct_subkey() {
    let dek = Dek::generate().unwrap();
    let subkeys: Vec<SecretKey> = PURPOSES.map(|p| dek.subkey(p).unwrap()).into();

    for (i, left) in subkeys.iter().enumerate() {
        for right in &subkeys[i + 1..] {
            assert!(left != right);
        }
    }
}

#[derive(Deserialize)]
struct SubkeyVector {
    dek: String,
    subkeys: BTreeMap<String, String>,
}

#[test]
fn subkeys_are_hkdf_sha512_with_the_versioned_purpose_label() {
    let vector: SubkeyVector = load_fixture("derived/dek_subkeys.json");
    let dek = Dek::from(key_from(hex_array(&vector.dek)));
    let labels = ["db", "field", "identity", "sessions", "meta"];

    assert_eq!(vector.subkeys.len(), PURPOSES.len());
    for (purpose, label) in PURPOSES.into_iter().zip(labels) {
        assert_eq!(
            dek.subkey(purpose).unwrap().expose_secret(),
            &hex_array::<32>(&vector.subkeys[label]),
            "{purpose:?}"
        );
    }
}
