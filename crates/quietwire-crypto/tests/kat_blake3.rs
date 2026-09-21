// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-CRY-007`: BLAKE3 keyed hash and key derivation against the official
//! vectors.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::{
    hash::{derive_key, keyed_hash},
    SecretKey,
};
use serde::Deserialize;
use support::{hex, load_fixture};

const VECTOR_CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";
const INPUT_PATTERN_PERIOD: usize = 251;
const OUTPUT_LEN: usize = 32;

#[derive(Deserialize)]
struct VectorFile {
    key: String,
    context_string: String,
    cases: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    input_len: usize,
    keyed_hash: String,
    derive_key: String,
}

fn vector_file() -> VectorFile {
    load_fixture("blake3/test_vectors.json")
}

fn input_of_len(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % INPUT_PATTERN_PERIOD).expect("below 251"))
        .collect()
}

fn first_output_bytes(extended_output_hex: &str) -> Vec<u8> {
    hex(extended_output_hex)[..OUTPUT_LEN].to_vec()
}

#[test]
fn qw_u_cry_007_keyed_hash_matches_every_official_vector() {
    let file = vector_file();
    let key = SecretKey::from_slice(file.key.as_bytes()).expect("32-byte key");
    assert_eq!(file.cases.len(), 35);

    for vector in &file.cases {
        let digest = keyed_hash(&key, &input_of_len(vector.input_len));

        assert_eq!(
            digest.to_vec(),
            first_output_bytes(&vector.keyed_hash),
            "input_len {}",
            vector.input_len
        );
    }
}

#[test]
fn qw_u_cry_007_derive_key_matches_every_official_vector() {
    let file = vector_file();
    assert_eq!(file.context_string, VECTOR_CONTEXT);

    for vector in &file.cases {
        let derived = derive_key(VECTOR_CONTEXT, &input_of_len(vector.input_len));

        assert_eq!(
            derived.to_vec(),
            first_output_bytes(&vector.derive_key),
            "input_len {}",
            vector.input_len
        );
    }
}
