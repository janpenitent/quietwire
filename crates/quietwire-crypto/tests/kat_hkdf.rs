// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-CRY-006`: HKDF-SHA512 against the Wycheproof vectors.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::{kdf::hkdf_sha512, Error};
use serde::Deserialize;
use support::{hex, load_fixture};

const MAXIMUM_OUTPUT_LEN: usize = 255 * 64;

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "testGroups")]
    groups: Vec<VectorGroup>,
}

#[derive(Deserialize)]
struct VectorGroup {
    tests: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "tcId")]
    id: u32,
    ikm: String,
    salt: String,
    info: String,
    size: usize,
    okm: String,
    result: String,
}

impl Vector {
    fn derive(&self) -> Result<Vec<u8>, Error> {
        hkdf_sha512(
            &hex(&self.ikm),
            &hex(&self.salt),
            &hex(&self.info),
            self.size,
        )
        .map(|okm| okm.to_vec())
    }
}

fn vectors_with_result(result: &str) -> Vec<Vector> {
    let file: VectorFile = load_fixture("wycheproof/hkdf_sha512_test.json");
    file.groups
        .into_iter()
        .flat_map(|group| group.tests)
        .filter(|vector| vector.result == result)
        .collect()
}

#[test]
fn qw_u_cry_006_hkdf_sha512_matches_every_valid_wycheproof_vector() {
    let valid = vectors_with_result("valid");
    assert_eq!(valid.len(), 80);

    for vector in valid {
        let okm = vector
            .derive()
            .unwrap_or_else(|error| panic!("tcId {}: {error}", vector.id));

        assert_eq!(okm, hex(&vector.okm), "tcId {}", vector.id);
    }
}

#[test]
fn qw_u_cry_006_hkdf_sha512_rejects_every_invalid_wycheproof_vector() {
    let invalid = vectors_with_result("invalid");
    assert_eq!(invalid.len(), 3);

    for vector in invalid {
        assert!(
            matches!(vector.derive(), Err(Error::InvalidLength)),
            "tcId {}",
            vector.id
        );
    }
}

#[test]
fn qw_u_cry_006_hkdf_sha512_output_limit_is_255_blocks() {
    assert!(hkdf_sha512(b"ikm", b"", b"", MAXIMUM_OUTPUT_LEN).is_ok());
    assert!(matches!(
        hkdf_sha512(b"ikm", b"", b"", MAXIMUM_OUTPUT_LEN + 1),
        Err(Error::InvalidLength)
    ));
}
