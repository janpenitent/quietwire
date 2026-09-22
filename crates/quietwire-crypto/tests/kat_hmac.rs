// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! HMAC-SHA512, the Double Ratchet chain function, against the Wycheproof
//! vectors.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::kdf::hmac_sha512;
use serde::Deserialize;
use support::{hex, load_fixture};

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "testGroups")]
    groups: Vec<VectorGroup>,
}

#[derive(Deserialize)]
struct VectorGroup {
    #[serde(rename = "tagSize")]
    tag_bits: usize,
    tests: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "tcId")]
    id: u32,
    key: String,
    msg: String,
    tag: String,
    result: String,
}

struct Case {
    tag_len: usize,
    vector: Vector,
}

impl Case {
    fn tag_matches(&self) -> bool {
        let tag = hmac_sha512(&hex(&self.vector.key), &hex(&self.vector.msg));
        tag[..self.tag_len] == hex(&self.vector.tag)
    }
}

fn cases_with_result(result: &str) -> Vec<Case> {
    let file: VectorFile = load_fixture("wycheproof/hmac_sha512_test.json");
    file.groups
        .into_iter()
        .flat_map(|group| {
            let tag_len = group.tag_bits / 8;
            group
                .tests
                .into_iter()
                .map(move |vector| Case { tag_len, vector })
        })
        .filter(|case| case.vector.result == result)
        .collect()
}

#[test]
fn hmac_sha512_matches_every_valid_wycheproof_vector() {
    let valid = cases_with_result("valid");
    assert_eq!(valid.len(), 66);

    for case in valid {
        assert!(case.tag_matches(), "tcId {}", case.vector.id);
    }
}

#[test]
fn hmac_sha512_differs_from_every_invalid_wycheproof_tag() {
    let invalid = cases_with_result("invalid");
    assert_eq!(invalid.len(), 108);

    for case in invalid {
        assert!(!case.tag_matches(), "tcId {}", case.vector.id);
    }
}
