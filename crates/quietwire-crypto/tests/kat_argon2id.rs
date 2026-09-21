// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-CRY-008`: the Argon2id implementation reproduces RFC 9106 §5.3.
//!
//! The RFC vector uses a secret and associated data, which the password KDF
//! never sets, so it is checked on the library directly; `derive_kek` is
//! checked against reference-implementation vectors in its own unit tests.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use serde::Deserialize;
use support::{hex, hex_array, load_fixture};

#[derive(Deserialize)]
struct Rfc9106Vector {
    password: String,
    salt: String,
    secret: String,
    associated_data: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    tag: String,
}

#[test]
fn qw_u_cry_008_argon2id_matches_rfc_9106_test_vector() {
    let vector: Rfc9106Vector = load_fixture("rfc9106/argon2id.json");
    let associated_data = hex(&vector.associated_data);
    let params = ParamsBuilder::new()
        .m_cost(vector.memory_kib)
        .t_cost(vector.iterations)
        .p_cost(vector.parallelism)
        .data(AssociatedData::new(&associated_data).expect("12 bytes fit"))
        .output_len(32)
        .build()
        .expect("RFC parameters are valid");
    let secret = hex(&vector.secret);
    let argon2 = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
        .expect("8-byte secret fits");

    let mut tag = [0u8; 32];
    argon2
        .hash_password_into(&hex(&vector.password), &hex(&vector.salt), &mut tag)
        .expect("hashing succeeds");

    assert_eq!(tag, hex_array::<32>(&vector.tag));
}
