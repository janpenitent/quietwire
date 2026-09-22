// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Key-hierarchy property QW-P-CRY-069: for any DEK and any KEK,
//! `unwrap(wrap(k)) == k`, and an unwrap under a different KEK or over an
//! altered byte always fails.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use quietwire_crypto::{
    hierarchy::{Dek, Kek, Purpose, WrappedDek, WRAPPED_DEK_LEN},
    Error, SecretKey,
};

const PURPOSES: [Purpose; 5] = [
    Purpose::Db,
    Purpose::Field,
    Purpose::Identity,
    Purpose::Sessions,
    Purpose::Meta,
];

fn key_from(bytes: [u8; 32]) -> SecretKey {
    SecretKey::from_slice(&bytes).expect("32 bytes")
}

/// `Dek` deliberately has no `PartialEq`, so two are the same when every
/// purpose derives the same subkey.
fn same_dek(left: &Dek, right: &Dek) -> bool {
    PURPOSES
        .into_iter()
        .all(|purpose| left.subkey(purpose).unwrap() == right.subkey(purpose).unwrap())
}

proptest! {
    #[test]
    fn unwrap_of_wrap_is_the_original_dek(dek: [u8; 32], kek: [u8; 32]) {
        let dek = Dek::from(key_from(dek));
        let kek = Kek::from(key_from(kek));

        let unwrapped = dek.wrap_with(&kek).unwrap().unwrap_with(&kek).unwrap();

        prop_assert!(same_dek(&dek, &unwrapped));
    }

    #[test]
    fn unwrap_under_a_different_kek_fails(dek: [u8; 32], kek: [u8; 32], other: [u8; 32]) {
        prop_assume!(kek != other);
        let wrapped = Dek::from(key_from(dek))
            .wrap_with(&Kek::from(key_from(kek)))
            .unwrap();

        let opened = wrapped.unwrap_with(&Kek::from(key_from(other)));

        prop_assert!(matches!(opened, Err(Error::Authentication)));
    }

    #[test]
    fn unwrap_of_an_altered_wrapping_fails(
        dek: [u8; 32],
        kek: [u8; 32],
        index in 0..WRAPPED_DEK_LEN,
        mask in 1u8..=u8::MAX,
    ) {
        let kek = Kek::from(key_from(kek));
        let mut bytes = Dek::from(key_from(dek)).wrap_with(&kek).unwrap().to_bytes();
        bytes[index] ^= mask;

        let opened = WrappedDek::from_bytes(bytes).unwrap_with(&kek);

        prop_assert!(matches!(opened, Err(Error::Authentication)));
    }
}
