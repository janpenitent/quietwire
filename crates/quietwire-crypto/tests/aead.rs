// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! XChaCha20-Poly1305 behaviour beyond the known answers: nonce generation and
//! rejection of anything that was not sealed as presented.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use quietwire_crypto::{
    aead::{open, seal, Nonce},
    Error, SecretKey,
};

const TAG_LEN: usize = 16;

fn key() -> SecretKey {
    SecretKey::random().unwrap()
}

#[test]
fn random_nonces_are_distinct() {
    let first = Nonce::random().unwrap();
    let second = Nonce::random().unwrap();

    assert_ne!(first.as_bytes(), second.as_bytes());
}

#[test]
fn nonce_keeps_the_given_bytes() {
    assert_eq!(Nonce::from_bytes([9; 24]).as_bytes(), &[9; 24]);
}

#[test]
fn sealed_message_is_plaintext_length_plus_tag_and_opens() {
    let key = key();
    let nonce = Nonce::random().unwrap();

    let sealed = seal(&key, &nonce, b"header", b"attack at dawn").unwrap();
    let opened = open(&key, &nonce, b"header", &sealed).unwrap();

    assert_eq!(sealed.len(), b"attack at dawn".len() + TAG_LEN);
    assert_eq!(*opened, b"attack at dawn");
}

#[test]
fn open_rejects_other_associated_data() {
    let key = key();
    let nonce = Nonce::random().unwrap();
    let sealed = seal(&key, &nonce, b"header", b"payload").unwrap();

    assert!(matches!(
        open(&key, &nonce, b"other", &sealed),
        Err(Error::Authentication)
    ));
}

#[test]
fn open_rejects_another_nonce() {
    let key = key();
    let sealed = seal(&key, &Nonce::from_bytes([1; 24]), b"", b"payload").unwrap();

    assert!(matches!(
        open(&key, &Nonce::from_bytes([2; 24]), b"", &sealed),
        Err(Error::Authentication)
    ));
}

#[test]
fn open_rejects_input_shorter_than_a_tag() {
    let nonce = Nonce::random().unwrap();

    for len in 0..TAG_LEN {
        assert!(
            matches!(
                open(&key(), &nonce, b"", &vec![0; len]),
                Err(Error::Authentication)
            ),
            "length {len}"
        );
    }
}
