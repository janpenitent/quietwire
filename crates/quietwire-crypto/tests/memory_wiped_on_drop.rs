// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! QW-U-CRY-050: once dropped, no heap block that held a secret may still hold
//! it. The scanning allocator reads every freed block back before releasing it.
//!
//! Every test watches a secret of its own, so tests running in parallel
//! threads do not disturb each other.

#![allow(missing_docs, clippy::unwrap_used)]

use quietwire_crypto::{
    aead::{open, seal, Nonce},
    hierarchy::{Dek, Kek, Purpose},
    SecretKey,
};
use quietwire_crypto_memtest::ScanningAllocator;

#[global_allocator]
static ALLOCATOR: ScanningAllocator = ScanningAllocator::new();

fn random_bytes() -> [u8; 32] {
    *SecretKey::random().unwrap().expose_secret()
}

#[test]
fn secret_key_is_wiped_when_dropped() {
    let key = SecretKey::random().unwrap();
    let watch = ALLOCATOR.watch_bytes(key.expose_secret()).unwrap();

    drop(key);

    assert_eq!(watch.unwiped_frees(), 0);
}

#[test]
fn deriving_a_subkey_leaves_no_copy_of_it_behind() {
    let dek = Dek::generate().unwrap();
    let subkey = dek.subkey(Purpose::Db).unwrap();
    let watch = ALLOCATOR.watch_bytes(subkey.expose_secret()).unwrap();

    drop(subkey);
    drop(dek.subkey(Purpose::Db).unwrap());

    assert_eq!(watch.unwiped_frees(), 0);
}

#[test]
fn wrapping_and_unwrapping_a_dek_leaves_no_copy_of_it_behind() {
    let dek_bytes = random_bytes();
    let kek = Kek::from(SecretKey::random().unwrap());
    let watch = ALLOCATOR.watch_bytes(&dek_bytes).unwrap();

    let dek = Dek::from(SecretKey::from_slice(&dek_bytes).unwrap());
    let wrapped = dek.wrap_with(&kek).unwrap();
    drop(dek);
    drop(wrapped.unwrap_with(&kek).unwrap());

    assert_eq!(watch.unwiped_frees(), 0);
}

#[test]
fn sealing_and_opening_leaves_no_copy_of_the_plaintext_behind() {
    const PLAINTEXT: &[u8] = b"memory hygiene: sealed then opened";
    let key = SecretKey::random().unwrap();
    let nonce = Nonce::random().unwrap();
    let watch = ALLOCATOR.watch_bytes(PLAINTEXT).unwrap();

    let sealed = seal(&key, &nonce, b"", PLAINTEXT).unwrap();
    drop(open(&key, &nonce, b"", &sealed).unwrap());

    assert_eq!(watch.unwiped_frees(), 0);
}
