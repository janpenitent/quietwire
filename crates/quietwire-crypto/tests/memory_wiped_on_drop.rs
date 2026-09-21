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
    ed25519::SigningKey,
    hierarchy::{Dek, Kek, Purpose},
    mlkem, x25519, SecretKey,
};
use quietwire_crypto_memtest::ScanningAllocator;
use sha2::{Digest, Sha512};

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

#[test]
fn x25519_leaves_no_copy_of_the_private_key_or_the_shared_secret_behind() {
    let private_bytes = random_bytes();
    let peer = x25519::PrivateKey::generate().unwrap().public_key();
    let private_watch = ALLOCATOR.watch_bytes(&private_bytes).unwrap();

    let private = x25519::PrivateKey::from(SecretKey::from_slice(&private_bytes).unwrap());
    let _ = private.public_key();
    let shared = private.diffie_hellman(&peer).unwrap();
    let shared_watch = ALLOCATOR.watch_bytes(shared.expose_secret()).unwrap();
    drop(shared);
    drop(private);

    assert_eq!(private_watch.unwiped_frees(), 0);
    assert_eq!(shared_watch.unwiped_frees(), 0);
}

#[test]
fn signing_leaves_no_copy_of_the_seed_or_its_nonce_prefix_behind() {
    let seed = random_bytes();
    let prefix = Sha512::digest(seed)[32..].to_vec();
    let seed_watch = ALLOCATOR.watch_bytes(&seed).unwrap();
    let prefix_watch = ALLOCATOR.watch_bytes(&prefix).unwrap();

    let key = SigningKey::from(SecretKey::from_slice(&seed).unwrap());
    let _ = key.verifying_key();
    let _ = key.sign(b"memory hygiene");
    drop(key);

    assert_eq!(seed_watch.unwiped_frees(), 0);
    assert_eq!(prefix_watch.unwiped_frees(), 0);
}

#[test]
fn ml_kem_leaves_no_copy_of_the_seed_or_the_shared_key_behind() {
    let (d, z) = (random_bytes(), random_bytes());
    let d_watch = ALLOCATOR.watch_bytes(&d).unwrap();
    let z_watch = ALLOCATOR.watch_bytes(&z).unwrap();

    let key = mlkem::DecapsulationKey::from_seed(
        SecretKey::from_slice(&d).unwrap(),
        SecretKey::from_slice(&z).unwrap(),
    );
    let (ciphertext, sent) = key.encapsulation_key().encapsulate().unwrap();
    let shared_watch = ALLOCATOR.watch_bytes(sent.expose_secret()).unwrap();
    drop(key.decapsulate(&ciphertext));
    drop(sent);
    drop(key);

    assert_eq!(d_watch.unwiped_frees(), 0);
    assert_eq!(z_watch.unwiped_frees(), 0);
    assert_eq!(shared_watch.unwiped_frees(), 0);
}
