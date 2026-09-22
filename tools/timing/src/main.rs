// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Welch's t-test over the secret-dependent operations of §16.
//!
//! Each bench feeds two classes of input that differ only in where a secret
//! byte differs, and `tools/ci/constant-time.sh` requires |t| < 4.5 for every
//! bench but the `mutant_` ones, which must exceed it.
//!
//! Every bench draws its class and builds its input outside `run_one`, which
//! is the only timed region.

use std::env;

use dudect_bencher::{ctbench_main, rand::RngExt, BenchRng, Class, CtRunner};
use quietwire_crypto::{
    aead::{self, Nonce, TAG_LEN},
    SecretKey,
};

const KEY_LEN: usize = 32;
const BASE: [u8; KEY_LEN] = [0x2a; KEY_LEN];
const NONCE: [u8; 24] = [0x5c; 24];
const AAD: &[u8] = b"aad";
const PLAINTEXT: [u8; 452] = [0x11; 452];
const DEFAULT_SAMPLES: usize = 10_000_000;
const SAMPLES_VAR: &str = "QW_TIMING_SAMPLES";

fn classes(rng: &mut BenchRng) -> Vec<Class> {
    let samples = env::var(SAMPLES_VAR)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_SAMPLES);
    (0..samples)
        .map(|_| {
            if rng.random::<bool>() {
                Class::Left
            } else {
                Class::Right
            }
        })
        .collect()
}

fn key(bytes: &[u8; KEY_LEN]) -> SecretKey {
    SecretKey::from_slice(bytes).expect("a 32-byte key")
}

fn differing_at(at: usize) -> SecretKey {
    let mut bytes = BASE;
    bytes[at] ^= 0xff;
    key(&bytes)
}

/// QW-U-CRY-030: the AEAD tag comparison.
///
/// Both classes fail to open, and differ only in which byte of the tag is
/// wrong: the first, or the last. A comparison that stops at the first
/// mismatch separates them.
///
/// The wrong byte is written into one buffer rather than picking between two,
/// because two allocations of the same bytes are themselves separable: at 10⁷
/// samples they measured |t| ≈ 5 with no tag involved at all.
fn aead_tag(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = key(&BASE);
    let nonce = Nonce::from_bytes(NONCE);
    let mut sealed = aead::seal(&key, &nonce, AAD, &PLAINTEXT).expect("sealing succeeds");
    let first = sealed.len() - TAG_LEN;
    let last = sealed.len() - 1;

    for class in classes(rng) {
        let at = match class {
            Class::Left => first,
            Class::Right => last,
        };
        sealed[at] ^= 0xff;
        runner.run_one(class, || aead::open(&key, &nonce, AAD, &sealed).is_ok());
        sealed[at] ^= 0xff;
    }
}

/// QW-U-CRY-036: `PartialEq` on a secret type.
///
/// Both classes are unequal keys, and differ only in which byte differs. A
/// `SecretKey` owns a locked page, so the two are built once; being page
/// aligned they sit identically in the cache, which is what lets the bench
/// pick between them instead of writing into one.
fn secret_key_eq(runner: &mut CtRunner, rng: &mut BenchRng) {
    let base = key(&BASE);
    let early = differing_at(0);
    let late = differing_at(KEY_LEN - 1);

    for class in classes(rng) {
        let other = match class {
            Class::Left => &early,
            Class::Right => &late,
        };
        runner.run_one(class, || base == *other);
    }
}

/// QW-U-CRY-046: the deliberate mutant.
///
/// The comparison of [`secret_key_eq`] with `subtle::ConstantTimeEq` replaced
/// by the short-circuiting byte loop the rest of the tree is forbidden from
/// using. A harness that cannot tell this apart from [`secret_key_eq`] is
/// measuring nothing, so the CI gate requires this bench to fail.
fn mutant_secret_key_eq(runner: &mut CtRunner, rng: &mut BenchRng) {
    let base = key(&BASE);
    let early = differing_at(0);
    let late = differing_at(KEY_LEN - 1);

    for class in classes(rng) {
        let other = match class {
            Class::Left => &early,
            Class::Right => &late,
        };
        runner.run_one(class, || {
            let (base, other) = (base.expose_secret(), other.expose_secret());
            let mut index = 0;
            while index < KEY_LEN && base[index] == other[index] {
                index += 1;
            }
            index == KEY_LEN
        });
    }
}

ctbench_main!(aead_tag, secret_key_eq, mutant_secret_key_eq);
