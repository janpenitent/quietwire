// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `SecretKey`: construction, comparison and placement in memory.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use quietwire_crypto::{Error, SecretKey};

const DEDICATED_PAGE_ALIGN: usize = 16 * 1024;

#[test]
fn from_slice_keeps_exactly_the_given_32_bytes() {
    let bytes = [0x5a; 32];

    let key = SecretKey::from_slice(&bytes).unwrap();

    assert_eq!(key.expose_secret(), &bytes);
}

#[test]
fn from_slice_rejects_every_other_length() {
    for len in [0, 1, 16, 31, 33, 64] {
        assert!(
            matches!(
                SecretKey::from_slice(&vec![0; len]),
                Err(Error::InvalidLength)
            ),
            "length {len}"
        );
    }
}

#[test]
fn random_keys_are_distinct() {
    let first = SecretKey::random().unwrap();
    let second = SecretKey::random().unwrap();

    assert!(first != second);
}

#[test]
fn keys_are_equal_exactly_when_their_bytes_are() {
    let key = SecretKey::from_slice(&[7; 32]).unwrap();
    let same = SecretKey::from_slice(&[7; 32]).unwrap();
    let mut last_byte_differs = [7; 32];
    last_byte_differs[31] = 8;

    assert!(key == same);
    assert!(key != SecretKey::from_slice(&last_byte_differs).unwrap());
}

#[test]
fn every_key_starts_its_own_16_kib_aligned_page() {
    let keys: Vec<SecretKey> = (0..4).map(|_| SecretKey::random().unwrap()).collect();

    for key in &keys {
        assert_eq!(
            key.expose_secret().as_ptr().addr() % DEDICATED_PAGE_ALIGN,
            0
        );
    }
}

#[cfg(all(target_os = "linux", not(miri)))]
mod ram_lock {
    use std::{env, fs, process::Command};

    use quietwire_crypto::SecretKey;

    const CAP_IPC_LOCK: u32 = 14;
    const COMFORTABLE_LOCK_LIMIT: u64 = 1024 * 1024;

    fn proc_self(file: &str, field: &str) -> String {
        fs::read_to_string(format!("/proc/self/{file}"))
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix(field).map(str::to_owned))
            .unwrap_or_else(|| panic!("{field} missing from /proc/self/{file}"))
    }

    fn may_ignore_lock_limit() -> bool {
        let effective = u64::from_str_radix(proc_self("status", "CapEff:").trim(), 16).unwrap();
        effective & (1 << CAP_IPC_LOCK) != 0
    }

    fn soft_lock_limit() -> Option<u64> {
        let soft = proc_self("limits", "Max locked memory");
        let soft = soft.split_whitespace().next().unwrap();
        soft.parse().ok()
    }

    fn lock_is_certain() -> bool {
        may_ignore_lock_limit()
            || soft_lock_limit().is_none_or(|limit| limit >= COMFORTABLE_LOCK_LIMIT)
    }

    fn lock_is_impossible() -> bool {
        !may_ignore_lock_limit() && soft_lock_limit() == Some(0)
    }

    #[test]
    fn is_memory_locked_matches_what_the_lock_limit_allows() {
        let key = SecretKey::random().unwrap();

        if lock_is_certain() {
            assert!(key.is_memory_locked());
        }
        if lock_is_impossible() {
            assert!(!key.is_memory_locked());
        }
    }

    #[test]
    fn is_memory_locked_is_false_when_the_os_refuses_the_lock() {
        let this_test_binary = env::current_exe().unwrap();

        let child = Command::new("sh")
            .arg("-c")
            .arg("ulimit -l 0 && exec \"$0\" --exact \"$1\" --nocapture")
            .arg(this_test_binary)
            .arg("ram_lock::is_memory_locked_matches_what_the_lock_limit_allows")
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(child.status.success(), "{stdout}");
        assert!(stdout.contains("1 passed"), "{stdout}");
    }
}
