// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Test-only helpers that decode the hex and JSON fixtures the integration
//! tests read.

use std::path::Path;

use serde::de::DeserializeOwned;

/// The bytes a hex string encodes.
///
/// # Panics
/// If the string is not an even number of hex digits.
#[must_use]
pub fn hex(encoded: &str) -> Vec<u8> {
    assert!(encoded.len().is_multiple_of(2), "odd-length hex: {encoded}");
    (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// The bytes a hex string encodes, as an array of the expected length.
///
/// # Panics
/// If the string is not `N` bytes of hex.
#[must_use]
pub fn hex_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex(encoded).try_into().expect("hex of the expected length")
}

/// The fixture at `<manifest_dir>/tests/fixtures/<relative_path>`.
///
/// Each crate reads its own fixtures, so the caller passes its own
/// `env!("CARGO_MANIFEST_DIR")`.
///
/// # Panics
/// If the fixture is unreadable or does not parse as `T`.
#[must_use]
pub fn load_fixture<T: DeserializeOwned>(manifest_dir: &str, relative_path: &str) -> T {
    let path = Path::new(manifest_dir)
        .join("tests/fixtures")
        .join(relative_path);
    let text = std::fs::read_to_string(&path).expect("fixture readable");
    serde_json::from_str(&text).expect("fixture parses")
}
