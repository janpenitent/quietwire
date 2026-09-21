// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use serde::de::DeserializeOwned;

pub fn hex(encoded: &str) -> Vec<u8> {
    assert!(encoded.len().is_multiple_of(2), "odd-length hex: {encoded}");
    (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).expect("hex digit"))
        .collect()
}

pub fn hex_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex(encoded).try_into().expect("hex of the expected length")
}

pub fn load_fixture<T: DeserializeOwned>(relative_path: &str) -> T {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative_path);
    let text = std::fs::read_to_string(&path).expect("fixture readable");
    serde_json::from_str(&text).expect("fixture parses")
}
