// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

#![allow(
    dead_code,
    unused_imports,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use serde::de::DeserializeOwned;

pub use quietwire_fixtures::{hex, hex_array};

pub fn load_fixture<T: DeserializeOwned>(relative_path: &str) -> T {
    quietwire_fixtures::load_fixture(env!("CARGO_MANIFEST_DIR"), relative_path)
}
