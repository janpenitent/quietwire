// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! BLAKE3 in its keyed and key-derivation modes.

use zeroize::Zeroizing;

use crate::SecretKey;

/// BLAKE3 keyed hash of `input`: a MAC and PRF under `key`.
#[must_use]
pub fn keyed_hash(key: &SecretKey, input: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(key.expose_secret(), input).into()
}

/// BLAKE3 key derivation from `key_material`, domain-separated by `context`.
///
/// `context` must be a hard-coded, globally unique, application-specific
/// string, which is why only `'static` strings are accepted.
#[must_use]
pub fn derive_key(context: &'static str, key_material: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(context, key_material))
}
