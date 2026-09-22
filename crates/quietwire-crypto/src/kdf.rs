// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! HKDF-SHA512 (RFC 5869) and HMAC-SHA512 (RFC 2104).

use hkdf::Hkdf;
use hmac::{digest::FixedOutput, Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::Error;

/// Length of an [`hmac_sha512`] output in bytes.
pub const HMAC_SHA512_LEN: usize = 64;

/// Extracts from `ikm` with `salt`, then expands `len` bytes bound to `info`.
///
/// An empty `salt` is the RFC's "not provided" case.
///
/// # Errors
/// [`Error::InvalidLength`] if `len` exceeds 255 SHA-512 blocks (16 320 bytes).
pub fn hkdf_sha512(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut okm = Zeroizing::new(vec![0; len]);
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .map_err(|_| Error::InvalidLength)?;
    Ok(okm)
}

/// HMAC-SHA512 of `message` under `key`.
#[must_use]
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Zeroizing<[u8; HMAC_SHA512_LEN]> {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    mac.update(message);
    let mut tag = Zeroizing::new([0; HMAC_SHA512_LEN]);
    mac.finalize_into((&mut *tag).into());
    tag
}
