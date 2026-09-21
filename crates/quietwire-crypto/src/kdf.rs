// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! HKDF-SHA512 (RFC 5869).

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::Error;

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
