// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

use crate::Error;

pub(crate) fn fill(bytes: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(bytes).map_err(|_| Error::Rng)
}
