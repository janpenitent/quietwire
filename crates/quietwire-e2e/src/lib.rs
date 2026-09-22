// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! End-to-end security: hybrid post-quantum X3DH, Double Ratchet and per-message epoch tags.

// Lets `tests/support`, shared with the integration tests, name this crate.
#[cfg(test)]
extern crate self as quietwire_e2e;

pub mod ratchet;
pub mod x3dh;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;
