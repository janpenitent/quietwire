// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

use quietwire_crypto::{
    ed25519::SigningKey,
    hierarchy::{Dek, Kek},
    mlkem::DecapsulationKey,
    x25519::PrivateKey,
    SecretKey,
};

fn requires_debug<T: std::fmt::Debug>() {}

fn main() {
    requires_debug::<SecretKey>();
    requires_debug::<PrivateKey>();
    requires_debug::<SigningKey>();
    requires_debug::<DecapsulationKey>();
    requires_debug::<Kek>();
    requires_debug::<Dek>();
}
