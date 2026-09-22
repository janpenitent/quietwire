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

fn requires_clone<T: Clone>() {}

fn main() {
    requires_clone::<SecretKey>();
    requires_clone::<PrivateKey>();
    requires_clone::<SigningKey>();
    requires_clone::<DecapsulationKey>();
    requires_clone::<Kek>();
    requires_clone::<Dek>();
}
