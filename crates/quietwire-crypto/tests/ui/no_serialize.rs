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

fn requires_serialize<T: serde::Serialize>() {}

fn main() {
    requires_serialize::<SecretKey>();
    requires_serialize::<PrivateKey>();
    requires_serialize::<SigningKey>();
    requires_serialize::<DecapsulationKey>();
    requires_serialize::<Kek>();
    requires_serialize::<Dek>();
}
