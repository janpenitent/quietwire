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

fn requires_display<T: std::fmt::Display>() {}

fn main() {
    requires_display::<SecretKey>();
    requires_display::<PrivateKey>();
    requires_display::<SigningKey>();
    requires_display::<DecapsulationKey>();
    requires_display::<Kek>();
    requires_display::<Dek>();
}
