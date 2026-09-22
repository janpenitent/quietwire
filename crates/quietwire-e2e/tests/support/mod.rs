// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../../quietwire-crypto/tests/support/mod.rs"]
mod fixtures;

pub use fixtures::{hex, hex_array, load_fixture};

use quietwire_crypto::{
    ed25519::VerifyingKey,
    mlkem::{Ciphertext, DecapsulationKey, EncapsulationKey},
    x25519::{PrivateKey, PublicKey},
    SecretKey,
};
use quietwire_e2e::x3dh::{IdentityPublic, InitialMessage, PrekeyBundle};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Party {
    sign_public: String,
    dh_private: String,
    dh_public: String,
    kem_d: String,
    kem_z: String,
    kem_public: String,
}

impl Party {
    pub fn identity(&self) -> IdentityPublic {
        IdentityPublic {
            sign: VerifyingKey::from_bytes(&hex_array(&self.sign_public)).unwrap(),
            dh: public(&self.dh_public),
            kem: EncapsulationKey::from_bytes(&hex_array(&self.kem_public)).unwrap(),
        }
    }

    pub fn identity_dh(&self) -> PrivateKey {
        private(&self.dh_private)
    }

    pub fn kem(&self) -> DecapsulationKey {
        DecapsulationKey::from_seed(secret(&self.kem_d), secret(&self.kem_z))
    }
}

#[derive(Deserialize)]
pub struct X3dhCase {
    pub name: String,
    pub initiator: Party,
    pub responder: Party,
    signed_prekey_private: String,
    signed_prekey_public: String,
    one_time_prekey_private: Option<String>,
    one_time_prekey_public: Option<String>,
    ephemeral_private: String,
    ephemeral_public: String,
    kem_ciphertext: String,
    kem_shared: String,
    pub transcript: String,
    pub shared_key: String,
}

impl X3dhCase {
    pub fn bundle(&self) -> PrekeyBundle {
        PrekeyBundle {
            identity: self.responder.identity(),
            signed_prekey: public(&self.signed_prekey_public),
            one_time_prekey: self.one_time_prekey_public.as_deref().map(public),
        }
    }

    pub fn message(&self) -> InitialMessage {
        InitialMessage {
            ephemeral: public(&self.ephemeral_public),
            kem_ciphertext: Ciphertext::from_bytes(hex_array(&self.kem_ciphertext)),
        }
    }

    pub fn signed_prekey(&self) -> PrivateKey {
        private(&self.signed_prekey_private)
    }

    pub fn one_time_prekey(&self) -> Option<PrivateKey> {
        self.one_time_prekey_private.as_deref().map(private)
    }

    pub fn ephemeral(&self) -> PrivateKey {
        private(&self.ephemeral_private)
    }

    pub fn encapsulation(&self) -> (Ciphertext, SecretKey) {
        (self.message().kem_ciphertext, secret(&self.kem_shared))
    }
}

pub fn x3dh_cases() -> Vec<X3dhCase> {
    load_fixture("derived/x3dh.json")
}

pub fn secret(encoded: &str) -> SecretKey {
    SecretKey::from_slice(&hex(encoded)).unwrap()
}

fn private(encoded: &str) -> PrivateKey {
    PrivateKey::from(secret(encoded))
}

fn public(encoded: &str) -> PublicKey {
    PublicKey::from_bytes(hex_array(encoded))
}
