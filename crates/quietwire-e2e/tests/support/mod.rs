// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

#![allow(
    dead_code,
    unused_imports,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use serde::de::DeserializeOwned;

pub use quietwire_fixtures::{hex, hex_array};

pub fn load_fixture<T: DeserializeOwned>(relative_path: &str) -> T {
    quietwire_fixtures::load_fixture(env!("CARGO_MANIFEST_DIR"), relative_path)
}

use quietwire_crypto::{
    aead::Nonce,
    ed25519::{SigningKey, VerifyingKey},
    mlkem::{Ciphertext, DecapsulationKey, EncapsulationKey},
    x25519::{PrivateKey, PublicKey},
    SecretKey,
};
use quietwire_e2e::{
    ratchet::{SealedFrame, PLAINTEXT_LEN},
    x3dh::{IdentityPublic, InitialMessage, Initiator, PrekeyBundle, Responder},
};
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

/// A party with fresh keys, for sessions that no vector pins.
pub struct GeneratedParty {
    pub identity: IdentityPublic,
    pub identity_dh: PrivateKey,
    pub kem: DecapsulationKey,
    pub signed_prekey: PrivateKey,
    pub one_time_prekey: PrivateKey,
}

impl GeneratedParty {
    pub fn generate() -> Self {
        let identity_dh = PrivateKey::generate().unwrap();
        let kem = DecapsulationKey::generate().unwrap();
        Self {
            identity: IdentityPublic {
                sign: SigningKey::generate().unwrap().verifying_key(),
                dh: identity_dh.public_key(),
                kem: kem.encapsulation_key(),
            },
            identity_dh,
            kem,
            signed_prekey: PrivateKey::generate().unwrap(),
            one_time_prekey: PrivateKey::generate().unwrap(),
        }
    }

    pub fn initiator(&self) -> Initiator<'_> {
        Initiator {
            identity: &self.identity,
            identity_dh: &self.identity_dh,
        }
    }

    pub fn responder(&self, with_one_time_prekey: bool) -> Responder<'_> {
        Responder {
            identity: &self.identity,
            identity_dh: &self.identity_dh,
            kem: &self.kem,
            signed_prekey: &self.signed_prekey,
            one_time_prekey: with_one_time_prekey.then_some(&self.one_time_prekey),
        }
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

#[derive(Deserialize)]
pub struct RatchetCase {
    shared_key: String,
    initiator_ratchet_keys: Vec<String>,
    responder_ratchet_keys: Vec<String>,
    messages: Vec<RatchetMessage>,
    pub steps: Vec<RatchetStep>,
}

impl RatchetCase {
    pub fn shared_key(&self) -> SecretKey {
        secret(&self.shared_key)
    }

    /// The initiator's ratchet keys, in the order it draws them.
    pub fn initiator_ratchet_keys(&self) -> Vec<PrivateKey> {
        self.initiator_ratchet_keys
            .iter()
            .map(|key| private(key))
            .collect()
    }

    /// The responder's ratchet keys, its signed prekey first.
    pub fn responder_ratchet_keys(&self) -> Vec<PrivateKey> {
        self.responder_ratchet_keys
            .iter()
            .map(|key| private(key))
            .collect()
    }

    pub fn message(&self, name: &str) -> &RatchetMessage {
        self.messages
            .iter()
            .find(|message| message.name == name)
            .unwrap()
    }
}

#[derive(Deserialize)]
pub struct RatchetMessage {
    name: String,
    pub sender: Sender,
    nonce: String,
    plaintext: String,
    frame: String,
}

impl RatchetMessage {
    pub fn nonce(&self) -> Nonce {
        Nonce::from_bytes(hex_array(&self.nonce))
    }

    pub fn plaintext(&self) -> [u8; PLAINTEXT_LEN] {
        hex_array(&self.plaintext)
    }

    pub fn sealed(&self) -> SealedFrame {
        SealedFrame {
            nonce: self.nonce(),
            frame: hex_array(&self.frame),
        }
    }
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Sender {
    Initiator,
    Responder,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RatchetStep {
    Send(String),
    Receive(String),
}

pub fn ratchet_case() -> RatchetCase {
    load_fixture("derived/ratchet.json")
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
