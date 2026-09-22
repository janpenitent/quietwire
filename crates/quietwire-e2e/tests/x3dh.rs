// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Hybrid X3DH (QW-U-E2E-011) through the public API: independent vectors,
//! fresh sessions and the inputs a session must refuse or tell apart.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::{
    ed25519::SigningKey,
    mlkem::{Ciphertext, DecapsulationKey, CIPHERTEXT_LEN},
    x25519::{PrivateKey, PublicKey},
    Error, SecretKey,
};
use quietwire_e2e::x3dh::{IdentityPublic, InitialMessage, Initiator, PrekeyBundle, Responder};
use support::{hex, x3dh_cases};

const LOW_ORDER_POINT: PublicKey = PublicKey::from_bytes([0; 32]);

struct Party {
    identity: IdentityPublic,
    identity_dh: PrivateKey,
    kem: DecapsulationKey,
    signed_prekey: PrivateKey,
    one_time_prekey: PrivateKey,
}

impl Party {
    fn generate() -> Self {
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

    fn initiator(&self) -> Initiator<'_> {
        Initiator {
            identity: &self.identity,
            identity_dh: &self.identity_dh,
        }
    }

    fn responder(&self, with_one_time_prekey: bool) -> Responder<'_> {
        Responder {
            identity: &self.identity,
            identity_dh: &self.identity_dh,
            kem: &self.kem,
            signed_prekey: &self.signed_prekey,
            one_time_prekey: with_one_time_prekey.then_some(&self.one_time_prekey),
        }
    }
}

fn bytes(key: &SecretKey) -> Vec<u8> {
    key.expose_secret().to_vec()
}

fn initiate(alice: &Party, bundle: &PrekeyBundle) -> (Vec<u8>, InitialMessage) {
    let (shared, message) = alice.initiator().initiate(bundle).unwrap();
    (bytes(&shared), message)
}

fn respond(bob: &Responder<'_>, alice: &Party, message: &InitialMessage) -> Vec<u8> {
    bytes(&bob.respond(&alice.identity, message).unwrap())
}

#[test]
fn responder_matches_every_independent_vector() {
    let cases = x3dh_cases();
    assert_eq!(cases.len(), 2);

    for case in cases {
        let one_time_prekey = case.one_time_prekey();
        let responder = Responder {
            identity: &case.responder.identity(),
            identity_dh: &case.responder.identity_dh(),
            kem: &case.responder.kem(),
            signed_prekey: &case.signed_prekey(),
            one_time_prekey: one_time_prekey.as_ref(),
        };

        assert_eq!(responder.bundle(), case.bundle(), "{}", case.name);
        let shared = responder
            .respond(&case.initiator.identity(), &case.message())
            .unwrap();
        assert_eq!(bytes(&shared), hex(&case.shared_key), "{}", case.name);
    }
}

#[test]
fn vector_private_keys_match_their_public_keys() {
    for case in x3dh_cases() {
        for party in [&case.initiator, &case.responder] {
            let identity = party.identity();
            assert_eq!(party.identity_dh().public_key(), identity.dh);
            assert_eq!(party.kem().encapsulation_key(), identity.kem);
        }
        assert_eq!(case.ephemeral().public_key(), case.message().ephemeral);
    }
}

#[test]
fn fresh_sessions_agree_with_and_without_one_time_prekey() {
    let (alice, bob) = (Party::generate(), Party::generate());

    for with_one_time_prekey in [true, false] {
        let responder = bob.responder(with_one_time_prekey);
        let (initiator_key, message) = initiate(&alice, &responder.bundle());

        assert_eq!(respond(&responder, &alice, &message), initiator_key);
    }
}

#[test]
fn every_session_derives_a_new_key() {
    let (alice, bob) = (Party::generate(), Party::generate());
    let bundle = bob.responder(true).bundle();

    let (first, first_message) = initiate(&alice, &bundle);
    let (second, second_message) = initiate(&alice, &bundle);

    assert_ne!(first, second);
    assert_ne!(first_message.ephemeral, second_message.ephemeral);
}

#[test]
fn stripping_the_one_time_prekey_splits_the_session() {
    let (alice, bob) = (Party::generate(), Party::generate());
    let responder = bob.responder(true);
    let stripped = PrekeyBundle {
        one_time_prekey: None,
        ..responder.bundle()
    };

    let (initiator_key, message) = initiate(&alice, &stripped);

    assert_ne!(respond(&responder, &alice, &message), initiator_key);
}

#[test]
fn a_forged_kem_ciphertext_splits_the_session() {
    let (alice, bob) = (Party::generate(), Party::generate());
    let responder = bob.responder(true);
    let (initiator_key, message) = initiate(&alice, &responder.bundle());
    let forged = InitialMessage {
        kem_ciphertext: Ciphertext::from_bytes([0x5A; CIPHERTEXT_LEN]),
        ..message
    };

    assert_ne!(respond(&responder, &alice, &forged), initiator_key);
}

#[test]
fn a_claimed_initiator_identity_splits_the_session() {
    let (alice, bob, mallory) = (Party::generate(), Party::generate(), Party::generate());
    let responder = bob.responder(true);
    let (initiator_key, message) = initiate(&alice, &responder.bundle());
    let claimed = IdentityPublic {
        dh: alice.identity.dh,
        ..mallory.identity.clone()
    };

    let responder_key = responder.respond(&claimed, &message).unwrap();

    assert_ne!(bytes(&responder_key), initiator_key);
}

#[test]
fn initiator_refuses_a_low_order_prekey() {
    let (alice, bob) = (Party::generate(), Party::generate());
    let bundle = bob.responder(true).bundle();
    let low_order_signed_prekey = PrekeyBundle {
        signed_prekey: LOW_ORDER_POINT,
        ..bundle.clone()
    };
    let low_order_one_time_prekey = PrekeyBundle {
        one_time_prekey: Some(LOW_ORDER_POINT),
        ..bundle
    };

    for bundle in [low_order_signed_prekey, low_order_one_time_prekey] {
        let refused = alice.initiator().initiate(&bundle);
        assert!(matches!(refused, Err(Error::InvalidPublicKey)));
    }
}

#[test]
fn responder_refuses_a_low_order_ephemeral_key() {
    let (alice, bob) = (Party::generate(), Party::generate());
    let responder = bob.responder(true);
    let (_, message) = initiate(&alice, &responder.bundle());
    let low_order = InitialMessage {
        ephemeral: LOW_ORDER_POINT,
        ..message
    };

    let refused = responder.respond(&alice.identity, &low_order);

    assert!(matches!(refused, Err(Error::InvalidPublicKey)));
}
