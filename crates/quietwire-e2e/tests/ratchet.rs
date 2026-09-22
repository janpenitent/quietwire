// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Double Ratchet (QW-U-E2E-012) through the public API: sessions started by
//! X3DH, frames lost, reordered, replayed or forged, and the limits of §5.4.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use quietwire_crypto::{
    x25519::{PrivateKey, PublicKey, PUBLIC_KEY_LEN},
    Error as CryptoError, SecretKey,
};
use quietwire_e2e::ratchet::{Error, SealedFrame, Session, HEADER_LEN, PLAINTEXT_LEN};
use support::GeneratedParty;

const LOW_ORDER_POINT: PublicKey = PublicKey::from_bytes([0; 32]);
const CHAIN_LIMIT: u32 = 2000;
const MAX_SKIP_PER_CHAIN: u32 = 1000;
const MAX_SKIPPED_TOTAL: u32 = 10_000;
const PREVIOUS_CHAIN_LEN: usize = PUBLIC_KEY_LEN;
const MESSAGE_NUMBER: usize = PUBLIC_KEY_LEN + 4;
const REFUSED: Result<(), Error> = Err(Error::Crypto(CryptoError::Authentication));
const TOO_FAR_AHEAD: Result<(), Error> = Err(Error::TooFarAhead);

struct Pair {
    alice: Session,
    bob: Session,
}

impl Pair {
    fn new() -> Self {
        let shared_key = [0x42; 32];
        let signed_prekey = PrivateKey::generate().unwrap();
        let remote_ratchet = signed_prekey.public_key();
        Self {
            alice: Session::initiator(&SecretKey::from_slice(&shared_key).unwrap(), remote_ratchet)
                .unwrap(),
            bob: Session::responder(SecretKey::from_slice(&shared_key).unwrap(), signed_prekey),
        }
    }

    fn alice_sends(&mut self, count: u32) -> Vec<SealedFrame> {
        (0..count)
            .map(|number| self.alice.encrypt(&plaintext(number)).unwrap())
            .collect()
    }

    /// Bob answers Alice's latest frame, so her next frames open a new chain.
    fn round_trip(&mut self) {
        let reply = self.bob.encrypt(&plaintext(0)).unwrap();
        self.alice.decrypt(&reply).unwrap();
    }
}

fn plaintext(number: u32) -> [u8; PLAINTEXT_LEN] {
    let mut plaintext = [0; PLAINTEXT_LEN];
    plaintext[..4].copy_from_slice(&number.to_le_bytes());
    plaintext
}

fn receive(session: &mut Session, frame: &SealedFrame) -> Result<(), Error> {
    let opened = session.decrypt(frame)?;
    assert_eq!(opened[..4], frame.frame[MESSAGE_NUMBER..HEADER_LEN]);
    Ok(())
}

fn with_header_field(frame: &SealedFrame, offset: usize, value: u32) -> SealedFrame {
    let mut forged = frame.clone();
    forged.frame[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    forged
}

#[test]
fn sessions_started_by_x3dh_exchange_frames_both_ways() {
    let (alice, bob) = (GeneratedParty::generate(), GeneratedParty::generate());
    let responder = bob.responder(true);
    let (initiator_key, message) = alice.initiator().initiate(&responder.bundle()).unwrap();
    let responder_key = responder.respond(&alice.identity, &message).unwrap();
    let mut alice_session =
        Session::initiator(&initiator_key, responder.bundle().signed_prekey).unwrap();
    let mut bob_session = Session::responder(responder_key, bob.signed_prekey);

    for round in 0..3 {
        let from_alice = alice_session.encrypt(&plaintext(round)).unwrap();
        assert_eq!(*bob_session.decrypt(&from_alice).unwrap(), plaintext(round));
        let from_bob = bob_session.encrypt(&plaintext(round + 100)).unwrap();
        assert_eq!(
            *alice_session.decrypt(&from_bob).unwrap(),
            plaintext(round + 100)
        );
    }
}

#[test]
fn frames_open_in_any_order() {
    let mut pair = Pair::new();
    let frames = pair.alice_sends(5);

    for index in [4, 0, 3, 1, 2] {
        assert_eq!(receive(&mut pair.bob, &frames[index]), Ok(()));
    }
}

#[test]
fn a_frame_opens_only_once() {
    let mut pair = Pair::new();
    let frames = pair.alice_sends(3);

    for index in [0, 2, 1] {
        receive(&mut pair.bob, &frames[index]).unwrap();
    }

    for frame in &frames {
        assert_eq!(receive(&mut pair.bob, frame), REFUSED);
    }
}

#[test]
fn a_forged_frame_leaves_the_session_as_it_was() {
    let mut pair = Pair::new();
    let frames = pair.alice_sends(3);
    receive(&mut pair.bob, &frames[0]).unwrap();
    let new_ratchet_key = PrivateKey::generate().unwrap().public_key();
    let flip = |offset: usize| {
        let mut forged = frames[1].clone();
        forged.frame[offset] ^= 1;
        forged
    };
    let mut other_nonce = frames[1].clone();
    other_nonce.nonce = quietwire_crypto::aead::Nonce::from_bytes([7; 24]);
    let mut other_ratchet = frames[1].clone();
    other_ratchet.frame[..PUBLIC_KEY_LEN].copy_from_slice(new_ratchet_key.as_bytes());

    let forgeries = [
        flip(MESSAGE_NUMBER),
        flip(PREVIOUS_CHAIN_LEN),
        flip(HEADER_LEN),
        flip(frames[1].frame.len() - 1),
        other_nonce,
        other_ratchet,
        with_header_field(&frames[1], MESSAGE_NUMBER, MAX_SKIP_PER_CHAIN),
    ];
    for forged in &forgeries {
        assert_eq!(receive(&mut pair.bob, forged), REFUSED);
    }

    assert_eq!(receive(&mut pair.bob, &frames[2]), Ok(()));
    assert_eq!(receive(&mut pair.bob, &frames[1]), Ok(()));
}

#[test]
fn every_frame_draws_a_fresh_nonce() {
    let mut pair = Pair::new();
    let first = pair.alice.encrypt(&plaintext(0)).unwrap();
    let mut second = pair.alice.encrypt(&plaintext(0)).unwrap();

    assert_ne!(first.nonce, second.nonce);
    second.nonce = first.nonce;
    assert_ne!(first.frame, second.frame);
}

#[test]
fn the_responder_sends_only_after_receiving() {
    let mut pair = Pair::new();
    assert_eq!(pair.bob.encrypt(&plaintext(0)), Err(Error::SendingBlocked));

    let frame = pair.alice.encrypt(&plaintext(0)).unwrap();
    pair.bob.decrypt(&frame).unwrap();

    assert!(pair.bob.encrypt(&plaintext(0)).is_ok());
}

#[test]
fn sending_stops_at_the_chain_limit_until_the_peer_replies() {
    let mut pair = Pair::new();
    let frames = pair.alice_sends(CHAIN_LIMIT);
    assert_eq!(
        pair.alice.encrypt(&plaintext(0)),
        Err(Error::SendingBlocked)
    );

    receive(&mut pair.bob, &frames[MAX_SKIP_PER_CHAIN as usize]).unwrap();
    receive(&mut pair.bob, &frames[CHAIN_LIMIT as usize - 1]).unwrap();
    pair.round_trip();

    let next = pair.alice.encrypt(&plaintext(0)).unwrap();
    assert_eq!(receive(&mut pair.bob, &next), Ok(()));
}

#[test]
fn a_chain_skips_at_most_its_limit_of_keys() {
    let mut pair = Pair::new();
    let frames = pair.alice_sends(MAX_SKIP_PER_CHAIN + 2);

    let too_far = &frames[MAX_SKIP_PER_CHAIN as usize + 1];
    assert_eq!(receive(&mut pair.bob, too_far), TOO_FAR_AHEAD);
    assert_eq!(
        receive(&mut pair.bob, &frames[MAX_SKIP_PER_CHAIN as usize]),
        Ok(())
    );
    assert_eq!(receive(&mut pair.bob, &frames[0]), Ok(()));
}

#[test]
fn a_chain_ends_at_its_limit() {
    let mut pair = Pair::new();
    let frames = pair.alice_sends(MAX_SKIP_PER_CHAIN + 1);
    receive(&mut pair.bob, &frames[MAX_SKIP_PER_CHAIN as usize]).unwrap();
    let last = &frames[MAX_SKIP_PER_CHAIN as usize];

    let past_the_limit = with_header_field(last, MESSAGE_NUMBER, CHAIN_LIMIT);
    let last_number = with_header_field(last, MESSAGE_NUMBER, CHAIN_LIMIT - 1);

    assert_eq!(receive(&mut pair.bob, &past_the_limit), TOO_FAR_AHEAD);
    assert_eq!(receive(&mut pair.bob, &last_number), REFUSED);
}

#[test]
fn a_new_chain_skips_at_most_the_limit_left_in_the_previous_one() {
    let mut pair = Pair::new();
    let frames = pair.alice_sends(MAX_SKIP_PER_CHAIN + 1);
    receive(&mut pair.bob, &frames[MAX_SKIP_PER_CHAIN as usize]).unwrap();
    pair.round_trip();
    let next_chain = pair.alice.encrypt(&plaintext(0)).unwrap();

    let at_the_limit = with_header_field(&next_chain, PREVIOUS_CHAIN_LEN, CHAIN_LIMIT);
    let past_the_limit = with_header_field(&next_chain, PREVIOUS_CHAIN_LEN, CHAIN_LIMIT + 1);

    assert_eq!(receive(&mut pair.bob, &past_the_limit), TOO_FAR_AHEAD);
    assert_eq!(receive(&mut pair.bob, &at_the_limit), REFUSED);
    assert_eq!(receive(&mut pair.bob, &next_chain), Ok(()));
}

#[test]
fn a_new_chain_skips_at_most_the_per_chain_limit_in_the_previous_one() {
    let mut pair = Pair::new();
    let first = pair.alice.encrypt(&plaintext(0)).unwrap();
    receive(&mut pair.bob, &first).unwrap();
    pair.round_trip();
    let next_chain = pair.alice.encrypt(&plaintext(0)).unwrap();

    let at_the_limit = with_header_field(&next_chain, PREVIOUS_CHAIN_LEN, MAX_SKIP_PER_CHAIN + 1);
    let past_the_limit = with_header_field(&next_chain, PREVIOUS_CHAIN_LEN, MAX_SKIP_PER_CHAIN + 2);

    assert_eq!(receive(&mut pair.bob, &past_the_limit), TOO_FAR_AHEAD);
    assert_eq!(receive(&mut pair.bob, &at_the_limit), REFUSED);
}

#[test]
fn a_chain_keeps_only_its_newest_skipped_keys() {
    let mut pair = Pair::new();
    let frames = pair.alice_sends(CHAIN_LIMIT);
    receive(&mut pair.bob, &frames[MAX_SKIP_PER_CHAIN as usize]).unwrap();
    receive(&mut pair.bob, &frames[CHAIN_LIMIT as usize - 1]).unwrap();

    let skipped = 2 * MAX_SKIP_PER_CHAIN - 2;
    let evicted = skipped - MAX_SKIP_PER_CHAIN;
    assert_eq!(
        receive(&mut pair.bob, &frames[evicted as usize - 1]),
        REFUSED
    );
    assert_eq!(receive(&mut pair.bob, &frames[evicted as usize]), Ok(()));
}

#[test]
fn the_session_keeps_only_the_newest_skipped_keys() {
    let mut pair = Pair::new();
    let chains = MAX_SKIPPED_TOTAL / MAX_SKIP_PER_CHAIN + 1;
    let skipped_frames: Vec<Vec<SealedFrame>> = (0..chains)
        .map(|_| {
            let mut frames = pair.alice_sends(MAX_SKIP_PER_CHAIN + 1);
            receive(&mut pair.bob, &frames.pop().unwrap()).unwrap();
            pair.round_trip();
            frames
        })
        .collect();

    let newest_of_first_chain = skipped_frames[0].last().unwrap();
    assert_eq!(receive(&mut pair.bob, newest_of_first_chain), REFUSED);
    assert_eq!(receive(&mut pair.bob, &skipped_frames[1][0]), Ok(()));
}

#[test]
fn a_low_order_ratchet_key_is_refused() {
    let shared_key = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let refused = Session::initiator(&shared_key, LOW_ORDER_POINT);
    assert!(matches!(
        refused,
        Err(Error::Crypto(CryptoError::InvalidPublicKey))
    ));

    let mut pair = Pair::new();
    let mut low_order = pair.alice.encrypt(&plaintext(0)).unwrap();
    low_order.frame[..PUBLIC_KEY_LEN].copy_from_slice(LOW_ORDER_POINT.as_bytes());
    assert_eq!(
        receive(&mut pair.bob, &low_order),
        Err(Error::Crypto(CryptoError::InvalidPublicKey))
    );
}

#[test]
fn errors_describe_themselves_and_their_cause() {
    use std::error::Error as _;

    let errors = [
        Error::Crypto(CryptoError::Authentication),
        Error::SendingBlocked,
        Error::TooFarAhead,
    ];
    let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();

    assert_eq!(messages[0], CryptoError::Authentication.to_string());
    assert!(messages[1].contains("blocked") && messages[2].contains("ahead"));
    assert!(errors[0].source().is_some());
    assert!(errors[1].source().is_none() && errors[2].source().is_none());
    assert_eq!(
        Error::from(CryptoError::Rng),
        Error::Crypto(CryptoError::Rng)
    );
}
