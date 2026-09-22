// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Double Ratchet properties QW-P-E2E-060 to QW-P-E2E-063: arbitrary
//! conversations delivered out of order, with losses, duplicates and flipped
//! bits.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::{prelude::*, sample::Index};
use quietwire_crypto::{
    aead::{Nonce, NONCE_LEN},
    x25519::PrivateKey,
    Error as CryptoError, SecretKey,
};
use quietwire_e2e::ratchet::{Error, SealedFrame, Session, FRAME_LEN, PLAINTEXT_LEN};

const MAX_ACTIONS: usize = 200;
const SEALED_BITS: usize = (NONCE_LEN + FRAME_LEN) * 8;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Party {
    Alice,
    Bob,
}

impl Party {
    fn peer(self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }
}

/// One step of a conversation. Frames never picked by a delivery are lost;
/// frames picked again are duplicates.
#[derive(Clone, Debug)]
enum Action {
    Send(Party),
    Deliver { to: Party, pick: Index },
}

struct InFlight {
    sealed: SealedFrame,
    plaintext: [u8; PLAINTEXT_LEN],
    opened: bool,
}

struct Conversation {
    alice: Session,
    bob: Session,
    to_alice: Vec<InFlight>,
    to_bob: Vec<InFlight>,
    bob_has_received: bool,
    sent: u32,
}

impl Conversation {
    fn new() -> Self {
        let shared_key = [0x42; 32];
        let signed_prekey = PrivateKey::generate().unwrap();
        let remote_ratchet = signed_prekey.public_key();
        Self {
            alice: Session::initiator(&SecretKey::from_slice(&shared_key).unwrap(), remote_ratchet)
                .unwrap(),
            bob: Session::responder(SecretKey::from_slice(&shared_key).unwrap(), signed_prekey),
            to_alice: Vec::new(),
            to_bob: Vec::new(),
            bob_has_received: false,
            sent: 0,
        }
    }

    fn session(&mut self, party: Party) -> &mut Session {
        match party {
            Party::Alice => &mut self.alice,
            Party::Bob => &mut self.bob,
        }
    }

    fn inbox(&mut self, party: Party) -> &mut Vec<InFlight> {
        match party {
            Party::Alice => &mut self.to_alice,
            Party::Bob => &mut self.to_bob,
        }
    }

    fn apply(&mut self, action: &Action) {
        match action {
            Action::Send(from) => self.send(*from),
            Action::Deliver { to, pick } => self.deliver(*to, *pick),
        }
    }

    fn send(&mut self, from: Party) {
        let plaintext = numbered_plaintext(self.sent);
        self.sent += 1;
        let result = self.session(from).encrypt(&plaintext);
        if from == Party::Bob && !self.bob_has_received {
            assert_eq!(result.err(), Some(Error::SendingBlocked));
            return;
        }
        let sealed = result.unwrap();
        self.inbox(from.peer()).push(InFlight {
            sealed,
            plaintext,
            opened: false,
        });
    }

    fn deliver(&mut self, to: Party, pick: Index) {
        if self.inbox(to).is_empty() {
            return;
        }
        let index = pick.index(self.inbox(to).len());
        let sealed = self.inbox(to)[index].sealed.clone();
        let result = self.session(to).decrypt(&sealed);
        let frame = &mut self.inbox(to)[index];
        if frame.opened {
            assert_eq!(
                result.err(),
                Some(Error::Crypto(CryptoError::Authentication))
            );
            return;
        }
        assert_eq!(*result.unwrap(), frame.plaintext);
        frame.opened = true;
        self.bob_has_received |= to == Party::Bob;
    }
}

fn numbered_plaintext(number: u32) -> [u8; PLAINTEXT_LEN] {
    let mut plaintext = [0; PLAINTEXT_LEN];
    plaintext[..4].copy_from_slice(&number.to_le_bytes());
    plaintext
}

fn party() -> impl Strategy<Value = Party> {
    prop_oneof![Just(Party::Alice), Just(Party::Bob)]
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        party().prop_map(Action::Send),
        (party(), any::<Index>()).prop_map(|(to, pick)| Action::Deliver { to, pick }),
    ]
}

fn with_bit_flipped(sealed: &SealedFrame, bit: usize) -> SealedFrame {
    let mut flipped = sealed.clone();
    let (byte, mask) = (bit / 8, 1 << (bit % 8));
    match byte.checked_sub(NONCE_LEN) {
        None => {
            let mut nonce = *flipped.nonce.as_bytes();
            nonce[byte] ^= mask;
            flipped.nonce = Nonce::from_bytes(nonce);
        }
        Some(offset) => flipped.frame[offset] ^= mask,
    }
    flipped
}

proptest! {
    /// QW-P-E2E-060, QW-P-E2E-061 and QW-P-E2E-062: whatever the order, the
    /// losses and the duplicates, every frame opens once to its plaintext and
    /// is refused after that.
    #[test]
    fn every_delivered_frame_opens_exactly_once(
        actions in prop::collection::vec(action(), 1..MAX_ACTIONS),
    ) {
        let mut conversation = Conversation::new();
        for action in &actions {
            conversation.apply(action);
        }
    }

    /// QW-P-E2E-063: a frame with any single bit flipped yields no plaintext
    /// and leaves the session able to open the genuine frame.
    #[test]
    fn a_flipped_bit_yields_no_plaintext(
        preceding in 0..8_u32,
        bit in 0..SEALED_BITS,
    ) {
        let mut conversation = Conversation::new();
        for _ in 0..=preceding {
            conversation.send(Party::Alice);
        }
        let genuine = conversation.to_bob.last().unwrap();
        let (sealed, plaintext) = (genuine.sealed.clone(), genuine.plaintext);

        prop_assert!(conversation.bob.decrypt(&with_bit_flipped(&sealed, bit)).is_err());
        prop_assert_eq!(*conversation.bob.decrypt(&sealed).unwrap(), plaintext);
    }
}
