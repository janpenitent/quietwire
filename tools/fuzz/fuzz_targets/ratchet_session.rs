// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! QW-F-E2E-082: a whole conversation driven by a peer, with frames reordered,
//! lost, duplicated and tampered with.
//!
//! The model of the proptest suite, with the sequence chosen by the fuzzer
//! instead of by proptest, and with tampering at any byte rather than one bit.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use quietwire_crypto::{
    aead::{Nonce, NONCE_LEN},
    Error as CryptoError,
};
use quietwire_e2e::ratchet::{Error, SealedFrame, Session, FRAME_LEN, PLAINTEXT_LEN};
use quietwire_fuzz::Conversation as Sessions;

const MAX_ACTIONS: usize = 256;
const SEALED_LEN: usize = NONCE_LEN + FRAME_LEN;

#[derive(Arbitrary, Clone, Copy, Debug, PartialEq, Eq)]
enum Party {
    Alice,
    Bob,
}

impl Party {
    const fn peer(self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }
}

/// One step of a conversation. Frames never picked by a delivery are lost;
/// frames picked again are duplicates.
#[derive(Arbitrary, Debug)]
enum Action {
    Send(Party),
    Deliver {
        to: Party,
        pick: u8,
    },
    Tamper {
        to: Party,
        pick: u8,
        at: u16,
        xor: u8,
    },
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
        let Sessions { alice, bob } = Sessions::start();
        Self {
            alice,
            bob,
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
        match *action {
            Action::Send(from) => self.send(from),
            Action::Deliver { to, pick } => self.deliver(to, pick),
            Action::Tamper { to, pick, at, xor } => self.tamper(to, pick, at, xor),
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
        let sealed = result.expect("a party that has received can send");
        self.inbox(from.peer()).push(InFlight {
            sealed,
            plaintext,
            opened: false,
        });
    }

    fn deliver(&mut self, to: Party, pick: u8) {
        let Some(index) = self.index(to, pick) else {
            return;
        };
        let sealed = self.inbox(to)[index].sealed.clone();
        let result = self.session(to).decrypt(&sealed);
        let frame = &mut self.inbox(to)[index];
        if frame.opened {
            assert_eq!(
                result.err(),
                Some(Error::Crypto(CryptoError::Authentication)),
                "a duplicate opened"
            );
            return;
        }
        assert_eq!(
            *result.expect("a genuine frame opens"),
            frame.plaintext,
            "a genuine frame opened to the wrong plaintext"
        );
        frame.opened = true;
        self.bob_has_received |= to == Party::Bob;
    }

    fn tamper(&mut self, to: Party, pick: u8, at: u16, xor: u8) {
        let Some(index) = self.index(to, pick) else {
            return;
        };
        if xor == 0 {
            return;
        }
        let byte = usize::from(at) % SEALED_LEN;
        let sealed = tampered(&self.inbox(to)[index].sealed, byte, xor);
        assert!(
            self.session(to).decrypt(&sealed).is_err(),
            "a tampered frame opened"
        );
    }

    fn index(&mut self, to: Party, pick: u8) -> Option<usize> {
        let len = self.inbox(to).len();
        (len > 0).then(|| usize::from(pick) % len)
    }
}

fn numbered_plaintext(number: u32) -> [u8; PLAINTEXT_LEN] {
    let mut plaintext = [0; PLAINTEXT_LEN];
    plaintext[..4].copy_from_slice(&number.to_le_bytes());
    plaintext
}

fn tampered(sealed: &SealedFrame, byte: usize, xor: u8) -> SealedFrame {
    let mut tampered = sealed.clone();
    match byte.checked_sub(NONCE_LEN) {
        None => {
            let mut nonce = *tampered.nonce.as_bytes();
            nonce[byte] ^= xor;
            tampered.nonce = Nonce::from_bytes(nonce);
        }
        Some(offset) => tampered.frame[offset] ^= xor,
    }
    tampered
}

fuzz_target!(|actions: Vec<Action>| {
    let mut conversation = Conversation::new();
    for action in actions.iter().take(MAX_ACTIONS) {
        conversation.apply(action);
    }
});
