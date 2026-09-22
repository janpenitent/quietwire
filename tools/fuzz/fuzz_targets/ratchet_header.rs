// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! QW-F-E2E-081: the header of a frame a peer sends, on a live session.
//!
//! Only the genuine frame may decrypt, and whatever the peer sends, the session
//! must still accept the next genuine frame.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use quietwire_crypto::{
    aead::{Nonce, NONCE_LEN},
    x25519::PUBLIC_KEY_LEN,
};
use quietwire_e2e::ratchet::{SealedFrame, FRAME_LEN, HEADER_LEN, PLAINTEXT_LEN};
use quietwire_fuzz::{edited, Conversation, Edit};

const PLAINTEXT: [u8; PLAINTEXT_LEN] = [0x11; PLAINTEXT_LEN];
const CHAIN_LEN_AT: usize = PUBLIC_KEY_LEN;
const MESSAGE_NUMBER_AT: usize = PUBLIC_KEY_LEN + 4;

#[derive(Arbitrary, Debug)]
struct Input {
    nonce: Bytes<NONCE_LEN>,
    frame: FrameBody,
}

#[derive(Arbitrary, Debug)]
enum Bytes<const N: usize> {
    Genuine(Vec<Edit>),
    Raw(Box<[u8; N]>),
}

impl<const N: usize> Bytes<N> {
    fn resolve(&self, genuine: &[u8; N]) -> [u8; N] {
        match self {
            Self::Genuine(edits) => edited(*genuine, edits),
            Self::Raw(bytes) => **bytes,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FrameBody {
    Whole(Bytes<FRAME_LEN>),
    Reheadered {
        ratchet_key: Option<[u8; PUBLIC_KEY_LEN]>,
        previous_chain_len: u32,
        message_number: u32,
    },
}

impl FrameBody {
    fn resolve(&self, genuine: &[u8; FRAME_LEN]) -> [u8; FRAME_LEN] {
        match self {
            Self::Whole(bytes) => bytes.resolve(genuine),
            Self::Reheadered {
                ratchet_key,
                previous_chain_len,
                message_number,
            } => {
                let mut frame = *genuine;
                if let Some(bytes) = ratchet_key {
                    frame[..PUBLIC_KEY_LEN].copy_from_slice(bytes);
                }
                frame[CHAIN_LEN_AT..MESSAGE_NUMBER_AT]
                    .copy_from_slice(&previous_chain_len.to_be_bytes());
                frame[MESSAGE_NUMBER_AT..HEADER_LEN].copy_from_slice(&message_number.to_be_bytes());
                frame
            }
        }
    }
}

fuzz_target!(|input: Input| {
    let Conversation { mut alice, mut bob } = Conversation::start();
    let opening = alice.encrypt(&PLAINTEXT).expect("alice can send");
    bob.decrypt(&opening).expect("bob reads the opening frame");

    let genuine = alice.encrypt(&PLAINTEXT).expect("alice can send");
    let peer = SealedFrame {
        nonce: Nonce::from_bytes(input.nonce.resolve(genuine.nonce.as_bytes())),
        frame: input.frame.resolve(&genuine.frame),
    };
    let is_genuine =
        peer.nonce.as_bytes() == genuine.nonce.as_bytes() && peer.frame == genuine.frame;

    match bob.decrypt(&peer) {
        Ok(plaintext) => assert!(
            is_genuine && *plaintext == PLAINTEXT,
            "a frame the peer did not send decrypted"
        ),
        Err(error) => assert!(!is_genuine, "the genuine frame failed: {error:?}"),
    }

    assert_eq!(
        bob.decrypt(&genuine).is_ok(),
        !is_genuine,
        "the genuine frame must decrypt exactly once"
    );

    let next = alice.encrypt(&PLAINTEXT).expect("alice can send");
    assert!(
        bob.decrypt(&next)
            .is_ok_and(|plaintext| *plaintext == PLAINTEXT),
        "the session no longer accepts genuine frames"
    );
});
