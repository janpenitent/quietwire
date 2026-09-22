// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! QW-F-CRY-080, responder side: the initiator identity and initial message a
//! responder reads from a peer.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use quietwire_crypto::{
    mlkem::{Ciphertext, CIPHERTEXT_LEN},
    x25519::{PublicKey, PUBLIC_KEY_LEN},
    Error,
};
use quietwire_e2e::x3dh::InitialMessage;
use quietwire_fuzz::{Party, PeerIdentity};

static RESPONDER: LazyLock<Party> = LazyLock::new(Party::generate);

#[derive(Arbitrary, Debug)]
struct Input {
    initiator: PeerIdentity,
    ephemeral: [u8; PUBLIC_KEY_LEN],
    kem_ciphertext: Box<[u8; CIPHERTEXT_LEN]>,
    with_one_time_prekey: bool,
}

fuzz_target!(|input: Input| {
    let Some(initiator) = input.initiator.parse() else {
        return;
    };
    let message = InitialMessage {
        ephemeral: PublicKey::from_bytes(input.ephemeral),
        kem_ciphertext: Ciphertext::from_bytes(*input.kem_ciphertext),
    };
    match RESPONDER
        .responder(input.with_one_time_prekey)
        .respond(&initiator, &message)
    {
        Ok(_) | Err(Error::InvalidPublicKey) => {}
        Err(error) => panic!("unexpected {error:?}"),
    }
});
