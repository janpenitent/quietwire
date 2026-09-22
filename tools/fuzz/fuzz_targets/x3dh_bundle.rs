// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! QW-F-CRY-080: an initiator starting a session from a peer's prekey bundle.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use quietwire_crypto::{
    x25519::{PublicKey, PUBLIC_KEY_LEN},
    Error,
};
use quietwire_e2e::x3dh::PrekeyBundle;
use quietwire_fuzz::{Party, PeerIdentity};

static INITIATOR: LazyLock<Party> = LazyLock::new(Party::generate);

#[derive(Arbitrary, Debug)]
struct Bundle {
    identity: PeerIdentity,
    signed_prekey: [u8; PUBLIC_KEY_LEN],
    one_time_prekey: Option<[u8; PUBLIC_KEY_LEN]>,
}

impl Bundle {
    fn parse(&self) -> Option<PrekeyBundle> {
        Some(PrekeyBundle {
            identity: self.identity.parse()?,
            signed_prekey: PublicKey::from_bytes(self.signed_prekey),
            one_time_prekey: self.one_time_prekey.map(PublicKey::from_bytes),
        })
    }
}

fuzz_target!(|input: Bundle| {
    let Some(bundle) = input.parse() else {
        return;
    };
    match INITIATOR.initiator().initiate(&bundle) {
        Ok(_) | Err(Error::InvalidPublicKey) => {}
        Err(error) => panic!("unexpected {error:?}"),
    }
});
