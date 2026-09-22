// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Keys and sessions shared by the fuzz targets.
//!
//! Most random bytes are not valid ML-KEM or Ed25519 public keys, so targets
//! reach the code past the parsers by editing genuine keys instead.

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use quietwire_crypto::{
    ed25519::{SigningKey, VerifyingKey, VERIFYING_KEY_LEN},
    mlkem::{DecapsulationKey, EncapsulationKey, ENCAPSULATION_KEY_LEN},
    x25519::{PrivateKey, PublicKey, PUBLIC_KEY_LEN},
    SecretKey,
};
use quietwire_e2e::{
    ratchet::Session,
    x3dh::{IdentityPublic, Initiator, Responder},
};

static GENUINE_KEM: LazyLock<EncapsulationKey> = LazyLock::new(|| {
    DecapsulationKey::generate()
        .expect("RNG")
        .encapsulation_key()
});

/// An identity as a peer sends it, before parsing.
#[derive(Arbitrary, Debug)]
pub struct PeerIdentity {
    sign: [u8; VERIFYING_KEY_LEN],
    dh: [u8; PUBLIC_KEY_LEN],
    kem: KemKey,
}

impl PeerIdentity {
    /// The identity, or `None` when a key does not parse.
    #[must_use]
    pub fn parse(&self) -> Option<IdentityPublic> {
        Some(IdentityPublic {
            sign: VerifyingKey::from_bytes(&self.sign).ok()?,
            dh: PublicKey::from_bytes(self.dh),
            kem: EncapsulationKey::from_bytes(&self.kem.to_bytes()).ok()?,
        })
    }
}

#[derive(Arbitrary, Debug)]
enum KemKey {
    Genuine(Vec<Edit>),
    Raw(Box<[u8; ENCAPSULATION_KEY_LEN]>),
}

impl KemKey {
    fn to_bytes(&self) -> [u8; ENCAPSULATION_KEY_LEN] {
        match self {
            Self::Genuine(edits) => edited(GENUINE_KEM.to_bytes(), edits),
            Self::Raw(bytes) => **bytes,
        }
    }
}

/// One byte of an input XOR-ed with a value.
#[derive(Arbitrary, Debug, Clone, Copy)]
pub struct Edit {
    at: u16,
    xor: u8,
}

/// `bytes` with every edit applied, wrapping positions past the end.
#[must_use]
pub fn edited<const N: usize>(mut bytes: [u8; N], edits: &[Edit]) -> [u8; N] {
    for edit in edits {
        bytes[usize::from(edit.at) % N] ^= edit.xor;
    }
    bytes
}

/// Every private key an X3DH party holds, with its public identity.
pub struct Party {
    identity: IdentityPublic,
    identity_dh: PrivateKey,
    kem: DecapsulationKey,
    signed_prekey: PrivateKey,
    one_time_prekey: PrivateKey,
}

impl Party {
    /// A party with fresh keys.
    ///
    /// # Panics
    /// If the operating system RNG fails.
    #[must_use]
    pub fn generate() -> Self {
        let identity_dh = PrivateKey::generate().expect("RNG");
        let kem = DecapsulationKey::generate().expect("RNG");
        Self {
            identity: IdentityPublic {
                sign: SigningKey::generate().expect("RNG").verifying_key(),
                dh: identity_dh.public_key(),
                kem: kem.encapsulation_key(),
            },
            identity_dh,
            kem,
            signed_prekey: PrivateKey::generate().expect("RNG"),
            one_time_prekey: PrivateKey::generate().expect("RNG"),
        }
    }

    /// The party starting a session.
    #[must_use]
    pub fn initiator(&self) -> Initiator<'_> {
        Initiator {
            identity: &self.identity,
            identity_dh: &self.identity_dh,
        }
    }

    /// The party answering a session, with or without its one-time prekey.
    #[must_use]
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

/// The two sessions of a conversation, as X3DH would have started them.
pub struct Conversation {
    /// The initiator, which can send at once.
    pub alice: Session,
    /// The responder, which can send once it has received a frame.
    pub bob: Session,
}

impl Conversation {
    /// Starts both sessions from a fixed shared key and a fresh signed prekey.
    ///
    /// # Panics
    /// If the operating system RNG fails.
    #[must_use]
    pub fn start() -> Self {
        const SHARED_KEY: [u8; 32] = [0x42; 32];
        let signed_prekey = PrivateKey::generate().expect("RNG");
        let remote_ratchet: PublicKey = signed_prekey.public_key();
        let shared_key = || SecretKey::from_slice(&SHARED_KEY).expect("32 bytes");
        Self {
            alice: Session::initiator(&shared_key(), remote_ratchet).expect("valid prekey"),
            bob: Session::responder(shared_key(), signed_prekey),
        }
    }
}
