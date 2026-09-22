// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Session establishment: hybrid post-quantum X3DH (plan §5.3).
//!
//! Verifying the signature over a [`PrekeyBundle`] belongs to contact
//! establishment (§5.2) and happens before a bundle reaches this module.

use std::iter;

use quietwire_crypto::{
    ed25519::VerifyingKey,
    hash,
    kdf::hkdf_sha512,
    mlkem::{Ciphertext, DecapsulationKey, EncapsulationKey},
    x25519::{PrivateKey, PublicKey},
    Error, SecretKey,
};
use zeroize::Zeroizing;

/// Length of the shared key `SK` in bytes.
pub const SHARED_KEY_LEN: usize = 32;

const TRANSCRIPT_CONTEXT: &str = "QUIETWIRE-X3DH-TRANSCRIPT-v1";
const HYBRID_INFO: &[u8] = b"QUIETWIRE-X3DH-HYBRID-v1";
const CURVE25519_PREFIX: [u8; 32] = [0xFF; 32];

/// The three public identity keys of a party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPublic {
    /// `IK_sign_pub`.
    pub sign: VerifyingKey,
    /// `IK_dh_pub`.
    pub dh: PublicKey,
    /// `PQ_kem_pub`.
    pub kem: EncapsulationKey,
}

impl IdentityPublic {
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.sign.to_bytes()[..],
            self.dh.as_bytes(),
            &self.kem.to_bytes(),
        ]
        .concat()
    }
}

/// The responder keys an initiator needs, as published in a contact QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeyBundle {
    /// The responder's identity.
    pub identity: IdentityPublic,
    /// `SPK_pub`.
    pub signed_prekey: PublicKey,
    /// `OPK_pub`, when one was left.
    pub one_time_prekey: Option<PublicKey>,
}

/// What the initiator sends so that the responder can derive the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialMessage {
    /// `EK_pub`.
    pub ephemeral: PublicKey,
    /// `CT_pq`.
    pub kem_ciphertext: Ciphertext,
}

/// The party that starts a session from a [`PrekeyBundle`].
pub struct Initiator<'a> {
    /// Its public identity.
    pub identity: &'a IdentityPublic,
    /// `IK_dh_priv`.
    pub identity_dh: &'a PrivateKey,
}

impl Initiator<'_> {
    /// Derives `SK` with a fresh ephemeral key, which is wiped on return, and
    /// the message the responder needs to derive it too.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if a bundle key is a low-order point, and
    /// [`Error::Rng`] if the RNG fails.
    pub fn initiate(&self, bundle: &PrekeyBundle) -> Result<(SecretKey, InitialMessage), Error> {
        let ephemeral = PrivateKey::generate()?;
        let encapsulation = bundle.identity.kem.encapsulate()?;
        self.initiate_with(bundle, &ephemeral, encapsulation)
    }

    fn initiate_with(
        &self,
        bundle: &PrekeyBundle,
        ephemeral: &PrivateKey,
        (kem_ciphertext, kem_shared): (Ciphertext, SecretKey),
    ) -> Result<(SecretKey, InitialMessage), Error> {
        let message = InitialMessage {
            ephemeral: ephemeral.public_key(),
            kem_ciphertext,
        };
        let mut secrets = vec![
            self.identity_dh.diffie_hellman(&bundle.signed_prekey)?,
            ephemeral.diffie_hellman(&bundle.identity.dh)?,
            ephemeral.diffie_hellman(&bundle.signed_prekey)?,
        ];
        if let Some(one_time_prekey) = &bundle.one_time_prekey {
            secrets.push(ephemeral.diffie_hellman(one_time_prekey)?);
        }
        secrets.push(kem_shared);
        let transcript = transcript(self.identity, bundle, &message);
        Ok((derive_shared_key(&secrets, &transcript)?, message))
    }
}

/// The party whose [`PrekeyBundle`] a session is started from.
pub struct Responder<'a> {
    /// Its public identity.
    pub identity: &'a IdentityPublic,
    /// `IK_dh_priv`.
    pub identity_dh: &'a PrivateKey,
    /// `PQ_kem_priv`.
    pub kem: &'a DecapsulationKey,
    /// `SPK_priv`.
    pub signed_prekey: &'a PrivateKey,
    /// `OPK_priv`, when the initiator used one.
    pub one_time_prekey: Option<&'a PrivateKey>,
}

impl Responder<'_> {
    /// The bundle these keys answer to.
    #[must_use]
    pub fn bundle(&self) -> PrekeyBundle {
        PrekeyBundle {
            identity: self.identity.clone(),
            signed_prekey: self.signed_prekey.public_key(),
            one_time_prekey: self.one_time_prekey.map(PrivateKey::public_key),
        }
    }

    /// Derives the `SK` that `initiator` derived when it sent `message`.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if an initiator key is a low-order point.
    pub fn respond(
        &self,
        initiator: &IdentityPublic,
        message: &InitialMessage,
    ) -> Result<SecretKey, Error> {
        let mut secrets = vec![
            self.signed_prekey.diffie_hellman(&initiator.dh)?,
            self.identity_dh.diffie_hellman(&message.ephemeral)?,
            self.signed_prekey.diffie_hellman(&message.ephemeral)?,
        ];
        if let Some(one_time_prekey) = self.one_time_prekey {
            secrets.push(one_time_prekey.diffie_hellman(&message.ephemeral)?);
        }
        secrets.push(self.kem.decapsulate(&message.kem_ciphertext));
        derive_shared_key(&secrets, &transcript(initiator, &self.bundle(), message))
    }
}

fn transcript(
    initiator: &IdentityPublic,
    bundle: &PrekeyBundle,
    message: &InitialMessage,
) -> Zeroizing<[u8; 32]> {
    let one_time_prekey = bundle
        .one_time_prekey
        .as_ref()
        .map_or(&[][..], |key| key.as_bytes());
    let bytes = [
        &initiator.to_bytes()[..],
        &bundle.identity.to_bytes(),
        message.ephemeral.as_bytes(),
        bundle.signed_prekey.as_bytes(),
        one_time_prekey,
        message.kem_ciphertext.as_bytes(),
    ]
    .concat();
    hash::derive_key(TRANSCRIPT_CONTEXT, &bytes)
}

/// `secrets` are `DH1..DH4` followed by `SS_pq`.
fn derive_shared_key(secrets: &[SecretKey], transcript: &[u8; 32]) -> Result<SecretKey, Error> {
    let parts: Vec<&[u8]> = iter::once(&CURVE25519_PREFIX[..])
        .chain(secrets.iter().map(|secret| &secret.expose_secret()[..]))
        .collect();
    let ikm = Zeroizing::new(parts.concat());
    let okm = hkdf_sha512(&ikm, transcript, HYBRID_INFO, SHARED_KEY_LEN)?;
    SecretKey::from_slice(&okm)
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::support::{hex, x3dh_cases};
    use super::*;

    #[test]
    fn initiator_matches_every_independent_vector() {
        let cases = x3dh_cases();
        assert_eq!(cases.len(), 2);

        for case in cases {
            let identity = case.initiator.identity();
            let initiator = Initiator {
                identity: &identity,
                identity_dh: &case.initiator.identity_dh(),
            };
            let bundle = case.bundle();

            let (shared, message) = initiator
                .initiate_with(&bundle, &case.ephemeral(), case.encapsulation())
                .unwrap();

            assert_eq!(message, case.message(), "{}", case.name);
            assert_eq!(
                transcript(&identity, &bundle, &message).to_vec(),
                hex(&case.transcript),
                "{}",
                case.name
            );
            assert_eq!(
                shared.expose_secret().to_vec(),
                hex(&case.shared_key),
                "{}",
                case.name
            );
        }
    }
}
