// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Message encryption: the Double Ratchet (plan §5.4) over the fixed
//! 452-byte frame of §6.2.
//!
//! A session only changes when a frame authenticates: a forged, replayed or
//! truncated frame leaves it exactly as it was.

use std::{collections::VecDeque, fmt};

use quietwire_crypto::{
    aead::{self, Nonce, TAG_LEN},
    kdf::{hkdf_sha512, hmac_sha512},
    x25519::{PrivateKey, PublicKey, PUBLIC_KEY_LEN},
    SecretKey,
};
use zeroize::Zeroizing;

/// Length of the cleartext ratchet header at the start of a frame.
pub const HEADER_LEN: usize = PUBLIC_KEY_LEN + 4 + 4;
/// Length of the plaintext a frame carries.
pub const PLAINTEXT_LEN: usize = 396;
/// Length of a frame: header, ciphertext and tag.
pub const FRAME_LEN: usize = HEADER_LEN + PLAINTEXT_LEN + TAG_LEN;

const KEY_LEN: usize = 32;
const CHAIN_LIMIT: u32 = 2000;
const MAX_SKIP_PER_CHAIN: u32 = 1000;
const MAX_SKIPPED_TOTAL: usize = 10_000;
const ROOT_INFO: &[u8] = b"QUIETWIRE-ROOT-v1";
const MESSAGE_KEY_INPUT: &[u8] = &[0x01];
const CHAIN_KEY_INPUT: &[u8] = &[0x02];

type Key = Zeroizing<[u8; KEY_LEN]>;

/// Why a frame could not be sent or received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A primitive failed. [`quietwire_crypto::Error::Authentication`] also
    /// covers a frame whose key is gone: a replay, or one older than the
    /// skipped keys kept.
    Crypto(quietwire_crypto::Error),
    /// There is no sending chain yet, or it has reached the chain limit;
    /// sending resumes once a frame from the peer is received.
    SendingBlocked,
    /// The header asks for more skipped keys than one chain may hold.
    TooFarAhead,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => error.fmt(formatter),
            Self::SendingBlocked => {
                formatter.write_str("sending is blocked until the peer replies")
            }
            Self::TooFarAhead => formatter.write_str("frame is too far ahead of its chain"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::SendingBlocked | Self::TooFarAhead => None,
        }
    }
}

impl From<quietwire_crypto::Error> for Error {
    fn from(error: quietwire_crypto::Error) -> Self {
        Self::Crypto(error)
    }
}

/// An encrypted frame and the nonce it was sealed with.
///
/// The nonce is not part of the frame: the cell carries it (§6.1) and reuses
/// it under its own, independent key (ADR-0020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFrame {
    /// The random nonce.
    pub nonce: Nonce,
    /// Ratchet header, ciphertext and tag.
    pub frame: [u8; FRAME_LEN],
}

/// One side of a Double Ratchet session.
pub struct Session {
    root_key: SecretKey,
    own_ratchet: PrivateKey,
    remote_ratchet: Option<PublicKey>,
    sending: Option<Chain>,
    receiving: Option<Chain>,
    previous_sending_len: u32,
    skipped: SkippedKeys,
}

impl Session {
    /// Starts the session of the X3DH initiator, whose first ratchet step is
    /// against the responder's signed prekey.
    ///
    /// # Errors
    /// [`quietwire_crypto::Error::InvalidPublicKey`] if `remote_ratchet` is a
    /// low-order point, and [`quietwire_crypto::Error::Rng`] if the RNG fails.
    pub fn initiator(shared_key: &SecretKey, remote_ratchet: PublicKey) -> Result<Self, Error> {
        Self::initiator_with(shared_key, remote_ratchet, PrivateKey::generate()?)
    }

    fn initiator_with(
        shared_key: &SecretKey,
        remote_ratchet: PublicKey,
        own_ratchet: PrivateKey,
    ) -> Result<Self, Error> {
        let (root_key, sending) = kdf_root(shared_key, &own_ratchet, &remote_ratchet)?;
        Ok(Self {
            root_key,
            own_ratchet,
            remote_ratchet: Some(remote_ratchet),
            sending: Some(Chain::start(&sending)?),
            receiving: None,
            previous_sending_len: 0,
            skipped: SkippedKeys::default(),
        })
    }

    /// Starts the session of the X3DH responder, whose signed prekey is its
    /// first ratchet key. It can send once it has received a frame.
    #[must_use]
    pub fn responder(shared_key: SecretKey, signed_prekey: PrivateKey) -> Self {
        Self {
            root_key: shared_key,
            own_ratchet: signed_prekey,
            remote_ratchet: None,
            sending: None,
            receiving: None,
            previous_sending_len: 0,
            skipped: SkippedKeys::default(),
        }
    }

    /// Encrypts `plaintext` under the next message key and a fresh nonce.
    ///
    /// # Errors
    /// [`Error::SendingBlocked`] before the responder has received a frame or
    /// after 2 000 frames without a reply, and
    /// [`quietwire_crypto::Error::Rng`] if the RNG fails.
    pub fn encrypt(&mut self, plaintext: &[u8; PLAINTEXT_LEN]) -> Result<SealedFrame, Error> {
        self.encrypt_with(Nonce::random()?, plaintext)
    }

    fn encrypt_with(
        &mut self,
        nonce: Nonce,
        plaintext: &[u8; PLAINTEXT_LEN],
    ) -> Result<SealedFrame, Error> {
        let chain = self.sending.as_ref().ok_or(Error::SendingBlocked)?;
        if chain.next >= CHAIN_LIMIT {
            return Err(Error::SendingBlocked);
        }
        let header = Header {
            ratchet: self.own_ratchet.public_key(),
            previous_chain_len: self.previous_sending_len,
            message_number: chain.next,
        }
        .to_bytes();
        let mut cursor = Cursor::at(chain);
        let message_key = SecretKey::from_slice(&cursor.next_message_key()[..])?;
        let sealed = aead::seal(&message_key, &nonce, &header, plaintext)?;

        let mut frame = [0; FRAME_LEN];
        frame[..HEADER_LEN].copy_from_slice(&header);
        frame[HEADER_LEN..].copy_from_slice(&sealed);
        self.sending = Some(cursor.into_chain()?);
        Ok(SealedFrame { nonce, frame })
    }

    /// Decrypts a frame from the peer, taking a DH ratchet step when it
    /// carries a new ratchet key.
    ///
    /// # Errors
    /// [`quietwire_crypto::Error::Authentication`] if the frame was forged or
    /// its key is gone, [`Error::TooFarAhead`] if it would skip too many keys,
    /// [`quietwire_crypto::Error::InvalidPublicKey`] if its ratchet key is a
    /// low-order point and [`quietwire_crypto::Error::Rng`] if the RNG fails.
    pub fn decrypt(
        &mut self,
        sealed: &SealedFrame,
    ) -> Result<Zeroizing<[u8; PLAINTEXT_LEN]>, Error> {
        self.decrypt_with(sealed, PrivateKey::generate)
    }

    fn decrypt_with(
        &mut self,
        sealed: &SealedFrame,
        next_ratchet: impl FnOnce() -> Result<PrivateKey, quietwire_crypto::Error>,
    ) -> Result<Zeroizing<[u8; PLAINTEXT_LEN]>, Error> {
        let header = Header::parse(&sealed.frame);
        if let Some(index) = self.skipped.position(&header) {
            let plaintext = open(self.skipped.key(index), sealed)?;
            self.skipped.remove(index);
            return Ok(plaintext);
        }
        if self.remote_ratchet == Some(header.ratchet) {
            self.decrypt_in_receiving_chain(&header, sealed)
        } else {
            self.decrypt_after_ratchet_step(&header, sealed, next_ratchet)
        }
    }

    fn decrypt_in_receiving_chain(
        &mut self,
        header: &Header,
        sealed: &SealedFrame,
    ) -> Result<Zeroizing<[u8; PLAINTEXT_LEN]>, Error> {
        let chain = self
            .receiving
            .as_ref()
            .ok_or(quietwire_crypto::Error::Authentication)?;
        let mut cursor = Cursor::at(chain);
        let plaintext = open(&cursor.message_key(header.message_number)?, sealed)?;

        self.skipped.extend(header.ratchet, cursor.take_skipped());
        self.receiving = Some(cursor.into_chain()?);
        Ok(plaintext)
    }

    fn decrypt_after_ratchet_step(
        &mut self,
        header: &Header,
        sealed: &SealedFrame,
        next_ratchet: impl FnOnce() -> Result<PrivateKey, quietwire_crypto::Error>,
    ) -> Result<Zeroizing<[u8; PLAINTEXT_LEN]>, Error> {
        let mut previous = self.receiving.as_ref().map(Cursor::at);
        if let Some(cursor) = &mut previous {
            cursor.skip_to(header.previous_chain_len)?;
        }
        let (root_key, receiving) = kdf_root(&self.root_key, &self.own_ratchet, &header.ratchet)?;
        let own_ratchet = next_ratchet()?;
        let (root_key, sending) = kdf_root(&root_key, &own_ratchet, &header.ratchet)?;
        let mut cursor = Cursor::new(receiving);
        let plaintext = open(&cursor.message_key(header.message_number)?, sealed)?;

        if let (Some(mut previous), Some(remote)) = (previous, self.remote_ratchet) {
            self.skipped.extend(remote, previous.take_skipped());
        }
        self.skipped.extend(header.ratchet, cursor.take_skipped());
        self.root_key = root_key;
        self.own_ratchet = own_ratchet;
        self.remote_ratchet = Some(header.ratchet);
        self.previous_sending_len = self.sending.as_ref().map_or(0, |chain| chain.next);
        self.sending = Some(Chain::start(&sending)?);
        self.receiving = Some(cursor.into_chain()?);
        Ok(plaintext)
    }
}

struct Header {
    ratchet: PublicKey,
    previous_chain_len: u32,
    message_number: u32,
}

impl Header {
    const PREVIOUS_CHAIN_LEN: usize = PUBLIC_KEY_LEN;
    const MESSAGE_NUMBER: usize = PUBLIC_KEY_LEN + 4;

    fn parse(frame: &[u8; FRAME_LEN]) -> Self {
        Self {
            ratchet: PublicKey::from_bytes(array(&frame[..Self::PREVIOUS_CHAIN_LEN])),
            previous_chain_len: u32::from_le_bytes(array(
                &frame[Self::PREVIOUS_CHAIN_LEN..Self::MESSAGE_NUMBER],
            )),
            message_number: u32::from_le_bytes(array(&frame[Self::MESSAGE_NUMBER..HEADER_LEN])),
        }
    }

    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..Self::PREVIOUS_CHAIN_LEN].copy_from_slice(self.ratchet.as_bytes());
        bytes[Self::PREVIOUS_CHAIN_LEN..Self::MESSAGE_NUMBER]
            .copy_from_slice(&self.previous_chain_len.to_le_bytes());
        bytes[Self::MESSAGE_NUMBER..].copy_from_slice(&self.message_number.to_le_bytes());
        bytes
    }
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut array = [0; N];
    array.copy_from_slice(bytes);
    array
}

struct Chain {
    key: SecretKey,
    next: u32,
}

impl Chain {
    fn start(key: &Key) -> Result<Self, Error> {
        Ok(Self {
            key: SecretKey::from_slice(&key[..])?,
            next: 0,
        })
    }
}

/// A chain being advanced; nothing reaches the session until it is turned
/// back into a [`Chain`].
struct Cursor {
    key: Key,
    next: u32,
    skipped: Vec<(u32, Key)>,
}

impl Cursor {
    fn new(key: Key) -> Self {
        Self {
            key,
            next: 0,
            skipped: Vec::new(),
        }
    }

    fn at(chain: &Chain) -> Self {
        Self {
            next: chain.next,
            ..Self::new(Zeroizing::new(*chain.key.expose_secret()))
        }
    }

    fn skip_to(&mut self, until: u32) -> Result<(), Error> {
        if until > CHAIN_LIMIT || until.saturating_sub(self.next) > MAX_SKIP_PER_CHAIN {
            return Err(Error::TooFarAhead);
        }
        while self.next < until {
            let number = self.next;
            let key = self.next_message_key();
            self.skipped.push((number, key));
        }
        Ok(())
    }

    fn message_key(&mut self, number: u32) -> Result<Key, Error> {
        if number >= CHAIN_LIMIT {
            return Err(Error::TooFarAhead);
        }
        if number < self.next {
            return Err(quietwire_crypto::Error::Authentication.into());
        }
        self.skip_to(number)?;
        Ok(self.next_message_key())
    }

    fn next_message_key(&mut self) -> Key {
        let (message_key, chain_key) = kdf_chain(&self.key);
        self.key = chain_key;
        self.next += 1;
        message_key
    }

    fn take_skipped(&mut self) -> Vec<(u32, Key)> {
        std::mem::take(&mut self.skipped)
    }

    fn into_chain(self) -> Result<Chain, Error> {
        Ok(Chain {
            key: SecretKey::from_slice(&self.key[..])?,
            next: self.next,
        })
    }
}

/// Message keys of frames that have not arrived yet, oldest first. They are
/// kept outside [`SecretKey`] because up to ten thousand of them may be held.
#[derive(Default)]
struct SkippedKeys(VecDeque<SkippedKey>);

struct SkippedKey {
    ratchet: PublicKey,
    number: u32,
    key: Key,
}

impl SkippedKeys {
    fn position(&self, header: &Header) -> Option<usize> {
        self.0.iter().position(|skipped| {
            skipped.ratchet == header.ratchet && skipped.number == header.message_number
        })
    }

    fn key(&self, index: usize) -> &Key {
        &self.0[index].key
    }

    fn remove(&mut self, index: usize) {
        self.0.remove(index);
    }

    fn extend(&mut self, ratchet: PublicKey, keys: Vec<(u32, Key)>) {
        self.0
            .extend(keys.into_iter().map(|(number, key)| SkippedKey {
                ratchet,
                number,
                key,
            }));
        self.evict_oldest_of_chain(ratchet);
        while self.0.len() > MAX_SKIPPED_TOTAL {
            self.0.pop_front();
        }
    }

    fn evict_oldest_of_chain(&mut self, ratchet: PublicKey) {
        let in_chain = self
            .0
            .iter()
            .filter(|skipped| skipped.ratchet == ratchet)
            .count();
        let mut excess = in_chain.saturating_sub(MAX_SKIP_PER_CHAIN as usize);
        self.0.retain(|skipped| {
            let evicted = excess > 0 && skipped.ratchet == ratchet;
            excess -= usize::from(evicted);
            !evicted
        });
    }
}

fn open(message_key: &Key, sealed: &SealedFrame) -> Result<Zeroizing<[u8; PLAINTEXT_LEN]>, Error> {
    let key = SecretKey::from_slice(&message_key[..])?;
    let (header, ciphertext) = sealed.frame.split_at(HEADER_LEN);
    let opened = aead::open(&key, &sealed.nonce, header, ciphertext)?;
    let mut plaintext = Zeroizing::new([0; PLAINTEXT_LEN]);
    plaintext.copy_from_slice(&opened);
    Ok(plaintext)
}

/// Returns the next root key and a new chain key.
fn kdf_root(
    root_key: &SecretKey,
    own: &PrivateKey,
    remote: &PublicKey,
) -> Result<(SecretKey, Key), Error> {
    let shared = own.diffie_hellman(remote)?;
    let out = hkdf_sha512(
        shared.expose_secret(),
        root_key.expose_secret(),
        ROOT_INFO,
        2 * KEY_LEN,
    )?;
    let (next_root_key, chain_key) = out.split_at(KEY_LEN);
    Ok((
        SecretKey::from_slice(next_root_key)?,
        Zeroizing::new(array(chain_key)),
    ))
}

/// Returns the message key and the next chain key.
fn kdf_chain(chain_key: &Key) -> (Key, Key) {
    let derive = |input| Zeroizing::new(array(&hmac_sha512(&chain_key[..], input)[..KEY_LEN]));
    (derive(MESSAGE_KEY_INPUT), derive(CHAIN_KEY_INPUT))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{PrivateKey, SealedFrame, Session};
    use crate::support::{ratchet_case, RatchetStep, Sender};

    struct Party {
        session: Session,
        ratchet_keys: VecDeque<PrivateKey>,
    }

    impl Party {
        fn receive(&mut self, sealed: &SealedFrame) -> [u8; super::PLAINTEXT_LEN] {
            let keys = &mut self.ratchet_keys;
            let next_ratchet = || Ok(keys.pop_front().unwrap());
            *self.session.decrypt_with(sealed, next_ratchet).unwrap()
        }
    }

    #[test]
    fn sessions_match_the_independent_vector() {
        let case = ratchet_case();
        let mut initiator_keys = VecDeque::from(case.initiator_ratchet_keys());
        let mut responder_keys = VecDeque::from(case.responder_ratchet_keys());
        let signed_prekey = responder_keys.pop_front().unwrap();
        let signed_prekey_public = signed_prekey.public_key();
        let mut responder = Party {
            session: Session::responder(case.shared_key(), signed_prekey),
            ratchet_keys: responder_keys,
        };
        let initial_ratchet = initiator_keys.pop_front().unwrap();
        let mut initiator = Party {
            session: Session::initiator_with(
                &case.shared_key(),
                signed_prekey_public,
                initial_ratchet,
            )
            .unwrap(),
            ratchet_keys: initiator_keys,
        };

        for step in &case.steps {
            let (RatchetStep::Send(name) | RatchetStep::Receive(name)) = step;
            let message = case.message(name);
            let (sender, receiver) = match message.sender {
                Sender::Initiator => (&mut initiator, &mut responder),
                Sender::Responder => (&mut responder, &mut initiator),
            };
            match step {
                RatchetStep::Send(_) => {
                    let sealed = sender
                        .session
                        .encrypt_with(message.nonce(), &message.plaintext())
                        .unwrap();
                    assert_eq!(sealed, message.sealed(), "{name}");
                }
                RatchetStep::Receive(_) => {
                    assert_eq!(
                        receiver.receive(&message.sealed()),
                        message.plaintext(),
                        "{name}"
                    );
                }
            }
        }
        assert!(initiator.ratchet_keys.is_empty() && responder.ratchet_keys.is_empty());
    }
}
