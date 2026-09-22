// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! The 396-byte application payload of PROTOCOL.md §6.3.
//!
//! This is the plaintext a ratchet frame carries, and it has no slack: the body
//! field is always 365 bytes, filled with content and then with random bytes to
//! the end. Padding that were zeroes would hand anybody who ever sees a
//! plaintext the exact length of what was written, so it is drawn from the same
//! source as a key.
//!
//! The timestamp is rounded down to a whole minute. A millisecond reading is a
//! fingerprint of the sending device's clock and of the moment it was awake.

use core::fmt;

/// Length of a payload, which is the whole plaintext of one frame.
pub const PAYLOAD_LEN: usize = 396;
/// Offset of the body field.
pub const BODY_AT: usize = 31;
/// Length of the body field: content, then random padding.
pub const MAX_BODY_LEN: usize = 365;
/// Granularity the timestamp is rounded down to, in milliseconds.
pub const TIMESTAMP_GRANULARITY_MS: u64 = 60_000;
/// Length of the message identifier.
pub const MESSAGE_ID_LEN: usize = 16;

const MESSAGE_ID_AT: usize = 0;
const TIMESTAMP_AT: usize = 16;
const CONTENT_TYPE_AT: usize = 24;
const FRAGMENT_INDEX_AT: usize = 25;
const FRAGMENT_TOTAL_AT: usize = 27;
const BODY_LENGTH_AT: usize = 29;

/// The code point withdrawn from v1 and reserved against reuse.
const WITHDRAWN: u8 = 0x06;

/// Why a payload could not be read or built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input was not exactly [`PAYLOAD_LEN`] bytes.
    InvalidLength,
    /// The body was longer than [`MAX_BODY_LEN`].
    BodyTooLong(usize),
    /// The content type was 0x06, withdrawn from v1.
    ReservedContentType,
    /// The content type named nothing this build knows.
    UnknownContentType(u8),
    /// A fragment set of no fragments.
    EmptyFragmentSet,
    /// A fragment index at or past the size of its set.
    FragmentOutOfSet,
    /// The operating system random number generator failed.
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("a payload is exactly 396 bytes"),
            Self::BodyTooLong(len) => write!(f, "body of {len} bytes above {MAX_BODY_LEN}"),
            Self::ReservedContentType => f.write_str("content type 0x06 is withdrawn from v1"),
            Self::UnknownContentType(code) => write!(f, "unknown content type {code:#04x}"),
            Self::EmptyFragmentSet => f.write_str("a fragment set holds at least one fragment"),
            Self::FragmentOutOfSet => f.write_str("fragment index past the end of its set"),
            Self::Rng => f.write_str("random number generator unavailable"),
        }
    }
}

impl std::error::Error for Error {}

/// What the body of a payload holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// UTF-8 text.
    Text,
    /// Confirmation that a message arrived.
    DeliveryReceipt,
    /// Confirmation that a message was read.
    ReadReceipt,
    /// A contact's public bundle.
    ContactBundle,
    /// One fragment of a file.
    FileFragment,
    /// The opening message of a session.
    SessionInit,
    /// A request to resynchronise epoch tags.
    TagResync,
    /// Cover traffic, addressed to the sender and discarded on arrival.
    Decoy,
}

impl ContentType {
    /// The code point of §6.3.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Text => 0x01,
            Self::DeliveryReceipt => 0x02,
            Self::ReadReceipt => 0x03,
            Self::ContactBundle => 0x04,
            Self::FileFragment => 0x05,
            Self::SessionInit => 0x07,
            Self::TagResync => 0x08,
            Self::Decoy => 0xFF,
        }
    }

    /// Reads a code point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReservedContentType`] for 0x06, which v1 withdrew and
    /// which must stay unusable so a later version can spend it, and
    /// [`Error::UnknownContentType`] for anything else unassigned.
    pub fn from_code(code: u8) -> Result<Self, Error> {
        match code {
            0x01 => Ok(Self::Text),
            0x02 => Ok(Self::DeliveryReceipt),
            0x03 => Ok(Self::ReadReceipt),
            0x04 => Ok(Self::ContactBundle),
            0x05 => Ok(Self::FileFragment),
            WITHDRAWN => Err(Error::ReservedContentType),
            0x07 => Ok(Self::SessionInit),
            0x08 => Ok(Self::TagResync),
            0xFF => Ok(Self::Decoy),
            _ => Err(Error::UnknownContentType(code)),
        }
    }
}

/// Where a payload sits in the set of payloads that carry one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    index: u16,
    total: u16,
}

impl Fragment {
    /// Places a fragment in its set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyFragmentSet`] for a set of no fragments and
    /// [`Error::FragmentOutOfSet`] for an index at or past its end.
    pub fn new(index: u16, total: u16) -> Result<Self, Error> {
        if total == 0 {
            return Err(Error::EmptyFragmentSet);
        }
        if index >= total {
            return Err(Error::FragmentOutOfSet);
        }
        Ok(Self { index, total })
    }

    /// This fragment's place in its set.
    #[must_use]
    pub fn index(self) -> u16 {
        self.index
    }

    /// How many fragments the whole message takes.
    #[must_use]
    pub fn total(self) -> u16 {
        self.total
    }
}

/// One application payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Payload {
    message_id: [u8; MESSAGE_ID_LEN],
    timestamp_ms: u64,
    content_type: ContentType,
    fragment: Fragment,
    body_length: u16,
    body: [u8; MAX_BODY_LEN],
}

impl fmt::Debug for Payload {
    /// Prints everything but the body, which is the part worth not printing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("message_id", &self.message_id)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("content_type", &self.content_type)
            .field("fragment", &self.fragment)
            .field("body_length", &self.body_length)
            .finish_non_exhaustive()
    }
}

impl Payload {
    /// Builds a payload around a body, drawing a fresh message identifier and
    /// filling the rest of the body field with random padding.
    ///
    /// `clock_ms` is a millisecond reading; the payload keeps it rounded down
    /// to [`TIMESTAMP_GRANULARITY_MS`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::BodyTooLong`] for a body above [`MAX_BODY_LEN`] and
    /// [`Error::Rng`] if the operating system random number generator fails.
    pub fn new(
        content_type: ContentType,
        fragment: Fragment,
        clock_ms: u64,
        body: &[u8],
    ) -> Result<Self, Error> {
        let body_length = u16::try_from(body.len()).map_err(|_| Error::BodyTooLong(body.len()))?;
        if body.len() > MAX_BODY_LEN {
            return Err(Error::BodyTooLong(body.len()));
        }

        let mut message_id = [0u8; MESSAGE_ID_LEN];
        getrandom::fill(&mut message_id).map_err(|_| Error::Rng)?;

        let mut filled = [0u8; MAX_BODY_LEN];
        getrandom::fill(&mut filled).map_err(|_| Error::Rng)?;
        filled[..body.len()].copy_from_slice(body);

        Ok(Self {
            message_id,
            timestamp_ms: clock_ms - clock_ms % TIMESTAMP_GRANULARITY_MS,
            content_type,
            fragment,
            body_length,
            body: filled,
        })
    }

    /// Builds one cover payload: a whole body field of random bytes, which is
    /// what a payload of any other kind also looks like once sealed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if the operating system random number generator
    /// fails.
    pub fn decoy(clock_ms: u64) -> Result<Self, Error> {
        Self::new(ContentType::Decoy, Fragment::new(0, 1)?, clock_ms, &[])
    }

    /// Reads a payload out of a decrypted frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] unless the input is exactly
    /// [`PAYLOAD_LEN`] bytes, [`Error::BodyTooLong`] for a body length past the
    /// field, and the content-type and fragment errors of [`ContentType`] and
    /// [`Fragment`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; PAYLOAD_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;

        let body_length = u16::from_le_bytes([bytes[BODY_LENGTH_AT], bytes[BODY_LENGTH_AT + 1]]);
        if usize::from(body_length) > MAX_BODY_LEN {
            return Err(Error::BodyTooLong(usize::from(body_length)));
        }

        let mut message_id = [0u8; MESSAGE_ID_LEN];
        message_id.copy_from_slice(&bytes[MESSAGE_ID_AT..TIMESTAMP_AT]);
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&bytes[TIMESTAMP_AT..CONTENT_TYPE_AT]);
        let mut body = [0u8; MAX_BODY_LEN];
        body.copy_from_slice(&bytes[BODY_AT..]);

        Ok(Self {
            message_id,
            timestamp_ms: u64::from_le_bytes(timestamp),
            content_type: ContentType::from_code(bytes[CONTENT_TYPE_AT])?,
            fragment: Fragment::new(
                u16::from_le_bytes([bytes[FRAGMENT_INDEX_AT], bytes[FRAGMENT_INDEX_AT + 1]]),
                u16::from_le_bytes([bytes[FRAGMENT_TOTAL_AT], bytes[FRAGMENT_TOTAL_AT + 1]]),
            )?,
            body_length,
            body,
        })
    }

    /// Writes the payload out in wire order, padding included.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PAYLOAD_LEN] {
        let mut bytes = [0u8; PAYLOAD_LEN];
        bytes[MESSAGE_ID_AT..TIMESTAMP_AT].copy_from_slice(&self.message_id);
        bytes[TIMESTAMP_AT..CONTENT_TYPE_AT].copy_from_slice(&self.timestamp_ms.to_le_bytes());
        bytes[CONTENT_TYPE_AT] = self.content_type.code();
        bytes[FRAGMENT_INDEX_AT..FRAGMENT_TOTAL_AT]
            .copy_from_slice(&self.fragment.index.to_le_bytes());
        bytes[FRAGMENT_TOTAL_AT..BODY_LENGTH_AT]
            .copy_from_slice(&self.fragment.total.to_le_bytes());
        bytes[BODY_LENGTH_AT..BODY_AT].copy_from_slice(&self.body_length.to_le_bytes());
        bytes[BODY_AT..].copy_from_slice(&self.body);
        bytes
    }

    /// The random identifier of the message this payload belongs to.
    #[must_use]
    pub fn message_id(&self) -> &[u8; MESSAGE_ID_LEN] {
        &self.message_id
    }

    /// When the message was written, to the minute.
    #[must_use]
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// What the body holds.
    #[must_use]
    pub fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Where this payload sits among the payloads of its message.
    #[must_use]
    pub fn fragment(&self) -> Fragment {
        self.fragment
    }

    /// The content, without the padding that follows it.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body[..usize::from(self.body_length)]
    }
}
