// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! The 512-byte cell of PROTOCOL.md §6.1.
//!
//! Every cell on every link has this length, whatever it carries, so length
//! reveals nothing. Two of its fields — `ttl` and `copies` — are spent by the
//! relays that forward it, which is why the end-to-end associated data covers
//! the rest and leaves them out. A relay that rewrites them cannot be
//! distinguished from one that did not; §5.6 protects them hop by hop inside
//! the Noise tunnel instead.

use core::fmt;

/// Length of a cell on the wire.
pub const CELL_LEN: usize = 512;
/// The only protocol version this build speaks.
pub const VERSION: u8 = 0x01;
/// Length of the per-message epoch tag of §5.5.
pub const TAG_LEN: usize = 16;
/// Length of the XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// Length of the encrypted payload, which holds one ratchet frame.
pub const CIPHERTEXT_LEN: usize = 452;
/// Length of the Poly1305 tag over that payload.
pub const MAC_LEN: usize = 16;
/// Length of the associated data: the authenticated bytes, in wire order.
pub const AAD_LEN: usize = 42;
/// Largest hop count a cell may carry.
pub const MAX_TTL: u8 = 64;
/// Largest copy budget a cell may carry.
pub const MAX_COPIES: u8 = 15;

const VERSION_AT: usize = 0;
const FLAGS_AT: usize = 1;
const TTL_AT: usize = 2;
const COPIES_AT: usize = 3;
const TAG_AT: usize = 4;
const NONCE_AT: usize = TAG_AT + TAG_LEN;
const CIPHERTEXT_AT: usize = NONCE_AT + NONCE_LEN;
const MAC_AT: usize = CIPHERTEXT_AT + CIPHERTEXT_LEN;

/// Why a cell could not be read or built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input was not exactly [`CELL_LEN`] bytes.
    InvalidLength,
    /// The version byte named a protocol this build does not speak.
    UnsupportedVersion(u8),
    /// The hop count was above [`MAX_TTL`].
    TtlOutOfRange(u8),
    /// The copy budget was above [`MAX_COPIES`].
    CopiesOutOfRange(u8),
    /// The operating system random number generator failed.
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("a cell is exactly 512 bytes"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported version {version:#04x}"),
            Self::TtlOutOfRange(ttl) => write!(f, "ttl {ttl} above {MAX_TTL}"),
            Self::CopiesOutOfRange(copies) => write!(f, "copies {copies} above {MAX_COPIES}"),
            Self::Rng => f.write_str("random number generator unavailable"),
        }
    }
}

impl std::error::Error for Error {}

/// The authenticated head of a cell: what the sender fixes and no relay may
/// touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellHeader {
    flags: u8,
    tag: [u8; TAG_LEN],
    nonce: [u8; NONCE_LEN],
}

impl CellHeader {
    /// Builds a header around a tag and nonce, drawing the flags byte fresh.
    ///
    /// All eight flag bits are reserved and carry no meaning, so they are
    /// random: a constant byte would be a free field for a censor to match on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if the operating system random number generator
    /// fails.
    pub fn new(tag: [u8; TAG_LEN], nonce: [u8; NONCE_LEN]) -> Result<Self, Error> {
        let mut flags = [0u8; 1];
        getrandom::fill(&mut flags).map_err(|_| Error::Rng)?;
        Ok(Self {
            flags: flags[0],
            tag,
            nonce,
        })
    }

    /// The associated data an end-to-end seal over this cell must cover.
    #[must_use]
    pub fn aad(&self) -> [u8; AAD_LEN] {
        let mut aad = [0u8; AAD_LEN];
        aad[0] = VERSION;
        aad[1] = self.flags;
        aad[2..2 + TAG_LEN].copy_from_slice(&self.tag);
        aad[2 + TAG_LEN..].copy_from_slice(&self.nonce);
        aad
    }
}

/// The hop fields, spent by relays and outside the end-to-end associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hops {
    ttl: u8,
    copies: u8,
}

impl Hops {
    /// Builds a hop budget.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TtlOutOfRange`] or [`Error::CopiesOutOfRange`] if
    /// either field is above the §6.1 maximum.
    pub fn new(ttl: u8, copies: u8) -> Result<Self, Error> {
        if ttl > MAX_TTL {
            return Err(Error::TtlOutOfRange(ttl));
        }
        if copies > MAX_COPIES {
            return Err(Error::CopiesOutOfRange(copies));
        }
        Ok(Self { ttl, copies })
    }

    /// Hops this cell may still travel.
    #[must_use]
    pub fn ttl(self) -> u8 {
        self.ttl
    }

    /// Copies the carrier may still hand out.
    #[must_use]
    pub fn copies(self) -> u8 {
        self.copies
    }

    /// The same budget one hop poorer, or `None` when it is spent.
    #[must_use]
    pub fn spent(self) -> Option<Self> {
        self.ttl.checked_sub(1).map(|ttl| Self {
            ttl,
            copies: self.copies,
        })
    }
}

/// The sealed payload of a cell: one ratchet frame and its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedBody {
    /// The encrypted payload, the 452 bytes of PROTOCOL.md §6.2.
    pub ciphertext: [u8; CIPHERTEXT_LEN],
    /// The Poly1305 tag over that payload.
    pub mac: [u8; MAC_LEN],
}

/// One cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell512 {
    header: CellHeader,
    hops: Hops,
    body: SealedBody,
}

impl Cell512 {
    /// Assembles a cell from the three groups of §6.1: the authenticated head,
    /// the relay-mutable hop fields and the sealed payload.
    #[must_use]
    pub fn new(header: CellHeader, hops: Hops, body: SealedBody) -> Self {
        Self { header, hops, body }
    }

    /// Reads a cell off the wire.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] unless the input is exactly
    /// [`CELL_LEN`] bytes, [`Error::UnsupportedVersion`] for a version this
    /// build does not speak, and [`Error::TtlOutOfRange`] or
    /// [`Error::CopiesOutOfRange`] for a hop field above its maximum.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; CELL_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        if bytes[VERSION_AT] != VERSION {
            return Err(Error::UnsupportedVersion(bytes[VERSION_AT]));
        }

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[TAG_AT..NONCE_AT]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[NONCE_AT..CIPHERTEXT_AT]);
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        ciphertext.copy_from_slice(&bytes[CIPHERTEXT_AT..MAC_AT]);
        let mut mac = [0u8; MAC_LEN];
        mac.copy_from_slice(&bytes[MAC_AT..]);

        Ok(Self {
            header: CellHeader {
                flags: bytes[FLAGS_AT],
                tag,
                nonce,
            },
            hops: Hops::new(bytes[TTL_AT], bytes[COPIES_AT])?,
            body: SealedBody { ciphertext, mac },
        })
    }

    /// Writes the cell out in wire order.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CELL_LEN] {
        let mut bytes = [0u8; CELL_LEN];
        bytes[VERSION_AT] = VERSION;
        bytes[FLAGS_AT] = self.header.flags;
        bytes[TTL_AT] = self.hops.ttl;
        bytes[COPIES_AT] = self.hops.copies;
        bytes[TAG_AT..NONCE_AT].copy_from_slice(&self.header.tag);
        bytes[NONCE_AT..CIPHERTEXT_AT].copy_from_slice(&self.header.nonce);
        bytes[CIPHERTEXT_AT..MAC_AT].copy_from_slice(&self.body.ciphertext);
        bytes[MAC_AT..].copy_from_slice(&self.body.mac);
        bytes
    }

    /// The associated data of the end-to-end seal.
    #[must_use]
    pub fn aad(&self) -> [u8; AAD_LEN] {
        self.header.aad()
    }

    /// The flags byte. It carries no meaning and exists to be read only here,
    /// where the associated data is assembled.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.header.flags
    }

    /// Hops this cell may still travel.
    #[must_use]
    pub fn ttl(&self) -> u8 {
        self.hops.ttl()
    }

    /// Copies the carrier may still hand out.
    #[must_use]
    pub fn copies(&self) -> u8 {
        self.hops.copies()
    }

    /// The per-message epoch tag of §5.5.
    #[must_use]
    pub fn tag(&self) -> &[u8; TAG_LEN] {
        &self.header.tag
    }

    /// The nonce of the end-to-end seal.
    #[must_use]
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.header.nonce
    }

    /// The encrypted payload.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8; CIPHERTEXT_LEN] {
        &self.body.ciphertext
    }

    /// The Poly1305 tag over that payload.
    #[must_use]
    pub fn mac(&self) -> &[u8; MAC_LEN] {
        &self.body.mac
    }

    /// The cell a relay passes on, one hop poorer, or `None` when the hop
    /// budget is spent and the cell must be dropped.
    #[must_use]
    pub fn forwarded(&self) -> Option<Self> {
        self.hops.spent().map(|hops| Self { hops, ..*self })
    }
}
