// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

use std::{mem, ptr};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{rng, Error};

pub(crate) const KEY_LEN: usize = 32;

#[repr(C, align(16384))]
struct DedicatedPage([u8; KEY_LEN]);

const DEDICATED_PAGE_SIZE: usize = mem::size_of::<DedicatedPage>();

/// A 32-byte symmetric key for long-lived secrets.
///
/// Each key sits alone at the start of its own 16 KiB-aligned allocation, is
/// locked in RAM when the operating system allows it and is wiped on drop.
/// It has no `Debug`, `Display` or `Clone`, and compares in constant time.
pub struct SecretKey {
    ram_lock: Option<region::LockGuard>,
    page: Box<DedicatedPage>,
}

impl SecretKey {
    /// Draws a fresh key from the operating system RNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the RNG fails.
    pub fn random() -> Result<Self, Error> {
        Self::build_in_place(|bytes| rng::fill(bytes))
    }

    /// Copies exactly 32 bytes into a new key.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] for any other length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != KEY_LEN {
            return Err(Error::InvalidLength);
        }
        Self::build_in_place(|key| {
            key.copy_from_slice(bytes);
            Ok(())
        })
    }

    /// The key bytes, for handing to a primitive.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.page.0
    }

    /// Whether the operating system agreed to keep this key out of swap.
    #[must_use]
    pub fn is_memory_locked(&self) -> bool {
        self.ram_lock.is_some()
    }

    pub(crate) fn build_in_place(
        write: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let page = Box::new(DedicatedPage([0; KEY_LEN]));
        let mut key = Self {
            ram_lock: lock_in_ram(&page),
            page,
        };
        write(&mut key.page.0)?;
        Ok(key)
    }
}

/// Locking an OS page larger than the dedicated one would also lock, and on
/// drop unlock, whatever else the allocator put in that page.
fn lock_in_ram(page: &DedicatedPage) -> Option<region::LockGuard> {
    let covers_whole_os_pages = DEDICATED_PAGE_SIZE.is_multiple_of(region::page::size());
    covers_whole_os_pages
        .then(|| region::lock(ptr::from_ref(page), DEDICATED_PAGE_SIZE).ok())
        .flatten()
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.page.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.page.0.ct_eq(&other.page.0).into()
    }
}

impl Eq for SecretKey {}
