// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! A global allocator for tests that reports secrets left in freed heap memory.
//!
//! `QW-U-CRY-050` requires every secret buffer to be all zero once dropped.
//! Install [`ScanningAllocator`] as the `#[global_allocator]` of a test binary,
//! start a [`Watch`], drop the secret, and [`Watch::unwiped_frees`] tells how
//! many freed blocks still held it.
//!
//! Test-only: nothing shipped depends on this crate. ADR-0015 records why it
//! may contain unsafe code while the security crates may not.

mod freed_block;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{Mutex, MutexGuard, PoisonError},
};

use freed_block::FreedBlock;

/// How many watches can be active at once.
pub const MAX_WATCHES: usize = 16;

/// Longest secret [`ScanningAllocator::watch_bytes`] accepts.
pub const MAX_PATTERN_LEN: usize = 64;

type Slots = [Option<Slot>; MAX_WATCHES];

/// Delegates to the system allocator and checks every block against the active
/// watches just before freeing it.
///
/// The bookkeeping lives in fixed-size arrays behind a mutex, so inspecting a
/// block never allocates. `realloc` keeps the default, which moves every block,
/// so a secret left behind by a growing buffer is caught as well.
pub struct ScanningAllocator {
    slots: Mutex<Slots>,
}

impl ScanningAllocator {
    /// An allocator with no active watches.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: Mutex::new([None; MAX_WATCHES]),
        }
    }

    /// Counts every freed block that still contains `secret`.
    ///
    /// # Errors
    /// [`WatchError::InvalidPattern`] if `secret` is all zero (wiped memory
    /// would match it), empty or longer than [`MAX_PATTERN_LEN`];
    /// [`WatchError::Full`] if [`MAX_WATCHES`] watches are active.
    pub fn watch_bytes(&self, secret: &[u8]) -> Result<Watch<'_>, WatchError> {
        let pattern = Pattern::new(secret).ok_or(WatchError::InvalidPattern)?;
        self.start_watch(Target::Bytes(pattern))
    }

    /// Counts every freed block of exactly `size` bytes that is not all zero.
    ///
    /// For secret working memory whose contents a test cannot know, such as
    /// the Argon2 blocks.
    ///
    /// # Errors
    /// [`WatchError::Full`] if [`MAX_WATCHES`] watches are active.
    pub fn watch_blocks_of_size(&self, size: usize) -> Result<Watch<'_>, WatchError> {
        self.start_watch(Target::BlocksOfSize(size))
    }

    fn start_watch(&self, target: Target) -> Result<Watch<'_>, WatchError> {
        let mut slots = self.lock();
        let index = slots
            .iter()
            .position(Option::is_none)
            .ok_or(WatchError::Full)?;
        slots[index] = Some(Slot {
            target,
            unwiped_frees: 0,
        });
        Ok(Watch {
            allocator: self,
            index,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Slots> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn inspect(&self, block: &FreedBlock) {
        for slot in self.lock().iter_mut().flatten() {
            slot.inspect(block);
        }
    }
}

impl Default for ScanningAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every method forwards its arguments unchanged to `System`, so the
// GlobalAlloc contract holds exactly as it does for `System`; `dealloc` only
// reads the block before forwarding it.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for ScanningAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's guarantees about `layout` are those
        // `System.alloc` requires.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's guarantees about `layout` are those
        // `System.alloc_zeroed` requires.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` is a live block of
        // `layout.size()` bytes, and it stays live until `System.dealloc`.
        let block = unsafe { FreedBlock::new(ptr, layout.size()) };
        self.inspect(&block);
        // SAFETY: `ptr` came from `System` with this `layout`, because `alloc`
        // and `alloc_zeroed` forward to it unchanged.
        unsafe { System.dealloc(ptr, layout) };
    }
}

/// An active watch. It stops, and frees its slot, when dropped.
pub struct Watch<'a> {
    allocator: &'a ScanningAllocator,
    index: usize,
}

impl Watch<'_> {
    /// How many freed blocks still held the watched secret since the watch started.
    #[must_use]
    pub fn unwiped_frees(&self) -> usize {
        self.allocator.lock()[self.index].map_or(0, |slot| slot.unwiped_frees)
    }
}

impl Drop for Watch<'_> {
    fn drop(&mut self) {
        self.allocator.lock()[self.index] = None;
    }
}

/// Why a watch could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchError {
    /// The secret is all zero, empty or longer than [`MAX_PATTERN_LEN`].
    InvalidPattern,
    /// [`MAX_WATCHES`] watches are already active.
    Full,
}

#[derive(Clone, Copy)]
struct Slot {
    target: Target,
    unwiped_frees: usize,
}

impl Slot {
    fn inspect(&mut self, block: &FreedBlock) {
        if self.target.is_left_in(block) {
            self.unwiped_frees += 1;
        }
    }
}

#[derive(Clone, Copy)]
enum Target {
    Bytes(Pattern),
    BlocksOfSize(usize),
}

impl Target {
    fn is_left_in(&self, block: &FreedBlock) -> bool {
        match self {
            Self::Bytes(pattern) => block.contains(pattern.as_bytes()),
            Self::BlocksOfSize(size) => block.len() == *size && !block.is_all_zero(),
        }
    }
}

#[derive(Clone, Copy)]
struct Pattern {
    bytes: [u8; MAX_PATTERN_LEN],
    len: usize,
}

impl Pattern {
    fn new(secret: &[u8]) -> Option<Self> {
        let recognisable = secret.len() <= MAX_PATTERN_LEN && secret.iter().any(|&b| b != 0);
        recognisable.then(|| {
            let mut bytes = [0; MAX_PATTERN_LEN];
            bytes[..secret.len()].copy_from_slice(secret);
            Self {
                bytes,
                len: secret.len(),
            }
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn watch_bytes_rejects_patterns_that_wiped_memory_could_match() {
        let allocator = ScanningAllocator::new();

        for secret in [&[][..], &[0; 8], &[1; MAX_PATTERN_LEN + 1]] {
            assert_eq!(
                allocator.watch_bytes(secret).err(),
                Some(WatchError::InvalidPattern)
            );
        }
    }

    #[test]
    fn watch_bytes_accepts_the_longest_pattern() {
        let allocator = ScanningAllocator::new();

        assert!(allocator.watch_bytes(&[1; MAX_PATTERN_LEN]).is_ok());
    }

    #[test]
    fn start_watch_fails_once_every_slot_is_taken() {
        let allocator = ScanningAllocator::new();
        let _watches: Vec<_> = (1..=MAX_WATCHES)
            .map(|size| allocator.watch_blocks_of_size(size).unwrap())
            .collect();

        assert_eq!(
            allocator.watch_blocks_of_size(0).err(),
            Some(WatchError::Full)
        );
    }

    #[test]
    fn dropping_a_watch_frees_its_slot() {
        let allocator = ScanningAllocator::new();
        let watches: Vec<_> = (1..=MAX_WATCHES)
            .map(|size| allocator.watch_blocks_of_size(size).unwrap())
            .collect();

        drop(watches);

        assert!(allocator.watch_blocks_of_size(0).is_ok());
    }
}
