// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

use std::arch::asm;

/// The bytes of a block handed to `dealloc`, read as the hardware holds them.
///
/// Padding and spare capacity are uninitialised as far as the compiler is
/// concerned, so reading them through a Rust pointer would be undefined
/// behaviour. Each byte is loaded by an inline-assembly instruction instead,
/// which observes whatever the memory holds.
pub(crate) struct FreedBlock {
    start: *const u8,
    len: usize,
}

impl FreedBlock {
    /// # Safety
    /// `start..start + len` must lie inside one live allocation for as long as
    /// the returned value exists.
    #[allow(unsafe_code)]
    pub(crate) const unsafe fn new(start: *const u8, len: usize) -> Self {
        Self { start, len }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_all_zero(&self) -> bool {
        (0..self.len).all(|offset| self.byte(offset) == Some(0))
    }

    pub(crate) fn contains(&self, pattern: &[u8]) -> bool {
        let Some(last_start) = self.len.checked_sub(pattern.len()) else {
            return false;
        };
        (0..=last_start).any(|start| self.matches_at(start, pattern))
    }

    fn matches_at(&self, start: usize, pattern: &[u8]) -> bool {
        pattern
            .iter()
            .zip(start..)
            .all(|(&expected, offset)| self.byte(offset) == Some(expected))
    }

    #[allow(unsafe_code)]
    fn byte(&self, offset: usize) -> Option<u8> {
        (offset < self.len).then(|| {
            // SAFETY: `offset < len`, so `start + offset` stays inside the live
            // allocation that `new` was promised.
            unsafe { load_byte(self.start.add(offset)) }
        })
    }
}

/// # Safety
/// `address` must point into a live allocation.
#[allow(unsafe_code)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn load_byte(address: *const u8) -> u8 {
    let byte: u8;
    // SAFETY: the caller guarantees `address` is readable; the instruction
    // reads that one byte and writes only the output register.
    unsafe {
        asm!(
            "mov {byte}, byte ptr [{address}]",
            address = in(reg) address,
            byte = out(reg_byte) byte,
            options(nostack, readonly, preserves_flags),
        );
    }
    byte
}

/// # Safety
/// `address` must point into a live allocation.
#[allow(unsafe_code)]
#[cfg(target_arch = "aarch64")]
unsafe fn load_byte(address: *const u8) -> u8 {
    let byte: u8;
    // SAFETY: the caller guarantees `address` is readable; the instruction
    // reads that one byte and writes only the output register.
    unsafe {
        asm!(
            "ldrb {byte:w}, [{address}]",
            address = in(reg) address,
            byte = out(reg) byte,
            options(nostack, readonly, preserves_flags),
        );
    }
    byte
}

/// # Safety
/// `address` must point into a live allocation.
#[allow(unsafe_code)]
#[cfg(target_arch = "arm")]
unsafe fn load_byte(address: *const u8) -> u8 {
    let byte: u8;
    // SAFETY: the caller guarantees `address` is readable; the instruction
    // reads that one byte and writes only the output register.
    unsafe {
        asm!(
            "ldrb {byte}, [{address}]",
            address = in(reg) address,
            byte = out(reg) byte,
            options(nostack, readonly, preserves_flags),
        );
    }
    byte
}

#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm"
)))]
compile_error!("quietwire-crypto-memtest has no byte load for this architecture");

#[cfg(test)]
mod tests {
    use super::*;

    const BYTES: [u8; 4] = [1, 2, 3, 4];

    #[allow(unsafe_code)]
    fn first_three_of(bytes: &[u8; 4]) -> FreedBlock {
        // SAFETY: three bytes lie inside `bytes`, which outlives the block in
        // every test below.
        unsafe { FreedBlock::new(bytes.as_ptr(), 3) }
    }

    #[test]
    fn byte_reads_inside_the_block() {
        let bytes = BYTES;

        assert_eq!(first_three_of(&bytes).byte(2), Some(3));
    }

    #[test]
    fn byte_stops_at_the_end_of_the_block() {
        let bytes = BYTES;

        assert_eq!(first_three_of(&bytes).byte(3), None);
    }

    #[test]
    fn contains_ignores_bytes_past_the_end_of_the_block() {
        let bytes = BYTES;

        assert!(!first_three_of(&bytes).contains(&[3, 4]));
    }
}
