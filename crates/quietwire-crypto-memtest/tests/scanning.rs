// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Control tests: the allocator must see secrets that were left behind and
//! must not see secrets that were wiped. Each test watches its own pattern or
//! block size, so tests running in parallel threads do not disturb each other.

#![allow(clippy::unwrap_used)]

use std::hint::black_box;

use quietwire_crypto_memtest::ScanningAllocator;
use zeroize::Zeroizing;

#[global_allocator]
static ALLOCATOR: ScanningAllocator = ScanningAllocator::new();

#[test]
fn reports_a_freed_buffer_still_holding_the_secret() {
    const SECRET: &[u8] = b"memtest control: left behind";
    let watch = ALLOCATOR.watch_bytes(SECRET).unwrap();

    drop(black_box(SECRET.to_vec()));

    assert_eq!(watch.unwiped_frees(), 1);
}

#[test]
fn ignores_a_buffer_wiped_before_it_is_freed() {
    const SECRET: &[u8] = b"memtest control: wiped";
    let watch = ALLOCATOR.watch_bytes(SECRET).unwrap();

    drop(black_box(Zeroizing::new(SECRET.to_vec())));

    assert_eq!(watch.unwiped_frees(), 0);
}

#[test]
fn reports_a_secret_left_behind_when_a_buffer_grows() {
    const SECRET: &[u8] = b"memtest control: moved by realloc";
    let watch = ALLOCATOR.watch_bytes(SECRET).unwrap();

    let mut buffer = Zeroizing::new(SECRET.to_vec());
    buffer.reserve(black_box(4096));
    drop(buffer);

    assert_eq!(watch.unwiped_frees(), 1);
}

#[test]
fn reports_a_freed_block_of_the_watched_size_that_is_not_zero() {
    const SIZE: usize = 4099;
    let watch = ALLOCATOR.watch_blocks_of_size(SIZE).unwrap();

    drop(black_box(vec![1_u8; SIZE]));

    assert_eq!(watch.unwiped_frees(), 1);
}

#[test]
fn ignores_a_freed_block_of_the_watched_size_that_is_zero() {
    const SIZE: usize = 4101;
    let watch = ALLOCATOR.watch_blocks_of_size(SIZE).unwrap();

    drop(black_box(Zeroizing::new(vec![1_u8; SIZE])));

    assert_eq!(watch.unwiped_frees(), 0);
}

#[test]
fn ignores_freed_blocks_of_other_sizes() {
    const SIZE: usize = 4103;
    let watch = ALLOCATOR.watch_blocks_of_size(SIZE).unwrap();

    drop(black_box(vec![1_u8; SIZE - 1]));
    drop(black_box(vec![1_u8; SIZE + 1]));

    assert_eq!(watch.unwiped_frees(), 0);
}
