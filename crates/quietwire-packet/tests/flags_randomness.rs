// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-PKT-102` and `QW-U-PKT-102b`: the flags byte is uniformly random and
//! means nothing.
//!
//! The distribution test is the cheap half. The structural test is the half
//! that matters: a flag bit that acquires a meaning becomes a field a censor
//! can match on, and no amount of entropy prevents that.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use quietwire_packet::cell::{CellHeader, NONCE_LEN, TAG_LEN};

const CELLS: usize = 1_000_000;
const BUCKETS: usize = 256;
/// The 0.01 point of the chi-squared distribution with 255 degrees of freedom.
/// A uniform byte exceeds it once in a hundred runs.
const CHI_SQUARED_CRITICAL: f64 = 310.457;
/// Five sigma on a million fair coins.
const BIT_TOLERANCE: u64 = 2_500;

fn flags_byte() -> u8 {
    CellHeader::new([0u8; TAG_LEN], [0u8; NONCE_LEN])
        .unwrap()
        .aad()[1]
}

#[test]
fn qw_u_pkt_102_the_flags_byte_is_uniform_over_a_million_cells() {
    let mut counts = [0u64; BUCKETS];
    for _ in 0..CELLS {
        counts[flags_byte() as usize] += 1;
    }

    #[allow(clippy::cast_precision_loss)]
    let expected = CELLS as f64 / BUCKETS as f64;
    #[allow(clippy::cast_precision_loss)]
    let chi_squared: f64 = counts
        .iter()
        .map(|&count| {
            let deviation = count as f64 - expected;
            deviation * deviation / expected
        })
        .sum();

    assert!(
        chi_squared < CHI_SQUARED_CRITICAL,
        "chi-squared {chi_squared} over {BUCKETS} buckets is not uniform"
    );
}

#[test]
fn qw_u_pkt_102_every_bit_is_set_about_half_the_time() {
    let mut set = [0u64; 8];
    for _ in 0..CELLS {
        let flags = flags_byte();
        for (bit, count) in set.iter_mut().enumerate() {
            *count += u64::from(flags >> bit & 1);
        }
    }

    let half = (CELLS / 2) as u64;
    for (bit, count) in set.iter().enumerate() {
        assert!(
            count.abs_diff(half) < BIT_TOLERANCE,
            "bit {bit} was set {count} times in {CELLS} cells"
        );
    }
}

/// Every `.rs` file under a crate's `src`, which is the code that ships.
fn shipped_sources() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut sources = Vec::new();
    let mut pending: Vec<PathBuf> = fs::read_dir(crates)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("src"))
        .filter(|src| src.is_dir())
        .collect();

    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                sources.push(path);
            }
        }
    }
    sources
}

/// Whole identifiers only, so the `preserves_flags` of an inline-asm option
/// block is not mistaken for the cell's flags byte.
fn names_the_flags(line: &str) -> bool {
    line.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token == "flags")
}

#[test]
fn qw_u_pkt_102b_nothing_outside_the_cell_layout_names_the_flags() {
    let owner = Path::new("quietwire-packet").join("src").join("cell.rs");
    let owner = owner.to_string_lossy().into_owned();

    let mut offenders: BTreeMap<String, usize> = BTreeMap::new();
    for path in shipped_sources() {
        let display = path.to_string_lossy().into_owned();
        if display.ends_with(&owner) {
            continue;
        }
        let hits = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|line| names_the_flags(line))
            .count();
        if hits > 0 {
            offenders.insert(display, hits);
        }
    }

    assert!(
        offenders.is_empty(),
        "the flags byte is reserved and carries no meaning, so only the cell \
         layout may name it: {offenders:?}"
    );
}

#[test]
fn qw_u_pkt_102b_the_flags_byte_cannot_be_chosen_by_a_caller() {
    let layout = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("cell.rs");
    let source = fs::read_to_string(layout).unwrap();

    assert!(
        !source.contains("pub flags"),
        "the flags byte is not a public field"
    );
    assert!(
        source.contains("fn new(tag: [u8; TAG_LEN], nonce: [u8; NONCE_LEN])"),
        "a header is built from a tag and a nonce, and draws its own flags"
    );
}
