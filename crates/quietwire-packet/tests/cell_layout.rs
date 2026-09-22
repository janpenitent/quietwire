// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-PKT-100` and `QW-U-PKT-101`: the wire layout of PROTOCOL.md §6.1,
//! checked against a fixture written out field by field from the specification
//! table. Nothing here calls the serializer to decide what the bytes should be,
//! so a serializer that moves a field cannot move the fixture with it.
//!
//! `QW-U-PKT-105` and `QW-U-PKT-106` ride along, because both are statements
//! about the same table: what a relay may change, and what the associated data
//! therefore cannot cover.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use quietwire_packet::cell::{Cell512, Error, AAD_LEN, CELL_LEN, MAX_COPIES, MAX_TTL, VERSION};

const VERSION_HEX: &str = "01";
const FLAGS_HEX: &str = "a7";
const TTL_HEX: &str = "40";
const COPIES_HEX: &str = "0f";
const TAG_HEX: &str = "101112131415161718191a1b1c1d1e1f";
const NONCE_HEX: &str = "202122232425262728292a2b2c2d2e2f3031323334353637";
const MAC_HEX: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

fn ciphertext_hex() -> String {
    "5a".repeat(452)
}

fn fixture_hex() -> String {
    format!(
        "{VERSION_HEX}{FLAGS_HEX}{TTL_HEX}{COPIES_HEX}{TAG_HEX}{NONCE_HEX}{}{MAC_HEX}",
        ciphertext_hex()
    )
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd number of hex digits");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture() -> Vec<u8> {
    unhex(&fixture_hex())
}

#[test]
fn qw_u_pkt_100_the_fixture_is_exactly_one_cell_long() {
    assert_eq!(fixture().len(), CELL_LEN);
    assert_eq!(CELL_LEN, 512);
}

#[test]
fn qw_u_pkt_101_every_field_sits_where_the_table_says() {
    let bytes = fixture();
    let cell = Cell512::from_bytes(&bytes).unwrap();

    assert_eq!(bytes[0], VERSION);
    assert_eq!(cell.flags(), unhex(FLAGS_HEX)[0]);
    assert_eq!(cell.ttl(), unhex(TTL_HEX)[0]);
    assert_eq!(cell.copies(), unhex(COPIES_HEX)[0]);
    assert_eq!(cell.tag()[..], unhex(TAG_HEX)[..]);
    assert_eq!(cell.nonce()[..], unhex(NONCE_HEX)[..]);
    assert_eq!(cell.ciphertext()[..], unhex(&ciphertext_hex())[..]);
    assert_eq!(cell.mac()[..], unhex(MAC_HEX)[..]);
}

#[test]
fn qw_u_pkt_101_serialising_reproduces_the_fixture_byte_for_byte() {
    let bytes = fixture();
    assert_eq!(
        Cell512::from_bytes(&bytes).unwrap().to_bytes()[..],
        bytes[..]
    );
}

#[test]
fn qw_u_pkt_101_a_cell_of_any_other_length_is_refused() {
    let bytes = fixture();
    for len in [0, 1, CELL_LEN - 1, CELL_LEN + 1] {
        let mut short = bytes.clone();
        short.resize(len, 0);
        assert_eq!(Cell512::from_bytes(&short), Err(Error::InvalidLength));
    }
}

#[test]
fn qw_u_pkt_101_an_unknown_version_is_refused() {
    let mut bytes = fixture();
    bytes[0] = 0x02;
    assert_eq!(
        Cell512::from_bytes(&bytes),
        Err(Error::UnsupportedVersion(0x02))
    );
}

#[test]
fn qw_u_pkt_105_the_hop_fields_are_refused_outside_their_range() {
    let mut bytes = fixture();
    bytes[2] = MAX_TTL + 1;
    assert_eq!(
        Cell512::from_bytes(&bytes),
        Err(Error::TtlOutOfRange(MAX_TTL + 1))
    );

    let mut bytes = fixture();
    bytes[3] = MAX_COPIES + 1;
    assert_eq!(
        Cell512::from_bytes(&bytes),
        Err(Error::CopiesOutOfRange(MAX_COPIES + 1))
    );
}

#[test]
fn qw_u_pkt_105_forwarding_spends_exactly_one_hop_and_stops_at_zero() {
    let cell = Cell512::from_bytes(&fixture()).unwrap();
    let mut hops: u32 = 0;
    let mut current = cell;
    while let Some(next) = current.forwarded() {
        assert_eq!(next.ttl(), current.ttl() - 1);
        current = next;
        hops += 1;
    }
    assert_eq!(hops, u32::from(cell.ttl()));
    assert_eq!(current.ttl(), 0);
    assert_eq!(current.forwarded(), None);
}

#[test]
fn qw_u_pkt_106_the_associated_data_is_the_two_immutable_runs() {
    let bytes = fixture();
    let cell = Cell512::from_bytes(&bytes).unwrap();

    let mut expected = Vec::with_capacity(AAD_LEN);
    expected.extend_from_slice(&bytes[0..2]);
    expected.extend_from_slice(&bytes[4..44]);

    assert_eq!(cell.aad()[..], expected[..]);
    assert_eq!(AAD_LEN, 42);
}

#[test]
fn qw_u_pkt_106_a_relay_that_spends_hops_does_not_move_the_associated_data() {
    let cell = Cell512::from_bytes(&fixture()).unwrap();
    let forwarded = cell.forwarded().unwrap();

    assert_eq!(cell.aad(), forwarded.aad());
    assert_ne!(cell.to_bytes()[..], forwarded.to_bytes()[..]);
}

#[test]
fn qw_u_pkt_106_every_authenticated_byte_changes_the_associated_data() {
    let bytes = fixture();
    let aad = Cell512::from_bytes(&bytes).unwrap().aad();

    // Offset 0 is excluded: the version is authenticated but has one legal
    // value, so a parser that accepted a second one would fail an earlier test.
    for offset in (1..2).chain(4..44) {
        let mut tampered = bytes.clone();
        tampered[offset] ^= 0xff;
        let moved = Cell512::from_bytes(&tampered).unwrap().aad();
        assert_ne!(aad, moved, "offset {offset} left the AAD alone");
    }
}
