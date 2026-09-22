// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-PKT-103`: the application payload of PROTOCOL.md §6.3, and the random
//! padding that fills it.
//!
//! The layout half is a fixture written from the specification table, like
//! `cell_layout.rs`. The padding half is the point: a body shorter than 365
//! bytes leaves room that must look like the body, or the length of what
//! somebody wrote survives as the length of the part that is not random.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use quietwire_packet::payload::{
    ContentType, Error, Fragment, Payload, BODY_AT, MAX_BODY_LEN, PAYLOAD_LEN,
};

const MINUTE_MS: u64 = 60_000;
/// A clock reading that is not on a minute boundary.
const CLOCK_MS: u64 = 1_774_000_123_456;

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn payload_with(body_len: usize) -> Payload {
    Payload::new(
        ContentType::Text,
        Fragment::new(0, 1).unwrap(),
        CLOCK_MS,
        &body(body_len),
    )
    .unwrap()
}

#[test]
fn qw_u_pkt_103_a_payload_is_exactly_the_inner_plaintext() {
    assert_eq!(PAYLOAD_LEN, 396);
    assert_eq!(BODY_AT, 31);
    assert_eq!(MAX_BODY_LEN, 365);
    assert_eq!(BODY_AT + MAX_BODY_LEN, PAYLOAD_LEN);
    assert_eq!(payload_with(10).to_bytes().len(), PAYLOAD_LEN);
}

#[test]
fn qw_u_pkt_103_every_field_sits_where_the_table_says() {
    let payload = payload_with(7);
    let bytes = payload.to_bytes();

    assert_eq!(&bytes[0..16], payload.message_id());
    assert_eq!(
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        payload.timestamp_ms()
    );
    assert_eq!(bytes[24], ContentType::Text.code());
    assert_eq!(u16::from_le_bytes(bytes[25..27].try_into().unwrap()), 0);
    assert_eq!(u16::from_le_bytes(bytes[27..29].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(bytes[29..31].try_into().unwrap()), 7);
    assert_eq!(&bytes[BODY_AT..BODY_AT + 7], &body(7)[..]);
}

#[test]
fn qw_u_pkt_103_a_payload_survives_a_round_trip() {
    for len in [0, 1, 7, MAX_BODY_LEN - 1, MAX_BODY_LEN] {
        let payload = payload_with(len);
        let bytes = payload.to_bytes();
        let read = Payload::from_bytes(&bytes).unwrap();
        assert_eq!(read.body(), &body(len)[..]);
        assert_eq!(read.to_bytes(), bytes);
    }
}

#[test]
fn qw_u_pkt_103_the_timestamp_is_rounded_down_to_a_minute() {
    let payload = payload_with(1);
    assert_eq!(payload.timestamp_ms() % MINUTE_MS, 0);
    assert_eq!(payload.timestamp_ms(), CLOCK_MS - CLOCK_MS % MINUTE_MS);
    assert!(payload.timestamp_ms() <= CLOCK_MS);
}

#[test]
fn qw_u_pkt_103_a_body_past_the_field_is_refused() {
    let too_long = body(MAX_BODY_LEN + 1);
    assert_eq!(
        Payload::new(
            ContentType::Text,
            Fragment::new(0, 1).unwrap(),
            CLOCK_MS,
            &too_long
        ),
        Err(Error::BodyTooLong(MAX_BODY_LEN + 1))
    );

    let mut bytes = payload_with(1).to_bytes();
    let over = u16::try_from(MAX_BODY_LEN + 1).unwrap();
    bytes[29..31].copy_from_slice(&over.to_le_bytes());
    assert_eq!(
        Payload::from_bytes(&bytes),
        Err(Error::BodyTooLong(MAX_BODY_LEN + 1))
    );
}

#[test]
fn qw_u_pkt_103_a_payload_of_any_other_length_is_refused() {
    let bytes = payload_with(1).to_bytes();
    for len in [0, 1, PAYLOAD_LEN - 1, PAYLOAD_LEN + 1] {
        let mut wrong = bytes.to_vec();
        wrong.resize(len, 0);
        assert_eq!(Payload::from_bytes(&wrong), Err(Error::InvalidLength));
    }
}

#[test]
fn qw_u_pkt_103_the_withdrawn_content_type_stays_withdrawn() {
    let mut bytes = payload_with(1).to_bytes();
    bytes[24] = 0x06;
    assert_eq!(Payload::from_bytes(&bytes), Err(Error::ReservedContentType));

    bytes[24] = 0x09;
    assert_eq!(
        Payload::from_bytes(&bytes),
        Err(Error::UnknownContentType(0x09))
    );
}

#[test]
fn qw_u_pkt_103_every_live_content_type_round_trips() {
    for content_type in [
        ContentType::Text,
        ContentType::DeliveryReceipt,
        ContentType::ReadReceipt,
        ContentType::ContactBundle,
        ContentType::FileFragment,
        ContentType::SessionInit,
        ContentType::TagResync,
        ContentType::Decoy,
    ] {
        let payload = Payload::new(
            content_type,
            Fragment::new(0, 1).unwrap(),
            CLOCK_MS,
            &body(4),
        )
        .unwrap();
        let read = Payload::from_bytes(&payload.to_bytes()).unwrap();
        assert_eq!(read.content_type(), content_type);
    }
}

#[test]
fn qw_u_pkt_103_a_fragment_outside_its_set_is_refused() {
    assert_eq!(Fragment::new(0, 0), Err(Error::EmptyFragmentSet));
    assert_eq!(Fragment::new(3, 3), Err(Error::FragmentOutOfSet));

    let mut bytes = payload_with(1).to_bytes();
    bytes[25..27].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(Payload::from_bytes(&bytes), Err(Error::FragmentOutOfSet));
}

#[test]
fn qw_u_pkt_103_the_padding_is_uniform_over_the_bytes_it_fills() {
    // The 0.01 point of the chi-squared distribution with 255 degrees of
    // freedom. A uniform byte exceeds it once in a hundred runs.
    const CRITICAL: f64 = 310.457;
    const PAYLOADS: usize = 4_000;
    const BODY_LEN: usize = 100;

    let mut counts = [0u64; 256];
    let mut samples = 0u64;
    for _ in 0..PAYLOADS {
        let bytes = payload_with(BODY_LEN).to_bytes();
        for byte in &bytes[BODY_AT + BODY_LEN..] {
            counts[*byte as usize] += 1;
            samples += 1;
        }
    }
    assert_eq!(
        samples,
        u64::try_from(PAYLOADS * (MAX_BODY_LEN - BODY_LEN)).unwrap(),
        "the padding must fill the body field to its end"
    );

    #[allow(clippy::cast_precision_loss)]
    let expected = samples as f64 / 256.0;
    #[allow(clippy::cast_precision_loss)]
    let chi_squared: f64 = counts
        .iter()
        .map(|&count| {
            let deviation = count as f64 - expected;
            deviation * deviation / expected
        })
        .sum();

    assert!(
        chi_squared < CRITICAL,
        "chi-squared {chi_squared} over the padding is not uniform"
    );
}

#[test]
fn qw_u_pkt_103_two_payloads_with_the_same_body_differ_everywhere_else() {
    let first = payload_with(32).to_bytes();
    let second = payload_with(32).to_bytes();

    assert_eq!(
        &first[BODY_AT..BODY_AT + 32],
        &second[BODY_AT..BODY_AT + 32]
    );
    assert_ne!(
        &first[0..16],
        &second[0..16],
        "the message id is drawn fresh"
    );
    assert_ne!(
        &first[BODY_AT + 32..],
        &second[BODY_AT + 32..],
        "the padding is drawn fresh"
    );
}

#[test]
fn qw_u_pkt_103_a_decoy_is_a_payload_like_any_other() {
    let decoy = Payload::decoy(CLOCK_MS).unwrap();
    let bytes = decoy.to_bytes();

    assert_eq!(bytes.len(), PAYLOAD_LEN);
    assert_eq!(decoy.content_type(), ContentType::Decoy);
    assert_eq!(bytes[24], 0xFF);
    assert_eq!(Payload::from_bytes(&bytes).unwrap().to_bytes(), bytes);
}
