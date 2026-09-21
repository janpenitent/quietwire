// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! `QW-U-CRY-020`: the compiled-in Argon2id parameters are exactly the ones in
//! PROTOCOL.md §5.7. Changing them means changing this test.

#![allow(missing_docs)]

use quietwire_crypto::password::KdfParams;

#[test]
fn qw_u_cry_020_mobile_parameters_are_256_mib_4_passes_2_lanes() {
    let params = KdfParams::MOBILE;

    assert_eq!(params.memory_kib(), 262_144);
    assert_eq!(params.iterations(), 4);
    assert_eq!(params.parallelism(), 2);
}

#[test]
fn qw_u_cry_020_desktop_parameters_are_1_gib_4_passes_2_lanes() {
    let params = KdfParams::DESKTOP;

    assert_eq!(params.memory_kib(), 1_048_576);
    assert_eq!(params.iterations(), 4);
    assert_eq!(params.parallelism(), 2);
}
