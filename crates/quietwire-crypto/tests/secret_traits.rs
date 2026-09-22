// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! QW-U-CRY-051: no secret type implements `Debug`, `Display`, `Serialize` or
//! `Clone`. Opting one in means adding the impl and deleting its error from
//! the matching `ui/*.stderr`, a change that review sees.

#[test]
#[cfg_attr(miri, ignore = "trybuild runs rustc")]
fn secret_types_implement_no_debug_display_serialize_or_clone() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
