// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

//! Workspace-local binding generator, so the generator version always matches the runtime version.

fn main() {
    uniffi::uniffi_bindgen_main();
}
