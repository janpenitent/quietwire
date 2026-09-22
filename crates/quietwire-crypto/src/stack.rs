// SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
//
// SPDX-License-Identifier: Apache-2.0

use std::hint::black_box;

use zeroize::Zeroize;

const SCRUBBED_BYTES: usize = 64 * 1024;
const SCRUBBED_WORDS: usize = SCRUBBED_BYTES / size_of::<u64>();

/// Runs `operation`, then overwrites the stack it ran on, so that copies of
/// key material left in its frames and in those of the libraries it called
/// do not outlive it (ADR-0018).
pub(crate) fn scrubbed<T>(operation: impl FnOnce() -> T) -> T {
    let result = run(operation);
    scrub();
    result
}

#[inline(never)]
fn run<T>(operation: impl FnOnce() -> T) -> T {
    operation()
}

/// Called from the same frame as [`run`], so its own frame covers the one
/// `run` left behind, down to [`SCRUBBED_BYTES`].
#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    reason = "the array is the stack to overwrite"
)]
fn scrub() {
    let mut frame = [0_u64; SCRUBBED_WORDS];
    frame.zeroize();
    black_box(&frame);
}
