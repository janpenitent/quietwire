<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0017: Miri over the crypto crate

- Status: Accepted
- Date: 2026-09-22
- Source: project plan §16 (`QW-U-CRY-053`), ADR-0015

## Context

`QW-U-CRY-053` asks for a Miri run over the whole crypto crate with no
undefined behaviour and no uninitialised reads. Miri interprets the code
instead of running it, so it cannot call into the operating system for
everything a native test does, and it is two to three orders of magnitude
slower: the full known-answer suites take more than twenty minutes each.

## Decision

1. **Every test of `quietwire-crypto` runs under Miri**, known-answer vectors
   included, with the same fixtures as the native run.
2. **`mlock` is not called under Miri.** `SecretKey` treats the key as one the
   operating system refused to lock, the path a native process with
   `ulimit -l 0` already takes. The tests of the lock itself read the lock
   limit and spawn a child process, so they are native only.
3. **The scanning allocator is left out under Miri.** It reads freed blocks
   with inline assembly (ADR-0015). The memory-wipe tests that install it,
   `memory_wiped_on_drop.rs` and the Argon2id working-memory test, are native
   only.
4. **`trybuild` tests are skipped**, since they run `rustc`.
5. **Nightly CI, pinned toolchain.** Miri needs a nightly compiler. The
   nightly workflow installs one fixed nightly with the `miri` and
   `rust-src` components and runs `cargo miri nextest` over the crate. The
   date is bumped by hand, like the stable toolchain.

## Consequences

Miri checks the code paths of every primitive and of the key hierarchy,
including the dependencies they call, for undefined behaviour and
uninitialised reads. What it skips, the lock and the heap scan, is covered by
the native tests, which run on every pull request.

The run takes over an hour, so it is not a pull-request check.

## Rejected alternatives

- Running a subset of the known-answer vectors under Miri: faster, but the
  plan asks for the whole crate, and nightly time is cheap.
- A Miri shim for `mlock`: Miri has none, and faking success would make
  `is_memory_locked` lie.
