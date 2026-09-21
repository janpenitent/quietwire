<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0015: Test allocator for memory hygiene

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §16 (`QW-U-CRY-050`), unsafe-code gate of §17

## Context

`QW-U-CRY-050` requires every secret buffer to be all zero after `drop`,
verified by reading the raw allocation back through a custom test allocator.
A `GlobalAlloc` implementation is `unsafe` by definition, and the workspace
forbids unsafe code: the plan allows none in security crates and asks for a
`// SAFETY:` proof and a named reviewer everywhere else.

Freed blocks also hold bytes the compiler treats as uninitialised: struct
padding and the spare capacity of a `Vec`. Reading them through a Rust
pointer is undefined behaviour, even inside a test.

## Decision

1. **A separate, test-only crate.** `quietwire-crypto-memtest` holds the
   allocator and nothing else. It is only ever a `dev-dependency`, so no
   shipped binary links it, and it is not a security crate. It overrides the
   workspace lint to `unsafe_code = "deny"` and allows it item by item;
   `clippy::undocumented_unsafe_blocks` and `clippy::missing_safety_doc` are
   denied, so every unsafe block and function carries its proof. The
   maintainer is the named reviewer of those proofs (ADR-0013).
2. **What it checks.** `ScanningAllocator` forwards to the system allocator
   and inspects each block in `dealloc`, before releasing it. A test either
   watches known secret bytes, counting freed blocks that still contain them,
   or watches a block size, counting freed blocks of that size that are not
   all zero, for working memory whose contents a test cannot know. The
   bookkeeping sits in fixed arrays behind a mutex, so inspection never
   allocates. The default `realloc` is kept on purpose: it moves every block,
   so a secret left behind by a growing buffer is caught too.
3. **Reading without undefined behaviour.** Each byte is loaded by one
   inline-assembly instruction, which reads whatever the memory holds instead
   of a Rust value. The crate supports x86, x86-64, AArch64 and 32-bit Arm,
   which covers every target of the toolchain setup, and fails to compile on
   any other architecture.
4. **Security crates stay unsafe-free.** A test binary that installs the
   allocator only names it in a `#[global_allocator]` static, which compiles
   under `forbid(unsafe_code)`.
5. **Mutation testing.** The `Drop` of `SecretKey` is no longer excluded
   from `cargo mutants`: removing the wipe now fails
   `memory_wiped_on_drop.rs`.

## Consequences

The first run found a real leak. `argon2` 0.6 allocates its working memory
itself and frees it without wiping, leaving the whole Argon2id state, from
which the KEK follows, in freed heap. `derive_kek` now passes its own
`Zeroizing` block buffer through `hash_password_into_with_memory`, and a
unit test watches blocks of the working-memory size.

Miri cannot execute inline assembly. `QW-U-CRY-053` must build the crypto
tests without the scanning allocator when running under Miri.

Only the heap is checked. Stack copies and registers are outside what an
allocator can see; `QW-U-CRY-052` covers the process image as a whole.

## Rejected alternatives

- Reading freed bytes with `ptr::read_volatile`: still a read of
  uninitialised memory as `u8`, so still undefined behaviour.
- Wiping or poisoning every block in `dealloc`: it would hide the leaks the
  test exists to find.
- Checking only `SecretKey` through a hook in the crypto crate: it misses
  copies made by dependencies, which is exactly where the Argon2 leak was.
- Keeping the allocator inside `quietwire-crypto` behind `cfg(test)`: the
  crate would need to allow unsafe code, breaking the zero-unsafe rule for
  security crates.
