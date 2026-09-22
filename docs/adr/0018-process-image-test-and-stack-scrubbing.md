<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0018: Process image test and stack scrubbing

- Status: Accepted
- Date: 2026-09-22
- Source: project plan §16 (`QW-U-CRY-052`), ADR-0014, ADR-0015, ADR-0016

## Context

`QW-U-CRY-052` requires that a full core dump of an unlocked process, searched
for known key material, find it only inside `mlock`ed regions, and find none
of it once the vault is locked. `SecretKey` keeps every long-lived key in a
locked page (ADR-0014), and the scanning allocator checks the heap
(ADR-0015). Neither covers the stack. The primitives take keys and return
shared secrets by value, so copies land in the frames of this crate and of the
libraries it calls, where the heap scan never looks.

The first run of the test found five copies of the ML-KEM shared key in an
unoptimised build, all on the thread stack below `decapsulate`. An optimised
build of the same code left none, but only because of how the frames happened
to be laid out.

## Decision

1. **The test reads the process image through `/proc/<pid>/mem`.** It runs
   itself again as a child, which unlocks a vault from material piped in on
   stdin. The parent then reads every mapping that a Linux core dump would
   hold: readable mappings not marked `dd`, `io` or `pf`. Pages in guard
   regions (`gu`) cannot be read and count as zeros. The `lo` flag in `VmFlags`
   marks a mapping as locked. A real core file depends on `core_pattern`,
   `ulimit -c` and, on most distributions, `systemd-coredump`, none of which a
   test runner controls. The mappings it would contain are the same.
2. **The needles cover resident and transient material.** Resident needles
   (DEK, subkeys, private keys, seeds, shared secrets) must each be found, so a
   broken scan cannot pass. Transient needles (the password, the KEK, the
   clamped X25519 scalar, the expanded Ed25519 key) need not be found. Any
   needle that is found must be in a locked mapping. After the vault is
   dropped, which is what locking it means, no needle may be found.
3. **Asymmetric operations scrub the stack they used.** `stack::scrubbed` runs
   the operation in a frame of its own. It then overwrites 64 KiB of stack from
   the same depth with a zeroised array. It wraps every `x25519`, `ed25519` and
   `mlkem` operation that touches a private key. The residue found was between
   4 and 8 KiB below the caller. 64 KiB leaves a wide margin for deeper call
   paths and other targets.
4. **The test runs unoptimised on every pull request.** That is the build in
   which it caught the leak; an optimised build hid it.

## Consequences

The scrub adds about 5 µs to each asymmetric operation on a desktop CPU,
measured in a release build:

| Operation | Before | After |
|---|---|---|
| X25519 agreement | 52 µs | 57 µs |
| Ed25519 signing | 28 µs | 34 µs |
| ML-KEM-768 decapsulation | 76 µs | 82 µs |

The test takes about 35 s unoptimised. Almost all of that is Argon2id at the
mobile profile, which runs once in each process.

The test is Linux-only. Other platforms run the same code paths.

## Rejected alternatives

- **Scrubbing the symmetric operations too** (AEAD, HKDF, BLAKE3). They sit on
  the per-message and per-field path, and the test finds no residue from them.
  The test still covers them, and they get the scrub as soon as it does.
- **Relying on the libraries to wipe their frames.** None of them can: a Rust
  move is a copy that no destructor sees.
- **`MADV_DONTDUMP` on the stack.** It hides the copies from a core dump but
  not from swap, from `/proc/<pid>/mem` or from a debugger.
- **Running each operation on a dedicated locked stack.** Switching stacks
  needs `unsafe`, which the crate forbids.
