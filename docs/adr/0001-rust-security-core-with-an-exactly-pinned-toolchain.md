<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0001: Rust security core with an exactly pinned toolchain

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

The security core must be memory-safe, have no garbage collector or runtime, compile to Android, iOS, desktop and embedded targets, and use mature constant-time cryptographic crates. Builds must be reproducible bit for bit.

## Decision

All protocol, cryptography, storage, routing and transport code is written in Rust, edition 2021. The toolchain is pinned to an exact version in `rust-toolchain.toml` (currently 1.94.1), not floored by an MSRV. The pin advances deliberately, is reviewed quarterly, and every advance is a new ADR because it changes the reproducible-build baseline.

## Consequences

No downstream compatibility promise is made for older compilers. Contributors get the pinned toolchain automatically through rustup. Workspace lints forbid `unsafe` code and deny panics, `unwrap` and `expect` in library code.

## Rejected alternatives

C/C++ (memory-safety bugs), Go (GC pauses, weaker mobile story), Python (unsuitable for a security core).
