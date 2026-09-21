<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0002: UniFFI 0.28 for cross-language bindings

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

Android, iOS and Python tooling must all call one auditable Rust implementation.

## Decision

Bindings are generated with UniFFI 0.28 from `quietwire-ffi`. The generator ships inside the workspace as `crates/quietwire-ffi/src/bin/uniffi-bindgen.rs`, so the generator version always matches the runtime version. No global `uniffi-bindgen` is installed.

## Consequences

One implementation to audit. The FFI surface is the public API of `quietwire-core` and is tracked with `cargo-public-api`.

## Rejected alternatives

Hand-written JNI/FFI (error-prone); separate implementations per platform.
