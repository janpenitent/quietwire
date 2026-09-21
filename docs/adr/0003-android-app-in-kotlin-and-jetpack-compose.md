<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0003: Android app in Kotlin and Jetpack Compose

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

Android needs low-level BLE and Wi-Fi Direct access, StrongBox-backed keys and a long-lived background service.

## Decision

The Android app is written in Kotlin with Jetpack Compose and calls the Rust core through UniFFI-generated bindings.

## Consequences

Native platform APIs are available without bridges. Android builds need the NDK and `cargo-ndk`.

## Rejected alternatives

Flutter (poor low-level BLE), React Native.
