<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0004: iOS app in Swift and SwiftUI

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

iOS exposes Core Bluetooth, the Secure Enclave and background BLE modes only to native code.

## Decision

The iOS app is written in Swift with SwiftUI. The Swift version is pinned in `.swift-version` and the Xcode project, never in prose.

## Consequences

iOS work needs a macOS build host and a dedicated specialist.

## Rejected alternatives

Any cross-platform framework.
