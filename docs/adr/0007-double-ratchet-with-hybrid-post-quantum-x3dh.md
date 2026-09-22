<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0007: Double Ratchet with hybrid post-quantum X3DH

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

Messages need forward secrecy and post-compromise security stronger than Reticulum's native end-to-end encryption, and resistance to harvest-now-decrypt-later.

## Decision

Sessions use a hybrid X3DH (X25519 + ML-KEM-768) handshake followed by the Double Ratchet, implemented against the Signal specification. `vodozemac` (Apache-2.0, audited by Least Authority) is the reference for ratchet structure and primitive usage; the session layer is our own because it needs the hybrid handshake and the tag scheme.

## Consequences

The protocol test vectors and the FIPS 203 ML-KEM-768 vectors must pass. Signal publishes no X3DH or Double Ratchet vectors, so ADR-0019 derives them from independent implementations.

## Rejected alternatives

Rolling our own primitives; PGP (no forward secrecy); Reticulum-only E2E (no ratcheting); `libsignal` (AGPL).
