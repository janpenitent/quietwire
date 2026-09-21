<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0008: Noise XX for hop-to-hop link encryption

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

Relays must not even learn that an end-to-end packet exists.

## Decision

Every link is encrypted with the Noise Protocol Framework `XX` handshake using the `snow` crate.

## Consequences

Formally analysed handshake, no PKI.

## Rejected alternatives

TLS (needs PKI and certificates).
