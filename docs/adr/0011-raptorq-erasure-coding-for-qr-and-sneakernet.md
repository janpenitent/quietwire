<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0011: RaptorQ erasure coding for QR and sneakernet

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

Payloads moved by animated QR codes or removable media must survive missed or reordered frames.

## Decision

QR and sneakernet payloads are encoded with RaptorQ (`raptorq` crate, RFC 6330).

## Consequences

A scanner recovers the payload from any sufficient subset of frames, in any order.

## Rejected alternatives

Static QR chunking (fails on a single missed frame).
