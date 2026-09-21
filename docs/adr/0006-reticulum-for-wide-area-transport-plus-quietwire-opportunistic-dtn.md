<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0006: Reticulum for wide-area transport plus QUIETWIRE opportunistic DTN

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

The network must work with no infrastructure, over LoRa, packet radio and serial links as well as short-range encounters.

## Decision

The wide-area layer is the Reticulum Network Stack (`reticulum-rs`). QUIETWIRE adds its own store-carry-forward layer using encounter-utility routing and binary Spray-and-Wait for short-range encounters that Reticulum does not cover.

## Consequences

Reuses a field-tested stack with an existing user base; the routing work concentrates on the DTN layer.

## Rejected alternatives

Building a whole network stack from scratch (2+ years); libp2p (assumes IP).
