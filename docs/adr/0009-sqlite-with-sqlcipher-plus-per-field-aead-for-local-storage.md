<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0009: SQLite with SQLCipher plus per-field AEAD for local storage

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

Data at rest must leak nothing, including schema and indices, even if one encryption layer fails.

## Decision

Local storage is SQLite 3 via `rusqlite` with SQLCipher page encryption, and every sensitive field is additionally sealed with XChaCha20-Poly1305.

## Consequences

Two independent layers. Queries remain possible.

## Rejected alternatives

Plain SQLite (leaks), Realm (proprietary), flat files (no queries).
