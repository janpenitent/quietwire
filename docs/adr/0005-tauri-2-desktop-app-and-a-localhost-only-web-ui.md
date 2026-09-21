<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0005: Tauri 2 desktop app and a localhost-only web UI

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

Desktop users on Windows, macOS and Linux need the same core, and a web interface is required without putting keys in a browser.

## Decision

The desktop app uses Tauri 2.x with a Rust backend and a Svelte 5 frontend, linking the core as a native library. The web interface is a local-only UI served by the desktop node on `127.0.0.1`.

## Consequences

Roughly 8 MB binaries with no Node runtime shipped. There is no public web app.

## Rejected alternatives

Electron (size, Node inside the trust boundary), Qt (licensing and FFI friction), a public web app (keys in the browser).
