<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0012: Reproducible builds with Nix, and Python only for tooling

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §3

## Context

Anyone must be able to verify that a published binary matches the published source. Lab tooling needs a fast scripting language that must never enter the security path.

## Decision

Builds are defined in `flake.nix`, binaries carry `cargo-auditable` metadata, and releases publish SLSA provenance. Python 3.12 is used only for the simulator, lab bench and Raspberry Pi provisioning under `tools/`.

## Consequences

Two independent machines must produce bit-identical artefacts. Python code never links into a shipped binary.

## Rejected alternatives

Trusting CI blindly; Python in the core.
