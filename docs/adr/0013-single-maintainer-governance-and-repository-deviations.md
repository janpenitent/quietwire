<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0013: Single-maintainer governance and repository deviations

- Status: Accepted
- Date: 2026-09-21
- Source: project plan §17.11, §18.12, §19.7, §19.8, §19.9

## Context

The plan assumes two maintainers, hardware signing keys and a repository owned
by an organization. QUIETWIRE starts as a one-person project on a
user-owned repository, with an OpenPGP signing key kept in software. Several
requirements cannot be met as written, and silent non-compliance is worse than
a recorded one.

## Decision

1. **One maintainer holds every role**, including release authority and the
   `INT-02` cryptography review (`MAINTAINERS.md`). GitHub forbids approving
   one's own pull request, so the protected-branch ruleset requires zero
   approvals. Every change still goes through a pull request with all required
   status checks, signed and signed-off commits and linear history. The
   four-eyes rule of `INT-01` and §19.7 is not met.
2. **The signing key is an OpenPGP key stored in software**, with no backup
   key in separate custody. Audit items `I007` and `I014` are not met.
3. **No `.allowed_signers` file.** It lists SSH signing keys; commits are
   signed with OpenPGP, and CI imports the published keys from
   `https://github.com/<account>.gpg` (`tools/ci/import-signing-keys.sh`).
4. **`REUSE.toml` replaces `.reuse/dep5`**, which REUSE 3.x deprecates.
5. **The reproducible-build check (§17.11 stage 8) runs on every pull request**
   and is a required status check, because GitHub rejects merge queues on
   user-owned repositories.

Items 1 and 2 weaken security properties. The project has made no release and
has no users, so they are accepted for development only: before the first
release tag, each is either closed (a second maintainer with a backup key; a
hardware-backed signing key) or restated in a superseding ADR that goes
through the 30-day comment period of §19.7.

## Consequences

- A compromised maintainer account or laptop can merge and sign anything. The
  signature walk, DCO check and settings-drift check make such a change
  visible, not impossible.
- The external audits of §18 remain the only independent review of the
  cryptography until a second reviewer exists.
- Each pull request waits for two Nix builds. When the repository moves to an
  organization, stage 8 moves to a merge queue scoped to `~DEFAULT_BRANCH`.

## Rejected alternatives

- Requiring one approval: blocks every merge, since the only maintainer cannot
  approve their own pull request.
- Bypass actors on the ruleset: an exception that is always used is no rule.
- Dropping stage 8 until a merge queue is available: leaves reproducibility
  untested until the first release.
