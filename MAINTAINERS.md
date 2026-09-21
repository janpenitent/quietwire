<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Maintainers

QUIETWIRE is a single-maintainer project. One person holds every role.

| Role | Person | GitHub |
|---|---|---|
| Maintainer (release authority) | Janier Rodríguez <jrodriguez@virtualcable.es> | @janpenitent |
| Cryptography reviewer (`INT-02`) | Janier Rodríguez <jrodriguez@virtualcable.es> | @janpenitent |

## Signing key

Commits and release tags are signed with the OpenPGP key
`DAB7 4123 0EEE 188D 64AA  7602 6157 60F8 085A C27C`, published at
<https://github.com/janpenitent.gpg>. There is no backup signing key.

## Review

A pull request author cannot approve their own pull request on GitHub, so the
protected-branch ruleset requires zero approvals. Every change still goes
through a pull request and must pass the required status checks, carry signed
and signed-off commits, and keep a linear history. The cryptography paths in
`CODEOWNERS` are reviewed by the maintainer in the pull request itself.
