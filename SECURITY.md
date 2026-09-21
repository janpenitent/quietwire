<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub private vulnerability reporting:

https://github.com/janpenitent/quietwire/security/advisories/new

A dedicated role address and a PGP key, published in three independent places,
will be added here before the first release. Until then private vulnerability
reporting is the only intake channel.

## What to expect

| Step | Deadline |
|---|---|
| Acknowledgement | 72 hours |
| Triage and severity assessment | 7 days |
| Coordinated disclosure | 90 days from the report, or earlier once a fix ships |

Every fixed vulnerability gets a published advisory, including those found
internally, with a CVE identifier requested where applicable. Users running an
affected version are notified in-app on first launch of the fixed release.

## Safe harbour

Good-faith security research on QUIETWIRE is welcome. The maintainers will not
pursue or support legal action against anyone who:

- makes a good-faith effort to avoid privacy violations, data destruction and
  service interruption;
- tests only against devices and data they own or have explicit permission to test;
- reports the vulnerability privately and gives reasonable time to fix it
  before public disclosure.

## Supported versions

No release has been published yet. Once one is, each protocol version is
supported for at least three years after its successor ships.

## Verifying a release

Every release commit and tag is signed, and every release is reproducible from
source. Step-by-step verification commands will be published here with the
first release.
