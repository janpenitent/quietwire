<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Maintainers

| Role | Person | GitHub | Signing key | Custody |
|---|---|---|---|---|
| Maintainer (release authority) | Janier Rodríguez <jrodriguez@virtualcable.es> | @janpenitent | OpenPGP RSA-4096 `DAB7 4123 0EEE 188D 64AA  7602 6157 60F8 085A C27C` | Software key on the maintainer's workstation |
| Second maintainer (backup signing key) | *vacant* | | | |
| Cryptography reviewer (`INT-02`) | *vacant* | | | |

Security-relevant decisions require both maintainers. Until the second
maintainer is appointed, no release may be tagged.

## Open items before the first release

- **Hardware-backed signing key.** The current key is stored on disk. It must be
  replaced by an OpenPGP subkey on a hardware token, or a FIDO2 SSH key, before
  any release tag is signed.
- **Employer authorisation.** Commits are authored and signed off with the
  address `jrodriguez@virtualcable.es`. A written statement from Virtual Cable
  S.L.U. confirming that this contribution is authorised under Apache-2.0 must be
  recorded in this file, or the commit identity moved to a personal address.
- **Second maintainer** with a backup signing key in separate physical custody.
- **Cryptography reviewer** named in `CODEOWNERS`.
