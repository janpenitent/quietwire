<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing to QUIETWIRE

Repository: https://github.com/janpenitent/quietwire

## Developer Certificate of Origin

Contributions are accepted under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
There is no CLA and no copyright assignment. Certify each commit by signing it off:

```bash
git commit -s
```

The `Signed-off-by` email must match the commit author email and the email of
the signing key. CI (`dco-check`) rejects any commit where they differ.

## Signing — every commit, every tag

Every commit and tag must show **Verified** on GitHub. Unsigned commits cannot
merge, and one unsigned commit anywhere in history blocks a release. Signing
keys should be hardware-backed.

```bash
# --- Identity: set it per-repository, not globally ---
git config user.name  "<your name>"
git config user.email "<email verified on your GitHub account>"

# --- Option A: SSH signing (simplest, hardware-backed with a FIDO2 key) ---
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "quietwire signing"
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global push.gpgSign if-asked
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
# then add the SAME key to GitHub twice: once as an Authentication key,
# once as a SIGNING key. Adding it only as an authentication key is the
# single most common reason commits still show Unverified.

# --- Option B: OpenPGP on a YubiKey ---
git config --global user.signingkey <KEYID>
git config --global commit.gpgsign true
git config --global tag.gpgsign true
# Upload the PUBLIC key to GitHub, and make sure the UID email matches
# the commit author email exactly, verified on the account.
```

Also turn on **Vigilant Mode** ("Flag unsigned commits as unverified") in your
GitHub account settings.

Check before pushing:

```bash
git log --show-signature -1
```

## Merging

Pull requests merge by **squash** or **merge commit** only. Rebase merge is
disabled because GitHub does not sign rebased commits.

## Review expectations

- Two approving reviews. Changes under `crates/quietwire-crypto/` and
  `crates/quietwire-e2e/` also need the cryptography reviewer (`CODEOWNERS`).
- Every change states which tests (`QW-<LEVEL>-<AREA>-<NNN>`) cover it.
- A change that weakens a security property needs a published ADR in
  `docs/adr/` and a 30-day comment period before it can merge.

## Before opening a pull request

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo deny check
reuse lint
```

Every new file needs an SPDX header (`reuse annotate`). Code is Apache-2.0,
specifications and documentation CC-BY-4.0, test vectors and corpora CC0-1.0.

## Security issues

Never in a public issue. See `SECURITY.md`.
