<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Fuzz targets

cargo-fuzz targets for the parsers and state machines that read peer input
(§17). This crate stays outside the workspace because it needs a nightly
toolchain, and it never ships: it is not published, not vendored into any
release artifact, and not covered by `cargo vet`.

| Target | Item | Input |
|---|---|---|
| `x3dh_bundle` | QW-F-CRY-080 | a peer's prekey bundle, read by an initiator |
| `x3dh_initial_message` | QW-F-CRY-080 | a peer's identity and initial message, read by a responder |
| `ratchet_header` | QW-F-E2E-081 | the header of one frame, on a live session |
| `ratchet_session` | QW-F-E2E-082 | a whole conversation: reordered, lost, duplicated and tampered frames |

QW-F-CRY-083 arrives with the safety-number renderer it fuzzes.

## Running

```sh
cargo +nightly-2026-09-20 fuzz run --fuzz-dir tools/fuzz <target> -- -max_total_time=60 -timeout=1
```

`-timeout=1` is the §17 hang budget: an input that takes longer than a second
is a failure. Crashes, hangs and OOMs all block a release.

## Oracles

Random bytes are almost never a valid ML-KEM or Ed25519 public key, so the
targets edit genuine keys as well as generating raw ones
(`quietwire_fuzz::PeerIdentity`). Beyond "it did not crash", each target
asserts:

- the X3DH targets: every outcome is either a session or `InvalidPublicKey`;
- `ratchet_header`: only the frame the peer actually sent decrypts, it decrypts
  exactly once, and the session still opens the next genuine frame;
- `ratchet_session`: the model of `crates/quietwire-e2e/tests/ratchet_properties.rs`
  — every frame opens once to its plaintext, duplicates are refused with
  `Authentication`, tampered frames never open.

## Corpus

`corpus/<target>/` is committed and grows monotonically: inputs are minimised
(`cargo fuzz cmin`) and never deleted. It is generated data, licensed CC0-1.0,
and holds no real key material (§17.12).

`x3dh_initial_message` reads about 1.4 kB per input — mostly the ML-KEM
ciphertext — and rejects anything shorter before it reaches the responder, so
its corpus is seeded with random inputs of that length. Starting it from an
empty corpus wastes the run.

## Schedule

- every push: 60 s per target, in CI;
- nightly: 6 h per target, the GitHub-hosted runner cap. The 24 h nightly and
  72 h release-candidate runs of §17 need a self-hosted runner or a local
  machine.
