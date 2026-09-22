<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# What worries us

The running list README §18.12 `INT-09` mandates, and the memo `ROE-04` makes a
contractual input to every audit. It lists what the engineering side already
believes is weak, unresolved, or shortcut. It is never emptied to look better:
an entry leaves only when the thing it describes is fixed, and the fix is
named.

Each entry carries the date it was opened, the §18.6 checklist item an auditor
would reach it through, and its state.

## Design — open

| Opened | Item | Concern | State |
|---|---|---|---|
| 2026-09-23 | `A017`, `A034` | The tag resynchronisation path of PROTOCOL.md §5.5 is specified but has no adversary argument written down. We believe it cannot be forced and resets no key material; we have not proven it. | Open — AUD-1 question |
| 2026-09-23 | `A015`, `A016` | The skipped-key cap and the 2 000-message chain limit are stated as numbers, not derived from an attacker model. What an attacker buys by forcing eviction is unquantified. | Open — AUD-1 question |
| 2026-09-23 | `A018` | The 16-byte epoch-tag collision bound is asserted against "the expected number of contacts and epochs" without that number being written down anywhere. | Open — AUD-1 question |
| 2026-09-23 | `A019` | The ±2 h clock-skew window is a usability choice. Nobody has analysed what an attacker with clock control achieves inside it. | Open — AUD-1 question |
| 2026-09-23 | `A020` | Trial decryption is claimed to be a non-oracle. The claim rests on both paths being AEAD failures; it has no timing measurement behind it, because the code that would be measured does not exist yet (see QW-U-CRY-031). | Open — blocked on code |
| 2026-09-23 | `F00x`, §8.6 | Peer reputation is worth close to nothing: it binds to a link pseudonym discarded every 24 h, so an attacker resets to zero daily and a Sybil swarm mints one identity per encounter. README §8.6 says so plainly and the copy budget is the real defence. We would rather an auditor tell us the copy bound is also insufficient than discover it in the field. | Open by design — disclosed |
| 2026-09-23 | §5.6 | The 24-hour link pseudonym costs routing quality and anti-Sybil strength, deliberately. The delivery gates in §17.4 assume that cost is survivable. The simulation that would confirm it is Phase 2 work. | Open — blocked on `tools/sim` |

## Verification — open

| Opened | Item | Concern | State |
|---|---|---|---|
| 2026-09-23 | `AUD-4` | `docs/formal/` does not exist. No ProVerif, Verifpal, Tamarin or Noise Explorer model has been written, so AUD-4 has nothing to review and the §17 formal-verification gates are unmet. | Open — not started |
| 2026-09-23 | `K005` | Phase 1 asks for 24 fuzz-hours per target. The nightly caps at 6 h, which is the GitHub-hosted runner limit. `tools/fuzz/soak.sh` runs the remaining 18 h per target, but there is no machine committed to running it, so the budget is unspent. | Open — blocked on runner |
| 2026-09-23 | `B00x`, §16 | Five of the §16 constant-time items are deferred because the code they measure does not exist: QW-U-CRY-031 epoch-tag lookup, 032 duress unwrap, 033 password verification, 035 safety-number comparison, and QW-F-CRY-083, its fuzz target. Recorded in `tools/timing/README.md` and `tools/fuzz/README.md`. | Open — blocked on code |
| 2026-09-23 | `QW-N-CRY-021` | Argon2id derivation latency is bounded on the fastest and the slowest supported device. A CI runner is neither, so the gate cannot run in CI and has no device lab behind it yet. Recorded in `crates/quietwire-crypto/tests/argon2_parameters.rs`. | Open — blocked on device lab |
| 2026-09-23 | `INT-01`, `INT-02` | The project has one maintainer, who is also the reviewer and the signer. Four-eyes review is structurally unavailable; ADR-0013 records the deviation. Every `INT-0x` control that names a second engineer is therefore unmet, and no branch protection can fake it. | Open by design — disclosed |

## Supply chain — accepted

| Opened | Item | Concern | State |
|---|---|---|---|
| 2026-09-23 | `I00x` | `tools/timing` carries three advisories the workspace policy would refuse: RUSTSEC-2021-0139 and RUSTSEC-2024-0375 (unmaintained), RUSTSEC-2021-0145 (unsound). All three arrive through clap 2 under `dudect-bencher`. The tool is never published, never vendored into a release artifact and outside `cargo vet`. Reasons are in `tools/timing/deny.toml`. | Accepted — janpenitent, 2026-09-23 |

## Closed

Nothing yet. An entry moves here with the commit that closed it.
