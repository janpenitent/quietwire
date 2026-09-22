<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Audit

Where the external reviews of README §18 land. One directory per audit, named
`<year>-<type>-<firm>`, holding the full unredacted report, the "what worries
us" memo written before it, the response to every finding including the
disputed ones, the re-test report, and the commit hashes audited and fixed.

Two files live here permanently rather than inside one audit:

- [`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md) — the running "what worries us"
  list `INT-09` mandates. It is also the `ROE-04` memo every audit contracts
  for, so it is written continuously instead of assembled at kickoff.
- [`ROTATION.md`](ROTATION.md) — which firm did which audit in which year,
  checked against the §18.2 rotation rule at contract signature.

## State

| Audit | Scope | State |
|---|---|---|
| AUD-1 Cryptographic design | `docs/PROTOCOL.md`, `docs/formal/` | Ready to issue, not contracted |
| AUD-4 Formal verification | `docs/formal/` | Blocked — no model written |
| AUD-2, 3, 5–11 | Code, platforms, forensics, RF, legal | Not due until the layers they cover exist |
| AUD-12 Internal continuous | Every commit | Running, with the ADR-0013 deviations |
| AUD-13 Bug bounty | Public | After v1.0 |

## AUD-1 readiness

README §11 places AUD-1 at the end of Phase 1, around week 9, deliberately
earlier than the §18.14 calendar implies: a design flaw found once the packet,
storage and transport layers exist invalidates all of them. What the review
needs is therefore ready now, except for two inputs it shares with AUD-4.

| Input | §18 reference | State |
|---|---|---|
| `docs/PROTOCOL.md` | §18.3 scope | Complete for the layers Phase 1 builds |
| Design decisions and their rejected alternatives | §18.3 scope | `docs/adr/`, 20 records |
| Threat model | `A029` | `docs/THREAT_MODEL.md` |
| "What worries us" memo | `ROE-04` | [`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md) |
| §17 test artefacts, fuzzing corpora | `ROE-03` | Crypto suite, four fuzz targets, timing harness |
| Formal models | `A00x` background, AUD-4 scope | **Missing** — `docs/formal/` does not exist |
| Test mesh, 6 devices and 4 RNodes | `ROE-02` | **Missing** — no hardware |
| Contract, named reviewers, fee | §18.2 | **Not started** — funding decision |

The two missing technical inputs are recorded as open entries in
`OPEN_QUESTIONS.md` rather than treated as done, and the checklist items they
would have answered will come back from the auditor marked "Not reviewed".
That is the honest outcome, and §18.6 requires the justification to be written
down, which is what this table is.
