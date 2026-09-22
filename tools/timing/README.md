<!--
SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>

SPDX-License-Identifier: CC-BY-4.0
-->

# Timing harness

Welch's t-test over the secret-dependent operations of §16, with
`dudect-bencher`. Each operation gets two classes of input that differ only in
where a secret byte differs; a comparison that stops at the first mismatch
separates the classes, a constant-time one does not.

This crate stays outside the workspace because `dudect-bencher` builds a
standalone command line on clap 2, which drags in three crates the workspace
policy refuses. It never ships: it is not published, not vendored into any
release artifact and not covered by `cargo vet`. `deny.toml` here is the root
policy with exactly those three exemptions, each with its reason, so relaxing
them cannot weaken the workspace scan.

## Coverage

| Bench | Item | Operation |
|---|---|---|
| `aead_tag` | QW-U-CRY-030 | the Poly1305 tag comparison in `aead::open` |
| `secret_key_eq` | QW-U-CRY-036 | `PartialEq` on `SecretKey`, the only secret type that has one |
| `mutant_secret_key_eq` | QW-U-CRY-046 | the same comparison, deliberately not constant time |

The remaining items of §16 arrive with the code they measure:

- QW-U-CRY-031 epoch-tag map lookup, QW-U-CRY-032 duress DEK unwrap and
  QW-U-CRY-033 password verification: `password::derive_kek` produces a KEK
  today, but nothing verifies one yet;
- QW-U-CRY-034 skipped-key lookup: `ratchet::SkippedKeys` is keyed on the
  ratchet key and message number the peer puts in the frame header, both
  public, so there is no secret to leak. It gets a bench if it is ever keyed on
  anything else;
- QW-U-CRY-035 safety-number comparison: with the renderer, like
  QW-F-CRY-083.

`x25519::agree` rejects an all-zero shared secret with `ConstantTimeEq`, but
the outcome of that check is a public error return, so measuring it would only
measure the branch it is allowed to take.

## The mutant

QW-U-CRY-046 asks for a deliberate mutant that the suite must fail on.
Replacing `ConstantTimeEq` with `==` on `[u8; 32]` is not one: the compiler
lowers it to a single vector comparison, below the resolution of the clock the
harness reads, and almost every sample is cropped as an outlier. Measured at
3 · 10⁶ samples:

```
bench array_eq ... : n == +0.015M, max t = +1.68610
bench ct       ... : n == +2.952M, max t = +1.92931
bench loop_eq  ... : n == +2.986M, max t = -40.30756
```

So the mutant is the ordinary short-circuiting byte loop, which is what an
implementation would actually get wrong.

## Measurement hygiene

`aead_tag` writes the wrong byte into one buffer instead of picking between
two, because two allocations holding the same bytes are themselves separable:
they measured |t| ≈ 5 at 3 · 10⁶ samples with no tag involved. `SecretKey`
owns a page-aligned locked page, so its two inputs sit identically in the cache
and can be picked between.

Every bench draws its class and prepares its input outside `run_one`, which is
the only timed region.

## Running

```sh
tools/ci/constant-time.sh
```

10⁷ samples per operation, about two minutes. `QW_TIMING_SAMPLES` shortens a
run while working on it; the CI gate uses the default. The gate fails a bench
whose |t| crosses 4.5 in the wrong direction, and one whose surviving sample
count is so low that it passed by measuring nothing.

A verdict of "leaks" needs every usable run to cross 4.5 in the same
direction, because a shared runner crosses it on scheduling noise alone, and
at ten million samples it can do so several runs in a row: `secret_key_eq` has
been seen at -7.3, +8.6 and +4.6 in three consecutive CI runs. The sign is
what separates that from a leak. Noise flips it; a real bias does not, and the
planted leak holds one sign at t = -1622 with a tau three orders of magnitude
larger than anything the real benches produce. `QW_TIMING_ATTEMPTS` caps how
many runs the gate will spend before giving up; a clean verdict ends it early,
so an operation that is in fact constant-time normally costs a single run.

```sh
tools/timing/target/release/quietwire-timing --filter aead --continuous aead_tag
```

`--continuous` runs one bench until interrupted, which is how a borderline
result gets settled.
