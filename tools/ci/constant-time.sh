#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

# §16: Welch's t-test over every secret-dependent operation, and the
# QW-U-CRY-046 meta-test that proves the harness can see a leak at all.
set -euo pipefail

samples="${QW_TIMING_SAMPLES:-10000000}"
# dudect crops the samples it considers outliers, so a bench can report a
# near-empty population and pass vacuously. Below this floor the run says
# nothing.
floor=1000000
threshold=4.5

cargo build --manifest-path tools/timing/Cargo.toml --release --locked

QW_TIMING_SAMPLES="${samples}" tools/timing/target/release/quietwire-timing |
    tee /dev/stderr |
    awk -v floor="${floor}" -v threshold="${threshold}" '
        /max t = / {
            name = $2
            t = substr($0, index($0, "max t = ") + 8) + 0
            n = (substr($0, index($0, "n == ") + 5) + 0) * 1000000
            leaks = (t < -threshold || t > threshold)
            mutant = (name ~ /^mutant_/)
            if (n < floor) {
                printf "%s: only %d samples survived cropping, need %d\n", name, n, floor
                status = 1
            } else if (mutant && !leaks) {
                printf "%s: |t| = %.5f below %.1f — the harness cannot see a known leak\n", name, t, threshold
                status = 1
            } else if (!mutant && leaks) {
                printf "%s: |t| = %.5f above %.1f — the operation leaks timing\n", name, t, threshold
                status = 1
            }
            seen++
        }
        END {
            if (seen == 0) {
                print "no bench reported a t statistic"
                status = 1
            }
            exit status
        }
    '
