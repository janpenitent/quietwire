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
# A shared CI runner hands a single run a t statistic that crosses the
# threshold on scheduling noise alone: locally the two real benches land
# between -2.1 and +2.9 but flip sign from run to run, while the planted leak
# stays near -50 with the same sign every time. A leak is therefore declared
# only when every usable run agrees, which leaves the §16 threshold itself
# untouched. The common case still costs one run: the loop stops as soon as
# the evidence so far clears every bench.
attempts="${QW_TIMING_ATTEMPTS:-3}"

cargo build --manifest-path tools/timing/Cargo.toml --release --locked

log="$(mktemp)"
trap 'rm -f "${log}"' EXIT

verdict() {
    awk -v floor="${floor}" -v threshold="${threshold}" '
        /max t = / {
            name = $2
            t = substr($0, index($0, "max t = ") + 8) + 0
            n = (substr($0, index($0, "n == ") + 5) + 0) * 1000000
            if (!(name in usable)) {
                usable[name] = 0
                leaked[name] = 0
                order[++count] = name
            }
            if (n < floor) next
            usable[name]++
            if (t < -threshold || t > threshold) leaked[name]++
        }
        END {
            if (count == 0) {
                print "no bench reported a t statistic"
                exit 1
            }
            for (i = 1; i <= count; i++) {
                name = order[i]
                runs = usable[name]
                if (runs == 0) {
                    printf "%s: no run kept %d samples through cropping\n", name, floor
                    status = 1
                } else if (name ~ /^mutant_/ && leaked[name] < runs) {
                    printf "%s: |t| stayed below %.1f in %d of %d runs — the harness cannot see a known leak\n",
                        name, threshold, runs - leaked[name], runs
                    status = 1
                } else if (name !~ /^mutant_/ && leaked[name] == runs) {
                    printf "%s: |t| above %.1f in all %d runs — the operation leaks timing\n",
                        name, threshold, runs
                    status = 1
                }
            }
            exit status
        }
    ' "$1"
}

for attempt in $(seq "${attempts}"); do
    printf 'dudect run %d of %d\n' "${attempt}" "${attempts}" >&2
    QW_TIMING_SAMPLES="${samples}" tools/timing/target/release/quietwire-timing |
        tee -a "${log}" >&2
    # More runs can only clear a bench, never condemn one, so the first clean
    # verdict is the final one.
    if verdict "${log}"; then
        exit 0
    fi
done

verdict "${log}"
