#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

# The part of the §17 fuzz budget a GitHub-hosted runner cannot reach. Its
# 6-hour job cap leaves 18 of the 24 hours per target unspent, and the
# release-candidate run asks for 72. This runs the remainder on a self-hosted
# runner or a developer machine, one target at a time so each gets the whole
# machine.
set -euo pipefail

hours="${1:-18}"
# Seconds, for checking that the script itself runs without spending a day on
# it. The real budget is always the hour argument.
seconds="${QW_FUZZ_SECONDS:-$((hours * 3600))}"
toolchain="${FUZZ_TOOLCHAIN:-nightly-2026-09-20}"
targets=(x3dh_bundle x3dh_initial_message ratchet_header ratchet_session)

here="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${here}"

printf 'fuzzing %d target(s) for %s s each, toolchain %s\n' \
    "${#targets[@]}" "${seconds}" "${toolchain}" >&2

for target in "${targets[@]}"; do
    printf '\n=== %s  start %s\n' "${target}" "$(date -u +%FT%TZ)" >&2
    cargo +"${toolchain}" fuzz run --fuzz-dir tools/fuzz "${target}" -- \
        -max_total_time="${seconds}" -timeout=1
    printf '=== %s  clean  %s\n' "${target}" "$(date -u +%FT%TZ)" >&2
done

# A run that reaches here crashed nothing, hung nothing and leaked nothing.
# The record of it is this output plus the corpus growth it committed.
printf '\nall targets clean\n' >&2
