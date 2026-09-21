#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

# QW-C-SYS-353: every commit in the range carries a Signed-off-by trailer
# naming its author by email or by name. Dependabot signs off as
# "dependabot[bot] <support@github.com>" while authoring from a noreply
# address, so an email-only match would reject every bot update.
set -euo pipefail

range="${1:?usage: dco-check.sh <revision-range>}"
status=0

for commit in $(git rev-list --no-merges "${range}"); do
    author_name="$(git log -1 --pretty='%an' "${commit}")"
    author_email="$(git log -1 --pretty='%ae' "${commit}")"
    if ! git log -1 --pretty='%(trailers:key=Signed-off-by,valueonly)' "${commit}" \
        | grep -qiF -e "<${author_email}>" -e "${author_name} <"; then
        echo "missing Signed-off-by for ${author_name} <${author_email}>: $(git log -1 --oneline "${commit}")"
        status=1
    fi
done

exit "${status}"
