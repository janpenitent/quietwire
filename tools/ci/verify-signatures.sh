#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

# QW-C-SYS-351: every reachable commit must carry a good signature (G or U).
set -euo pipefail

git log "${@:---all}" --pretty='%H %G?' \
    | awk '$2 !~ /^[GU]$/ { print "unsigned or bad signature: " $0; bad=1 } END { exit bad }'
