#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

# §19.8: every file that names the repository must name the same one.
set -euo pipefail

expected="github.com/janpenitent/quietwire"
must_mention=(README.md SECURITY.md CONTRIBUTING.md Cargo.toml flake.nix)
status=0

for file in "${must_mention[@]}"; do
    if ! grep -qF "${expected}" "${file}"; then
        echo "${file}: does not mention ${expected}"
        status=1
    fi
done

if git grep -nE 'github\.com/[A-Za-z0-9_.-]+/quietwire' \
    | grep -vF "${expected}"; then
    echo "found a repository URL other than ${expected}"
    status=1
fi

exit "${status}"
