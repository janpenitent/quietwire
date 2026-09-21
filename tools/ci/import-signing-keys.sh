#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

# Imports the keys GitHub publishes for the maintainers and for web-flow,
# which signs squash and merge commits created in the web UI.
set -euo pipefail

signers=(web-flow janpenitent)

for account in "${signers[@]}"; do
    curl --proto '=https' --tlsv1.2 -fsSL "https://github.com/${account}.gpg" | gpg --batch --import
done
