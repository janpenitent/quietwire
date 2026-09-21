#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

# Installs the gitleaks release pinned by GITLEAKS_VERSION into /usr/local/bin,
# refusing any archive whose SHA-256 is not GITLEAKS_SHA256.
set -euo pipefail

: "${GITLEAKS_VERSION:?}" "${GITLEAKS_SHA256:?}"

archive="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

curl --proto '=https' --tlsv1.2 -fsSL -o "${workdir}/${archive}" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${archive}"
echo "${GITLEAKS_SHA256}  ${workdir}/${archive}" | sha256sum --check --strict
tar -xzf "${workdir}/${archive}" -C "${workdir}" gitleaks
sudo install -m 0755 "${workdir}/gitleaks" /usr/local/bin/gitleaks
