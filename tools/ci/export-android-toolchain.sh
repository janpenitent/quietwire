#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

# The C parts of dependencies (BLAKE3) must be built by the NDK clang for the
# §7.1b Android floor, API 26, not by the host compiler.
set -euo pipefail

: "${TARGET:?}" "${NDK_PREFIX:?}" "${ANDROID_NDK_LATEST_HOME:?}" "${GITHUB_ENV:?}"

llvm="${ANDROID_NDK_LATEST_HOME}/toolchains/llvm"
bin="${llvm}/prebuilt/linux-x86_64/bin"
suffix="${TARGET//-/_}"
{
  echo "CC_${suffix}=${bin}/${NDK_PREFIX}-clang"
  echo "AR_${suffix}=${bin}/llvm-ar"
} >> "$GITHUB_ENV"
