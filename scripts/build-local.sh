#!/usr/bin/env bash
# Helper: configure + build tesseract-crypt with the MSYS2 MinGW toolchain.
# Usage: bash scripts/build-local.sh [build-dir] [extra cmake args...]
set -euo pipefail

export PATH="/c/msys64/mingw64/bin:/c/msys64/usr/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${1:-$ROOT/build-audit}"
shift || true

cmake -S "$ROOT" -B "$BUILD" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DTESS_WARNINGS_AS_ERRORS=ON \
    "$@"

cmake --build "$BUILD" -j"$(nproc)"
