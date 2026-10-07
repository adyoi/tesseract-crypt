#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
CLEAN="${CLEAN:-0}"
PARALLEL="${PARALLEL:-$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"

usage() {
  cat <<'USAGE'
Usage: scripts/build-linux.sh [--clean] [--type Debug|Release|RelWithDebInfo] [--jobs N]

Builds and tests the project on Linux-like systems.
- Creates/uses BUILD_DIR (default: build)
- Runs ctest after build
- Generates CPack packages (TGZ, DEB when available)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      CLEAN=1
      shift
      ;;
    --type)
      CMAKE_BUILD_TYPE="${2:-Release}"
      shift 2
      ;;
    --jobs)
      PARALLEL="${2:-1}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

if [[ "${CLEAN}" -eq 1 ]]; then
  rm -rf "${BUILD_DIR}"
fi

cmake -S . -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" -DTESS_WARNINGS_AS_ERRORS=ON
cmake --build "${BUILD_DIR}" --parallel "${PARALLEL}"
ctest --test-dir "${BUILD_DIR}" --output-on-failure

cmake --build "${BUILD_DIR}" --target package || true
echo "=== build complete in ${BUILD_DIR} ==="
ls -1 "${BUILD_DIR}"/*.tar.gz "${BUILD_DIR}"/*.deb "${BUILD_DIR}"/*.zip 2>/dev/null | tail -20
