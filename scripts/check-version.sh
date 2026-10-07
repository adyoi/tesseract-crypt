#!/bin/sh
# check-version.sh — assert the declared package version is consistent.
#
# The version is declared in three places that must agree:
#   1. CMakeLists.txt        project(VERSION x.y.z)
#   2. include/tesseract/tesseract.h   TESS_VERSION_* macros / TESS_VERSION_STRING
#   3. CHANGELOG.md           newest "## [x.y.z]" entry
#
# Run from anywhere; used by CI to catch a forgotten version bump.
# Exit status 0 = consistent, 1 = mismatch.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cmake_ver=$(sed -n 's/^[[:space:]]*VERSION[[:space:]]*\([0-9][0-9.]*\).*/\1/p' \
    "$root/CMakeLists.txt" | head -n 1)
[ -n "$cmake_ver" ] || { echo "check-version: no VERSION in CMakeLists.txt" >&2; exit 1; }

hdr_major=$(sed -n 's/^#define[[:space:]]*TESS_VERSION_MAJOR[[:space:]]*\([0-9]*\).*/\1/p' \
    "$root/include/tesseract/tesseract.h")
hdr_minor=$(sed -n 's/^#define[[:space:]]*TESS_VERSION_MINOR[[:space:]]*\([0-9]*\).*/\1/p' \
    "$root/include/tesseract/tesseract.h")
hdr_patch=$(sed -n 's/^#define[[:space:]]*TESS_VERSION_PATCH[[:space:]]*\([0-9]*\).*/\1/p' \
    "$root/include/tesseract/tesseract.h")
hdr_str=$(sed -n 's/^#define[[:space:]]*TESS_VERSION_STRING[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$root/include/tesseract/tesseract.h")
hdr_ver="$hdr_major.$hdr_minor.$hdr_patch"

if [ "$hdr_ver" != "$cmake_ver" ]; then
    echo "check-version: header $hdr_ver != CMakeLists $cmake_ver" >&2
    exit 1
fi
if [ "$hdr_str" != "$cmake_ver" ]; then
    echo "check-version: TESS_VERSION_STRING '$hdr_str' != $cmake_ver" >&2
    exit 1
fi

cl_ver=$(grep -m 1 '^## \[' "$root/CHANGELOG.md" | sed 's/^## \[\([0-9][0-9.]*\)\].*/\1/')
if [ -z "$cl_ver" ] || [ "$cl_ver" != "$cmake_ver" ]; then
    echo "check-version: CHANGELOG top entry '$cl_ver' != $cmake_ver" >&2
    exit 1
fi

echo "check-version: $cmake_ver consistent (CMakeLists + header + CHANGELOG)"