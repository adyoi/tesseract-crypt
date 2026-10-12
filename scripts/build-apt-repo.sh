#!/usr/bin/env bash
# build-apt-repo.sh — lay out an APT repository on GitHub Pages.
#
#   usage: build-apt-repo.sh <package.deb> <apt-root> [key-id]
#
# Produces:
#   <apt-root>/dists/stable/{InRelease,Release,Release.gpg,
#                            main/binary-amd64/{Packages,Packages.gz,Release}}
#   <apt-root>/pool/main/t/tesseract-crypt/<package.deb>
#
# [key-id] is the keygrip/fingerprint of an already-imported key.  When given,
# the suite Release is GPG-signed (InRelease + Release.gpg).  The signing key
# passphrase, if any, is read from $APT_SIGNING_KEY_PASSPHRASE (default "").
# Without a key id the repo is left unsigned (InRelease is omitted).
set -euo pipefail

DEB="${1:?usage: build-apt-repo.sh <package.deb> <apt-root> [key-id]}"
APT="${2:?usage: build-apt-repo.sh <package.deb> <apt-root> [key-id]}"
KEYID="${3:-}"

# resolve to an absolute path: makes every relative redirect/`cd` inside the
# apt-ftparchive subshell unambiguous
case "$APT" in
    /*) : ;;
    *) APT="$(pwd -P)/$APT" ;;
esac

ARCH="amd64"
SUITE="stable"
COMP="main"
PKGNAME="tesseract-crypt"

command -v apt-ftparchive >/dev/null 2>&1 ||
    { echo "apt-ftparchive missing — install apt-utils" >&2; exit 1; }
[ -f "$DEB" ] || { echo "no such package: $DEB" >&2; exit 1; }

DIST="$APT/dists/$SUITE"
BIN="$DIST/$COMP/binary-$ARCH"
POOL="$APT/pool/$COMP/t/$PKGNAME"

rm -rf "$APT"
mkdir -p "$BIN" "$POOL"
cp "$DEB" "$POOL/"

# Packages indexes (amd64)
(
    cd "$APT"
    apt-ftparchive packages "pool/$COMP" > "$BIN/Packages"
    gzip -9c "$BIN/Packages" > "$BIN/Packages.gz"
)

# binary-<arch> Release
apt-ftparchive -o "APT::FTPArchive::Release::Architecture=$ARCH" \
    release "$BIN" > "$BIN/Release"

# suite Release
apt-ftparchive \
    -o "APT::FTPArchive::Release::Origin=Tesseract Crypt" \
    -o "APT::FTPArchive::Release::Label=Tesseract Crypt" \
    -o "APT::FTPArchive::Release::Suite=$SUITE" \
    -o "APT::FTPArchive::Release::Codename=$SUITE" \
    -o "APT::FTPArchive::Release::Architectures=$ARCH" \
    -o "APT::FTPArchive::Release::Components=$COMP" \
    -o "APT::FTPArchive::Release::Date=$(date -Ru -u)" \
    release "$DIST" > "$DIST/Release"

if [ -n "$KEYID" ]; then
    command -v gpg >/dev/null 2>&1 ||
        { echo "gpg missing — install gnupg" >&2; exit 1; }
    PASS="${APT_SIGNING_KEY_PASSPHRASE:-}"
    # Suite Release must exist in $DIST; run from there so gpg finds it.
    gpg --batch --yes --pinentry-mode loopback --passphrase "$PASS" \
        --local-user "$KEYID" --detach-sign --armor \
        -o "$DIST/Release.gpg" "$DIST/Release"
    gpg --batch --yes --pinentry-mode loopback --passphrase "$PASS" \
        --local-user "$KEYID" --clear-sign \
        -o "$DIST/InRelease" "$DIST/Release"
else
    echo "no signing key given — repository left unsigned (InRelease omitted)" >&2
fi

echo "APT repository ready at $APT"
find "$APT" -type f | sort