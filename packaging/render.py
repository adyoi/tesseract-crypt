#!/usr/bin/env python3
"""Render Homebrew, Scoop, Chocolatey and Arch metadata for a tesseract-crypt release.

Usage:
    render.py --version 1.2.3 --dist dist --out out [--repo adyoi/tesseract-crypt]
    render.py --version 1.2.3 --dist build --out out --only pkgbuild

Hashes are taken from the asset files in --dist when present, otherwise from a
``SHA256SUMS`` file in the same directory, so the script also runs without the
large binaries.  ``--only`` renders a single target and then only the assets
that target needs, which is what lets the Linux release job emit the Arch
PKGBUILD while holding nothing but the Linux assets.
"""

import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_DEFAULT = "adyoi/tesseract-crypt"

# The version is substituted verbatim into shell (PKGBUILD ``pkgver=``),
# PowerShell (Chocolatey ``$version =``) and XML (AppVeyor/Homebrew) templates,
# so anything outside a version grammar is an injection into the generated
# files.  Arch additionally forbids ``-`` in pkgver.  Accept an optional leading
# ``v`` plus dotted numeric components and an optional pre-release suffix.
VERSION_RE = re.compile(r"^v?\d+(?:\.\d+)*[A-Za-z0-9.]*$")


def normalize_version(raw):
    """Validate and normalize ``--version``; exit(2) on anything unusable."""
    version = raw.strip()
    if version.startswith("v"):
        version = version[1:]
    if not version or not VERSION_RE.match(raw.strip()):
        sys.stderr.write(
            "render.py: refusing unsafe --version %r: expected something like "
            "'1.2.3' or 'v1.2.3' (letters, digits and dots only)\n" % raw
        )
        sys.exit(2)
    return version


class Assets(object):
    """Resolve released assets to ``(url, sha256)`` with a friendly failure."""

    def __init__(self, dist, base):
        self.dist = dist
        self.base = base
        self.sums = load_sums(dist)

    def sha(self, name):
        """sha256 of an asset, or None when the release does not carry it."""
        return sha_for(self.dist, self.sums, name)

    def url(self, name):
        return "%s/%s" % (self.base, name)

    def __call__(self, name):
        digest = self.sha(name)
        if not digest:
            sys.exit("error: missing asset for %s" % name)
        return self.url(name), digest


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_sums(dist):
    sums = {}
    path = os.path.join(dist, "SHA256SUMS")
    if not os.path.isfile(path):
        return sums
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) == 2:
                sums[parts[1].lstrip("*")] = parts[0]
    return sums


def sha_for(dist, sums, name):
    path = os.path.join(dist, name)
    if os.path.isfile(path):
        return file_sha256(path)
    return sums.get(name)


def render(template_path, values):
    with open(template_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    for key, value in values.items():
        text = text.replace("@@%s@@" % key, value)
    return text


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote", path)


# --------------------------------------------------------------- targets ---


def render_homebrew(version, out, repo, asset):
    macos = asset("tesseract-crypt-%s-macOS-universal2.tar.gz" % version)
    linux_amd64 = asset("tesseract-crypt-%s-Linux-x86_64.tar.gz" % version)
    linux_arm64 = asset("tesseract-crypt-%s-Linux-aarch64.tar.gz" % version)

    text = render(
        os.path.join(HERE, "homebrew", "tesseract-crypt.rb.in"),
        {
            "version": version,
            "sha_macos": macos[1],
            "sha_linux_x86_64": linux_amd64[1],
            "sha_linux_aarch64": linux_arm64[1],
        },
    )
    write(os.path.join(out, "homebrew", "tesseract-crypt.rb"), text)


def render_scoop(version, out, repo, asset):
    architectures = {}
    for key, stem in (
        ("64bit", "Windows-x64"),
        ("32bit", "Windows-x86"),
        ("arm64", "Windows-arm64"),
    ):
        name = "tesseract-crypt-%s-%s.zip" % (version, stem)
        digest = asset.sha(name)
        if digest:
            architectures[key] = {
                "url": asset.url(name),
                "hash": digest,
                "extract_dir": "tesseract-crypt-%s-%s" % (version, stem),
            }
    if "64bit" not in architectures:
        sys.exit("error: missing asset for tesseract-crypt-%s-Windows-x64.zip" % version)

    scoop = {
        "version": version,
        "description": "Hybrid public-key string & file encryption (libsodium)",
        "homepage": "https://github.com/%s" % repo,
        "license": "MIT",
        "architecture": architectures,
        "bin": ["bin\\tesseract-crypt.exe", "bin\\tscrypt.exe"],
        "checkver": {"github": "https://github.com/%s" % repo},
    }
    write(
        os.path.join(out, "scoop", "tesseract-crypt.json"),
        json.dumps(scoop, indent=4) + "\n",
    )


def render_chocolatey(version, out, repo, asset):
    win_setup_x64 = asset("tesseract-crypt-%s-windows-x64-setup.exe" % version)
    win_setup_x86 = asset("tesseract-crypt-%s-windows-x86-setup.exe" % version)

    nuspec = render(
        os.path.join(HERE, "chocolatey", "tesseract-crypt.nuspec.in"),
        {"version": version},
    )
    write(os.path.join(out, "chocolatey", "tesseract-crypt.nuspec"), nuspec)

    install_ps1 = render(
        os.path.join(HERE, "chocolatey", "tools", "chocolateyinstall.ps1.in"),
        {
            "version": version,
            "url_setup_x64": win_setup_x64[0],
            "sha_setup_x64": win_setup_x64[1],
            "url_setup_x86": win_setup_x86[0],
            "sha_setup_x86": win_setup_x86[1],
        },
    )
    write(
        os.path.join(out, "chocolatey", "tools", "chocolateyinstall.ps1"),
        install_ps1,
    )

    # No placeholders: the uninstaller resolves the Inno Setup entry by
    # wildcard at uninstall time.
    uninstall_ps1 = render(
        os.path.join(HERE, "chocolatey", "tools", "chocolateyuninstall.ps1.in"),
        {},
    )
    write(
        os.path.join(out, "chocolatey", "tools", "chocolateyuninstall.ps1"),
        uninstall_ps1,
    )


def render_pkgbuild(version, out, repo, asset):
    """Arch package recipe for the prebuilt release tarball (AUR `-bin` style)."""
    linux_amd64 = asset("tesseract-crypt-%s-Linux-x86_64.tar.gz" % version)

    text = render(
        os.path.join(HERE, "arch", "PKGBUILD.in"),
        {
            "version": version,
            "url_linux_x86_64": linux_amd64[0],
            "sha_linux_x86_64": linux_amd64[1],
        },
    )
    write(os.path.join(out, "arch", "PKGBUILD"), text)


# Insertion order matters: the default run must keep asking for the Homebrew
# assets first, so a release that misses an asset fails on the same name.
TARGETS = {
    "homebrew": render_homebrew,
    "scoop": render_scoop,
    "chocolatey": render_chocolatey,
    "pkgbuild": render_pkgbuild,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--repo", default=REPO_DEFAULT)
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        choices=sorted(TARGETS),
        help="render just this target (repeatable); default: all of them",
    )
    args = parser.parse_args()

    version = normalize_version(args.version)
    base = "https://github.com/%s/releases/download/v%s" % (args.repo, version)
    asset = Assets(args.dist, base)

    for target in args.only or list(TARGETS):
        TARGETS[target](version=version, out=args.out, repo=args.repo, asset=asset)


if __name__ == "__main__":
    main()
