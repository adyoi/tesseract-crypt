#!/usr/bin/env python3
"""Render Homebrew, Scoop and Chocolatey manifests for a tesseract-crypt release.

Usage:
    render.py --version 1.0.2 --dist dist --out out [--repo adyoi/tesseract-crypt]

Hashes are taken from the asset files in --dist when present, otherwise from a
``SHA256SUMS`` file in the same directory, so the script also runs without the
large binaries.
"""

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_DEFAULT = "adyoi/tesseract-crypt"


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--repo", default=REPO_DEFAULT)
    args = parser.parse_args()

    version = args.version.lstrip("v")
    base = "https://github.com/%s/releases/download/v%s" % (args.repo, version)
    sums = load_sums(args.dist)

    def asset(name):
        digest = sha_for(args.dist, sums, name)
        if not digest:
            sys.exit("error: missing asset for %s" % name)
        return base + "/" + name, digest

    macos = asset("tesseract-crypt-%s-macOS-universal2.tar.gz" % version)
    linux_amd64 = asset("tesseract-crypt-%s-Linux-x86_64.tar.gz" % version)
    linux_arm64 = asset("tesseract-crypt-%s-Linux-aarch64.tar.gz" % version)
    win_setup_x64 = asset("tesseract-crypt-%s-windows-x64-setup.exe" % version)
    win_setup_x86 = asset("tesseract-crypt-%s-windows-x86-setup.exe" % version)

    homebrew = render(
        os.path.join(HERE, "homebrew", "tesseract-crypt.rb.in"),
        {
            "version": version,
            "sha_macos": macos[1],
            "sha_linux_x86_64": linux_amd64[1],
            "sha_linux_aarch64": linux_arm64[1],
        },
    )
    write(os.path.join(args.out, "homebrew", "tesseract-crypt.rb"), homebrew)

    architectures = {}
    for key, stem in (
        ("64bit", "Windows-x64"),
        ("32bit", "Windows-x86"),
        ("arm64", "Windows-arm64"),
    ):
        name = "tesseract-crypt-%s-%s.zip" % (version, stem)
        digest = sha_for(args.dist, sums, name)
        if digest:
            architectures[key] = {
                "url": "%s/%s" % (base, name),
                "hash": digest,
                "extract_dir": "tesseract-crypt-%s-%s" % (version, stem),
            }
    if "64bit" not in architectures:
        sys.exit("error: missing asset for tesseract-crypt-%s-Windows-x64.zip" % version)

    scoop = {
        "version": version,
        "description": "Hybrid public-key string & file encryption (libsodium)",
        "homepage": "https://github.com/%s" % args.repo,
        "license": "MIT",
        "architecture": architectures,
        "bin": ["bin\\tesseract-crypt.exe", "bin\\tscrypt.exe"],
        "checkver": {"github": "https://github.com/%s" % args.repo},
    }
    write(
        os.path.join(args.out, "scoop", "tesseract-crypt.json"),
        json.dumps(scoop, indent=4) + "\n",
    )

    nuspec = render(
        os.path.join(HERE, "chocolatey", "tesseract-crypt.nuspec.in"),
        {"version": version},
    )
    write(os.path.join(args.out, "chocolatey", "tesseract-crypt.nuspec"), nuspec)

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
        os.path.join(args.out, "chocolatey", "tools", "chocolateyinstall.ps1"),
        install_ps1,
    )

    # No placeholders: the uninstaller resolves the Inno Setup entry by
    # wildcard at uninstall time.
    uninstall_ps1 = render(
        os.path.join(HERE, "chocolatey", "tools", "chocolateyuninstall.ps1.in"),
        {},
    )
    write(
        os.path.join(args.out, "chocolatey", "tools", "chocolateyuninstall.ps1"),
        uninstall_ps1,
    )


if __name__ == "__main__":
    main()
