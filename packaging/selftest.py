#!/usr/bin/env python3
"""Self-test for the release packaging pipeline (standard library only).

Renders the Homebrew / Scoop / Chocolatey metadata from a synthetic
``SHA256SUMS`` file and validates the result: hash wiring, well-formed
XML/JSON, no leftover ``@@placeholder@@``, and the Chocolatey uninstall script
matching the Inno Setup ``UninstallDisplayName``.  Finally it checks that the
project version is consistent across the repository.

Run from the repository root:

    python3 packaging/selftest.py
"""

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RENDER = REPO / "packaging" / "render.py"
ISS = REPO / "packaging" / "windows" / "tesseract-crypt.iss"
NUSPEC_NS = "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"

# Synthetic release version: deliberately different from the project version so
# the test only exercises the renderer.
TEST_VERSION = "9.9.9"
BASE_URL = "https://github.com/adyoi/tesseract-crypt/releases/download/v%s" % TEST_VERSION

PASSED = 0
FAILED = 0


def check(ok, message):
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print("  ok    %s" % message)
    else:
        FAILED += 1
        print("  FAIL  %s" % message)
    return bool(ok)


def summary():
    print("\n%d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


def asset(name):
    return "tesseract-crypt-%s-%s" % (TEST_VERSION, name)


def sha_of(name):
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- helpers ---


def write_sums(dist, names):
    """Write a sha256sum-style SHA256SUMS holding the given asset names."""
    lines = ["%s  %s" % (sha_of(n), n) for n in names]
    (dist / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_render(version, dist, out):
    return subprocess.run(
        [
            sys.executable,
            str(RENDER),
            "--version",
            version,
            "--dist",
            str(dist),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
    )


def nuspec_fields(xml_text):
    """Return {local-name: text} for the <metadata> element."""
    root = ET.fromstring(xml_text)
    meta = root.find("{%s}metadata" % NUSPEC_NS)
    if meta is None:
        return {}
    return {
        child.tag.split("}")[-1]: (child.text or "").strip() for child in meta
    }


# ------------------------------------------------------------------ tests ---


def test_render(tmp):
    """Render a synthetic release and validate every produced file."""
    names = [
        asset("macOS-universal2.tar.gz"),
        asset("Linux-x86_64.tar.gz"),
        asset("Linux-aarch64.tar.gz"),
        asset("Windows-x64.zip"),
        asset("Windows-x86.zip"),
        asset("Windows-arm64.zip"),
        asset("windows-x64-setup.exe"),
        asset("windows-x86-setup.exe"),
    ]
    sums = {n: sha_of(n) for n in names}

    dist, out = tmp / "dist", tmp / "out"
    dist.mkdir()
    write_sums(dist, names)

    proc = run_render(TEST_VERSION, dist, out)
    if not check(proc.returncode == 0, "render.py exits 0"):
        print(proc.stdout)
        print(proc.stderr)
        return

    paths = {
        "homebrew": out / "homebrew" / "tesseract-crypt.rb",
        "scoop": out / "scoop" / "tesseract-crypt.json",
        "nuspec": out / "chocolatey" / "tesseract-crypt.nuspec",
        "chocolateyinstall.ps1": out / "chocolatey" / "tools" / "chocolateyinstall.ps1",
        "chocolateyuninstall.ps1": out / "chocolatey" / "tools" / "chocolateyuninstall.ps1",
    }
    if not check(
        all(p.is_file() for p in paths.values()),
        "all files rendered (%s)" % ", ".join(sorted(paths)),
    ):
        return
    text = {k: p.read_text(encoding="utf-8") for k, p in paths.items()}
    for name, body in text.items():
        check("@@" not in body, "%s: every placeholder substituted" % name)

    # Homebrew ---------------------------------------------------------
    formula = text["homebrew"]
    check('version "%s"' % TEST_VERSION in formula, "homebrew: version pinned")
    # The formula interpolates #{version} into the asset names, so pair each
    # url with the sha256 that follows it.
    pairs = dict(
        re.findall(
            r'tesseract-crypt-#\{version\}-([\w.\-]+)"\s+sha256 "([0-9a-f]{64})"', formula
        )
    )
    for label, suffix in (
        ("macOS", "macOS-universal2.tar.gz"),
        ("Linux x86_64", "Linux-x86_64.tar.gz"),
        ("Linux aarch64", "Linux-aarch64.tar.gz"),
    ):
        check(
            pairs.get(suffix) == sums[asset(suffix)],
            "homebrew: %s url + sha256 pair" % label,
        )
    check("test do" in formula, "homebrew: has a test block")

    # Scoop ------------------------------------------------------------
    scoop = json.loads(text["scoop"])
    check(scoop.get("version") == TEST_VERSION, "scoop: version")
    for key, name in (
        ("64bit", "Windows-x64.zip"),
        ("32bit", "Windows-x86.zip"),
        ("arm64", "Windows-arm64.zip"),
    ):
        entry = scoop.get("architecture", {}).get(key, {})
        check(
            entry.get("url") == "%s/%s" % (BASE_URL, asset(name))
            and entry.get("hash") == sums[asset(name)],
            "scoop: %s url + hash" % key,
        )
    check(
        scoop.get("bin") == ["bin\\tesseract-crypt.exe", "bin\\tscrypt.exe"],
        "scoop: both executables shimmed",
    )
    check(
        scoop.get("checkver", {}).get("github") == "https://github.com/adyoi/tesseract-crypt",
        "scoop: checkver wired",
    )

    # Chocolatey nuspec ------------------------------------------------
    fields = nuspec_fields(text["nuspec"])
    check(fields.get("id") == "tesseract-crypt", "nuspec: id")
    check(fields.get("version") == TEST_VERSION, "nuspec: version")
    for field in (
        "licenseUrl",
        "projectUrl",
        "projectSourceUrl",
        "packageSourceUrl",
        "docsUrl",
        "bugTrackerUrl",
        "releaseNotes",
        "description",
    ):
        check(bool(fields.get(field)), "nuspec: %s present" % field)

    # chocolateyinstall.ps1 --------------------------------------------
    install = text["chocolateyinstall.ps1"]
    check("Install-ChocolateyPackage" in install, "install.ps1: calls Install-ChocolateyPackage")
    for label, name in (("64-bit", "windows-x64-setup.exe"), ("32-bit", "windows-x86-setup.exe")):
        check(
            "%s/%s" % (BASE_URL, asset(name)) in install and sums[asset(name)] in install,
            "install.ps1: %s installer url + checksum" % label,
        )
    check("silentArgs" in install and "validExitCodes" in install, "install.ps1: silent args")

    # chocolateyuninstall.ps1 ------------------------------------------
    uninstall = text["chocolateyuninstall.ps1"]
    check("Get-UninstallRegistryKey" in uninstall, "uninstall.ps1: looks up the registry entry")
    check("Uninstall-ChocolateyPackage" in uninstall, "uninstall.ps1: calls the uninstall helper")

    iss = ISS.read_text(encoding="utf-8")
    match = re.search(r'#define\s+AppName\s+"([^"]+)"', iss)
    app_name = match.group(1) if match else None
    check(app_name is not None, "tesseract-crypt.iss: AppName defined")
    check(
        "UninstallDisplayName={#AppName} {#AppVersion}" in iss,
        "tesseract-crypt.iss: UninstallDisplayName is '<AppName> <AppVersion>'",
    )
    if app_name:
        # Chocolatey resolves the uninstaller through the DisplayName, so the
        # wildcard in the uninstall script must match the Inno Setup AppName.
        check(
            "'%s*'" % app_name in uninstall,
            "uninstall.ps1: DisplayName pattern matches '%s*'" % app_name,
        )


def test_missing_asset(tmp):
    """A release that misses an asset must fail the renderer loudly."""
    names = [asset("Linux-x86_64.tar.gz"), asset("windows-x64-setup.exe")]
    dist, out = tmp / "dist-partial", tmp / "out-partial"
    dist.mkdir()
    write_sums(dist, names)

    proc = run_render(TEST_VERSION, dist, out)
    check(proc.returncode != 0, "render.py fails on an incomplete release")
    check(
        "macOS-universal2" in (proc.stdout + proc.stderr),
        "render.py names the missing asset",
    )


def test_templates_are_used():
    """Every .in template under packaging/ must be referenced by render.py."""
    renderer = RENDER.read_text(encoding="utf-8")
    for template in sorted((REPO / "packaging").rglob("*.in")):
        check(template.name in renderer, "render.py consumes %s" % template.name)


def test_version_consistency():
    """CMakeLists.txt, vcpkg.json and CHANGELOG.md must agree."""
    cmake = re.search(
        r"project\(\s*tesseract-crypt\s+VERSION\s+([0-9][0-9.]*)",
        (REPO / "CMakeLists.txt").read_text(encoding="utf-8"),
    )
    vcpkg = json.loads((REPO / "vcpkg.json").read_text(encoding="utf-8"))
    changelog = re.search(
        r"^##\s*\[([0-9][0-9.]*)\]",
        (REPO / "CHANGELOG.md").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    versions = {
        "CMakeLists.txt": cmake.group(1) if cmake else None,
        "vcpkg.json": vcpkg.get("version-semver"),
        "CHANGELOG.md": changelog.group(1) if changelog else None,
    }
    check(
        None not in versions.values() and len(set(versions.values())) == 1,
        "version consistent across %s" % versions,
    )


def main():
    print("packaging self-test (renderer %s)" % RENDER.relative_to(REPO))
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        test_render(tmp)
        test_missing_asset(tmp)
    test_templates_are_used()
    test_version_consistency()
    return summary()


if __name__ == "__main__":
    sys.exit(main())
