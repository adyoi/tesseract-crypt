# Installation

`tesseract-crypt` ships as one binary installed under two names: the
canonical `tesseract-crypt` and the short alias `tscrypt`. Both point at the
same tool (on Windows `tscrypt` is a second copy of the binary, so no
symlink privilege is needed). Every package below installs both names.

- [Windows](#windows) — winget, release archive, source
- [Linux](#linux) — Debian/Ubuntu (APT), Fedora/RHEL/openSUSE (RPM), Arch (PKGBUILD), other distros
- [macOS](#macos) — Homebrew / source
- [BSD & other Unix-like](#bsd--other-unix-like)
- [From source (all platforms)](#from-source-all-platforms)
- [Verifying the install](#verifying-the-install)
- [Upgrading and uninstalling](#upgrading-and-uninstalling)

Requirements on every platform: CMake ≥ 3.16, a C11 compiler, a C++17
compiler, and [libsodium](https://doc.libsodium.org/) 1.0.16 or newer
(only needed for source builds; the packaged installs handle it for you).

## Windows

### winget (Windows Package Manager)

```powershell
winget install Adyoi.TesseractCrypt
```

To upgrade: `winget upgrade Adyoi.TesseractCrypt`

To uninstall: `winget uninstall Adyoi.TesseractCrypt`

### Release archive

1. Download `tesseract-crypt-*-win64.zip` from the
   [GitHub Releases](https://github.com/adyoi/tesseract-crypt/releases) page.
2. Verify the SHA-256 checksum against the `SHA256SUMS` file attached to the
   same release.
3. Extract the archive and add the folder to your `PATH`.

### From source (MSVC + vcpkg)

Prerequisites: Visual Studio 2019 or newer (Desktop development with C++),
CMake ≥ 3.16, and a [vcpkg](https://github.com/microsoft/vcpkg) checkout.

```powershell
git clone https://github.com/adyoi/tesseract-crypt.git
cd tesseract-crypt

# install libsodium once, then build
vcpkg install libsodium:x64-windows
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure

# optional: install into a prefix
cmake --install build --config Release --prefix C:\tools\tesseract
```

## Linux

### Debian / Ubuntu — APT repository (amd64)

Prebuilt binaries are served from an APT repository hosted on GitHub Pages
and signed with GPG:

```bash
# 1. install the repository public key
curl -fsSL https://adyoi.github.io/tesseract-crypt/apt/tesseract-crypt.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/tesseract-crypt.gpg

# 2. register the repository
echo "deb [signed-by=/usr/share/keyrings/tesseract-crypt.gpg] https://adyoi.github.io/tesseract-crypt/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/tesseract-crypt.list

# 3. install (the short alias tscrypt comes along)
sudo apt update
sudo apt install tesseract-crypt
```

> The repository is rebuilt (and re-signed) on every push to `main`.
> Verify the key: `gpg --show-keys /usr/share/keyrings/tesseract-crypt.gpg`
> → fingerprint `747E1BDB 928B3101 7718FD38 E1206C36 5D198C58`.

### Fedora / RHEL / openSUSE — RPM

The repository includes `packaging/tesseract-crypt.spec`. Build an RPM from
the release source tarball with `rpmbuild`:

```bash
curl -L -o tesseract-crypt-0.1.0.tar.gz \
  https://github.com/adyoi/tesseract-crypt/archive/refs/tags/v0.1.0.tar.gz

# Fedora/RHEL:
sudo dnf install rpm-build cmake gcc gcc-c++ libsodium-devel
# openSUSE: sudo zypper install rpm-build cmake gcc-c++ libsodium-devel

rpmbuild -ba packaging/tesseract-crypt.spec --define "_sourcedir $PWD"
sudo dnf install ~/rpmbuild/RPMS/*/tesseract-crypt-*.rpm
```

### Arch Linux / Manjaro — PKGBUILD

The repository includes `packaging/PKGBUILD`, which downloads the release
tarball and builds with `makepkg`:

```bash
cp packaging/PKGBUILD /tmp/tesseract-build/
cd /tmp/tesseract-build
makepkg -si   # downloads the source, builds, installs (both binaries + man pages)
```

Arch requires `libsodium` (from `[extra]`); `makepkg` pulls `cmake`, `ninja`
and `gcc` automatically.

### Other distributions — generic build

Install the same three toolchain pieces with your package manager, then
follow [From source](#from-source-all-platforms):

```bash
# Debian/Ubuntu
sudo apt install build-essential cmake libsodium-dev
# Fedora/RHEL
sudo dnf install cmake gcc gcc-c++ libsodium-devel
# Arch
sudo pacman -S cmake gcc libsodium
# openSUSE
sudo zypper install cmake gcc gcc-c++ libsodium-devel
```

## macOS

There is no Homebrew cask yet, so build from source:

```bash
brew install cmake libsodium

git clone https://github.com/adyoi/tesseract-crypt.git
cd tesseract-crypt

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$(brew --prefix)
cmake --build build --parallel
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

Alternatively use vcpkg on macOS exactly as on Windows (see
[From source](#from-source-all-platforms)).

## BSD & other Unix-like

Everything is standard C11/C++17 + libsodium — the same source build works
on FreeBSD, OpenBSD, NetBSD and other Unix-likes:

```bash
# FreeBSD
sudo pkg install cmake libsodium

git clone https://github.com/adyoi/tesseract-crypt.git
cd tesseract-crypt
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

(On OpenBSD/NetBSD install the `cmake` and `libsodium` packages with
`pkg_add` instead.)

## From source (all platforms)

### Requirements

| Tool | Minimum |
|------|---------|
| CMake | 3.16 |
| C compiler (C11) | GCC 9+, Clang 10+, MSVC 2019+, AppleClang 12+ |
| C++ compiler (C++17) | same as above |
| libsodium | 1.0.16+ (development & testing against 1.0.18–1.0.22) |

libsodium can come from your distro/Homebrew (`libsodium-dev`, `libsodium`,
`libsodium-devel`) or from [vcpkg](https://github.com/microsoft/vcpkg)
(`vcpkg install libsodium:x64-windows`, or `:x64-osx` / `:x64-linux`).

### Build

```bash
git clone https://github.com/adyoi/tesseract-crypt.git
cd tesseract-crypt

# system libsodium (Linux/macOS/BSD):
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
# vcpkg libsodium (any platform, incl. Windows):
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake

cmake --build build --parallel
ctest --test-dir build --output-on-failure      # add -C Release on MSVC
sudo cmake --install build                      # optional: install
```

### CMake options

| Option | Default | Meaning |
|--------|---------|---------|
| `TESS_BUILD_CLI` | `ON` | Build the `tesseract-crypt` CLI + `tscrypt` alias |
| `TESS_BUILD_TESTS` | `ON` | Build the CTest suite |
| `TESS_SANITIZE` | `OFF` | Enable AddressSanitizer + UBSan (Clang/GCC) |
| `TESS_COVERAGE` | `OFF` | Enable gcov/lcov coverage instrumentation |
| `TESS_WARNINGS_AS_ERRORS` | `OFF` | Treat compiler warnings as errors |
| `TESS_FUZZ` | `OFF` | Build libFuzzer harnesses (Clang only) |

### Packaging with CPack

`cpack` produces:
- **Linux**: `.tar.gz` and `.deb`
- **macOS**: `.tar.gz`
- **Windows**: `.zip`

```bash
cmake --build build --config Release --parallel   # first build
cpack --config build/CPackConfig.cmake            # from the build dir: cpack
```

Release binaries are also published as GitHub Release assets with a
`SHA256SUMS` checksum file (and the Windows `.zip` is pushed to winget).

### Using the library from your own CMake project

```cmake
find_package(tesseract CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE tesseract::tesseract_crypt)
```

## Verifying the install

```bash
tesseract-crypt version        # or: tscrypt version
man tesseract-crypt            # man page (Unix-like)
```

A quick round-trip check:

```bash
tesseract-crypt keygen -o alice --passphrase
echo "hello" | tesseract-crypt encrypt -r alice.pub | tesseract-crypt decrypt -k alice.key
```

## Upgrading and uninstalling

| Install method | Upgrade | Uninstall |
|----------------|---------|-----------|
| winget | `winget upgrade Adyoi.TesseractCrypt` | `winget uninstall Adyoi.TesseractCrypt` |
| APT | `sudo apt update && sudo apt upgrade` | `sudo apt remove tesseract-crypt` |
| RPM | `sudo dnf upgrade` / re-run `rpmbuild -ba` | `sudo dnf remove tesseract-crypt` |
| Arch | `makepkg -si` again / `pacman -U <new>.pkg.tar.zst` | `sudo pacman -R tesseract-crypt` |
| Source (`cmake --install`) | rebuild & reinstall into the same prefix | remove the prefix directory (or the installed files) manually |
| Release archive | download the new archive | delete the extracted folder and `PATH` entry |