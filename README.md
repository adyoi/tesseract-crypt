# Tesseract Crypt

[![CI](https://github.com/adyoi/tesseract-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/adyoi/tesseract-crypt/actions/workflows/ci.yml)
[![Pages](https://github.com/adyoi/tesseract-crypt/actions/workflows/pages.yml/badge.svg)](https://github.com/adyoi/tesseract-crypt/actions/workflows/pages.yml)
[![Release](https://img.shields.io/github/v/release/adyoi/tesseract-crypt)](https://github.com/adyoi/tesseract-crypt/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-6ee7ff.svg)](LICENSE)
[![Codecov](https://codecov.io/gh/adyoi/tesseract-crypt/branch/main/graph/badge.svg)](https://codecov.io/gh/adyoi/tesseract-crypt)

**Encrypt strings & files with public/private keys — modern hybrid, streaming, signed.**

> **Bahasa Indonesia:** [README.md](README.md) · dokumentasi ID:
> [https://adyoi.github.io/tesseract-crypt/id/](https://adyoi.github.io/tesseract-crypt/id/)

`libtesseract_crypt` (C11) + `tesseract-crypt` (CLI, C++17, short alias: `tscrypt`)
built on [libsodium](https://doc.libsodium.org/): X25519 *hybrid* encryption,
Ed25519 sign-then-encrypt, XChaCha20-Poly1305 AEAD per-chunk, and Argon2id for
passphrase mode.

| Feature | Description |
|---------|-------------|
| **Hybrid public-key** | Ephemeral X25519 (per-message forward secrecy) + static DH (identity binding) → BLAKE2b KDF → XChaCha20-Poly1305 |
| **Sign-then-encrypt** | Ed25519ph (streaming) signature lives in the header, which is authenticated as AAD |
| **Passphrase mode** | Argon2id (memory-hard) as symmetric fallback |
| **Streaming chunked** | 64 KiB per chunk, per-chunk subkey (`crypto_kdf`), constant memory, reorder/truncation detection |
| **PEM-like armor** | Base64 `-----BEGIN TESSERACT MESSAGE-----` for stdout & text |
| **Multi-recipient (v2)** | One message for many recipients: a random data key wrapped per recipient (format v2) |
| **Rekey / key rotation** | `tesseract-crypt rekey` to rewrap an existing message for new recipients/sender without touching the ciphertext payload | 
| **Atomic output** | File is written to `.part`, renamed only after decryption & verification succeed |

### Windows Package Manager (winget)

```powershell
winget install Adyoi.TesseractCrypt
```

To upgrade: `winget upgrade Adyoi.TesseractCrypt`

To uninstall: `winget uninstall Adyoi.TesseractCrypt`

## Install (APT — Debian/Ubuntu amd64)

Prebuilt `tesseract-crypt` binaries are served from an APT repository hosted
on GitHub Pages and signed with GPG:

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

## Build

```bash
# get the source
git clone https://github.com/adyoi/tesseract-crypt.git
cd tesseract-crypt

# Linux (libsodium from the distro)
sudo apt install build-essential cmake libsodium-dev   # Debian/Ubuntu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

```bash
# vcpkg (Windows/macOS/anything)
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release -j
```

## Quick start

```bash
# 1. generate a keypair
tesseract-crypt keygen -o alice
tesseract-crypt keygen -o bob

# 2. encrypt a file for Bob, signed by Alice
tesseract-crypt encrypt -r bob.pub -k alice.key -i secret.txt -o secret.enc

# 3. decrypt — the signature is verified before the file is written
tesseract-crypt decrypt -k bob.key -i secret.enc -o secret.out \
                        --require-signer alice.pub

# 4. encrypt a string straight to stdout (auto-armored on TTY)
tesseract-crypt encrypt --text "Hello world" -r bob.pub

# 5. passphrase mode (no public key needed)
tesseract-crypt encrypt --passphrase -i note.txt -o note.enc

# 6. rekey a message for new recipients
tesseract-crypt keygen -o charlie
tesseract-crypt rekey -k bob.key -i secret.enc -o secret.rekey -r charlie.pub --require-signer alice.pub

# 7. inspect the message header
tesseract-crypt inspect -i secret.enc
tesseract-crypt info -k alice.key
```

> `tscrypt` ships as an alias — every command above also works as
> `tscrypt` (e.g. `tscrypt keygen -o alice`). The binary name is the same
> on every platform: `tesseract-crypt` (plus `.exe` on Windows).

## Library (C)

```c
#include <tesseract/tesseract.h>

tess_key *sec, *pub;
tess_keygen(&sec, &pub);

tess_seal_options so;
tess_seal_options_init(&so);
so.recipient_public = pub;
so.sign = 1;
so.sender_secret = sec;

uint8_t *ct; size_t ct_len;
tess_seal((const uint8_t *)"secret", 6, &so, &ct, &ct_len);
```

A header-only C++17 wrapper is available in `<tesseract/tesseract.hpp>`
(`tess::key`, `tess::seal`, `tess::open`).

## Documentation

- [Landing page](https://adyoi.github.io/tesseract-crypt/) — overview & quick start
- [CLI reference](https://adyoi.github.io/tesseract-crypt/cli.html)
- [Format specification](https://adyoi.github.io/tesseract-crypt/format.html)
- [About & comparison](https://adyoi.github.io/tesseract-crypt/tentang.html)
- [Audit readiness](docs/audit-readiness.md) — checklist for security auditors
- [Code coverage](docs/coverage.md) — gcov/lcov workflow

Indonesian versions live under [adyoi.github.io/tesseract-crypt/id/](https://adyoi.github.io/tesseract-crypt/id/).

## Platform support

- **Windows** (MSVC, vcpkg), **Linux** (GCC/Clang), **macOS** (AppleClang),
  **BSD/Unix-like** — same CLI and file formats everywhere.
- Atomic output uses `rename()`; on Windows it is `MoveFileExA` with
  `MOVEFILE_REPLACE_EXISTING` (`tess_replace_file`), so overwriting an
  existing destination works.
- The `tscrypt` alias is a **symlink** on Unix-like systems and a
  **second copy of the binary** on Windows (no symlink privilege needed).

## Security

- Private keys are stored with Argon2id (`--passphrase`), unlocked in memory
  and zeroized (`sodium_memzero`).
- The 264-byte header is the AAD of every chunk → truncation/reorder/splice
  are detected.
- Output is written to `.part` and **only** renamed after AEAD + signature
  verification succeeds.
- Argon2id parameters are capped when reading untrusted headers/blobs
  (max 16 ops / 4 GiB) — anti-DoS.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE)
