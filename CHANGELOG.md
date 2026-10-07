# Changelog

All notable changes to Tesseract Crypt are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [Unreleased] — 0.1.0

### Added

- **Core C11 library** `libtesseract_crypt`:
  - Hybrid public-key encryption: ephemeral X25519 (forward secrecy) +
    static DH (identity binding) → BLAKE2b KDF → XChaCha20-Poly1305 AEAD.
  - Sign-then-encrypt: Ed25519ph streaming; header (264 bytes) becomes AAD
    for every chunk (anti reorder/splice/truncation).
  - Passphrase fallback mode with Argon2id (memory-hard, ops/mem taken from
    header, bounded for untrusted input).
  - Streaming chunked: per-chunk subkey (`crypto_kdf`, context `TSCHNK01`),
    nonce = base nonce XOR index, constant memory.
  - PEM-like armor (base64) `-----BEGIN TESSERACT MESSAGE-----` + dearmor.
  - Key file formats `TSK1` (plain private, 164B), `TSK2` (Argon2id-locked,
    232B), `TSKp` (public, 68B).
  - Atomic write: output written to `.part`, moved only after AEAD and
    signature succeed. Uses `tess_replace_file` on Windows.
- **CLI** `tesseract-crypt` (canonical name) with alias `tscrypt`:
  `keygen`, `pubkey`, `encrypt`, `decrypt`, `rekey`, `sign`, `verify`,
  `inspect`, `info`, `version`, `help`.
- **C++17 header-only wrapper** `<tesseract/tesseract.hpp>`.
- **Build & CI**:
  - CMake ≥ 3.16 + `FindSodium.cmake` fallback; package configuration
    (`tesseract-config.cmake`) + CPack.
  - CI Linux: GCC & Clang × Debug/Release (warnings-as-errors) + ASan/UBSan
    job + fuzz LibFuzzer job (60s/target).
  - LibFuzzer targets `fuzz_inspect`, `fuzz_dearmor`, `fuzz_key_parse`
    (opt-in with `-DTESS_FUZZ=ON`, Clang only).
  - Known-answer tests (KAT) `tests/test_vectors.c` + locked fixtures in
    `tests/fixtures/`: v1 format header (264 bytes), armor, and deterministic
    Ed25519ph signature over fixture key.
  - **Multi-recipient (v2):** one message for many public keys — a random 32-byte
    data key wrapped per recipient (80-byte block: recipient pk + AEAD 48-byte,
    AAD = header 264 bytes + recipient pk); v2 header contains recipient count
    (u32 at offset 40, bytes 44–71 reserved zero). Other private keys are rejected
    explicitly (`TESS_ERR_RECIPIENT`, exit 3). CLI: repeat `-r`. Tested with
    `tests/test_multi.c` + v2 header vector.
  - GitHub Pages workflow for `docs/`.
  - **Linux APT repository** on GitHub Pages (`/apt`): on each push to `main`
    a DEB (CPack) + repo `dists/stable` + `pool/` is rebuilt and signed with
    GPG RSA-4096 (`InRelease`, `Release.gpg`). Public key committed in
    `docs/apt/tesseract-crypt.asc`; `apt install` instructions in README EN/ID.
- **Docs**: landing page, CLI reference, format specification; man page
  `tesseract-crypt(1)` (alias `tscrypt(1)`).

### Fixed

- Armor buffer sizing overflow on long labels.
- Dearmor test corruption logic.
- `out_signed` not propagated on armored file decrypt path.
- Windows `rename()` not replacing destination file → `tess_replace_file`.
- `getpass` reading a line from stdin when non-TTY.

### Security

- Argon2id bounds when reading untrusted header/blob:
  ≤ 16 ops, ≤ 4 GiB memory, min 64 KiB.
- All sensitive material is `sodium_memzero`; private keys `sodium_mlock`.

### Notes

- Report vulnerabilities → [SECURITY.md](SECURITY.md).

## [0.0.1] — 2026-10-07

- Early milestone (M0/M1) — internal code, not for production use.
