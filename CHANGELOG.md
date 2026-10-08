# Changelog

All notable changes to Tesseract Crypt are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-08

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

- **Security**: Passphrase length timing leak in Argon2id KDF — `lock_derive`
  now accepts explicit passphrase length instead of using `strlen()`.
- **Security**: Buffer overflow in `tess_armor` — added overflow checks for
  `need` calculation.
- **Security**: Integer overflow in `tess_read_file` — added check for `sz + 1`
  overflow before allocation.
- **Correctness**: Const violation in `tess_open` and `tess_open_file` —
  replaced casts with mutable local copies.
- **Validation**: Added explicit validation in `tess_sign` and `tess_verify`
  to fail fast with `TESS_ERR_INVALID_ARG` for wrong key types.
- **Validation**: Locked key parsing now validates Argon2id parameters before
  attempting unlock.
- **Optimization**: `tess_chunk_nonce` unrolled loop for better performance.
- **Build**: Fixed CMake to prefer project's `FindSodium.cmake` over broken
  `unofficial-sodium` config package.
- **Test**: Removed unused variable warning in `test_rekey.c`.

### Security

- Argon2id bounds when reading untrusted header/blob:
  ≤ 16 ops, ≤ 4 GiB memory, min 64 KiB.
- All sensitive material is `sodium_memzero`; private keys `sodium_mlock`.
- Passphrase handling uses constant-time length where applicable.

### Notes

- Report vulnerabilities → [SECURITY.md](SECURITY.md).

## [0.0.1] — 2026-10-07

- Early milestone (M0/M1) — internal code, not for production use.
