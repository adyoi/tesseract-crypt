# Changelog

Semua perubahan penting pada Tesseract Crypt dicatat di sini, mengikuti
[Keep a Changelog](https://keepachangelog.com/id-ID/1.1.0/) dan
[Semantic Versioning](https://semver.org/lang/id/).

## [Belum dirilis] — 0.1.0

### Ditambahkan

- **Library inti C11** `libtesseract_crypt`:
  - Hybrid public-key encryption: ephemeral X25519 (forward secrecy) +
    static DH (identity binding) → BLAKE2b KDF → XChaCha20-Poly1305 AEAD.
  - Sign-then-encrypt: Ed25519ph streaming; header 264 byte menjadi AAD
    setiap chunk (anti reorder/splice/truncation).
  - Mode passphrase fallback dengan Argon2id (memory-hard, ops/mem dari
    header, dibatasi untuk input tak tepercaya).
  - Streaming chunked: subkey per-chunk (`crypto_kdf`, konteks `TSCHNK01`),
    nonce = base nonce XOR index, memori konstan.
  - PEM-like armor (base64) `-----BEGIN TESSERACT MESSAGE-----` + dearmor.
  - Format berkas kunci `TSK1` (privat polos, 164 B), `TSK2` (privat
    terkunci Argon2id, 232 B), `TSKp` (publik, 68 B).
  - Atomic write: output ditulis ke `.part`, dipindahkan hanya setelah AEAD
    dan signature sukses (Windows memakai `MoveFileExA`, lihat
    `tess_replace_file`).
- **CLI** `tesseract-crypt` (nama kanonik) dengan alias `tscrypt`:
  `keygen`, `pubkey`, `encrypt`, `decrypt`, `sign`, `verify`, `inspect`,
  `info`, `version`, `help`.
- **Wrapper C++17 header-only** `<tesseract/tesseract.hpp>`.
- **Build & CI**:
  - CMake ≥ 3.16 + `FindSodium.cmake` fallback; konfigurasi package
    (`tesseract-config.cmake`) + CPack.
  - CI Linux: GCC & Clang × Debug/Release (warnings-as-errors) + job
    ASan/UBSan + job fuzz libFuzzer (60 detik/target).
  - Target libFuzzer `fuzz_inspect`, `fuzz_dearmor`, `fuzz_key_parse`
    (opt-in `-DTESS_FUZZ=ON`, Clang saja).
  - Tes known-answer (KAT) `tests/test_vectors.c` + fixture terkunci
    `tests/fixtures/`: header format v1 (264 byte), armor, dan signature
    Ed25519ph deterministik atas kunci fixture.
  - **Multi-penerima (format v2):** satu pesan untuk banyak kunci publik —
    data key acak 32 byte dibungkus per penerima (blok 80 byte: recipient pk
    + AEAD 48 byte, AAD = header 264 byte + pk penerima); header v2 memuat
    jumlah penerima (u32 @ offset 40, byte 44–71 cadangan wajib nol). Kunci
    privat lain yang bukan penerima ditolak eksplisit (`TESS_ERR_RECIPIENT`,
    exit 3). CLI: ulangi `-r`. Tes `tests/test_multi.c` + vektor header v2.
  - GitHub Pages workflow untuk `docs/`.
- **Docs**: landing page, referensi CLI, spesifikasi format; man page
    `tesseract-crypt(1)` (alias `tscrypt(1)`).

### Diperbaiki

- Armor buffer sizing overflow pada label panjang.
- Logika korupsi tes dearmor.
- `out_signed` tidak tersebar pada jalur dekripsi berkas ber-armor.
- `rename()` Windows tidak menimpa berkas tujuan → `tess_replace_file`.
- `getpass` membaca baris stdin saat non-TTY.

### Keamanan

- Batas kaprah Argon2id saat membaca header/blob tak tepercaya:
  ≤ 16 ops, ≤ 4 GiB memori, min 64 KiB.
- Seluruh material sensitif di-`sodium_memzero`; kunci privat di-`sodium_mlock`.

### Catatan

- Laporan kerentanan → [SECURITY.md](SECURITY.md).

## [0.0.1] — 2026-10-07

- Lintasan awal milistik (milestone M0/M1) — kode internal, tidak untuk
  pemakaian produksi.