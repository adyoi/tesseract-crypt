ï»¿# RENCANA Ã¢â¬â Repository `tesseract-crypt`

**Codename:** Tesseract
**Bahasa:** C11 (library inti) + C++17 (CLI)
**Platform target:** Linux (x86_64, aarch64)
**Build system:** CMake Ã¢â°Â¥ 3.16
**Dependensi kripto:** libsodium (dipilih karena API misuse-resistant, audit berkala, tersedia di semua distro Linux)

---

## 1. Visi & Fitur Utama

Aplikasi enkripsi/dekripsi **string dan file** dengan **asymmetric key (private/public key)**,
dibangun di atas model kunci hibrida modern:

| # | Fitur | Deskripsi |
|---|-------|-----------|
| 1 | **Hybrid Public-Key Encryption** | Ephemeral X25519 (forward secrecy per pesan) + static DH (identity binding) Ã¢â â BLAKE2b KDF Ã¢â â XChaCha20-Poly1305 AEAD |
| 2 | **Sign-then-Encrypt** | Ed25519 detached signature atas plaintext, disimpan di header yang ikut di-authenticate (authenticity + non-repudiation) |
| 3 | **Mode Passphrase** | Fallback simetris: Argon2id (memory-hard) Ã¢â â XChaCha20-Poly1305 |
| 4 | **Streaming chunked** | File besar diproses per-chunk (default 64 KiB) dengan subkey per-chunk (`crypto_kdf`) Ã¢â¬â memori konstan, deteksi reorder/truncation |
| 5 | **PEM-like armor** | Output biner bisa di-armor jadi teks (`-----BEGIN TESSERACT MESSAGE-----`), auto-detect saat dekripsi |
| 6 | **Key file terenkripsi** | Private key dilindungi Argon2id (opsi `--passphrase` saat keygen) |
| 7 | **Fingerprint & trust** | Fingerprint BLAKE2b-128 dari public key; opsi `--require-signer` untuk pinning identity |
| 8 | **Kebersihan memori** | `sodium_memzero` + `sodium_mlock` pada material kunci |
| 9 | **Multi-penerima (v2)** | Satu pesan untuk banyak kunci publik: data key acak dibungkus per penerima (blok 80 B); non-penerima ditolak eksplisit |

### Pembeda ("belum pernah ada")
- **Header terikat ke setiap chunk** (header seluruhnya jadi AAD + index chunk + flag final) Ã¢â â mencegah splice, reorder, dan truncation secara kriptografis, bukan sekadar checksum.
- **Identity-bound hybrid encryption**: kombinasi ephemeral DH *dan* static DH antara senderÃ¢â ârecipient, sehingga dekripsi hanya berhasil bila memang pasangan kunci yang benar, sambil tetap mempertahankan forward secrecy.
- **Multi-recipient tanpa replikasi header**: format v2 memakai satu header 264 B + satu data key acak, dengan wrap key per penerima di blok 80 B Ã¢â¬â ukuran pesan Ã¢â°Ë v1 + 80 B/penerima, dan blok terikat ke header (AAD) sehingga tak bisa dipindah antar pesan.
- **Verifikasi signature saat streaming dengan output-file atomik** (tulis `.part` Ã¢â â verify Ã¢â â `rename`), sehingga plaintext yang belum tervalidasi tidak pernah muncul di path final.

---

## 2. Arsitektur

```
tesseract-crypt/
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ include/tesseract/      # Public API (C) + wrapper header-only (C++)
Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ tesseract.h
Ã¢ââ   Ã¢ââÃ¢ââ¬Ã¢ââ¬ tesseract.hpp
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ src/
Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ core/               # libtesseract_crypt (C11)
Ã¢ââ   Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ tess_internal.h
Ã¢ââ   Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ tess_status.c   # kode error + pesan
Ã¢ââ   Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ tess_util.c     # armor/base64, fingerprint, I/O aman
Ã¢ââ   Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ tess_keys.c     # keygen, simpan/muat key (plain & Argon2id)
Ã¢ââ   Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ tess_header.c   # serialisasi/parse header pesan (264 byte)
Ã¢ââ   Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ tess_seal.c     # seal/open buffer + streaming file
Ã¢ââ   Ã¢ââ   Ã¢ââÃ¢ââ¬Ã¢ââ¬ tess_sign.c     # Ed25519 detached sign/verify (streaming)
Ã¢ââ   Ã¢ââÃ¢ââ¬Ã¢ââ¬ cli/                # bin `tesseract-crypt` + alias `tscrypt` (C++17)
Ã¢ââ       Ã¢ââÃ¢ââ¬Ã¢ââ¬ main.cpp        # subcommands: keygen, pubkey, encrypt, decrypt,
Ã¢ââ                           #   sign, verify, inspect, info, version
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ tests/                  # CTest (roundtrip, tamper, armor, multi-chunk, dll.)
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ docs/                   # GitHub Pages (landing + CLI ref + desain format)
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ man/                    # man page tesseract-crypt(1)
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ cmake/                  # FindSodium fallback, config package
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ .github/
Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ workflows/ci.yml    # build+test (gcc/clang, Debug/Release, ASan/UBSan)
Ã¢ââ   Ã¢âÅÃ¢ââ¬Ã¢ââ¬ workflows/pages.yml # deploy docs/ Ã¢â â GitHub Pages
Ã¢ââ   Ã¢ââÃ¢ââ¬Ã¢ââ¬ ISSUE_TEMPLATE/
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ packaging/              # PKGBUILD (Arch), spec (RPM), .deb recipe
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ scripts/build-linux.sh
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ CMakeLists.txt
Ã¢âÅÃ¢ââ¬Ã¢ââ¬ README.md ÃÂ· RENCANA.md ÃÂ· CHANGELOG.md ÃÂ· CONTRIBUTING.md ÃÂ· SECURITY.md
Ã¢ââÃ¢ââ¬Ã¢ââ¬ LICENSE (MIT)
```

**Layer:**
1. `libtesseract_crypt` Ã¢â¬â API C stabil, tanpa dependensi selain libsodium.
2. `tesseract-crypt` (CLI, alias `tscrypt`) Ã¢â¬â hanya memanggil API publik, sebagai contoh pemakaian.
3. Tests + CI Ã¢â¬â menjaga kualitas.

---

## 3. Desain Kriptografi

### 3.1 Pasangan kunci
- **X25519** (32 B pk / 32 B sk) Ã¢â â enkripsi
- **Ed25519** (32 B pk / 64 B sk) Ã¢â â tanda tangan
- Disimpan dalam satu key file; publik diekspor terpisah.

### 3.2 Format header pesan (`TSCR`, 264 byte, little-endian)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | magic `"TSCR"` |
| 4 | 1 | version = 1 (single) / 2 (multi-recipient) |
| 5 | 1 | suite = 1 (X25519 + BLAKE2b + XChaCha20-Poly1305 + Ed25519) |
| 6 | 1 | mode (1 = public-key, 2 = passphrase) |
| 7 | 1 | flags (bit0 = signed) |
| 8 | 32 | ephemeral X25519 pk (mode 1) |
| 40 | 32 | recipient X25519 pk (mode 1, binding) Ã¢â¬â v2: recipient count (u32) + reserved 28 B wajib nol |
| 72 | 32 | sender X25519 pk (mode 1, opsional/anonymous) |
| 104 | 32 | sender Ed25519 pk (jika signed, else nol) |
| 136 | 64 | signature Ed25519 atas plaintext (jika signed, else nol) |
| 200 | 16 | KDF salt |
| 216 | 4 | Argon2id ops limit (mode 2) |
| 220 | 8 | Argon2id mem limit (mode 2) |
| 228 | 24 | base nonce |
| 252 | 4 | chunk size (u32) |
| 256 | 8 | panjang plaintext (u64; `UINT64_MAX` = unknown) |

### 3.3 Key schedule

**Mode 1 (public-key):**
```
dh_eph   = X25519(eph_sk, recipient_pk)          # forward secrecy
dh_stat  = X25519(sender_sk, recipient_pk)       # identity binding (0 jika anonymous)
master   = BLAKE2b-256(key = dh_eph,
                       in  = dh_stat || salt || "tesseract-kdf-v1")
```
**Mode 1, format v2 (multi-recipient):**
```
data_key = randombytes(32)                       # melindungi muatan
wrap_i   = BLAKE2b-256(key = X25519(eph_sk, recipient_i_pk),
                       in  = X25519(sender_sk, recipient_i_pk) || salt || "tesseract-kdf-v1")
block_i  = recipient_i_pk(32) || XChaCha20-Poly1305(wrap_i, data_key,
                                                    nonce = base_nonce,
                                                    aad = header(264) || recipient_i_pk)(48)
```
Lalu chunk muatan memakai `data_key` menggantikan `master`; AAD chunk tetap header(264).
**Mode 2 (passphrase):**
```
master = Argon2id(passphrase, salt, ops, mem)    # ops/mem dari header
```
**Per chunk i:**
```
subkey_i  = crypto_kdf_derive_from_key(32, i+1, "TSCHNK01", master)
nonce_i   = base_nonce XOR (i di 8 byte terakhir, big-endian)
AAD_i     = header(264) || u64be(i) || u8(final)
ct_i      = XChaCha20-Poly1305(subkey_i, nonce_i, pt_i, AAD_i)
```
Cangkang file: `header || (u32le len(ct_i) || ct_i)*` Ã¢â¬â chunk terakhir ditandai flag `final`.
Pesan kosong = satu chunk final berisi 0 byte plaintext.

### 3.4 Alur sign-then-encrypt
1. Pass 1: stream plaintext Ã¢â â Ed25519 (stateful) Ã¢â â signature 64 B.
2. Signature + sender Ed25519 pk dimasukkan ke header.
3. Pass 2: encrypt (header jadi AAD).
4. Dekripsi: streaming plaintext ke **file `.part`** Ã¢â â verifikasi signature Ã¢â â `rename` atomik.

> Catatan kepercayaan: signature diverifikasi terhadap sender key di dalam header.
> Untuk pinning, gunakan `tesseract-crypt decrypt --require-signer sender.pub`.

### 3.5 Batasan keamanan yang diterapkan
- Validasi ketat header (magic/version/suite/bounds) sebelum alokasi.
- Batas Argon2id mem/ops dari header (anti-DoS saat dekripsi file tak dikenal).
- `chunk_size` dibatasi 4 KiB Ã¢â¬Â¦ 16 MiB.
- Seluruh material sensitif di-`sodium_memzero`; key di-`sodium_mlock`.
- Tanpa penggunaan RNG sendiri Ã¢â¬â hanya `randombytes_buf`.

---

## 4. CLI (`tesseract-crypt`, alias `tscrypt`)

```
tesseract-crypt keygen    -o alice [--passphrase] [--kdf-ops N] [--kdf-mem MB]
tesseract-crypt pubkey    -k alice.key [-o alice.pub]
tesseract-crypt encrypt   -r bob.pub [-r carol.pub ...] [-k alice.key] [-i in] [-o out] [--armor]
                          [--chunk-size N] [--no-sign]    # -r berulang Ã¢â â format v2
tesseract-crypt encrypt   --passphrase [-i in] [-o out]        # mode simetris
tesseract-crypt encrypt   --text "rahasia" -r bob.pub          # string Ã¢â â stdout (armor)
tesseract-crypt decrypt   -k bob.key [-i in] [-o out]
                          [--require-signer alice.pub] [--passphrase]
tesseract-crypt sign      -k alice.key -i file [-o file.sig]
tesseract-crypt verify    -k alice.pub -i file -s file.sig
tesseract-crypt inspect   [-i pesan.enc]                       # baca header
tesseract-crypt info      -k alice.key | -k alice.pub          # fingerprint
tesseract-crypt version | help
```

`tscrypt` adalah alias yang ikut ter-install di semua platform (Linux/Windows/macOS/BSD).
Nama canonical: `tesseract-crypt` (`.exe` otomatis di Windows).

UX: output ke TTY Ã¢â â otomatis armor; stdin/stdout (`-`) didukung; exit code Ã¢â°Â  0 pada kegagalan.

---

## 5. Kualitas & CI

| Pekerjaan | Detail |
|-----------|--------|
| `ci.yml` | Matrix: gcc & clang Ãâ Debug/Release; job terpisah ASan+UBSan (`-fsanitize=address,undefined`); `ctest --output-on-failure` |
| `pages.yml` | Build ulang `docs/` Ã¢â â deploy GitHub Pages pada push `main` |
| Sanitizers | Seluruh tests dijalankan di bawah ASan/UBSan |
| Format | `.clang-format` + workflow optional `clang-format --dry-run` |
| Coverage (roadmap) | gcov/lcov Ã¢â â Codecov |

---

## 6. Penerapan di GitHub

1. `git init` + commit pertama (sudah disiapkan).
2. Buat repository GitHub (mis. `github.com/<user>/tesseract-crypt`).
3. `git remote add origin Ã¢â¬Â¦ && git push -u origin main`.
4. **Pages:** Settings Ã¢â â Pages Ã¢â â Source = *GitHub Actions* (workflow `pages.yml` sudah disiapkan).
5. **Topics/labels:** `encryption`, `c`, `libsodium`, `x25519`, `ed25519`, `cli`.
6. **Release:** tag `v0.1.0` Ã¢â â tarball sumber (workflow rilis menyusul di milestone M3).
7. README menampilkan badge: CI, License, Pages.

> Catatan: repositori live di `github.com/adyoi/tesseract-crypt`; remote `origin` sudah diset dan `gh` terautentikasi Ã¢â¬â push langsung ke `main`.

---

## 7. Roadmap (Milestone)

| Milestone | Isi | Status |
|-----------|-----|--------|
| **M0 Ã¢â¬â Skeleton** | Struktur repo, CMake, RENCANA, README, LICENSE, CI dasar | Ã¢Åâ¦ |
| **M1 Ã¢â¬â Core crypto** | keygen, seal/open buffer & file, sign/verify, armor, tests | Ã¢Åâ¦ |
| **M2 Ã¢â¬â CLI lengkap** | Semua subcommand, man page, UX TTY/armor otomatis | Ã¢Åâ¦ |
| **M3 Ã¢â¬â Docs & Pages** | `docs/` landing + CLI reference + format spec, deploy Pages | Ã¢Åâ¦ |
| **M4 Ã¢â¬â Packaging** | PKGBUILD, RPM spec, `.deb`, biner rilis CI, APT repo di Pages | Ã°Å¸Å¡Â§ |
| **M5 Ã¢â¬â Hardening** | Fuzz target (libFuzzer), fuzzing CI, coverage, audit eksternal | Ã°Å¸Å¡Â§ |
| **M6 Ã¢â¬â Ekstra** | `--rekey`, KMS/plugin backend, key rotation tooling | Ã°Å¸Å¡Â§ |

---

## 8. Keputusan Desain (ADR singkat)

1. **libsodium > OpenSSL** Ã¢â¬â API sulit salah, default aman, lisensi ISC, sedikit dependensi.
2. **C inti + C++ CLI** Ã¢â¬â library dapat di-*embed* ke proyek C mana pun; CLI nyaman untuk UX.
3. **Sign-then-encrypt, bukan sebaliknya** Ã¢â¬â tidak ada plaintext tak-terproteksi; signature terlindungi header.
4. **Format biner ber-versi** Ã¢â¬â memudahkan evolusi (v2 dapat menambah algorithm suite).
5. **MIT** Ã¢â¬â kompatibel dengan ekosistem Linux & libsodium (ISC).

