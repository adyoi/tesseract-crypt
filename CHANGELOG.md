# Changelog

Semua perubahan penting pada Tesseract Crypt dicatat di sini, mengikuti
[Keep a Changelog](https://keepachangelog.com/id-ID/1.1.0/) dan
[Semantic Versioning](https://semver.org/lang/id/).

## [Unreleased]

### Ditambahkan

- **Kontainer PE (PE-split)** untuk berkas besar: berkas yang melebihi batas
  praktis penyegelan dipotong menjadi frame-frame yang masing-masing disegel
  sendiri, dengan penanda `PE` di awal berkas sehingga `decrypt` mendeteksinya
  otomatis. Tersedia opsi `--pe`, `--pe-chunk-size MB` pada CLI dan kotak
  centang *Use PE-split for large files* pada GUI.
- **Penyegelan/penyandian direktori dan subdirektori** (batch): `--dir DIR`,
  `--out-dir DIR`, `--recursive` pada CLI; menu *Tools → Batch encrypt/decrypt
  from directory...* dan kotak centang *Include subdirectories (batch)* pada GUI.
- **Paket RPM** (`tesseract-crypt-<versi>-1.<arch>.rpm`) kini dibangun CPack
  berdampingan dengan `.deb`/`tar.gz` untuk setiap rilis Linux (x86_64, i686,
  aarch64). Isinya setara `.deb`: libsodium statis, jadi tidak ada paket runtime
  yang dibutuhkan (`Requires` kosong; paket `libsodium` hanya diminta bila
  libsodium ditautkan dinamis). Job Linux mengekstrak RPM dan menjalankan
  binernya sebagai uji asap, sama seperti `.deb`.
- **PKGBUILD untuk Arch Linux** dirender dari tarball rilis tepat saat rilis dan
  ikut diterbitkan sebagai aset `PKGBUILD`, sehingga checksum di dalamnya selalu
  cocok dengan arsip yang dirilis. Paketnya `tesseract-crypt-bin` (menyediakan
  `tesseract-crypt`), tidak mengompilasi apa pun dan memasang pohon rilis apa
  adanya — berkas terpasang identik byte dengan artefak yang di-attest. Pakai
  langsung dengan `curl -fsSLO …/releases/latest/download/PKGBUILD && makepkg -si`.
- `packaging/render.py` mengenal opsi `--only <target>` sehingga target PKGBUILD
  dapat dirender dari job Linux (yang hanya memegang aset Linux); keluaran target
  lain tidak berubah.

### Diubah

- **Pipeline rilis dipatok ke image `ubuntu-24.04`**, bukan `ubuntu-latest`
  (`release.yml` dan `pages.yml`). Biner Linux, `.deb`, dan `.rpm` mewarisi glibc
  dari image pembangunnya, jadi saat `ubuntu-latest` bermigrasi ke Ubuntu 26
  (mulai 2026-10-19) syarat glibc artefak rilis bisa naik diam-diam dan
  mematahkan Debian 12/Ubuntu 22.04. Untuk rilis, image dinaikkan secara sadar,
  bukan otomatis.
- Langkah **attest SBOM** memakai `actions/attest` langsung.
  `actions/attest-sbom` sudah deprecated (ia hanya pembungkus tipis atas aksi
  yang sama), dan memunculkan peringatan di setiap rilis.

## [1.0.4] — 2026-10-19

### Diperbaiki

- **Paket Windows kini mandiri (self-contained)**. Biner MSVC sebelumnya hanya
  menautkan *runtime* VC++ secara dinamis (`MSVCP140.dll`, `VCRUNTIME140.dll`,
  `VCRUNTIME140_1.dll`) yang **tidak** ikut dipaketkan, sehingga di Windows yang
  belum pernah memasang *VC++ 2015–2022 Redistributable* kedua executable gagal
  start sama sekali (`0xC0000135 STATUS_DLL_NOT_FOUND`). Ketiga DLL itu kini
  dikirim di samping executable di ZIP dan installer, jadi tidak ada lagi
  prasyarat tersembunyi. Ini juga penyebab kegagalan validasi paket winget
  (`Validation-Executable-Error`) pada VM bersih milik Microsoft, yang sekaligus
  mengonfirmasi bug tersebut.
- **Repo APT (GitHub Pages)** kini benar-benar terbit. Sebelumnya langkah Pages
  selalu jatuh ke jalur "docs only" karena secret penandatangan belum ada, jadi
  `apt install tesseract-crypt` yang didokumentasikan tidak pernah bisa jalan.
  Langkah Pages kini memberi peringatan (`::warning::`) bila repo APT dilewati.
- **Kunci penandatangan APT dirotasi** ke pasangan baru (RSA 4096, sign-only,
  berlaku sampai 2027-10-17). Sidik jari di workflow dan kunci publik di
  `docs/apt/tesseract-crypt.asc` diperbarui; salinan cadangannya disimpan lokal
  di `.apt-keys/` (di-`gitignore`, tidak pernah di-commit). Pengguna yang sudah
  menambahkan kunci lama cukup mengunduh ulang kunci publik baru dari
  <https://adyoi.github.io/tesseract-crypt/apt/tesseract-crypt.asc>.

## [1.0.3] — 2026-10-16

### Diperbaiki

- **Paket Chocolatey**: installer **x86** kini benar-benar dipakai pada Windows
  32-bit (`url`/`checksum`, sebelumnya hanya `url64bit`), dan `choco uninstall`
  kembali bekerja — entri Inno Setup beregistrasi sebagai `Tesseract Crypt
  &lt;versi&gt;` (bukan `tesseract-crypt`) sehingga tidak pernah cocok dengan
  nama paket; kini dicari lewat wildcard oleh `chocolateyuninstall.ps1`.
- **Metadata nuspec**: `owners`, `packageSourceUrl`, `docsUrl`, `bugTrackerUrl`
  dan `releaseNotes` ditambahkan sesuai pedoman moderasi chocolatey.org.

### Ditambahkan

- **Self-test paket di CI**: `packaging/selftest.py` merender rilis sintetis lalu
  memvalidasi tautan hash, XML/JSON yang valid, tidak ada placeholder tersisa,
  skrip uninstall cocok dengan nama aplikasi Inno Setup, dan versi konsisten
  antara `CMakeLists.txt`, `vcpkg.json` dan `CHANGELOG.md`.

### Diubah

- **Situs**: halaman utama (EN/ID) mendapat bagian **Install/Pasang** dengan
  perintah Homebrew, Scoop, WinGet, Chocolatey dan repositori APT; versi footer
  di-stamp saat situs dibangun, bukan ditulis manual di 12 berkas HTML.
- **Alur kerja rilis**: `choco push` dilewati bila versi sudah dikenal feed
  (terbit maupun masih moderasi) sehingga backfill tidak membuat entri moderasi
  ganda; action pihak ketiga (`winget-releaser`, `sbom-action`) dipin ke commit
  SHA, dan langkah Winget dilewati (dengan notice) sampai paketnya ada di
  `microsoft/winget-pkgs`.

## [1.0.2] — 2026-10-13

### Diperbaiki

- **Paket Windows `.zip`**: kini menyertakan runtime libsodium (`libsodium*.dll`)
  di `bin/`, sehingga biner berjalan tanpa instalasi tambahan (sebelumnya
  `tesseract-crypt.exe` gagal karena DLL tak ada). Installer x64/x86 tidak
  terpengaruh.
- **Linux `.tar.gz` & `.deb`**: libsodium kini ditautkan **statis** (1.0.20)
  sehingga arsip benar-benar mandiri; `.deb` tidak lagi memerlukan paket
  `libsodium23`. macOS sudah statis.

### Ditambahkan

- **Smoke test paket di CI**: setiap job merilis mengekstrak arsip hasil
  (`tar.gz`/`.zip`) lalu menjalankan `tesseract-crypt version` (dan `tscrypt`)
  untuk menjamin paket benar-benar jalan — menutup celah DLL/library yang hilang.
- **Metadata paket**: `pkg-config` (`tesseract-crypt.pc`) dan CMake package
  config (`tesseract-config.cmake` + `FindSodium.cmake`) kini ikut ter-install,
  sehingga `pkg-config` dan `find_package(tesseract)` bekerja untuk konsumen.
- **LICENSE & README** ikut dalam setiap arsip (`zip`/`tar.gz`/`.deb`).
- **Distribusi pihak ketiga**: formula Homebrew
  ([`adyoi/homebrew-tap`](https://github.com/adyoi/homebrew-tap)), manifest
  Scoop ([`adyoi/scoop-bucket`](https://github.com/adyoi/scoop-bucket)), Winget
  dan Chocolatey — semuanya dibangkitkan otomatis dari setiap rilis oleh
  `packages.yml`.
- **Provenance & SBOM**: setiap rilis menerbitkan SBOM SPDX dan attestation
  build provenance (Sigstore) yang dapat diverifikasi dengan
  `gh attestation verify`.

### Diubah

- Windows kini memakai **vcpkg manifest** (`vcpkg.json`) sehingga libsodium
  di-resolve lewat manifest dan hasil build dapat di-cache antar-job.
- Biner rilis macOS di-*ad-hoc code sign*; unduhan libsodium diverifikasi
  terhadap **SHA256** yang dipin.

## [1.0.1] — 2026-10-12

### Ditambahkan

- **Rilis multi-arsitektur**: setiap rilis kini menyertakan Linux (x86_64,
  i686, aarch64), macOS (universal2 — x86_64 + arm64), dan Windows (x64, x86,
  arm64): `tar.gz`/`zip`/`.deb` per arsitektur.
- **Installer Windows x86**: `tesseract-crypt-<versi>-windows-x86-setup.exe`
  (selain x64). Kedua installer memakai `AppId` berbeda sehingga dapat terpasang
  berdampingan.

### Diperbaiki

- **Installer Windows**: opsi "tambahkan ke `PATH`" kini benar-benar
  menambahkan folder instalasi ke `PATH` pengguna saat pemasangan, dan
  menghapusnya saat uninstall (mencegah entri `PATH` yatim).
- **Mojibake pada `--help`**: karakter em-dash diganti ASCII agar tampil benar
  pada konsol non-UTF-8.

## [1.0.0] — 2026-10-12

### Ditambahkan

- **Installer Windows (Inno Setup)**: `tesseract-crypt-<versi>-windows-x64-setup.exe`,
  dibangun otomatis oleh workflow rilis dan disertakan pada GitHub Release
  (termasuk runtime libsodium bila diperlukan); opsi menambahkan ke `PATH`.
- **Dokumentasi Fitur & Kinerja**: halaman
  `docs/features.html` + `docs/id/features.html` (setiap kemampuan dijelaskan)
  dan `docs/performance.html` + `docs/id/performance.html` (metodologi + angka
  terukur + cara reproduksi). Navigasi, tombol hero, dan `hreflang` ditambahkan
  ke 8 halaman lama; `README.md`/`README.en.md` serta man page (bagian KINERJA)
  ikut diperbarui.
- **`scripts/bench.sh`**: benchmark end-to-end CLI (best-of-N) untuk keygen,
  encrypt/decrypt (public-key & passphrase), sign/verify, variasi
  `--chunk-size`, dan multi-penerima.
- **`sodium_mlock`**: skalar/kunci rahasia disematkan di memori (`is_mlocked`
  pada `struct tess_key`) dan di-`sodium_munlock` saat dibebaskan.
- **`.gitattributes`**: normalisasi akhir baris (LF) lintas platform.

### Diperbaiki

- **`read_stream`** (`src/cli/main.cpp`): input dengan ukuran kelipatan tepat
  64 KiB gagal terbaca (memengaruhi `encrypt`/`decrypt --passphrase` dari berkas
  dan jalur stdin). Loop baru mengembalikan `in.eof() || !in.bad()`.
- **`encrypt --passphrase --text`**: sebelumnya gagal senyap (exit 1) karena
  passphrase lebih dulu menghabiskan stdin; sekarang `--text`, `--armor`, dan
  `have_text` ditangani pada jalur passphrase. Teks bantuan diperbarui.

### Keamanan

- Material kunci rahasia kini di-`sodium_mlock` selama dipakai (lihat di atas).

## [0.1.0] — 2026-10-08

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
  - **APT repository Linux** di GitHub Pages (`/apt`): tiap push `main`
    membangun ulang DEB (CPack) + repo `dists/stable` + `pool/`, ditandatangani
    GPG RSA-4096 (`InRelease` + `Release.gpg`); kunci publik di-commit di
    `docs/apt/tesseract-crypt.asc`; instruksi `apt install` di README EN/ID.
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