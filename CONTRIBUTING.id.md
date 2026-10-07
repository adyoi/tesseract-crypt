# Berkontribusi

Terima kasih telah melirik proyek ini! Kontribusi disambut baik: perbaikan
bug, tes, dokumentasi, dan fitur baru — selama tetap sejalan dengan desain di
[`DEVELOPMENT.md`](DEVELOPMENT.md).

## Lingkup

- **Library inti** (`src/core/`, C11) — API publik stabil di
  `include/tesseract/tesseract.h`. Semua perubahan kriptografi dan format
  harus mempertahankan prinsip berikut:
  - Sign-then-encrypt, header-ke-chunk AAD (anti reorder/splice/truncation),
  - forward secrecy (ephemeral X25519 per pesan),
  - kebersihan memori (`sodium_mlock` / `sodium_memzero`),
  - tidak memakai RNG sendiri; selalu `randombytes_buf`.
- **CLI** (`src/cli/main.cpp`, C++17) — hanya memanggil API publik. Jangan
  pindahkan logika kripto ke CLI.
- **Docs** (`docs/`) — harus sinkron dengan `DEVELOPMENT.md` dan kode aktual
  (offset header, label armor, format berkas kunci).

## Menyiapkan lingkungan

```bash
# Debian/Ubuntu
sudo apt install build-essential cmake libsodium-dev

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Windows/macOS/vcpkg:

```bash
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release -j
ctest --test-dir build -C Release --output-on-failure
```

## Standar

1. **Gaya C/C++**: ikuti konsistensi file sekitar; jalankan
   `clang-format -i` bila tersedia (konfigurasi di `.clang-format`).
2. **Peringatan**: build harus bersih di GCC, Clang, dan MSVC
   (`-DTESS_WARNINGS_AS_ERRORS=ON` dipakai di CI).
3. **Tes**: setiap perbaikan bug harus disertai tes yang gagal sebelumnya;
   fitur baru wajib punya tes roundtrip/tamper yang relevan di `tests/`.
4. **Sanitizer**: pastikan lulus `-DTESS_SANITIZE=ON` sebelum mengirim PR:
   ```bash
   cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DTESS_SANITIZE=ON
   cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure
   ```
5. **Dokumentasi**: ubah `DEVELOPMENT.md`, `docs/*`, README, dan man page bila
   perilaku atau format berubah.

## Alur pull request

1. Fork & buat branch: `git checkout -b fix/deskripsi-singkat`.
2. Tulis/perbarui tes, jalankan seluruh suite, lalu commit dengan pesan
   ringkas (lihat `git log` untuk gaya pesan).
3. Buka PR yang menyebutkan *masalah apa* dan *mengapa*; tempel ringkasan
   `ctest`.
4. CI (GCC/Clang, Debug/Release, ASan+UBSan) harus hijau.

## Baris teratas yang tidak boleh dilanggar

- Jangan memperkenalkan primitif kripto sendiri; hanya libsodium.
- Jangan ubah format biner tanpa bump versi header (`version`) dan update
  `docs/format.html` + `DEVELOPMENT.md`.
- Jangan commit kunci, passphrase, atau materal berkas uji (lihat
  `.gitignore`).

## Melaporkan kerentanan

Jangan buka issue publik untuk kerentanan keamanan. Ikuti petunjuk di
[`SECURITY.md`](SECURITY.md).

## Lisensi

Kontribusi diterima dengan lisensi MIT, sama seperti proyek ini.
Lihat [`LICENSE`](LICENSE).