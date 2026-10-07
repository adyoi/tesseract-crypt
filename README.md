# Tesseract Crypt

**Enkripsi string & file dengan public/private key — hibrida modern, streaming, bertanda tangan.**

`libtesseract_crypt` (C11) + `tesseract-crypt` (CLI, C++17, alias pendek: `tscrypt`)
dibangun di atas
[libsodium](https://doc.libsodium.org/): X25519 *hybrid* encryption, Ed25519
sign-then-encrypt, XChaCha20-Poly1305 AEAD per-chunk, dan Argon2id untuk mode
passphrase.

| Fitur | Deskripsi |
|-------|-----------|
| **Hybrid public-key** | Ephemeral X25519 (forward secrecy per pesan) + static DH (identity binding) → BLAKE2b KDF → XChaCha20-Poly1305 |
| **Sign-then-encrypt** | Tanda tangan Ed25519ph (streaming) menempel di header yang ikut di-authenticate |
| **Mode passphrase** | Argon2id (memory-hard) sebagai fallback simetris |
| **Streaming chunked** | 64 KiB per chunk, subkey per-chunk (`crypto_kdf`), memori konstan, deteksi reorder/truncation |
| **PEM-like armor** | Base64 `-----BEGIN TESSERACT MESSAGE-----` untuk stdout & teks |
| **Atomic output** | File ditulis ke `.part`, di-rename hanya setelah dekripsi & verifikasi sukses |

## Build

```bash
# Linux (libsodium dari distro)
sudo apt install build-essential cmake libsodium-dev   # Debian/Ubuntu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

```bash
# vcpkg (Windows/macOS/apa pun)
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release -j
```

## Mulai cepat

```bash
# 1. Buat pasangan kunci
tesseract-crypt keygen -o alice
tesseract-crypt keygen -o bob

# 2. Enkripsi file untuk Bob, ditandatangani Alice
tesseract-crypt encrypt -r bob.pub -k alice.key -i rahasia.txt -o rahasia.enc

# 3. Dekripsi — tanda tangan diverifikasi sebelum file ditulis
tesseract-crypt decrypt -k bob.key -i rahasia.enc -o rahasia.out \
                        --require-signer alice.pub

# 4. Enkripsi string langsung (otomatis armor ke TTY)
tesseract-crypt encrypt --text "Halo dunia" -r bob.pub

# 5. Mode passphrase (tanpa kunci publik)
tesseract-crypt encrypt --passphrase -i catatan.txt -o catatan.enc

# 6. Inspeksi header pesan
tesseract-crypt inspect -i rahasia.enc
tesseract-crypt info -k alice.key
```

> `tscrypt` adalah alias yang ikut ter-install — semua perintah di atas juga
> berfungsi dengan `tscrypt` (mis. `tscrypt keygen -o alice`). Nama binary
> di semua platform sama: `tesseract-crypt` (di Windows ditambah `.exe`).

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
tess_seal((const uint8_t *)"rahasia", 7, &so, &ct, &ct_len);
```

Wrapper C++17 header-only tersedia di `<tesseract/tesseract.hpp>` (`tess::key`,
`tess::seal`, `ess::open`).

## Dokumentasi

- [Landing page](https://<owner>.github.io/tesseract-crypt/) — gambaran & quick start
- [Referensi CLI](https://<owner>.github.io/tesseract-crypt/cli.html)
- [Spesifikasi format](https://<owner>.github.io/tesseract-crypt/format.html)

## Keamanan

- Kunci privat disimpan dengan Argon2id (opsi `--passphrase`), di-unlock di memori
  dan di-zeroize (`sodium_memzero`).
- Header 264 byte ikut menjadi AAD setiap chunk → truncation/reorder/splice terdeteksi.
- File output ditulis ke `.part` dan **hanya** di-rename setelah AEAD + signature sukses.
- Batas Argon2id ketika membaca header/blob tak tepercaya (max 16 ops / 4 GiB) anti-DoS.

Lihat [SECURITY.md](SECURITY.md) untuk pelaporan kerentanan.

## Lisensi

[MIT](LICENSE)
