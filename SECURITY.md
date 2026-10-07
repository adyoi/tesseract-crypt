# Kebijakan Keamanan

## Prinsip desain (apa yang membuat aplikasi ini aman)

- **Hybrid public-key encryption** — ephemeral X25519 (forward secrecy per
  pesan) + static DH (identity binding) → BLAKE2b KDF → XChaCha20-Poly1305.
- **Sign-then-encrypt** — Ed25519ph streaming; header 264 byte menjadi AAD
  setiap chunk sehingga truncation, reorder, dan splice terdeteksi secara
  kriptografis.
- **Atomic output** — plaintext ditulis ke `.part` dan hanya di-*rename*
  setelah AEAD + tanda tangan (bila diminta) sukses.
- **Mode passphrase** — Argon2id memory-hard; saat membaca header/blob tak
  tepercaya parameter dibatasi (≤ 16 ops, ≤ 4 GiB, min 64 KiB) untuk
  mencegah DoS memori.
- **Kebersihan memori** — private key di-`sodium_mlock`, material sensitif
  di-`sodium_memzero`. Tanpa RNG sendiri; hanya `randombytes_buf` libsodium.

## Versi yang didukung

| Versi | Status dukungan |
|-------|-----------------|
| `v0.1.x` | Aktif (pengembangan) — tampatkan di lingkungan yang tidak tepercaya |

Catatan: format `v1` belum pernah dirilis publik; jika ditemukan masalah
format sebelum rilis 1.0, kami dapat mengganti format tanpa kompatibilitas
mundur.

## Melaporkan kerentanan

**Jangan membuka issue publik.** Kirim laporan pribadi melalui salah satu
saluran berikut:

1. **GitHub Security Advisory** — halaman repo → *Security* → *Report a
   vulnerability* (cara yang disukai).
2. **Email maintainer** — alamat kontak yang tercantum pada halaman profile
   maintainer repo (hanya untuk laporan keamanan).

### Yang perlu disertakan

- Versi produk (`tesseract-crypt version`) dan platform (OS, arsitektur).
- Cara build (distro libsodium / vcpkg / manual).
- Deskripsi kerentanan: apa yang bisa disalahgunakan, bagaimana, dan dampaknya.
- Bukti konsep singkat — **tanpa** kunci/private material publik di daftar CC.
- Jika melibatkan format biner, sertakan berkas contoh terkecil yang memicu.

### Komitmen kami

- Balasan konfirmasi dalam **≤ 72 jam**.
- Pembaruan status setiap **≤ 5 hari kerja**.
- Resolusi: perbaikan + tes regresi, lalu pengumuman bersamaan dengan rilis
  penambal (tanpa *embargo* publik yang permanen).
- Bila layak, kredit pelapor di CHANGELOG (kecuali diminta anonim).

## Area sensitif (fokus reviewer keamanan)

- Arbitrase alokasi dari ukuran header/chunk (`tess_header_parse`,
  `tess_seal`).
- Batas Argon2id pada jalur *untrusted* (buka pesan/kunci tak dikenal).
- Transisi state streaming (tanda tangan & enkripsi) dan atomisitas output.
- Cross-platform naming/binary (`tesseract-crypt` / `tscrypt`) di PATH.

## Proses

1. Pelapor membuat laporan pribadi (advisory atau email).
2. Maintainer menetapkan keparahan (CVSS) dan memverifikasi.
3. Perbaikan dikembangkan dengan tes regresi; diuji GCC/Clang + ASan/UBSan.
4. Release tambalan + catatan keamanan diterbitkan.