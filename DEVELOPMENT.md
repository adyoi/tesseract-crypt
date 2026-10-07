# Development Plan — `tesseract-crypt`

**Codename:** Tesseract  
**Language:** C11 (core library) + C++17 (CLI)  
**Target platform:** Linux (x86_64, aarch64)  
**Build system:** CMake ≥ 3.16  
**Crypto dependency:** libsodium (chosen for misuse-resistant API, periodic audits, wide distro availability)

---

## 1. Vision & Core Features

Application for encrypting/decrypting **strings and files** with **asymmetric keys** (private/public),
built on a modern hybrid key model:

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Hybrid Public-Key Encryption** | Ephemeral X25519 (per-message forward secrecy) + static DH (identity binding) → BLAKE2b KDF → XChaCha20-Poly1305 AEAD |
| 2 | **Sign-then-Encrypt** | Ed25519 detached signature over plaintext, stored in header that is authenticated (authenticity + non-repudiation) |
| 3 | **Passphrase Mode** | Symmetric fallback: Argon2id (memory-hard) → XChaCha20-Poly1305 |
| 4 | **Streaming chunked** | Large files processed per-chunk (default 64 KiB) with per-chunk subkey (`crypto_kdf`) — constant memory, reorder/truncation detection |
| 5 | **PEM-like armor** | Binary output can be armored into text (`-----BEGIN TESSERACT MESSAGE-----`), auto-detect on decrypt |
| 6 | **Encrypted key file** | Private key protected with Argon2id (`--passphrase` option during keygen) |
| 7 | **Fingerprint & trust** | BLAKE2b-128 fingerprint of public key; `--require-signer` option for identity pinning |
| 8 | **Memory hygiene** | `sodium_memzero` + `sodium_mlock` on key material |
| 9 | **Multi-recipient (v2)** | Single message to multiple public keys: random data key wrapped per recipient (80-byte block); non-recipients explicitly rejected |

### Differentiators (“nothing like it before”)

- **Header bound to every chunk** (entire header as AAD + chunk index + final flag) → prevents splice, reorder, and truncation cryptographically, not just a checksum.
- **Identity-bound hybrid encryption**: combination of ephemeral DH *and* static DH between sender↔recipient, so decryption only succeeds for the correct key pair while preserving forward secrecy.
- **Multi-recipient without header replication**: v2 uses one 264-byte header + one random data key, with wrap key per recipient in 80-byte blocks — message size ≈ v1 + 80 B/recipient, and blocks are bound to the header (AAD) so they cannot be moved between messages.
- **Signature verification while streaming with atomic output file** (write `.part` → verify → `rename`), so unauthenticated plaintext never appears at the final path.

---

## 2. Architecture

```
tesseract-crypt/
├── include/tesseract/      # Public API (C) + header-only wrapper (C++)
│   ├── tesseract.h
│   └── tesseract.hpp
├── src/
│   ├── core/               # libtesseract_crypt (C11)
│   │   ├── tess_internal.h
│   │   ├── tess_status.c   # error codes + messages
│   │   ├── tess_util.c     # armor/base64, fingerprint, safe I/O
│   │   ├── tess_keys.c     # keygen, load/save keys (plain & Argon2id)
│   │   ├── tess_header.c   # serialize/parse message header (264 byte)
│   │   ├── tess_seal.c     # seal/open buffer + streaming file
│   │   └── tess_sign.c     # Ed25519 detached sign/verify (streaming)
│   └── cli/                # bin `tesseract-crypt` + alias `tscrypt` (C++17)
│       └── main.cpp        # subcommands: keygen, pubkey, encrypt, decrypt,
│                           #        sign, verify, inspect, info, version
├── tests/                  # CTest (roundtrip, tamper, armor, multi-chunk, etc.)
├── docs/                   # GitHub Pages (landing + CLI ref + format design)
├── man/                    # man page tesseract-crypt(1)
├── cmake/                  # FindSodium fallback, config package
├── .github/
│   ├── workflows/ci.yml    # build+test (gcc/clang, Debug/Release, ASan/UBSan)
│   ├── workflows/pages.yml # deploy docs/ → GitHub Pages
│   └── ISSUE_TEMPLATE/
├── packaging/              # PKGBUILD (Arch), spec (RPM), .deb recipe
├── scripts/build-linux.sh
├── CMakeLists.txt
├── README.md · DEVELOPMENT.md · CHANGELOG.md · CONTRIBUTING.md · SECURITY.md
└── LICENSE (MIT)
```

**Layers:**

1. `libtesseract_crypt` — stable C API, only libsodium dependency.
2. `tesseract-crypt` (CLI, alias `tscrypt`) — calls only public API, as a usage example.
3. Tests + CI — maintain quality.

---

## 3. Cryptographic Design

### 3.1 Key Pair

- **X25519** (32 B pk / 32 B sk) → encryption
- **Ed25519** (32 B pk / 64 B sk) → signature
- Stored in a single key file; public key exported separately.

### 3.2 Message Header Format (`TSCR`, 264 bytes, little-endian)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | magic `"TSCR"` |
| 4 | 1 | version = 1 (single) / 2 (multi-recipient) |
| 5 | 1 | suite = 1 (X25519 + BLAKE2b + XChaCha20-Poly1305 + Ed25519) |
| 6 | 1 | mode (1 = public-key, 2 = passphrase) |
| 7 | 1 | flags (bit0 = signed) |
| 8 | 32 | ephemeral X25519 pk (mode 1) |
| 40 | 32 | recipient X25519 pk (mode 1, binding) — v2: recipient count (u32) + reserved 28 B must be zero |
| 72 | 32 | sender X25519 pk (mode 1, optional/anonymous) |
| 104 | 32 | sender Ed25519 pk (if signed, else zero) |
| 136 | 64 | Ed25519 signature over plaintext (if signed, else zero) |
| 200 | 16 | KDF salt |
| 216 | 4 | Argon2id ops limit (mode 2) |
| 220 | 8 | Argon2id mem limit (mode 2) |
| 228 | 24 | base nonce |
| 252 | 4 | chunk size (u32) |
| 256 | 8 | plaintext length (u64; `UINT64_MAX` = unknown) |

### 3.3 Key Schedule

**Mode 1 (public-key):**
```
dh_eph   = X25519(eph_sk, recipient_pk)          # forward secrecy
dh_stat  = X25519(sender_sk, recipient_pk)       # identity binding (0 if anonymous)
master   = BLAKE2b-256(key = dh_eph,
                       in  = dh_stat || salt || "tesseract-kdf-v1")
```
**Mode 1, format v2 (multi-recipient):**
```
data_key = randombytes(32)                       # protects payload
wrap_i   = BLAKE2b-256(key = X25519(eph_sk, recipient_i_pk),
                       in  = X25519(sender_sk, recipient_i_pk) || salt || "tesseract-kdf-v1")
block_i  = recipient_i_pk(32) || XChaCha20-Poly1305(wrap_i, data_key,
                                                    nonce = base_nonce,
                                                    aad = header(264) || recipient_i_pk)(48)
```
Chunks then use `data_key` as `master`; chunk AAD remains header(264).
**Mode 2 (passphrase):**
```
master = Argon2id(passphrase, salt, ops, mem)    # ops/mem from header
```
**Per chunk i:**
```
subkey_i  = crypto_kdf_derive_from_key(32, i+1, "TSCHNK01", master)
nonce_i   = base_nonce XOR (i in last 8 bytes, big-endian)
AAD_i     = header(264) || u64be(i) || u8(final)
ct_i      = XChaCha20-Poly1305(subkey_i, nonce_i, pt_i, AAD_i)
```
File shell: `header || (u32le len(ct_i) || ct_i)*` — last chunk flagged `final`.
Empty message = one final chunk of 0-byte plaintext.

### 3.4 Sign-then-Encrypt Flow

1. Pass 1: stream plaintext → Ed25519 (stateful) → 64-byte signature.
2. Signature + sender Ed25519 pk placed into header.
3. Pass 2: encrypt (header as AAD).
4. Decrypt: stream plaintext to **`.part` file** → verify signature → atomic `rename`.

> Trust note: signature verified against sender key inside header.
> For pinning, use `tesseract-crypt decrypt --require-signer sender.pub`.

### 3.5 Security Limits Imposed

- Strict header validation (magic/version/suite/bounds) before allocation.
- Bound Argon2id mem/ops from header (anti-DoS on unknown file decrypt).
- `chunk_size` limited to 4 KiB … 16 MiB.
- All sensitive material `sodium_memzero`; keys `sodium_mlock`.
- No custom RNG — only `randombytes_buf`.

---

## 4. CLI (`tesseract-crypt`, alias `tscrypt`)

```
tesseract-crypt keygen    -o alice [--passphrase] [--kdf-ops N] [--kdf-mem MB]
tesseract-crypt pubkey    -k alice.key [-o alice.pub]
tesseract-crypt encrypt   -r bob.pub [-r carol.pub ...] [-k alice.key] [-i in] [-o out] [--armor]
                          [--chunk-size N] [--no-sign]    # repeated -r → v2 format
tesseract-crypt encrypt   --passphrase [-i in] [-o out]        # symmetric mode
tesseract-crypt encrypt   --text "rahasia" -r bob.pub          # string → stdout (armor)
tesseract-crypt decrypt   -k bob.key [-i in] [-o out]
                          [--require-signer alice.pub] [--passphrase]
tesseract-crypt rekey     -i in.enc -o out.enc -r new.pub[-r ...] [-k sender.key] [--no-sign]
tesseract-crypt sign      -k alice.key -i file [-o file.sig]
tesseract-crypt verify    -k alice.pub -i file -s file.sig
tesseract-crypt inspect   [-i pesan.enc]                       # read header
tesseract-crypt info      -k alice.key | -k alice.pub          # fingerprint
tesseract-crypt version | help
```

`tscrypt` is an alias that gets installed on all platforms (Linux/Windows/macOS/BSD).
Canonical name: `tesseract-crypt` (`.exe` automatically on Windows).

UX: output to TTY → automatic armor; stdin/stdout (`-`) supported; non-zero exit on failure.

---

## 5. Quality & CI

| Task | Detail |
|------|--------|
| `ci.yml` | Matrix: gcc & clang × Debug/Release; separate ASan+UBSan job (`-fsanitize=address,undefined`); `ctest --output-on-failure` |
| `pages.yml` | Rebuild `docs/` → deploy GitHub Pages on push `main` |
| Sanitizers | All tests run under ASan/UBSan |
| Format | `.clang-format` + optional `clang-format --dry-run` workflow |
| Coverage (roadmap) | gcov/lcov → Codecov |

---

## 6. GitHub Deployment

1. `git init` + initial commit (ready).
2. Create GitHub repository (e.g. `github.com/<user>/tesseract-crypt`).
3. `git remote add origin … && git push -u origin main`.
4. **Pages:** Settings → Pages → Source = *GitHub Actions* (workflow `pages.yml` is ready).
5. **Topics/labels:** `encryption`, `c`, `libsodium`, `x25519`, `ed25519`, `cli`.
6. **Release:** tag `v0.1.0` → source tarball (release workflow follows after M3 milestone).
7. README shows badges: CI, License, Pages.

> Note: live repository at `github.com/adyoi/tesseract-crypt`; remote `origin` set and `gh` authenticated — push directly to `main`.

---

## 7. Roadmap (Milestone)

| Milestone | Contents | Status |
|-----------|----------|--------|
| **M0 — Skeleton** | Repo structure, CMake, DEVELOPMENT, README, LICENSE, basic CI | ✅ |
| **M1 — Core crypto** | keygen, seal/open buffer & file, sign/verify, armor, tests | ✅ |
| **M2 — Full CLI** | All subcommands, man page, UX TTY/armor auto | ✅ |
| **M3 — Docs & Pages** | `docs/` landing + CLI reference + format spec, deploy Pages | ✅ |
| **M4 — Packaging** | PKGBUILD, RPM spec, `.deb`, CI release binary, APT repo on Pages | 🚧 |
| **M5 — Hardening** | Fuzz target (libFuzzer), fuzzing CI, coverage, external audit | 🚧 |
| **M6 — Extras** | `--rekey`, KMS/plugin backend, key rotation tooling | 🚧 |

---

## 8. Design Decisions (Short ADR)

1. **libsodium > OpenSSL** — hard to misuse, safe defaults, ISC license, few dependencies.
2. **C core + C++ CLI** — library embeddable into any C project; CLI convenient for UX.
3. **Sign-then-encrypt, not the reverse** — no unprotected plaintext; signature protected inside header.
4. **Versioned binary format** — eases evolution (v2 can add algorithm suite).
5. **MIT** — compatible with Linux ecosystem & libsodium (ISC).
