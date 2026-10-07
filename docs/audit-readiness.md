# Audit Readiness Checklist

This document provides guidance for an independent security audit of Tesseract Crypt. It is intended for auditors, maintainers, and contributors.

## 1. Project overview

- Language: C11 (library core), C++17 (CLI)
- Cryptographic backend: libsodium 1.0.18+
- Algorithms: X25519 (ECDH), Ed25519 (signatures), XChaCha20-Poly1305 (AEAD), Argon2id (password-based key derivation), BLAKE2b (key derivation)
- Formats: binary message format (v1 single-recipient, v2 multi-recipient), PEM-like armored text
- Target platforms: Linux, macOS, Windows, BSD/Unix-like systems

## 2. Threat model summary

Tesseract Crypt implements sign-then-encrypt with hybrid public-key encryption. Key assumptions:
- libsodium provides correct low-level primitives
- Secure random source via `randombytes_buf`
- Passive/active network adversary sees ciphertext only; no side-channel mitigations claimed beyond libsodium defaults
- Private keys must be protected (unlocked only when needed; `sodium_mlock` used for sensitive material where possible)

Assets to protect: plaintext confidentiality/integrity, sender authenticity (when signed), forward secrecy (per-message ephemeral X25519), identity binding (static DH).

## 3. Codebase inventory

- `include/tesseract/` - Public API (C, C++ header-only wrapper)
- `src/core/` - Core cryptographic implementation (header validation, key schedule, seal/open, signatures, keys, utilities)
- `src/cli/` - Command-line interface
- `tests/` - Unit/integration tests including known-answer tests and tamper detection
- `fuzz/` - libFuzzer targets (inspect, dearmor, key_parse)
- `cmake/`, `CMakeLists.txt` - Build system

## 4. Security features

- Versioned message header (magic "TSCR", versions 1/2) with strict validation
- Chunked streaming with per-chunk subkeys and AAD binding header + chunk index + final flag (prevents splice/reorder/truncation)
- Sign-then-encrypt: signature in authenticated header; decrypt writes to `.part` and renames only after verification (atomic verify-then-rename)
- Multi-recipient v2: data key wrapped per recipient (80-byte block), explicit recipient rejection (`TESS_ERR_RECIPIENT`)
- Passphrase mode uses Argon2id with enforced bounds when reading untrusted headers
- Memory safety: `sodium_memzero` for sensitive data, `sodium_mlock` on private key material
- No custom RNG; strict bounds checking (chunk sizes, Argon2 params, recipient counts)
- Armor/base64 with length/bounds handling

## 5. Testing & validation

- CTest suite: roundtrip, tamper, armor, keys, file, sign, vectors, multi
- Known-answer tests (KAT) with fixtures in `tests/fixtures/`
- ASan/UBSan in CI (sanitize job)
- libFuzzer fuzzing targets with 60s smoke runs in CI
- Build matrix: gcc/clang (Linux), AppleClang (macOS), MSVC (Windows), Debug/Release

## 6. Known limitations / out of scope

- External third-party security audit not yet performed (this is a readiness document)
- Side-channel resistance depends on libsodium platform implementations
- No formal verification; correctness relies on tests + review

## 7. Audit scope recommendations

Recommended areas for deep review:
1. Header parsing/validation (`tess_header.c`) - boundary conditions, integer handling
2. Key schedule (mode 1 v1/v2, passphrase mode) - domain separation, DH correctness
3. Chunk AEAD construction - nonce derivation, AAD structure, index overflow
4. Multi-recipient unwrap - block layout, AAD = header || recipient_pk, recipient lookup
5. Atomic file operations (verify-then-rename) - TOCTOU, platform differences (Windows)
6. Memory clearing/locking - coverage of all sensitive paths
7. Fuzzing coverage & harness safety

## 8. References

- Specification: `docs/format.html`, `docs/id/format.html`
- API: `include/tesseract/tesseract.h`
- Threats/handling: `SECURITY.md`
- Design decisions: `RENCANA.md`
