# Security Policy

## Design Principles (what makes this application secure)

- **Hybrid public-key encryption** — ephemeral X25519 (forward secrecy per
  message) + static DH (identity binding) → BLAKE2b KDF → XChaCha20-Poly1305.
- **Sign-then-encrypt** — Ed25519ph streaming; header (264 bytes) becomes AAD
  for every chunk so truncation, reordering, and splicing are detected
  cryptographically.
- **Atomic output** — plaintext is written to `.part` and only renamed
  after AEAD + signature (if requested) succeed.
- **Passphrase mode** — memory-hard Argon2id; bounds on ops/mem when reading
  untrusted headers/blobs to prevent memory DoS.
- **Memory hygiene** — private keys `sodium_mlock`, sensitive material
  `sodium_memzero`. No custom RNG; only libsodium `randombytes_buf`.

## Supported Versions

| Version | Support status |
|---------|----------------|
| `v0.1.x` | Active (development) — use in untrusted environments |

Note: format `v1` has not been released publicly; if a format issue is found
before a 1.0 release, we may change the format without backward compatibility.

## Reporting a Vulnerability

**Do not open a public issue.** Submit a private report via one of the
following channels:

1. **GitHub Security Advisory** — repo page → *Security* → *Report a
   vulnerability* (preferred).
2. **Email maintainers** — contact address listed on the repo maintainer
   profile page (only for security reports).

### What to include

- Product version (`tesseract-crypt version`) and platform (OS, architecture).
- Build method (libsodium distro / vcpkg / manual).
- Description of the vulnerability: what can be abused, how, and impact.
- Brief proof-of-concept — **without** exposing public keys/private material.
- If it involves the binary format, include the smallest sample file that
  triggers it.

### Our commitment

- Acknowledgment within **≤ 72 hours**.
- Status updates every **≤ 5 business days**.
- Resolution: fix + regression tests, then announcement with patch release
  (no permanent public embargo).
- Credit to the reporter in CHANGELOG when applicable (unless anonymity requested).

## Sensitive areas (reviewer focus)

- Allocation arbitration from header/chunk sizes (`tess_header_parse`,
  `tess_seal`).
- Argon2id bounds on untrusted paths (opening unknown messages/keys).
- Streaming state transitions (signing & encryption) and output atomicity.
- Cross-platform naming/binary (`tesseract-crypt` / `tscrypt`) in PATH.

## Process

1. Reporter submits a private report (advisory or email).
2. Maintainers assess severity (CVSS) and verify.
3. Fix developed with regression tests; tested on GCC/Clang + ASan/UBSan.
4. Patch release + security notes published.
