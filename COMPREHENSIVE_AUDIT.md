# COMPREHENSIVE AUDIT REPORT

Repository: C:/Users/RDP/Documents/Default Project/tesseract-Crypt
Thoroughness: very thorough
Date: Wed Oct 07 2026

## 1. LANGUAGE INVENTORY

| File | Language |
|---|---|
| README.md | Indonesian (markdown) |
| README.en.md | English (markdown) |
| CONTRIBUTING.md | Indonesian (markdown) |
| SECURITY.md | Indonesian (markdown) |
| CHANGELOG.md | Indonesian (markdown) |
| DEVELOPMENT.md | Indonesian (markdown) |
| man/tesseract-crypt.1 | roff (man page, Indonesian content) |
| man/tscrypt.1 | roff include (.so directive) |
| docs/index.html | English (HTML) |
| docs/cli.html | English (HTML) |
| docs/format.html | English (HTML) |
| docs/tentang.html | English (HTML) |
| docs/style.css | CSS |
| docs/id/index.html | Indonesian (HTML) |
| docs/id/cli.html | Indonesian (HTML) |
| docs/id/format.html | Indonesian (HTML) |
| docs/id/tentang.html | Indonesian (HTML) |
| .github/ISSUE_TEMPLATE/bug_report.md | Indonesian (markdown) |
| .github/ISSUE_TEMPLATE/feature_request.md | Indonesian (markdown) |
| .github/workflows/pages.yml | YAML |
| .github/workflows/codeql.yml | YAML |
| .github/workflows/ci.yml | YAML |
| .github/dependabot.yml | YAML |

## 2. DOCS SITE STRUCTURE

- EN nav (docs/*.html): Home, CLI Reference, Format Spec, About, GitHub, ID link to id/*.html; active class on current page; relative hrefs.
- ID nav (docs/id/*.html): Beranda, Referensi CLI, Spesifikasi Format, Tentang, GitHub, EN link to ../*.html.
- Footer EN: GitHub, Contributing, Security, License → GitHub URLs (https://github.com/adyoi/tesseract-crypt/...).
- Footer ID: GitHub, Kontribusi, Keamanan, Lisensi (same targets).
- Header/nav markup pattern consistent across all pages (header.site .wrap with brand/logo + nav). hreflang/alternate links present for EN↔ID.

## 3. OUTDATED/WRONG CONTENT

Commands match implementation: keygen, pubkey, encrypt, decrypt, sign, verify, inspect, info, version, help. Flags present: -r (repeatable/multi-recipient), --passphrase, --armor, --chunk-size, --no-sign, --text, --require-signer, --kdf-ops, --kdf-mem, -i, -o, -s, -k.
Multi-recipient v2 documented (repeat -r). Format v2: recipient count at offset 40 (u32), bytes 44-71 reserved zero; 80-byte recipient blocks; header remains AAD. 264-byte header layout matches spec. Exit codes 0/1/2/3 correctly documented. No obvious incorrect claims about single-recipient-only.

## 4. FEATURES (EXIST VS MENTION)

- APT repo key docs/apt/tesseract-crypt.asc exists; install instructions in README.md/en.md only (not in EN/ID HTML pages).
- Multi-recipient v2 (80-byte blocks): documented in CHANGELOG/DEVELOPMENT and docs (EN/ID); present in code/tests.
- KAT fixtures: tests/test_vectors.c + tests/fixtures/* exist; mentioned in CHANGELOG only.
- Fuzzing (fuzz_inspect, fuzz_dearmor, fuzz_key_parse): exist + CI fuzz job; mentioned in CHANGELOG only.
- CI matrix (gcc/clang/MSVC/AppleClang, ASan/UBSan): ci.yml shows gcc/clang matrix, ASan job, MSVC Windows, AppleClang macOS, fuzz; mentioned in CHANGELOG partially.
- CPack (TGZ/DEB/ZIP): CMakeLists.txt includes CPack; pages.yml builds DEB; mentioned in CHANGELOG.

