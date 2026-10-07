# Contributing

Thank you for your interest in this project! Contributions are welcome: bug fixes,
tests, documentation, and new features — as long as they stay in line with the
design in [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Scope

- **Core library** (`src/core/`, C11) — stable public API in
  `include/tesseract/tesseract.h`. All cryptographic changes and format
  modifications must preserve the following principles:
  - Sign-then-encrypt, header-to-chunk AAD (anti reorder/splice/truncation),
  - forward secrecy (ephemeral X25519 per message),
  - memory hygiene (`sodium_mlock` / `sodium_memzero`),
  - no custom RNG; always `randombytes_buf`.
- **CLI** (`src/cli/main.cpp`, C++17) — only calls the public API. Do not
  move crypto logic into the CLI.
- **Docs** (`docs/`) — must stay in sync with `DEVELOPMENT.md` and the actual
  code (header offsets, armor labels, key file formats).

## Setting up the environment

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

## Standards

1. **C/C++ style**: follow the surrounding file conventions; run
   `clang-format -i` if available (config in `.clang-format`).
2. **Warnings**: build must be clean on GCC, Clang, and MSVC
   (`-DTESS_WARNINGS_AS_ERRORS=ON` is used in CI).
3. **Tests**: every bug fix must be accompanied by a test that failed before;
   new features need relevant roundtrip/tamper tests in `tests/`.
4. **Sanitizer**: ensure it passes `-DTESS_SANITIZE=ON` before submitting a PR:
   ```bash
   cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DTESS_SANITIZE=ON
   cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure
   ```
5. **Documentation**: update `DEVELOPMENT.md`, `docs/*`, README, and man pages if
   behavior or format changes.

## Pull request workflow

1. Fork & create a branch: `git checkout -b fix/brief-description`.
2. Write/update tests, run the full suite, then commit with a concise message
   (see `git log` for message style).
3. Open a PR that states *what problem* and *why*; paste the `ctest` summary.
4. CI (GCC/Clang, Debug/Release, ASan+UBSan) must be green.

## Top-level rules that must not be violated

- Do not introduce custom cryptographic primitives; use only libsodium.
- Do not change the binary format without bumping the header `version` and
  updating `docs/format.html` + `DEVELOPMENT.md`.
- Do not commit keys, passphrases, or test fixture material (see `.gitignore`).

## Reporting vulnerabilities

Do not open a public issue for security vulnerabilities. Follow the
instructions in [`SECURITY.md`](SECURITY.md).

## License

Contributions are accepted under the MIT license, same as the project.
See [`LICENSE`](LICENSE).
