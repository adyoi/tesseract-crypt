# Code Coverage

This project supports code coverage instrumentation using GCC/Clang with gcov/lcov.

## Local usage (Linux/macOS with GCC/Clang)

```bash
mkdir -p build-coverage
cd build-coverage
cmake .. -DCMAKE_BUILD_TYPE=Debug -DTESS_COVERAGE=ON -DTESS_BUILD_TESTS=ON
cmake --build . --parallel
ctest --output-on-failure
```

Generate HTML report:
```bash
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '*/tests/*' '*/fuzz/*' '/usr/*' --output-file coverage-filtered.info
genhtml coverage-filtered.info --output-directory coverage-html
```

Open `coverage-html/index.html` in a browser.

## CI integration

A dedicated CI job can upload coverage to Codecov. See `.github/workflows/ci.yml` for the coverage job template (recommended).

## Notes

- `TESS_COVERAGE` adds `--coverage -O0 -g` flags
- Exclude tests, fuzz harnesses, and system headers from reports for cleaner metrics
- MSVC coverage is supported via Visual Studio's coverage tools (separate workflow)
