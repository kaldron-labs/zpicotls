# Repository Guidelines

## Project Structure & Module Organization
- `include/` holds public headers (`zpicotls.h`, `include/zpicotls/*.h`).
- `lib/` contains the core C implementation and crypto backends (OpenSSL, mbedtls, minicrypto, fusion).
- `src/` includes auxiliary source files (for example, ESNI/ECH helpers).
- `t/` contains tests, including Perl end-to-end scripts (`t/*.t`) and C test sources/assets.
- `fuzz/` provides fuzzing harnesses; `deps/` hosts git submodules such as `picotest`, `cifra`, and `micro-ecc`.
- Build tooling lives in `CMakeLists.txt` and `cmake/`; platform projects live in `picotlsvs/` and `picotls.xcodeproj`.

## Build, Test, and Development Commands
- Initialize submodules (required for bundled deps):
  ```sh
  git submodule init
  git submodule update
  ```
- Configure and build:
  ```sh
  cmake .
  make
  ```
- Run the test suite:
  ```sh
  make check
  ```
  This builds and runs the `test-*.t` executables and the Perl tests in `t/`.
- Run the CLI for local manual testing:
  ```sh
  ./cli -c /path/to/cert.pem -k /path/to/key.pem 127.0.0.1 8443
  ./cli 127.0.0.1 8443
  ```

## Coding Style & Naming Conventions
- C code is formatted with `clang-format` using `.clang-format` (LLVM base, 4-space indents, 132-column limit, Linux braces).
- Keep public APIs in `include/` and implementation details in `lib/`.
- Prefer descriptive, lowercase filenames consistent with existing modules (e.g., `certificate_compression.c`).

## Testing Guidelines
- Tests live in `t/`: Perl E2E tests use `t/*.t`, and C unit/integration tests are built into `test-*.t` binaries.
- Add new tests alongside related modules and ensure `make check` passes.

## Commit & Pull Request Guidelines
- Git history favors short, direct subjects (often lowercase) and merge-style messages like `Merge pull request #...` or `merged PR-###`.
- Include a brief rationale, testing notes (e.g., `make check`), and link issues/PRs when applicable.

## Security & Reporting
- Report vulnerabilities privately via `h2o-vuln@googlegroups.com`. See `SECURITY.md` for details.
