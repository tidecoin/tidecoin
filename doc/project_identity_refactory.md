# Project Identity Refactor Status (Hard Cutover)

Date: 2026-03-03

## Policy

This refactor follows strict hard cutover rules:

- No backward compatibility aliases.
- No dual naming period.
- No `BITCOIN_*` env fallback.
- No compatibility shims for old target names.

## Scope Reviewed

- Build graph: `CMakeLists.txt`, `src/*/CMakeLists.txt`, `cmake/module/*`, `cmake/script/*`
- CI and test framework: `ci/test/*`, `test/*`
- Packaging/resources: `share/*`, `src/qt/res/icons/*`
- Guix/contrib/depends: `contrib/guix/*`, `contrib/devtools/*`, `contrib/verify-commits/*`, `depends/*`
- Active docs touched by build/test/runtime naming

## Implemented (Completed)

### 1) CMake target identity cutover

Completed target-id rename to Tidecoin naming across the CMake graph:

- Executables: `tidecoin`, `tidecoind`, `tidecoin-node`, `tidecoin-cli`, `tidecoin-tx`, `tidecoin-util`, `tidecoin-wallet`
- Libraries: `tidecoin_*` naming across core libs
- Tests/bench: `test_tidecoin`, `test_tidecoin-qt`, `bench_tidecoin`
- Kernel target id cutover: `bitcoinkernel` -> `tidecoinkernel`

### 2) Atomic source/module filename cutover (completed)

Completed rename + reference rewiring for core, init, qt, bench, and kernel sources:

- Core entrypoints:
  - `src/bitcoin.cpp` -> `src/tidecoin.cpp`
  - `src/bitcoind.cpp` -> `src/tidecoind.cpp`
  - `src/bitcoin-cli.cpp` -> `src/tidecoin-cli.cpp`
  - `src/bitcoin-tx.cpp` -> `src/tidecoin-tx.cpp`
  - `src/bitcoin-util.cpp` -> `src/tidecoin-util.cpp`
  - `src/bitcoin-wallet.cpp` -> `src/tidecoin-wallet.cpp`
  - `src/bitcoin-chainstate.cpp` -> `src/tidecoin-chainstate.cpp`
- Init:
  - `src/init/bitcoin-*.cpp` -> `src/init/tidecoin-*.cpp`
  - `src/init/bitcoind.cpp` -> `src/init/tidecoind.cpp`
- Bench/kernel:
  - `src/bench/bench_bitcoin.cpp` -> `src/bench/bench_tidecoin.cpp`
  - `src/kernel/bitcoinkernel.cpp` -> `src/kernel/tidecoinkernel.cpp`
- Qt core source namespace:
  - `src/qt/bitcoin.cpp|.h` -> `src/qt/tidecoin.cpp|.h`
  - `src/qt/bitcoingui.*` -> `src/qt/tidecoingui.*`
  - `src/qt/bitcoinunits.*` -> `src/qt/tidecoinunits.*`
  - `src/qt/bitcoinamountfield.*` -> `src/qt/tidecoinamountfield.*`
  - `src/qt/bitcoinaddressvalidator.*` -> `src/qt/tidecoinaddressvalidator.*`
  - `src/qt/bitcoinstrings.cpp` -> `src/qt/tidecoinstrings.cpp`
  - `src/qt/bitcoin.qrc` -> `src/qt/tidecoin.qrc`
  - `src/qt/bitcoin_locale.qrc` -> `src/qt/tidecoin_locale.qrc`

### 3) CI/env namespace cutover

Completed migration to Tidecoin-only env namespace in active framework/CI surfaces:

- `TIDECOIN_CONFIG`, `TIDECOIN_CONFIG_ALL`, `TIDECOIN_CMD`, `TIDECOIN_GENBUILD_NO_GIT`
- Functional framework reads Tidecoin vars only (no `BITCOIN_*` fallback)

### 4) Packaging/resources cutover

Completed installer/deploy namespace and icon identity cutover:

- NSIS placeholders renamed from `@BITCOIN_*@` to `@TIDECOIN_*@`
- Icon/resource files renamed and rewired:
  - `share/pixmaps/tidecoin.ico`
  - `src/qt/res/icons/tidecoin.icns`
  - `src/qt/res/icons/tidecoin.ico`
  - `src/qt/res/icons/tidecoin_testnet.ico`
- Windows RC renamed:
  - `src/qt/res/bitcoin-qt-res.rc` -> `src/qt/res/tidecoin-qt-res.rc`
- macOS deploy path uses `tidecoin.icns`

### 5) Functional framework naming cleanup

Completed active functional naming cleanup:

- `test/functional/interface_bitcoin_cli.py` -> `test/functional/interface_tidecoin_cli.py`
- `test/functional/tool_bitcoin_chainstate.py` -> `test/functional/tool_tidecoin_chainstate.py`
- `test/functional/test_runner.py` entries updated to new script names
- Dead previous-release plumbing removed in framework/test runner

### 6) contrib/guix/devtools/depends hard cutover

Completed high-impact identity rewrites:

- `contrib/devtools/bitcoin-tidy` renamed to `contrib/devtools/tidecoin-tidy`
  - Target/library/check names switched to `tidecoin-*`
  - CI tidy flow updated to new path/target/`.so` name
- `contrib/devtools/check-deps.sh` validates `libtidecoin_*.a`
- Guix scripts switched container bind path `/bitcoin` -> `/tidecoin`
- Guix manifest symbol rename:
  - `make-bitcoin-cross-toolchain` -> `make-tidecoin-cross-toolchain`
- Verify-commits env namespace:
  - `TIDECOIN_VERIFY_COMMITS_ALLOW_SHA1`
- `depends` docs wording updated to Tidecoin naming

### 7) Active naming lint quality

`test/lint/lint-tidecoin-naming.py` was tightened to avoid false positives from:

- URL hostnames like `en.bitcoin.it`
- source filename references like `src/tidecoind.cpp`

Current status: lint passes for active surfaces.

### 8) Build config/build-info header cutover

Completed internal header/template naming cutover:

- `cmake/bitcoin-build-config.h.in` -> `cmake/tidecoin-build-config.h.in`
- `src/CMakeLists.txt` now generates:
  - `tidecoin-build-config.h`
  - `tidecoin-build-info.h`
- `#include <bitcoin-build-config.h>` replaced with `#include <tidecoin-build-config.h>` in source tree.
- `#include <bitcoin-build-info.h>` replaced with `#include <tidecoin-build-info.h>`.
- `test/lint/test_runner/src/main.rs` updated to reference `tidecoin-build-config.h(.in)`.

### 9) Qt locale/asset namespace + translation docs cutover

Completed Qt locale and translation tooling identity migration:

- Locale files renamed:
  - `src/qt/locale/bitcoin_*.ts` -> `src/qt/locale/tidecoin_*.ts`
  - `src/qt/locale/bitcoin_en.xlf` -> `src/qt/locale/tidecoin_en.xlf`
- Locale manifests/tooling updated:
  - `src/qt/locale/ts_files.cmake`
  - `src/qt/tidecoin_locale.qrc` (`locale/tidecoin_*.qm`)
  - `share/qt/translate.cmake` (`tidecoinstrings.cpp`, `tidecoin_en.ts`, `tidecoin_en.xlf`)
- Qt asset filenames renamed:
  - `src/qt/res/src/bitcoin.svg` -> `src/qt/res/src/tidecoin.svg`
  - `src/qt/res/icons/bitcoin.png` -> `src/qt/res/icons/tidecoin.png`
- Qt runtime/icon usage aligned:
  - `src/qt/tidecoin.qrc` icon alias switched to `tidecoin`
  - `src/qt/intro.cpp` now uses `:/icons/tidecoin`
- Translation documentation updated:
  - `doc/translation_process.md`
  - `doc/translation_strings_policy.md`
  - `doc/release-process.md`
  - `src/qt/README.md`

### 10) CI/lint infrastructure identity cutover

Completed remaining CI/lint identity rewrites:

- `ci/lint_imagefile` now uses `WORKDIR /tidecoin`.
- `ci/lint/container-entrypoint.sh` now sets git safe directory to `/tidecoin`.
- `ci/lint/06_script.sh` now gates signed-commit verification on `CIRRUS_REPO_FULL_NAME=tidecoin/tidecoin`.
- Legacy env script filename cut over:
  - `ci/test/00_setup_env_native_nowallet_libbitcoinkernel.sh`
  - -> `ci/test/00_setup_env_native_nowallet_libtidecoinkernel.sh`
- GitHub Actions CI matrix updated to reference the renamed file.

### 11) verify-binaries hard cutover (removed)

Completed hard-cutover removal of Bitcoin-specific binary verification tooling:

- Removed `contrib/verify-binaries/` entirely.
- Removed stale `Verify-Binaries` section from `contrib/README.md`.

### 12) Debian metadata branding cleanup

Completed Debian metadata identity update:

- `contrib/debian/copyright` now uses:
  - `Upstream-Name: Tidecoin`
  - Tidecoin upstream contact and source URL
  - combined copyright attribution for
    - upstream Bitcoin Core-era contributors
    - Tidecoin-era contributors

### 13) Naming lint coverage expansion + final wording cleanup

Completed remaining identity guardrails and low-priority wording fix:

- `test/lint/lint-tidecoin-naming.py` now scans `src/` and `ci/` in addition to existing surfaces.
- Added explicit exclusion for `src/qt/locale/**` to avoid false positives from translation catalogs.
- `src/kernel/tidecoinkernel.cpp` comment updated from `libbitcoinkernel` to `libtidecoinkernel`.
- `ci/test/03_test_script.sh` default datadir guard updated:
  - macOS: `~/Library/Application Support/Tidecoin`
  - other: `~/.tidecoin`

## Validation Run (After This Cutover)

- `cmake --build build -j$(nproc) --target tidecoin tidecoind tidecoin-cli tidecoin-qt test_tidecoin bench_tidecoin` ✅
- `cmake --build build -j$(nproc) --target translate tidecoin-qt` ✅
- `cargo check --manifest-path test/lint/test_runner/Cargo.toml` ✅
- `python3 test/lint/lint-tidecoin-naming.py` ✅
- `build/bin/test_tidecoin-qt` ✅
- `ctest --test-dir build -R '^test_tidecoin-qt$' --output-on-failure` ✅
- `ctest --test-dir build` ✅ (155/155 passed)
- Functional smoke:
  - `python3 test/functional/test_runner.py --jobs 2 --tmpdirprefix=/tmp/tide_smoke feature_config_args.py mempool_accept.py` ✅
- Extended functional matrix:
  - `python3 test/functional/test_runner.py --jobs 4 --combinedlogslen 200 --tmpdirprefix=/tmp/tide_ext_matrix_20260303 ...` ✅ (28/28 passed)
- Guix reproducible packaging check (linux host):
  - `env FORCE_DIRTY_WORKTREE=1 HOSTS='x86_64-linux-gnu' JOBS=4 ./contrib/guix/guix-build` ✅
  - Output artifacts:
    - `guix-build-5e2fbd86310e/output/x86_64-linux-gnu/tidecoin-5e2fbd86310e-x86_64-linux-gnu.tar.gz`
    - `guix-build-5e2fbd86310e/output/x86_64-linux-gnu/tidecoin-5e2fbd86310e-x86_64-linux-gnu-debug.tar.gz`
    - `guix-build-5e2fbd86310e/output/x86_64-linux-gnu/SHA256SUMS.part`
  - Checksum verification:
    - `cd guix-build-5e2fbd86310e/output && sha256sum -c x86_64-linux-gnu/SHA256SUMS.part` ✅
- Local install staging sanity (current working tree):
  - `cmake --install build --prefix /tmp/tide_install_sanity` ✅
  - Installed binaries/manpages use Tidecoin naming under `/tmp/tide_install_sanity`.

Note:
- Guix `contrib/guix/libexec/build.sh` creates its source tarball via `git archive ... HEAD`.
- This means the Guix run validates the current `HEAD` commit snapshot (hash `5e2fbd86310e`), not uncommitted working-tree edits.

## Remaining Work (Explicitly Not Yet Completed)

### A) No identity blockers currently open

Identity-cutover tasks tracked in this document are completed.

## Next Cutover Batch (Recommended Order)

1. Keep `lint-tidecoin-naming.py` in CI enforcement mode over expanded `src/` + `ci/` coverage.
2. Continue routine release hardening (functional extended suite and release packaging checks).
