This folder contains lint scripts and the Rust-based lint test runner used by
CI.

Running locally
===============

To run linters locally with the same versions as CI, use the lint container:

```sh
LINT_IMAGE=bitcoin-linter # current CI image name
DOCKER_BUILDKIT=1 docker build -t "$LINT_IMAGE" --file "./ci/lint_imagefile" .
docker run --rm -v "$(pwd)":/bitcoin -it "$LINT_IMAGE"
```

Notes:
- The container mount path is `/bitcoin` because current CI scripts and
  entrypoint expect that path.
- Rebuilding the image regularly is recommended to pick up dependency updates in
  `ci/lint/01_install.sh`.

test runner
===========

The main lint orchestration is `test/lint/test_runner` (Rust). Install Rust
with your package manager or [rustup](https://www.rust-lang.org/tools/install),
then run:

```sh
RUST_BACKTRACE=1 cargo run --manifest-path "./test/lint/test_runner/Cargo.toml"
```

Run selected checks:

```sh
RUST_BACKTRACE=1 cargo run --manifest-path "./test/lint/test_runner/Cargo.toml" -- --lint=doc --lint=trailing_whitespace
```

List available checks:

```sh
cargo run --manifest-path "./test/lint/test_runner/Cargo.toml" -- --help
```

Useful environment variables:
- `COMMIT_RANGE=<from>..<to>`: limit checks that inspect commit diffs.
- `RUN_PQ_VENDOR_DEEP=1`: enable deep PQ vendor diff check (`pq_vendor_deep`).

Dependencies
============

| Lint test | Dependency |
|-----------|:----------:|
| [`lint-python.py`](/test/lint/lint-python.py) | [lief](https://github.com/lief-project/LIEF) |
| [`lint-python.py`](/test/lint/lint-python.py) | [mypy](https://github.com/python/mypy) |
| [`lint-python.py`](/test/lint/lint-python.py) | [pyzmq](https://github.com/zeromq/pyzmq) |
| [`lint-python-dead-code.py`](/test/lint/lint-python-dead-code.py) | [vulture](https://github.com/jendrikseipp/vulture) |
| [`lint-shell.py`](/test/lint/lint-shell.py) | [ShellCheck](https://github.com/koalaman/shellcheck) |
| [`lint-spelling.py`](/test/lint/lint-spelling.py) | [codespell](https://github.com/codespell-project/codespell) |
| `py_lint` (test runner) | [ruff](https://github.com/astral-sh/ruff) |
| markdown link check (`markdown`) | [mlc](https://github.com/becheran/mlc) |

Pinned versions and install steps used by CI are in
[ci/lint/01_install.sh](../../ci/lint/01_install.sh).

Running individual scripts
==========================

Individual checks can be run directly, for example:

```sh
test/lint/lint-files.py
```

Tidecoin naming policy
======================

Active user/operator surfaces must use Tidecoin naming:
- `tidecoin.conf` (not `bitcoin.conf`)
- `tidecoind` (not `bitcoind`)
- `tidecoin-*` executables for CLI/tooling references
- Tidecoin datadir and service identifiers in docs/templates

This is enforced by
[`lint-tidecoin-naming.py`](/test/lint/lint-tidecoin-naming.py). Historical
release notes under `doc/release-notes/**` are intentionally excluded.

PQ vendor provenance policy
===========================

Vendored post-quantum components under `src/pq/` are tracked by
`src/pq/VERSIONS.toml`.

- `test/lint/lint-pq-vendor.py` validates manifest schema and required metadata.
- `contrib/devtools/check_pq_vendor.py` performs deep diffs against pinned
  upstream PQClean commits and verifies declared divergence.

Run locally:

```sh
test/lint/lint-pq-vendor.py
python3 contrib/devtools/check_pq_vendor.py
```

Deep vendor check in test runner (`pq_vendor_deep`):

```sh
RUN_PQ_VENDOR_DEEP=1 cargo run --manifest-path "./test/lint/test_runner/Cargo.toml" -- --lint=pq_vendor_deep
```

In CI, `RUN_PQ_VENDOR_DEEP` is auto-enabled when relevant PQ vendor paths
change in `COMMIT_RANGE`.

PQ script coverage scorecard
============================

`test/lint/lint-pq-script-coverage.py` enforces Tidecoin's PQ script coverage
lock-in:

- required script category/polarity presence in `src/test/data/script_tests_pq.json`
- required script-assets flag/profile coverage in `src/test/data/script_assets_test.json`
- required script cell IDs/family polarities from `test/lint/pq_script_required_cells.json`
- required script-assets cell IDs from `test/lint/pq_script_assets_required_cells.json`
- hard-cutover invariants (legacy fixture/reference and legacy-term bans in script/tx tests)

Run locally:

```sh
python3 test/lint/lint-pq-script-coverage.py
```

check-doc.py
============

Check for missing documentation of command line options.

commit-script-check.sh
======================

Verification of [scripted diffs](/doc/developer-notes.md#scripted-diffs).
Scripted diffs are only assumed to run on the latest Ubuntu LTS release.
On other systems, GNU tool variants may be required.

git-subtree-check.sh
====================

Run this script from the repository root to verify that a subtree matches the
commit it claims to have been updated to.

```text
Usage: test/lint/git-subtree-check.sh [-r] DIR [COMMIT]
       test/lint/git-subtree-check.sh -?
```

- `DIR` is the subtree prefix within the repository.
- `COMMIT` is the commit to check (defaults to `HEAD` if omitted).
- `-r` checks that the imported base matches the upstream subtree commit.
- Intentional local changes must exactly match the full diff recorded in
  `test/lint/subtree-patches/<DIR>.patch`. File contents and modes are checked;
  unrecorded changes fail. The upstream base is still checked with `-r`.

For a full `-r` check, fetch the corresponding upstream subtree remotes:
- `src/crc32c`: https://github.com/bitcoin-core/crc32c-subtree.git (branch `bitcoin-fork`)
- `src/crypto/ctaes`: https://github.com/bitcoin-core/ctaes.git (branch `master`)
- `src/ipc/libmultiprocess`: https://github.com/bitcoin-core/libmultiprocess (branch `master`)
- `src/leveldb`: https://github.com/bitcoin-core/leveldb-subtree.git (branch `bitcoin-fork`)
- `src/minisketch`: https://github.com/bitcoin-core/minisketch.git (branch `master`)

Keep this list in sync with `fn get_subtrees()` in
`test/lint/test_runner/src/main.rs`.

Example remote:

```sh
git remote add --fetch minisketch https://github.com/bitcoin-core/minisketch.git
```

lint_ignore_dirs.py
===================

Contains a shared list of directories to ignore for lint checks.
