#!/usr/bin/env bash
#
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

set -ex

if [ -n "$GITHUB_PULL_REQUEST" ]; then
  export COMMIT_RANGE="HEAD~..HEAD"
  if [ "$(git rev-list -1 HEAD)" != "$(git rev-list -1 --merges HEAD)" ]; then
    echo "Error: The top commit must be a merge commit, usually the remote 'pull/${PR_NUMBER}/merge' branch."
    false
  fi
fi

if [ -z "${COMMIT_RANGE:-}" ]; then
  MERGE_BASE="$(git rev-list --max-count=1 --merges HEAD || true)"
  if [ -n "$MERGE_BASE" ]; then
    COMMIT_RANGE="${MERGE_BASE}..HEAD"
  else
    COMMIT_RANGE="HEAD~1..HEAD"
  fi
fi

PQ_VENDOR_DEEP_PATHS_REGEX='^(src/pq/|contrib/devtools/check_pq_vendor.py$|test/lint/lint-pq-vendor.py$|test/lint/test_runner/src/main.rs$|doc/developer-notes.md$|test/lint/README.md$)'
CHANGED_PATHS="$(git diff --name-only "${COMMIT_RANGE}" -- || true)"
if printf '%s\n' "$CHANGED_PATHS" | grep -Eq "$PQ_VENDOR_DEEP_PATHS_REGEX"; then
  export RUN_PQ_VENDOR_DEEP=1
  echo "Enabling pq_vendor_deep lint (RUN_PQ_VENDOR_DEEP=1) for range ${COMMIT_RANGE}"
else
  echo "Skipping pq_vendor_deep auto-enable; no relevant path changes in ${COMMIT_RANGE}"
fi

RUST_BACKTRACE=1 cargo run --manifest-path "./test/lint/test_runner/Cargo.toml"

if [ "$GITHUB_REPOSITORY" = "tidecoin/tidecoin" ] && [ "$GITHUB_PULL_REQUEST" = "" ] ; then
    # Sanity check only the last few commits to get notified of missing sigs,
    # missing keys, or expired keys. Usually there is only one new merge commit
    # per push on the master branch and a few commits on release branches, so
    # sanity checking only a few (10) commits seems sufficient and cheap.
    TIDECOIN_GUIX_SIGS_REPO_URL="${TIDECOIN_GUIX_SIGS_REPO_URL:-https://github.com/tidecoin/guix.sigs.git}"
    TIDECOIN_GUIX_SIGS_DIR="$(mktemp -d)"
    git clone --depth=1 "$TIDECOIN_GUIX_SIGS_REPO_URL" "$TIDECOIN_GUIX_SIGS_DIR"
    cp "$TIDECOIN_GUIX_SIGS_DIR/trusted-commit-keys/ssh-allowed-signers" ./contrib/verify-commits/trusted-ssh-allowed-signers
    if [ -f "$TIDECOIN_GUIX_SIGS_DIR/trusted-commit-keys/pgp-fingerprints" ]; then
        cp "$TIDECOIN_GUIX_SIGS_DIR/trusted-commit-keys/pgp-fingerprints" ./contrib/verify-commits/trusted-keys
    else
        : > ./contrib/verify-commits/trusted-keys
    fi
    git log HEAD~10 -1 --format='%H' > ./contrib/verify-commits/trusted-sha512-root-commit
    git log HEAD~10 -1 --format='%H' > ./contrib/verify-commits/trusted-git-root
    mapfile -t KEYS < <(grep -Ev '^[[:space:]]*(#.*)?$' contrib/verify-commits/trusted-keys)
    git config user.email "ci@ci.ci"
    git config user.name "ci"
    if [ "${#KEYS[@]}" -gt 0 ]; then
        ${CI_RETRY_EXE} gpg --keyserver hkps://keys.openpgp.org --recv-keys "${KEYS[@]}"
    fi
    ./contrib/verify-commits/verify-commits.py --disable-tree-check;
fi
