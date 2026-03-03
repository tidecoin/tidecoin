#!/usr/bin/env python3
#
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Prevent reintroduction of legacy Bitcoin naming in active Tidecoin surfaces."""

import os
import re
import subprocess
import sys


ACTIVE_PATHS = (
    "src",
    "ci",
    "contrib",
    "doc",
    "share",
    "test/README.md",
    "test/functional/README.md",
    "test/functional/test-shell.md",
    "test/functional/data/README.md",
)

EXCLUDE_PATHSPECS = (
    # Translation catalogs intentionally preserve upstream source text fragments.
    ":(exclude)src/qt/locale/**",
    ":(exclude)doc/release-notes/**",
)

FORBIDDEN_PATTERNS = (
    (re.compile(r"\bbitcoin\.conf\b"), "Use tidecoin.conf"),
    # Avoid flagging source file references like src/tidecoind.cpp.
    (re.compile(r"\bbitcoind\b(?!\.cpp\b)"), "Use tidecoind"),
    (re.compile(r"\bbitcoin-cli\b"), "Use tidecoin-cli"),
    (re.compile(r"\bbitcoin-qt\b"), "Use tidecoin-qt"),
    (re.compile(r"\bbitcoin-tx\b"), "Use tidecoin-tx"),
    (re.compile(r"\bbitcoin-wallet\b"), "Use tidecoin-wallet"),
    (re.compile(r"\bbitcoin-util\b"), "Use tidecoin-util"),
    (re.compile(r"\bbitcoin-chainstate\b"), "Use tidecoin-chainstate"),
    # Match datadir path segment ".bitcoin" but ignore hostnames like en.bitcoin.it.
    (re.compile(r"(?<![A-Za-z0-9])\.bitcoin\b"), "Use Tidecoin datadir naming"),
    (re.compile(r"/etc/bitcoin\b"), "Use /etc/tidecoin"),
    (re.compile(r"/var/lib/bitcoind\b"), "Use /var/lib/tidecoind"),
    (re.compile(r"org\.bitcoin(?:\.bitcoind)?\b"), "Use org.tidecoin.* identifiers"),
    (re.compile(r"/Applications/Bitcoin-Qt\b"), "Use /Applications/Tidecoin-Qt"),
    (re.compile(r"/Bitcoin/"), "Use Tidecoin-branded paths"),
)


def list_files() -> list[str]:
    cmd = ["git", "ls-files", "--", *ACTIVE_PATHS, *EXCLUDE_PATHSPECS]
    return subprocess.check_output(cmd, text=True, encoding="utf8").splitlines()


def main() -> None:
    violations: list[str] = []
    for path in list_files():
        if not os.path.exists(path):
            # Deleted/renamed files may still appear in ls-files in a dirty tree.
            continue
        with open(path, encoding="utf8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                for pattern, hint in FORBIDDEN_PATTERNS:
                    if pattern.search(line):
                        violations.append(f"{path}:{line_no}: {hint}: {line.rstrip()}")

    if violations:
        print("Legacy Bitcoin naming detected in active Tidecoin surfaces:\n")
        print("\n".join(violations))
        sys.exit(1)

    print("No legacy Bitcoin naming found in active Tidecoin surfaces.")


if __name__ == "__main__":
    main()
