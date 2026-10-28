#!/usr/bin/env python3
#
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate metadata for Tidecoin-maintained PQ implementations."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "contrib/devtools"))


def main() -> int:
    from check_pq_vendor import DEFAULT_MANIFEST, read_manifest

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        read_manifest(args.manifest)
    except (RuntimeError, OSError, ValueError) as error:
        print(f"PQ provenance manifest validation failed: {error}")
        return 1
    print(f"PQ provenance manifest is valid: {args.manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
