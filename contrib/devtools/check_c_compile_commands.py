#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Check that configured compiler checks reach Tidecoin's C implementations."""

import argparse
import json
from pathlib import Path
import shlex
import sys


ROOT = Path(__file__).resolve().parents[2]
REQUIRED_SOURCES = {
    "src/pq/fips202.c",
    "src/pq/falcon-512/pqclean.c",
    "src/pq/falcon-1024/pqclean.c",
    "src/pq/ml-dsa-44/sign.c",
    "src/pq/ml-dsa-65/sign.c",
    "src/pq/ml-dsa-87/sign.c",
    "src/pq/ml-kem-512/kem.c",
    "src/crypto/yespower/sha256.c",
    "src/crypto/yespower/yespower-opt.c",
}


def check_integer_exceptions(path: Path) -> list[str]:
    """Keep optional arithmetic exceptions from disabling other instrumentation."""
    allowed = {"unsigned-integer-overflow", "unsigned-shift-base"}
    section = None
    errors = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section not in allowed:
                errors.append(f"{path}:{number}: unsupported exception section {section}")
        elif section not in allowed or not line.startswith(("src:", "fun:")):
            errors.append(f"{path}:{number}: unscoped or unsupported exception")
    return errors


def check(build_dir: Path) -> list[str]:
    cache = {}
    for line in (build_dir / "CMakeCache.txt").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(("#", "//")) and "=" in line:
            name, value = line.split("=", 1)
            cache[name.split(":", 1)[0]] = value
    requested = {"fuzzer-no-link" if item == "fuzzer" else item
                 for item in cache.get("SANITIZERS", "").split(",") if item}
    werror = cache.get("WERROR", "OFF").upper() in {"1", "ON", "YES", "TRUE", "Y"}
    seen = set()
    errors = check_integer_exceptions(ROOT / "test/sanitizer_suppressions/pq_integer")
    for entry in json.loads((build_dir / "compile_commands.json").read_text(encoding="utf-8")):
        source = (Path(entry["directory"]) / entry["file"]).resolve()
        if not source.is_relative_to(ROOT):
            continue
        relative = source.relative_to(ROOT).as_posix()
        if source.suffix != ".c" or not relative.startswith(("src/pq/", "src/crypto/yespower/")):
            continue
        seen.add(relative)
        args = entry.get("arguments") or shlex.split(entry["command"])
        enabled = set()
        ndebug = False
        warnings_as_errors = False
        options = iter(args)
        for arg in options:
            if arg in {"-D", "-U", "/D", "/U"}:
                arg += next(options, "")
            if arg.startswith("-fsanitize="):
                enabled.update(arg.split("=", 1)[1].split(","))
            elif arg.startswith("-fno-sanitize="):
                disabled = set(arg.split("=", 1)[1].split(","))
                if "all" in disabled:
                    enabled.clear()
                else:
                    enabled.difference_update(disabled)
            elif arg in {"-UNDEBUG", "/UNDEBUG"}:
                ndebug = False
            elif arg.split("=", 1)[0] in {"-DNDEBUG", "/DNDEBUG"}:
                ndebug = True
            elif arg in {"-Werror", "/WX"}:
                warnings_as_errors = True
            elif arg in {"-Wno-error", "/WX-"}:
                warnings_as_errors = False
        if ndebug:
            errors.append(f"{relative}: assertions disabled by NDEBUG")
        if requested - enabled:
            errors.append(f"{relative}: missing sanitizers {sorted(requested - enabled)}")
        if werror and not warnings_as_errors:
            errors.append(f"{relative}: WERROR does not reach C")
        for option, probe in (("-Wall", "C_SUPPORTS__WALL"),
                              ("-Wextra", "C_SUPPORTS__WEXTRA"),
                              ("/W3", "C_SUPPORTS__W3"),
                              ("-fstack-protector-all", "C_SUPPORTS__FSTACK_PROTECTOR_ALL")):
            if cache.get(probe) == "1" and option not in args:
                errors.append(f"{relative}: missing supported option {option}")
    for missing in sorted(REQUIRED_SOURCES - seen):
        errors.append(f"Missing C compile command: {missing}")
    if not errors:
        print(f"Checked {len(seen)} PQ/Yespower C sources: assertions, warnings and requested instrumentation are enabled.")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path, help="CMake build with CMAKE_EXPORT_COMPILE_COMMANDS=ON")
    args = parser.parse_args()
    try:
        errors = check(args.build_dir)
    except (OSError, ValueError, KeyError) as error:
        errors = [str(error)]
    for error in errors:
        print(error, file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
