#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check PQ script fixture/corpus scorecard and hard-cutover invariants."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_FIXTURE = ROOT / "src/test/data/script_tests_pq.json"
SCRIPT_ASSETS = ROOT / "src/test/data/script_assets_test.json"
SCRIPT_REQUIRED_CELLS_MANIFEST = ROOT / "test/lint/pq_script_required_cells.json"
SCRIPT_ASSETS_REQUIRED_CELLS_MANIFEST = ROOT / "test/lint/pq_script_assets_required_cells.json"

FLAG_ORDER = (
    "P2SH",
    "NULLDUMMY",
    "CHECKLOCKTIMEVERIFY",
    "CHECKSEQUENCEVERIFY",
    "WITNESS",
    "PQ_STRICT",
)

REQUIRED_SCRIPT_CATEGORIES = (
    ("P2PK/P2PKH", r"^PQ P2PKH?\b|^PQ P2PK\b", True, True),
    ("P2SH semantics", r"^PQ P2SH", True, True),
    ("Multisig", r"1-of-2|2-of-3|MSIG-", True, True),
    ("Sighash modes", r"sighash", True, True),
    ("NULLDUMMY", r"NULLDUMMY", True, True),
    ("SIGPUSHONLY", r"SIGPUSHONLY|non-push scriptSig", True, True),
    ("CLEANSTACK", r"CLEANSTACK", True, True),
    ("MINIMALDATA", r"MINIMALDATA", True, True),
    ("MINIMALIF", r"MINIMALIF", True, True),
    ("NULLFAIL", r"NULLFAIL", True, True),
    ("CLTV", r"\bCLTV\b", True, True),
    ("CSV", r"\bCSV\b", True, True),
    ("Interpreter surface", r"^PQ interpreter ", True, True),
    ("CONST_SCRIPTCODE", r"CONST_SCRIPTCODE", True, True),
    ("OP_SHA512", r"OP_SHA512", True, True),
    ("witness v1_512", r"v1_512", True, True),
    ("PQ_STRICT", r"^PQ strict|^PQ non-strict", True, True),
)

SCRIPT_CELL_ID_RE = re.compile(r"\b(?:INT|MSIG|TIME|WIT)-[A-Z0-9-]+\b")

LEGACY_FORBIDDEN_PATTERNS = (
    r"\bBIP66\b",
    r"\bDERSIG\b",
    r"\bLOW_S\b",
    r"\bSTRICTENC\b",
    r"\bECDSA\b",
    r"\bsecp(?:256k1)?\b",
)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def read_json(path: Path, errors: list[str], label: str) -> Any | None:
    try:
        return json.loads(read_text(path))
    except FileNotFoundError:
        fail(errors, f"missing {label}: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(errors, f"invalid JSON in {label} ({path.relative_to(ROOT)}): {exc}")
    except OSError as exc:
        fail(errors, f"unable to read {label} ({path.relative_to(ROOT)}): {exc}")
    return None


def check_legacy_invariants(errors: list[str]) -> None:
    if (ROOT / "src/test/data/script_tests.json").exists():
        fail(errors, "legacy fixture present: src/test/data/script_tests.json")

    test_tree_files = [p for p in (ROOT / "src/test").rglob("*") if p.is_file() and p.suffix in {".cpp", ".h", ".json", ".cmake", ".txt"}]
    bad_refs = []
    pattern = re.compile(r"script_tests\.json\b")
    for path in test_tree_files:
        if pattern.search(read_text(path)):
            bad_refs.append(path.relative_to(ROOT).as_posix())
    if bad_refs:
        fail(errors, "legacy script_tests.json references found under src/test: " + ", ".join(sorted(bad_refs)))

    script_tests_cpp = read_text(ROOT / "src/test/script_tests.cpp")
    transaction_tests_cpp = read_text(ROOT / "src/test/transaction_tests.cpp")
    cmake_tests = read_text(ROOT / "src/test/CMakeLists.txt")
    script_assets_tests_cpp = read_text(ROOT / "src/test/script_assets_tests.cpp")

    if "#include <test/data/script_tests_pq.json.h>" not in script_tests_cpp:
        fail(errors, "missing include: <test/data/script_tests_pq.json.h> in src/test/script_tests.cpp")

    if "#include <test/data/tx_valid_pq.json.h>" not in transaction_tests_cpp:
        fail(errors, "missing include: <test/data/tx_valid_pq.json.h> in src/test/transaction_tests.cpp")
    if "#include <test/data/tx_invalid_pq.json.h>" not in transaction_tests_cpp:
        fail(errors, "missing include: <test/data/tx_invalid_pq.json.h> in src/test/transaction_tests.cpp")

    if "data/script_tests.json" in cmake_tests:
        fail(errors, "legacy data/script_tests.json still listed in src/test/CMakeLists.txt")

    for forbidden in LEGACY_FORBIDDEN_PATTERNS:
        matcher = re.compile(forbidden)
        if matcher.search(script_tests_cpp):
            fail(errors, f"legacy term found in src/test/script_tests.cpp: /{forbidden}/")
        if matcher.search(transaction_tests_cpp):
            fail(errors, f"legacy term found in src/test/transaction_tests.cpp: /{forbidden}/")

    legacy_size_gate = "CKey::SIZE != 32"
    if legacy_size_gate in script_tests_cpp or legacy_size_gate in transaction_tests_cpp:
        fail(errors, "legacy CKey::SIZE != 32 gate still present in script/transaction tests")

    if "skipping script_assets_test" in cmake_tests or "skipping script_assets_test" in script_assets_tests_cpp:
        fail(errors, "script_assets_test skip path detected in required test path")


def parse_script_fixture_rows(errors: list[str]) -> list[dict[str, str]]:
    data = read_json(SCRIPT_FIXTURE, errors, "script fixture")
    if not isinstance(data, list):
        if data is not None:
            fail(errors, f"{SCRIPT_FIXTURE.relative_to(ROOT)} must be a JSON array")
        return []

    parsed = []
    for idx, row in enumerate(data):
        if not isinstance(row, list):
            continue
        pos = 1 if row and isinstance(row[0], list) else 0
        if len(row) < pos + 4:
            continue
        expected = row[pos + 3]
        comment = row[pos + 4] if len(row) > pos + 4 and isinstance(row[pos + 4], str) else ""
        parsed.append(
            {
                "index": str(idx),
                "expected": str(expected),
                "comment": comment,
            }
        )
    return parsed


def check_script_fixture_scorecard(errors: list[str], rows: list[dict[str, str]]) -> tuple[int, int]:
    if not rows:
        fail(errors, "script fixture scorecard has no parsed rows")
        return (0, 0)

    for category_name, regex, require_ok, require_fail in REQUIRED_SCRIPT_CATEGORIES:
        matcher = re.compile(regex)
        matched = [row for row in rows if matcher.search(row["comment"])]
        if not matched:
            fail(errors, f"script category missing: {category_name}")
            continue

        ok_count = sum(1 for row in matched if row["expected"] == "OK")
        fail_count = len(matched) - ok_count
        if require_ok and ok_count == 0:
            fail(errors, f"script category lacks positive coverage: {category_name}")
        if require_fail and fail_count == 0:
            fail(errors, f"script category lacks negative coverage: {category_name}")

    return (len(rows), len(REQUIRED_SCRIPT_CATEGORIES))


def extract_cell_ids(comment: str) -> set[str]:
    return set(SCRIPT_CELL_ID_RE.findall(comment))


def check_required_script_cells(errors: list[str], rows: list[dict[str, str]]) -> tuple[int, int]:
    manifest = read_json(SCRIPT_REQUIRED_CELLS_MANIFEST, errors, "script required-cells manifest")
    if not isinstance(manifest, dict):
        if manifest is not None:
            fail(errors, f"{SCRIPT_REQUIRED_CELLS_MANIFEST.relative_to(ROOT)} must be a JSON object")
        return (0, 0)

    required_cells = manifest.get("required_cells", [])
    required_families = manifest.get("required_families", [])
    if not isinstance(required_cells, list):
        fail(errors, "script required-cells manifest key 'required_cells' must be an array")
        required_cells = []
    if not isinstance(required_families, list):
        fail(errors, "script required-cells manifest key 'required_families' must be an array")
        required_families = []

    cell_polarity: dict[str, dict[str, int]] = {}
    for row in rows:
        for cell_id in extract_cell_ids(row["comment"]):
            if cell_id not in cell_polarity:
                cell_polarity[cell_id] = {"ok": 0, "fail": 0}
            if row["expected"] == "OK":
                cell_polarity[cell_id]["ok"] += 1
            else:
                cell_polarity[cell_id]["fail"] += 1

    for entry in required_cells:
        if not isinstance(entry, dict):
            fail(errors, "script required-cells entry must be an object")
            continue
        cell_id = str(entry.get("id", "")).strip()
        polarity = str(entry.get("polarity", "")).strip().lower()
        if not cell_id:
            fail(errors, "script required-cells entry missing non-empty 'id'")
            continue
        if polarity not in {"ok", "fail", "both", "any"}:
            fail(errors, f"script required-cells entry '{cell_id}' has invalid polarity '{polarity}'")
            continue
        if cell_id not in cell_polarity:
            fail(errors, f"missing required script cell ID: {cell_id}")
            continue
        ok_count = cell_polarity[cell_id]["ok"]
        fail_count = cell_polarity[cell_id]["fail"]
        if polarity == "ok" and ok_count == 0:
            fail(errors, f"required script cell lacks OK polarity: {cell_id}")
        if polarity == "fail" and fail_count == 0:
            fail(errors, f"required script cell lacks fail polarity: {cell_id}")
        if polarity == "both" and (ok_count == 0 or fail_count == 0):
            fail(errors, f"required script cell lacks both polarities: {cell_id}")

    for family in required_families:
        if not isinstance(family, dict):
            fail(errors, "script required-families entry must be an object")
            continue
        name = str(family.get("name", "")).strip() or "<unnamed>"
        prefix = str(family.get("prefix", "")).strip()
        require_ok = bool(family.get("require_ok", False))
        require_fail = bool(family.get("require_fail", False))
        if not prefix:
            fail(errors, f"script required-families entry '{name}' missing non-empty 'prefix'")
            continue

        matched_ids = [cell_id for cell_id in cell_polarity if cell_id.startswith(prefix)]
        if not matched_ids:
            fail(errors, f"required script family has no matched cells: {name} (prefix={prefix})")
            continue

        ok_count = sum(cell_polarity[cell_id]["ok"] for cell_id in matched_ids)
        fail_count = sum(cell_polarity[cell_id]["fail"] for cell_id in matched_ids)
        if require_ok and ok_count == 0:
            fail(errors, f"required script family lacks OK polarity: {name}")
        if require_fail and fail_count == 0:
            fail(errors, f"required script family lacks fail polarity: {name}")

    return (len(required_cells), len(required_families))


def check_script_assets_scorecard(errors: list[str]) -> tuple[int, int, int]:
    data = read_json(SCRIPT_ASSETS, errors, "script-assets corpus")
    if not isinstance(data, list):
        if data is not None:
            fail(errors, "script-assets corpus must be a JSON array")
        return (0, 0, 0)

    manifest = read_json(SCRIPT_ASSETS_REQUIRED_CELLS_MANIFEST, errors, "script-assets required-cells manifest")
    if not isinstance(manifest, dict):
        if manifest is not None:
            fail(errors, f"{SCRIPT_ASSETS_REQUIRED_CELLS_MANIFEST.relative_to(ROOT)} must be a JSON object")
        manifest = {}

    required_flag_sets_raw = manifest.get("required_flag_sets", [])
    required_asset_cells = manifest.get("required_cells", [])
    if not isinstance(required_flag_sets_raw, list):
        fail(errors, "script-assets required-cells manifest key 'required_flag_sets' must be an array")
        required_flag_sets_raw = []
    if not isinstance(required_asset_cells, list):
        fail(errors, "script-assets required-cells manifest key 'required_cells' must be an array")
        required_asset_cells = []
    required_flag_sets = {str(flags) for flags in required_flag_sets_raw if isinstance(flags, str)}

    flag_order_index = {name: idx for idx, name in enumerate(FLAG_ORDER)}
    present_flag_sets = set()
    comments: list[str] = []

    for idx, entry in enumerate(data):
        if not isinstance(entry, dict):
            fail(errors, f"script-assets entry #{idx} must be an object")
            continue

        for required_key in ("tx", "prevouts", "index", "flags", "comment", "success", "failure"):
            if required_key not in entry:
                fail(errors, f"script-assets entry #{idx} missing key: {required_key}")

        flags = str(entry.get("flags", ""))
        present_flag_sets.add(flags)
        split_flags = [flag for flag in flags.split(",") if flag]
        unknown_flags = [flag for flag in split_flags if flag not in flag_order_index]
        if unknown_flags:
            fail(errors, f"script-assets entry #{idx} has unknown flag(s): {unknown_flags}")
            continue
        canonical = sorted(split_flags, key=lambda flag: flag_order_index[flag])
        if split_flags != canonical:
            fail(errors, f"script-assets entry #{idx} has non-canonical flag order: {flags}")

        comments.append(str(entry.get("comment", "")))

    missing_flag_sets = sorted(required_flag_sets - present_flag_sets)
    if missing_flag_sets:
        fail(errors, "missing required script-assets flag set(s): " + ", ".join(missing_flag_sets))

    for entry in required_asset_cells:
        if not isinstance(entry, dict):
            fail(errors, "script-assets required-cells entry must be an object")
            continue
        cell_id = str(entry.get("id", "")).strip() or "<unnamed>"
        comment_prefix = str(entry.get("comment_prefix", "")).strip()
        min_count = entry.get("min_count", 1)
        if not comment_prefix:
            fail(errors, f"script-assets required-cells entry '{cell_id}' missing non-empty 'comment_prefix'")
            continue
        if not isinstance(min_count, int) or min_count < 1:
            fail(errors, f"script-assets required-cells entry '{cell_id}' has invalid min_count")
            continue
        present_count = sum(1 for comment in comments if comment.startswith(comment_prefix))
        if present_count < min_count:
            fail(errors, f"missing required script-assets cell '{cell_id}' (prefix='{comment_prefix}', need>={min_count}, found={present_count})")

    return (len(data), len(present_flag_sets), len(required_asset_cells))


def main() -> int:
    errors: list[str] = []

    check_legacy_invariants(errors)
    rows = parse_script_fixture_rows(errors)
    script_rows, script_categories = check_script_fixture_scorecard(errors, rows)
    required_script_cells, required_script_families = check_required_script_cells(errors, rows)
    assets_entries, assets_flag_sets, required_asset_cells = check_script_assets_scorecard(errors)

    if errors:
        print("PQ script coverage scorecard failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("PQ script coverage scorecard OK")
    print(f"- script fixture rows: {script_rows}")
    print(f"- required script categories checked: {script_categories}")
    print(f"- required script cells checked: {required_script_cells}")
    print(f"- required script families checked: {required_script_families}")
    print(f"- script-assets entries: {assets_entries}")
    print(f"- script-assets distinct flag sets: {assets_flag_sets}")
    print(f"- required script-assets cells checked: {required_asset_cells}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
