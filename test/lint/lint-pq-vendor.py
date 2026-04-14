#!/usr/bin/env python3
#
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate the vendored PQClean provenance manifest."""

from __future__ import annotations

from pathlib import Path
import argparse
import re
import sys

try:
    import tomllib  # type: ignore[attr-defined,import]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import,no-redef]


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "src/pq/VERSIONS.toml"
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
VALID_STATUS = {"pristine", "patched"}
VALID_IMPACT = {"none", "indirect", "direct"}


def _require_keys(obj: dict, keys: list[str], context: str, errors: list[str]) -> None:
    for key in keys:
        if key not in obj:
            errors.append(f"{context}: missing required key '{key}'")


def _check_rel_paths(paths: list[str], context: str, errors: list[str]) -> None:
    for path in paths:
        if not isinstance(path, str) or not path:
            errors.append(f"{context}: path entries must be non-empty strings")
            continue
        abs_path = ROOT / path
        if not abs_path.exists():
            errors.append(f"{context}: path does not exist: {path}")


def _check_hex40(value: str, context: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not HEX40_RE.fullmatch(value):
        errors.append(f"{context}: expected 40-char lowercase hex commit id")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=MANIFEST_PATH,
        help=f"Path to VERSIONS.toml (default: {MANIFEST_PATH})",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = args.manifest.resolve()
    errors: list[str] = []

    if not manifest_path.exists():
        print(f"Missing manifest: {manifest_path}")
        return 1

    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf8"))
    except Exception as e:  # pragma: no cover
        print(f"Failed to parse {manifest_path}: {e}")
        return 1

    _require_keys(manifest, ["schema_version", "upstream", "patches", "components"], "manifest", errors)

    schema_version = manifest.get("schema_version")
    if schema_version != 1:
        errors.append("manifest: schema_version must be 1")

    upstream = manifest.get("upstream", {})
    if not isinstance(upstream, dict):
        errors.append("manifest: upstream must be a table")
        upstream = {}
    else:
        _require_keys(upstream, ["pqclean_repo", "default_upstream_commit"], "upstream", errors)
        _check_hex40(upstream.get("default_upstream_commit", ""), "upstream.default_upstream_commit", errors)

    settings = manifest.get("settings", {})
    if settings and not isinstance(settings, dict):
        errors.append("manifest: settings must be a table if present")
    ignored = settings.get("ignored_upstream_files", []) if isinstance(settings, dict) else []
    if ignored and (not isinstance(ignored, list) or any(not isinstance(x, str) for x in ignored)):
        errors.append("settings.ignored_upstream_files must be a list of strings")

    patches = manifest.get("patches", [])
    if not isinstance(patches, list) or not patches:
        errors.append("manifest: patches must be a non-empty array of tables")
        patches = []

    patch_ids: set[str] = set()
    patch_files: set[str] = set()
    for i, patch in enumerate(patches):
        context = f"patches[{i}]"
        if not isinstance(patch, dict):
            errors.append(f"{context}: must be a table")
            continue

        _require_keys(
            patch,
            ["id", "patch_file", "summary", "reason", "owner", "consensus_impact", "files"],
            context,
            errors,
        )

        patch_id = patch.get("id")
        if not isinstance(patch_id, str) or not patch_id:
            errors.append(f"{context}.id: must be a non-empty string")
        elif patch_id in patch_ids:
            errors.append(f"{context}.id: duplicate id '{patch_id}'")
        else:
            patch_ids.add(patch_id)

        patch_file = patch.get("patch_file")
        if not isinstance(patch_file, str) or not patch_file:
            errors.append(f"{context}.patch_file: must be a non-empty string")
        else:
            patch_abs = ROOT / patch_file
            if patch_file in patch_files:
                errors.append(f"{context}.patch_file: duplicate patch file '{patch_file}'")
            patch_files.add(patch_file)
            if not patch_abs.exists():
                errors.append(f"{context}.patch_file does not exist: {patch_file}")
            elif patch_abs.stat().st_size == 0:
                errors.append(f"{context}.patch_file is empty: {patch_file}")

        impact = patch.get("consensus_impact")
        if impact not in VALID_IMPACT:
            errors.append(f"{context}.consensus_impact: must be one of {sorted(VALID_IMPACT)}")

        files = patch.get("files")
        if not isinstance(files, list) or not files:
            errors.append(f"{context}.files: must be a non-empty list")
        else:
            if any(not isinstance(path, str) for path in files):
                errors.append(f"{context}.files: entries must be strings")
            else:
                _check_rel_paths(files, f"{context}.files", errors)

    components = manifest.get("components", [])
    if not isinstance(components, list) or not components:
        errors.append("manifest: components must be a non-empty array of tables")
        components = []

    component_names: set[str] = set()
    for i, component in enumerate(components):
        context = f"components[{i}]"
        if not isinstance(component, dict):
            errors.append(f"{context}: must be a table")
            continue

        _require_keys(
            component,
            ["name", "status", "local_path", "upstream_path", "upstream_commit", "import_commit", "local_patch_set", "notes"],
            context,
            errors,
        )

        name = component.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"{context}.name: must be a non-empty string")
        elif name in component_names:
            errors.append(f"{context}.name: duplicate component name '{name}'")
        else:
            component_names.add(name)

        status = component.get("status")
        if status not in VALID_STATUS:
            errors.append(f"{context}.status: must be one of {sorted(VALID_STATUS)}")

        local_path = component.get("local_path")
        if not isinstance(local_path, str) or not local_path:
            errors.append(f"{context}.local_path: must be a non-empty string")
            local_abs = ROOT
        else:
            local_abs = ROOT / local_path
            if not local_abs.exists():
                errors.append(f"{context}.local_path does not exist: {local_path}")

        upstream_path = component.get("upstream_path")
        if not isinstance(upstream_path, str) or not upstream_path:
            errors.append(f"{context}.upstream_path: must be a non-empty string")

        _check_hex40(component.get("upstream_commit", ""), f"{context}.upstream_commit", errors)
        _check_hex40(component.get("import_commit", ""), f"{context}.import_commit", errors)

        include_files = component.get("include_files", [])
        if include_files:
            if not isinstance(include_files, list) or any(not isinstance(x, str) or not x for x in include_files):
                errors.append(f"{context}.include_files: must be a list of non-empty strings")
            elif local_abs.exists():
                for rel_file in include_files:
                    if not (local_abs / rel_file).is_file():
                        errors.append(f"{context}.include_files: missing local file '{local_path}/{rel_file}'")

        patch_set = component.get("local_patch_set")
        if not isinstance(patch_set, list) or any(not isinstance(x, str) or not x for x in patch_set):
            errors.append(f"{context}.local_patch_set: must be a list of non-empty strings")
            patch_set = []

        if status == "patched" and not patch_set:
            errors.append(f"{context}: patched component must define non-empty local_patch_set")
        if status == "pristine" and patch_set:
            errors.append(f"{context}: pristine component must not define local_patch_set")

        for patch_id in patch_set:
            if patch_id not in patch_ids:
                errors.append(f"{context}.local_patch_set: unknown patch id '{patch_id}'")

    native_adapters = manifest.get("native_adapters", [])
    if native_adapters:
        if not isinstance(native_adapters, list):
            errors.append("manifest.native_adapters must be a list")
        else:
            for i, adapter in enumerate(native_adapters):
                context = f"native_adapters[{i}]"
                if not isinstance(adapter, dict):
                    errors.append(f"{context}: must be a table")
                    continue
                _require_keys(adapter, ["name", "local_paths", "notes"], context, errors)
                local_paths = adapter.get("local_paths", [])
                if not isinstance(local_paths, list) or any(not isinstance(x, str) or not x for x in local_paths):
                    errors.append(f"{context}.local_paths must be a list of non-empty strings")
                    continue
                _check_rel_paths(local_paths, f"{context}.local_paths", errors)

    if errors:
        print("PQ vendor manifest validation failed:\n")
        for issue in errors:
            print(f"- {issue}")
        return 1

    print(f"PQ vendor manifest is valid: {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
