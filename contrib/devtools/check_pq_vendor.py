#!/usr/bin/env python3
#
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Verify vendored PQ components against pinned PQClean upstream commits."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import argparse
import filecmp
import subprocess
import sys

try:
    import tomllib  # type: ignore[attr-defined,import]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import,no-redef]


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "src/pq/VERSIONS.toml"
DEFAULT_CACHE_DIR = Path("/tmp/pqclean-vendor-cache")


def run(cmd: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        check=False,
        text=True,
        encoding="utf8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.strip()}"
        )
    return result.stdout.strip()


def run_manifest_lint(manifest_path: Path) -> None:
    lint_script = ROOT / "test/lint/lint-pq-vendor.py"
    result = subprocess.run(
        ["python3", str(lint_script), "--manifest", str(manifest_path)],
        cwd=ROOT,
        check=False,
        text=True,
        encoding="utf8",
    )
    if result.returncode != 0:
        raise RuntimeError("Manifest lint failed; fix metadata before deep vendor checks.")


def load_manifest(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf8"))


def ensure_repo(cache_dir: Path, repo_url: str) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = cache_dir / "PQClean"
    if not repo_dir.exists():
        run(["git", "clone", repo_url, str(repo_dir)])
    return repo_dir


def ensure_commit(repo_dir: Path, commit: str, do_fetch: bool) -> None:
    try:
        run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=repo_dir)
        return
    except RuntimeError:
        if not do_fetch:
            raise RuntimeError(
                f"Commit {commit} not found in cached PQClean repository. "
                "Re-run without --no-fetch or prefetch this commit."
            )

    run(["git", "fetch", "--tags", "--prune", "origin"], cwd=repo_dir)
    run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=repo_dir)


def export_commit_tree(repo_dir: Path, commit: str, export_dir: Path) -> Path:
    commit_dir = export_dir / commit
    if commit_dir.exists():
        return commit_dir

    commit_dir.mkdir(parents=True, exist_ok=True)
    command = (
        f"git -C {shlex_quote(str(repo_dir))} archive --format=tar {shlex_quote(commit)} | "
        f"tar -x -C {shlex_quote(str(commit_dir))}"
    )
    run(["/bin/bash", "-lc", command])
    return commit_dir


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def should_ignore(path: Path, ignored_basenames: set[str]) -> bool:
    return path.name in ignored_basenames


def collect_files(base: Path, ignored_basenames: set[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if should_ignore(path, ignored_basenames):
            continue
        rel = path.relative_to(base).as_posix()
        result[rel] = path
    return result


def compare_paths(local_base: Path, upstream_base: Path, include_files: list[str], ignored_basenames: set[str]) -> set[str]:
    diffs: set[str] = set()

    if include_files:
        for rel in include_files:
            local_file = local_base / rel
            upstream_file = upstream_base / rel
            display = (local_base / rel).relative_to(ROOT).as_posix()
            if not local_file.exists() or not upstream_file.exists():
                diffs.add(display)
                continue
            if should_ignore(local_file, ignored_basenames):
                continue
            if not filecmp.cmp(local_file, upstream_file, shallow=False):
                diffs.add(display)
        return diffs

    if local_base.is_file() and upstream_base.is_file():
        display = local_base.relative_to(ROOT).as_posix()
        if not filecmp.cmp(local_base, upstream_base, shallow=False):
            diffs.add(display)
        return diffs

    if not local_base.is_dir() or not upstream_base.is_dir():
        diffs.add(local_base.relative_to(ROOT).as_posix())
        return diffs

    local_files = collect_files(local_base, ignored_basenames)
    upstream_files = collect_files(upstream_base, ignored_basenames)

    local_rel = set(local_files)
    upstream_rel = set(upstream_files)

    for rel in sorted(local_rel - upstream_rel):
        diffs.add((local_base / rel).relative_to(ROOT).as_posix())

    for rel in sorted(upstream_rel - local_rel):
        diffs.add((local_base / rel).relative_to(ROOT).as_posix())

    for rel in sorted(local_rel & upstream_rel):
        if not filecmp.cmp(local_files[rel], upstream_files[rel], shallow=False):
            diffs.add((local_base / rel).relative_to(ROOT).as_posix())

    return diffs


def validate_components(manifest: dict, selected: set[str] | None, do_fetch: bool, cache_dir: Path) -> int:
    patches = {patch["id"]: patch for patch in manifest.get("patches", [])}
    components = manifest.get("components", [])
    ignored = set(manifest.get("settings", {}).get("ignored_upstream_files", []))

    upstream_cfg = manifest.get("upstream", {})
    repo_url = upstream_cfg.get("pqclean_repo")
    if not isinstance(repo_url, str) or not repo_url:
        raise RuntimeError("Manifest upstream.pqclean_repo is missing or invalid")

    if selected:
        components = [c for c in components if c.get("name") in selected]
        missing = selected - {c.get("name") for c in components}
        if missing:
            raise RuntimeError(f"Requested components not found in manifest: {', '.join(sorted(missing))}")

    repo_dir = ensure_repo(cache_dir, repo_url)

    commits = sorted({c["upstream_commit"] for c in components})
    for commit in commits:
        ensure_commit(repo_dir, commit, do_fetch)

    failures = 0
    with TemporaryDirectory(prefix="pqclean-export-") as temp_dir:
        export_root = Path(temp_dir)
        exported: dict[str, Path] = {}

        for component in components:
            name = component["name"]
            status = component["status"]
            local_path = ROOT / component["local_path"]
            upstream_path = component["upstream_path"]
            upstream_commit = component["upstream_commit"]
            include_files = component.get("include_files", [])

            if upstream_commit not in exported:
                exported[upstream_commit] = export_commit_tree(repo_dir, upstream_commit, export_root)
            upstream_root = exported[upstream_commit]
            upstream_abs = upstream_root / upstream_path

            diffs = compare_paths(local_path, upstream_abs, include_files, ignored)

            allowed: set[str] = set()
            patch_ids = component.get("local_patch_set", [])
            for patch_id in patch_ids:
                patch = patches[patch_id]
                allowed.update(patch.get("files", []))

            if status == "pristine":
                if diffs:
                    failures += 1
                    print(f"[FAIL] {name}: pristine component has unexpected diffs ({len(diffs)})")
                    for path in sorted(diffs):
                        print(f"  - {path}")
                else:
                    print(f"[PASS] {name}: pristine, no diffs")
                continue

            unexplained = sorted(diffs - allowed)
            if unexplained:
                failures += 1
                print(f"[FAIL] {name}: patched component has unexplained diffs ({len(unexplained)})")
                for path in unexplained:
                    print(f"  - {path}")
            else:
                print(f"[PASS] {name}: patched diffs fully covered ({len(diffs)} files)")

    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help=f"Path to VERSIONS.toml (default: {DEFAULT_MANIFEST})",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"Cache directory for PQClean upstream clone (default: {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="Do not fetch from origin when requested commit is not in cache.",
    )
    parser.add_argument(
        "--component",
        action="append",
        dest="components",
        help="Optional component name filter (repeatable).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    manifest_path = args.manifest.resolve()
    if not manifest_path.exists():
        print(f"Missing manifest: {manifest_path}")
        return 1

    try:
        run_manifest_lint(manifest_path)
        manifest = load_manifest(manifest_path)
        selected = set(args.components) if args.components else None
        failures = validate_components(manifest, selected, not args.no_fetch, args.cache_dir)
    except RuntimeError as e:
        print(f"Error: {e}")
        return 1

    if failures:
        print(f"\nPQ vendor deep check failed with {failures} component failure(s).")
        return 1

    print("\nPQ vendor deep check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
