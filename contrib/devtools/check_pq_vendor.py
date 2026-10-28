#!/usr/bin/env python3
#
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Reconstruct Tidecoin-maintained PQ sources from preserved origins and patches."""

from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

try:
    import tomllib  # type: ignore[attr-defined,import]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import,no-redef]

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "src/pq/VERSIONS.toml"
DEFAULT_CACHE_DIR = Path("/tmp/pqclean-vendor-cache")


def relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or any(c in value for c in "\\\n\r\t\0"):
        raise RuntimeError(f"Invalid relative path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value or value == ".":
        raise RuntimeError(f"Invalid relative path: {value!r}")
    return value


def local_path(root: Path, value: object) -> Path:
    path = root / relative_path(value)
    if not path.resolve().is_relative_to(root.resolve()):
        raise RuntimeError(f"Path leaves source tree: {value}")
    for part in (path, *path.parents):
        if part == root:
            break
        if part.is_symlink():
            raise RuntimeError(f"Expected an ordinary file/directory: {value}")
    return path


def strings(value: object, context: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(s, str) or not s for s in value):
        raise RuntimeError(f"{context}: expected a list of non-empty strings")
    if nonempty and not value:
        raise RuntimeError(f"{context}: list must not be empty")
    if len(value) != len(set(value)):
        raise RuntimeError(f"{context}: duplicate entries")
    return value


def tables(value: object, context: str) -> list[dict]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuntimeError(f"{context}: expected an array of tables")
    return value


def table(value: object, context: str) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError(f"{context}: expected a table")
    return value


def required_text(table: dict, key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"Missing or invalid {key}")
    return value


def commit_id(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise RuntimeError("Expected a 40-character lowercase commit ID")
    return value


def in_component(path: str, component: dict) -> bool:
    prefix = component["local_path"] + "/"
    if not path.startswith(prefix):
        return False
    included = component.get("include_files", [])
    return not included or path[len(prefix):] in included


def validate_manifest(manifest: dict, root: Path, *, require_patches: bool = True) -> None:
    if manifest.get("schema_version") != 2:
        raise RuntimeError("manifest: schema_version must be 2")
    maintenance = table(manifest.get("maintenance"), "maintenance")
    required_text(maintenance, "owner")
    if maintenance.get("source_of_truth") != "checked-in-source":
        raise RuntimeError("maintenance.source_of_truth must be checked-in-source")
    upstream = table(manifest.get("upstream"), "upstream")
    required_text(upstream, "pqclean_repo")
    commit_id(upstream.get("default_upstream_commit"))
    if upstream.get("status") != "archived":
        raise RuntimeError("upstream.status must describe the archived origin")
    ignored = strings(table(manifest.get("settings", {}), "settings").get("ignored_upstream_files", []), "ignored_upstream_files")
    if any("/" in relative_path(name) for name in ignored):
        raise RuntimeError("ignored_upstream_files must contain basenames")

    snapshots = {}
    for snapshot in tables(manifest.get("snapshots"), "snapshots"):
        commit = commit_id(snapshot.get("upstream_commit"))
        if commit in snapshots:
            raise RuntimeError(f"Duplicate snapshot: {commit}")
        archive = local_path(root, snapshot.get("archive_file"))
        if not archive.is_file():
            raise RuntimeError(f"Missing origin archive: {archive}")
        if not re.fullmatch(r"[0-9a-f]{64}", required_text(snapshot, "sha256")):
            raise RuntimeError("snapshot.sha256 must be a lowercase SHA-256 digest")
        for path in strings(snapshot.get("paths"), "snapshot.paths", nonempty=True):
            relative_path(path)
        snapshots[commit] = snapshot

    patches = {}
    patch_paths = set()
    for patch in tables(manifest.get("patches"), "patches"):
        ident = required_text(patch, "id")
        path = required_text(patch, "patch_file")
        if ident in patches or path in patch_paths:
            raise RuntimeError(f"Duplicate patch ID/path: {ident}")
        if not path.startswith("src/pq/patches/") or not path.endswith(".patch"):
            raise RuntimeError(f"Patch output must be under src/pq/patches/: {path}")
        patch_path = local_path(root, path)
        if require_patches and (not patch_path.is_file() or patch_path.stat().st_size == 0):
            raise RuntimeError(f"Missing or empty patch: {path}")
        for key in ("summary", "reason", "owner"):
            required_text(patch, key)
        if required_text(patch, "consensus_impact") not in {"none", "indirect", "direct"}:
            raise RuntimeError(f"Invalid consensus_impact: {ident}")
        for file_name in strings(patch.get("files"), f"{ident}.files", nonempty=True):
            local_path(root, file_name)  # A recorded deletion need not exist locally.
        patches[ident] = patch
        patch_paths.add(path)

    names = set()
    used_patches = set()
    used_files = set()
    components = tables(manifest.get("components"), "components")
    if not components:
        raise RuntimeError("No components declared")
    for component in components:
        name = required_text(component, "name")
        if name in names:
            raise RuntimeError(f"Duplicate component: {name}")
        names.add(name)
        required_text(component, "notes")
        if not local_path(root, component.get("local_path")).is_dir():
            raise RuntimeError(f"Missing component directory: {name}")
        relative_path(component.get("upstream_path"))
        commit_id(component.get("import_commit"))
        commit = commit_id(component.get("upstream_commit"))
        if commit not in snapshots:
            raise RuntimeError(f"No preserved snapshot for {name}: {commit}")
        for path in strings(component.get("include_files", []), f"{name}.include_files"):
            relative_path(path)
        patch_set = strings(component.get("local_patch_set"), f"{name}.local_patch_set")
        status = required_text(component, "status")
        if status not in {"pristine", "patched"} or (status == "pristine") != (not patch_set):
            raise RuntimeError(f"Invalid status/local_patch_set combination: {name}")
        for ident in patch_set:
            if ident not in patches or ident in used_patches:
                raise RuntimeError(f"Patch must belong to exactly one component: {ident}")
            used_patches.add(ident)
            for path in patches[ident]["files"]:
                if not in_component(path, component) or PurePosixPath(path).name in ignored:
                    raise RuntimeError(f"Patch file outside component scope: {path}")
                if path in used_files:
                    raise RuntimeError(f"Overlapping patch ownership; consolidate changes for {path}")
                used_files.add(path)
    if used_patches != set(patches):
        raise RuntimeError(f"Unreferenced patches: {sorted(set(patches) - used_patches)}")
    for adapter in tables(manifest.get("native_adapters", []), "native_adapters"):
        required_text(adapter, "name")
        required_text(adapter, "notes")
        for path in strings(adapter.get("local_paths"), "native_adapters.local_paths", nonempty=True):
            if not local_path(root, path).is_file():
                raise RuntimeError(f"Missing native adapter: {path}")


def read_manifest(path: Path, root: Path = ROOT, *, require_patches: bool = True) -> dict:
    manifest = tomllib.loads(path.read_text(encoding="utf8"))
    validate_manifest(manifest, root, require_patches=require_patches)
    return manifest


def run(cmd: list[str], *, cwd: Path | None = None, expected: tuple[int, ...] = (0,)) -> bytes:
    result = subprocess.run(cmd, cwd=cwd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode not in expected:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.decode('utf8', errors='replace').strip()}")
    return result.stdout


def read_archive(data: bytes) -> dict[str, bytes]:
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            if member.isdir():
                relative_path(member.name.rstrip("/"))
                continue
            name = relative_path(member.name)
            if not member.isfile() or name in files:
                raise RuntimeError(f"Non-regular or duplicate archive member: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError(f"Cannot read archive member: {name}")
            files[name] = stream.read()
    return files


def load_snapshot(snapshot: dict, root: Path) -> dict[str, bytes]:
    path = local_path(root, snapshot["archive_file"])
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != snapshot["sha256"]:
        raise RuntimeError(f"Origin archive hash mismatch: {path}")
    files = read_archive(data)
    selections = snapshot["paths"]
    for name in files:
        if not any(name == path or name.startswith(path + "/") for path in selections):
            raise RuntimeError(f"Unexplained origin archive file: {name}")
    for selection in selections:
        if not any(name == selection or name.startswith(selection + "/") for name in files):
            raise RuntimeError(f"Missing origin archive selection: {selection}")
    return files


def ensure_repo(cache_dir: Path, repo_url: str, do_fetch: bool) -> Path:
    repo = cache_dir / "PQClean"
    if not repo.exists():
        if not do_fetch:
            raise RuntimeError(f"No cached origin at {repo}; --no-fetch forbids cloning")
        cache_dir.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--no-checkout", repo_url, str(repo)])
    return repo


def verify_upstream(manifest: dict, root: Path, repo: Path, do_fetch: bool) -> None:
    for snapshot in manifest["snapshots"]:
        commit = snapshot["upstream_commit"]
        try:
            run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=repo)
        except RuntimeError:
            if not do_fetch:
                raise RuntimeError(f"Origin commit {commit} unavailable; --no-fetch forbids fetching")
            run(["git", "fetch", "origin", commit], cwd=repo)
            run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=repo)
        original = read_archive(run(["git", "archive", "--format=tar", commit, "--", *snapshot["paths"]], cwd=repo))
        if original != load_snapshot(snapshot, root):
            raise RuntimeError(f"Preserved snapshot differs from Git origin {commit}")
        print(f"[PASS] preserved snapshot matches origin {commit} ({len(original)} files)")


def origin_files(component: dict, snapshot: dict[str, bytes], ignored: set[str]) -> dict[str, bytes]:
    prefix = component["upstream_path"] + "/"
    included = component.get("include_files", [])
    if included:
        for name in included:
            if prefix + name not in snapshot:
                raise RuntimeError(f"Missing origin file: {prefix}{name}")
    files = {component["local_path"] + "/" + name[len(prefix):]: data
             for name, data in snapshot.items() if name.startswith(prefix)
             and (not included or name[len(prefix):] in included)
             and PurePosixPath(name).name not in ignored}
    if not files:
        raise RuntimeError(f"Empty origin component: {component['name']}")
    return files


def local_files(component: dict, root: Path, ignored: set[str]) -> dict[str, bytes]:
    base = local_path(root, component["local_path"])
    included = component.get("include_files", [])
    paths = [base / name for name in included] if included else sorted(base.rglob("*"))
    files = {}
    for path in paths:
        if path.is_symlink():
            raise RuntimeError(f"Unexpected symlink: {path}")
        if path.is_file() and path.name not in ignored:
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    for name, data in files.items():
        path = local_path(root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o644)


# Use fixed options for generated records, independent of personal Git settings.
GIT = ["git", "-c", "core.autocrlf=false", "-c", "core.attributesFile=/dev/null",
       "-c", "apply.ignoreWhitespace=false", "-c", "color.ui=false",
       "-c", "diff.algorithm=myers", "-c", "diff.indentHeuristic=false"]


def generate_patch(before: dict[str, bytes], after: dict[str, bytes]) -> bytes:
    with TemporaryDirectory(prefix="pq-patch-generate-") as tmp:
        root = Path(tmp)
        (root / "a").mkdir()
        (root / "b").mkdir()
        write_tree(root / "a", before)
        write_tree(root / "b", after)
        data = run([*GIT, "diff", "--no-index", "--binary", "--full-index", "--no-renames", "--no-ext-diff", "--no-textconv", "-U3",
                    "--src-prefix=", "--dst-prefix=", "--", "a", "b"], cwd=root, expected=(0, 1))
        # Like diff --suppress-blank-empty, avoid trailing spaces on empty
        # context lines. Leave added/removed source bytes untouched.
        return b"".join(b"\n" if line == b" \n" else line for line in data.splitlines(keepends=True))


def apply_patch(root: Path, patch_file: Path, declared: set[str]) -> None:
    stats = run([*GIT, "apply", "--numstat", "-z", str(patch_file)], cwd=root)
    paths = []
    for entry in stats.split(b"\0"):
        if not entry:
            continue
        fields = entry.split(b"\t", 2)
        if len(fields) != 3 or not fields[2]:
            raise RuntimeError(f"Unsupported patch path record: {patch_file}")
        paths.append(relative_path(fields[2].decode("utf8")))
    if set(paths) != declared or len(paths) != len(set(paths)):
        raise RuntimeError(f"Patch file list differs from manifest: {patch_file}")
    run([*GIT, "apply", "--check", "--whitespace=nowarn", str(patch_file)], cwd=root)
    run([*GIT, "apply", "--whitespace=nowarn", str(patch_file)], cwd=root)


def check_component(component: dict, before: dict[str, bytes], after: dict[str, bytes], patches: dict, root: Path) -> None:
    with TemporaryDirectory(prefix="pq-patch-replay-") as tmp:
        replay = Path(tmp)
        write_tree(replay, before)
        for ident in component["local_patch_set"]:
            patch = patches[ident]
            apply_patch(replay, local_path(root, patch["patch_file"]), set(patch["files"]))
        rebuilt = {}
        for path in replay.rglob("*"):
            if path.is_symlink():
                raise RuntimeError(f"Patch produced a symlink: {path.relative_to(replay)}")
            if path.is_file():
                rebuilt[path.relative_to(replay).as_posix()] = path.read_bytes()
        differences = sorted(name for name in rebuilt.keys() | after.keys() if rebuilt.get(name) != after.get(name))
        if differences:
            raise RuntimeError(f"Reconstruction differs for {component['name']}: {', '.join(differences)}")


def process_components(manifest: dict, root: Path, selected: set[str] | None = None, *, regenerate: bool = False) -> int:
    components = manifest["components"]
    if selected:
        missing = selected - {c["name"] for c in components}
        if missing:
            raise RuntimeError(f"Unknown components: {sorted(missing)}")
        components = [c for c in components if c["name"] in selected]
    snapshots = {s["upstream_commit"]: load_snapshot(s, root) for s in manifest["snapshots"]}
    patches = {p["id"]: p for p in manifest["patches"]}
    ignored = set(manifest.get("settings", {}).get("ignored_upstream_files", []))
    pending = {}
    prepared = []
    owned: set[str] = set()
    for component in components:
        before = origin_files(component, snapshots[component["upstream_commit"]], ignored)
        after = local_files(component, root, ignored)
        files = before.keys() | after.keys()
        if owned & files:
            raise RuntimeError(f"Overlapping component files: {sorted(owned & files)}")
        owned.update(files)
        changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
        declared = {name for ident in component["local_patch_set"] for name in patches[ident]["files"]}
        if changed != declared:
            raise RuntimeError(f"Change inventory differs for {component['name']}: unrecorded={sorted(changed - declared)}, unchanged={sorted(declared - changed)}")
        prepared.append((component, before, after))
        if regenerate:
            for ident in component["local_patch_set"]:
                patch = patches[ident]
                names = set(patch["files"])
                pending[local_path(root, patch["patch_file"])] = generate_patch(
                    {name: data for name, data in before.items() if name in names},
                    {name: data for name, data in after.items() if name in names})
    # Validate every selected inventory and generate all records before writing.
    for path, data in pending.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(f"[WRITE] {path.relative_to(root)}")
    failures = 0
    for component, before, after in prepared:
        try:
            check_component(component, before, after, patches, root)
            print(f"[PASS] {component['name']}: exact reconstruction ({len(after)} files)")
        except RuntimeError as error:
            failures += 1
            print(f"[FAIL] {error}")
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--component", action="append", dest="components", help="Select a component; may be repeated")
    parser.add_argument("--regenerate", action="store_true", help="Generate patch records from current source, then verify reconstruction")
    parser.add_argument("--verify-upstream", action="store_true", help="Also compare preserved snapshots with the pinned Git objects")
    parser.add_argument("--upstream-repo", type=Path, help="Use an existing PQClean Git repository for --verify-upstream")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR, help="Git origin cache for --verify-upstream")
    parser.add_argument("--no-fetch", action="store_true", help="Forbid cloning/fetching during optional origin verification; normal checks are always offline")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = read_manifest(args.manifest, require_patches=not args.regenerate)
        if args.verify_upstream:
            repo = args.upstream_repo or ensure_repo(args.cache_dir, manifest["upstream"]["pqclean_repo"], not args.no_fetch)
            verify_upstream(manifest, ROOT, repo, not args.no_fetch)
        failures = process_components(manifest, ROOT, set(args.components) if args.components else None, regenerate=args.regenerate)
        if failures:
            print(f"\nPQ reconstruction failed for {failures} component(s).")
            return 1
    except (RuntimeError, OSError, ValueError, tarfile.TarError) as error:
        print(f"Error: {error}")
        return 1
    print("\nPQ reconstruction passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
