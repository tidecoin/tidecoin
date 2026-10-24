#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise reconstruction and generation without changing real PQ sources."""

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import check_pq_vendor as vendor


class PQVendorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(prefix="pq-vendor-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.prefix = "src/pq/example/"
        self.one = self.prefix + "one.c"
        self.two = self.prefix + "space name.c"
        self.original = {self.one: b"".join(f"line {i}\n".encode() for i in range(40)), self.two: b"original\n"}
        self.current = {self.one: self.original[self.one].replace(b"line 1\n", b"first change\n").replace(b"line 38\n", b"second change\n"),
                        self.two: b"maintained\n"}
        self.archive = self.root / "src/pq/upstream/origin.tar.gz"
        self.archive.parent.mkdir(parents=True)
        self.origin_files = {"origin/clean/" + name[len(self.prefix):]: data for name, data in self.original.items()}
        self.origin_files["origin/clean/Makefile"] = b"original makefile\n"
        self.write_archive(self.origin_files)
        vendor.write_tree(self.root, self.current)
        self.manifest = {
            "schema_version": 2,
            "maintenance": {"owner": "Tidecoin developers", "source_of_truth": "checked-in-source"},
            "upstream": {"status": "archived", "pqclean_repo": "unused", "default_upstream_commit": "1" * 40},
            "settings": {"ignored_upstream_files": ["Makefile"]},
            "snapshots": [{"upstream_commit": "1" * 40, "archive_file": self.archive.relative_to(self.root).as_posix(),
                           "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(), "paths": ["origin/clean"]}],
            "patches": [{"id": "example", "patch_file": "src/pq/patches/example.patch", "summary": "Example",
                         "reason": "Test", "owner": "Tidecoin developers", "consensus_impact": "none", "files": [self.one, self.two]}],
            "components": [{"name": "example", "status": "patched", "local_path": "src/pq/example", "upstream_path": "origin/clean",
                            "upstream_commit": "1" * 40, "import_commit": "2" * 40, "local_patch_set": ["example"], "notes": "Test"}],
        }
        self.regenerate()

    def write_archive(self, files):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

    def process(self, **kwargs):
        with redirect_stdout(io.StringIO()) as output:
            result = vendor.process_components(self.manifest, self.root, **kwargs)
        return result, output.getvalue()

    def regenerate(self):
        vendor.validate_manifest(self.manifest, self.root, require_patches=False)
        self.assertEqual(self.process(regenerate=True)[0], 0)

    @property
    def patch_path(self):
        return self.root / self.manifest["patches"][0]["patch_file"]

    def test_replay_and_repeatable_generation_leave_sources_unchanged(self):
        before = {path: (self.root / path).read_bytes() for path in self.current}
        record = self.patch_path.read_bytes()
        self.assertEqual(self.process()[0], 0)
        self.regenerate()
        self.assertEqual(record, self.patch_path.read_bytes())
        self.assertEqual(before, {path: (self.root / path).read_bytes() for path in self.current})

    def test_generation_does_not_inherit_personal_diff_options(self):
        record = self.patch_path.read_bytes()
        config = self.root / "personal-gitconfig"
        config.write_text("[diff]\ncontext = 10\nalgorithm = histogram\nindentHeuristic = true\n[core]\nabbrev = 12\nautocrlf = true\n", encoding="utf8")
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config)}):
            self.regenerate()
        self.assertEqual(record, self.patch_path.read_bytes())

    def test_omitted_hunk_is_not_covered_by_the_filename(self):
        incomplete = dict(self.current)
        incomplete[self.one] = incomplete[self.one].replace(b"second change\n", b"line 38\n")
        self.patch_path.write_bytes(vendor.generate_patch(self.original, incomplete))
        result, output = self.process()
        self.assertEqual(result, 1)
        self.assertIn("Reconstruction differs", output)

    def test_changed_source_in_already_listed_file_fails(self):
        (self.root / self.one).write_bytes(self.current[self.one] + b"unrecorded change\n")
        self.assertEqual(self.process()[0], 1)

    def test_extra_file_fails_without_rewriting_records(self):
        record = self.patch_path.read_bytes()
        (self.root / self.prefix / "extra.c").write_text("extra\n", encoding="utf8")
        for regenerate in (False, True):
            with self.assertRaisesRegex(RuntimeError, "unrecorded=.*extra.c"):
                self.process(regenerate=regenerate)
        self.assertEqual(record, self.patch_path.read_bytes())

    def test_failed_hunk_fails(self):
        self.patch_path.write_bytes(self.patch_path.read_bytes().replace(b"-line 1\n", b"-not the original line\n"))
        result, output = self.process()
        self.assertEqual(result, 1)
        self.assertIn("Command failed", output)

    def test_patch_cannot_touch_an_unlisted_file(self):
        extra = vendor.generate_patch({}, {self.prefix + "extra.c": b"extra\n"})
        self.patch_path.write_bytes(self.patch_path.read_bytes() + extra)
        result, output = self.process()
        self.assertEqual(result, 1)
        self.assertIn("file list differs", output)
        self.assertFalse((self.root / self.prefix / "extra.c").exists())

    def test_declared_binary_addition_and_deletion(self):
        added = self.prefix + "vector.bin"
        (self.root / added).write_bytes(bytes(range(256)))
        (self.root / self.two).unlink()
        self.manifest["patches"][0]["files"].append(added)
        self.regenerate()
        self.assertEqual(self.process()[0], 0)

    def test_multiple_disjoint_patches(self):
        second = deepcopy(self.manifest["patches"][0])
        second.update(id="second", patch_file="src/pq/patches/second.patch", files=[self.two])
        self.manifest["patches"][0]["files"] = [self.one]
        self.manifest["patches"].append(second)
        self.manifest["components"][0]["local_patch_set"].append("second")
        self.regenerate()
        self.assertEqual(self.process()[0], 0)
        second["files"].append(self.one)
        with self.assertRaisesRegex(RuntimeError, "Overlapping patch ownership"):
            vendor.validate_manifest(self.manifest, self.root)

    def test_pristine_component_and_explicit_shared_file_scope(self):
        self.manifest["patches"] = []
        self.manifest["components"][0].update(status="pristine", local_patch_set=[], include_files=["one.c"])
        (self.root / self.one).write_bytes(self.original[self.one])
        # The other file is deliberately outside this shared component's scope.
        vendor.validate_manifest(self.manifest, self.root)
        self.assertEqual(self.process()[0], 0)

    def test_archive_content_must_match_digest_and_declared_paths(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"extra")
        with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
            self.process()
        self.write_archive({**self.origin_files, "outside/file": b"extra"})
        self.manifest["snapshots"][0]["sha256"] = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "Unexplained origin archive file"):
            self.process()

    def test_archive_rejects_duplicate_parent_and_link_entries(self):
        for kind in ("duplicate", "parent", "link"):
            with self.subTest(kind=kind):
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode="w") as archive:
                    info = tarfile.TarInfo("origin/file")
                    archive.addfile(info)
                    if kind == "parent":
                        info = tarfile.TarInfo("../outside")
                    elif kind == "link":
                        info = tarfile.TarInfo("origin/link")
                        info.type = tarfile.SYMTYPE
                        info.linkname = "outside"
                    archive.addfile(info)
                with self.assertRaises(RuntimeError):
                    vendor.read_archive(data.getvalue())

    def test_unknown_component_and_metadata_errors(self):
        with self.assertRaisesRegex(RuntimeError, "Unknown components"):
            self.process(selected={"missing"})
        for invalid in ([], "owner", None):
            with self.subTest(invalid=invalid):
                manifest = deepcopy(self.manifest)
                manifest["maintenance"] = invalid
                with self.assertRaises(RuntimeError):
                    vendor.validate_manifest(manifest, self.root)
        self.manifest["patches"][0]["patch_file"] = "src/pq/example/one.c"
        with self.assertRaisesRegex(RuntimeError, "Patch output must be"):
            vendor.validate_manifest(self.manifest, self.root)

    def test_no_fetch_forbids_initial_clone(self):
        with patch.object(vendor, "run") as command:
            with self.assertRaisesRegex(RuntimeError, "forbids cloning"):
                vendor.ensure_repo(self.root / "absent-cache", "unused", False)
            command.assert_not_called()
        self.assertFalse((self.root / "absent-cache").exists())

    def test_optional_git_origin_verification(self):
        repo = self.root / "origin repo"
        repo.mkdir()
        vendor.run(["git", "init", "-q", str(repo)])
        vendor.write_tree(repo, self.origin_files)
        vendor.run(["git", "add", "."], cwd=repo)
        vendor.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                    "commit", "-qm", "Origin"], cwd=repo)
        commit = vendor.run(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()
        self.manifest["snapshots"][0]["upstream_commit"] = commit
        with redirect_stdout(io.StringIO()):
            vendor.verify_upstream(self.manifest, self.root, repo, False)
        self.write_archive({**self.origin_files, "origin/clean/one.c": b"different\n"})
        self.manifest["snapshots"][0]["sha256"] = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "differs from Git origin"):
            vendor.verify_upstream(self.manifest, self.root, repo, False)
        self.manifest["snapshots"][0]["upstream_commit"] = "0" * 40
        with self.assertRaisesRegex(RuntimeError, "forbids fetching"):
            vendor.verify_upstream(self.manifest, self.root, repo, False)

    def test_cli_generate_check_and_failure_without_origin_access(self):
        scripts = self.root / "contrib/devtools"
        scripts.mkdir(parents=True)
        shutil.copyfile(Path(vendor.__file__), scripts / "check_pq_vendor.py")
        # JSON strings are also TOML basic strings; write the small fixture's tables.
        lines = []
        for key, value in self.manifest.items():
            if isinstance(value, dict):
                lines += [f"[{key}]"] + [f"{k} = {json.dumps(v)}" for k, v in value.items()]
            elif isinstance(value, list):
                for item in value:
                    lines += [f"[[{key}]]"] + [f"{k} = {json.dumps(v)}" for k, v in item.items()]
            else:
                lines += [f"{key} = {json.dumps(value)}"]
        manifest = self.root / "src/pq/VERSIONS.toml"
        manifest.write_text("\n".join(lines) + "\n", encoding="utf8")
        for args in (["--regenerate"], ["--no-fetch"], []):
            result = subprocess.run([sys.executable, str(scripts / "check_pq_vendor.py"), *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (self.root / self.one).write_bytes(b"unrecorded edit\n")
        result = subprocess.run([sys.executable, str(scripts / "check_pq_vendor.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Reconstruction differs", result.stdout)


if __name__ == "__main__":
    unittest.main()
