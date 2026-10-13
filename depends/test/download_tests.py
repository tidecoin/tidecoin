#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Test dependency downloads with isolated caches and a local HTTP server."""

import hashlib
import http.server
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def archive(data):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as tar:
        entry = tarfile.TarInfo("fixture/content")
        entry.size = len(data)
        tar.addfile(entry, io.BytesIO(data))
    return result.getvalue()


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="depends-download-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.depends = self.root / "depends"
        self.depends.mkdir()
        original = Path(__file__).resolve().parents[1]
        for name in ("Makefile", "funcs.mk", "config.guess", "config.sub"):
            shutil.copy2(original / name, self.depends / name)
        for name in ("builders", "hosts", "packages"):
            shutil.copytree(original / name, self.depends / name)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.stamp = self.sources / "download-stamps/.stamp_fetched-fixture-source.tar.gz.hash"
        self.payload = archive(b"current source")
        self.requests = []
        self.routes = {"/primary/upstream.tar.gz": self.payload,
                       "/mirror/source.tar.gz": self.payload}
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append(self.path)
                body = test.routes.get(self.path)
                self.send_response(404 if body is None else 200)
                self.end_headers()
                if body is not None:
                    self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.recipe = self.depends / "packages/fixture.mk"
        self.recipe.write_text(f"""package=fixture
$(package)_version=1
$(package)_file_name=source.tar.gz
$(package)_download_file=upstream.tar.gz
$(package)_download_path={self.url}/primary
$(package)_sha256_hash={checksum(self.payload)}
""", encoding="utf8")

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def seed(self, data, stamp=True):
        (self.sources / "source.tar.gz").write_bytes(data)
        if stamp:
            self.stamp.parent.mkdir(exist_ok=True)
            self.stamp.write_text(f"{checksum(data)}  source.tar.gz\n", encoding="utf8")

    def make(self, *targets, success=True):
        result = subprocess.run(
            ["make", "--no-print-directory", "-C", str(self.depends),
             "packages=fixture", "native_packages=", "HOST=x86_64-linux-gnu",
             f"SOURCES_PATH={self.sources}", f"WORK_PATH={self.root / 'work'}",
             f"BASE_CACHE={self.root / 'cache'}", f"FALLBACK_DOWNLOAD_PATH={self.url}/mirror",
             *targets], capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def test_old_cache_with_stamp(self):
        self.seed(archive(b"old source"))
        self.make("check-sources", "fixture_extracted")
        self.assertEqual((self.sources / "source.tar.gz").read_bytes(), self.payload)
        self.assertEqual(self.requests, ["/primary/upstream.tar.gz"])

    def test_old_cache_without_stamp(self):
        self.seed(archive(b"old source"), stamp=False)
        self.make("fixture_extracted")
        self.assertEqual(self.requests, ["/primary/upstream.tar.gz"])

    def test_valid_cache_reused_without_reextracting(self):
        self.seed(self.payload)
        self.routes.clear()
        self.make("fixture_extracted")
        extracted = next((self.root / "work").rglob(".stamp_extracted"))
        previous_mtime = extracted.stat().st_mtime_ns
        self.make("check-sources", "fixture_extracted")
        self.assertEqual(extracted.stat().st_mtime_ns, previous_mtime)
        self.assertEqual(self.requests, [])

    def test_empty_cache(self):
        self.make("fixture_extracted")
        self.assertEqual(self.requests, ["/primary/upstream.tar.gz"])

    def test_missing_file_with_stamp(self):
        self.seed(self.payload)
        (self.sources / "source.tar.gz").unlink()
        self.make("fixture_extracted")
        self.assertEqual(self.requests, ["/primary/upstream.tar.gz"])

    def test_wrong_primary_uses_verified_fallback(self):
        self.routes["/primary/upstream.tar.gz"] = b"incorrect download"
        self.make("fixture_extracted")
        self.assertEqual(self.requests, ["/primary/upstream.tar.gz", "/mirror/source.tar.gz"])

    def test_unavailable_primary_uses_fallback(self):
        del self.routes["/primary/upstream.tar.gz"]
        self.make("fixture_extracted")
        self.assertEqual(self.requests, ["/primary/upstream.tar.gz", "/mirror/source.tar.gz"])

    def test_failed_download_does_not_leave_success_stamp(self):
        self.seed(archive(b"old source"))
        self.routes = dict.fromkeys(self.routes, b"incorrect download")
        self.make("fixture_extracted", success=False)
        self.assertFalse(self.stamp.exists())
        self.assertEqual(list((self.root / "work").rglob(".stamp_extracted")), [])
        self.routes["/primary/upstream.tar.gz"] = self.payload
        self.make("fixture_extracted")
        self.assertEqual((self.sources / "source.tar.gz").read_bytes(), self.payload)

    def test_changed_extra_source_preserves_valid_main_source(self):
        extra = b"first extra source"
        recipe = self.recipe.read_text(encoding="utf8") + f"""
$(package)_extra_sources=extra.txt
$(package)_extra_hash={checksum(extra)}
define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \\
$(call fetch_file,$(package),$($(package)_download_path),extra.txt,extra.txt,$($(package)_extra_hash))
endef
"""
        self.recipe.write_text(recipe, encoding="utf8")
        self.routes["/primary/extra.txt"] = extra
        self.make("fixture_fetched")
        main_mtime = (self.sources / "source.tar.gz").stat().st_mtime_ns
        self.requests.clear()
        replacement = b"new extra source"
        self.recipe.write_text(recipe.replace(checksum(extra), checksum(replacement)), encoding="utf8")
        self.routes["/primary/extra.txt"] = replacement
        self.make("check-sources", "fixture_fetched")
        self.assertEqual(self.requests, ["/primary/extra.txt"])
        self.assertEqual((self.sources / "source.tar.gz").stat().st_mtime_ns, main_mtime)
        self.assertEqual((self.sources / "extra.txt").read_bytes(), replacement)

        # Damage one file after a successful fetch. Keep the other file intact.
        (self.sources / "extra.txt").write_bytes(b"incomplete")
        self.requests.clear()
        self.make("check-sources", "fixture_fetched")
        self.assertEqual(self.requests, ["/primary/extra.txt"])
        self.assertEqual((self.sources / "source.tar.gz").stat().st_mtime_ns, main_mtime)
        self.assertEqual((self.sources / "extra.txt").read_bytes(), replacement)

    def test_local_source_is_not_downloaded(self):
        local = self.root / "local"
        local.mkdir()
        (local / "content").write_text("local source", encoding="utf8")
        self.recipe.write_text(f"package=fixture\n$(package)_local_dir={local}\n", encoding="utf8")
        self.make("fixture_extracted")
        self.make("fixture_extracted")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
