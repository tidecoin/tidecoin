#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import json
import os
import subprocess
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class BitcoinChainstateTest(BitcoinTestFramework):
    def skip_test_if_missing_module(self):
        self.skip_if_no_tidecoin_chainstate()

    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = ""
        self.num_nodes = 1
        # Set prune to avoid disk space warning.
        self.extra_args = [["-prune=550"]]

    def add_block(self, datadir, input, expected_stderr, expected_returncode=0):
        proc = subprocess.Popen(
            self.get_binaries().chainstate_argv() + [datadir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = proc.communicate(input=input + "\n", timeout=5 * self.options.timeout_factor)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        self.log.debug("STDOUT: {0}".format(stdout.strip("\n")))
        self.log.info("STDERR: {0}".format(stderr.strip("\n")))

        assert_equal(proc.returncode, expected_returncode)
        if expected_stderr not in stderr:
            raise AssertionError(f"Expected stderr output {expected_stderr} does not partially match stderr:\n{stderr}")
        return stdout

    def get_tidecoin_mainnet_block_one(self):
        data_path = os.path.join(self.config["environment"]["SRCDIR"], "test", "functional", "data", "mainnet_tide_alt.json")
        with open(data_path, encoding="utf8") as f:
            return json.load(f)["blocks"][0]["hex"]

    def run_test(self):
        node = self.nodes[0]
        datadir = node.cli.datadir
        node.stop_node()

        self.log.info(f"Testing tidecoin-chainstate {self.get_binaries().chainstate_argv()} with datadir: {datadir}")
        block_one = self.get_tidecoin_mainnet_block_one()
        self.add_block(datadir, block_one, "Block has not yet been rejected")
        self.add_block(datadir, block_one, "duplicate")
        self.add_block(datadir, "00", "Block decode failed")
        self.add_block(datadir, "", "Empty line found")

        self.log.info("Constructor errors report failure and preserve the XOR key file")
        key_path = node.blocks_key_path
        original_key = key_path.read_bytes()
        for size in (0, 7, 9):
            damaged = b'x' * size
            key_path.write_bytes(damaged)
            try:
                self.add_block(datadir, "", f"Invalid or unreadable XOR key file {key_path}: expected exactly 8 bytes", 1)
                assert_equal(key_path.read_bytes(), damaged)
            finally:
                key_path.write_bytes(original_key)
            assert "Active Height: 1" in self.add_block(datadir, "", "Empty line found")

        self.log.info("Snapshot metadata exceptions shut down the partially loaded manager")
        snapshot_dir = node.chain_path / "chainstate_snapshot"
        snapshot_dir.mkdir()
        metadata = snapshot_dir / "base_blockhash"
        try:
            for size in (0, 31, 33):
                damaged = b'x' * size
                metadata.write_bytes(damaged)
                self.add_block(datadir, "", f"Invalid or unreadable snapshot base blockhash file {metadata}: expected exactly 32 bytes", 1)
                assert_equal(metadata.read_bytes(), damaged)
        finally:
            metadata.unlink(missing_ok=True)
            snapshot_dir.rmdir()
        assert "Active Height: 1" in self.add_block(datadir, "", "Empty line found")

        self.log.info("Returned load errors include their reason and exit unsuccessfully")
        current = node.chain_path / "chainstate" / "CURRENT"
        saved_current = current.read_bytes()
        try:
            current.write_bytes(b'missing-manifest\n')
            self.add_block(datadir, "", "Failed to load chainstate: Error opening coins database", 1)
        finally:
            current.write_bytes(saved_current)
        assert "Active Height: 1" in self.add_block(datadir, "", "Empty line found")

        self.log.info("Filesystem errors before manager creation also exit normally with failure")
        not_directory = Path(self.options.tmpdir) / "not-a-directory"
        not_directory.write_bytes(b'preserve')
        self.add_block(str(not_directory), "", "Error:", 1)
        assert_equal(not_directory.read_bytes(), b'preserve')

if __name__ == "__main__":
    BitcoinChainstateTest(__file__).main()
