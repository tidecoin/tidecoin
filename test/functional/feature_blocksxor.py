#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test support for XORed block data and undo files (`-blocksxor` option)."""

import re

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import (
    ErrorMatch,
    NULL_BLK_XOR_KEY,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_not_equal,
    sha256sum_file,
    util_xor,
)
from test_framework.wallet import MiniWallet


class BlocksXORTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            '-blocksxor=1',
            '-fastprune=1',             # use smaller block files
        ]]

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        # A regular dot-prefixed temporary is ignored on Windows as well as Unix.
        self.nodes[0].blocks_path.mkdir(parents=True, exist_ok=True)
        (self.nodes[0].blocks_path / '.xor.dat.tmp').write_bytes(b'partial')
        self.start_nodes()

    def run_test(self):
        self.log.info("Mine some blocks, to create multiple blk*.dat/rev*.dat files")
        node = self.nodes[0]
        xor_key = node.read_xor_key()
        assert_not_equal(xor_key, NULL_BLK_XOR_KEY)
        assert not (node.blocks_path / '.xor.dat.tmp').exists()
        wallet = MiniWallet(node)
        self.generate(wallet, 101)
        for _ in range(5):
            wallet.send_self_transfer(from_node=node, target_vsize=20000)
            self.generate(wallet, 1)

        block_files = list(node.blocks_path.glob('blk[0-9][0-9][0-9][0-9][0-9].dat'))
        undo_files  = list(node.blocks_path.glob('rev[0-9][0-9][0-9][0-9][0-9].dat'))
        assert_equal(len(block_files), len(undo_files))
        assert_greater_than(len(block_files), 1)  # we want at least one full block file

        self.log.info("Malformed XOR metadata fails clearly without changing block data")
        self.stop_node(0)
        original_files = {path: sha256sum_file(path) for path in block_files + undo_files}
        for size in (0, 1, 7, 9):
            damaged = b'x' * size
            node.blocks_key_path.write_bytes(damaged)
            node.assert_start_raises_init_error(
                expected_msg=re.escape(f'Invalid or unreadable XOR key file {node.blocks_key_path}: expected exactly 8 bytes'),
                match=ErrorMatch.PARTIAL_REGEX,
            )
            assert_equal(node.blocks_key_path.read_bytes(), damaged)
        assert_equal({path: sha256sum_file(path) for path in original_files}, original_files)
        node.blocks_key_path.write_bytes(xor_key)
        self.start_node(0)
        assert_equal(node.read_xor_key(), xor_key)
        assert node.verifychain(checklevel=2, nblocks=0)

        self.log.info("Shut down node and un-XOR block/undo files manually")
        self.stop_node(0)
        for data_file in sorted(block_files + undo_files):
            self.log.debug(f"Rewriting file {data_file}...")
            with open(data_file, 'rb+') as f:
                xored_data = f.read()
                f.seek(0)
                f.write(util_xor(xored_data, xor_key, offset=0))

        self.log.info("Check that restarting with 'blocksxor=0' fails if XOR key is present")
        node.assert_start_raises_init_error(['-blocksxor=0'],
            'The blocksdir XOR-key can not be disabled when a random key was already stored!',
            match=ErrorMatch.PARTIAL_REGEX)

        self.log.info("Delete XOR key, restart node with '-blocksxor=0', check blk*.dat/rev*.dat file integrity")
        node.blocks_key_path.unlink()
        self.start_node(0, extra_args=['-blocksxor=0'])
        # checklevel=2 -> verify block validity + undo data
        # nblocks=0    -> verify all blocks
        assert node.verifychain(checklevel=2, nblocks=0)
        self.log.info("Check that blocks XOR key is recreated")
        assert_equal(node.read_xor_key(), NULL_BLK_XOR_KEY)


if __name__ == '__main__':
    BlocksXORTest(__file__).main()
