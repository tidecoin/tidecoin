#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining on a Tide-specific alternate mainnet chain.

The test replays precomputed blocks up to the retarget boundary and verifies
that getmininginfo reports a higher next-period difficulty as expected.
See test/functional/data/README.md for vector generation details.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.blocktools import nbits_str, target_str

from test_framework.messages import uint256_from_compact
from test_framework.util import assert_greater_than

import json
import os

class MiningMainnetTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = "" # main

    def add_options(self, parser):
        parser.add_argument(
            '--datafile',
            default='data/mainnet_tide_alt.json',
            help='Block data file (default: %(default)s)',
        )

    def submit_precomputed(self, block_height, block_data, node):
        self.log.debug(f"height={block_height}")
        assert_equal(node.submitblock(block_data["hex"]), None)
        assert_equal(node.getbestblockhash(), block_data["hash"])


    def run_test(self):
        node = self.nodes[0]
        # Clear disk space warning
        node.stderr.seek(0)
        node.stderr.truncate()
        self.log.info("Load alternative mainnet blocks")
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.options.datafile)
        vectors = None
        with open(path, encoding='utf-8') as f:
            vectors = json.load(f)

        interval = int(vectors['retarget_interval'])
        blocks = vectors["blocks"]
        assert_equal(len(blocks), interval)
        assert_equal(node.getblockhash(0), vectors['genesis_hash'])
        initial_nbits = int(vectors['initial_nbits'], 16)
        expected_next_bits = vectors.get("expected_next_bits", "1e43b698")

        # Mine up to the last block of the first retarget period
        for i in range(interval - 1):
            self.submit_precomputed(i + 1, blocks[i], node)

        assert_equal(node.getblockcount(), interval - 1)

        self.log.info("Check difficulty adjustment with getmininginfo")
        mining_info = node.getmininginfo()
        assert_equal(mining_info['bits'], nbits_str(initial_nbits))
        assert_equal(mining_info['target'], target_str(uint256_from_compact(initial_nbits)))

        assert_equal(mining_info['next']['height'], interval)
        assert_greater_than(mining_info['next']['difficulty'], mining_info['difficulty'])
        assert_greater_than(int(mining_info['target'], 16), int(mining_info['next']['target'], 16))
        assert_equal(mining_info["next"]["bits"], expected_next_bits)

        self.log.info("getblock RPC should show historical target")
        block_info = node.getblock(node.getblockhash(1))

        assert_equal(block_info['bits'], nbits_str(initial_nbits))
        assert_equal(block_info['target'], target_str(uint256_from_compact(initial_nbits)))


if __name__ == '__main__':
    MiningMainnetTest(__file__).main()
