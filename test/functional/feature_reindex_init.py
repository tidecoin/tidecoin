#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test automatic reindex for a missing index and recovery after a db load failure."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
import os
import shutil


class ReindexInitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        self.stop_nodes()

        self.log.info("Removing the block index triggers an automatic full rebuild")
        shutil.rmtree(node.blocks_path / "index")
        with node.assert_debug_log(["Database storage format upgrade:", "Reindexing finished"]):
            self.start_node(0)
        assert_equal(node.getbestblockhash(), tip)
        assert node.verifychain(4, 0)
        self.stop_node(0)
        with node.assert_debug_log([], unexpected_msgs=["Database storage format upgrade:", "Reindexing block file"]):
            self.start_node(0)
        assert_equal(node.getbestblockhash(), tip)
        self.stop_node(0)

        self.log.info("An unreadable chainstate still requires accepting the rebuild prompt")
        # Preserve the current block-index format marker so this exercises the
        # generic load-failure recovery path, not the automatic format upgrade.
        (node.chain_path / "chainstate" / "CURRENT").write_text("missing-manifest\n", encoding="utf8")
        node.assert_start_raises_init_error(
            expected_msg=f": Error opening coins database.{os.linesep}"
            "Please restart with -reindex or -reindex-chainstate to recover.",
        )

        self.log.info("Allowing the reindex should work fine")
        self.start_node(0, extra_args=["-test=reindex_after_failure_noninteractive_yes"])
        assert_equal(node.getblockcount(), 200)
        assert_equal(node.getbestblockhash(), tip)
        assert node.verifychain(4, 0)


if __name__ == "__main__":
    ReindexInitTest(__file__).main()
