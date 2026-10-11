#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reconsider overlapping candidate chains with a pruned common ancestor."""

from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class UnlinkedBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ['-fastprune', '-prune=1', '-checkblockindex=1', '-auxpowactivationheight=never'],
            ['-checkblockindex=1', '-auxpowactivationheight=never'],
        ]

    def run_test(self):
        node, reference = self.nodes
        main = self.generate(reference, 300)
        self.disconnect_nodes(0, 1)
        reference.invalidateblock(main[0])

        def large_fork_block():
            # Exceed the 64 KiB fastprune file size so each stale block goes
            # into its own file, while its output script remains below 64 KiB.
            output = CScript([OP_RETURN, b'x' * 65520])
            block_hash = self.generateblock(reference, output=f'raw({output.hex()})', transactions=[], sync_fun=self.no_op)['hash']
            block = reference.getblock(block_hash, 0)
            assert len(bytes.fromhex(block)) > 65536
            return block_hash, block

        missing_hash, missing = large_fork_block()
        reference.setmocktime(reference.getblockheader(missing_hash)['time'] + 1)
        reference.invalidateblock(missing_hash)
        filler_hash, filler = large_fork_block()
        for block in [missing, filler]:
            assert node.submitblock(block) in (None, 'inconclusive')
        node.pruneblockchain(1)
        assert_raises_rpc_error(-1, 'Block not available (pruned data)', node.getblock, missing_hash)
        assert_equal(node.getbestblockhash(), main[-1])

        self.log.info('Extend a fork whose first block was pruned')
        reference.invalidateblock(filler_hash)
        reference.reconsiderblock(missing_hash)
        assert_equal(reference.getbestblockhash(), missing_hash)
        fork = self.generate(reference, 301, sync_fun=self.no_op)
        for block_hash in fork:
            assert node.submitblock(reference.getblock(block_hash, 0)) in (None, 'inconclusive')
        # The last two candidate tips traverse the same missing-data path.
        # With duplicate queue entries, -checkblockindex catches the invariant
        # violation before the missing block is received again.
        assert_equal(node.getbestblockhash(), main[-1])
        for block_hash in fork[-2:]:
            node.reconsiderblock(block_hash)
            assert_equal(node.getbestblockhash(), main[-1])

        self.log.info('Restore the missing ancestor and complete the reorg')
        assert_equal(node.submitblock(missing), None)
        assert_equal(node.getbestblockhash(), fork[-1])
        expected = reference.gettxoutsetinfo('muhash')
        actual = node.gettxoutsetinfo('muhash')
        expected.pop('disk_size')
        actual.pop('disk_size')
        assert_equal(actual, expected)
        assert_equal(node.verifychain(4, 0), True)
        self.restart_node(0)
        actual = node.gettxoutsetinfo('muhash')
        actual.pop('disk_size')
        assert_equal(actual, expected)


if __name__ == '__main__':
    UnlinkedBlocksTest(__file__).main()
