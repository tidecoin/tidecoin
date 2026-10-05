#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Deterministic chainstate crashes, including reorg and interrupted replay."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode


class ChainstateRecoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.base_args = ['-dbbatchsize=1', '-auxpowactivationheight=203']
        self.extra_args = [self.base_args, self.base_args]
        self.rpc_timeout = 60

    def setup_network(self):
        self.setup_nodes()  # Deliver blocks explicitly; no peer synchronization.

    def run_test(self):
        node, reference = self.nodes
        wallet = MiniWallet(reference, mode=MiniWalletMode.RAW_P2PK)
        self.connect_nodes(0, 1)
        self.generate(wallet, 200)
        self.disconnect_nodes(0, 1)
        assert_equal(node.getblockcount(), 200)

        for case, crash_at in enumerate(['0', '1', '2', 'final']):
            self.log.info(f'Crash point {crash_at}, then compare complete recovered UTXO state')
            node.gettxoutsetinfo('muhash')  # Establish a fully committed baseline.
            self.stop_node(0)
            self.start_node(0, extra_args=self.base_args + [f'-dbcrashat={crash_at}'])

            if case == 1:
                # Reorganize through AuxPoW activation, replacing blocks 201–203.
                reference.setmocktime(reference.getblockheader(reference.getbestblockhash())['time'] + 1)
                reference.invalidateblock(reference.getblockhash(201))
                count = 5
            else:
                count = 3
            wallet.rescan_utxos()
            tx = wallet.send_self_transfer(from_node=reference)
            blocks = self.generate(reference, count, sync_fun=self.no_op)
            assert tx['txid'] in reference.getblock(blocks[0])['tx']
            expected = reference.gettxoutsetinfo('muhash')
            for block in blocks:
                # A valid competing block need not become the best tip yet.
                assert node.submitblock(reference.getblock(block, 0)) in (None, 'inconclusive')
            assert_equal(node.getbestblockhash(), reference.getbestblockhash())

            with node.assert_debug_log(['Simulating deterministic chainstate crash.']):
                try:
                    node.gettxoutsetinfo('muhash')
                except Exception:
                    # The exact RPC transport error varies by platform. Require
                    # the explicit crash log and exit status below, not just an exception.
                    pass
                node.wait_until_stopped(expect_error=True)

            if crash_at == '1':
                # Interrupt replay after its first batch as well, then recover
                # without injection. The unfinished transition must survive both exits.
                with node.assert_debug_log(['Replaying blocks', 'Simulating deterministic chainstate crash.']):
                    node.assert_start_raises_init_error(extra_args=self.base_args + ['-dbcrashat=1'], expected_msg='')

            self.start_node(0, extra_args=self.base_args)
            actual = node.gettxoutsetinfo('muhash')
            expected.pop('disk_size')
            actual.pop('disk_size')
            assert_equal(actual, expected)
            assert_equal(node.verifychain(4, 0), True)
            # A second normal restart must find a completed transition.
            self.restart_node(0, extra_args=self.base_args)
            assert_equal(node.getbestblockhash(), expected['bestblock'])

        self.stop_node(0)
        for invalid in ['-1', 'nonsense', '1junk']:
            node.assert_start_raises_init_error(
                extra_args=self.base_args + [f'-dbcrashat={invalid}'],
                expected_msg='-dbcrashat must be a non-negative batch number or final',
                match=ErrorMatch.PARTIAL_REGEX,
            )
        node.assert_start_raises_init_error(
            extra_args=['-regtest=0', '-chain=main', '-dbcrashat=0'],
            expected_msg='-dbcrashat is only supported on regtest',
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.start_node(0, extra_args=self.base_args)


if __name__ == '__main__':
    ChainstateRecoveryTest(__file__).main()
