#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logic for setting nMinimumChainWork on command line.

Nodes don't consider themselves out of "initial block download" until
their active chain has more work than nMinimumChainWork.

Nodes don't download blocks from a peer unless the peer's best known block
has more work than nMinimumChainWork.

While in initial block download, nodes won't relay blocks to their peers, so
test that this parameter functions as intended by verifying that block relay
only succeeds past a given node once its nMinimumChainWork has been exceeded.
"""

import time

from test_framework.p2p import P2PInterface, msg_getheaders
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    ensure_for,
)

class MinimumChainWorkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

        self.extra_args = [[], ["-minimumchainwork=0x65"], ["-minimumchainwork=0x65"]]
        self.node_min_work = [0, 101, 101]

    def setup_network(self):
        # This test relies on the chain setup being:
        # node0 <- node1 <- node2
        # Before leaving IBD, nodes prefer to download blocks from outbound
        # peers, so ensure that we're mining on an outbound peer and testing
        # block relay to inbound peers.
        self.setup_nodes()
        for i in range(self.num_nodes-1):
            self.connect_nodes(i+1, i)

        # Set clock of node2 2 days ahead, to keep it in IBD during this test.
        self.nodes[2].setmocktime(int(time.time()) + 48*60*60)

    def run_test(self):
        # Start building a chain on node0.  node2 shouldn't be able to sync until node1's
        # minchainwork is exceeded
        self.log.info(f"Testing relay across node 1 (minChainWork = {self.node_min_work[1]})")

        starting_blockcount = self.nodes[2].getblockcount()

        # Build the below-threshold chain while node0 is isolated. Otherwise,
        # the throwaway block that crosses the threshold below can be relayed
        # before invalidateblock returns, making the "below threshold" check
        # race against legitimate block download.
        self.disconnect_nodes(1, 0)

        # Mine until just below minchainwork. Work-per-block is chain specific.
        self.log.info("Generating blocks on node0 up to just below minchainwork")
        while True:
            besthash = self.nodes[0].getbestblockhash()
            current_chain_work = int(self.nodes[0].getblockheader(besthash)['chainwork'], 16)
            if current_chain_work >= self.node_min_work[1]:
                raise AssertionError("minimumchainwork threshold reached too early; expected to stop below threshold")
            hashes = self.generate(self.nodes[0], 1, sync_fun=self.no_op)
            next_chain_work = int(self.nodes[0].getblockheader(hashes[-1])['chainwork'], 16)
            if next_chain_work >= self.node_min_work[1]:
                # We crossed threshold with this block; invalidate it so we can test the below-threshold state.
                self.nodes[0].invalidateblock(hashes[-1])
                break

        besthash_below_threshold = self.nodes[0].getbestblockhash()
        self.log.info(f"Node0 current chain work: {self.nodes[0].getblockheader(besthash_below_threshold)['chainwork']}")
        self.connect_nodes(1, 0)

        self.log.info("Verifying node 2 has no more blocks than before")
        self.log.info(f"Blockcounts: {[n.getblockcount() for n in self.nodes]}")
        # Node2 shouldn't have any new headers yet, because node1 should not
        # have relayed anything.
        # We wait 3 seconds, rather than sync_blocks(node0, node1) because
        # it's reasonable either way for node1 to get the blocks, or not get
        # them (since they're below node1's minchainwork).
        ensure_for(duration=3, f=lambda: len(self.nodes[2].getchaintips()) == 1)
        assert_equal(self.nodes[2].getblockcount(), starting_blockcount)

        self.log.info("Check that getheaders requests to node2 are ignored")
        peer = self.nodes[2].add_p2p_connection(P2PInterface())
        msg = msg_getheaders()
        msg.locator.vHave = [int(self.nodes[2].getbestblockhash(), 16)]
        msg.hashstop = 0
        peer.send_and_ping(msg)
        ensure_for(duration=5, f=lambda: "headers" not in peer.last_message or len(peer.last_message["headers"].headers) == 0)

        self.log.info("Generating one more block")
        self.generate(self.nodes[0], 1)

        self.log.info("Verifying nodes are all synced")

        # Because nodes in regtest are all manual connections (eg using
        # addnode), node1 should not have disconnected node0. If not for that,
        # we'd expect node1 to have disconnected node0 for serving an
        # insufficient work chain, in which case we'd need to reconnect them to
        # continue the test.

        self.sync_all()
        self.log.info(f"Blockcounts: {[n.getblockcount() for n in self.nodes]}")

        self.log.info("Test that getheaders requests to node2 are not ignored")
        peer.send_and_ping(msg)
        assert "headers" in peer.last_message

        # Verify that node2 is in fact still in IBD (otherwise this test may
        # not be exercising the logic we want!)
        assert_equal(self.nodes[2].getblockchaininfo()['initialblockdownload'], True)

        self.log.info("Test -minimumchainwork with a non-hex value")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            ["-minimumchainwork=test"],
            expected_msg='Error: Invalid minimum work specified (test), must be up to 64 hex digits',
        )


if __name__ == '__main__':
    MinimumChainWorkTest(__file__).main()
