#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Check received AuxPoW proofs in both sync passes and independently in full blocks."""

from auxpow_alternate_proof import make_auxpow
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CBlock, CBlockHeader, msg_headers
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class HeadersPeer(P2PInterface):
    def on_getheaders(self, message):
        pass


class HeadersSyncAuxpowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-minimumchainwork=0x10000", "-checkblockindex=1"]]

    def run_test(self):
        node = self.nodes[0]
        genesis = node.getblockheader(node.getblockhash(0))
        previous = int(genesis["hash"], 16)
        blocks = []
        for height in range(1, 4001):
            block = create_block(previous, create_coinbase(height, halving_period=20), genesis["time"] + height)
            block.nBits = int(genesis["bits"], 16)
            block.set_auxpow_version(True)
            block.auxpow = make_auxpow(block.hash_hex, block.nBits, b"")
            blocks.append(block)
            previous = block.hash_int
        batches = [[CBlockHeader(b) for b in blocks[start:start + 2000]] for start in [0, 2000]]

        for phase in ["presync", "redownload"]:
            self.log.info("Reject an invalid proof during %s", phase)
            peer = node.add_p2p_connection(HeadersPeer())
            if phase == "redownload":
                for batch in batches:
                    peer.send_and_ping(msg_headers(batch))
            bad = [CBlockHeader(header) for header in batches[0]]
            bad[0].auxpow.nChainIndex = 1
            with node.assert_debug_log(["header with invalid proof of work"]):
                peer.send_without_ping(msg_headers(bad))
                peer.wait_for_disconnect()
            assert_equal(node.getblockchaininfo()["headers"], 0)

        self.log.info("Accept valid proofs through both passes")
        peer = node.add_p2p_connection(HeadersPeer())
        for _ in range(2):
            for batch in batches:
                peer.send_and_ping(msg_headers(batch))
        assert_equal(node.getblockchaininfo()["headers"], 4000)

        self.log.info("An indexed child header does not excuse an invalid full-block proof")
        bad_block = CBlock(blocks[0])
        bad_block.vtx = blocks[0].vtx
        bad_block.auxpow.nChainIndex = 1
        assert_equal(node.submitblock(bad_block.serialize().hex()), "auxpow-invalid")
        assert_equal(node.getblockcount(), 0)
        assert_equal(node.submitblock(blocks[0].serialize().hex()), None)
        assert_equal(node.getblockcount(), 1)


if __name__ == '__main__':
    HeadersSyncAuxpowTest(__file__).main()
