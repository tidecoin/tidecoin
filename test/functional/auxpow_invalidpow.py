#!/usr/bin/env python3
# Copyright (c) 2019 Daniel Kraft
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Submit a valid AuxPoW-marked block with invalid AuxPoW.

The block should not be accepted, but it also must NOT be marked as permanently
invalid. Resubmitting the same block with valid AuxPoW should then work.
"""

from io import BytesIO

from test_framework.auxpow_testing import computeAuxpow
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CAuxPow, uint256_from_compact
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AuxpowInvalidPoWTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1"]]

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())

        self.log.info("Sending block with invalid AuxPoW over P2P...")
        tip = node.getbestblockhash()
        blk, blkHash = self.createBlock()
        blk = self.addAuxpow(blk, blkHash, False)
        node.p2ps[0].send_blocks_and_test(
            [blk],
            node,
            force_send=True,
            success=False,
            reject_reason="auxpow-parent-pow",
        )
        assert_equal(node.getbestblockhash(), tip)

        self.log.info("Sending the same block with valid AuxPoW...")
        blk = self.addAuxpow(blk, blkHash, True)
        node.p2ps[0].send_blocks_and_test([blk], node, success=True)
        assert_equal(node.getbestblockhash(), blkHash)

        self.log.info("Submitting block with invalid AuxPoW...")
        tip = node.getbestblockhash()
        blk, blkHash = self.createBlock()
        blk = self.addAuxpow(blk, blkHash, False)
        assert_equal(node.submitblock(blk.serialize().hex()), "auxpow-parent-pow")
        assert_equal(node.getbestblockhash(), tip)

        self.log.info("Submitting block with valid AuxPoW...")
        blk = self.addAuxpow(blk, blkHash, True)
        assert_equal(node.submitblock(blk.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), blkHash)

    def createBlock(self):
        """
        Create a block for the current tip. It is marked as auxpow, but the
        auxpow is not yet filled in.
        """
        node = self.nodes[0]
        bestHash = node.getbestblockhash()
        bestBlock = node.getblock(bestHash)
        tip = int(bestHash, 16)
        height = bestBlock["height"] + 1
        ntime = bestBlock["time"] + 1

        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        coinbase = create_coinbase(height)
        coinbase.vout[0].nValue = tmpl["coinbasevalue"]

        block = create_block(tip, coinbase, ntime, tmpl=tmpl, use_auxpow=False)
        block.set_auxpow_version(True)
        blkHash = block.hash_hex
        return block, blkHash

    def addAuxpow(self, block, blkHash, ok):
        """
        Fill in auxpow for the given block. Chosen to be valid (ok=True) or
        invalid (ok=False) w.r.t. parent PoW.
        """
        target = b"%064x" % uint256_from_compact(block.nBits)
        auxpowHex = computeAuxpow(blkHash, target, ok)
        block.auxpow = CAuxPow()
        block.auxpow.deserialize(BytesIO(bytes.fromhex(auxpowHex)))
        return block


if __name__ == "__main__":
    AuxpowInvalidPoWTest(__file__).main()
