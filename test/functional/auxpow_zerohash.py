#!/usr/bin/env python3
# Copyright (c) 2019 Daniel Kraft
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Smoke-test AuxPoW blocks can be submitted and retrieved (RPC + P2P).

Historically, the 'hashBlock' field inside the MerkleTx portion of AuxPoW is
ignored by validation and may be zeroed out on serialization. This test focuses
on ensuring AuxPoW blocks round-trip through node interfaces.
"""

from io import BytesIO

from test_framework.auxpow_testing import computeAuxpow
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CAuxPow,
    CBlock,
    CInv,
    msg_getdata,
    uint256_from_compact,
)
from test_framework.p2p import P2PDataStore, P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PBlockGetter(P2PInterface):
    """P2P connection that can request a block by hash and return the parsed CBlock."""

    def on_block(self, message):
        self.block = message.block

    def getBlock(self, blkHash):
        self.block = None
        inv = CInv(t=2, h=int(blkHash, 16))
        self.send_without_ping(msg_getdata(inv=[inv]))
        self.wait_until(lambda: self.block is not None)
        return self.block


class AuxpowZeroHashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1"]]

    def run_test(self):
        node = self.nodes[0]
        p2pStore = node.add_p2p_connection(P2PDataStore())
        p2pGetter = node.add_p2p_connection(P2PBlockGetter())

        self.log.info("Adding a block with AuxPoW...")
        blk, blkHash = self.createBlock()
        assert_equal(node.submitblock(blk.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), blkHash)

        self.log.info("Retrieving block through RPC...")
        gotHex = node.getblock(blkHash, 0)
        gotBlk = CBlock()
        gotBlk.deserialize(BytesIO(bytes.fromhex(gotHex)))
        assert gotBlk.auxpow is not None
        # Tidecoin serializes MerkleTx.hashBlock inside AuxPoW as zero (see src/auxpow.h).
        assert_equal(gotBlk.auxpow.hashBlock, 0)

        self.log.info("Retrieving block through P2P...")
        gotBlk = p2pGetter.getBlock(blkHash)
        assert gotBlk.auxpow is not None
        assert_equal(gotBlk.auxpow.hashBlock, 0)

        self.log.info("Submitting another AuxPoW block through RPC...")
        blk, blkHash = self.createBlock()
        assert_equal(node.submitblock(blk.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), blkHash)

        self.log.info("Submitting AuxPoW block through P2P...")
        blk, blkHash = self.createBlock()
        p2pStore.send_blocks_and_test([blk], node, success=True)
        assert_equal(node.getbestblockhash(), blkHash)

    def createBlock(self):
        """Create and mine a new block with AuxPoW."""
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

        target = b"%064x" % uint256_from_compact(block.nBits)
        auxpowHex = computeAuxpow(blkHash, target, True)
        block.auxpow = CAuxPow()
        block.auxpow.deserialize(BytesIO(bytes.fromhex(auxpowHex)))

        return block, blkHash


if __name__ == "__main__":
    AuxpowZeroHashTest(__file__).main()
