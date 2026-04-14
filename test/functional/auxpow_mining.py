#!/usr/bin/env python3
# Copyright (c) 2014-2019 Daniel Kraft
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test Tidecoin's merge-mining RPC interface:
  - getauxblock
  - createauxblock
  - submitauxblock
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

from test_framework.auxpow import reverseHex
from test_framework.auxpow_testing import (
    computeAuxpow,
    getCoinbaseAddr,
    mineAuxpowBlockWithMethods,
)
from test_framework.address import address_to_scriptpubkey
from test_framework.messages import CHAIN_ID, COIN
from test_framework.wallet import MiniWallet


class AuxpowMiningTest(BitcoinTestFramework):
    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[], []]

    def add_options(self, parser):
        parser.add_argument(
            "--segwit",
            dest="segwit",
            default=False,
            action="store_true",
            help="Test behaviour with SegWit active",
        )

    def run_test(self):
        # Optional: activate segwit (if this chain treats it like upstream regtest).
        if self.options.segwit:
            self.generate(self.nodes[0], 500)

        self.test_getauxblock()
        self.test_create_submit_auxblock()

    def test_common(self, create, submit):
        """Common code for getauxblock and createauxblock/submitauxblock."""

        # Verify returned auxblock fields.
        auxblock = create()
        assert_equal(auxblock["chainid"], CHAIN_ID)
        assert_equal(auxblock["height"], self.nodes[0].getblockcount() + 1)
        assert_equal(
            auxblock["previousblockhash"],
            self.nodes[0].getblockhash(auxblock["height"] - 1),
        )

        # Calling again should give the same block.
        auxblock2 = create()
        assert_equal(auxblock2, auxblock)

        # New tip replaces outstanding auxblock.
        self.sync_all()
        self.generate(self.nodes[1], 1)
        auxblock2 = create()
        assert auxblock["hash"] != auxblock2["hash"]
        assert_raises_rpc_error(-8, "block hash unknown", submit, auxblock["hash"], "x")

        # Invalid auxpow format.
        assert_raises_rpc_error(-1, None, submit, auxblock2["hash"], "x")

        # Add a tx and ensure the mined auxblock includes it (cross-check target with GBT).
        self.generate(self.nodes[0], 1)
        addr = self.nodes[1].get_deterministic_priv_key().address
        miniwallet = MiniWallet(self.nodes[0])
        txid = miniwallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=address_to_scriptpubkey(addr),
            amount=1 * COIN,
        )["txid"]
        self.sync_all()
        assert_equal(self.nodes[1].getrawmempool(), [txid])
        auxblock = create()
        target = reverseHex(auxblock["_target"])

        gbt = self.nodes[0].getblocktemplate({"rules": ["segwit"]})
        assert_equal(target, gbt["target"].encode("ascii"))

        # Submit invalid auxpow (valid structure, insufficient PoW).
        apow = computeAuxpow(auxblock["hash"], target, False)
        res = submit(auxblock["hash"], apow)
        assert not res

        # Submit valid auxpow.
        apow = computeAuxpow(auxblock["hash"], target, True)
        res = submit(auxblock["hash"], apow)
        assert res

        # Block accepted and mempool cleared.
        self.sync_all()
        assert_equal(self.nodes[1].getrawmempool(), [])
        height = self.nodes[1].getblockcount()
        assert_equal(height, auxblock["height"])
        assert_equal(self.nodes[1].getblockhash(height), auxblock["hash"])

        # getblock should contain auxpow JSON.
        data = self.nodes[1].getblock(auxblock["hash"])
        assert "auxpow" in data
        auxJson = data["auxpow"]
        assert_equal(auxJson["chainindex"], 0)
        assert_equal(auxJson["merklebranch"], [])
        assert_equal(auxJson["chainmerklebranch"], [])
        assert_equal(auxJson["parentblock"], apow[-160:])

        # Blocks mined with regular generate() should not have auxpow attached.
        oldHash = self.nodes[1].getblockhash(100)
        data = self.nodes[1].getblock(oldHash)
        assert "auxpow" not in data

        # Verify payout to node0.
        t = self.nodes[0].listtransactions("*", 1)
        assert_equal(len(t), 1)
        t = t[0]
        assert_equal(t["category"], "immature")
        assert_equal(t["blockhash"], auxblock["hash"])
        assert t["generated"]
        # Tidecoin's subsidy schedule is not Bitcoin's; just assert it paid a positive amount.
        assert_greater_than_or_equal(t["amount"], Decimal("0.00000001"))
        assert_equal(t["confirmations"], 1)

        # Verify BIP34 height in coinbase (skip for segwit height differences).
        if not self.options.segwit:
            blk = self.nodes[1].getblock(auxblock["hash"])
            tx = self.nodes[1].getrawtransaction(blk["tx"][0], True, blk["hash"])
            coinbase = tx["vin"][0]["coinbase"]
            assert_equal("02%02x00" % auxblock["height"], coinbase[0:6])

    def test_getauxblock(self):
        create = self.nodes[0].getauxblock
        submit = self.nodes[0].getauxblock
        self.test_common(create, submit)

        # Payout address changes across mined blocks.
        hash1 = mineAuxpowBlockWithMethods(create, submit)
        hash2 = mineAuxpowBlockWithMethods(create, submit)
        self.sync_all()
        addr1 = getCoinbaseAddr(self.nodes[1], hash1)
        addr2 = getCoinbaseAddr(self.nodes[1], hash2)
        assert addr1 != addr2

        info = self.nodes[0].getaddressinfo(addr1)
        assert info["ismine"]
        info = self.nodes[0].getaddressinfo(addr2)
        assert info["ismine"]

    def test_create_submit_auxblock(self):
        # Parameter validation.
        assert_raises_rpc_error(-1, None, self.nodes[0].createauxblock)
        assert_raises_rpc_error(
            -5, "Invalid coinbase payout address", self.nodes[0].createauxblock, "this_an_invalid_address"
        )

        addr1 = self.nodes[0].get_deterministic_priv_key().address

        def create():
            return self.nodes[0].createauxblock(addr1)

        submit = self.nodes[0].submitauxblock
        self.test_common(create, submit)

        # Payout address is the one we specify.
        hash1 = mineAuxpowBlockWithMethods(create, submit)
        hash2 = mineAuxpowBlockWithMethods(create, submit)
        self.sync_all()
        actual1 = getCoinbaseAddr(self.nodes[1], hash1)
        actual2 = getCoinbaseAddr(self.nodes[1], hash2)
        assert_equal(actual1, addr1)
        assert_equal(actual2, addr1)

        # Different payout address => different auxblock.
        addr2 = self.nodes[1].get_deterministic_priv_key().address
        auxblock1 = self.nodes[0].createauxblock(addr1)
        auxblock2 = self.nodes[0].createauxblock(addr2)
        assert auxblock1["hash"] != auxblock2["hash"]


if __name__ == "__main__":
    AuxpowMiningTest(__file__).main()
