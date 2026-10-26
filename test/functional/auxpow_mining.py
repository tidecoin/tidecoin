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
        self.test_cache_refresh()

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

    def test_cache_refresh(self):
        self.log.info("Check per-payout template refresh and retention until the next tip")
        node = self.nodes[0]
        self.generate(node, 1)
        wallet = MiniWallet(node)
        address_a = node.get_deterministic_priv_key().address
        address_b = self.nodes[1].get_deterministic_priv_key().address
        start = node.getblockheader(node.getbestblockhash())["time"] + 1

        def set_time(offset):
            for peer in self.nodes:
                peer.setmocktime(start + offset)

        set_time(0)
        a0 = node.createauxblock(address_a)
        set_time(30)
        b0 = node.createauxblock(address_b)
        assert a0["hash"] != b0["hash"]
        tx1 = wallet.send_self_transfer(from_node=node)
        self.sync_mempools()

        set_time(60)
        assert_equal(node.createauxblock(address_a), a0)
        set_time(61)
        a1 = node.createauxblock(address_a)
        assert a1["hash"] != a0["hash"]
        assert_equal(a1["coinbasevalue"], a0["coinbasevalue"] + int(tx1["fee"] * COIN))
        assert_equal(node.createauxblock(address_a), a1)
        assert_equal(node.createauxblock(address_b), b0)

        set_time(90)
        assert_equal(node.createauxblock(address_b), b0)
        set_time(91)
        b1 = node.createauxblock(address_b)
        assert b1["hash"] != b0["hash"]
        assert_equal(b1["coinbasevalue"], a1["coinbasevalue"])
        assert_equal(node.createauxblock(address_b), b1)
        assert_equal(node.createauxblock(address_a), a1)

        tx2 = wallet.send_self_transfer(from_node=node)
        self.sync_mempools()
        set_time(122)
        a2 = node.createauxblock(address_a)
        assert a2["hash"] != a1["hash"]
        assert_equal(a2["coinbasevalue"], a1["coinbasevalue"] + int(tx2["fee"] * COIN))
        assert_equal(node.createauxblock(address_b), b1)
        set_time(152)
        b2 = node.createauxblock(address_b)
        assert b2["hash"] != b1["hash"]
        assert_equal(b2["coinbasevalue"], a2["coinbasevalue"])
        assert_equal(node.createauxblock(address_a), a2)
        assert_equal(node.createauxblock(address_b), b2)

        # An unchanged mempool and a long interval do not expire outstanding work.
        set_time(3600)
        assert_equal(node.createauxblock(address_a), a2)
        assert_equal(node.createauxblock(address_b), b2)
        issued = (a0, b0, a1, b1, a2, b2)
        for template in issued:
            # A known template reaches proof decoding instead of "block hash unknown".
            assert_raises_rpc_error(-1, None, node.submitauxblock, template["hash"], "x")

        # Submit the oldest template after both payouts have refreshed twice.
        proof = computeAuxpow(a0["hash"], reverseHex(a0["_target"]), True)
        assert node.submitauxblock(a0["hash"], proof)
        self.sync_all()
        assert_equal(node.getbestblockhash(), a0["hash"])
        assert_equal(len(node.getblock(a0["hash"])["tx"]), 1)
        assert_equal(set(node.getrawmempool()), {tx1["txid"], tx2["txid"]})

        # A create request observes the new tip and invalidates every old lookup.
        next_a = node.createauxblock(address_a)
        next_b = node.createauxblock(address_b)
        assert_equal(next_a["previousblockhash"], a0["hash"])
        assert_equal(next_b["previousblockhash"], a0["hash"])
        for template in issued:
            assert_raises_rpc_error(-8, "block hash unknown", node.submitauxblock, template["hash"], "x")
        proof = computeAuxpow(next_b["hash"], reverseHex(next_b["_target"]), True)
        assert node.submitauxblock(next_b["hash"], proof)
        self.sync_all()
        assert_equal(set(node.getblock(next_b["hash"])["tx"][1:]), {tx1["txid"], tx2["txid"]})
        assert_equal(getCoinbaseAddr(node, next_b["hash"]), address_b)
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    AuxpowMiningTest(__file__).main()
