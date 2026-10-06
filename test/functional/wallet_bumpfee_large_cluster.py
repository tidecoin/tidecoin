#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fee bumping works at the maximum supported connected-component count.

The old 502-entry connected-component fixture is no longer admissible.
MiniMiner's 500-entry union cutoff remains covered by miniminer_tests.
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class BumpFeeLargeClusterTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Permit wallet selection at the node admission bound for this fixture.
        self.extra_args = [["-limitancestorcount=64", "-limitdescendantcount=64"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miniwallet = MiniWallet(node)
        self.generate(miniwallet, COINBASE_MATURITY + 1)

        # Give the wallet one branch and grow a separate branch of the same
        # parent. The transaction to bump itself must have no descendants.
        address = node.getnewaddress()
        # The raw target has no change output. Supply a confirmed wallet input
        # so fee bumping can fund the increase without reducing its recipient.
        miniwallet.send_to(from_node=node, scriptPubKey=bytes.fromhex(node.getaddressinfo(address)['scriptPubKey']), amount=10000000)
        self.generate(miniwallet, 1)
        parent = miniwallet.create_self_transfer_multi(num_outputs=2)
        parent["tx"].vout[0].scriptPubKey = bytes.fromhex(node.getaddressinfo(address)["scriptPubKey"])
        parent_id = miniwallet.sendrawtransaction(from_node=node, tx_hex=parent["tx"].serialize().hex())
        value = Decimal(parent["tx"].vout[0].nValue) / COIN
        raw = node.createrawtransaction(
            [{"txid": parent_id, "vout": 0}],
            [{node.getnewaddress(): value - Decimal("0.001")}],
            replaceable=True,
        )
        signed = node.signrawtransactionwithwallet(raw)
        assert signed["complete"]
        target = node.sendrawtransaction(signed["hex"])

        utxo = miniwallet.get_utxo(txid=parent_id, vout=1)
        for _ in range(62):
            utxo = miniwallet.send_self_transfer(from_node=node, utxo_to_spend=utxo)["new_utxo"]
        assert_equal(node.getmempoolentry(target)["descendantcount"], 1)
        assert_equal(node.getmempoolinfo()["size"], 64)

        extra = miniwallet.create_self_transfer(utxo_to_spend=utxo)
        assert_raises_rpc_error(-26, "too-large-cluster", node.sendrawtransaction, extra['hex'])
        assert node.psbtbumpfee(target, {"fee_rate": 1000})['psbt']
        bumped = node.bumpfee(target, {"fee_rate": 1000})['txid']
        assert target not in node.getrawmempool()
        assert bumped in node.getrawmempool()
        assert_equal(node.getmempoolinfo()["size"], 64)

        self.generate(node, 1)
        assert_equal(node.gettransaction(bumped)["confirmations"], 1)


if __name__ == "__main__":
    BumpFeeLargeClusterTest(__file__).main()
