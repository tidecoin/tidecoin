#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Additional signature schemes become eligible at AuxPoW activation."""

from decimal import Decimal

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script_util import key_to_p2pkh_script, key_to_p2wpkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


class PQSchemeActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-auxpowactivationheight=110"], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # The second node signs under postactivation rules, independently of the
        # funding chain. This avoids relying on preactivation wallet restrictions.
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def check_before_activation(self, node, rows):
        for scheme, kind, raw in rows:
            expected = scheme == "falcon512"
            result = node.testmempoolaccept([raw])[0]
            assert_equal(result["allowed"], expected)
            if not expected:
                assert "script" in result["reject-reason"], (scheme, kind, result)
                assert_raises_rpc_error(-26, "script", node.sendrawtransaction, raw)
                # generateblock calls TestBlockValidity before solving the block,
                # independently of whether the transaction is in the mempool.
                assert_raises_rpc_error(
                    -25, "block-script-verify-flag-failed",
                    self.generateblock, node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [raw],
                    submit=False, sync_fun=self.no_op,
                )
            else:
                candidate = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [raw], submit=False, sync_fun=self.no_op)
                assert "hex" in candidate

    def run_test(self):
        node, signer = self.nodes
        mini = MiniWallet(node)
        self.generate(mini, 101, sync_fun=self.no_op)
        schemes = ["falcon512", "falcon1024", "mldsa44", "mldsa65", "mldsa87"]
        keys = [(scheme, *generate_keypair(scheme=str(7 + index))) for index, scheme in enumerate(schemes)]
        value = 1_000_000
        funding = mini.create_self_transfer()
        total = funding["tx"].vout[0].nValue
        outputs = []
        entries = []
        for batch in range(3):
            for scheme, secret, pubkey in keys:
                for kind, script in [("base", key_to_p2pkh_script(pubkey)), ("v0", key_to_p2wpkh_script(pubkey))]:
                    entries.append((batch, scheme, kind, secret, script))
                    outputs.append(CTxOut(value, script))
        funding["tx"].vout = outputs + [CTxOut(total - value * len(outputs), mini.get_output_script())]
        funding_id = mini.sendrawtransaction(from_node=node, tx_hex=funding["tx"].serialize().hex())
        self.generate(mini, 7, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 108)

        batches = [[], [], []]
        for index, (batch, scheme, kind, secret, script) in enumerate(entries):
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(funding_id, 16), index))]
            tx.vout = [CTxOut(value - 10_000, mini.get_output_script())]
            signed = signer.signrawtransactionwithkey(
                tx.serialize().hex(), [secret],
                [{"txid": funding_id, "vout": index, "scriptPubKey": script.hex(), "amount": Decimal(value) / COIN}],
            )
            assert signed["complete"], (scheme, kind, signed)
            batches[batch].append((scheme, kind, signed["hex"]))

        self.log.info("At H-1, only Falcon-512 signatures authorize BASE and witness-v0 spends")
        self.check_before_activation(node, batches[0])
        self.log.info("Activation disabled and restart preserve the same rule")
        self.restart_node(0, extra_args=["-auxpowactivationheight=never"])
        self.check_before_activation(node, batches[0])
        self.restart_node(0, extra_args=self.extra_args[0])
        controls = [raw for scheme, _, raw in batches[0] if scheme == "falcon512"]
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, controls, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 109)
        last_pre_activation = node.getbestblockhash()

        for batch, height in [(1, 110), (2, 111)]:
            self.log.info("All five schemes pass admission, templates and blocks at height %d", height)
            txids = []
            for _, _, raw in batches[batch]:
                assert node.testmempoolaccept([raw])[0]["allowed"]
                txids.append(node.sendrawtransaction(raw))
            template = node.getblocktemplate({"rules": ["segwit"]})
            assert_equal(template["height"], height)
            assert set(txids) <= {tx["txid"] for tx in template["transactions"]}
            self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, txids, sync_fun=self.no_op)
            assert_equal(node.getblockcount(), height)

        tip = node.getbestblockhash()
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), tip)
        pending = []
        for scheme, _, raw in batches[0]:
            if scheme != "falcon512":
                pending.append(mini.sendrawtransaction(from_node=node, tx_hex=raw))
        child = mini.send_self_transfer(from_node=node, utxo_to_spend=mini.get_utxo(txid=pending[0]))
        self.log.info("After disconnecting across activation, cached results cannot authorize early spends")
        node.invalidateblock(last_pre_activation)
        assert_equal(node.getblockcount(), 108)
        # Falcon controls may have returned to the mempool; only the additional
        # schemes must be absent and fail checks under preactivation rules.
        new_scheme_rows = [row for row in batches[1] if row[0] != "falcon512"]
        for _, _, raw in new_scheme_rows:
            txid = node.decoderawtransaction(raw)["txid"]
            assert txid not in node.getrawmempool()
        assert not set(pending + [child["txid"]]) & set(node.getrawmempool())
        for scheme, _, raw in batches[1]:
            if scheme == "falcon512":
                assert node.decoderawtransaction(raw)["txid"] in node.getrawmempool()
        self.check_before_activation(node, new_scheme_rows)
        assert_equal(node.getblocktemplate({"rules": ["segwit"]})["height"], 109)
        node.reconsiderblock(last_pre_activation)
        assert_equal(node.getbestblockhash(), tip)


if __name__ == "__main__":
    PQSchemeActivationTest(__file__).main()
