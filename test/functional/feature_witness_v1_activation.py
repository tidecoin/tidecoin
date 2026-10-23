#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Activate native 64-byte v1; preserve wrapped and reserved program behavior."""

from hashlib import sha512

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_TRUE
from test_framework.script_util import script_to_p2sh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class WitnessV1ActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-auxpowactivationheight=110"]]

    def candidate(self, transactions):
        return self.generateblock(self.nodes[0], ADDRESS_BCRT1_P2WSH_OP_TRUE, transactions,
                                  submit=False, sync_fun=self.no_op)

    def spend(self, batch, wrapped, *, witness=True, extra_sig=False, wrong_script=False, program=None, index=None):
        program = self.program if program is None else program
        tx = CTransaction()
        script_sig = CScript([OP_TRUE]) if extra_sig else CScript()
        if wrapped:
            script_sig = CScript(bytes(script_sig) + bytes(CScript([program])))
        tx.vin = [CTxIn(COutPoint(int(self.funding_id, 16), batch * 2 + int(wrapped) if index is None else index), script_sig)]
        tx.vout = [CTxOut(self.value - 10_000, self.mini.get_output_script())]
        if witness:
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(CScript([0])) if wrong_script else bytes(self.witness_script)]
        return tx.serialize().hex()

    def check_before(self, batch):
        node = self.nodes[0]
        for wrapped in (False, True):
            # Ordinary script evaluation permits these extra input pushes.
            assert "hex" in self.candidate([self.spend(batch, wrapped, witness=False, extra_sig=True)])
            assert "hex" in self.candidate([self.spend(batch, wrapped, witness=False)])
            raw = self.spend(batch, wrapped)
            assert_raises_rpc_error(-25, "Witness provided for non-witness script", self.candidate, [raw])
            # Relay policy also refuses this form before activation.
            assert_equal(node.testmempoolaccept([raw])[0]["allowed"], False)
        self.check_reserved()

    def check_after(self, batch):
        node = self.nodes[0]
        raw = self.spend(batch, False)
        assert_equal(node.testmempoolaccept([raw])[0]["allowed"], True)
        assert "hex" in self.candidate([raw])
        for invalid in (
            self.spend(batch, False, witness=False),
            self.spend(batch, False, extra_sig=True),
            self.spend(batch, False, wrong_script=True),
        ):
            assert_raises_rpc_error(-25, "block-script-verify-flag-failed", self.candidate, [invalid])

        # Wrapped 64-byte programs remain ordinary scripts at every height.
        for extra in (False, True):
            ordinary = self.spend(batch, True, witness=False, extra_sig=extra)
            assert "hex" in self.candidate([ordinary])
            rejected = node.testmempoolaccept([ordinary])[0]
            assert_equal(rejected["allowed"], False)
            assert "Stack size must be exactly one" in rejected["reject-reason"]
            assert_raises_rpc_error(-25, "Witness provided for non-witness script", self.candidate,
                                    [self.spend(batch, True, extra_sig=extra)])
        self.check_reserved()
        return [raw]

    def check_reserved(self):
        for index, length, wrapped, program in self.reserved:
            def spend(**kwargs):
                return self.spend(0, wrapped, index=index, program=program, **kwargs)
            for witness in (False, True):
                raw = spend(witness=witness)
                if length <= 40 or not witness:
                    assert "hex" in self.candidate([raw])
                else:
                    assert_raises_rpc_error(-25, "Witness provided for non-witness script", self.candidate, [raw])
                assert_equal(self.nodes[0].testmempoolaccept([raw])[0]["allowed"], False)
            # Short witness programs keep their scriptSig constraints; ordinary
            # 41-63-byte scripts continue to allow extra pushes.
            extra = spend(witness=False, extra_sig=True)
            if length <= 40:
                assert_raises_rpc_error(-25, "block-script-verify-flag-failed", self.candidate, [extra])
            else:
                assert "hex" in self.candidate([extra])

    def run_test(self):
        node = self.nodes[0]
        self.mini = MiniWallet(node)
        self.generate(self.mini, 101)
        self.witness_script = CScript([OP_TRUE])
        self.program = CScript([1, sha512(self.witness_script).digest()])
        self.value = 1_000_000
        funding = self.mini.create_self_transfer()
        total = funding["tx"].vout[0].nValue
        outputs = [
            CTxOut(self.value, script_to_p2sh_script(self.program) if wrapped else self.program)
            for _ in range(4) for wrapped in (False, True)
        ]
        self.reserved = []
        for length in (2, 20, 32, 40, 41, 63):
            program = CScript([1, bytes([1]) * length])
            for wrapped in (False, True):
                self.reserved.append((len(outputs), length, wrapped, program))
                outputs.append(CTxOut(self.value, script_to_p2sh_script(program) if wrapped else program))
        funding["tx"].vout = outputs + [CTxOut(total - len(outputs) * self.value, self.mini.get_output_script())]
        # Creating these outputs is permitted in blocks, while existing relay
        # policy intentionally refuses the new format before activation.
        self.funding_id = funding["tx"].txid_hex
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [funding["tx"].serialize().hex()])
        self.generate(self.mini, 6)
        assert_equal(node.getblockcount(), 108)

        self.log.info("Candidate H-1 uses ordinary script interpretation for native and P2SH forms")
        self.check_before(3)
        self.restart_node(0, extra_args=["-auxpowactivationheight=never"])
        self.check_before(3)
        self.restart_node(0, extra_args=self.extra_args[0])
        legacy = [self.spend(0, wrapped, witness=False, extra_sig=True) for wrapped in (False, True)]
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, legacy)
        assert_equal(node.getblockcount(), 109)
        last_before = node.getbestblockhash()

        for batch, height in ((1, 110), (2, 111)):
            self.log.info("Candidate %d enforces the witness script and accepts it into the mempool", height)
            raws = self.check_after(batch)
            txids = [node.sendrawtransaction(raw) for raw in raws]
            template = node.getblocktemplate({"rules": ["segwit"]})
            assert_equal(template["height"], height)
            assert set(txids) <= {entry["txid"] for entry in template["transactions"]}
            self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, txids)
            assert_equal(node.getblockcount(), height)

        tip = node.getbestblockhash()
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), tip)
        pending = [self.mini.sendrawtransaction(from_node=node, tx_hex=raw) for raw in self.check_after(3)]
        child = self.mini.send_self_transfer(from_node=node, utxo_to_spend=self.mini.get_utxo(txid=pending[0]))
        self.log.info("Rollback removes pending witness spends and their descendants")
        node.invalidateblock(last_before)
        assert_equal(node.getblockcount(), 108)
        removed = pending + [child["txid"]]
        removed += [node.decoderawtransaction(self.spend(batch, False))["txid"] for batch in (1, 2)]
        assert not set(removed) & set(node.getrawmempool())
        self.check_before(3)
        assert_equal(node.getblocktemplate({"rules": ["segwit"]})["height"], 109)
        node.reconsiderblock(last_before)
        assert_equal(node.getbestblockhash(), tip)
        self.check_after(3)


if __name__ == "__main__":
    WitnessV1ActivationTest(__file__).main()
