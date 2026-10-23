#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Falcon signatures must consume their compressed encoding exactly."""

from decimal import Decimal
from hashlib import sha512

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut, tx_from_hex
from test_framework.script import CScript, OP_1
from test_framework.script_util import key_to_p2pk_script, key_to_p2pkh_script, key_to_p2wpkh_script, script_to_p2sh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_not_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


class FalconEncodingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-auxpowactivationheight=110"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def candidate(self, raw):
        return self.generateblock(self.nodes[0], ADDRESS_BCRT1_P2WSH_OP_TRUE, [raw],
                                  submit=False, sync_fun=self.no_op)

    def check_encoding(self, row):
        node = self.nodes[0]
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(self.funding_id, 16), row["vout"]))]
        tx.vout = [CTxOut(self.value - 10_000, self.mini.get_output_script())]
        previous = {"txid": self.funding_id, "vout": row["vout"],
                    "scriptPubKey": row["output"].hex(), "amount": Decimal(self.value) / COIN}
        if "redeem" in row:
            previous["redeemScript"] = row["redeem"].hex()
        if "witness_script" in row:
            previous["witnessScript"] = row["witness_script"].hex()

        # Find a signature to which the old verifier's fixed-length padding
        # exception would apply. Production signatures remain variable-length.
        for _ in range(100):
            signed = node.signrawtransactionwithkey(tx.serialize().hex(), [row["secret"]], [previous])
            assert_equal(signed["complete"], True)
            original = tx_from_hex(signed["hex"])
            stack = original.wit.vtxinwit[0].scriptWitness.stack if row["witness"] else list(CScript(original.vin[0].scriptSig))
            signature = stack[0]
            if len(signature) - 1 < row["padded_size"]:
                break
        else:
            raise AssertionError("Could not obtain a short compressed Falcon signature")

        assert_equal(node.testmempoolaccept([signed["hex"]])[0]["allowed"], True)
        assert "hex" in self.candidate(signed["hex"])

        # Keep the sighash byte last. Only the Falcon serialization changes.
        padded = tx_from_hex(signed["hex"])
        stack = padded.wit.vtxinwit[0].scriptWitness.stack if row["witness"] else list(CScript(padded.vin[0].scriptSig))
        stack[0] = signature[:-1].ljust(row["padded_size"], b"\x00") + signature[-1:]
        if not row["witness"]:
            padded.vin[0].scriptSig = CScript(stack)
        assert_not_equal(padded.wtxid_hex, original.wtxid_hex)
        if row["witness"]:
            assert_equal(padded.txid_hex, original.txid_hex)
        else:
            assert_not_equal(padded.txid_hex, original.txid_hex)

        raw = padded.serialize().hex()
        result = node.testmempoolaccept([raw])[0]
        assert_equal(result["allowed"], False)
        assert "script" in result["reject-reason"], result
        assert_raises_rpc_error(-26, "script", node.sendrawtransaction, raw)
        assert_raises_rpc_error(-25, "block-script-verify-flag-failed", self.candidate, raw)
        # Rejected alternate bytes must not prevent the original from validating.
        assert_equal(node.testmempoolaccept([signed["hex"]])[0]["allowed"], True)
        assert "hex" in self.candidate(signed["hex"])
        return signed["hex"]

    def check_legacy(self):
        self.log.info("Legacy Falcon-512 also rejects padding, including after rollback")
        for row in self.rows:
            if row["scheme"] == 7 and row["form"] != "wsh512":
                self.check_encoding(row)

    def check_strict(self):
        self.log.info("Strict Falcon encoding at candidate height %d", self.nodes[0].getblockcount() + 1)
        return [self.check_encoding(row) for row in self.rows]

    def run_test(self):
        node = self.nodes[0]
        self.mini = MiniWallet(node)
        self.generate(self.mini, 101)
        self.value = 1_000_000
        self.rows = []
        outputs = []
        for scheme, padded_size in ((7, 666), (8, 1280)):
            secret, pubkey = generate_keypair(scheme=str(scheme))
            for form in ("pkh", "sh_pkh", "wpkh", "sh_wpkh", "wsh512"):
                row = {"scheme": scheme, "padded_size": padded_size, "secret": secret,
                       "form": form, "witness": form in ("wpkh", "sh_wpkh", "wsh512"), "vout": len(outputs)}
                if form in ("pkh", "sh_pkh"):
                    output = key_to_p2pkh_script(pubkey)
                elif form in ("wpkh", "sh_wpkh"):
                    output = key_to_p2wpkh_script(pubkey)
                else:
                    row["witness_script"] = key_to_p2pk_script(pubkey)
                    output = CScript([OP_1, sha512(row["witness_script"]).digest()])
                if form.startswith("sh_"):
                    row["redeem"] = output
                    output = script_to_p2sh_script(output)
                row["output"] = output
                self.rows.append(row)
                outputs.append(CTxOut(self.value, output))

        funding = self.mini.create_self_transfer()["tx"]
        change = funding.vout[0].nValue - len(outputs) * self.value
        funding.vout = outputs + [CTxOut(change, self.mini.get_output_script())]
        self.funding_id = funding.txid_hex
        # Native v1 funding is allowed in blocks before activation.
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [funding.serialize().hex()])
        self.generate(self.mini, 6)
        assert_equal(node.getblockcount(), 108)
        self.check_legacy()
        last_before = self.generate(self.mini, 1)[0]
        self.check_strict()  # Candidate activation block, height 110.
        self.generate(self.mini, 1)
        self.check_strict()
        node.invalidateblock(last_before)
        assert_equal(node.getblockcount(), 108)
        self.check_legacy()
        node.reconsiderblock(last_before)
        assert_equal(node.getblockcount(), 110)
        originals = self.check_strict()
        mined = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, originals)
        assert_equal(len(node.getblock(mined["hash"])["tx"]), 1 + len(originals))


if __name__ == "__main__":
    FalconEncodingTest(__file__).main()
