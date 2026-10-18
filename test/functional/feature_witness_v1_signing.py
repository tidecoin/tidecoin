#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Signed witness-v1 payments across all PQ schemes at and after activation."""

from decimal import Decimal
from hashlib import sha256, sha512

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut, tx_from_hex
from test_framework.script import CScript, OP_0, OP_1, OP_TRUE
from test_framework.script_util import key_to_p2pk_script, key_to_p2wpkh_script, script_to_p2sh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


class WitnessV1SigningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-auxpowactivationheight=110"], ["-auxpowactivationheight=1"]]

    def setup_network(self):
        self.setup_nodes()  # Keep the second node offline for caller-supplied amount tests.

    def sync_all(self, nodes=None):
        pass

    def add_options(self, parser):
        parser.add_argument("--direct-only", action="store_true", help="Run only direct witness-v1 payments")

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def candidate(self, raw):
        return self.generateblock(self.nodes[0], ADDRESS_BCRT1_P2WSH_OP_TRUE, [raw],
                                  submit=False, sync_fun=self.no_op)

    def unsigned_spend(self, row):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(self.funding_id, 16), row["vout"]), nSequence=0xfffffffe)]
        tx.vout = [CTxOut(self.value - 10_000, self.mini.get_output_script())]
        return tx

    def prevout(self, row, *, amount_delta=0):
        previous = {
            "txid": self.funding_id,
            "vout": row["vout"],
            "scriptPubKey": row["output"].hex(),
            "witnessScript": row["script"].hex(),
            "amount": Decimal(self.value + amount_delta) / COIN,
        }
        if row["wrapped"]:
            previous["redeemScript"] = row["program"].hex()
        return previous

    def reject(self, raw, label):
        node = self.nodes[0]
        result = node.testmempoolaccept([raw])[0]
        assert_equal(result["allowed"], False)
        assert "script" in result["reject-reason"], (label, result)
        assert_raises_rpc_error(-26, "script", node.sendrawtransaction, raw)
        # Check explicit block validation too, independently of relay policy.
        assert_raises_rpc_error(-25, "block-script-verify-flag-failed", self.candidate, raw)
        self.rejections += 1

    def signed_payment(self, row):
        node = self.nodes[0]
        label = f'{row["scheme"]}/{"p2sh" if row["wrapped"] else "direct"}'
        self.log.info("Sign and validate %s at candidate height %d", label, node.getblockcount() + 1)
        unsigned = self.unsigned_spend(row).serialize().hex()
        signed = node.signrawtransactionwithkey(unsigned, [row["secret"]], [self.prevout(row)], "ALL")
        assert_equal(signed["complete"], True)
        raw = signed["hex"]
        tx = tx_from_hex(raw)
        assert_equal(tx.vin[0].scriptSig, bytes(CScript([row["program"]])) if row["wrapped"] else b"")
        assert_equal(len(tx.wit.vtxinwit[0].scriptWitness.stack), 2)
        assert_equal(tx.wit.vtxinwit[0].scriptWitness.stack[-1], row["script"])
        assert_equal(tx.wit.vtxinwit[0].scriptWitness.stack[0][-1], 1)  # SIGHASH_ALL
        assert_equal(node.testmempoolaccept([raw])[0]["allowed"], True)
        assert "hex" in self.candidate(raw)

        if row["wrapped"]:
            # The explicit wrapper, witnessScript-only, and historical
            # redeemScript-only forms must all describe the same output.
            for fields in ({"witnessScript": row["script"].hex()},
                           {"redeemScript": row["script"].hex()},
                           {"witnessScript": row["script"].hex(), "redeemScript": row["script"].hex()}):
                previous = self.prevout(row)
                previous.pop("redeemScript")
                previous.pop("witnessScript")
                previous.update(fields)
                alternate = node.signrawtransactionwithkey(unsigned, [row["secret"]], [previous], "ALL")
                assert_equal(alternate["complete"], True)
                assert_equal(node.testmempoolaccept([alternate["hex"]])[0]["allowed"], True)

            previous = self.prevout(row)
            previous["redeemScript"] = CScript([OP_1, bytes(64)]).hex()
            assert_raises_rpc_error(-8, "redeemScript does not correspond to witnessScript",
                                    node.signrawtransactionwithkey, unsigned, [row["secret"]], [previous], "ALL")
            # A valid v0 wrapper for the same script still does not match this
            # output's P2SH commitment to a v1 wrapper.
            previous["redeemScript"] = CScript([OP_0, sha256(row["script"]).digest()]).hex()
            assert_raises_rpc_error(-8, "redeemScript/witnessScript does not match scriptPubKey",
                                    node.signrawtransactionwithkey, unsigned, [row["secret"]], [previous], "ALL")
            previous["witnessScript"] = bytes(CScript([OP_TRUE])).hex()
            previous["redeemScript"] = CScript([OP_1, sha512(bytes(CScript([OP_TRUE]))).digest()]).hex()
            assert_raises_rpc_error(-8, "redeemScript/witnessScript does not match scriptPubKey",
                                    node.signrawtransactionwithkey, unsigned, [row["secret"]], [previous], "ALL")

        # A different key must not produce a complete spend for this script.
        wrong_key = node.signrawtransactionwithkey(unsigned, [row["other_secret"]], [self.prevout(row)], "ALL")
        assert_equal(wrong_key["complete"], False)

        # Validate changes after a successful check has already filled caches.
        for change in ("signature", "missing_signature", "script", "output_value", "output_script", "locktime", "sequence", "previous_output"):
            changed = tx_from_hex(raw)
            stack = changed.wit.vtxinwit[0].scriptWitness.stack
            if change == "signature":
                signature = bytearray(stack[0])
                signature[len(signature) // 2] ^= 1
                stack[0] = bytes(signature)
            elif change == "missing_signature":
                stack[0] = b""
            elif change == "script":
                stack[-1] = bytes(CScript([OP_TRUE]))
            elif change == "output_value":
                changed.vout[0].nValue -= 1
            elif change == "output_script":
                changed.vout[0].scriptPubKey = key_to_p2wpkh_script(row["pubkey"])
            elif change == "locktime":
                changed.nLockTime = 1  # Still final at these heights.
            elif change == "sequence":
                changed.vin[0].nSequence = 0xfffffffd  # Relative locktime remains disabled.
            elif change == "previous_output":
                # This is a real, unspent output with identical script and amount.
                # Rejection must concern the signature, not a missing input.
                changed.vin[0].prevout.n = row["vout"] + 1
            self.reject(changed.serialize().hex(), f"{label}/{change}")

        # The signing RPC can work from caller-supplied amounts. Sign using a
        # wrong amount, then verify against the actual on-chain output amount.
        assert_raises_rpc_error(-22, "Previous output amount mismatch", node.signrawtransactionwithkey,
                                unsigned, [row["secret"]], [self.prevout(row, amount_delta=1)], "ALL")
        wrong_amount = self.nodes[1].signrawtransactionwithkey(unsigned, [row["secret"]], [self.prevout(row, amount_delta=1)], "ALL")
        assert_equal(wrong_amount["complete"], True)
        self.reject(wrong_amount["hex"], f"{label}/previous_amount")

        # The unchanged payment still succeeds after all negative checks.
        assert_equal(node.testmempoolaccept([raw])[0]["allowed"], True)
        txid = node.sendrawtransaction(raw)
        assert_equal(txid, tx.txid_hex)
        return txid

    def run_test(self):
        node = self.nodes[0]
        self.mini = MiniWallet(node)
        self.generate(self.mini, 101)
        self.value = 1_000_000
        self.rejections = 0
        schemes = ["falcon512", "falcon1024", "mldsa44", "mldsa65", "mldsa87"]
        keys = []
        for index, scheme in enumerate(schemes):
            secret, pubkey = generate_keypair(scheme=str(7 + index))
            other_secret, _ = generate_keypair(scheme=str(7 + index))
            keys.append((scheme, secret, pubkey, other_secret))

        funding = self.mini.create_self_transfer()
        total = funding["tx"].vout[0].nValue
        outputs = []
        batches = [[], []]
        for rows in batches:
            for scheme, secret, pubkey, other_secret in keys:
                script = key_to_p2pk_script(pubkey)
                program = CScript([OP_1, sha512(script).digest()])
                for wrapped in ((False,) if self.options.direct_only else (False, True)):
                    output = script_to_p2sh_script(program) if wrapped else program
                    rows.append({"scheme": scheme, "secret": secret, "pubkey": pubkey, "other_secret": other_secret,
                                 "script": script, "program": program, "output": output, "wrapped": wrapped, "vout": len(outputs)})
                    outputs.extend([CTxOut(self.value, output), CTxOut(self.value, output)])
        funding["tx"].vout = outputs + [CTxOut(total - len(outputs) * self.value, self.mini.get_output_script())]
        self.funding_id = funding["tx"].txid_hex
        # These future-format outputs are consensus-valid to create, but their
        # creation is intentionally not relayed before activation.
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [funding["tx"].serialize().hex()])
        self.generate(self.mini, 7)
        assert_equal(node.getblockcount(), 109)

        payments = []
        for rows, height in zip(batches, (110, 111)):
            txids = [self.signed_payment(row) for row in rows]
            assert_equal(set(node.getrawmempool()), set(txids))
            template = node.getblocktemplate({"rules": ["segwit"]})
            assert_equal(template["height"], height)
            assert set(txids) <= {entry["txid"] for entry in template["transactions"]}
            # Each script contains exactly one signature check.
            assert all(entry["sigops"] == 1 for entry in template["transactions"] if entry["txid"] in txids)
            mined = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, txids)
            block_hash = mined["hash"]
            assert_equal(node.getblockcount(), height)
            assert_equal(set(node.getblock(block_hash)["tx"][1:]), set(txids))
            for row, txid in zip(rows, txids):
                assert_equal(node.gettxout(self.funding_id, row["vout"]), None)
                assert node.gettxout(self.funding_id, row["vout"] + 1) is not None
                assert_equal(node.gettxout(txid, 0)["value"], Decimal(self.value - 10_000) / COIN)
            assert_equal(node.getrawmempool(), [])
            payments.extend(txids)
            # The second round also checks signing after a node restart.
            self.restart_node(0)
            assert_equal(node.getbestblockhash(), block_hash)

        expected_payments = 10 if self.options.direct_only else 20
        assert_equal(len(payments), expected_payments)
        assert_equal(self.rejections, 9 * expected_payments)
        for txid in payments:
            assert node.gettxout(txid, 0) is not None
        self.log.info("Verified %d mined payments, %d wrong-key signing refusals, and %d altered payments rejected by admission and block validation", expected_payments, expected_payments, self.rejections)


if __name__ == "__main__":
    WitnessV1SigningTest(__file__).main()
