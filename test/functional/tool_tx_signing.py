#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Offline signing selects an explicit era and matches node script checks."""

import json
import subprocess
from hashlib import sha256, sha512
from pathlib import Path

from feature_auxpow_mempool_transition import falcon_signature_variants
from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, tx_from_hex
from test_framework.script import CScript, OP_0, OP_1, OP_EQUAL, OP_NOP4, OP_TRUE
from test_framework.script_util import key_to_p2pk_script, key_to_p2sh_p2wpkh_script, key_to_p2wpkh_script, script_to_p2sh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


class TxSigningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-auxpowactivationheight=1"], ["-auxpowactivationheight=never"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_tidecoin_tx()

    def setup_network(self):
        # Independent nodes compare the two eras; only the strict node needs
        # real funding. The old-rule RPC checks caller-supplied previous outputs.
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def tool(self, raw, previous, *, rules, keys=None, verify=True, success=True, error=None):
        directory = Path(self.options.tmpdir)
        prevfile = directory / "prevtxs.json"
        prevfile.write_text(json.dumps(previous), encoding="utf8")
        argv = self.get_binaries().tx_argv() + ["-regtest", f"-rules={rules}"]
        if verify:
            argv.append("-verify")
        argv += ["-", f"load=prevtxs:{prevfile}"]
        if keys is not None:
            keyfile = directory / "test-keys.json"
            keyfile.touch(mode=0o600, exist_ok=True)
            keyfile.write_text(json.dumps(keys), encoding="utf8")
            argv += [f"load=privatekeys:{keyfile}", "sign=ALL"]
        result = subprocess.run(argv, input=raw, text=True, capture_output=True, timeout=60)
        assert_equal(result.returncode, 0 if success else 1)
        if success:
            assert_equal(result.stderr, "")
            if verify:
                assert_equal(result.stdout.strip(), "OK")
        elif error is not None:
            assert error in result.stderr, result.stderr
        return result.stdout.strip()

    def candidate(self, raw):
        return self.generateblock(self.nodes[0], ADDRESS_BCRT1_P2WSH_OP_TRUE, [raw], submit=False, sync_fun=self.no_op)

    def run_test(self):
        node, old = self.nodes
        mini = MiniWallet(node)
        self.generate(mini, 101, sync_fun=self.no_op)
        cases = []
        wrong_key, _ = generate_keypair()
        for scheme in range(7, 12):
            secret, pubkey = generate_keypair(scheme=str(scheme))
            script = key_to_p2pk_script(pubkey)
            v0 = CScript([OP_0, sha256(script).digest()])
            v1 = CScript([OP_1, sha512(script).digest()])
            for kind, output, fields in [
                ("p2pk", script, {}),
                ("p2sh", script_to_p2sh_script(script), {"redeemScript": script.hex()}),
                ("v0-key", key_to_p2wpkh_script(pubkey), {}),
                # No explicit redeemScript: key insertion must learn the wrapper.
                ("v0-wrapped-key", key_to_p2sh_p2wpkh_script(pubkey), {}),
                ("v0-script", v0, {"witnessScript": script.hex()}),
                ("v0-wrapped-script", script_to_p2sh_script(v0), {"witnessScript": script.hex(), "redeemScript": v0.hex()}),
                ("v1-native", v1, {"witnessScript": script.hex()}),
                ("v1-wrapped", script_to_p2sh_script(v1), {"witnessScript": script.hex(), "redeemScript": v1.hex()}),
            ]:
                cases.append(dict(scheme=scheme, kind=kind, output=output, fields=fields, secret=secret, script=script,
                                  key_program=key_to_p2wpkh_script(pubkey)))

        payload = b"Offline SHA512 rules"
        sha_script = CScript([OP_NOP4, sha512(payload).digest(), OP_EQUAL])
        value = 1_000_000
        funding = mini.create_self_transfer()["tx"]
        original = funding.vout[0].nValue
        outputs = [case["output"] for case in cases] + [CScript([OP_0, sha256(sha_script).digest()])]
        funding.vout = [CTxOut(value, output) for output in outputs]
        funding.vout.append(CTxOut(original - len(outputs) * value, mini.get_output_script()))
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [funding.serialize().hex()], sync_fun=self.no_op)
        extra = {"txid": "ab" * 32, "vout": 0, "amount": 0.01, "scriptPubKey": CScript([OP_1, bytes(64)]).hex()}
        fixtures = {}

        for index, case in enumerate(cases):
            label = f'{case["scheme"]}/{case["kind"]}'
            self.log.info("Checking %s in both eras", label)
            previous = [{"txid": funding.txid_hex, "vout": index, "amount": 0.01,
                         "scriptPubKey": case["output"].hex(), **case["fields"]}]
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(funding.txid_hex, 16), index), nSequence=0xfffffffe)]
            tx.vout = [CTxOut(value - 10000, mini.get_output_script())]
            unsigned = tx.serialize().hex()
            raw = self.tool(unsigned, previous, rules="post-auxpow", keys=[case["secret"]], verify=False)
            fixtures[label] = (tx, previous, case["secret"], raw)
            assert_equal(node.testmempoolaccept([raw])[0]["allowed"], True)
            assert "hex" in self.candidate(raw)
            rpc_previous = previous
            if case["kind"] == "v0-wrapped-key":
                # The RPC requires an explicit script even when checking an
                # existing signature; the utility permits omitted scripts.
                rpc_previous = [{**previous[0], "redeemScript": case["key_program"].hex()}]
            assert_equal(node.signrawtransactionwithkey(raw, [], rpc_previous)["complete"], True)
            old_allowed = case["scheme"] == 7 and not case["kind"].startswith("v1")
            assert_equal(old.signrawtransactionwithkey(raw, [], rpc_previous)["complete"], old_allowed)
            for rules, allowed in (("pre-auxpow", old_allowed), ("post-auxpow", True)):
                self.tool(unsigned, previous, rules=rules, keys=[case["secret"]], success=allowed)
                self.tool(raw, previous, rules=rules, success=allowed)
                self.tool(raw, previous + [extra], rules=rules, success=allowed)
                self.tool(unsigned, previous + [extra], rules=rules, keys=[case["secret"]], success=allowed)
            # Existing signatures can be reused without reloading their scripts.
            basic_previous = [{k: v for k, v in previous[0].items() if k not in ("redeemScript", "witnessScript")}]
            self.tool(raw, basic_previous, rules="post-auxpow", keys=[])
            self.tool(unsigned, previous, rules="post-auxpow", keys=[wrong_key], success=False)
            partial = self.tool(unsigned, previous, rules="post-auxpow", keys=[], verify=False)
            assert_equal(node.testmempoolaccept([partial])[0]["allowed"], False)
            changed = tx_from_hex(raw)
            changed.vout[0].nValue -= 1
            self.tool(changed.serialize().hex(), previous, rules="post-auxpow", success=False)
            changed = tx_from_hex(raw)
            if case["kind"].startswith("v"):
                stack = changed.wit.vtxinwit[0].scriptWitness.stack
            else:
                stack = list(CScript(changed.vin[0].scriptSig))
            signature = bytearray(stack[0])
            signature[len(signature) // 2] ^= 1
            stack[0] = bytes(signature)
            if not case["kind"].startswith("v"):
                changed.vin[0].scriptSig = CScript(stack)
            self.tool(changed.serialize().hex(), previous, rules="post-auxpow", success=False)

            if "witnessScript" in previous[0]:
                # Preserve both historical aliases and explicit wrapper fields.
                for fields in ({"redeemScript": case["script"].hex()},
                               {"witnessScript": case["script"].hex()},
                               {"redeemScript": case["script"].hex(), "witnessScript": case["script"].hex()}):
                    alias = [{**basic_previous[0], **fields}]
                    self.tool(unsigned, alias, rules="post-auxpow", keys=[case["secret"]])
                mismatch = [{**previous[0], "witnessScript": CScript([OP_TRUE]).hex()}]
                self.tool(unsigned, mismatch, rules="post-auxpow", keys=[case["secret"]], success=False)
                # A matching pair of scripts must still match the actual output.
                different = CScript([OP_TRUE])
                version = 1 if case["kind"].startswith("v1") else 0
                digest = sha512(different).digest() if version else sha256(different).digest()
                mismatch = [{**basic_previous[0], "witnessScript": different.hex(),
                             "redeemScript": CScript([OP_1 if version else OP_0, digest]).hex()}]
                self.tool(unsigned, mismatch, rules="post-auxpow", keys=[case["secret"]], success=False,
                          error="does not match scriptPubKey")
                if "wrapped" in case["kind"]:
                    other_wrapper = CScript([OP_0, sha256(case["script"]).digest()]) if version else CScript([OP_1, sha512(case["script"]).digest()])
                    mismatch = [{**previous[0], "redeemScript": other_wrapper.hex()}]
                    self.tool(unsigned, mismatch, rules="post-auxpow", keys=[case["secret"]], success=False,
                              error="does not match scriptPubKey")
            if case["kind"].startswith("v"):
                missing = [{k: v for k, v in previous[0].items() if k != "amount"}]
                self.tool(raw, missing, rules="post-auxpow", success=False, error="Missing amount")
                wrong_amount = [{**previous[0], "amount": 0.01000001}]
                self.tool(raw, wrong_amount, rules="post-auxpow", success=False)
                wrong_raw = self.tool(unsigned, wrong_amount, rules="post-auxpow", keys=[case["secret"]], verify=False)
                assert_equal(node.testmempoolaccept([wrong_raw])[0]["allowed"], False)

        self.log.info("Mixed inputs and previous-output order do not select rules")
        first, first_prev, first_key, _ = fixtures["9/v0-key"]
        second, second_prev, second_key, _ = fixtures["7/v1-native"]
        mixed = CTransaction()
        mixed.vin = first.vin + second.vin
        mixed.vout = [CTxOut(2 * value - 20000, mini.get_output_script())]
        previous = first_prev + second_prev
        unsigned = mixed.serialize().hex()
        raw = self.tool(unsigned, previous, rules="post-auxpow", keys=[first_key, second_key], verify=False)
        assert_equal(node.testmempoolaccept([raw])[0]["allowed"], True)
        assert "hex" in self.candidate(raw)
        for ordered in (previous, list(reversed(previous))):
            self.tool(raw, ordered, rules="post-auxpow")
            self.tool(raw, ordered, rules="pre-auxpow", success=False)
        # A partial result can be completed in a separate invocation.
        partial = self.tool(unsigned, previous, rules="post-auxpow", keys=[first_key], verify=False)
        completed = self.tool(partial, previous, rules="post-auxpow", keys=[second_key], verify=False)
        assert_equal(node.testmempoolaccept([completed])[0]["allowed"], True)
        self.tool(completed, [extra], rules="post-auxpow", success=False, error="prevtxs missing for input")

        self.log.info("Script registration retains the size limit and rejects invalid fields")
        tx, previous, secret, _ = fixtures["7/v1-native"]
        # Tidecoin's MAX_SCRIPT_ELEMENT_SIZE is 8192 bytes.
        oversized = [{**previous[0], "witnessScript": "51" * 8193}]
        self.tool(tx.serialize().hex(), oversized, rules="post-auxpow", keys=[secret], success=False,
                  error="exceeds maximum script element size")
        malformed = [{**previous[0], "witnessScript": 123}]
        self.tool(tx.serialize().hex(), malformed, rules="post-auxpow", keys=[secret], success=False,
                  error="must be hexadecimal string")

        self.log.info("Old-only Falcon signatures remain old-only with unused v1 metadata")
        _, previous, secret, raw = fixtures["7/v0-script"]
        changed = tx_from_hex(raw)
        signature = changed.wit.vtxinwit[0].scriptWitness.stack[0]
        for variant in falcon_signature_variants(signature, secret):
            changed.wit.vtxinwit[0].scriptWitness.stack[0] = variant
            raw = changed.serialize().hex()
            if old.signrawtransactionwithkey(raw, [], previous)["complete"] and not node.signrawtransactionwithkey(raw, [], previous)["complete"]:
                break
        else:
            raise AssertionError("No old-only Falcon fixture found")
        for supplied in (previous, previous + [extra]):
            self.tool(raw, supplied, rules="pre-auxpow")
            self.tool(raw, supplied, rules="post-auxpow", success=False)
        assert_equal(node.testmempoolaccept([raw])[0]["allowed"], False)
        assert_raises_rpc_error(-25, "block-script-verify-flag-failed", self.candidate, raw)

        self.log.info("SHA512 in v0 depends on the explicit era")
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(funding.txid_hex, 16), len(cases)), nSequence=0xfffffffe)]
        tx.vout = [CTxOut(value - 10000, mini.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [payload, bytes(sha_script)]
        previous = [{"txid": funding.txid_hex, "vout": len(cases), "amount": 0.01, "scriptPubKey": outputs[-1].hex()}]
        raw = tx.serialize().hex()
        for supplied in (previous, previous + [extra]):
            self.tool(raw, supplied, rules="post-auxpow")
            self.tool(raw, supplied, rules="pre-auxpow", success=False)
        assert_equal(node.testmempoolaccept([raw])[0]["allowed"], True)
        assert "hex" in self.candidate(raw)


if __name__ == "__main__":
    TxSigningTest(__file__).main()
