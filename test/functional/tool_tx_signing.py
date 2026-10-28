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
from test_framework.script import CScript, OP_0, OP_1, OP_2DROP, OP_4, OP_CHECKMULTISIG, OP_EQUAL, OP_NOP4, OP_TRUE
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

    def test_pubkey_encodings(self):
        self.log.info("Check supplied public-key encodings in transaction outputs")
        for scheme in range(7, 12):
            _, pubkey = generate_keypair(scheme=str(scheme))
            variants = [(pubkey, True)]
            if scheme in (7, 8):
                header = bytearray(pubkey)
                header[1] = 0
                variants.append((bytes(header), False))
                packed = bytearray(pubkey)
                packed[2] = 0xc0
                packed[3] = (packed[3] & 3) | 4
                variants.append((bytes(packed), False))
            for key, valid in variants:
                for command in (f"outpubkey=1:{key.hex()}", f"outmultisig=1:1:2:{pubkey.hex()}:{key.hex()}"):
                    result = subprocess.run(self.get_binaries().tx_argv() + ["-regtest", "-create", f"in={'01' * 32}:0", command],
                                            text=True, capture_output=True, timeout=60)
                    assert_equal(result.returncode, 0 if valid else 1)
                    if valid:
                        assert_equal(result.stderr, "")
                        assert_equal(len(tx_from_hex(result.stdout.strip()).vout), 1)
                    else:
                        assert "invalid TX output pubkey" in result.stderr, result.stderr

    def run_test(self):
        self.test_pubkey_encodings()
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
            ]:
                cases.append(dict(scheme=scheme, kind=kind, output=output, fields=fields, secret=secret, script=script,
                                  key_program=key_to_p2wpkh_script(pubkey)))
            if scheme == 11:
                # A PQ multisig witness script above the 8192-byte element
                # limit, which applies to P2SH redeem scripts but not here.
                others = [generate_keypair(scheme="11")[1] for _ in range(3)]
                large = CScript([OP_1, pubkey, *others, OP_4, OP_CHECKMULTISIG])
                assert len(large) > 8192
                v0 = CScript([OP_0, sha256(large).digest()])
                v1 = CScript([OP_1, sha512(large).digest()])
                for kind, output, fields in [
                    ("v0-script-large", v0, {"witnessScript": large.hex()}),
                    ("v0-wrapped-script-large", script_to_p2sh_script(v0), {"witnessScript": large.hex(), "redeemScript": v0.hex()}),
                    ("v1-native-large", v1, {"witnessScript": large.hex()}),
                ]:
                    cases.append(dict(scheme=scheme, kind=kind, output=output, fields=fields, secret=secret, script=large,
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
            # An incomplete pre-rules result must not carry a newly created
            # later-era signature, even without the tool's optional verification.
            pre_partial = self.tool(unsigned, previous, rules="pre-auxpow", keys=[case["secret"]], verify=False)
            checked = node.signrawtransactionwithkey(pre_partial, [], rpc_previous, rules="post-auxpow")
            assert_equal(checked["complete"], old_allowed)
            if not old_allowed:
                # Supplying a private key also learns its wrapped-v0 script;
                # give the public-only control the same script information.
                public_only = self.tool(unsigned, rpc_previous, rules="pre-auxpow", keys=[], verify=False)
                assert_equal(pre_partial, public_only)
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
            # Multisig witnesses start with an empty dummy element.
            position = next(i for i, item in enumerate(stack) if item)
            signature = bytearray(stack[position])
            signature[len(signature) // 2] ^= 1
            stack[position] = bytes(signature)
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
                # Supplied scripts must still match the actual output.
                different = CScript([OP_TRUE])
                mismatch = [{**basic_previous[0], "witnessScript": different.hex()}]
                if "wrapped" in case["kind"]:
                    mismatch[0]["redeemScript"] = CScript([OP_0, sha256(different).digest()]).hex()
                self.tool(unsigned, mismatch, rules="post-auxpow", keys=[case["secret"]], success=False,
                          error="does not match scriptPubKey")
                if "wrapped" in case["kind"]:
                    other_wrapper = CScript([OP_1, sha512(case["script"]).digest()])
                    mismatch = [{**previous[0], "redeemScript": other_wrapper.hex()}]
                    self.tool(unsigned, mismatch, rules="post-auxpow", keys=[case["secret"]], success=False,
                              error="does not correspond to witnessScript")
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

        self.log.info("Script registration applies each script role's size limit and rejects invalid fields")
        tx, previous, secret, _ = fixtures["7/p2sh"]
        # A P2SH redeem script is one stack element: at most 8192 bytes.
        redeem = CScript([bytes(4100), bytes(4100), OP_2DROP, OP_TRUE])
        oversized = [{**previous[0], "scriptPubKey": script_to_p2sh_script(redeem).hex(), "redeemScript": redeem.hex()}]
        self.tool(tx.serialize().hex(), oversized, rules="post-auxpow", keys=[secret], success=False,
                  error="redeemScript exceeds maximum script element size")
        tx, previous, secret, _ = fixtures["7/v1-native"]
        # A witness script is limited only by the 65536-byte script size.
        oversized = [{**previous[0], "witnessScript": "51" * 65537}]
        self.tool(tx.serialize().hex(), oversized, rules="post-auxpow", keys=[secret], success=False,
                  error="witnessScript exceeds maximum script size")
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
