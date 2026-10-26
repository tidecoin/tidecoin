#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Legacy Falcon decoding, canonical relay policy, and exact consumption in both eras."""

from decimal import Decimal
from hashlib import sha512
from io import BytesIO
import struct
import time

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.blocktools import add_witness_commitment
from test_framework.falcon import falcon512_alternates
from test_framework.messages import COIN, CBlock, CInv, COutPoint, CTransaction, CTxIn, CTxOut, MSG_WTX, msg_inv, tx_from_hex
from test_framework.p2p import P2PDataStore, p2p_lock
from test_framework.script import CScript, OP_1
from test_framework.script_util import key_to_p2pk_script, key_to_p2pkh_script, key_to_p2wpkh_script, keys_to_multisig_script, script_to_p2sh_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_not_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


class FalconEncodingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-auxpowactivationheight=110"]] * 2

    def setup_network(self):
        # Independent chains keep the existing padding checks at their original heights.
        self.setup_nodes()

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
        self.generate(self.mini, 101, sync_fun=self.no_op)
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
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [funding.serialize().hex()], sync_fun=self.no_op)
        self.generate(self.mini, 6, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 108)
        self.check_legacy()
        last_before = self.generate(self.mini, 1, sync_fun=self.no_op)[0]
        self.check_strict()  # Candidate activation block, height 110.
        self.generate(self.mini, 1, sync_fun=self.no_op)
        self.check_strict()
        node.invalidateblock(last_before)
        assert_equal(node.getblockcount(), 108)
        self.check_legacy()
        node.reconsiderblock(last_before)
        assert_equal(node.getblockcount(), 110)
        originals = self.check_strict()
        mined = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, originals, sync_fun=self.no_op)
        assert_equal(len(node.getblock(mined["hash"])["tx"]), 1 + len(originals))
        self.check_old_encodings()

    def check_old_encodings(self):
        node = self.nodes[1]
        mini = MiniWallet(node)
        self.generate(mini, 101, sync_fun=self.no_op)
        secret, pubkey = generate_keypair(scheme="7")
        value = 1_000_000
        rows = []
        forms = ("pk", "pkh", "sh_pkh", "wpkh", "sh_wpkh", "multi", "sh_multi", "wsh_multi", "sh_wsh_multi")
        # Independent coins for each form/encoding, plus peer and persistence controls.
        for form in forms + ("wpkh", "wpkh"):
            for variant in range(3):
                row = {"form": form, "variant": variant, "vout": len(rows),
                       "witness": "wpkh" in form or "wsh" in form, "multi": "multi" in form}
                if row["multi"]:
                    script = keys_to_multisig_script([pubkey], k=1)
                    output = script_to_p2wsh_script(script) if "wsh" in form else script
                    if row["witness"]:
                        row["witnessScript"] = script.hex()
                else:
                    output = key_to_p2pk_script(pubkey) if form == "pk" else key_to_p2wpkh_script(pubkey) if row["witness"] else key_to_p2pkh_script(pubkey)
                if form.startswith("sh_"):
                    row["redeemScript"] = output.hex()
                    output = script_to_p2sh_script(output)
                row["output"] = output
                rows.append(row)
        funding = mini.create_self_transfer()["tx"]
        funding.vout = [CTxOut(value, row["output"]) for row in rows] + [
            CTxOut(funding.vout[0].nValue - len(rows) * value, mini.get_output_script())]
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [funding.serialize().hex()], sync_fun=self.no_op)
        self.generate(mini, 6, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 108)

        for row in rows:
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(funding.txid_int, row["vout"]))]
            tx.vout = [CTxOut(value - 10_000, mini.get_output_script())]
            previous = dict(txid=funding.txid_hex, vout=row["vout"], scriptPubKey=row["output"].hex(), amount=Decimal(value) / COIN)
            previous.update({key: row[key] for key in ("redeemScript", "witnessScript") if key in row})
            for _ in range(100):
                signed = node.signrawtransactionwithkey(tx.serialize().hex(), [secret], [previous], rules="pre-auxpow")
                assert signed["complete"]
                original = tx_from_hex(signed["hex"])
                stack = original.wit.vtxinwit[0].scriptWitness.stack if row["witness"] else list(CScript(original.vin[0].scriptSig))
                sig_index = int(row["multi"])
                alternates = falcon512_alternates(stack[sig_index])
                if alternates:
                    break
            else:
                raise AssertionError("No Falcon signature with zero coefficient and unused bits")
            row["canonical"] = original
            changed = tx_from_hex(signed["hex"])
            stack = changed.wit.vtxinwit[0].scriptWitness.stack if row["witness"] else list(CScript(changed.vin[0].scriptSig))
            stack[sig_index] = alternates[row["variant"]]
            if not row["witness"]:
                changed.vin[0].scriptSig = CScript(stack)
            row["alternate"] = changed
            assert_not_equal(changed.wtxid_hex, original.wtxid_hex)
            assert_equal(changed.txid_hex == original.txid_hex, row["witness"])

        error = "Non-canonical Falcon-512 signature encoding"
        def refused(tx, reason=error):
            raw = tx.serialize().hex()
            result = node.testmempoolaccept([raw])[0]
            assert_equal(result["allowed"], False)
            assert reason in result.get("reject-details", result["reject-reason"]), result
            assert_raises_rpc_error(-26, reason, node.sendrawtransaction, raw)

        self.log.info("Both standardness settings retain the encoding policy")
        for nonstandard in (0, 1):
            self.restart_node(1, self.extra_args[1] + [f"-acceptnonstdtxn={nonstandard}"])
            for row in rows[:27]:
                refused(row["alternate"])
                assert node.testmempoolaccept([row["canonical"].serialize().hex()])[0]["allowed"]

        self.log.info("An ordinary peer stays connected and the canonical witness transaction remains fetchable")
        peer = node.add_p2p_connection(P2PDataStore())
        assert not node.getpeerinfo()[0].get("permissions")
        peer_row = rows[27]
        peer.send_txs_and_test([peer_row["alternate"]], node, success=False, reject_reason=error)
        canonical = peer_row["canonical"]
        with p2p_lock:
            peer.tx_store[canonical.wtxid_int] = canonical
        peer.send_without_ping(msg_inv([CInv(MSG_WTX, canonical.wtxid_int)]))
        self.wait_until(lambda: canonical.txid_hex in node.getrawmempool())
        with p2p_lock:
            assert canonical.wtxid_int in peer.getdata_requests
        peer.sync_with_ping()
        assert_equal(node.getconnectioncount(), 1)
        node.disconnect_p2ps()

        def child(parent):
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(parent.txid_int, 0))]
            tx.vout = [CTxOut(parent.vout[0].nValue - 100_000, mini.get_output_script())]
            mini.sign_tx(tx)
            return tx

        self.log.info("A high-fee child does not override the parent's encoding; saved entries undergo admission")
        parent = rows[28]["alternate"]
        package = node.submitpackage([parent.serialize().hex(), child(parent).serialize().hex()])
        assert_not_equal(package["package_msg"], "success")
        assert error in str(package), package
        assert parent.txid_hex not in node.getrawmempool()
        # Version 1 is the supported non-obfuscated mempool format. Include a
        # canonical control to prove startup actually loads and checks the file.
        saved_good, saved_bad = rows[29]["canonical"], rows[30]["alternate"]
        self.stop_node(1)
        entries = (canonical, saved_good, saved_bad)
        contents = struct.pack("<QQ", 1, len(entries))
        for tx in entries:
            contents += tx.serialize() + struct.pack("<qq", node.mocktime or int(time.time()), 0)
        contents += b"\x00\x00"  # Empty fee-delta map and unbroadcast set.
        (node.chain_path / "mempool.dat").write_bytes(contents)
        self.start_node(1, self.extra_args[1] + ["-acceptnonstdtxn=0"])
        self.wait_until(lambda: node.getmempoolinfo()["loaded"])
        assert_equal(set(node.getrawmempool()), {canonical.txid_hex, saved_good.txid_hex})
        refused(saved_bad)

        self.log.info("Submit old-rule blocks, disconnect an alternate parent, and keep unrelated entries")
        old_txs = [row["alternate"] for row in rows[:27]] + [canonical, saved_good]
        old_block = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [tx.serialize().hex() for tx in old_txs], sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 109)
        assert_equal(node.getbestblockhash(), old_block["hash"])
        dependent = child(old_txs[0])
        node.sendrawtransaction(dependent.serialize().hex())
        mini.rescan_utxos()
        unrelated = mini.send_self_transfer(from_node=node, utxo_to_spend=mini.get_utxo(txid=funding.txid_hex, vout=len(rows)))
        node.invalidateblock(old_block["hash"])
        assert_equal(node.getblockcount(), 108)
        assert unrelated["txid"] in node.getrawmempool()
        assert dependent.txid_hex not in node.getrawmempool()
        for tx in old_txs[:27]:
            assert tx.txid_hex not in node.getrawmempool()
            refused(tx)
        # Advance on a fresh branch with canonical mempool entries only.
        self.generate(mini, 1, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 109)
        canonical_txs = [row["canonical"] for row in rows[:27]]
        self.log.info("At and after activation, actual submitted alternate blocks fail script validation")
        for expected_height in (110, 111):
            candidate = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE,
                                           [tx.serialize().hex() for tx in canonical_txs], submit=False, sync_fun=self.no_op)
            for index, row in enumerate(rows[:27]):
                refused(row["alternate"], "Signature must be zero")
                block = CBlock()
                block.deserialize(BytesIO(bytes.fromhex(candidate["hex"])))
                block.vtx[index + 1] = row["alternate"]
                # Replace the generated commitment, then solve the changed header.
                block.vtx[0].vout.pop()
                add_witness_commitment(block)
                block.solve()
                result = node.submitblock(block.serialize().hex())
                assert "block-script-verify-flag-failed" in result, result
                assert_equal(node.getblockcount(), expected_height - 1)
            if expected_height == 110:
                self.generate(mini, 1, sync_fun=self.no_op)
        # Rollback restores block acceptance but never permits relay of these bytes.
        node.invalidateblock(node.getblockhash(109))
        assert_equal(node.getblockcount(), 108)
        for tx in old_txs[:27]:
            refused(tx)
        replay = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE,
                                    [tx.serialize().hex() for tx in old_txs[:27]], sync_fun=self.no_op)
        assert_equal(node.getbestblockhash(), replay["hash"])
        # Returning to strict rules does not retroactively reject that block.
        self.generate(mini, 2, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 111)


if __name__ == "__main__":
    FalconEncodingTest(__file__).main()
