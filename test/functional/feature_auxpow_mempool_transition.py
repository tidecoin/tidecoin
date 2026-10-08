#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Next-block admission and pending-transaction cleanup across AuxPoW activation."""

from decimal import Decimal
from hashlib import sha256, sha512
import time

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE, base58_to_byte
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, tx_from_hex
from test_framework.script import CScript, OP_0, OP_EQUAL, OP_NOP4
from test_framework.script_util import key_to_p2pk_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


def falcon_signature_variants(signature, secret):
    """Construct test signatures between the strict and historical norm bounds.

    Falcon's public polynomial is g/f. Adding k*f to s2 changes s1 by -k*g,
    preserving the signing equation while increasing the squared norm. The
    nodes themselves establish old-rule acceptance and strict-rule rejection.
    Codec layout follows src/pq/falcon-512/codec.c (logn=9, six-bit f).
    """
    key, _ = base58_to_byte(secret)
    assert_equal(key[:2], b"\x07\x59")
    key_bits = ''.join(f'{byte:08b}' for byte in key[2:386])
    f = [int(key_bits[i:i + 6], 2) for i in range(0, 512 * 6, 6)]
    f = [value - 64 if value >= 32 else value for value in f]
    assert_equal(signature[0], 0x39)
    bits = ''.join(f'{byte:08b}' for byte in signature[41:-1])
    coefficients = []
    offset = 0
    for _ in range(512):
        negative = bits[offset] == '1'
        value = int(bits[offset + 1:offset + 8], 2)
        offset += 8
        while bits[offset] == '0':
            value += 128
            offset += 1
        offset += 1
        coefficients.append(-value if negative else value)
    assert set(bits[offset:]) <= {'0'}
    for factor in range(1, 65):
        shifted = [value + factor * private for value, private in zip(coefficients, f)]
        if any(abs(value) > 2047 for value in shifted):
            continue
        encoded = ''.join(('1' if value < 0 else '0') + f'{abs(value) & 127:07b}' +
                          '0' * (abs(value) >> 7) + '1' for value in shifted)
        encoded += '0' * (-len(encoded) % 8)
        yield signature[:41] + int(encoded, 2).to_bytes(len(encoded) // 8, 'big') + signature[-1:]


class AuxpowMempoolTransitionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-auxpowactivationheight=110"], ["-auxpowactivationheight=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # The isolated second node checks signatures under strict rules using
        # caller-supplied previous outputs, without advancing the funding chain.
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def candidate(self, raw):
        return self.generateblock(self.nodes[0], ADDRESS_BCRT1_P2WSH_OP_TRUE, [raw],
                                  submit=False, sync_fun=self.no_op)

    def spend(self, index, stack):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(self.funding_id, 16), index))]
        tx.vout = [CTxOut(self.value - 10_000, self.mini.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        return tx

    def assert_rejected(self, raw):
        node = self.nodes[0]
        assert_equal(node.testmempoolaccept([raw])[0]["allowed"], False)
        assert_raises_rpc_error(-26, "script", node.sendrawtransaction, raw)
        assert_raises_rpc_error(-25, "block-script-verify-flag-failed", self.candidate, raw)

    def assert_pool(self, expected):
        node = self.nodes[0]
        assert_equal(set(node.getrawmempool()), set(expected))
        # getblocktemplate caches a template for five seconds after pool changes.
        node.setmocktime(max(node.mocktime or 0, int(time.time())) + 6)
        template = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(template["height"], node.getblockcount() + 1)
        assert_equal({tx["txid"] for tx in template["transactions"]}, set(expected))

    def run_test(self):
        node, strict = self.nodes
        self.mini = MiniWallet(node)
        self.generate(self.mini, 101, sync_fun=self.no_op)
        secret, pubkey = generate_keypair(scheme="7")
        falcon_script = key_to_p2pk_script(pubkey)
        payload = b"AuxPoW next-block SHA512 check"
        # OP_NOP4's byte becomes OP_SHA512 at activation.
        sha_script = CScript([OP_NOP4, sha512(payload).digest(), OP_EQUAL])
        scripts = [falcon_script, sha_script, sha_script]
        self.value = 1_000_000
        funding = self.mini.create_self_transfer()
        total = funding["tx"].vout[0].nValue
        funding["tx"].vout = [CTxOut(self.value, CScript([OP_0, sha256(script).digest()])) for script in scripts]
        funding["tx"].vout.append(CTxOut(total - len(scripts) * self.value, self.mini.get_output_script()))
        self.funding_id = self.mini.sendrawtransaction(from_node=node, tx_hex=funding["tx"].serialize().hex())
        self.generate(self.mini, 7, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 108)

        previous = [{"txid": self.funding_id, "vout": 0,
                     "scriptPubKey": funding["tx"].vout[0].scriptPubKey.hex(),
                     "witnessScript": falcon_script.hex(), "amount": Decimal(self.value) / COIN}]
        signed = strict.signrawtransactionwithkey(self.spend(0, []).serialize().hex(), [secret], previous)
        assert_equal(signed["complete"], True)
        tx = tx_from_hex(signed["hex"])
        signature = tx.wit.vtxinwit[0].scriptWitness.stack[0]
        legacy_raw = None
        for variant in falcon_signature_variants(signature, secret):
            tx.wit.vtxinwit[0].scriptWitness.stack[0] = variant
            raw = tx.serialize().hex()
            if not node.testmempoolaccept([raw])[0]["allowed"]:
                continue
            # No private key: this checks the supplied signature, not a replacement.
            if not strict.signrawtransactionwithkey(raw, [], previous)["complete"]:
                legacy_raw = raw
                break
        assert legacy_raw is not None, "Could not construct a legacy-only Falcon signature"
        assert "hex" in self.candidate(legacy_raw)
        legacy_id = self.mini.sendrawtransaction(from_node=node, tx_hex=legacy_raw)
        child = self.mini.send_self_transfer(from_node=node, sequence=0xfffffffd, utxo_to_spend=self.mini.get_utxo(txid=legacy_id))
        grandchild = self.mini.send_self_transfer(from_node=node, sequence=0xfffffffd, utxo_to_spend=self.mini.get_utxo(txid=child["txid"]))
        # Disable relative locks so rollback checks isolate script-rule changes.
        control = self.mini.send_self_transfer(from_node=node, sequence=0xfffffffd, utxo_to_spend=self.mini.get_utxo(txid=self.funding_id))
        control_child = self.mini.send_self_transfer(from_node=node, sequence=0xfffffffd, utxo_to_spend=self.mini.get_utxo(txid=control["txid"]))
        controls = {control["txid"], control_child["txid"]}
        self.assert_pool(controls | {legacy_id, child["txid"], grandchild["txid"]})
        sha_raws = [self.spend(index, [payload, bytes(sha_script)]).serialize().hex() for index in (1, 2)]
        for raw in sha_raws:
            self.assert_rejected(raw)

        self.log.info("Forward transition removes legacy-only Falcon and descendants, preserving unrelated entries")
        boundary = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [], sync_fun=self.no_op)["hash"]
        assert_equal(node.getblockcount(), 109)
        self.assert_pool(controls)
        self.assert_rejected(legacy_raw)
        assert node.gettxout(self.funding_id, 0) is not None
        assert_equal(node.testmempoolaccept([signed["hex"]])[0]["allowed"], True)
        self.restart_node(0)
        self.assert_pool(controls)

        self.log.info("SHA512 enters the pool before the first activation block and can be mined in it")
        sha_ids = []
        for raw in sha_raws:
            assert_equal(node.testmempoolaccept([raw])[0]["allowed"], True)
            assert "hex" in self.candidate(raw)
            sha_ids.append(self.mini.sendrawtransaction(from_node=node, tx_hex=raw))
        sha_child = self.mini.send_self_transfer(from_node=node, sequence=0xfffffffd, utxo_to_spend=self.mini.get_utxo(txid=sha_ids[1]))
        sha_grandchild = self.mini.send_self_transfer(from_node=node, sequence=0xfffffffd, utxo_to_spend=self.mini.get_utxo(txid=sha_child["txid"]))
        self.assert_pool(controls | set(sha_ids) | {sha_child["txid"], sha_grandchild["txid"]})
        mined = self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [sha_ids[0]], sync_fun=self.no_op)["hash"]
        assert_equal(node.getblockcount(), 110)
        assert sha_ids[0] in node.getblock(mined)["tx"]
        pending = controls | {sha_ids[1], sha_child["txid"], sha_grandchild["txid"]}
        self.assert_pool(pending)
        self.restart_node(0)
        self.assert_pool(pending)

        self.log.info("Rollback removes both pending and disconnected SHA512 spends and their descendants")
        node.invalidateblock(boundary)
        assert_equal(node.getblockcount(), 108)
        self.assert_pool(controls)
        for raw in sha_raws:
            self.assert_rejected(raw)
        assert_equal(node.testmempoolaccept([legacy_raw])[0]["allowed"], True)
        self.restart_node(0)
        self.assert_pool(controls)
        # Mining after cleanup must work, and both unrelated transactions survive.
        mined = self.generate(self.mini, 1, sync_fun=self.no_op)[0]
        assert controls <= set(node.getblock(mined)["tx"])
        assert_equal(node.getblockcount(), 109)
        self.assert_pool(set())
        for raw in sha_raws:
            node.sendrawtransaction(raw)
        mined = self.generate(self.mini, 1, sync_fun=self.no_op)[0]
        assert_equal(node.getblockcount(), 110)
        assert set(sha_ids) <= set(node.getblock(mined)["tx"])
        self.assert_pool(set())


if __name__ == "__main__":
    AuxpowMempoolTransitionTest(__file__).main()
