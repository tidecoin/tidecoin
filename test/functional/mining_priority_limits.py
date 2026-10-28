#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bounded priority adjustments, persisted values and large RBF diagrams."""

from decimal import Decimal
import struct
import time

from test_framework.messages import COIN, MAX_MONEY, ser_uint256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class PriorityLimitsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.test_live_and_saved_adjustments()
        self.test_many_affected_clusters()

    def test_live_and_saved_adjustments(self):
        self.log.info("Test accumulated limits on live entries and saved adjustments")
        node = self.nodes[0]
        maximum, minimum = 2**63 - 1, -(2**63)
        tx = self.wallet.create_self_transfer()
        txid = tx['txid']
        base = int(tx['fee'] * COIN)
        node.prioritisetransaction(txid, 0, maximum)
        assert_equal(node.getprioritisedtransactions()[txid], {'fee_delta': MAX_MONEY, 'in_mempool': False})
        node.sendrawtransaction(tx['hex'])

        def check(delta):
            entry = node.getmempoolentry(txid)
            assert_equal(entry['fees']['base'] * COIN, base)
            assert_equal(entry['fees']['modified'] * COIN, base + delta)
            assert_equal(entry['fees']['ancestor'] * COIN, base + delta)
            assert_equal(entry['fees']['descendant'] * COIN, base + delta)
            assert_equal(entry['fees']['chunk'] * COIN, base + delta)
            priorities = node.getprioritisedtransactions()
            if delta:
                assert_equal(priorities[txid], {'fee_delta': delta, 'in_mempool': True, 'modified_fee': base + delta})
            else:
                assert txid not in priorities

        check(MAX_MONEY)
        for request, expected in [(1, MAX_MONEY), (maximum, MAX_MONEY), (-MAX_MONEY, 0),
                                  (minimum, -MAX_MONEY), (-1, -MAX_MONEY), (MAX_MONEY, 0),
                                  (maximum, MAX_MONEY), (minimum, -MAX_MONEY), (maximum, MAX_MONEY)]:
            node.prioritisetransaction(txid, 0, request)
            check(expected)

        unknown = 'ff' * 32
        node.prioritisetransaction(unknown, 0, minimum)
        self.restart_node(0)
        check(MAX_MONEY)
        assert_equal(node.getprioritisedtransactions()[unknown], {'fee_delta': -MAX_MONEY, 'in_mempool': False})

        # A version-1 dump predates file obfuscation and remains supported. Both
        # per-transaction and unknown-ID records can contain pre-limit values.
        saved = self.wallet.create_self_transfer(confirmed_only=True)
        positive_id, negative_id = 'ee' * 32, 'dd' * 32
        dump = self.nodes[0].datadir_path / 'priority-limits.dat'
        dump.write_bytes(
            struct.pack('<QQ', 1, 1) + saved['tx'].serialize() + struct.pack('<qq', int(time.time()), maximum)
            + b'\x02' + ser_uint256(int(positive_id, 16)) + struct.pack('<q', maximum)
            + ser_uint256(int(negative_id, 16)) + struct.pack('<q', minimum) + b'\x00'
        )
        node.importmempool(str(dump), {'apply_fee_delta_priority': True})
        entries = node.getprioritisedtransactions()
        assert_equal(entries[saved['txid']]['fee_delta'], MAX_MONEY)
        assert_equal(entries[saved['txid']]['modified_fee'], int(saved['fee'] * COIN) + MAX_MONEY)
        assert_equal(entries[positive_id], {'fee_delta': MAX_MONEY, 'in_mempool': False})
        assert_equal(entries[negative_id], {'fee_delta': -MAX_MONEY, 'in_mempool': False})

        # Inverse adjustments clear the retained value exactly, even after a
        # saturated request. Clearing priority does not change the actual fee.
        for current_id, info in entries.items():
            node.prioritisetransaction(current_id, 0, -info['fee_delta'])
        assert_equal(node.getprioritisedtransactions(), {})
        check(0)
        self.generate(node, 1)
        self.wallet.rescan_utxos()

    def test_many_affected_clusters(self):
        self.log.info("Test replacement across 70 clusters with large surviving-ancestor fees")
        node = self.nodes[0]
        count = 70
        split = self.wallet.send_self_transfer_multi(from_node=node, num_outputs=2 * count)
        self.generate(node, 1)
        anchors = split['new_utxos'][1::2]
        ancestors, leaves = [], []
        for cluster in range(count):
            utxo = split['new_utxos'][2 * cluster]
            for _ in range(63):
                parent = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=utxo, fee=Decimal('0.00001'))
                node.prioritisetransaction(parent['txid'], 0, MAX_MONEY)
                ancestors.append(parent['txid'])
                utxo = parent['new_utxo']
            leaf = self.wallet.send_self_transfer_multi(from_node=node, utxos_to_spend=[utxo, anchors[cluster]])
            leaves.append(leaf['txid'])
        assert_equal(node.getmempoolinfo()['size'], 64 * count)
        # The replacement spends the confirmed anchors, leaving 4,410 ancestors
        # in the affected diagrams. Their summed adjustments exceed int64_t.
        assert len(ancestors) * MAX_MONEY > 2**63 - 1
        replacement = self.wallet.create_self_transfer_multi(utxos_to_spend=anchors, fee_per_output=1_000_000)
        node.prioritisetransaction(replacement['txid'], 0, MAX_MONEY)
        result = node.testmempoolaccept([replacement['hex']])[0]
        assert_equal(result['allowed'], True)
        node.sendrawtransaction(replacement['hex'])
        remaining = set(node.getrawmempool())
        assert_equal(remaining, set(ancestors) | {replacement['txid']})
        assert not remaining.intersection(leaves)
        # Mining uses the real fees, regardless of the much larger priorities.
        block = self.generate(node, 1)[0]
        assert replacement['txid'] in node.getblock(block)['tx']


if __name__ == '__main__':
    PriorityLimitsTest(__file__).main()
