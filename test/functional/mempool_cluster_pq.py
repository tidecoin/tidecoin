#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise cluster admission, consolidation, CPFP and replacement across PQ schemes."""
from decimal import Decimal
import json
from pathlib import Path
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet
from test_framework.messages import COIN, CTxOut, tx_from_hex
from test_framework.util import assert_equal, assert_raises_rpc_error


class ClusterPQTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def save(self):
        (Path(self.options.tmpdir) / 'pq_matrix.json').write_text(json.dumps(self.results, indent=2, default=str) + '\n')

    def test_mixed_schemes_and_truc(self, node, mini):
        node.createwallet('mixed-cluster')
        wallet = node.get_wallet_rpc('mixed-cluster')
        schemes = ['falcon512', 'falcon1024', 'mldsa44', 'mldsa65', 'mldsa87']
        addresses = [wallet.getnewaddress('', 'bech32pq', scheme) for scheme in schemes]
        funding = [mini.send_to(from_node=node, scriptPubKey=bytes.fromhex(node.validateaddress(address)['scriptPubKey']),
                                amount = 1000000) for address in addresses]
        self.generate(mini, 1)

        def signed_transfer(txid, vout, address, value, version=2):
            tx = tx_from_hex(node.createrawtransaction([{'txid': txid, 'vout': vout}], [{address: Decimal(value) / COIN}]))
            tx.version = version
            signed = wallet.signrawtransactionwithwallet(tx.serialize().hex())
            assert signed['complete']
            return node.sendrawtransaction(signed['hex'], 0)

        self.log.info('One connected chain spends all five schemes')
        txid, vout = funding[0]['txid'], funding[0]['sent_vout']
        for index in range(5):
            txid = signed_transfer(txid, vout, addresses[(index + 1) % 5], 1000000 - 5000 * (index + 1))
            vout = 0
        assert_equal(node.getmempoolentry(txid)['ancestorcount'], 5)
        self.generate(mini, 1)

        self.log.info('TRUC witness-v1 parent/child pairs support all five schemes')
        # Refresh the first funding output, which was spent by the mixed chain.
        funding[0] = mini.send_to(from_node=node, scriptPubKey=bytes.fromhex(node.validateaddress(addresses[0])['scriptPubKey']), amount=1000000)
        self.generate(mini, 1)
        for address, coin in zip(addresses, funding):
            parent = signed_transfer(coin['txid'], coin['sent_vout'], address, 999000, version=3)
            child = signed_transfer(parent, 0, address, 979000, version=3)
            assert_equal(node.getmempoolentry(child)['ancestorcount'], 2)
            assert node.getmempoolentry(child)['vsize'] <= 4000
        assert_equal(len(node.getrawmempool()), 10)
        self.generate(mini, 1)
        self.results['mixed_schemes_and_truc'] = True
        wallet.unloadwallet()

    def run_test(self):
        node = self.nodes[0]
        mini = MiniWallet(node)
        self.generate(mini, 160)
        self.results = {'rows': [], 'complete': False}
        for scheme in ['falcon512', 'falcon1024', 'mldsa44', 'mldsa65', 'mldsa87']:
            for kind in ['legacy', 'p2sh-segwit', 'bech32', 'bech32pq']:
                self.log.info('%s %s', scheme, kind)
                name = scheme + '-' + kind
                node.createwallet(name)
                wallet = node.get_wallet_rpc(name)
                wallet.setpqhdpolicy(scheme, scheme)
                address = wallet.getnewaddress('', kind, scheme)
                change = wallet.getrawchangeaddress(kind, scheme)
                script = bytes.fromhex(node.validateaddress(address)['scriptPubKey'])
                coins = []
                while sum(int(c['value'] * COIN) for c in coins) < 48 * 1000000 + 10000:
                    coins.append(mini.get_utxo(confirmed_only=True))
                fund = mini.create_self_transfer_multi(utxos_to_spend=coins)['tx']
                total = sum(int(c['value'] * COIN) for c in coins)
                fund.vout = [CTxOut(1000000, script) for _ in range(48)] + [CTxOut(total - 48 * 1000000 - 10000, mini.get_output_script())]
                fid = mini.sendrawtransaction(from_node=node, tx_hex=fund.serialize().hex())
                self.generate(mini, 1)
                wallet.syncwithvalidationinterfacequeue()
                row = {'scheme': scheme, 'address_type': kind, 'measurements': []}
                for label, offset, count, outputs in [('payment', 0, 2, 2), ('consolidation10', 2, 10, 1), ('consolidation30', 12, 30, 1)]:
                    value = count * 1000000 - 50000
                    out = [{address: Decimal(value) / COIN}] if outputs == 1 else [{address: Decimal(value // 2) / COIN}, {change: Decimal(value - value // 2) / COIN}]
                    raw = node.createrawtransaction([{'txid': fid, 'vout': i} for i in range(offset, offset + count)], out)
                    start = time.perf_counter()
                    signed = wallet.signrawtransactionwithwallet(raw)
                    assert signed['complete']
                    decoded = node.decoderawtransaction(signed['hex'])
                    accepted = node.testmempoolaccept([signed['hex']], 0)[0]
                    obs = {'shape': label, 'inputs': count, 'outputs': outputs, 'size': decoded['size'], 'vsize': decoded['vsize'], 'weight': decoded['weight'], 'scriptsig_max_bytes': max(len(i['scriptSig']['hex']) // 2 for i in decoded['vin']), 'sign_and_test_ms': (time.perf_counter() - start) * 1000, 'acceptance': accepted}
                    row['measurements'].append(obs)
                    if decoded['weight'] <= 800000:
                        assert accepted['allowed'], obs
                        node.sendrawtransaction(signed['hex'], 0)
                    else:
                        assert_equal(accepted['reject-reason'], 'tx-size')
                self.generate(mini, 1)
                # Actual parent-child relay and a replacement of the child.
                parent = wallet.signrawtransactionwithwallet(node.createrawtransaction([{'txid': fid, 'vout': 42}], [{address: Decimal(999000) / COIN}]))
                assert parent['complete']
                pid = node.sendrawtransaction(parent['hex'], 0)
                child = wallet.signrawtransactionwithwallet(node.createrawtransaction([{'txid': pid, 'vout': 0}], [{address: Decimal(979000) / COIN}]))
                assert child['complete']
                cid = node.sendrawtransaction(child['hex'], 0)
                replacement = wallet.signrawtransactionwithwallet(node.createrawtransaction([{'txid': pid, 'vout': 0}], [{address: Decimal(959000) / COIN}]))
                assert replacement['complete']
                rid = node.sendrawtransaction(replacement['hex'], 0)
                assert cid not in node.getrawmempool()
                assert_equal(set(node.getrawmempool()), {pid, rid})
                row['cpfp_rbf'] = {'parent_vsize': node.decoderawtransaction(parent['hex'])['vsize'], 'child_vsize': node.decoderawtransaction(child['hex'])['vsize'], 'replacement_vsize': node.decoderawtransaction(replacement['hex'])['vsize'], 'replacement_accepted': True}
                self.generate(mini, 1)
                # Paying more total fees must not replace a high-feerate CPFP
                # chunk with a larger transaction having a worse diagram.
                parent = wallet.signrawtransactionwithwallet(node.createrawtransaction(
                    [{'txid': fid, 'vout': 43}], [{address: Decimal(999000) / COIN}]))
                assert parent['complete']
                pid = node.sendrawtransaction(parent['hex'], 0)
                child = wallet.signrawtransactionwithwallet(node.createrawtransaction(
                    [{'txid': pid, 'vout': 0}], [{address: Decimal(899000) / COIN}]))
                assert child['complete']
                cid = node.sendrawtransaction(child['hex'], 0)
                replacement = wallet.signrawtransactionwithwallet(node.createrawtransaction(
                    [{'txid': fid, 'vout': 43}],
                    [{address: Decimal(880000) / COIN}, {'data': '00' * 30000}]))
                assert replacement['complete']
                old_vsize = sum(node.decoderawtransaction(tx['hex'])['vsize'] for tx in [parent, child])
                replacement_vsize = node.decoderawtransaction(replacement['hex'])['vsize']
                assert 120000 * old_vsize < 101000 * replacement_vsize
                before = node.getrawmempool(True)
                assert_raises_rpc_error(- 26, 'insufficient fee', node.sendrawtransaction, replacement['hex'], 0)
                assert_equal(node.getrawmempool(True), before)
                assert_equal(set(before), {pid, cid})
                row['worsening_rbf_rejected'] = True
                self.generate(mini, 1)
                # A wallet-created payment and the existing wallet fee-bump RPC.
                txid = wallet.sendtoaddress(mini.get_address(), Decimal('0.001'), fee_rate=2)
                bump = wallet.bumpfee(txid, {'fee_rate': 4})
                assert txid not in node.getrawmempool()
                assert bump['txid'] in node.getrawmempool()
                row['wallet_bumpfee'] = {'passed': True, 'original_fee': bump['origfee'], 'new_fee': bump['fee']}
                self.generate(mini, 1)
                assert_equal(node.getrawmempool(), [])
                wallet.unloadwallet()
                mini.rescan_utxos()
                self.results['rows'].append(row)
                self.save()
        self.test_mixed_schemes_and_truc(node, mini)
        self.results['complete'] = True
        self.save()


if __name__ == '__main__':
    ClusterPQTest(__file__).main()
