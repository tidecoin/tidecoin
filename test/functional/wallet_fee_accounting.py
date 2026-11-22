#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Whole-transaction fee accounting, count boundaries and exact weight constraints."""
from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN, CTransaction, CTxOut, ser_compact_size, ser_string, tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair_at_index


class WalletFeeAccountingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=1', '-auxpowactivationheight=1']]

    def add_options(self, parser):
        parser.add_argument('--case', choices=['all', 'counts', 'limits', 'weights', 'truc'], default='all')

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_truc_limits(self, miner, recipient, change):
        node = self.nodes[0]
        node.createwallet('truc', blank=True)
        wallet = node.get_wallet_rpc('truc')
        private, public = generate_keypair_at_index(13009, scheme='9')
        desc = descsum_create(f'wpkh({private})')
        assert wallet.importdescriptors([{'desc': desc, 'timestamp': 'now'}])[0]['success']
        address = node.deriveaddresses(node.getdescriptorinfo(desc)['descriptor'])[0]
        parent = CTransaction()
        parent.version = 3
        parent.vout = [CTxOut(COIN // 10, bytes.fromhex(node.validateaddress(address)['scriptPubKey'])) for _ in range(4)]
        funded = miner.fundrawtransaction(parent.serialize().hex(), {'fee_rate': 2, 'changePosition': 4})
        txid = node.sendrawtransaction(miner.signrawtransactionwithwallet(funded['hex'])['hex'])
        inputs = [{'txid': txid, 'vout': i} for i in range(4)]
        options = {'add_inputs': False, 'include_unsafe': True, 'fee_rate': 2, 'changeAddress': change}

        def fund(selected, amount, extra=None, funder=wallet):
            return funder.walletcreatefundedpsbt(selected, [{recipient: amount}], 0, options | (extra or {}), version=3)

        def accept(funded, count):
            final = node.finalizepsbt(wallet.walletprocesspsbt(funded['psbt'])['psbt'])
            assert final['complete']
            decoded = node.decoderawtransaction(final['hex'])
            assert_equal(len(decoded['vin']), count)
            assert node.testmempoolaccept([final['hex']])[0]['allowed']
            return decoded

        # ML-DSA has fixed signatures: four inputs fit without change (15962 WU)
        # but exceed the 16000-WU child limit with native-v1 change (16262 WU).
        assert_raises_rpc_error(-4, 'Transaction too large', fund, inputs, Decimal('0.35'))
        assert_equal(accept(fund(inputs[:3], Decimal('0.25')), 3)['weight'], 12357)
        # Allow per-input vbyte rounding in the selection target, leaving only
        # uneconomic change, which is added to the fee.
        assert_equal(accept(fund(inputs, Decimal('0.4') - Decimal(8000) / COIN), 4)['weight'], 15962)
        for preset, error in (([], 'The inputs size exceeds the maximum weight'), (inputs[:2], 'Transaction too large')):
            accept(fund(preset, Decimal('0.25'), {'add_inputs': True}), 3)
            assert_raises_rpc_error(-4, error, fund, preset, Decimal('0.35'), {'add_inputs': True})

        # Preserve a tighter caller limit; also exercise the exact child boundary
        # in the maximum estimate independently of the smaller actual signature.
        accept(fund(inputs[:3], Decimal('0.25'), {'max_tx_weight': 12357}), 3)
        assert_raises_rpc_error(-4, 'Transaction too large', fund, inputs[:3], Decimal('0.25'), {'max_tx_weight': 12356})
        at_limit = [inputs[0] | {'weight': 3905 + 16000 - 12357}, *inputs[1:3]]
        accept(fund(at_limit, Decimal('0.25')), 3)
        over_limit = [at_limit[0] | {'weight': at_limit[0]['weight'] + 1}, *at_limit[1:]]
        assert_raises_rpc_error(-4, 'Transaction too large', fund, over_limit, Decimal('0.25'))

        # An external funder has no wallet transaction/depth for these inputs.
        node.createwallet('truc_external', blank=True)
        external = node.get_wallet_rpc('truc_external')
        solving = {'solving_data': {'descriptors': [descsum_create(f'wpkh({public.hex()})')]}}
        assert_raises_rpc_error(-4, 'Transaction too large', fund, inputs, Decimal('0.35'), solving, external)
        accept(fund(inputs[:3], Decimal('0.25'), solving, external), 3)
        self.generate(node, 1)
        # Once the parent confirms, the same four inputs may use the larger v3 limit.
        for funder, extra in ((wallet, {}), (external, solving)):
            assert_equal(accept(fund(inputs, Decimal('0.35'), extra, funder), 4)['weight'], 16262)

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 110)
        miner = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet('funding', blank=True)
        node.createwallet('recipient')
        wallet = node.get_wallet_rpc('funding')
        receiver = node.get_wallet_rpc('recipient')
        recipient = receiver.getnewaddress('', 'bech32pq', 'falcon512')
        change = receiver.getnewaddress('', 'bech32pq', 'falcon512')
        if self.options.case in ('all', 'truc'):
            self.test_truc_limits(miner, recipient, change)
        if self.options.case == 'truc':
            return
        options = {'add_inputs': False, 'fee_rate': 1, 'changeAddress': change, 'replaceable': True}
        coins = {}
        pubkeys = {}
        addresses = {}
        for scheme in range(7, 12):
            private, public = generate_keypair_at_index(12000 + scheme, scheme=str(scheme))
            pubkeys[scheme] = public
            desc = descsum_create(f'wpkh({private})')
            assert wallet.importdescriptors([{'desc': desc, 'timestamp': 'now'}])[0]['success']
            address = node.deriveaddresses(node.getdescriptorinfo(desc)['descriptor'])[0]
            addresses[scheme] = address
            script = bytes.fromhex(node.validateaddress(address)['scriptPubKey'])
            coins[scheme] = []
            for start in range(0, 281 if scheme == 7 else 3, 60):
                count = min(60, (281 if scheme == 7 else 3) - start)
                tx = CTransaction()
                tx.vout = [CTxOut(COIN // 10, script) for _ in range(count)]
                funded = miner.fundrawtransaction(tx.serialize().hex(), {'fee_rate': 1, 'changePosition': count})
                signed = miner.signrawtransactionwithwallet(funded['hex'])
                assert signed['complete']
                txid = node.sendrawtransaction(signed['hex'])
                coins[scheme].extend({'txid': txid, 'vout': i} for i in range(count))
                self.generate(node, 1)

        def check(scheme, selected, outputs, extra=None, funding_wallet=None, external=False):
            funded = (funding_wallet or wallet).walletcreatefundedpsbt(selected, outputs, 0, options | (extra or {}))
            signed = wallet.walletprocesspsbt(funded['psbt'])
            final = node.finalizepsbt(signed['psbt'])
            assert final['complete']
            tx = tx_from_hex(final['hex'])
            decoded = node.decoderawtransaction(final['hex'])
            actual_selected = [{'txid': v['txid'], 'vout': v['vout']} for v in decoded['vin']]
            if selected:
                comparison = actual_selected[:len(selected)] if (extra or {}).get('add_inputs') else actual_selected
                assert_equal(comparison, [{k: v[k] for k in ('txid', 'vout')} for v in selected])
            else:
                assert all(v in coins[scheme] for v in actual_selected)
            count = len(actual_selected)
            payment = sum(next(iter(o.values())) for o in outputs)
            subtract = (extra or {}).get('subtractFeeFromOutputs', [])
            assert_equal(sum(o['value'] for i, o in enumerate(decoded['vout']) if i != funded['changepos']), payment - (funded['fee'] if subtract else 0))
            for i, output in enumerate(outputs):
                if i not in subtract:
                    address, amount = next(iter(output.items()))
                    assert_equal(next(o['value'] for j, o in enumerate(decoded['vout']) if j != funded['changepos'] and o['scriptPubKey'].get('address') == address), amount)
            assert_equal(Decimal(count) / 10 - sum(o['value'] for o in decoded['vout']), funded['fee'])
            # Independent serialization of the maximum wpkh satisfaction; never verify synthetic signatures.
            sig_size = {7: 666, 8: 1280, 9: 2420, 10: 3309, 11: 4627}[scheme] + 1
            if external and scheme in (7, 8):
                sig_size = {7: 752, 8: 1462}[scheme] + 1
            input_weight = 164 + 1 + len(ser_string(bytes(sig_size))) + len(ser_string(pubkeys[scheme]))
            weight = 4 * (8 + len(ser_compact_size(count)) + len(ser_compact_size(len(tx.vout))) + sum(len(o.serialize()) for o in tx.vout)) + 2 + count * input_weight
            assert_greater_than_or_equal(funded['fee'] * COIN, (weight + 3) // 4)
            assert_greater_than_or_equal((extra or {}).get('max_tx_weight', 800000), weight)
            assert node.testmempoolaccept([final['hex']])[0]['allowed']
            return funded

        if self.options.case in ('all', 'counts'):
            for count in (252, 253, 281):
                check(7, coins[7][:count], [{recipient: Decimal(count) / 10 - 1}])
            recipients = [receiver.getnewaddress('', 'bech32', 'falcon512') for _ in range(253)]
            for scheme in coins:
                for count in (251, 252, 253):
                    check(scheme, coins[scheme][:1], [{a: Decimal('0.0001')} for a in recipients[:count]])
            check(7, coins[7][:253], [{a: Decimal('0.0001')} for a in recipients[:252]])
            for scheme in coins:
                check(scheme, coins[scheme][:1], [{a: Decimal('0.0001')} for a in recipients[:252]], {'subtractFeeFromOutputs': [0, 1, 251]})
            # No change: the exact fee includes the two extra input-count bytes.
            exact_fee = 253 * 434 + 88
            total = Decimal('25.3')
            check(7, coins[7][:253], [{recipient: total - Decimal(exact_fee) / COIN}])
            assert_raises_rpc_error(-4, 'preselected coins total amount', wallet.walletcreatefundedpsbt, coins[7][:253], [{recipient: total - Decimal(exact_fee - 1) / COIN}], 0, options)

            # Automatic selection must also account for an observed count transition.
            others = [p for scheme, points in coins.items() if scheme != 7 for p in points]
            wallet.lockunspent(False, others)
            try:
                check(7, [], [{recipient: Decimal('27')}], {'add_inputs': True})
                check(7, coins[7][:250], [{recipient: Decimal('27')}], {'add_inputs': True})
                exact_fee = 281 * 434 + 88
                total = Decimal('28.1')
                check(7, [], [{recipient: total - Decimal(exact_fee) / COIN}], {'add_inputs': True})
                assert_raises_rpc_error(-4, 'Insufficient funds', wallet.walletcreatefundedpsbt, [], [{recipient: total - Decimal(exact_fee - 1) / COIN}], 0, options | {'add_inputs': True})
            finally:
                wallet.lockunspent(True, others)

        if self.options.case in ('all', 'limits'):
            for scheme, maximum in ((9, 4547), (10, 6076), (11, 8034)):
                for limit in (maximum - 40, maximum - 1):
                    assert_raises_rpc_error(-4, 'Transaction too large', wallet.walletcreatefundedpsbt, coins[scheme][:1], [{recipient: Decimal('0.05')}], 0, options | {'max_tx_weight': limit})
                check(scheme, coins[scheme][:1], [{recipient: Decimal('0.05')}], {'max_tx_weight': maximum})

        if self.options.case in ('all', 'weights'):
            for scheme, weight in ((7, 1736), (8, 3246), (9, 3905), (10, 5434), (11, 7392)):
                for delta in (1, 2, 3):
                    inputs = [p | {'weight': weight - delta} for p in coins[scheme][:2]]
                    assert_raises_rpc_error(-4, 'Specified input weight is too low', wallet.walletcreatefundedpsbt, inputs, [{recipient: Decimal('0.1')}], 0, options)
                check(scheme, [p | {'weight': weight} for p in coins[scheme][:2]], [{recipient: Decimal('0.1')}])
            node.createwallet('public', disable_private_keys=True, blank=True)
            node.createwallet('external', blank=True)
            public_wallet = node.get_wallet_rpc('public')
            external_wallet = node.get_wallet_rpc('external')
            for scheme, weight in ((7, 1822), (8, 3428), (9, 3905), (10, 5434), (11, 7392)):
                public_desc = descsum_create(f'wpkh({pubkeys[scheme].hex()})')
                assert public_wallet.importdescriptors([{'desc': public_desc, 'timestamp': 0}])[0]['success']
                for funding_wallet, solving in ((public_wallet, {}), (external_wallet, {'solving_data': {'descriptors': [public_desc]}})):
                    low = [p | {'weight': weight - 1} for p in coins[scheme][:2]]
                    assert_raises_rpc_error(-4, 'Specified input weight is too low', funding_wallet.walletcreatefundedpsbt, low, [{recipient: Decimal('0.1')}], 0, options | solving)
                    exact = [p | {'weight': weight} for p in coins[scheme][:2]]
                    check(scheme, exact, [{recipient: Decimal('0.1')}], solving, funding_wallet, external=True)

        if self.options.case == 'all':
            assert_equal(node.getrawmempool(), [])
            check(11, coins[11][:1], [{recipient: Decimal('0.05')}], {'lockUnspents': True})
            assert_equal(wallet.listlockunspent(), coins[11][:1])
            wallet.lockunspent(True, coins[11][:1])
            # Both bump paths inherit the same assembled-transaction accounting.
            funded = wallet.walletcreatefundedpsbt(coins[7][:253], [{recipient: Decimal('24.3')}], 0, options | {'fee_rate': Decimal('1.01'), 'changeAddress': addresses[7], 'changePosition': 1})
            signed = wallet.walletprocesspsbt(funded['psbt'])
            txid = node.sendrawtransaction(node.finalizepsbt(signed['psbt'])['hex'])
            bump_options = {'fee_rate': 3, 'original_change_index': 1}
            bumped = wallet.psbtbumpfee(txid, bump_options)
            final = node.finalizepsbt(wallet.walletprocesspsbt(bumped['psbt'])['psbt'])
            assert final['complete']
            assert node.testmempoolaccept([final['hex']])[0]['allowed']
            decoded = node.decoderawtransaction(final['hex'])
            assert_equal(len(decoded['vin']), 253)
            assert_equal(next(o['value'] for o in decoded['vout'] if o['scriptPubKey'].get('address') == recipient), Decimal('24.3'))
            assert_greater_than_or_equal(bumped['fee'] * COIN, 3 * decoded['vsize'])
            replacement = wallet.bumpfee(txid, bump_options)
            assert_greater_than_or_equal(node.getmempoolentry(replacement['txid'])['fees']['base'] * COIN, 3 * node.getmempoolentry(replacement['txid'])['vsize'])
        assert_equal(wallet.listlockunspent(), [])


if __name__ == '__main__':
    WalletFeeAccountingTest(__file__).main()
