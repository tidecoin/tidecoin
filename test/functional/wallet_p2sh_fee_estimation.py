#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""P2SH funding fees include the complete redeem-script push header."""

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal
from test_framework.wallet_util import generate_keypair


class P2SHFeeEstimationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-auxpowactivationheight=1', '-keypool=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 101)
        node.createwallet('p2sh_fee', blank=True)
        wallet = node.get_wallet_rpc('p2sh_fee')
        destination = miner.getnewaddress('', 'bech32')
        fee_rate = 10  # sat/vB: exact integer fee comparisons, with no rounding tolerance.
        mixed = []

        def check(inputs, fixed):
            raw = node.createrawtransaction(inputs, {destination: len(inputs)})
            funded = wallet.fundrawtransaction(raw, {
                'add_inputs': False, 'changeAddress': destination, 'fee_rate': fee_rate,
            })
            signed = wallet.signrawtransactionwithwallet(funded['hex'])
            assert signed['complete']
            decoded = node.decoderawtransaction(signed['hex'])
            assert_equal(len(decoded['vin']), len(inputs))
            actual_fee = 2 * len(inputs) - sum(out['value'] for out in decoded['vout'])
            assert_equal(funded['fee'], actual_fee)
            expected = Decimal(fee_rate * decoded['vsize']) / COIN
            assert_greater_than_or_equal(actual_fee, expected)
            if fixed:
                assert_equal(actual_fee, expected)
            assert node.testmempoolaccept([signed['hex']])[0]['allowed']

        keys = {scheme: generate_keypair(scheme=str(scheme)) for scheme in range(7, 12)}
        cases = []
        for scheme, (secret, _) in keys.items():
            for inner in (f'pk({secret})', f'multi(1,{secret})', f'pkh({secret})',
                          f'wpkh({secret})', f'wsh(pk({secret}))'):
                cases.append((f'scheme {scheme}, {inner.split("(")[0]}', inner, scheme >= 9))
        # Only the larger-signature key is available, making the 1-of-2 bound
        # exact while keeping this mixed-scheme input within relay size limits.
        _, other_pubkey = generate_keypair(scheme='9')
        cases.append(('mixed ML-DSA multisig', f'multi(1,{other_pubkey.hex()},{keys[10][0]})', True))

        for label, inner, fixed in cases:
            self.log.info('Checking %s with one and two inputs', label)
            descriptor = descsum_create(f'sh({inner})')
            assert wallet.importdescriptors([{'desc': descriptor, 'timestamp': 'now'}])[0]['success']
            address = node.deriveaddresses(descriptor)[0]
            inputs = []
            for _ in range(2):
                txid = miner.sendtoaddress(address, 2)
                previous = miner.gettransaction(txid, verbose=True)['decoded']
                index = next(out['n'] for out in previous['vout'] if out['scriptPubKey'].get('address') == address)
                inputs.append({'txid': txid, 'vout': index})
            self.generate(node, 1)
            check(inputs[:1], fixed)
            check(inputs, fixed)
            if inner == f'pk({keys[9][0]})' or inner == f'pk({keys[10][0]})':
                mixed.append(inputs[0])

        self.log.info('Checking multiple inputs with different fixed-size schemes')
        assert_equal(len(mixed), 2)
        check(mixed, True)


if __name__ == '__main__':
    P2SHFeeEstimationTest(__file__).main()
