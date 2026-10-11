#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Restore historical PQHD scripts from seeds and bounded descriptor metadata."""
from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class PQHDRecoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2', '-auxpowactivationheight=4']]

    def add_options(self, parser):
        parser.add_argument('--use-filter', action='store_true')

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        if self.options.use_filter:
            self.extra_args[0].append('-blockfilterindex=1')
        super().setup_network()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        node.setmocktime(1700000000)
        self.generate(node, 101)
        node.createwallet('original', blank=True)
        original = node.get_wallet_rpc('original')
        seeds = ['31' * 32, '32' * 32]
        seed_ids = [original.importpqhdseed(seed)['seed_id'] for seed in seeds]

        def key(seed, scheme, account, branch):
            return f'pqhd({seed})/10007h/6868h/{scheme}h/{account}h/{branch}h/*h'

        def import_ok(wallet, requests):
            results = wallet.importdescriptors(requests)
            assert_equal(len(results), len(requests))
            for result in results:
                assert result['success'], result

        def entries(wallet):
            return {entry['desc']: entry for entry in wallet.listdescriptors()['descriptors']}

        self.log.info('Create historical receive/change scripts for all five schemes and two seeds')
        requests = []
        for scheme, wrapper in [(7, 'pkh({})'), (8, 'sh(wpkh({}))'), (9, 'wpkh({})'),
                                (10, 'wsh512(pk({}))'), (11, 'wsh(pk({}))')]:
            for branch in (0, 1):
                body = wrapper.format(key(seed_ids[branch], scheme, 40 + scheme, branch))
                requests.append({'desc': descsum_create(body), 'timestamp': 0, 'range': [12, 14],
                                 'next_index': 14, 'active': True, 'internal': bool(branch)})
        # Recovery also needs the exact multikey script, not just its seeds.
        multisig = descsum_create(f'wsh(multi(2,{key(seed_ids[0], 7, 90, 0)},{key(seed_ids[1], 9, 91, 0)}))')
        requests.append({'desc': multisig, 'timestamp': 0, 'range': [12, 14], 'next_index': 14})
        import_ok(original, requests)
        addresses = [original.deriveaddresses(item['desc'], [12, 12])[0] for item in requests]
        payment = miner.sendmany('', {address: 1 for address in addresses})
        self.generate(node, 1)
        assert_equal(original.getbalance(), len(addresses))
        public = [original.getaddressinfo(address)['desc'] for address in addresses]
        for desc in public:
            info = node.getdescriptorinfo(desc)
            assert not info['isrange']
            assert not info['hasprivatekeys']
            assert 'pqhd(' not in desc
        metadata = list(entries(original).values())
        assert_equal(len(metadata), len(requests))
        # Historical activity is older than the two-hour timestamp window.
        payment_time = node.getblockheader(node.getbestblockhash())['time']
        node.setmocktime(payment_time + 10800)
        self.generate(node, 11)  # Advance median time past the historical payment too.

        self.log.info('Seed storage and insufficient ranges do not imply historical recovery')
        node.createwallet('restored', blank=True)
        restored = node.get_wallet_rpc('restored')
        for seed, seed_id in zip(seeds, seed_ids):
            assert_equal(restored.importpqhdseed(seed)['seed_id'], seed_id)
        assert 'stores the seed only' in restored.help('importpqhdseed')
        assert_equal(restored.listdescriptors()['descriptors'], [])
        assert_equal(restored.getbalance(), 0)
        assert_equal(restored.getwalletinfo()['txcount'], 0)
        short = [{'desc': item['desc'], 'timestamp': 0, 'range': [0, 1]} for item in metadata]
        import_ok(restored, short)
        assert_equal(restored.getbalance(), 0)
        # Include the earlier imported range; a descriptor update may not shrink it.
        recovery = [{**item, 'range': [0, item['range'][1]]} for item in metadata]
        self.log.info('Correct scripts with a recent scan time still miss old payments')
        import_ok(restored, [{**item, 'timestamp': 'now'} for item in recovery])
        assert_equal(restored.getbalance(), 0)
        import_ok(restored, recovery)
        assert_equal(restored.getbalance(), len(addresses))
        assert_equal(restored.gettransaction(payment)['confirmations'], 12)
        before = entries(restored)
        for item in metadata:
            assert_equal(before[item['desc']]['next_index'], item['next_index'])
            assert_equal(before[item['desc']]['active'], item['active'])
        # Stale next indices and later birthdays must not undo recovery state.
        import_ok(restored, [{**item, 'next_index': 0, 'timestamp': 'now'} for item in recovery])
        after = entries(restored)
        for desc, item in before.items():
            assert_equal(after[desc]['next_index'], item['next_index'])
            assert_equal(after[desc]['timestamp'], item['timestamp'])

        self.log.info('Transfer finite public descriptors to a wallet that holds no seeds')
        node.createwallet('watch', disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc('watch')
        rejected = watch.importdescriptors([{'desc': metadata[0]['desc'], 'range': [12, 14], 'timestamp': 0}])[0]
        assert not rejected['success']
        import_ok(watch, [{'desc': desc, 'timestamp': 0} for desc in public])
        assert_equal(watch.getbalance(), len(addresses))
        assert_equal(watch.listpqhdseeds(), [])
        assert not watch.getwalletinfo()['private_keys_enabled']
        assert_raises_rpc_error(-4, 'disabled', watch.importpqhdseed, seeds[0])
        # Provision one further fixed script; no fresh PQHD derivation is available to watch.
        parent = metadata[0]['desc']
        extra = original.deriveaddresses(parent, [14, 14])[0]
        miner.sendtoaddress(extra, 1)
        self.generate(node, 1)
        assert_equal(watch.getbalance(), len(addresses))
        import_ok(watch, [{'desc': original.getaddressinfo(extra)['desc'], 'timestamp': 0}])
        assert_equal(watch.getbalance(), len(addresses) + 1)
        assert_equal(watch.listpqhdseeds(), [])
        expected = Decimal(len(addresses) + 1)
        assert_equal(restored.getbalance(), expected)

        self.log.info('An exhausted exported range is restorable without widening its format')
        terminal = descsum_create('wpkh(' + key(seed_ids[0], 7, 99, 0) + ')')
        terminal_request = {'desc': terminal, 'timestamp': 'now', 'range': [2147483646, 2147483646],
                            'next_index': 2147483647}
        import_ok(restored, [terminal_request])
        assert_equal(entries(restored)[terminal]['next_index'], 2147483647)
        for bad in (-1, 2147483648):
            result = restored.importdescriptors([{**terminal_request, 'next_index': bad}])[0]
            assert not result['success']
            assert_equal(result['error']['message'], 'next_index is out of range')

        self.log.info('Restart with no original wallet and verify recovered signing and allocation')
        node.unloadwallet('original')
        node.unloadwallet('restored')
        node.loadwallet('restored')
        assert_equal(restored.getbalance(), expected)
        self.restart_node(0)
        node = self.nodes[0]
        for name in (self.default_wallet_name, 'restored', 'watch'):
            if name not in node.listwallets():
                node.loadwallet(name)
        miner = node.get_wallet_rpc(self.default_wallet_name)
        restored = node.get_wallet_rpc('restored')
        watch = node.get_wallet_rpc('watch')
        assert 'original' not in node.listwallets()
        assert_equal(restored.getbalance(), expected)
        assert_equal(watch.getbalance(), expected)
        # Active custom scripts, including internal ones, survive reconstruction.
        active = [item for item in entries(restored).values() if item['active']]
        for item in active:
            body = item['desc']
            output_type = ('legacy' if body.startswith('pkh(') else
                           'p2sh-segwit' if body.startswith('sh(') else
                           'bech32pq' if body.startswith('wsh512(') else 'bech32')
            index = item['next_index']
            expected_address = restored.deriveaddresses(body, [index, index])[0]
            actual = (restored.getrawchangeaddress(output_type) if item['internal'] else
                      restored.getnewaddress('', output_type))
            assert_equal(actual, expected_address)
            assert actual not in addresses
        coins = restored.listunspent()
        assert_equal(sum(coin['amount'] for coin in coins), expected)
        psbt = node.createpsbt([{'txid': coin['txid'], 'vout': coin['vout']} for coin in coins],
                              {miner.getnewaddress(): expected - Decimal('0.01')})
        public_psbt = watch.walletprocesspsbt(psbt)
        assert not public_psbt['complete']
        assert all('partial_signatures' not in item for item in node.decodepsbt(public_psbt['psbt'])['inputs'])
        signed = restored.walletprocesspsbt(public_psbt['psbt'])
        assert signed['complete']
        final = node.finalizepsbt(signed['psbt'])
        assert final['complete']
        txid = node.sendrawtransaction(final['hex'])
        self.generate(node, 1)
        assert_equal(restored.gettransaction(txid)['confirmations'], 1)
        assert_equal(restored.getbalance(), 0)
        assert_equal(watch.getbalance(), 0)


if __name__ == '__main__':
    PQHDRecoveryTest(__file__).main()
