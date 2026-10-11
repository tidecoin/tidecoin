#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Import uses referenced wallet material, exact ranges, and usable public caches."""
from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import get_generate_key


class PQHDImportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        source = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet('import')
        wallet = node.get_wallet_rpc('import')
        seed = wallet.importpqhdseed('11' * 32)['seed_id']
        second_seed = wallet.importpqhdseed('22' * 32)['seed_id']

        def ref(seed_id, account=42):
            return f'pqhd({seed_id})/10007h/6868h/7h/{account}h/0h/*h'

        def request(body, **kwargs):
            return {'desc': descsum_create(body), 'timestamp': 'now', **kwargs}

        def imported(rpc, item, success=True, message=None):
            result = rpc.importdescriptors([item])[0]
            assert result['success'] == success, result
            if message:
                assert message in result['error']['message'], result
            return result

        def record(item):
            return next(d for d in wallet.listdescriptors()['descriptors'] if d['desc'] == item['desc'])

        self.log.info('Use wallet seeds without private data in descriptor text, starting above zero')
        ranged = request(f'wpkh({ref(seed)})', range=[5, 6], next_index=6)
        imported(wallet, ranged)
        assert_equal(record(ranged)['range'], [5, 6])
        expected = wallet.deriveaddresses(ranged['desc'], [5, 6])
        # Generic expansion may derive outside the monitored import range.
        assert_equal(wallet.getaddressinfo(wallet.deriveaddresses(ranged['desc'], [4, 4])[0])['ismine'], False)
        assert all(wallet.getaddressinfo(address)['ismine'] for address in expected)
        fixed = request(f'wpkh({ref(seed).replace("*h", "6h")})')
        imported(wallet, fixed)
        assert_equal(wallet.deriveaddresses(fixed['desc']), [expected[1]])
        multi = request(f'wsh(multi(2,{ref(seed, 43)},{ref(second_seed, 43)}))', range=[7, 8])
        imported(wallet, multi)
        assert_equal(record(multi)['range'], [7, 8])
        multi_addresses = wallet.deriveaddresses(multi['desc'], [7, 8])
        assert_equal(len(set(multi_addresses)), 2)
        baseline = wallet.listdescriptors()
        missing = request(f'wsh(multi(2,{ref(seed, 44)},{ref("00" * 32, 44)}))', range=[9, 10])
        imported(wallet, missing, False, 'Cannot expand descriptor')
        assert_equal(wallet.listdescriptors(), baseline)
        wallet.unloadwallet()
        node.loadwallet('import')
        wallet = node.get_wallet_rpc('import')
        assert_equal(wallet.listdescriptors(), baseline)
        assert_equal(wallet.deriveaddresses(multi['desc'], [7, 8]), multi_addresses)

        self.log.info('Persisted caches allow locked updates but do not authorize fresh derivation')
        wallet.encryptwallet('pass')
        wallet.walletpassphrase('pass', 60)
        wallet.walletlock()
        imported(wallet, ranged)
        assert_equal(record(ranged)['range'], [5, 6])
        baseline = wallet.listdescriptors()
        imported(wallet, {**ranged, 'range': [5, 7]}, False, 'Cannot expand descriptor')
        imported(wallet, request(f'wpkh({ref(seed, 45)})', range=[5, 6]), False, 'Cannot expand descriptor')
        assert_equal(wallet.listdescriptors(), baseline)
        wallet.unloadwallet()
        node.loadwallet('import')
        wallet = node.get_wallet_rpc('import')
        imported(wallet, ranged)
        assert_equal(wallet.listdescriptors(), baseline)
        wallet.walletpassphrase('pass', 60)
        imported(wallet, {**ranged, 'range': [5, 7]})
        wallet.walletlock()
        imported(wallet, {**ranged, 'range': [5, 7]})

        self.log.info('Public-only wallets accept explicit public keys, not seed references')
        node.createwallet('watch', disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc('watch')
        key = get_generate_key()
        public = request(f'wpkh({key.pubkey})')
        imported(watch, public)
        watch_baseline = watch.listdescriptors()
        imported(watch, ranged, False, 'Cannot expand descriptor')
        imported(watch, request(f'wpkh({key.privkey})'), False, 'private keys disabled')
        assert_equal(watch.listdescriptors(), watch_baseline)
        batch = watch.importdescriptors([ranged, public])
        assert_equal([result['success'] for result in batch], [False, True])
        # A wallet's unrelated PQHD seed is not signing material for this key.
        imported(wallet, public, False, 'without private keys')
        imported(wallet, request(f'wpkh({key.privkey})'), False, 'passphrase')
        wallet.walletpassphrase('pass', 60)
        imported(wallet, request(f'wpkh({key.privkey})'))
        # Existing explicit private keys can be reused by another descriptor.
        reused = request(f'sh(wpkh({key.pubkey}))')
        imported(wallet, reused)
        wallet.walletlock()
        imported(wallet, reused)

        self.log.info('Public expansion and partial signing do not imply transaction completion')
        wallet.walletpassphrase('pass', 60)
        self.generate(node, 101)
        for threshold in [1, 2]:
            # One PQHD key belongs to this wallet; the explicit public key does not.
            remote = get_generate_key()
            body = f'wsh(multi({threshold},{ref(seed, 50 + threshold)},{remote.pubkey}))'
            item = request(body, range=[3, 3])
            result = imported(wallet, item)
            assert_equal(result['warnings'], ['Not all private keys provided. Some wallet functionality may return unexpected errors'])
            address = wallet.deriveaddresses(item['desc'], [3, 3])[0]
            txid = source.sendtoaddress(address, 1)
            self.generate(node, 1)
            decoded = source.gettransaction(txid, verbose=True)['decoded']
            vout = next(i for i, out in enumerate(decoded['vout']) if out['scriptPubKey'].get('address') == address)
            raw = wallet.createrawtransaction([{'txid': txid, 'vout': vout}], {source.getnewaddress(): Decimal('0.999')})
            signed = wallet.signrawtransactionwithwallet(raw)
            assert_equal(signed['complete'], threshold == 1)
            witness = node.decoderawtransaction(signed['hex'])['vin'][0]['txinwitness']
            assert_equal(sum(bool(signature) for signature in witness[1:-1]), 1)
            if threshold == 1:
                node.sendrawtransaction(signed['hex'])
            else:
                # Import the missing key into the same descriptor, retaining cache.
                current = record(item)
                full = request(body.replace(remote.pubkey, remote.privkey), range=current['range'], next_index=current['next_index'])
                assert 'warnings' not in imported(wallet, full)
                completed = wallet.signrawtransactionwithwallet(signed['hex'])
                assert_equal(completed['complete'], True)
                node.sendrawtransaction(completed['hex'])

        wallet.unloadwallet()
        node.loadwallet('import')
        wallet = node.get_wallet_rpc('import')
        wallet.walletpassphrase('pass', 60)
        assert_equal(wallet.deriveaddresses(multi['desc'], [7, 8]), multi_addresses)
        watch.unloadwallet()
        node.loadwallet('watch')
        assert_equal(node.get_wallet_rpc('watch').listdescriptors(), watch_baseline)


if __name__ == '__main__':
    PQHDImportTest(__file__).main()
