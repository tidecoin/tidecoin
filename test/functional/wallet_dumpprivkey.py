#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Export exact single keys by address or descriptor, including native witness v1."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class DumpPrivKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2', '-auxpowactivationheight=1']]
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet('imported', blank=True)
        imported = node.get_wallet_rpc('imported')
        node.createwallet('watch', disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc('watch')

        def import_descriptor(wallet, expression):
            descriptor = descsum_create(expression)
            assert wallet.importdescriptors([{'desc': descriptor, 'timestamp': 'now'}])[0]['success']
            return descriptor, node.deriveaddresses(descriptor)[0]

        self.log.info('Imported single-key exports agree for all five schemes and four address types')
        for scheme in ('falcon-512', 'falcon-1024', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'):
            secret, public = generate_keypair(scheme=scheme)
            for template in ('wsh512(pk({}))', 'pkh({})', 'wpkh({})', 'sh(wpkh({}))'):
                descriptor, address = import_descriptor(imported, template.format(secret))
                assert_equal(imported.dumpprivkey(descriptor), secret)
                assert_equal(imported.dumpprivkey(address), secret)
                watch_descriptor, watch_address = import_descriptor(watch, template.format(public.hex()))
                assert_equal(watch_address, address)
                assert_raises_rpc_error(-4, 'Private key not available in wallet', watch.dumpprivkey, address)
                assert_raises_rpc_error(-4, 'Private key not available for descriptor', watch.dumpprivkey, watch_descriptor)
                if scheme == 'falcon-512':
                    assert_equal(imported.dumpprivkey(address, {'format': 'legacy'}),
                                 imported.dumpprivkey(descriptor, {'format': 'legacy'}))
                else:
                    assert_raises_rpc_error(-8, 'legacy format is only supported for Falcon-512',
                                            imported.dumpprivkey, address, {'format': 'legacy'})

        self.log.info('A native-v1 address must resolve its script, not merely one available private key')
        first, first_pub = generate_keypair()
        second, second_pub = generate_keypair()
        unknown = node.deriveaddresses(descsum_create(f'wsh512(pk({first_pub.hex()}))'))[0]
        assert_raises_rpc_error(-4, 'address not found in wallet', imported.dumpprivkey, unknown)
        # Import the mixed public/private descriptor before its all-private
        # form: they share an ID, and importing a second key doesn't remove it.
        for expression, multiple_keys in (
            (f'wsh512(multi(1,{first}))', False),
            (f'wsh512(multi(1,{first},{second_pub.hex()}))', True),
            (f'wsh512(multi(1,{first},{second}))', True),
            (f'wsh512(pkh({first}))', False),
            (f'wsh512(and_v(v:pk({first}),after(10)))', False),
            (f'wsh(pk({first}))', False),
            (f'sh(wsh(pk({first})))', False),
        ):
            descriptor, address = import_descriptor(imported, expression)
            assert_raises_rpc_error(-8, 'Address does not resolve to a supported single-key script. Use a single-key wallet descriptor.',
                                    imported.dumpprivkey, address)
            if multiple_keys:
                assert_raises_rpc_error(-8, 'Descriptor does not contain a single key', imported.dumpprivkey, descriptor)
            else:
                # The address limitation does not prevent export by its single-key descriptor.
                assert_equal(imported.dumpprivkey(descriptor), first)

        self.log.info('Multi-key targets are ambiguous even in a watch-only wallet')
        descriptor, address = import_descriptor(watch, f'wsh512(multi(1,{first_pub.hex()},{second_pub.hex()}))')
        assert_raises_rpc_error(-8, 'Address does not resolve to a supported single-key script. Use a single-key wallet descriptor.',
                                watch.dumpprivkey, address)
        assert_raises_rpc_error(-8, 'Descriptor does not contain a single key', watch.dumpprivkey, descriptor)

        self.log.info('PQHD exports select the correct receive/change child and require unlocking')
        node.createwallet('pqhd', passphrase='test-passphrase')
        pqhd = node.get_wallet_rpc('pqhd')
        pqhd.walletpassphrase('test-passphrase', 300)
        descriptors = {
            entry['internal']: entry['desc'] for entry in pqhd.listdescriptors()['descriptors']
            if entry['active'] and entry['desc'].startswith('wsh512(')
        }
        assert_equal(set(descriptors), {False, True})
        exported = {}
        for internal, descriptor in descriptors.items():
            for index in range(2):
                address = (pqhd.getrawchangeaddress('bech32pq') if internal
                           else pqhd.getnewaddress(address_type='bech32pq'))
                assert_equal(pqhd.deriveaddresses(descriptor, [index, index]), [address])
                key = pqhd.dumpprivkey(descriptor, {'index': index})
                assert_equal(pqhd.dumpprivkey(address), key)
                assert_equal(node.deriveaddresses(descsum_create(f'wsh512(pk({key}))')), [address])
                exported[address] = key
        assert_equal(len(set(exported.values())), 4)
        pqhd.walletlock()
        for address in exported:
            assert_raises_rpc_error(-13, 'Please enter the wallet passphrase', pqhd.dumpprivkey, address)
        for descriptor in descriptors.values():
            assert_raises_rpc_error(-13, 'Please enter the wallet passphrase', pqhd.dumpprivkey, descriptor)
        node.unloadwallet('pqhd')
        node.loadwallet('pqhd')
        pqhd = node.get_wallet_rpc('pqhd')
        pqhd.walletpassphrase('test-passphrase', 300)
        for address, key in exported.items():
            assert_equal(pqhd.dumpprivkey(address), key)


if __name__ == '__main__':
    DumpPrivKeyTest(__file__).main()
