#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""PQHD scheme preferences survive load and reorg around positive activation."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class PQHDActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2', '-auxpowactivationheight=4']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 5)
        node.createwallet('policy')
        wallet = node.get_wallet_rpc('policy')
        receive_seed = wallet.listpqhdseeds()[0]['seed_id']
        change_seed = wallet.importpqhdseed('22' * 32)['seed_id']
        wallet.setpqhdseed(receive_seed, change_seed)
        wallet.setpqhdpolicy('mldsa44', 'mldsa65')
        self.check_addresses(wallet, receive_seed, change_seed)
        expected = self.active(wallet)
        wallet.unloadwallet()
        node.loadwallet('policy')
        wallet = node.get_wallet_rpc('policy')
        assert_equal(self.active(wallet), expected)
        self.check_addresses(wallet, receive_seed, change_seed)
        self.restart_node(0)
        node.loadwallet('policy')
        wallet = node.get_wallet_rpc('policy')
        assert_equal(self.active(wallet), expected)
        self.check_addresses(wallet, receive_seed, change_seed)

        self.log.info('Below activation, preserve preferences while refusing ineligible issuance')
        disconnect = node.getblockhash(3)
        node.invalidateblock(disconnect)
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getblockcount(), 2)
        self.check_ineligible(wallet)
        wallet.unloadwallet()
        node.loadwallet('policy')
        wallet = node.get_wallet_rpc('policy')
        assert_equal(self.active(wallet), expected)
        self.check_ineligible(wallet)
        self.restart_node(0)
        node.loadwallet('policy')
        wallet = node.get_wallet_rpc('policy')
        assert_equal(self.active(wallet), expected)
        self.check_ineligible(wallet)
        node.reconsiderblock(disconnect)
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getblockcount(), 5)
        self.check_addresses(wallet, receive_seed, change_seed)

    def active(self, wallet):
        return sorted(d['desc'] for d in wallet.listdescriptors()['descriptors'] if d['active'])

    def check_ineligible(self, wallet):
        for kind in ['legacy', 'p2sh-segwit', 'bech32', 'bech32pq']:
            assert_raises_rpc_error(-12, '', wallet.getnewaddress, '', kind)
            assert_raises_rpc_error(-12, '', wallet.getrawchangeaddress, kind)

    def check_addresses(self, wallet, receive_seed, change_seed):
        assert_equal(len(self.active(wallet)), 8)
        for kind in ['legacy', 'p2sh-segwit', 'bech32', 'bech32pq']:
            for internal, seed_id, prefix in [(False, receive_seed, '09'), (True, change_seed, '0a')]:
                addr = wallet.getrawchangeaddress(kind) if internal else wallet.getnewaddress('', kind)
                info = wallet.getaddressinfo(addr)
                assert_equal(info['pqhd_seedid'], seed_id)
                # PQ-native script addresses expose the contained key through
                # embedded metadata; the scheme is also explicit in the path.
                assert_equal(int(info['pqhd_path'].split('/')[3][:-1]), int(prefix, 16))


if __name__ == '__main__':
    PQHDActivationTest(__file__).main()
