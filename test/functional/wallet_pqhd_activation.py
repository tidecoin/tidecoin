#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""PQHD scheme preferences survive load and reorg around positive activation."""
from test_framework.descriptors import descsum_create
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
        self.check_locked_activation_reload()
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
        # Chain-dependent wallet RPCs must synchronize themselves.
        assert_equal(node.getblockcount(), 2)
        self.check_ineligible(wallet)
        assert_raises_rpc_error(-4, "not allowed before auxpow activation", wallet.setpqhdpolicy, "mldsa44", "mldsa65")
        wallet.setpqhdseed(receive_seed, change_seed)
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
        assert_equal(node.getblockcount(), 5)
        self.check_addresses(wallet, receive_seed, change_seed)

    def check_locked_activation_reload(self):
        node = self.nodes[0]
        name = 'preactivation-locked'
        self.log.info('A wallet made before activation reloads locked after activation')
        node.createwallet(name, passphrase='pass')
        wallet = node.get_wallet_rpc(name)
        wallet.walletpassphrase('pass', 60)
        seed_id = wallet.listpqhdseeds()[0]['seed_id']
        # Explicit active imports must survive both deferred load and unlock.
        imported = []
        for internal in (False, True):
            desc = descsum_create(f'wpkh(pqhd({seed_id})/10007h/1h/7h/42h/{int(internal)}h/*h)')
            result = wallet.importdescriptors([{'desc': desc, 'timestamp': 'now', 'range': [0, 2],
                                               'active': True, 'internal': internal}])[0]
            assert_equal(result['success'], True)
            imported.append(desc)
        before = self.active(wallet)
        assert_equal(len(before), 6)
        assert not any(desc.startswith('wsh512(') for desc in before)
        wallet.walletlock()
        wallet.unloadwallet()
        self.generate(node, 5)
        node.loadwallet(name)
        wallet = node.get_wallet_rpc(name)
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        assert_equal(self.active(wallet), before)
        assert_raises_rpc_error(-14, 'incorrect', wallet.walletpassphrase, 'wrong', 60)
        assert_equal(self.active(wallet), before)

        self.restart_node(0, extra_args=self.extra_args[0] + [f'-wallet={name}'])
        wallet = node.get_wallet_rpc(name)
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        assert_equal(self.active(wallet), before)
        wallet.walletpassphrase('pass', 60)
        expected = self.active(wallet)
        assert_equal(len(expected), 8)
        assert set(before).issubset(expected)
        assert set(imported).issubset(expected)
        issued = set()
        for _ in range(2):
            for internal in (False, True):
                address = wallet.getrawchangeaddress('bech32pq') if internal else wallet.getnewaddress('', 'bech32pq')
                assert address not in issued
                issued.add(address)
                info = wallet.getaddressinfo(address)
                assert_equal(info['pqhd_seedid'], seed_id)
                assert f'/0h/{int(internal)}h/' in info['pqhd_path']
            wallet.walletlock()
            wallet.unloadwallet()
            node.loadwallet(name)
            wallet = node.get_wallet_rpc(name)
            assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
            assert_equal(self.active(wallet), expected)
            wallet.walletpassphrase('pass', 60)
            assert_equal(self.active(wallet), expected)
        wallet.unloadwallet()

    def active(self, wallet):
        return sorted(d['desc'] for d in wallet.listdescriptors()['descriptors'] if d['active'])

    def check_ineligible(self, wallet):
        # This unencrypted wallet retains ML-DSA defaults, which are gated for
        # every address type, not just native witness v1.
        for kind in ['legacy', 'p2sh-segwit', 'bech32', 'bech32pq']:
            assert_raises_rpc_error(-12, 'not allowed', wallet.getnewaddress, '', kind)
            assert_raises_rpc_error(-12, 'not allowed', wallet.getrawchangeaddress, kind)
        wallet.getnewaddress('', 'bech32', 'falcon512')
        wallet.getrawchangeaddress('bech32', 'falcon512')

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
