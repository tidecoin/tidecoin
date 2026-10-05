#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep private PQHD seeds out of watch-only and external-signer wallets."""
from contextlib import closing
import sqlite3
import sys
import struct

from test_framework.messages import ser_string
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def records(path):
    with closing(sqlite3.connect(path)) as db:
        return dict(db.execute('SELECT key,value FROM main'))


class PQHDSeedRestrictionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        for signer in [False, True] if self.is_external_signer_compiled() else [False]:
            if signer:
                # A finite explicit-public-key mock exercises wallet restrictions
                # without relying on unsupported ranged signer provisioning.
                source = node.get_wallet_rpc(self.default_wallet_name)
                public_keys = [source.getaddressinfo(source.getnewaddress('', 'bech32'))['pubkey'] for _ in range(2)]
                descriptors = {'receive': [f'wpkh({public_keys[0]})'], 'internal': [f'wpkh({public_keys[1]})']}
                mock = node.datadir_path / 'public_signer.py'
                mock.write_text('import json, sys\n' +
                                'print(json.dumps(' + repr(descriptors) + " if 'getdescriptors' in sys.argv else [{'fingerprint': '00000001', 'model': 'public-test'}]))\n", encoding='utf8')
                def quote(value):
                    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'
                self.restart_node(0, extra_args=['-keypool=1', '-signer=' + quote(sys.executable) + ' ' + quote(mock)])
            name = 'signer' if signer else 'watch'
            node.createwallet(name, disable_private_keys=True, blank=True, external_signer=signer)
            wallet = node.get_wallet_rpc(name)
            expected_descriptors = wallet.listdescriptors()['descriptors']
            wallet.unloadwallet()
            path = node.wallets_path / name / 'wallet.dat'
            before = records(path)
            node.loadwallet(name)
            wallet = node.get_wallet_rpc(name)
            assert_raises_rpc_error(-4, 'Private PQHD seeds are disabled', wallet.importpqhdseed, '11' * 32)
            assert_raises_rpc_error(-4, 'Private PQHD seeds are disabled', wallet.setpqhdseed, '00' * 32)
            assert_raises_rpc_error(-4, 'Private PQHD seeds are disabled', wallet.setpqhdpolicy, 'falcon512', 'falcon512')
            assert_equal(wallet.listpqhdseeds(), [])
            assert_equal(wallet.listdescriptors()['descriptors'], expected_descriptors)
            assert_equal(wallet.getwalletinfo()['private_keys_enabled'], False)
            wallet.unloadwallet()
            assert_equal(records(path), before)
            node.loadwallet(name)
            assert_equal(node.get_wallet_rpc(name).listpqhdseeds(), [])

        self.log.info('Reject inconsistent seed-bearing wallets without rewriting their records')
        for encrypted in [False, True]:
            name = 'encrypted' if encrypted else 'plain'
            node.createwallet(name)
            wallet = node.get_wallet_rpc(name)
            address = wallet.getnewaddress('', 'legacy')
            if encrypted:
                wallet.encryptwallet('pass')
            wallet.unloadwallet()
            path = node.wallets_path / name / 'wallet.dat'
            with closing(sqlite3.connect(path)) as db:
                flags_key = ser_string(b'flags')
                flags = db.execute('SELECT value FROM main WHERE key=?', (flags_key,)).fetchone()[0]
                disabled = struct.pack('<Q', struct.unpack('<Q', flags)[0] | (1 << 32))
                db.execute('UPDATE main SET value=? WHERE key=?', (disabled, flags_key))
                db.commit()
            malformed = records(path)
            assert_raises_rpc_error(-4, 'Wallet corrupted', node.loadwallet, name)
            assert_equal(records(path), malformed)
            # Restore the fixture's original flag only; no seed repair is needed.
            with closing(sqlite3.connect(path)) as db:
                db.execute('UPDATE main SET value=? WHERE key=?', (flags, flags_key))
                db.commit()
            node.loadwallet(name)
            wallet = node.get_wallet_rpc(name)
            if encrypted:
                wallet.walletpassphrase('pass', 60)
            assert node.verifymessage(address, wallet.signmessage(address, 'preserved'), 'preserved')


if __name__ == '__main__':
    PQHDSeedRestrictionsTest(__file__).main()
