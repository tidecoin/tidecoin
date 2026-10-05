#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject inconsistent PQHD records, authenticate caches, and bound private export."""
from contextlib import closing
from io import BytesIO
import sqlite3
import struct

from test_framework.descriptors import descsum_create
from test_framework.messages import deser_string, ser_string
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def records(path):
    with closing(sqlite3.connect(path)) as db:
        return dict(db.execute('SELECT key,value FROM main'))


def replace_records(path, old, new):
    with closing(sqlite3.connect(path)) as db:
        for key in old:
            if key not in new:
                db.execute('DELETE FROM main WHERE key=?', (key,))
        for key, value in new.items():
            if old.get(key) != value:
                db.execute('INSERT OR REPLACE INTO main(key,value) VALUES(?,?)', (key, value))
        db.commit()


class PQHDIntegrityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        for encrypted in [False, True]:
            name = 'encrypted' if encrypted else 'plain'
            node.createwallet(name)
            wallet = node.get_wallet_rpc(name)
            if encrypted:
                wallet.encryptwallet('pass')
                wallet.walletpassphrase('pass', 60)
            descriptor = next(d['desc'] for d in wallet.listdescriptors()['descriptors'] if d['active'] and not d['internal'] and d['desc'].startswith('wpkh('))
            for invalid in [-1, 2**31, 2**32]:
                assert_raises_rpc_error(-8, 'index must be between', wallet.dumpprivkey, descriptor, {'index': invalid})
            # The full stateless PQHD endpoint still expands in bounded work.
            assert_equal(len(wallet.deriveaddresses(descriptor, [2**31 - 1, 2**31 - 1])), 1)
            # Wallet range storage retains its existing signed exclusive endpoint.
            public = node.getdescriptorinfo(descriptor)['descriptor']
            assert_raises_rpc_error(-8, 'Wallet descriptor range end', self.import_range, wallet, public)
            expected = wallet.deriveaddresses(descriptor, [0, 1])
            wallet.unloadwallet()
            path = node.wallets_path / name / 'wallet.dat'
            original = records(path)
            prefix = ser_string(b'walletdescriptorpubkeycache')
            keys = sorted(k for k in original if k.startswith(prefix))
            first = keys[0]
            second = first[:-4] + struct.pack('<I', 1)
            assert second in original
            swapped = dict(original)
            swapped[first], swapped[second] = original[second], original[first]
            replace_records(path, original, swapped)
            if encrypted:
                node.loadwallet(name)
                wallet = node.get_wallet_rpc(name)
                # Persisted public data is usable until a mismatch is detected.
                wallet.deriveaddresses(descriptor, [0, 0])
                assert_raises_rpc_error(-1, 'cache does not match', wallet.walletpassphrase, 'pass', 60)
                assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
                # Resolve the affected descriptor (cache ordering is independent
                # of output type) and check that detection blocks public reuse.
                affected_id = first[len(prefix):len(prefix)+32]
                affected = deser_string(BytesIO(swapped[ser_string(b'walletdescriptor') + affected_id])).decode()
                affected = descsum_create(affected.split('#')[0])
                assert_raises_rpc_error(-4, 'cache does not match', wallet.deriveaddresses, affected, [0, 0])
                assert_raises_rpc_error(-1, 'cache does not match', wallet.walletpassphrase, 'pass', 60)
                wallet.unloadwallet()
            else:
                assert_raises_rpc_error(-4, 'Wallet corrupted', node.loadwallet, name)
            assert_equal(records(path), swapped)
            replace_records(path, swapped, original)

            self.log.info('Malformed records fail loading without rewriting the wallet')
            mutations = []
            for tag in [b'pqhdpolicy', b'cpqhdseed' if encrypted else b'pqhdseed']:
                key = next(k for k in original if k.startswith(ser_string(tag)))
                mutated = dict(original)
                mutated[key] = struct.pack('<i', 2) + original[key][4:]
                mutations.append(mutated)
            # Coverage and expression/index validation are independent of seed access.
            missing = dict(original)
            del missing[first]
            mutations.append(missing)
            wrong_expression = dict(original)
            del wrong_expression[first]
            wrong_expression[first[:-8] + struct.pack('<II', 99, 0)] = original[first]
            mutations.append(wrong_expression)
            extra = dict(original)
            extra[first[:-4] + struct.pack('<I', 2)] = original[first]
            mutations.append(extra)
            if encrypted:
                key = next(k for k in original if k.startswith(ser_string(b'cpqhdseed')))
                bad_length = dict(original)
                bad_length[key] = original[key][:12] + ser_string(bytes(32))
                mutations.append(bad_length)
            for mutated in mutations:
                replace_records(path, original, mutated)
                assert_raises_rpc_error(-4, 'Wallet corrupted', node.loadwallet, name)
                assert_equal(records(path), mutated)
                replace_records(path, mutated, original)

            # Numeric descriptor corruption is rejected without changing the layout.
            key = ser_string(b'walletdescriptor') + first[len(prefix):len(prefix)+32]
            assert key in original
            stream = BytesIO(original[key])
            deser_string(stream)
            offset = stream.tell() + 8  # creation_time precedes next/start/end
            invalid_range = dict(original)
            value = bytearray(original[key])
            value[offset + 4:offset + 8] = struct.pack('<i', -1)
            invalid_range[key] = bytes(value)
            replace_records(path, original, invalid_range)
            assert_raises_rpc_error(-4, '', node.loadwallet, name)
            assert_equal(records(path), invalid_range)
            replace_records(path, invalid_range, original)

            node.loadwallet(name)
            wallet = node.get_wallet_rpc(name)
            if encrypted:
                assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
            assert_equal(wallet.deriveaddresses(descriptor, [0, 1]), expected)
            assert wallet.getnewaddress() in expected
            if encrypted:
                wallet.walletpassphrase('pass', 60)
            address = wallet.getnewaddress('', 'legacy')
            assert node.verifymessage(address, wallet.signmessage(address, 'recovered'), 'recovered')

        self.log.info('Finite explicit public descriptors remain usable without a seed')
        source = node.get_wallet_rpc('plain')
        address = source.getnewaddress('', 'bech32')
        public_key = source.getaddressinfo(address)['pubkey']
        public_descriptor = node.getdescriptorinfo(f'wpkh({public_key})')['descriptor']
        node.createwallet('public', disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc('public')
        result = watch.importdescriptors([{'desc': public_descriptor, 'timestamp': 'now'}])[0]
        assert_equal(result['success'], True)
        assert_equal(watch.listpqhdseeds(), [])
        watch.unloadwallet()
        node.loadwallet('public')
        watch = node.get_wallet_rpc('public')
        assert_equal(watch.deriveaddresses(public_descriptor), [address])
        assert_equal(watch.getaddressinfo(address)['ismine'], True)
        seed_descriptor = next(d['desc'] for d in source.listdescriptors()['descriptors'] if d['active'] and d['desc'].startswith('wpkh('))
        before = watch.listdescriptors()
        rejected = watch.importdescriptors([{'desc': seed_descriptor, 'timestamp': 'now', 'range': [0, 1]}])[0]
        assert_equal(rejected['success'], False)
        assert_equal(rejected['error']['code'], -4)
        assert 'Cannot expand descriptor' in rejected['error']['message']
        assert_equal(watch.listdescriptors(), before)
        watch.unloadwallet()
        node.loadwallet('public')
        assert_equal(node.get_wallet_rpc('public').listdescriptors(), before)

    def import_range(self, wallet, descriptor):
        result = wallet.importdescriptors([{'desc': descriptor, 'timestamp': 'now', 'range': [2**31-2, 2**31-1]}])[0]
        assert_equal(result['success'], False)
        # Expose the per-request error to the standard RPC assertion helper.
        from test_framework.authproxy import JSONRPCException
        raise JSONRPCException(result['error'])


if __name__ == '__main__':
    PQHDIntegrityTest(__file__).main()
