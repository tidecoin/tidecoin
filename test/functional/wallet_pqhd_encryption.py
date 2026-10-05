#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Authenticate PQHD seeds before accepting unlock or passphrase changes."""
from contextlib import closing
import sqlite3
import struct

from test_framework.messages import ser_string
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


# Deterministic encrypted master-key candidates with valid CBC padding. Each is
# AES-256-CBC(0x42 repeated n times), using the wallet's SHA512 password KDF,
# salt 0x31 repeated 8 times, and 25000 rounds. These are synthetic test data;
# no additional crypto dependency or probabilistic password search is needed.
CANDIDATES = {
    'padding-only': '99852dd7647110f9e365e4ec534ed75511e713fa420157f30eef863eb2435460c29262ad906d5fa2f178e4cc1399df53',  # n=47
    'wrong-master': '929ab5e33bd7a1008ba0ad879f7586fce843bbcf07e6030f08bc1d5a76e97bec7554e5fea93613f2d025a5ecbc308e20',  # n=32
}


def encryption_records(path):
    with closing(sqlite3.connect(path)) as db:
        prefixes = [ser_string(name) for name in [b'mkey', b'cpqhdseed', b'walletdescriptorckey']]
        return {k: v for k, v in db.execute('SELECT key, value FROM main') if any(k.startswith(p) for p in prefixes)}


class WalletPQHDEncryptionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet('authenticated')
        wallet = node.get_wallet_rpc('authenticated')
        address = wallet.getnewaddress('', 'legacy')
        wallet.importpqhdseed('11' * 32)
        wallet.encryptwallet('real password')
        descriptor = next(d['desc'] for d in wallet.listdescriptors()['descriptors']
                          if d['active'] and not d['internal'] and d['desc'].startswith('wpkh('))
        wallet.walletpassphrase('real password', 120)
        expected = wallet.deriveaddresses(descriptor, [10, 10])
        assert node.verifymessage(address, wallet.signmessage(address, 'before'), 'before')
        assert len(wallet.listpqhdseeds()) >= 3
        wallet.unloadwallet()
        path = node.wallets_path / 'authenticated' / 'wallet.dat'
        with closing(sqlite3.connect(path)) as db:
            for index, ciphertext in enumerate(CANDIDATES.values(), start=100):
                record = ser_string(bytes.fromhex(ciphertext)) + ser_string(b'1' * 8) + struct.pack('<II', 0, 25000) + ser_string(b'')
                db.execute('INSERT INTO main(key,value) VALUES(?,?)', (ser_string(b'mkey') + struct.pack('<I', index), record))
            db.commit()
        expected_records = encryption_records(path)
        node.loadwallet('authenticated')
        wallet = node.get_wallet_rpc('authenticated')

        self.log.info('Reject valid-padding candidates without changing lock state or encryption records')
        for locked in [True, False]:
            if not locked:
                wallet.walletpassphrase('real password', 120)
            unlocked_until = wallet.getwalletinfo()['unlocked_until']
            for password in CANDIDATES:
                assert_raises_rpc_error(-14, 'incorrect', wallet.walletpassphrase, password, 120)
                assert_equal(wallet.getwalletinfo()['unlocked_until'], unlocked_until)
                assert_raises_rpc_error(-14, 'incorrect', wallet.walletpassphrasechange, password, 'replacement')
                assert_equal(wallet.getwalletinfo()['unlocked_until'], unlocked_until)
            if not locked:
                assert_equal(wallet.deriveaddresses(descriptor, [10, 10]), expected)
                assert node.verifymessage(address, wallet.signmessage(address, 'after failure'), 'after failure')
            wallet.unloadwallet()
            assert_equal(encryption_records(path), expected_records)
            node.loadwallet('authenticated')
            wallet = node.get_wallet_rpc('authenticated')
            wallet.walletpassphrase('real password', 120)
            assert_equal(wallet.deriveaddresses(descriptor, [10, 10]), expected)
            wallet.walletlock()

        self.log.info('A legitimate password change preserves fresh derivation and signing after reopen')
        wallet.walletpassphrasechange('real password', 'replacement')
        wallet.unloadwallet()
        node.loadwallet('authenticated')
        wallet = node.get_wallet_rpc('authenticated')
        assert_raises_rpc_error(-14, 'incorrect', wallet.walletpassphrase, 'real password', 120)
        wallet.walletpassphrase('replacement', 120)
        assert_equal(wallet.deriveaddresses(descriptor, [10, 10]), expected)
        assert node.verifymessage(address, wallet.signmessage(address, 'after reopen'), 'after reopen')

        self.log.info('Corruption of one additional seed prevents unlock and password change')
        wallet.unloadwallet()
        with closing(sqlite3.connect(path)) as db:
            key, value = next((k, v) for k, v in db.execute('SELECT key, value FROM main') if k.startswith(ser_string(b'cpqhdseed')))
            damaged = value[:-1] + bytes([value[-1] ^ 1])
            db.execute('UPDATE main SET value=? WHERE key=?', (damaged, key))
            db.commit()
        damaged_records = encryption_records(path)
        node.loadwallet('authenticated')
        wallet = node.get_wallet_rpc('authenticated')
        assert_raises_rpc_error(-14, 'incorrect', wallet.walletpassphrase, 'replacement', 120)
        assert_raises_rpc_error(-14, 'incorrect', wallet.walletpassphrasechange, 'replacement', 'third password')
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        wallet.unloadwallet()
        assert_equal(encryption_records(path), damaged_records)
        # Restore only the intentionally damaged synthetic record, then verify
        # that the failed operations did not damage the valid master key.
        with closing(sqlite3.connect(path)) as db:
            db.execute('UPDATE main SET value=? WHERE key=?', (value, key))
            db.commit()
        node.loadwallet('authenticated')
        wallet = node.get_wallet_rpc('authenticated')
        wallet.walletpassphrase('replacement', 120)
        assert_equal(wallet.deriveaddresses(descriptor, [10, 10]), expected)
        assert node.verifymessage(address, wallet.signmessage(address, 'recovered'), 'recovered')


if __name__ == '__main__':
    WalletPQHDEncryptionTest(__file__).main()
