#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Legacy migration without locators, failed-migration settings, and rescan recovery.

The missing-locator scenario adapts Bitcoin Core PR 34198 to Tidecoin's
historical Falcon key representation and synthetic BDB fixtures.
"""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import struct

from wallet_persistence import legacy_bdb
from test_framework.address import base58_to_byte, key_to_p2pkh, key_to_p2sh_p2wpkh
from test_framework.descriptors import descsum_create
from test_framework.messages import hash256, ser_string
from test_framework.script import CScript, OP_CHECKSIG
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class WalletMigrationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [['-keypool=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def settings(self):
        return (self.nodes[0].datadir_path / 'regtest' / 'settings.json').read_bytes()

    def fixture(self, name, records):
        path = self.nodes[0].wallets_path / name / 'wallet.dat'
        path.parent.mkdir(exist_ok=True)
        original = bytes(legacy_bdb(records))
        path.write_bytes(original)
        return path, original

    @staticmethod
    def key_material():
        secret, pub = generate_keypair(wif=True, scheme='falcon-512')
        encoded, _ = base58_to_byte(secret)
        assert_equal(encoded[0], 7)
        raw = encoded[1:]
        assert_equal(len(raw), 1281)
        records = {ser_string(b'key') + ser_string(pub): ser_string(raw) + hash256(pub + raw)}
        return secret, pub, records

    def unload_migrated(self, result):
        for field in ['wallet_name', 'watchonly_name', 'solvables_name']:
            name = result.get(field)
            if name and name in self.nodes[0].listwallets():
                self.nodes[0].unloadwallet(name, load_on_startup=False)

    def test_missing_locators(self):
        node = self.nodes[0]
        secret, pub, records = self.key_material()
        address = key_to_p2pkh(pub)
        self.generatetoaddress(node, 2, address)
        empty = struct.pack('<iB', 70016, 0)
        genesis = struct.pack('<iB', 70016, 1) + bytes.fromhex(node.getblockhash(0))[::-1]
        cases = [
            ('missing', {}),
            ('', {}),
            ('empty-old', {b'bestblock': empty}),
            ('empty-modern', {b'bestblock_nomerkle': empty}),
            ('valid-old', {b'bestblock': genesis}),
            ('valid-modern', {b'bestblock_nomerkle': genesis}),
        ]
        for name, locators in cases:
            self.log.info('Migrate and rescan legacy key fixture %r', name)
            data = dict(records)
            data.update({ser_string(k): v for k, v in locators.items()})
            _, original = self.fixture(name, data)
            with node.assert_debug_log(['Rescanning']):
                result = node.migratewallet(name)
            assert_equal(Path(result['backup_path']).read_bytes(), original)
            wallet = node.get_wallet_rpc(name)
            assert wallet.getaddressinfo(address)['ismine']
            assert_equal(wallet.getwalletinfo()['txcount'], 2)
            assert wallet.getbalances()['mine']['immature'] > 0
            node.unloadwallet(name)
            node.loadwallet(name)
            assert_equal(wallet.getwalletinfo()['txcount'], 2)
            node.unloadwallet(name)
            if name == '':
                (node.wallets_path / 'wallet.dat').unlink()

        self.log.info('Migrate encrypted key records without a locator')
        node.createwallet('encrypted-source', blank=True)
        wallet = node.get_wallet_rpc('encrypted-source')
        assert wallet.importdescriptors([{'desc': descsum_create(f'pkh({secret})'), 'timestamp': 0}])[0]['success']
        wallet.encryptwallet('migration-test')
        node.unloadwallet('encrypted-source')
        # Reuse actual encrypted key/master records, without external AES code.
        encrypted = {}
        with closing(sqlite3.connect(node.wallets_path / 'encrypted-source' / 'wallet.dat')) as db:
            for key, value in db.execute('SELECT key, value FROM main'):
                if key.startswith(ser_string(b'mkey')):
                    encrypted[key] = value
                elif key.startswith(ser_string(b'walletdescriptorckey')):
                    encrypted[ser_string(b'ckey') + ser_string(pub)] = value
        assert_equal(len(encrypted), 2)
        path, original = self.fixture('encrypted-legacy', encrypted)
        assert_raises_rpc_error(-4, 'decryption failed', node.migratewallet, 'encrypted-legacy', 'wrong')
        assert_equal(path.read_bytes(), original)
        result = node.migratewallet('encrypted-legacy', 'migration-test')
        wallet = node.get_wallet_rpc('encrypted-legacy')
        assert_equal(wallet.getwalletinfo()['txcount'], 2)
        wallet.walletpassphrase('migration-test', 10)
        assert wallet.getaddressinfo(address)['ismine']
        wallet.walletlock()
        node.unloadwallet('encrypted-legacy')
        self.restart_node(0)
        node.loadwallet('encrypted-legacy')
        assert_equal(node.get_wallet_rpc('encrypted-legacy').getwalletinfo()['txcount'], 2)
        self.unload_migrated(result)

    def test_settings_cleanup(self):
        node = self.nodes[0]
        _, pub, _ = self.key_material()
        script = bytes(CScript([pub, OP_CHECKSIG]))
        records = {ser_string(b'watchs') + ser_string(script): b'1'}
        # Both the watch-only and solvable wallet are produced by this record.
        for stage in ['early', 'late', 'late-preexisting']:
            name = 'cleanup-' + stage
            watch_name, solvable_name = name + '_watchonly', name + '_solvables'
            restored = None
            if stage == 'early':
                node.createwallet(solvable_name, blank=True, load_on_startup=True)
                node.unloadwallet(solvable_name)
            if stage == 'late-preexisting':
                node.createwallet(watch_name, blank=True, load_on_startup=True)
                node.unloadwallet(watch_name)
                restored = node.wallets_path / watch_name / 'wallet.dat'
                saved = restored.read_bytes()
                restored.unlink()
            data = dict(records)
            data[ser_string(b'bestblock_nomerkle')] = b'\x01'  # Fail after auxiliary creation.
            path, original = self.fixture(name, data)
            before = self.settings()
            for _ in range(2):
                error = 'Database already exists' if stage == 'early' else "Unable to read wallet's best block locator record"
                assert_raises_rpc_error(-4, error, node.migratewallet, name)
                assert_equal(path.read_bytes(), original)
                assert_equal(self.settings(), before)
                assert name not in node.listwallets()
            if restored:
                restored.write_bytes(saved)
            self.restart_node(0)  # No newly introduced missing-wallet warnings.
            for wallet_name in [watch_name, solvable_name]:
                if wallet_name in node.listwallets():
                    node.unloadwallet(wallet_name, load_on_startup=False)

        self.log.info('Missing-locator split wallets recover transactions and load on restart')
        watched_address = key_to_p2sh_p2wpkh(pub)
        self.generatetodescriptor(node, 1, descsum_create(f'pk({pub.hex()})'))
        self.generatetoaddress(node, 1, watched_address)
        _, original = self.fixture('split', records)
        result = node.migratewallet('split')
        assert_equal(Path(result['backup_path']).read_bytes(), original)
        primary = node.get_wallet_rpc(result['wallet_name'])
        assert_equal(primary.getwalletinfo()['txcount'], 1)
        assert primary.getbalances()['mine']['immature'] > 0
        solvables = node.get_wallet_rpc(result['solvables_name'])
        assert_equal(solvables.getwalletinfo()['txcount'], 1)
        assert solvables.getaddressinfo(watched_address)['ismine']
        startup = json.loads(self.settings())['wallet']
        assert result['wallet_name'] in startup
        assert result['solvables_name'] in startup
        self.restart_node(0)
        assert_equal(node.get_wallet_rpc(result['wallet_name']).getwalletinfo()['txcount'], 1)
        assert result['solvables_name'] in node.listwallets()
        self.unload_migrated(result)

        for suffix, bad in [('truncated', b'\x01'), ('partial', struct.pack('<iB', 70016, 2) + bytes(32))]:
            data = dict(records)
            data[ser_string(b'bestblock_nomerkle')] = bad
            path, original = self.fixture('bad-' + suffix, data)
            before = self.settings()
            assert_raises_rpc_error(-4, "Unable to read wallet's best block locator record", node.migratewallet, 'bad-' + suffix)
            assert_equal(path.read_bytes(), original)
            assert_equal(self.settings(), before)

    def test_settings_write_failure(self):
        node = self.nodes[0]
        _, pub, _ = self.key_material()
        records = {ser_string(b'watchs') + ser_string(bytes(CScript([pub, OP_CHECKSIG]))): b'1'}
        path, original = self.fixture('settings-failure', records)
        # A directory at the temporary-file path forces a real settings write error.
        blocker = node.datadir_path / 'regtest' / 'settings.json.tmp'
        blocker.mkdir()
        try:
            bad_records = dict(records)
            bad_records[ser_string(b'bestblock_nomerkle')] = b'\x01'
            bad_path, bad_original = self.fixture('settings-rollback', bad_records)
            before = self.settings()
            assert_raises_rpc_error(-4, "Unable to read wallet's best block locator record", node.migratewallet, 'settings-rollback')
            assert_equal(bad_path.read_bytes(), bad_original)
            assert_equal(self.settings(), before)
            result = node.migratewallet('settings-failure')
            assert any('startup setting could not be updated' in w for w in result['warnings'])
            assert_equal(Path(result['backup_path']).read_bytes(), original)
            assert result['wallet_name'] in node.listwallets()
        finally:
            blocker.rmdir()
        self.unload_migrated(result)
        self.restart_node(0, extra_args=['-keypool=1', '-nosettings'])
        self.fixture('nosettings', records)
        result = node.migratewallet('nosettings')
        assert any('startup setting could not be updated' in w for w in result['warnings'])
        assert result['wallet_name'] in node.listwallets()
        self.unload_migrated(result)
        self.restart_node(0)

    def test_pruned_history(self):
        node = self.nodes[0]
        self.restart_node(0, extra_args=['-keypool=1', '-prune=1', '-fastprune'])
        _, pub, records = self.key_material()
        address = key_to_p2pkh(pub)
        self.generatetoaddress(node, 600, address)
        assert node.pruneblockchain(300) > 0
        path, original = self.fixture('pruned-legacy', records)
        before = self.settings()
        assert_raises_rpc_error(-4, 'Prune: last wallet synchronisation', node.migratewallet, 'pruned-legacy')
        assert_equal(path.read_bytes(), original)
        assert_equal(self.settings(), before)
        assert 'pruned-legacy' not in node.listwallets()
        self.restart_node(0, extra_args=['-keypool=1', '-prune=1', '-fastprune'])
        assert_equal(path.read_bytes(), original)

        self.log.info('Roll back an already loaded auxiliary wallet when the next rescan fails')
        watch_name = 'late-load_watchonly'
        node.createwallet(watch_name, blank=True, load_on_startup=True)
        node.unloadwallet(watch_name)
        placeholder = node.wallets_path / watch_name / 'wallet.dat'
        saved = placeholder.read_bytes()
        placeholder.unlink()
        script = bytes(CScript([pub, OP_CHECKSIG]))
        # The watched script is new enough to skip missing historical blocks,
        # but its unwatched solvable wrappers have unknown birthdays.
        timestamp = node.getblockheader(node.getbestblockhash())['time'] + 7201
        split_records = {
            ser_string(b'watchs') + ser_string(script): b'1',
            ser_string(b'watchmeta') + ser_string(script): struct.pack('<iq', 1, timestamp),
        }
        path, original = self.fixture('late-load', split_records)
        before = self.settings()
        with node.assert_debug_log(['[late-load_watchonly] Releasing wallet late-load_watchonly']):
            assert_raises_rpc_error(-4, 'Prune: last wallet synchronisation', node.migratewallet, 'late-load')
        assert_equal(path.read_bytes(), original)
        assert_equal(self.settings(), before)
        assert watch_name not in node.listwallets()
        assert not placeholder.exists()
        assert not (node.wallets_path / 'late-load_solvables' / 'wallet.dat').exists()
        placeholder.write_bytes(saved)
        self.restart_node(0, extra_args=['-keypool=1', '-prune=1', '-fastprune'])
        assert watch_name in node.listwallets()
        node.unloadwallet(watch_name, load_on_startup=False)

    def run_test(self):
        self.test_missing_locators()
        self.test_settings_cleanup()
        self.test_settings_write_failure()
        self.test_pruned_history()


if __name__ == '__main__':
    WalletMigrationTest(__file__).main()
