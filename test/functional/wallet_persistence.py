#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Restore and migrate disposable wallets without removing unrelated files."""
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import struct

from test_framework.messages import ser_string
from test_framework.script import CScript, OP_CHECKSIG, hash160
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def legacy_bdb(records):
    """Build a flushed BDB v9 file with one leaf, using synthetic wallet records."""
    size = 4096
    data = bytearray(4 * size)
    def u32(offset, value):
        struct.pack_into('<I', data, offset, value)
    for page in range(4):
        u32(page * size + 4, 1)
        u32(page * size + 8, page)
    for page, root in [(0, 1), (2, 3)]:
        base = page * size
        for offset, value in [(12, 0x53162), (16, 9), (20, size), (32, 3), (48, 0x20), (88, root)]:
            u32(base + offset, value)
        data[base + 25] = 9
    for page, pairs in [(1, [(b'main', struct.pack('>I', 2))]), (3, sorted(records.items()))]:
        base = page * size
        struct.pack_into('<H', data, base + 20, len(pairs) * 2)
        data[base + 24:base + 26] = b'\x01\x05'
        cursor = size
        for index, record in enumerate(part for pair in pairs for part in pair):
            cursor -= len(record) + 3
            assert cursor >= 26 + len(pairs) * 4
            struct.pack_into('<H', data, base + 26 + index * 2, cursor)
            struct.pack_into('<HB', data, base + cursor, len(record), 1)
            data[base + cursor + 3:base + cursor + 3 + len(record)] = record
    return data


class WalletPersistenceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-keypool=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet('source')
        source = node.get_wallet_rpc('source')
        address = source.getnewaddress()
        pub = bytes.fromhex(source.getaddressinfo(address)['pubkey'])
        backup = node.datadir_path / 'source.bak'
        source.backupwallet(backup)
        expected_backup = backup.read_bytes()
        invalid = node.datadir_path / 'invalid.bak'
        invalid.write_bytes(b'not a database')

        self.log.info('Restore into existing named and unnamed directories and preserve unrelated data')
        for name in ['restored', '']:
            directory = node.wallets_path / name
            directory.mkdir(exist_ok=True)
            unrelated = directory / 'keep.txt'
            unrelated.write_text('preserve this')
            # Invalid copied data must be removed, but the existing directory survives.
            assert_raises_rpc_error(-18, 'Data is not in recognized format', node.restorewallet, name, invalid)
            assert directory.is_dir()
            assert not (directory / 'wallet.dat').exists()
            assert_equal(unrelated.read_text(), 'preserve this')
            node.restorewallet(name, backup)
            restored = node.get_wallet_rpc(name)
            assert restored.getaddressinfo(address)['ismine']
            restored.unloadwallet()
            current = (directory / 'wallet.dat').read_bytes()
            assert_raises_rpc_error(-36, 'Database already exists', node.restorewallet, name, backup)
            assert_equal((directory / 'wallet.dat').read_bytes(), current)
            node.loadwallet(name)
            assert node.get_wallet_rpc(name).getaddressinfo(address)['ismine']
            node.unloadwallet(name)
        # Free only the test's unnamed restored database for default-wallet migration.
        (node.wallets_path / 'wallet.dat').unlink()
        standalone = node.wallets_path / 'existing-file'
        standalone.write_bytes(b'preexisting file')
        assert_raises_rpc_error(-36, 'Database already exists', node.restorewallet, 'existing-file', backup)
        assert_equal(standalone.read_bytes(), b'preexisting file')
        if os.name == 'posix':
            # A dangling symlink is still a pre-existing destination entry.
            symlink_dir = node.wallets_path / 'existing-symlink'
            symlink_dir.mkdir()
            symlink = symlink_dir / 'wallet.dat'
            symlink.symlink_to('missing-wallet-target')
            assert_raises_rpc_error(-36, 'Database already exists', node.restorewallet, 'existing-symlink', backup)
            assert symlink.is_symlink()
            assert_equal(os.readlink(symlink), 'missing-wallet-target')
        assert_raises_rpc_error(-18, 'Data is not in recognized format', node.restorewallet, 'new-invalid', invalid)
        assert not (node.wallets_path / 'new-invalid').exists()
        # A directory cannot be copied as a backup file. Preserve existing destinations,
        # and remove a newly-created empty destination after the copy throws.
        bad_backup = node.datadir_path / 'backup-directory'
        bad_backup.mkdir()
        for name in ['copy-existing', 'copy-new']:
            destination = node.wallets_path / name
            if name == 'copy-existing':
                destination.mkdir()
                (destination / 'keep.txt').write_bytes(b'keep')
            assert_raises_rpc_error(-4, 'Unexpected exception', node.restorewallet, name, bad_backup)
            if name == 'copy-existing':
                assert_equal((destination / 'keep.txt').read_bytes(), b'keep')
                assert not (destination / 'wallet.dat').exists()
            else:
                assert not destination.exists()
        assert_equal(backup.read_bytes(), expected_backup)

        self.log.info('Reject a readable SQLite wallet in a non-writable directory')
        if os.name == 'posix' and os.geteuid() != 0:
            node.createwallet('permissions', blank=True)
            node.unloadwallet('permissions')
            directory = node.wallets_path / 'permissions'
            mode = directory.stat().st_mode & 0o777
            directory.chmod(0o500)
            try:
                assert_raises_rpc_error(-4, 'directory is not writable', node.loadwallet, 'permissions')
            finally:
                directory.chmod(mode)
            node.loadwallet('permissions')
            node.unloadwallet('permissions')
        else:
            self.log.info('Skipping directory permission denial under Windows or a privileged account')

        self.log.info('Migrate synthetic watch-only and solvable records, including rollback collisions')
        watch = bytes(CScript([pub, OP_CHECKSIG]))
        records = {
            ser_string(b'watchs') + ser_string(watch): b'1',
            ser_string(b'cscript') + hash160(watch): ser_string(watch),
            ser_string(b'bestblock_nomerkle'): struct.pack('<iB', 70016, 0),
        }
        migrated = []
        for name in ['legacy-named', '']:
            prefix = name or 'default_wallet'
            directory = node.wallets_path / name
            directory.mkdir(exist_ok=True)
            database = directory / 'wallet.dat'
            original = bytes(legacy_bdb(records))
            database.write_bytes(original)
            sentinel = directory / 'migration-keep.txt'
            sentinel.write_bytes(b'original directory content')
            watch_directory = node.wallets_path / (prefix + '_watchonly')
            watch_directory.mkdir()
            watch_sentinel = watch_directory / 'keep.txt'
            watch_sentinel.write_bytes(b'watch directory content')
            # Force failure after the watch-only wallet has been created.
            blocker = prefix + '_solvables'
            node.createwallet(blocker, disable_private_keys=True, blank=True)
            node.unloadwallet(blocker)
            blocker_file = node.wallets_path / blocker / 'wallet.dat'
            blocker_content = blocker_file.read_bytes()
            node.setmocktime(1800000000)
            collision = node.wallets_path / f'{prefix}_1800000000.legacy.bak'
            collision.write_bytes(b'preexisting backup')
            assert_raises_rpc_error(-4, 'Database already exists', node.migratewallet, name)
            assert_equal(database.read_bytes(), original)
            assert_equal(sentinel.read_bytes(), b'original directory content')
            assert_equal(watch_sentinel.read_bytes(), b'watch directory content')
            assert not (watch_directory / 'wallet.dat').exists()
            assert_equal(blocker_file.read_bytes(), blocker_content)
            assert_equal(collision.read_bytes(), b'preexisting backup')
            backup_one = node.wallets_path / f'{prefix}_1800000000_1.legacy.bak'
            assert_equal(backup_one.read_bytes(), original)
            # Remove only the deliberately-created blocker; retry the restored legacy wallet.
            shutil.rmtree(node.wallets_path / blocker)
            result = node.migratewallet(name)
            assert_equal(result['wallet_name'], prefix + '_watchonly')
            assert_equal(result['solvables_name'], prefix + '_solvables')
            assert not database.exists()  # Empty main wallet removed after successful split.
            assert_equal(sentinel.read_bytes(), b'original directory content')
            assert_equal(watch_sentinel.read_bytes(), b'watch directory content')
            assert_equal(Path(result['backup_path']).read_bytes(), original)
            migrated += [prefix + '_watchonly', prefix + '_solvables']
            for wallet_name in migrated[-2:]:
                assert node.get_wallet_rpc(wallet_name).getwalletinfo()['descriptors']
                node.unloadwallet(wallet_name)
        node.setmocktime(0)

        self.log.info('An empty legacy wallet migrates without removing unrelated files')
        # Structurally valid BDB containers are not necessarily initialized
        # wallets. Reject missing-key/flag states without aborting the daemon,
        # modifying the source, or creating migration outputs.
        for name, empty_records in [
            ('legacy-recordless', {}),
            ('legacy-version-only', {ser_string(b'version'): struct.pack('<i', 170000)}),
            ('legacy-zero-flags', {ser_string(b'flags'): struct.pack('<Q', 0)}),
        ]:
            directory = node.wallets_path / name
            directory.mkdir()
            original = bytes(legacy_bdb(empty_records))
            (directory / 'wallet.dat').write_bytes(original)
            (directory / 'keep.txt').write_bytes(b'keep')
            entries = set(node.wallets_path.iterdir())
            for _ in range(2):
                assert_raises_rpc_error(-4, 'Wallet is empty and does not have the blank wallet flag set.', node.migratewallet, name)
                assert_equal((directory / 'wallet.dat').read_bytes(), original)
                assert_equal((directory / 'keep.txt').read_bytes(), b'keep')
                assert_equal(set(node.wallets_path.iterdir()), entries)
                assert name not in node.listwallets()
                node.getblockcount()  # A failed migration must leave RPC usable.

        empty_dir = node.wallets_path / 'legacy-empty'
        empty_dir.mkdir()
        (empty_dir / 'wallet.dat').write_bytes(legacy_bdb({ser_string(b'flags'): struct.pack('<Q', 1 << 33)}))
        (empty_dir / 'keep.txt').write_bytes(b'keep')
        node.migratewallet('legacy-empty')
        node.unloadwallet('legacy-empty')
        assert_equal((empty_dir / 'keep.txt').read_bytes(), b'keep')
        migrated += ['legacy-empty', 'restored']
        self.restart_node(0)
        for name in migrated:
            if name not in node.listwallets():
                node.loadwallet(name)
            assert node.get_wallet_rpc(name).getwalletinfo()['descriptors']
        assert node.get_wallet_rpc('restored').getaddressinfo(address)['ismine']

        self.test_reconciliation_recovery(node)

    def test_reconciliation_recovery(self, node):
        self.log.info('Failed load-time reconciliation preserves records and recovers on a fresh load')
        # Real SQLite triggers exercise the public loadwallet failure path without
        # introducing runtime fault-injection options into the daemon.
        record_types = [b'walletdescriptor', b'walletdescriptorpubkeycache', b'flags',
                        b'activeexternalspk', b'activeinternalspk']
        for index, record_type in enumerate(record_types):
            name = f'reconciliation-{index}'
            node.createwallet(name)
            wallet = node.get_wallet_rpc(name)
            original_address = wallet.getnewaddress('', 'bech32')
            node.unloadwallet(name)
            database = node.wallets_path / name / 'wallet.dat'
            with closing(sqlite3.connect(database)) as connection, connection:
                # Preserve the seed and policy; require load to recreate managers.
                for kind in [b'walletdescriptor', b'walletdescriptorpubkeycache',
                             b'activeexternalspk', b'activeinternalspk']:
                    prefix = ser_string(kind)
                    connection.execute('DELETE FROM main WHERE substr(key, 1, ?) = ?', (len(prefix), prefix))
                prefix = ser_string(record_type)
                connection.execute(f"""CREATE TRIGGER fail_reconciliation BEFORE INSERT ON main
                    WHEN substr(NEW.key, 1, {len(prefix)}) = X'{prefix.hex()}'
                    BEGIN SELECT RAISE(FAIL, 'injected reconciliation write failure'); END""")
                baseline = connection.execute('SELECT key, value FROM main ORDER BY key').fetchall()
            assert_raises_rpc_error(-4, 'Wallet corrupted', node.loadwallet, name)
            assert name not in node.listwallets()
            with closing(sqlite3.connect(database)) as connection, connection:
                assert_equal(connection.execute('SELECT key, value FROM main ORDER BY key').fetchall(), baseline)
                connection.execute('DROP TRIGGER fail_reconciliation')
            for _ in range(2):
                node.loadwallet(name)
                assert wallet.getaddressinfo(original_address)['ismine']
                for _ in range(3):
                    receive = wallet.getnewaddress('', 'bech32')
                    change = wallet.getrawchangeaddress('bech32')
                    assert wallet.getaddressinfo(receive)['ismine']
                    assert wallet.getaddressinfo(change)['ismine']
                node.unloadwallet(name)


if __name__ == '__main__':
    WalletPersistenceTest(__file__).main()
