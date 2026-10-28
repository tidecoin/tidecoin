#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Authenticate PQHD seeds before accepting unlock or passphrase changes."""
from contextlib import closing
from pathlib import Path
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


def seed_defaults(wallet):
    seeds = wallet.listpqhdseeds()
    return tuple(next((s['seed_id'] for s in seeds if s[flag]), None)
                 for flag in ['default_receive', 'default_change'])


class WalletPQHDEncryptionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.check_blank_encryption()
        self.check_passphrase_operation_errors()
        self.check_failed_post_encryption_setup()
        self.check_generated_seeds()
        self.check_generated_seed_write_failure()
        node.createwallet('authenticated')
        wallet = node.get_wallet_rpc('authenticated')
        address = wallet.getnewaddress('', 'legacy')
        wallet.importpqhdseed('11' * 32)
        old_seed_ids = {seed['seed_id'] for seed in wallet.listpqhdseeds()}
        result = wallet.encryptwallet('real password')
        assert 'a new PQHD seed was generated' in result
        assert 'backupwallet' in result
        new_seed_ids = {seed['seed_id'] for seed in wallet.listpqhdseeds()}
        assert old_seed_ids < new_seed_ids
        assert_equal(len(new_seed_ids - old_seed_ids), 1)
        new_seed_id = (new_seed_ids - old_seed_ids).pop()
        assert_equal(seed_defaults(wallet), (new_seed_id, new_seed_id))
        descriptor = next(d['desc'] for d in wallet.listdescriptors()['descriptors']
                          if d['active'] and not d['internal'] and d['desc'].startswith('wpkh('))
        assert new_seed_id in descriptor
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

    def check_blank_encryption(self):
        node = self.nodes[0]
        self.log.info('Blank-wallet encryption retains seeds and policy without provisioning descriptors')
        for seeded in [False, True]:
            name = f'blank-encryption-{seeded}'
            node.createwallet(name, blank=True)
            wallet = node.get_wallet_rpc(name)
            if seeded:
                wallet.createpqhdseed()
            seeds = wallet.listpqhdseeds()
            assert_equal(len(seeds), int(seeded))
            assert_equal(wallet.listdescriptors()['descriptors'], [])

            def policy_and_flags():
                snapshot = Path(self.options.tmpdir) / f'{name}.backup'
                wallet.backupwallet(str(snapshot))
                with closing(sqlite3.connect(snapshot)) as db:
                    return {key: value for key, value in db.execute('SELECT key, value FROM main')
                            if key in (ser_string(b'pqhdpolicy'), ser_string(b'flags'))}

            state = policy_and_flags()
            assert ser_string(b'flags') in state
            assert_equal(ser_string(b'pqhdpolicy') in state, seeded)
            result = wallet.encryptwallet('pass')
            assert 'No new PQHD seed or descriptors were generated' in result
            assert 'backupwallet' in result
            expected_seeds = [dict(seed, encrypted=True) for seed in seeds]
            assert_equal(wallet.listpqhdseeds(), expected_seeds)
            assert_equal(wallet.listdescriptors()['descriptors'], [])
            assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
            assert_equal(policy_and_flags(), state)

            # Unlocking in the same session does not provision a freshly seeded blank wallet.
            wallet.walletpassphrase('pass', 120)
            assert_equal(wallet.listpqhdseeds(), expected_seeds)
            assert_equal(wallet.listdescriptors()['descriptors'], [])
            assert_equal(policy_and_flags(), state)
            if seeded:
                seed_id = seeds[0]['seed_id']
                wallet.setpqhdseed(seed_id)
                assert_equal(wallet.listpqhdseeds(), expected_seeds)
                for address in (wallet.getnewaddress(address_type='legacy'), wallet.getrawchangeaddress('legacy')):
                    assert_equal(wallet.getaddressinfo(address)['pqhd_seedid'], seed_id)
            wallet.unloadwallet()

    def check_passphrase_operation_errors(self):
        node = self.nodes[0]
        self.log.info('Passphrase RPCs distinguish write failures from incorrect credentials')
        for deferred, initially_locked in [(True, True), (False, True), (False, False)]:
            name = f'passphrase-errors-{deferred}-{initially_locked}'
            node.createwallet(name, blank=deferred, passphrase='old')
            wallet = node.get_wallet_rpc(name)
            wallet.walletpassphrase('old', 3600)
            if deferred:
                wallet.createpqhdseed()
                assert_equal(wallet.listdescriptors()['descriptors'], [])
            wallet.unloadwallet()
            path = node.wallets_path / name / 'wallet.dat'
            saved_keys = encryption_records(path)
            prefix = ser_string(b'walletdescriptor' if deferred else b'mkey')
            with closing(sqlite3.connect(path)) as db, db:
                db.execute(f"""CREATE TRIGGER fail_passphrase_write BEFORE INSERT ON main
                    WHEN substr(NEW.key, 1, {len(prefix)}) = X'{prefix.hex()}'
                    BEGIN SELECT RAISE(FAIL, 'injected passphrase write failure'); END""")
            node.loadwallet(name)
            if not initially_locked:
                wallet.walletpassphrase('old', 3600)
            deadline = wallet.getwalletinfo()['unlocked_until']
            descriptors = wallet.listdescriptors()['descriptors']
            seeds = wallet.listpqhdseeds()
            assert_raises_rpc_error(-14, 'passphrase entered was incorrect', wallet.walletpassphrase, 'wrong', 3600)
            assert_raises_rpc_error(-14, 'passphrase entered was incorrect', wallet.walletpassphrasechange, 'wrong', 'new')
            message = 'writing descriptor failed' if deferred else 'Unable to save the new wallet passphrase'
            if deferred:
                assert_raises_rpc_error(-4, message, wallet.walletpassphrase, 'old', 3600)
            assert_raises_rpc_error(-4, message, wallet.walletpassphrasechange, 'old', 'new')
            assert_equal(wallet.getwalletinfo()['unlocked_until'], deadline)
            assert_equal(wallet.listdescriptors()['descriptors'], descriptors)
            assert_equal(wallet.listpqhdseeds(), seeds)
            wallet.unloadwallet()
            assert_equal(encryption_records(path), saved_keys)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('DROP TRIGGER fail_passphrase_write')
            node.loadwallet(name)
            # A restart still uses the old saved key. Retry provisioning and
            # changing the passphrase after the write failure is resolved.
            assert_raises_rpc_error(-14, 'passphrase entered was incorrect', wallet.walletpassphrase, 'new', 3600)
            wallet.walletpassphrase('old', 3600)
            descriptors = wallet.listdescriptors()['descriptors']
            assert descriptors
            wallet.walletlock()
            wallet.walletpassphrase('old', 3600)
            assert_equal(wallet.listdescriptors()['descriptors'], descriptors)
            wallet.walletpassphrasechange('old', 'new')
            wallet.unloadwallet()
            node.loadwallet(name)
            assert_raises_rpc_error(-14, 'passphrase entered was incorrect', wallet.walletpassphrase, 'old', 3600)
            wallet.walletpassphrase('new', 3600)
            address = wallet.getnewaddress(address_type='legacy')
            assert node.verifymessage(address, wallet.signmessage(address, 'passphrase retry'), 'passphrase retry')
            wallet.unloadwallet()

    def check_failed_post_encryption_setup(self):
        node = self.nodes[0]
        self.log.info('Failed post-encryption setup keeps the saved encrypted wallet usable')
        for index, record_type in enumerate([b'pqhdpolicy', b'activeinternalspk']):
            name = f'failed-encryption-setup-{index}'
            node.createwallet(name)
            wallet = node.get_wallet_rpc(name)
            address = wallet.getnewaddress('', 'legacy')
            seeds = wallet.listpqhdseeds()
            old_seed = seeds[0]['seed_id']
            wallet.unloadwallet()
            path = node.wallets_path / name / 'wallet.dat'
            # These records are written by the new setup, after encryption of
            # the existing keys/seeds has committed. No daemon fault hook needed.
            prefix = ser_string(record_type)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute(f"""CREATE TRIGGER fail_encryption_setup BEFORE INSERT ON main
                    WHEN substr(NEW.key, 1, {len(prefix)}) = X'{prefix.hex()}'
                    BEGIN SELECT RAISE(FAIL, 'injected post-encryption setup failure'); END""")
            node.loadwallet(name)
            descriptors = wallet.listdescriptors()['descriptors']
            assert_raises_rpc_error(-16, 'Wallet was encrypted and locked, but replacement-seed setup failed. Existing active descriptors remain in use; no replacement seed was installed. Reason:',
                                    wallet.encryptwallet, 'pass')
            assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
            assert_equal(wallet.listpqhdseeds(), [dict(seed, encrypted=True) for seed in seeds])
            assert_equal(wallet.listdescriptors()['descriptors'], descriptors)
            assert_raises_rpc_error(-15, 'running with an encrypted wallet', wallet.encryptwallet, 'pass')
            wallet.walletpassphrase('pass', 60)
            assert node.verifymessage(address, wallet.signmessage(address, 'after setup failure'), 'after setup failure')
            fresh = wallet.getnewaddress(address_type='bech32', scheme='falcon512')
            assert_equal(wallet.getaddressinfo(fresh)['pqhd_seedid'], old_seed)
            wallet.unloadwallet()
            with closing(sqlite3.connect(path)) as db, db:
                records = dict(db.execute('SELECT key, value FROM main'))
                assert not any(key.startswith(ser_string(b'pqhdseed')) for key in records)
                assert_equal(sum(key.startswith(ser_string(b'cpqhdseed')) for key in records), 1)
                db.execute('DROP TRIGGER fail_encryption_setup')
            node.loadwallet(name)
            assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
            wallet.walletpassphrase('pass', 60)
            assert node.verifymessage(address, wallet.signmessage(address, 'after restart'), 'after restart')
            for _ in range(3):
                fresh = wallet.getnewaddress(address_type='bech32', scheme='falcon512')
                assert_equal(wallet.getaddressinfo(fresh)['pqhd_seedid'], old_seed)
            # Persist a new policy explicitly after the failed automatic setup.
            before_generation = wallet.listdescriptors()['descriptors']
            replacement = wallet.createpqhdseed()['seed_id']
            assert_equal(wallet.listdescriptors()['descriptors'], before_generation)
            assert_equal(seed_defaults(wallet)[0], old_seed)
            wallet.setpqhdseed(replacement)
            wallet.unloadwallet()
            node.loadwallet(name)
            wallet.walletpassphrase('pass', 60)
            fresh = wallet.getnewaddress(address_type='bech32', scheme='falcon512')
            assert_equal(wallet.getaddressinfo(fresh)['pqhd_seedid'], replacement)
            assert node.verifymessage(address, wallet.signmessage(address, 'after policy retry'), 'after policy retry')
            wallet.unloadwallet()

    def check_generated_seeds(self):
        node = self.nodes[0]
        self.log.info('Generated seeds persist without changing existing defaults until selected')
        for encrypted in [False, True]:
            for blank in [False, True]:
                name = f'generated-{encrypted}-{blank}'
                node.createwallet(name, blank=blank, passphrase='pass' if encrypted else None)
                wallet = node.get_wallet_rpc(name)
                if encrypted:
                    seeds = wallet.listpqhdseeds()
                    assert_equal(len(seeds), int(not blank))
                    assert_raises_rpc_error(-13, 'must be unlocked', wallet.createpqhdseed)
                    assert_equal(wallet.listpqhdseeds(), seeds)
                    wallet.walletpassphrase('pass', 120)
                    assert_equal(wallet.listpqhdseeds(), seeds)
                    wallet.unloadwallet()
                    node.loadwallet(name)
                    wallet.walletpassphrase('pass', 120)
                    assert_equal(wallet.listpqhdseeds(), seeds)
                old_address = None if blank else wallet.getnewaddress(address_type='legacy')
                descriptors = wallet.listdescriptors()['descriptors']
                defaults = seed_defaults(wallet)
                first = wallet.createpqhdseed()
                assert_equal(set(first), {'seed_id'})
                assert_equal(len(bytes.fromhex(first['seed_id'])), 32)
                second = wallet.createpqhdseed()['seed_id']
                assert second != first['seed_id']
                assert_equal(wallet.listdescriptors()['descriptors'], descriptors)
                if not blank:
                    assert_equal(seed_defaults(wallet), defaults)
                else:
                    assert_equal(descriptors, [])
                    assert_equal(seed_defaults(wallet)[0], first['seed_id'])
                wallet.setpqhdseed(second)
                address = wallet.getnewaddress(address_type='legacy')
                assert_equal(wallet.getaddressinfo(address)['pqhd_seedid'], second)
                backup = Path(self.options.tmpdir) / f'{name}.backup'
                wallet.backupwallet(str(backup))
                wallet.unloadwallet()
                if encrypted:
                    with closing(sqlite3.connect(node.wallets_path / name / 'wallet.dat')) as db:
                        records = dict(db.execute('SELECT key, value FROM main'))
                    assert not any(key.startswith(ser_string(b'pqhdseed')) for key in records)
                node.loadwallet(name)
                restored_name = name + '-restored'
                node.restorewallet(restored_name, str(backup))
                for candidate in [wallet, node.get_wallet_rpc(restored_name)]:
                    if encrypted:
                        assert_equal(candidate.getwalletinfo()['unlocked_until'], 0)
                        candidate.walletpassphrase('pass', 120)
                    assert_equal(seed_defaults(candidate)[0], second)
                    assert {first['seed_id'], second}.issubset({seed['seed_id'] for seed in candidate.listpqhdseeds()})
                    for owned in [address] + ([old_address] if old_address else []):
                        assert node.verifymessage(owned, candidate.signmessage(owned, 'saved seed'), 'saved seed')
                    candidate.unloadwallet()
        node.createwallet('generate-watchonly', disable_private_keys=True)
        watch = node.get_wallet_rpc('generate-watchonly')
        assert_raises_rpc_error(-4, 'Private PQHD seeds are disabled', watch.createpqhdseed)
        assert_equal(watch.listpqhdseeds(), [])
        watch.unloadwallet()

    def check_generated_seed_write_failure(self):
        node = self.nodes[0]
        self.log.info('Failed seed writes publish nothing; failed selection keeps the saved seed for retry')
        name = 'generated-write-failure'
        node.createwallet(name, passphrase='pass')
        wallet = node.get_wallet_rpc(name)
        path = node.wallets_path / name / 'wallet.dat'
        seeds = wallet.listpqhdseeds()
        defaults = seed_defaults(wallet)
        wallet.unloadwallet()

        def install_failure(record):
            prefix = ser_string(record)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute(f"""CREATE TRIGGER fail_generated_seed BEFORE INSERT ON main
                    WHEN substr(NEW.key, 1, {len(prefix)}) = X'{prefix.hex()}'
                    BEGIN SELECT RAISE(FAIL, 'injected seed write failure'); END""")

        def remove_failure():
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('DROP TRIGGER fail_generated_seed')

        install_failure(b'cpqhdseed')
        node.loadwallet(name)
        wallet.walletpassphrase('pass', 120)
        assert_raises_rpc_error(-4, 'Failed to write encrypted PQHD seed', wallet.createpqhdseed)
        assert_equal(wallet.listpqhdseeds(), seeds)
        wallet.unloadwallet()
        remove_failure()
        node.loadwallet(name)
        wallet.walletpassphrase('pass', 120)
        assert_equal(wallet.listpqhdseeds(), seeds)
        replacement = wallet.createpqhdseed()['seed_id']
        seeds = wallet.listpqhdseeds()
        wallet.unloadwallet()
        install_failure(b'pqhdpolicy')
        node.loadwallet(name)
        wallet.walletpassphrase('pass', 120)
        assert_raises_rpc_error(-4, 'Failed to write PQHD policy', wallet.setpqhdseed, replacement)
        assert_equal(wallet.listpqhdseeds(), seeds)
        assert_equal(seed_defaults(wallet), defaults)
        wallet.unloadwallet()
        remove_failure()
        node.loadwallet(name)
        wallet.walletpassphrase('pass', 120)
        wallet.setpqhdseed(replacement)
        fresh = wallet.getnewaddress(address_type='legacy')
        assert_equal(wallet.getaddressinfo(fresh)['pqhd_seedid'], replacement)
        assert node.verifymessage(fresh, wallet.signmessage(fresh, 'retry selection'), 'retry selection')
        wallet.unloadwallet()



if __name__ == '__main__':
    WalletPQHDEncryptionTest(__file__).main()
