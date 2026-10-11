#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Locked receipts consume cached receive/change indices durably."""
from contextlib import closing
import sqlite3

from test_framework.messages import ser_string
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class PQHDConsumptionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet('locked', passphrase='pass')
        wallet = node.get_wallet_rpc('locked')
        entries = [d for d in wallet.listdescriptors()['descriptors'] if d['active']]
        assert_equal(len(entries), 8)
        used = []
        for d in entries:
            addresses = wallet.deriveaddresses(d['desc'], [0, 1])
            self.generatetoaddress(node, 1, addresses[1])
            used += addresses
        node.syncwithvalidationinterfacequeue()
        self.check_consumed(wallet)
        wallet.unloadwallet()
        node.loadwallet('locked')
        wallet = node.get_wallet_rpc('locked')
        self.check_consumed(wallet)
        self.restart_node(0)
        node.loadwallet('locked')
        wallet = node.get_wallet_rpc('locked')
        self.check_consumed(wallet)
        for kind in ['legacy', 'p2sh-segwit', 'bech32', 'bech32pq']:
            assert_raises_rpc_error(-12, 'Keypool ran out', wallet.getnewaddress, '', kind)
            assert_raises_rpc_error(-12, 'Keypool ran out', wallet.getrawchangeaddress, kind)
        wallet.walletpassphrase('pass', 60)
        for kind in ['legacy', 'p2sh-segwit', 'bech32', 'bech32pq']:
            assert wallet.getnewaddress('', kind) not in used
            assert wallet.getrawchangeaddress(kind) not in used

        self.log.info('Failed startup replay preserves its checkpoint and releases the wallet for retry')
        for internal in [False, True]:
            name = f'replay_{internal}'
            node.createwallet(name, passphrase='pass')
            replay = node.get_wallet_rpc(name)
            desc = next(d for d in replay.listdescriptors()['descriptors']
                        if d['active'] and d['internal'] == internal and d['desc'].startswith('wpkh('))
            paid = replay.deriveaddresses(desc['desc'], [1, 1])[0]
            replay.unloadwallet()
            path = node.wallets_path / name / 'wallet.dat'
            checkpoint_key = ser_string(b'bestblock_nomerkle')
            with closing(sqlite3.connect(path)) as db:
                checkpoint = db.execute('SELECT value FROM main WHERE key=?', (checkpoint_key,)).fetchone()[0]
                prefix = ser_string(b'walletdescriptor')
                # Fail only an attempted consumption of child 1. This is an
                # external SQLite test fault, not a production runtime hook.
                db.execute(f"""CREATE TRIGGER fail_consumption BEFORE INSERT ON main
                    WHEN substr(NEW.key, 1, {len(prefix)}) = X'{prefix.hex()}'
                    AND substr(NEW.value, -12, 4) = X'02000000'
                    BEGIN SELECT RAISE(FAIL, 'injected consumption failure'); END""")
                db.commit()
            paid_block = self.generatetoaddress(node, 1, paid)[0]
            txid = node.getblock(paid_block)['tx'][0]
            if not internal:
                # Make the chain durable independently of the wallet fault, so
                # the subsequent abrupt kill tests wallet recovery, not loss of
                # a newly mined block from the node's unflushed chain state.
                self.restart_node(0)
            assert_raises_rpc_error(-4, 'writing descriptor failed', node.loadwallet, name)
            assert name not in node.listwallets()
            # A failed load must release its DB/notification ownership. Reading
            # and repairing only the injected trigger must work without restart.
            with closing(sqlite3.connect(path)) as db:
                assert_equal(db.execute('SELECT value FROM main WHERE key=?', (checkpoint_key,)).fetchone()[0], checkpoint)
                db.execute('DROP TRIGGER fail_consumption')
                db.commit()
            if not internal:
                node.kill_process()
                self.start_node(0)
                if 'locked' not in node.listwallets():
                    node.loadwallet('locked')
                wallet = node.get_wallet_rpc('locked')
                wallet.walletpassphrase('pass', 60)
            node.loadwallet(name)
            replay = node.get_wallet_rpc(name)
            recovered = next(d for d in replay.listdescriptors()['descriptors'] if d['desc'] == desc['desc'])
            assert_equal(recovered['next_index'], 2)
            assert_equal(replay.gettransaction(txid)['confirmations'], 1)
            replay.walletpassphrase('pass', 60)
            next_address = replay.getrawchangeaddress('bech32') if internal else replay.getnewaddress('', 'bech32')
            assert next_address != paid
            # Verify actual recovered spending, not just descriptor metadata.
            self.generatetoaddress(node, 101, wallet.getnewaddress())
            sent = replay.sendtoaddress(wallet.getnewaddress(), 1)
            self.generatetoaddress(node, 1, wallet.getnewaddress())
            assert_equal(replay.gettransaction(sent)['confirmations'], 1)
            replay.unloadwallet()

    def check_consumed(self, wallet):
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        for d in wallet.listdescriptors()['descriptors']:
            if d['active']:
                assert_equal(d['next_index'], 2)


if __name__ == '__main__':
    PQHDConsumptionTest(__file__).main()
