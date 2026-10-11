#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check unlock rollback and cancellation before a descriptor rescan starts."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import sqlite3

from test_framework.messages import ser_string
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy


class WalletRPCFailuresTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.log.info('A failed keypool refill must leave an initially locked wallet locked')
        node.createwallet('unlock-failure')
        wallet = node.get_wallet_rpc('unlock-failure')
        address = wallet.getnewaddress('', 'legacy')
        wallet.encryptwallet('test password')
        # Consume the cached receive key while locked so the next unlock must
        # extend its range. Load-time writes of unchanged records remain allowed.
        wallet.getnewaddress()
        wallet.unloadwallet()
        path = node.wallets_path / 'unlock-failure' / 'wallet.dat'
        prefix = ser_string(b'walletdescriptor')
        with closing(sqlite3.connect(path)) as db:
            db.execute(f"""CREATE TRIGGER fail_descriptor BEFORE INSERT ON main
                WHEN substr(NEW.key,1,{len(prefix)})=X'{prefix.hex()}'
                AND NEW.value != (SELECT value FROM main WHERE key=NEW.key)
                BEGIN SELECT RAISE(FAIL, 'injected descriptor update failure'); END""")
            db.commit()
        node.loadwallet('unlock-failure')
        assert_raises_rpc_error(-1, 'writing descriptor failed', wallet.walletpassphrase, 'test password', 1)
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        assert_raises_rpc_error(-13, 'Please enter the wallet passphrase', wallet.signmessage, address, 'failed unlock')

        wallet.unloadwallet()
        with closing(sqlite3.connect(path)) as db:
            db.execute('DROP TRIGGER fail_descriptor')
            db.commit()
        node.loadwallet('unlock-failure')
        wallet.walletpassphrase('test password', 10)
        assert node.verifymessage(address, wallet.signmessage(address, 'recovered'), 'recovered')
        wallet.walletpassphrase('test password', 0)
        self.wait_until(lambda: wallet.getwalletinfo()['unlocked_until'] == 0)
        assert_raises_rpc_error(-13, 'Please enter the wallet passphrase', wallet.signmessage, address, 'after timeout')

        self.log.info('An accepted abort during descriptor preparation must not become scan success')
        node.createwallet('early-abort')
        wallet = node.get_wallet_rpc('early-abort')
        self.generate(node, 2)
        desc = next(d['desc'] for d in wallet.listdescriptors()['descriptors']
                    if d['active'] and not d['internal'] and d['desc'].startswith('wpkh('))
        # A separate HTTP connection is required for concurrent RPC calls.
        other = get_rpc_proxy(node.url + '/wallet/early-abort', 0, timeout=120)
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(assert_raises_rpc_error, -1, 'Rescan aborted by user.',
                                 other.importdescriptors, [{'desc': desc, 'range': [0, 299], 'timestamp': 0}])
            self.wait_until(lambda: wallet.abortrescan(), timeout=30)
            result.result(timeout=120)
        assert_equal(wallet.getwalletinfo()['scanning'], False)
        assert_equal(wallet.abortrescan(), False)
        # Cancellation does not undo already committed imports. Retrying is safe
        # and the previous cancellation must not poison this new reservation.
        result = wallet.importdescriptors([{'desc': desc, 'range': [0, 299], 'timestamp': 0}])
        assert_equal(result[0]['success'], True)
        assert_equal(wallet.getwalletinfo()['scanning'], False)
        wallet.unloadwallet()
        node.loadwallet('early-abort')
        assert_equal(wallet.rescanblockchain(0)['start_height'], 0)


if __name__ == '__main__':
    WalletRPCFailuresTest(__file__).main()
