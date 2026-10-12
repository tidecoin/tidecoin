#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Existing descriptor RPCs resolve PQHD without allocating or monitoring addresses."""
from contextlib import closing
import base64
import hmac
from http.client import HTTPConnection, HTTPException
import json
from urllib.parse import urlsplit
import sqlite3
import time
from itertools import count
from threading import Thread

from test_framework.authproxy import JSONRPCException
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy, rpc_url


class WalletDescriptorExpansionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        auth = hmac.new(b'expansion-test-salt', b'restricted-password', 'sha256').hexdigest()
        self.extra_args = [['-keypool=2', '-blockfilterindex=1', f'-rpcauth=expandlimited:expansion-test-salt${auth}', '-rpcwhitelist=expandlimited:getwalletinfo', '-rpcwhitelistdefault=0']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_cli()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet('expand', passphrase='test expansion passphrase')
        wallet = node.get_wallet_rpc('expand')
        self.log.info('Scan and funding help describe cached public operations while locked after reload')
        for method in ['scantxoutset', 'scanblocks', 'fundrawtransaction', 'walletcreatefundedpsbt', 'send', 'sendall']:
            help_text = wallet.help(method)
            assert 'cached public keys work while locked, including after reload' in help_text, method
            assert 'Fresh PQHD derivation requires an unlocked wallet with the seed' in help_text, method
            assert 'unlock once after reload' not in help_text, method
            assert 'require verified cached keys' not in help_text, method
        node.createwallet('other', blank=True, disable_private_keys=True)
        other = node.get_wallet_rpc('other')
        entries = wallet.listdescriptors()['descriptors']
        desc = next(e['desc'] for e in entries if e.get('active') and not e.get('internal') and e['desc'].startswith('wpkh(') and '/7h/' in e['desc'])
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        snapshots = count()

        def records():
            backup = node.datadir_path / f'expand-snapshot-{next(snapshots)}.dat'
            wallet.backupwallet(backup)
            with closing(sqlite3.connect(f'file:{backup}?mode=ro', uri=True)) as connection:
                return connection.execute('SELECT key, value FROM main ORDER BY key').fetchall()

        def state():
            info = wallet.getwalletinfo()
            return wallet.listdescriptors(), wallet.listpqhdseeds(), {k: info[k] for k in ['keypoolsize', 'keypoolsize_hd_internal', 'txcount', 'birthtime']}, records()

        def scan_calls(rpc, bounds):
            objects = [{'desc': desc, 'range': bounds}]
            return [
                (rpc.scantxoutset, ['start', objects]),
                (rpc.scanblocks, ['start', objects]),
                (rpc.getdescriptoractivity, [[], objects, False]),
            ]

        self.log.info('Use existing RPC permissions and remove the superseded command')
        assert_raises_rpc_error(-32601, 'Method not found', wallet.expandwalletdescriptor, 'status')
        endpoint = urlsplit(rpc_url(node.datadir_path, node.index, node.chain, node.rpchost))
        headers = {'Authorization': 'Basic ' + base64.b64encode(b'expandlimited:restricted-password').decode(), 'Content-Type': 'application/json'}
        for method, params, expected_status in [('getwalletinfo', [], 200)] + [(method, [], 403) for method in ['deriveaddresses', 'scantxoutset', 'scanblocks', 'getdescriptoractivity']]:
            with closing(HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)) as connection:
                connection.request('POST', '/wallet/expand', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}), headers)
                response = connection.getresponse()
                assert_equal(response.status, expected_status)
                response.read()

        baseline = state()
        message = 'Select the owning wallet explicitly'
        assert_raises_rpc_error(-5, message, node.deriveaddresses, desc, [0, 0])
        assert_raises_rpc_error(-5, 'not registered in this wallet', other.deriveaddresses, desc, [0, 0])
        missing = node.get_wallet_rpc('missing')
        assert_raises_rpc_error(-18, 'does not exist or is not loaded', missing.deriveaddresses, desc, [0, 0])
        assert_raises_rpc_error(-8, 'Range must be specified', wallet.deriveaddresses, desc)
        assert_raises_rpc_error(-8, 'End of range is too high', wallet.deriveaddresses, desc, [2**31 - 1, 2**31])
        assert_raises_rpc_error(-8, 'must not have begin after end', wallet.deriveaddresses, desc, [2, 1])
        assert_raises_rpc_error(-8, 'Range is too large', wallet.deriveaddresses, desc, [0, 1000000])
        # Knowing a seed id does not authorize an arbitrary derivation path.
        altered = descsum_create(desc.split('#')[0].replace('/0h/0h/*h', '/99h/0h/*h'))
        assert altered != desc
        assert_raises_rpc_error(-5, 'not registered in this wallet', wallet.deriveaddresses, altered, [0, 0])

        self.log.info('Locked cached expansion returns the existing address result format')
        cached = wallet.deriveaddresses(desc, [0, 1])
        assert_equal(len(cached), 2)
        assert all(isinstance(address, str) for address in cached)
        assert_equal(node.cli('-rpcwallet=expand').deriveaddresses(desc, [0, 1]), cached)
        assert_equal(wallet.deriveaddresses(descriptor=desc, range=[0, 1]), cached)
        fixed = descsum_create(f'addr({cached[0]})')
        for rpc in [node, wallet, other, missing]:
            assert_equal(rpc.deriveaddresses(fixed), [cached[0]])
        assert_raises_rpc_error(-8, 'un-ranged descriptor', node.deriveaddresses, fixed, [0, 0])
        assert_raises_rpc_error(-13, 'Index 2 is not cached', wallet.deriveaddresses, desc, [0, 2])
        for call, args in scan_calls(node, [0, 1]):
            assert_raises_rpc_error(-5, message, call, *args)
        for call, args in scan_calls(other, [0, 1]):
            assert_raises_rpc_error(-5, 'not registered in this wallet', call, *args)
        for call, args in scan_calls(wallet, [0, 1]):
            call(*args)
        for call, args in scan_calls(wallet, [0, 2]):
            assert_raises_rpc_error(-13, 'Index 2 is not cached', call, *args)
        # Existing scanner default remains the inclusive range [0,1000].
        assert_raises_rpc_error(-13, 'Index 2 is not cached', wallet.scantxoutset, 'start', [desc])
        assert_equal(state(), baseline)

        self.log.info('Fresh derivation is temporary and uses the existing range rules')
        wallet.walletpassphrase('test expansion passphrase', 60)
        assert_equal(wallet.deriveaddresses(desc, [0, 1]), cached)
        fresh = wallet.deriveaddresses(desc, [2, 3])
        terminal = wallet.deriveaddresses(desc, [2**31 - 1, 2**31 - 1])
        assert_equal(len(terminal), 1)
        assert_equal(wallet.deriveaddresses(desc, [2, 3]), fresh)
        # The removed RPC's 100-index limit must not leak into existing commands.
        assert_equal(len(wallet.deriveaddresses(desc, [100, 200])), 101)
        for call, args in scan_calls(wallet, [2**31 - 1, 2**31 - 1]):
            call(*args)
        # Scanners accept descriptors without checksums as before.
        assert_equal(wallet.scantxoutset('start', [{'desc': desc.split('#')[0], 'range': [0, 1]}])['success'], True)
        assert_equal(state(), baseline)
        wallet.walletlock()
        assert_raises_rpc_error(-13, 'Index 2 is not cached', wallet.deriveaddresses, desc, [2, 2])
        assert_equal(wallet.deriveaddresses(desc, [0, 1]), cached)

        self.log.info('Expired unlock deadlines block fresh derivation before the timer runs')
        wallet.walletpassphrase('test expansion passphrase', 60)
        node.setmocktime(wallet.getwalletinfo()['unlocked_until'] + 1)
        try:
            assert_equal(wallet.deriveaddresses(desc, [0, 1]), cached)
            assert_raises_rpc_error(-13, 'Unlock this wallet', wallet.deriveaddresses, desc, [2, 2])
            for call, args in scan_calls(wallet, [2, 2]):
                assert_raises_rpc_error(-13, 'Unlock this wallet', call, *args)
        finally:
            node.setmocktime(0)
            wallet.walletlock()
        assert_equal(state(), baseline)

        def start_background(method):
            outcome = []
            def run():
                worker = get_rpc_proxy(rpc_url(node.datadir_path, node.index, node.chain, node.rpchost) + '/wallet/expand', node.index, timeout=60)
                # A cached probe may briefly acquire the reservation before
                # this worker starts. Retry only that startup conflict.
                for attempt in range(1000):
                    try:
                        if method == 'deriveaddresses':
                            outcome.append(worker.deriveaddresses(desc, [1000, 1999]))
                        else:
                            outcome.append(getattr(worker, method)('start', [{'desc': desc, 'range': [1000, 1999]}]))
                        return
                    except JSONRPCException as error:
                        if error.error['code'] == -4 and 'already in progress' in error.error['message'] and attempt < 999:
                            time.sleep(0.001)
                            continue
                        outcome.append(error.error)
                        return
                    except (OSError, HTTPException) as error:
                        outcome.append({'transport_error': type(error).__name__})
                        return
            thread = Thread(target=run)
            thread.start()
            return thread, outcome

        def expanding():
            # A second request tests the actual wallet reservation, not merely
            # whether the first request has reached the RPC dispatch table.
            try:
                wallet.deriveaddresses(desc, [0, 0])
            except JSONRPCException as error:
                assert_equal(error.error['code'], -4)
                assert 'already in progress' in error.error['message']
                return True
            return False

        self.log.info('Existing scan abort actions interrupt the descriptor expansion stage')
        wallet.walletpassphrase('test expansion passphrase', 60)
        for method in ['scantxoutset', 'scanblocks']:
            thread, outcome = start_background(method)
            try:
                self.wait_until(expanding, timeout=10, check_interval=0.01)
                assert getattr(wallet, method)('status') is not None
                assert_equal(getattr(wallet, method)('abort'), True)
            finally:
                thread.join(timeout=60)
            assert not thread.is_alive()
            assert_equal(outcome[0]['code'], -1)
            assert 'interrupted' in outcome[0]['message']
            assert_equal(getattr(wallet, method)('status'), None)
            assert_equal(getattr(wallet, method)('abort'), False)
            # A subsequent successful scan confirms reservation and abort cleanup.
            assert getattr(wallet, method)('start', [{'desc': desc, 'range': [0, 1]}])
        assert_equal(state(), baseline)

        self.log.info('Relocking interrupts deriveaddresses without returning a partial list')
        thread, outcome = start_background('deriveaddresses')
        try:
            self.wait_until(expanding, timeout=10, check_interval=0.01)
            wallet.walletlock()
        finally:
            thread.join(timeout=60)
        assert not thread.is_alive()
        assert_equal(outcome[0]['code'], -1)
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        assert_equal(state(), baseline)

        self.log.info('Shutdown preserves cache and address allocation')
        wallet.walletpassphrase('test expansion passphrase', 60)
        thread, outcome = start_background('deriveaddresses')
        try:
            self.wait_until(expanding, timeout=10, check_interval=0.01)
            self.restart_node(0)
        finally:
            thread.join(timeout=60)
        assert not thread.is_alive()
        assert isinstance(outcome[0], dict) and ('code' in outcome[0] or 'transport_error' in outcome[0])
        node.loadwallet('expand')
        wallet = node.get_wallet_rpc('expand')
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        assert_equal(wallet.deriveaddresses(desc, [0, 1]), cached)
        assert_raises_rpc_error(-13, 'Index 2 is not cached', wallet.deriveaddresses, desc, [2, 2])
        assert_equal(wallet.getnewaddress('', 'bech32'), cached[0])

        self.log.info('All three scanners find a future payment without importing it into the wallet')
        wallet.walletpassphrase('test expansion passphrase', 60)
        future = wallet.deriveaddresses(desc, [500, 500])[0]
        future_script = node.validateaddress(future)['scriptPubKey']
        before = wallet.listdescriptors()
        block = self.generatetoaddress(node, 1, future)[0]
        self.wait_until(lambda: node.getindexinfo()['basic block filter index']['synced'])
        objects = [{'desc': desc, 'range': [500, 500]}]
        coins = wallet.scantxoutset('start', objects)
        assert_equal(coins['success'], True)
        assert_equal(len(coins['unspents']), 1)
        assert_equal(coins['unspents'][0]['scriptPubKey'], future_script)
        assert_equal(coins['total_amount'], node.scantxoutset('start', [f'addr({future})'])['total_amount'])
        blocks = wallet.scanblocks('start', objects)
        assert_equal(blocks['completed'], True)
        assert_equal(blocks['relevant_blocks'], [block])
        activity = wallet.getdescriptoractivity([block], objects, False)
        assert_equal(activity, node.getdescriptoractivity([block], [f'addr({future})'], False))
        assert_equal(len(activity['activity']), 1)
        assert_equal(wallet.listdescriptors(), before)
        assert_equal(wallet.getaddressinfo(future)['ismine'], False)
        assert_equal(wallet.getwalletinfo()['txcount'], 0)
        wallet.walletlock()
        assert_raises_rpc_error(-13, 'Index 500 is not cached', wallet.deriveaddresses, desc, [500, 500])


if __name__ == '__main__':
    WalletDescriptorExpansionTest(__file__).main()
