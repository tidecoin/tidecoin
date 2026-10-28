#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying COPYING file.
"""Host rule selection survives a chain transition during a device response."""

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import json
from pathlib import Path
import socket
import sys

from feature_auxpow_mempool_transition import falcon_signature_variants
from rpc_transaction_rules import PRE, POST, TransactionRulesTest
from test_framework.descriptors import descsum_create
from test_framework.psbt import PSBT, PSBT_IN_NON_WITNESS_UTXO
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy
from test_framework.wallet_util import generate_keypair


class TransactionRulesSignerTest(TransactionRulesTest):
    def set_test_params(self):
        super().set_test_params()
        mock = Path(__file__).resolve().parent / 'mocks' / 'pq_signer.py'
        self.extra_args[1] = self.extra_args[1] + [f'-signer="{sys.executable}" "{mock}" --state rules_signer.json']

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_external_signer()

    def run_test(self):
        node, offline = self.nodes
        self.generate(node, 201, sync_fun=self.no_op)
        local = offline.get_wallet_rpc(self.default_wallet_name)
        payout = local.getnewaddress()
        secret, pub = generate_keypair(wif=True, scheme='7')
        _, change_pub = generate_keypair(wif=True, scheme='7')
        descriptor = descsum_create(f'pkh({secret})')
        public = node.getdescriptorinfo(descriptor)['descriptor']
        address = node.deriveaddresses(public)[0]
        change_descriptor = descsum_create(f'wpkh({change_pub.hex()})')
        change = offline.deriveaddresses(change_descriptor)[0]
        self.state_path = Path(offline.cwd) / 'rules_signer.json'
        self.state = {'descriptors': {'receive': [public], 'internal': [change_descriptor]},
                      'addresses': {public: address, change_descriptor: change}}
        self.save()
        offline.createwallet('device', disable_private_keys=True, external_signer=True)
        device = offline.get_wallet_rpc('device')
        outpoint, previous = self.fund(address)
        base = PSBT.from_base64(node.createpsbt([outpoint], {change: Decimal('0.995')}))
        base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
        request = device.walletprocesspsbt(base.to_base64(), False, finalize=False, rules=POST)['psbt']
        fresh = node.descriptorprocesspsbt(request, [descriptor], finalize=False, rules=POST)['psbt']
        partial = PSBT.from_base64(fresh)
        key = b'\x02' + pub
        for variant in falcon_signature_variants(partial.i[0].map[key], secret):
            partial.i[0].map[key] = variant
            old = offline.finalizepsbt(partial.to_base64(), rules=PRE)
            if old['complete'] and not offline.finalizepsbt(partial.to_base64(), rules=POST)['complete']:
                break
        else:
            raise AssertionError('No old-only signature')
        old_partial = partial.to_base64()
        old_final = offline.finalizepsbt(old_partial, False, PRE)['psbt']
        for response in (old_partial, old_final):
            self.response(response)
            self.metadata(device.walletprocesspsbt(request, rules=PRE), PRE)
            assert_raises_rpc_error(-25, 'External signer failed', device.walletprocesspsbt, request, rules=POST)
        self.response(fresh)
        self.accepted(device.walletprocesspsbt(old_partial, rules=POST))
        sent = PSBT.from_base64(Path(str(self.state_path) + '.request').read_text())
        assert key not in sent.i[0].map
        calls = Path(str(self.state_path) + '.calls').read_text()
        assert_raises_rpc_error(-8, 'rules must be', device.walletprocesspsbt, request, rules='invalid')
        assert_equal(Path(str(self.state_path) + '.calls').read_text(), calls)

        self.log.info('Advance during a device call retains pre rules through extraction')
        self.generatetoaddress(offline, 108, payout, sync_fun=self.no_op)
        self.metadata(device.walletprocesspsbt(request, sign=False), PRE, explicit=False)
        # The next block at tip 108 is still pre activation. Advance to 109
        # only after the host has selected its context and reached the device.
        self.response(old_partial)
        worker = get_rpc_proxy(offline.url + '/wallet/device', offline.index, timeout=60)
        result = self.during_call(
            lambda: worker.walletprocesspsbt(request),
            lambda: self.generatetoaddress(offline, 1, payout, sync_fun=self.no_op))
        self.metadata(result, PRE, explicit=False)
        assert result['complete'] and 'hex' in result
        assert_equal(offline.getblockcount(), 109)
        assert_raises_rpc_error(-25, 'External signer failed', device.walletprocesspsbt, request)
        boundary = offline.getbestblockhash()

        # For rollback, a native-v1 final distinguishes post from pre.
        v1_descriptor = descsum_create(f'wsh512(pk({secret}))')
        v1_public = node.getdescriptorinfo(v1_descriptor)['descriptor']
        self.state['descriptors']['receive'] = [v1_public]
        self.save()
        offline.createwallet('device_v1', disable_private_keys=True, external_signer=True)
        v1_device = offline.get_wallet_rpc('device_v1')
        v1_address = node.deriveaddresses(v1_public)[0]
        v1_outpoint, v1_previous = self.fund(v1_address)
        v1_base = PSBT.from_base64(node.createpsbt([v1_outpoint], {change: Decimal('0.995')}))
        v1_base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = v1_previous
        v1_request = v1_device.walletprocesspsbt(v1_base.to_base64(), False, finalize=False, rules=POST)['psbt']
        # Post-rule updating may compact a native-v1 previous transaction. Keep
        # the full record so a pre-rule request reaches device-result checking.
        v1_with_full = PSBT.from_base64(v1_request)
        v1_with_full.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = v1_previous
        v1_request = v1_with_full.to_base64()
        v1_fresh = node.descriptorprocesspsbt(v1_request, [v1_descriptor], rules=POST)['psbt']
        v1_partial = node.descriptorprocesspsbt(v1_request, [v1_descriptor], finalize=False, rules=POST)['psbt']
        for response in (v1_partial, v1_fresh):
            self.response(response)
            assert_raises_rpc_error(-25, 'External signer failed', v1_device.walletprocesspsbt, v1_request, rules=PRE)
            self.accepted(v1_device.walletprocesspsbt(v1_request, rules=POST))
        for scheme in range(8, 12):
            later_secret, _ = generate_keypair(wif=True, scheme=str(scheme))
            later_descriptor = descsum_create(f'wpkh({later_secret})')
            later_public = node.getdescriptorinfo(later_descriptor)['descriptor']
            self.state['descriptors']['receive'] = [later_public]
            self.save()
            name = f'device_scheme_{scheme}'
            offline.createwallet(name, disable_private_keys=True, external_signer=True)
            later_device = offline.get_wallet_rpc(name)
            later_outpoint, later_previous = self.fund(node.deriveaddresses(later_public)[0])
            later_base = PSBT.from_base64(node.createpsbt([later_outpoint], {change: Decimal('0.995')}))
            later_base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = later_previous
            later_request = later_device.walletprocesspsbt(later_base.to_base64(), False, finalize=False, rules=POST)['psbt']
            for finalize in (False, True):
                response = node.descriptorprocesspsbt(later_request, [later_descriptor], finalize=finalize, rules=POST)['psbt']
                self.response(response)
                assert_raises_rpc_error(-25, 'External signer failed', later_device.walletprocesspsbt, later_request, rules=PRE)
                self.accepted(later_device.walletprocesspsbt(later_request, rules=POST))
        self.state['descriptors']['receive'] = [v1_public]
        self.response(v1_fresh)
        self.log.info('Rollback during a device call retains post rules through extraction')
        worker = get_rpc_proxy(offline.url + '/wallet/device_v1', offline.index, timeout=60)
        result = self.during_call(lambda: worker.walletprocesspsbt(v1_request),
                                  lambda: offline.invalidateblock(boundary))
        self.metadata(result, POST, POST, explicit=False)
        self.accepted(result)
        assert_equal(offline.getblockcount(), 108)
        subsequent = v1_device.walletprocesspsbt(v1_fresh, sign=False)
        self.metadata(subsequent, PRE, explicit=False)
        assert not subsequent['complete']
        self.accepted(v1_device.walletprocesspsbt(v1_fresh, rules=POST))

        self.log.info('Ordinary send retains its local rules through both fills and extraction')
        offline.reconsiderblock(boundary)
        local.sendtoaddress(v1_address, 1)
        self.generatetoaddress(offline, 1, payout, sync_fun=self.no_op)
        def reply_and_roll_back():
            incoming = Path(str(self.state_path) + '.request').read_text()
            response = node.descriptorprocesspsbt(incoming, [v1_descriptor], rules=POST)
            assert response['complete']
            self.response(response['psbt'])
            offline.invalidateblock(boundary)
        sent = self.during_call(
            lambda: worker.send({payout: Decimal('0.5')}, fee_rate=10,
                                options={'change_address': change, 'add_to_wallet': False}),
            reply_and_roll_back)
        assert sent['complete']
        assert 'rules' not in sent
        expected = offline.finalizepsbt(self.state['response']['psbt'], rules=POST)
        assert_equal(sent['hex'], expected['hex'])
        assert_equal(offline.getblockcount(), 108)

        self.log.info('Fee bump retains its local rules through both fills and extraction')
        offline.reconsiderblock(boundary)

        def reply_v1():
            incoming = Path(str(self.state_path) + '.request').read_text()
            response = node.descriptorprocesspsbt(incoming, [v1_descriptor], rules=POST)
            assert response['complete']
            self.response(response['psbt'])

        original = self.during_call(
            lambda: worker.send({payout: Decimal('0.3')}, fee_rate=10,
                                options={'change_address': change}),
            reply_v1)
        assert original['complete']
        assert original['txid'] in offline.getrawmempool()

        def reply_bump_and_roll_back():
            reply_v1()
            offline.invalidateblock(boundary)

        bumped = self.during_call(
            lambda: worker.bumpfee(original['txid'], {'fee_rate': 20}),
            reply_bump_and_roll_back)
        assert_equal(bumped['errors'], [])
        assert 'rules' not in bumped
        expected = offline.finalizepsbt(self.state['response']['psbt'], rules=POST)
        assert expected['complete']
        assert_equal(bumped['txid'], offline.decoderawtransaction(expected['hex'])['txid'])
        assert_equal(v1_device.gettransaction(bumped['txid'])['hex'], expected['hex'])
        assert_equal(offline.getblockcount(), 108)
        # Processing keeps its selected rules; admission still uses the live chain.
        assert bumped['txid'] not in offline.getrawmempool()
        assert not offline.finalizepsbt(self.state['response']['psbt'])['complete']
        offline.reconsiderblock(boundary)
        assert_equal(offline.sendrawtransaction(expected['hex']), bumped['txid'])

    def save(self):
        self.state_path.write_text(json.dumps(self.state))

    def response(self, value):
        self.state['response'] = {'psbt': value, 'complete': True}
        self.save()

    def during_call(self, call, transition):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(30)
            self.state['pause_port'] = listener.getsockname()[1]
            self.save()
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(call)
                with listener.accept()[0] as connection:
                    connection.settimeout(30)
                    assert_equal(connection.recv(1), b'R')
                    try:
                        transition()
                    finally:
                        self.state.pop('pause_port')
                        self.save()
                        connection.sendall(b'C')
                return future.result(timeout=30)


if __name__ == '__main__':
    TransactionRulesSignerTest(__file__).main()
