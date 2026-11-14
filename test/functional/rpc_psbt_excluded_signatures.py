#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying COPYING file.
"""Excluded partials retain their data without constraining eligible signing."""

from decimal import Decimal
import json
from pathlib import Path
import sys

from rpc_psbt_witness_v1 import WitnessV1PSBTTest
from test_framework.descriptors import descsum_create
from test_framework.psbt import (
    PSBT, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_PARTIAL_SIG,
    PSBT_IN_SIGHASH_TYPE, PSBT_IN_WITNESS_SCRIPT,
)
from test_framework.script import hash160
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair

PRE = 'pre-auxpow'
POST = 'post-auxpow'


class ExcludedSignaturesTest(WitnessV1PSBTTest):
    def set_test_params(self):
        super().set_test_params()
        mock = Path(__file__).resolve().parent / 'mocks' / 'pq_signer.py'
        self.extra_args[1] = ['-keypool=1', '-auxpowactivationheight=never',
                              f'-signer="{sys.executable}" "{mock}" --state excluded_signer.json']

    def make_psbt(self, descriptor):
        node = self.nodes[0]
        address = node.deriveaddresses(descriptor)[0]
        outpoint, previous = self.fund(address)
        base = PSBT.from_base64(node.createpsbt([outpoint], {self.destination: Decimal('0.995')}))
        base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
        return base

    def run_test(self):
        node, offline = self.nodes
        self.generate(node, 201, sync_fun=self.no_op)
        self.destination = node.getnewaddress()
        falcon_secret, falcon_pub = generate_keypair(scheme='7')
        self.falcon_pub = falcon_pub
        falcon_sigkey = bytes([PSBT_IN_PARTIAL_SIG]) + falcon_pub
        for scheme in range(8, 12):
            other_secret, other_pub = generate_keypair(scheme=str(scheme))
            other_sigkey = bytes([PSBT_IN_PARTIAL_SIG]) + other_pub
            for reverse in (False, True):
                self.log.info('Mixed multisig: scheme %s, reverse=%s', scheme, reverse)
                def desc(left, right, threshold=1):
                    keys = (right, left) if reverse else (left, right)
                    return descsum_create(f'wsh(multi({threshold},{",".join(keys)}))')
                public = desc(falcon_pub.hex(), other_pub.hex())
                eligible = desc(falcon_secret, other_pub.hex())
                excluded = desc(falcon_pub.hex(), other_secret)
                both = desc(falcon_secret, other_secret)
                base = self.make_psbt(public)
                wallets = []
                # Separate managers and ownership of the excluded key exercise
                # wallet-wide preflight, not just the final descriptor signer.
                for label, owned in (('eligible', eligible), ('both', both), ('separate', eligible)):
                    name = f'{scheme}-{reverse}-{label}'
                    offline.createwallet(name, blank=True)
                    wallet = offline.get_wallet_rpc(name)
                    assert wallet.importdescriptors([{'desc': owned, 'timestamp': 'now'}])[0]['success']
                    if label == 'separate':
                        extra = descsum_create(f'pkh({other_secret})')
                        assert wallet.importdescriptors([{'desc': extra, 'timestamp': 'now'}])[0]['success']
                    wallets.append(wallet)
                for mode, other_mode, value in (('ALL', 'NONE', 1), ('NONE', 'SINGLE', 2), ('SINGLE', 'ALL', 3)):
                    foreign = PSBT.from_base64(offline.descriptorprocesspsbt(psbt=base.to_base64(), descriptors=[excluded], sighashtype=other_mode, finalize=False, rules=POST)['psbt'])
                    foreign.i[0].map.pop(PSBT_IN_SIGHASH_TYPE, None)
                    if value != 1:
                        foreign.i[0].map[PSBT_IN_SIGHASH_TYPE] = value.to_bytes(4, 'little')
                    own = PSBT.from_base64(offline.descriptorprocesspsbt(psbt=base.to_base64(), descriptors=[eligible], sighashtype=mode, finalize=False, rules=POST)['psbt'])
                    cached = PSBT.from_base64(foreign.to_base64())
                    cached.i[0].map[falcon_sigkey] = own.i[0].map[falcon_sigkey]
                    original_other = foreign.i[0].map[other_sigkey]
                    for candidate in (foreign, cached):
                        for descriptors in ([eligible], [both]):
                            result = offline.descriptorprocesspsbt(psbt=candidate.to_base64(), descriptors=descriptors, sighashtype=mode, finalize=False, rules=PRE)
                            self.check_partial(result, other_sigkey, original_other)
                        for wallet in wallets:
                            result = wallet.walletprocesspsbt(psbt=candidate.to_base64(), sighashtype=mode, finalize=False, rules=PRE)
                            self.check_partial(result, other_sigkey, original_other)
                        # Omitted rules on the offline node select pre rules too.
                        result = wallets[-1].walletprocesspsbt(psbt=candidate.to_base64(), sighashtype=mode, finalize=False)
                        self.check_partial(result, other_sigkey, original_other)
                    final = offline.finalizepsbt(psbt=cached.to_base64(), rules=PRE)
                    assert final['complete']
                    assert node.testmempoolaccept([final['hex']])[0]['allowed']
                    analysis = offline.analyzepsbt(psbt=cached.to_base64(), rules=PRE)
                    assert_equal(analysis['next'], 'finalizer')
                    assert 'excluded_signatures' not in analysis['inputs'][0]
                    # Both candidates are eligible after activation: their mode
                    # disagreement must still be enforced.
                    assert not offline.finalizepsbt(psbt=cached.to_base64(), rules=POST)['complete']
                    assert_raises_rpc_error(-22, 'sighash', wallets[1].walletprocesspsbt,
                                            psbt=cached.to_base64(), sighashtype=mode, rules=POST)
                    # Explicit declarations remain authoritative, even under pre.
                    conflict = PSBT.from_base64(cached.to_base64())
                    conflict.i[0].map[PSBT_IN_SIGHASH_TYPE] = (2 if value == 1 else 1).to_bytes(4, 'little')
                    assert not offline.finalizepsbt(psbt=conflict.to_base64(), rules=PRE)['complete']
                    assert not wallets[0].walletprocesspsbt(psbt=conflict.to_base64(), sighashtype=mode, rules=PRE)['complete']
                    if mode == 'ALL':
                        self.check_declaration(foreign, cached, wallets[-1], other_sigkey, original_other)
                        if scheme == 9 and not reverse and self.is_external_signer_compiled():
                            self.check_device(public, eligible, foreign, cached, other_sigkey, original_other)
                # Missing scripts remain undecidable, not excluded Falcon data.
                unknown = PSBT.from_base64(own.to_base64())
                unknown.i[0].map.pop(PSBT_IN_WITNESS_SCRIPT)
                assert not offline.finalizepsbt(psbt=unknown.to_base64(), rules=PRE)['complete']
                self.check_analysis(other_secret, other_pub, falcon_secret, falcon_pub, desc)

    def check_partial(self, result, excluded_key, excluded_value):
        fields = PSBT.from_base64(result['psbt']).i[0].map
        assert_equal(fields[excluded_key], excluded_value)
        assert bytes([PSBT_IN_PARTIAL_SIG]) + self.falcon_pub in fields
        assert self.nodes[1].finalizepsbt(psbt=result['psbt'], rules=PRE)['complete']

    def check_declaration(self, foreign, cached, wallet, key, signature):
        result = wallet.walletprocesspsbt(psbt=foreign.to_base64(), sign=False, sighashtype='ALL', finalize=False, rules=PRE)
        fields = PSBT.from_base64(result['psbt']).i[0].map
        assert_equal(fields[key], signature)
        assert_equal(fields[PSBT_IN_SIGHASH_TYPE], b'\x01\x00\x00\x00')
        assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt,
                                psbt=foreign.to_base64(), sign=False, sighashtype='ALL', rules=POST)
        conflict = PSBT.from_base64(foreign.to_base64())
        conflict.i[0].map[PSBT_IN_SIGHASH_TYPE] = b'\x02\x00\x00\x00'
        assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt,
                                psbt=conflict.to_base64(), sign=False, sighashtype='ALL', rules=PRE)
        # A mismatching eligible signature is not exempt.
        assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt,
                                psbt=cached.to_base64(), sign=False, sighashtype='NONE', rules=PRE)

    def check_analysis(self, secret, pub, falcon_secret, falcon_pub, desc):
        offline = self.nodes[1]
        for descriptor, keys in ((descsum_create(f'wsh(pk({secret}))'), [pub]),
                                 (descsum_create(f'wsh512(pk({falcon_secret}))'), [falcon_pub]),
                                 (desc(falcon_secret, secret, 2), [pub])):
            public = offline.getdescriptorinfo(descriptor)['descriptor']
            base = self.make_psbt(public)
            partial = offline.descriptorprocesspsbt(psbt=base.to_base64(), descriptors=[descriptor], finalize=False, rules=POST)['psbt']
            analysis = offline.analyzepsbt(psbt=partial, rules=PRE)
            item = analysis['inputs'][0]
            assert_equal(item['excluded_signatures'], [hash160(key).hex() for key in keys])
            assert_equal(item['issue'], 'rules_excluded')
            assert_equal(item['next'], 'updater')
            assert not item.get('missing', {}).get('signatures')
            assert not offline.finalizepsbt(psbt=partial, rules=PRE)['complete']
            assert offline.finalizepsbt(psbt=partial, rules=POST)['complete']

    def check_device(self, public, eligible, foreign, cached, key, signature):
        offline = self.nodes[1]
        change = descsum_create(f'wpkh({self.falcon_pub.hex()})')
        path = Path(offline.cwd) / 'excluded_signer.json'
        state = {'descriptors': {'receive': [public], 'internal': [change]}}
        path.write_text(json.dumps(state), encoding='utf8')
        offline.createwallet('device', disable_private_keys=True, external_signer=True)
        device = offline.get_wallet_rpc('device')
        request = device.walletprocesspsbt(psbt=foreign.to_base64(), sign=False, finalize=False, rules=PRE)['psbt']
        response = offline.descriptorprocesspsbt(psbt=request, descriptors=[eligible], finalize=False, rules=PRE)['psbt']
        state['response'] = {'psbt': response}
        path.write_text(json.dumps(state), encoding='utf8')
        result = device.walletprocesspsbt(psbt=request, finalize=False, rules=PRE)
        self.check_partial(result, key, signature)
        sent = PSBT.from_base64(Path(str(path) + '.request').read_text(encoding='utf8'))
        assert_equal(sent.i[0].map[key], signature)
        assert device.walletprocesspsbt(psbt=request, rules=PRE)['complete']
        # Existing response verification still rejects a newly supplied excluded
        # signature, rather than trusting the device's completion claim.
        without = PSBT.from_base64(request)
        without.i[0].map.pop(key)
        assert_raises_rpc_error(-25, 'External signer failed', device.walletprocesspsbt,
                                psbt=without.to_base64(), rules=PRE)
        assert_raises_rpc_error(-22, 'sighash', device.walletprocesspsbt,
                                psbt=cached.to_base64(), rules=POST)


if __name__ == '__main__':
    ExcludedSignaturesTest(__file__).main()
