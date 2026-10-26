#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying COPYING file.
"""Explicit script eras for chainless processing; the destination still decides admission."""

from decimal import Decimal
from io import BytesIO

from feature_auxpow_mempool_transition import falcon_signature_variants
from rpc_psbt_witness_v1 import WitnessV1PSBTTest
from test_framework.address import script_to_p2sh
from test_framework.descriptors import descsum_create
from test_framework.falcon import falcon512_alternates
from test_framework.messages import CTransaction, CTxOut, tx_from_hex
from test_framework.psbt import (
    PSBT, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_PARTIAL_SIG, PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO,
)
from test_framework.util import assert_equal, assert_not_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair

PRE = 'pre-auxpow'
POST = 'post-auxpow'


class TransactionRulesTest(WitnessV1PSBTTest):
    def set_test_params(self):
        super().set_test_params()
        self.extra_args = [['-keypool=1', '-auxpowactivationheight=110']] * 2

    def skip_test_if_missing_module(self):
        super().skip_test_if_missing_module()
        self.skip_if_no_cli()

    def metadata(self, result, effective, local=PRE, explicit=True):
        assert_equal(result['rules'], effective)
        mismatch = explicit and effective != local
        assert_equal('warnings' in result, mismatch)
        if mismatch:
            notice = result['warnings'][0]
            assert f'Explicit {effective}' in notice
            assert f'({local})' in notice

    def accepted(self, result):
        assert result['complete'], result
        check = self.nodes[0].testmempoolaccept([result['hex']])[0]
        assert check['allowed'], check

    def run_test(self):
        node, offline = self.nodes
        self.generate(node, 201, sync_fun=self.no_op)
        self.destination = node.getnewaddress()
        self.empty = offline.get_wallet_rpc(self.default_wallet_name)
        offline.createwallet('owner', blank=True)
        owner = offline.get_wallet_rpc('owner')
        cases = []
        for scheme in range(7, 12):
            secret, pubkey = generate_keypair(wif=True, scheme=str(scheme))
            for template in ('pkh({})', 'sh(wpkh({}))', 'wpkh({})', 'wsh512(pk({}))'):
                self.log.info(f'Offline rule selection: {scheme}, {template}')
                descriptor = descsum_create(template.format(secret))
                public = node.getdescriptorinfo(descriptor)['descriptor']
                address = node.deriveaddresses(public)[0]
                outpoint, previous = self.fund(address)
                self.generate(node, 1, sync_fun=self.no_op)
                tx = CTransaction()
                tx.deserialize(BytesIO(previous))
                utxo = tx.vout[outpoint['vout']]
                base = PSBT.from_base64(node.createpsbt([outpoint], {self.destination: Decimal('0.995')}))
                base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
                assert owner.importdescriptors([{'desc': descriptor, 'timestamp': 'now'}])[0]['success']
                filled = offline.descriptorprocesspsbt(base.to_base64(), [public], finalize=False, rules=POST)['psbt']
                scripts = PSBT.from_base64(filled).i[0].map
                prevout = dict(outpoint, amount=1, scriptPubKey=utxo.scriptPubKey.hex())
                for field, key in (('redeemScript', PSBT_IN_REDEEM_SCRIPT), ('witnessScript', PSBT_IN_WITNESS_SCRIPT)):
                    if key in scripts:
                        prevout[field] = scripts[key].hex()
                raw = base.tx.serialize().hex()
                # All five schemes and four script forms through all four local signers.
                for call in (
                    lambda rules: offline.descriptorprocesspsbt(base.to_base64(), [descriptor], rules=rules),
                    lambda rules: owner.walletprocesspsbt(base.to_base64(), rules=rules),
                    lambda rules: offline.signrawtransactionwithkey(raw, [secret], [prevout], rules=rules),
                    lambda rules: owner.signrawtransactionwithwallet(raw, [prevout], rules=rules),
                ):
                    result = call(POST)
                    self.metadata(result, POST)
                    self.accepted(result)
                    pre = call(PRE)
                    self.metadata(pre, PRE)
                    assert_equal(pre['complete'], scheme == 7 and template != 'wsh512(pk({}))')
                    if pre['complete']:
                        self.accepted(pre)
                automatic = owner.walletprocesspsbt(base.to_base64())
                self.metadata(automatic, PRE, explicit=False)
                assert_equal(automatic['complete'], scheme == 7 and template != 'wsh512(pk({}))')
                cases.append((scheme, template, secret, pubkey, descriptor, public, base, prevout, filled))
        assert_equal(offline.getblockcount(), 0)
        self.check_contract(cases[0], owner)
        self.check_cached(cases[0], owner)
        self.check_alternate_encodings(cases, owner)
        self.check_cleanup_and_missing(cases, owner)
        self.check_multisig(cases, owner)
        self.check_workflow()
        self.check_boundaries(cases[0])

    def check_contract(self, case, owner):
        node, offline = self.nodes
        _, _, secret, _, descriptor, _, base, prevout, _ = case
        partial = owner.walletprocesspsbt(base.to_base64(), finalize=False, rules=POST)['psbt']
        raw = base.tx.serialize().hex()
        final = offline.finalizepsbt(partial, rules=POST)['hex']
        calls = [
            (owner, 'walletprocesspsbt', [base.to_base64()], 5),
            (offline, 'descriptorprocesspsbt', [base.to_base64(), [descriptor]], 4),
            (offline, 'finalizepsbt', [partial], 2),
            (offline, 'analyzepsbt', [partial], 1),
            (offline, 'signrawtransactionwithkey', [raw, [secret], [prevout]], 4),
            (owner, 'signrawtransactionwithwallet', [raw, [prevout]], 3),
            (offline, 'utxoupdatepsbt', [partial], 2),
            # Combining still needs the actual local coin view.
            (node, 'combinerawtransaction', [[final]], 1),
        ]
        for rpc, name, args, position in calls:
            call = getattr(rpc, name)
            local = POST if rpc is node else PRE
            for era in (PRE, POST, None):
                for result in (call(*args, rules=era), call(*(args + [None] * (position - len(args)) + [era]))):
                    if isinstance(result, dict):
                        self.metadata(result, era or local, local, explicit=era is not None)
                    elif name == 'utxoupdatepsbt':
                        assert_equal(PSBT.from_base64(result).tx.serialize(), base.tx.serialize())
                    else:
                        assert_equal(tx_from_hex(result).vin[0].prevout.serialize(), base.tx.vin[0].prevout.serialize())
                assert isinstance(call(*args), type(result))
            cli = (node if rpc is node else offline).cli(*(['-rpcwallet=owner'] if rpc is owner else []))
            for era in (PRE, POST):
                names = {
                    'walletprocesspsbt': ('psbt',),
                    'descriptorprocesspsbt': ('psbt', 'descriptors'),
                    'finalizepsbt': ('psbt',),
                    'analyzepsbt': ('psbt',),
                    'signrawtransactionwithkey': ('hexstring', 'privkeys', 'prevtxs'),
                    'signrawtransactionwithwallet': ('hexstring', 'prevtxs'),
                    'utxoupdatepsbt': ('psbt',),
                    'combinerawtransaction': ('txs',),
                }
                # Base64 padding contains '='; keep every CLI argument named.
                result = getattr(cli, name)(**dict(zip(names[name], args)), rules=era)
                if isinstance(result, dict):
                    self.metadata(result, era, local)
                else:
                    assert isinstance(result, str)
            for invalid in ('', 'auto', 'POST-AUXPOW', 'bad'):
                assert_raises_rpc_error(-8, 'rules must be', call, *args, rules=invalid)
            for invalid in (0, True, [], {}):
                assert_raises_rpc_error(-3, '', call, *args, rules=invalid)
        assert_raises_rpc_error(-25, 'Input not found', offline.combinerawtransaction, [final], POST)
        matching = node.finalizepsbt(partial, rules=POST)
        self.metadata(matching, POST, POST)
        mismatch = node.finalizepsbt(partial, rules=PRE)
        self.metadata(mismatch, PRE, POST)
        self.metadata(node.finalizepsbt(partial), POST, POST, explicit=False)
        for extract in (False, True):
            result = offline.finalizepsbt(partial, extract, POST)
            assert result['complete']
            assert_equal('hex' in result, extract)
        # The default pre-activation wallet still cannot issue native v1 addresses.
        assert_raises_rpc_error(-12, '', self.empty.getnewaddress, '', 'bech32pq')
        assert_raises_rpc_error(-8, '', self.empty.getnewaddress, rules=POST)

    def check_cached(self, case, owner):
        node, offline = self.nodes
        _, _, secret, pubkey, descriptor, _, base, prevout, _ = case
        partial = PSBT.from_base64(owner.walletprocesspsbt(base.to_base64(), finalize=False, rules=PRE)['psbt'])
        key = bytes([PSBT_IN_PARTIAL_SIG]) + pubkey
        signature = partial.i[0].map[key]
        for variant in falcon_signature_variants(signature, secret):
            partial.i[0].map[key] = variant
            old = offline.finalizepsbt(partial.to_base64(), rules=PRE)
            strict = offline.finalizepsbt(partial.to_base64(), rules=POST)
            if old['complete'] and not strict['complete']:
                break
        else:
            raise AssertionError('No signature distinguishing the two rule eras')
        self.log.info('Cached partial proven to verify only under pre-auxpow rules')
        value = partial.to_base64()
        # Signing replaces an owned invalid partial. Declaration/ownership behavior is unchanged.
        for call in (lambda: owner.walletprocesspsbt(value, rules=POST),
                     lambda: offline.descriptorprocesspsbt(value, [descriptor], rules=POST)):
            self.accepted(call())
        for call in (lambda: self.empty.walletprocesspsbt(value, rules=POST),
                     lambda: offline.descriptorprocesspsbt(value, [], rules=POST)):
            result = call()
            assert not result['complete']
            assert_equal(PSBT.from_base64(result['psbt']).i[0].map[key], variant)
        assert not owner.walletprocesspsbt(value, sign=False, rules=POST)['complete']
        for era, complete in ((PRE, True), (POST, False)):
            final = offline.finalizepsbt(value, False, PRE)['psbt']
            for candidate in (value, final):
                for extract in (False, True):
                    result = offline.finalizepsbt(candidate, extract, era)
                    assert_equal(result['complete'], complete)
                    assert_equal('hex' in result, complete and extract)
                for call in (lambda: owner.walletprocesspsbt(candidate, rules=era),
                             lambda: offline.descriptorprocesspsbt(candidate, [descriptor], rules=era)):
                    # Supplied finals are checked, never silently repaired.
                    if candidate == final:
                        assert_equal(call()['complete'], complete)
            analysis = offline.analyzepsbt(final, era)
            assert_equal(analysis['inputs'][0]['is_final'], complete)
            assert_equal(analysis['next'] == 'extractor', complete)
            for result in (offline.signrawtransactionwithkey(old['hex'], [], [prevout], rules=era),
                           self.empty.signrawtransactionwithwallet(old['hex'], [prevout], rules=era)):
                assert_equal(result['complete'], complete)
            combined = node.combinerawtransaction([old['hex']], era)
            checked = offline.signrawtransactionwithkey(combined, [], [prevout], rules=PRE)
            assert_equal(checked['complete'], complete)
        assert not node.testmempoolaccept([old['hex']])[0]['allowed']

    def check_alternate_encodings(self, cases, owner):
        node, offline = self.nodes
        _, foreign_pubkey = generate_keypair(scheme="7")
        foreign_key = bytes([PSBT_IN_PARTIAL_SIG]) + foreign_pubkey
        foreign_signature = b"\x01\x01"
        self.log.info("Old encodings complete under pre rules; strict processing replaces owned invalid partials")
        for scheme, template, _, pubkey, descriptor, _, base, _, _ in cases:
            if scheme != 7 or template == 'wsh512(pk({}))':
                continue
            own_key = bytes([PSBT_IN_PARTIAL_SIG]) + pubkey
            for mode in ('ALL', 'NONE'):
                for _ in range(100):
                    partial = PSBT.from_base64(owner.walletprocesspsbt(base.to_base64(), sighashtype=mode, finalize=False, rules=PRE)['psbt'])
                    original = partial.i[0].map[own_key]
                    alternates = falcon512_alternates(original)
                    if alternates:
                        break
                else:
                    raise AssertionError('No Falcon signature with both alternate encodings')
                for alternate in alternates:
                    partial.i[0].map[own_key] = alternate
                    partial.i[0].map[foreign_key] = foreign_signature
                    value = partial.to_base64()
                    if mode == 'NONE':
                        assert_raises_rpc_error(-22, 'sighash', owner.walletprocesspsbt, value, rules=PRE)
                        assert_raises_rpc_error(-22, 'sighash', offline.descriptorprocesspsbt, value, [descriptor], rules=PRE)
                    calls = (
                        lambda psbt, era, finalize: owner.walletprocesspsbt(psbt, sighashtype=mode, finalize=finalize, rules=era),
                        lambda psbt, era, finalize: offline.descriptorprocesspsbt(psbt, [descriptor], sighashtype=mode, finalize=finalize, rules=era),
                    )
                    final = offline.finalizepsbt(value, False, PRE)['psbt']
                    for call in calls:
                        old = call(value, PRE, True)
                        assert old['complete']
                        assert not node.testmempoolaccept([old['hex']])[0]['allowed']
                        assert call(final, PRE, True)['complete']
                        assert not call(final, POST, True)['complete']
                        replaced = call(value, POST, False)
                        fields = PSBT.from_base64(replaced['psbt']).i[0].map
                        assert_not_equal(fields[own_key], alternate)
                        assert_equal(fields[foreign_key], foreign_signature)
                        self.accepted(offline.finalizepsbt(replaced['psbt'], rules=POST))
                    # No key is needed to finish a valid pre-rules partial.
                    assert offline.descriptorprocesspsbt(value, [], sighashtype=mode, rules=PRE)['complete']
                    strict = offline.descriptorprocesspsbt(value, [], sighashtype=mode, rules=POST)
                    assert not strict['complete']
                    assert_equal(PSBT.from_base64(strict['psbt']).i[0].map[own_key], alternate)
                    assert not offline.finalizepsbt(final, rules=POST)['complete']

    def check_cleanup_and_missing(self, cases, owner):
        node, offline = self.nodes
        v1 = next(case for case in cases if case[1] == 'wsh512(pk({}))')
        _, _, _, _, descriptor, public, base, prevout, filled = v1
        partial = owner.walletprocesspsbt(base.to_base64(), finalize=False, rules=POST)['psbt']
        with_full = PSBT.from_base64(partial)
        with_full.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = base.i[0].map[PSBT_IN_NON_WITNESS_UTXO]
        for era in (PRE, POST):
            updated = offline.utxoupdatepsbt(with_full.to_base64(), [public], era)
            fields = PSBT.from_base64(updated).i[0].map
            assert_equal(PSBT_IN_NON_WITNESS_UTXO in fields, era == PRE)
            assert PSBT_IN_WITNESS_UTXO in fields
            assert_equal(offline.finalizepsbt(updated, rules=era)['complete'], era == POST)
        for missing in (PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO):
            bad = PSBT.from_base64(partial)
            bad.i[0].map.pop(missing, None)
            assert not offline.finalizepsbt(bad.to_base64(), rules=POST)['complete']
        legacy = cases[0]
        missing_prev = PSBT.from_base64(owner.walletprocesspsbt(legacy[6].to_base64(), rules=POST)['psbt'])
        missing_prev.i[0].map.pop(PSBT_IN_NON_WITNESS_UTXO)
        missing_prev.i[0].map[PSBT_IN_WITNESS_UTXO] = CTxOut(100_000_000, bytes.fromhex(legacy[7]['scriptPubKey'])).serialize()
        assert not offline.finalizepsbt(missing_prev.to_base64(), rules=POST)['complete']
        assert 'fee' not in offline.analyzepsbt(missing_prev.to_base64(), POST)
        # V1 ALL needs every spent output, even an input not owned by this signer.
        mixed = PSBT.from_base64(node.createpsbt([{k: prevout[k] for k in ('txid', 'vout')},
                                               {k: legacy[7][k] for k in ('txid', 'vout')}],
                                              {self.destination: Decimal('1.99')}))
        mixed.i[0].map = dict(PSBT.from_base64(filled).i[0].map)
        assert not owner.walletprocesspsbt(mixed.to_base64(), rules=POST)['complete']
        mixed.i[1].map = dict(legacy[6].i[0].map)
        self.accepted(owner.walletprocesspsbt(mixed.to_base64(), rules=POST))
        # An unsupported wrapped v1 form is not enabled by a processing option.
        assert_raises_rpc_error(-5, '', offline.getdescriptorinfo, descsum_create('sh(' + descriptor.split('#')[0] + ')'))
        wrapped = script_to_p2sh(bytes.fromhex(prevout['scriptPubKey']))
        outpoint, previous = self.fund(wrapped)
        wrapped_base = node.createpsbt([outpoint], {self.destination: Decimal('0.995')})
        wrapped_prev = dict(outpoint, amount=1, scriptPubKey=node.validateaddress(wrapped)['scriptPubKey'],
                            redeemScript=prevout['scriptPubKey'], witnessScript=prevout['witnessScript'])
        assert_raises_rpc_error(-8, '', offline.signrawtransactionwithkey,
                                PSBT.from_base64(wrapped_base).tx.serialize().hex(), [v1[2]], [wrapped_prev], rules=POST)

    def check_multisig(self, cases, owner):
        node, offline = self.nodes
        first = next(case for case in cases if case[0] == 8)
        second = next(case for case in cases if case[0] == 9)
        private = descsum_create(f'wsh512(multi(2,{first[2]},{second[2]}))')
        public = node.getdescriptorinfo(private)['descriptor']
        outpoint, previous = self.fund(node.deriveaddresses(public)[0])
        base = PSBT.from_base64(node.createpsbt([outpoint], {self.destination: Decimal('0.99')}))
        base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
        one = descsum_create(f'wsh512(multi(2,{first[2]},{second[3].hex()}))')
        two = descsum_create(f'wsh512(multi(2,{first[3].hex()},{second[2]}))')
        partial = offline.descriptorprocesspsbt(base.to_base64(), [one], finalize=False, rules=POST)
        assert not partial['complete']
        self.accepted(offline.descriptorprocesspsbt(partial['psbt'], [two], rules=POST))
        assert owner.importdescriptors([{'desc': private, 'timestamp': 'now'}])[0]['success']
        self.accepted(owner.walletprocesspsbt(base.to_base64(), rules=POST))

    def check_workflow(self):
        node, offline = self.nodes
        offline.createwallet('offline_workflow', passphrase='test passphrase')
        signer = offline.get_wallet_rpc('offline_workflow')
        signer.walletpassphrase('test passphrase', 60)
        receive = signer.getnewaddress('', 'bech32')
        change = signer.getrawchangeaddress('bech32')
        node.createwallet('online_watch', disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc('online_watch')
        assert all(item['success'] for item in watch.importdescriptors([
            {'desc': signer.getaddressinfo(receive)['desc'], 'timestamp': 'now'},
            {'desc': signer.getaddressinfo(change)['desc'], 'timestamp': 'now', 'internal': True},
        ]))
        assert_raises_rpc_error(-4, 'no available keys', watch.getnewaddress)
        # Use the default funding wallet explicitly now that another is loaded.
        self.fund(receive)
        self.generatetoaddress(node, 1, self.destination, sync_fun=self.no_op)
        unsigned = watch.send({self.destination: Decimal('0.5')}, fee_rate=10,
                              options={'change_address': change, 'psbt': True})
        assert not unsigned['complete']
        self.metadata(offline.analyzepsbt(unsigned['psbt'], POST), POST)
        none = signer.walletprocesspsbt(unsigned['psbt'], sighashtype='NONE', finalize=False, rules=POST)
        assert_raises_rpc_error(-22, 'sighash', signer.walletprocesspsbt, none['psbt'], rules=POST)
        self.accepted(signer.walletprocesspsbt(none['psbt'], sighashtype='NONE', rules=POST))
        signed = signer.walletprocesspsbt(unsigned['psbt'], rules=POST)
        self.metadata(signed, POST)
        self.accepted(signed)
        signer.walletlock()
        final = offline.finalizepsbt(signed['psbt'], rules=POST)
        self.accepted(final)
        node.sendrawtransaction(final['hex'])
        self.generatetoaddress(node, 1, self.destination, sync_fun=self.no_op)
        assert 0 < watch.getbalances()['mine']['trusted'] < Decimal('0.5')

    def check_boundaries(self, case):
        _, offline = self.nodes
        value = case[6].to_base64()
        payout = self.empty.getnewaddress()
        self.generatetoaddress(offline, 108, payout, sync_fun=self.no_op)
        self.metadata(offline.analyzepsbt(value), PRE, explicit=False)
        self.generatetoaddress(offline, 1, payout, sync_fun=self.no_op)
        self.metadata(offline.analyzepsbt(value), POST, POST, explicit=False)
        boundary = offline.getbestblockhash()
        self.generatetoaddress(offline, 1, payout, sync_fun=self.no_op)
        self.metadata(offline.analyzepsbt(value), POST, POST, explicit=False)
        offline.invalidateblock(boundary)
        assert_equal(offline.getblockcount(), 108)
        self.metadata(offline.analyzepsbt(value), PRE, explicit=False)
        self.metadata(offline.analyzepsbt(value, POST), POST)
        self.metadata(offline.analyzepsbt(value), PRE, explicit=False)


if __name__ == '__main__':
    TransactionRulesTest(__file__).main()
