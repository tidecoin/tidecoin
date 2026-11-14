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
    PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO, PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_OUT_WITNESS_SCRIPT,
)
from test_framework.util import assert_equal, assert_not_equal, assert_raises_rpc_error, get_rpc_proxy, rpc_url
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
                filled = offline.descriptorprocesspsbt(psbt=base.to_base64(), descriptors=[public], finalize=False, rules=POST)['psbt']
                scripts = PSBT.from_base64(filled).i[0].map
                prevout = dict(outpoint, amount=1, scriptPubKey=utxo.scriptPubKey.hex())
                for field, key in (('redeemScript', PSBT_IN_REDEEM_SCRIPT), ('witnessScript', PSBT_IN_WITNESS_SCRIPT)):
                    if key in scripts:
                        prevout[field] = scripts[key].hex()
                raw = base.tx.serialize().hex()
                # All five schemes and four script forms through all four local signers.
                eligible = scheme == 7 and template != 'wsh512(pk({}))'
                for is_psbt, call in (
                    (True, lambda **opts: offline.descriptorprocesspsbt(psbt=base.to_base64(), descriptors=[descriptor], **opts)),
                    (True, lambda **opts: owner.walletprocesspsbt(psbt=base.to_base64(), **opts)),
                    (False, lambda **opts: offline.signrawtransactionwithkey(raw, [secret], [prevout], **opts)),
                    (False, lambda **opts: owner.signrawtransactionwithwallet(raw, [prevout], **opts)),
                ):
                    result = call(rules=POST)
                    self.metadata(result, POST)
                    self.accepted(result)
                    for selection in ({'rules': PRE}, {}):
                        for finalize in ((True, False) if is_psbt else (True,)):
                            pre = call(**selection, **({'finalize': finalize} if is_psbt else {}))
                            self.metadata(pre, PRE, explicit=bool(selection))
                            if finalize:
                                assert_equal(pre['complete'], eligible)
                            if is_psbt:
                                fields = PSBT.from_base64(pre['psbt']).i[0].map
                                if not eligible:
                                    assert not any(isinstance(k, bytes) and k[0] == PSBT_IN_PARTIAL_SIG for k in fields)
                                    assert PSBT_IN_FINAL_SCRIPTSIG not in fields
                                    assert PSBT_IN_FINAL_SCRIPTWITNESS not in fields
                                elif not finalize:
                                    assert bytes([PSBT_IN_PARTIAL_SIG]) + pubkey in fields
                                # No private key: an excluded signature must not
                                # become usable merely by changing the rule era.
                                checked = offline.finalizepsbt(psbt=pre['psbt'], rules=POST)
                            else:
                                checked = offline.signrawtransactionwithkey(pre['hex'], [], [prevout], rules=POST)
                            assert_equal(checked['complete'], eligible)
                            if eligible:
                                self.accepted(checked)
                cases.append((scheme, template, secret, pubkey, descriptor, public, base, prevout, filled))
        assert_equal(offline.getblockcount(), 0)
        self.check_contract(cases[0], owner)
        self.check_cached(cases[0], owner)
        self.check_alternate_encodings(cases, owner)
        self.check_cleanup_and_missing(cases, owner)
        self.check_multisig(cases, owner)
        self.check_mixed_eligibility(cases, owner)
        self.check_workflow()
        self.check_boundaries(cases[0])

    def check_contract(self, case, owner):
        node, offline = self.nodes
        _, _, secret, _, descriptor, _, base, prevout, _ = case
        partial = owner.walletprocesspsbt(psbt=base.to_base64(), finalize=False, rules=POST)['psbt']
        raw = base.tx.serialize().hex()
        final = offline.finalizepsbt(psbt=partial, rules=POST)['hex']
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
        for rpc, name, args, position in calls:
            call = getattr(rpc, name)
            named_args = dict(zip(names[name], args))
            source = node if rpc is node else offline
            url = rpc_url(source.datadir_path, source.index, source.chain, source.rpchost)
            if rpc is owner:
                url += '/wallet/owner'
            # JSON nulls and non-string type errors require HTTP: the CLI treats
            # unconverted string arguments (including rules and sighash) as text.
            json_call = getattr(get_rpc_proxy(url, source.index), name)
            local = POST if rpc is node else PRE
            for era in (PRE, POST, None):
                for result in (call(**named_args, rules=era), json_call(*(args + [None] * (position - len(args)) + [era]))):
                    if isinstance(result, dict):
                        self.metadata(result, era or local, local, explicit=era is not None)
                    elif name == 'utxoupdatepsbt':
                        assert_equal(PSBT.from_base64(result).tx.serialize(), base.tx.serialize())
                    else:
                        assert_equal(tx_from_hex(result).vin[0].prevout.serialize(), base.tx.vin[0].prevout.serialize())
                assert isinstance(call(*args), type(result))
            cli = (node if rpc is node else offline).cli(*(['-rpcwallet=owner'] if rpc is owner else []))
            for era in (PRE, POST):
                # Base64 padding contains '='; keep every CLI argument named.
                result = getattr(cli, name)(**named_args, rules=era)
                if isinstance(result, dict):
                    self.metadata(result, era, local)
                else:
                    assert isinstance(result, str)
            for invalid in ('', 'auto', 'POST-AUXPOW', 'bad'):
                assert_raises_rpc_error(-8, 'rules must be', call, **named_args, rules=invalid)
            for invalid in (0, True, [], {}):
                assert_raises_rpc_error(-3, '', json_call, **named_args, rules=invalid)
        assert_raises_rpc_error(-25, 'Input not found', offline.combinerawtransaction, [final], POST)
        matching = node.finalizepsbt(psbt=partial, rules=POST)
        self.metadata(matching, POST, POST)
        mismatch = node.finalizepsbt(psbt=partial, rules=PRE)
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
        partial = PSBT.from_base64(owner.walletprocesspsbt(psbt=base.to_base64(), finalize=False, rules=PRE)['psbt'])
        key = bytes([PSBT_IN_PARTIAL_SIG]) + pubkey
        signature = partial.i[0].map[key]
        for variant in falcon_signature_variants(signature, secret):
            partial.i[0].map[key] = variant
            old = offline.finalizepsbt(psbt=partial.to_base64(), rules=PRE)
            strict = offline.finalizepsbt(psbt=partial.to_base64(), rules=POST)
            if old['complete'] and not strict['complete']:
                break
        else:
            raise AssertionError('No signature distinguishing the two rule eras')
        self.log.info('Cached partial proven to verify only under pre-auxpow rules')
        value = partial.to_base64()
        # Signing replaces an owned invalid partial. Declaration/ownership behavior is unchanged.
        for call in (lambda: owner.walletprocesspsbt(psbt=value, rules=POST),
                     lambda: offline.descriptorprocesspsbt(psbt=value, descriptors=[descriptor], rules=POST)):
            self.accepted(call())
        for call in (lambda: self.empty.walletprocesspsbt(psbt=value, rules=POST),
                     lambda: offline.descriptorprocesspsbt(psbt=value, descriptors=[], rules=POST)):
            result = call()
            assert not result['complete']
            assert_equal(PSBT.from_base64(result['psbt']).i[0].map[key], variant)
        assert not owner.walletprocesspsbt(psbt=value, sign=False, rules=POST)['complete']
        for era, complete in ((PRE, True), (POST, False)):
            final = offline.finalizepsbt(value, False, PRE)['psbt']
            for candidate in (value, final):
                for extract in (False, True):
                    result = offline.finalizepsbt(candidate, extract, era)
                    assert_equal(result['complete'], complete)
                    assert_equal('hex' in result, complete and extract)
                for call in (lambda: owner.walletprocesspsbt(psbt=candidate, rules=era),
                             lambda: offline.descriptorprocesspsbt(psbt=candidate, descriptors=[descriptor], rules=era)):
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
                    partial = PSBT.from_base64(owner.walletprocesspsbt(psbt=base.to_base64(), sighashtype=mode, finalize=False, rules=PRE)['psbt'])
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
                        assert_raises_rpc_error(-22, 'sighash', owner.walletprocesspsbt, psbt=value, rules=PRE)
                        assert_raises_rpc_error(-22, 'sighash', offline.descriptorprocesspsbt, psbt=value, descriptors=[descriptor], rules=PRE)
                    calls = (
                        lambda psbt, era, finalize: owner.walletprocesspsbt(psbt=psbt, sighashtype=mode, finalize=finalize, rules=era),
                        lambda psbt, era, finalize: offline.descriptorprocesspsbt(psbt=psbt, descriptors=[descriptor], sighashtype=mode, finalize=finalize, rules=era),
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
                        self.accepted(offline.finalizepsbt(psbt=replaced['psbt'], rules=POST))
                    # No key is needed to finish a valid pre-rules partial.
                    assert offline.descriptorprocesspsbt(psbt=value, descriptors=[], sighashtype=mode, rules=PRE)['complete']
                    strict = offline.descriptorprocesspsbt(psbt=value, descriptors=[], sighashtype=mode, rules=POST)
                    assert not strict['complete']
                    assert_equal(PSBT.from_base64(strict['psbt']).i[0].map[own_key], alternate)
                    assert not offline.finalizepsbt(psbt=final, rules=POST)['complete']

    def check_cleanup_and_missing(self, cases, owner):
        node, offline = self.nodes
        v1 = next(case for case in cases if case[1] == 'wsh512(pk({}))')
        _, _, _, _, descriptor, public, base, prevout, filled = v1
        # Public input/output metadata stays available before activation, without
        # invoking a signer or changing address-issuance policy.
        metadata = offline.descriptorprocesspsbt(psbt=base.to_base64(), descriptors=[public], finalize=False, rules=PRE)['psbt']
        assert_equal(PSBT.from_base64(metadata).i[0].map[PSBT_IN_WITNESS_SCRIPT].hex(), prevout['witnessScript'])
        output_base = node.createpsbt([{k: prevout[k] for k in ('txid', 'vout')}],
                                     {node.deriveaddresses(public)[0]: Decimal('0.99')})
        for result in (offline.descriptorprocesspsbt(psbt=output_base, descriptors=[public], finalize=False, rules=PRE),
                       owner.walletprocesspsbt(psbt=output_base, sign=False, finalize=False, rules=PRE)):
            output = PSBT.from_base64(result['psbt']).o[0].map
            assert_equal(output[PSBT_OUT_WITNESS_SCRIPT].hex(), prevout['witnessScript'])
        partial = owner.walletprocesspsbt(psbt=base.to_base64(), finalize=False, rules=POST)['psbt']
        with_full = PSBT.from_base64(partial)
        with_full.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = base.i[0].map[PSBT_IN_NON_WITNESS_UTXO]
        for era in (PRE, POST):
            updated = offline.utxoupdatepsbt(with_full.to_base64(), [public], era)
            fields = PSBT.from_base64(updated).i[0].map
            assert_equal(PSBT_IN_NON_WITNESS_UTXO in fields, era == PRE)
            assert PSBT_IN_WITNESS_UTXO in fields
            assert_equal(offline.finalizepsbt(psbt=updated, rules=era)['complete'], era == POST)
        for missing in (PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO):
            bad = PSBT.from_base64(partial)
            bad.i[0].map.pop(missing, None)
            assert not offline.finalizepsbt(psbt=bad.to_base64(), rules=POST)['complete']
        legacy = cases[0]
        missing_prev = PSBT.from_base64(owner.walletprocesspsbt(psbt=legacy[6].to_base64(), rules=POST)['psbt'])
        missing_prev.i[0].map.pop(PSBT_IN_NON_WITNESS_UTXO)
        missing_prev.i[0].map[PSBT_IN_WITNESS_UTXO] = CTxOut(100_000_000, bytes.fromhex(legacy[7]['scriptPubKey'])).serialize()
        assert not offline.finalizepsbt(psbt=missing_prev.to_base64(), rules=POST)['complete']
        assert 'fee' not in offline.analyzepsbt(missing_prev.to_base64(), POST)
        # V1 ALL needs every spent output, even an input not owned by this signer.
        mixed = PSBT.from_base64(node.createpsbt([{k: prevout[k] for k in ('txid', 'vout')},
                                               {k: legacy[7][k] for k in ('txid', 'vout')}],
                                              {self.destination: Decimal('1.99')}))
        mixed.i[0].map = dict(PSBT.from_base64(filled).i[0].map)
        assert not owner.walletprocesspsbt(psbt=mixed.to_base64(), rules=POST)['complete']
        mixed.i[1].map = dict(legacy[6].i[0].map)
        self.accepted(owner.walletprocesspsbt(psbt=mixed.to_base64(), rules=POST))
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
        partial = offline.descriptorprocesspsbt(psbt=base.to_base64(), descriptors=[one], finalize=False, rules=POST)
        assert not partial['complete']
        self.accepted(offline.descriptorprocesspsbt(psbt=partial['psbt'], descriptors=[two], rules=POST))
        assert owner.importdescriptors([{'desc': private, 'timestamp': 'now'}])[0]['success']
        self.accepted(owner.walletprocesspsbt(psbt=base.to_base64(), rules=POST))

    def check_mixed_eligibility(self, cases, owner):
        node, offline = self.nodes
        falcon = next(case for case in cases if case[0] == 7)
        mldsa = next(case for case in cases if case[0] == 9)
        falcon_key = bytes([PSBT_IN_PARTIAL_SIG]) + falcon[3]
        mldsa_key = bytes([PSBT_IN_PARTIAL_SIG]) + mldsa[3]
        marker = b'\xfaretained'
        self.log.info('Mixed thresholds and alternatives ignore excluded cached candidates in either key order')
        for reverse in (False, True):
            for required in (1, 2, 'alternative'):
                def descriptor(f, m):
                    keys = [m, f] if reverse else [f, m]
                    inner = f'or_i(pk({keys[0]}),pk({keys[1]}))' if required == 'alternative' else f'multi({required},{keys[0]},{keys[1]})'
                    return descsum_create(f'wsh({inner})')

                private = descriptor(falcon[2], mldsa[2])
                public = node.getdescriptorinfo(private)['descriptor']
                outpoint, previous = self.fund(node.deriveaddresses(public)[0])
                base = PSBT.from_base64(node.createpsbt([outpoint], {self.destination: Decimal('0.99')}))
                base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
                base.i[0].map[marker] = b'input'
                base.g.map[marker] = b'global'
                one = descriptor(falcon[2], mldsa[3].hex())
                two = descriptor(falcon[3].hex(), mldsa[2])
                assert owner.importdescriptors([{'desc': private, 'timestamp': 'now'}])[0]['success']
                cached = offline.descriptorprocesspsbt(psbt=base.to_base64(), descriptors=[two], finalize=False, rules=POST)['psbt']
                original = PSBT.from_base64(cached).i[0].map[mldsa_key]
                for value in (base.to_base64(), cached):
                    for finalize in (False, True):
                        for result in (
                            offline.descriptorprocesspsbt(psbt=value, descriptors=[one], finalize=finalize, rules=PRE),
                            owner.walletprocesspsbt(psbt=value, finalize=finalize, rules=PRE),
                        ):
                            parsed = PSBT.from_base64(result['psbt'])
                            fields = parsed.i[0].map
                            assert_equal(parsed.g.map[marker], b'global')
                            assert_equal(fields[marker], b'input')
                            if not finalize or required == 2:
                                assert falcon_key in fields
                                assert_equal(mldsa_key in fields, value == cached)
                                if value == cached:
                                    assert_equal(fields[mldsa_key], original)
                            finished = offline.finalizepsbt(psbt=result['psbt'], rules=PRE)
                            assert_equal(finished['complete'], required != 2)
                            if required != 2:
                                self.accepted(finished)
                            # The preserved eligible partial can finish later with
                            # the other signer under the appropriate rules.
                            self.accepted(offline.descriptorprocesspsbt(psbt=result['psbt'], descriptors=[two], rules=POST))

        self.log.info('Mixed inputs retain eligible work without creating excluded signatures')
        mixed_cases = [falcon, mldsa, next(case for case in cases if case[1] == 'wsh512(pk({}))')]
        inputs = [{k: case[7][k] for k in ('txid', 'vout')} for case in mixed_cases]
        mixed = PSBT.from_base64(node.createpsbt(inputs, {self.destination: Decimal('2.98')}))
        for index, case in enumerate(mixed_cases):
            mixed.i[index].map = dict(case[6].i[0].map)
            mixed.i[index].map[marker] = bytes([index])
        for result in (owner.walletprocesspsbt(psbt=mixed.to_base64(), finalize=False, rules=PRE),
                       offline.descriptorprocesspsbt(psbt=mixed.to_base64(), descriptors=[case[4] for case in mixed_cases], finalize=False, rules=PRE)):
            assert not result['complete']
            parsed = PSBT.from_base64(result['psbt'])
            for index, case in enumerate(mixed_cases):
                fields = parsed.i[index].map
                assert_equal(fields[marker], bytes([index]))
                assert_equal(bytes([PSBT_IN_PARTIAL_SIG]) + case[3] in fields, index == 0)
            assert not offline.finalizepsbt(psbt=result['psbt'], rules=POST)['complete']
            self.accepted(owner.walletprocesspsbt(psbt=result['psbt'], rules=POST))

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
        none = signer.walletprocesspsbt(psbt=unsigned['psbt'], sighashtype='NONE', finalize=False, rules=POST)
        assert_raises_rpc_error(-22, 'sighash', signer.walletprocesspsbt, psbt=none['psbt'], rules=POST)
        self.accepted(signer.walletprocesspsbt(psbt=none['psbt'], sighashtype='NONE', rules=POST))
        signed = signer.walletprocesspsbt(psbt=unsigned['psbt'], rules=POST)
        self.metadata(signed, POST)
        self.accepted(signed)
        signer.walletlock()
        final = offline.finalizepsbt(psbt=signed['psbt'], rules=POST)
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
