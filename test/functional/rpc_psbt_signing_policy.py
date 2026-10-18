#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying COPYING file.
"""Signing intent, declarations, missing amounts, and SINGLE output requirements."""

from decimal import Decimal
from hashlib import sha512
import json
import subprocess

from rpc_psbt_witness_v1 import WitnessV1PSBTTest
from test_framework.authproxy import JSONRPCException
from test_framework.descriptors import descsum_create
from test_framework.messages import tx_from_hex
from test_framework.psbt import PSBT, PSBT_GLOBAL_UNSIGNED_TX, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_SIGHASH_TYPE
from test_framework.script import CScript, OP_1, OP_CHECKSIG, SegwitV0SignatureHash
from test_framework.script_util import key_to_p2pkh_script, key_to_p2wpkh_script, script_to_p2sh_script
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair, _get_testkeys_path


class PSBTSigningPolicyTest(WitnessV1PSBTTest):
    def add_options(self, parser):
        parser.add_argument('--preactivation', action='store_true')

    def set_test_params(self):
        super().set_test_params()
        if self.options.preactivation:
            self.extra_args = [['-keypool=1', '-auxpowactivationheight=never']] * 2

    def run_test(self):
        node, offline = self.nodes
        self.generate(node, 201, sync_fun=self.no_op)
        destination = node.getnewaddress()
        other_destination = node.getnewaddress()
        templates = ['pkh({})', 'sh(pk({}))', 'wpkh({})']
        if not self.options.preactivation:
            templates += ['wsh512(pk({}))', 'sh(wsh512(pk({})))', 'wsh512(multi(1,{}))', 'sh(wsh512(multi(1,{})))']
        for template in templates:
            keys = [generate_keypair(wif=True, scheme='7') for _ in range(2)]
            descriptors = [descsum_create(template.format(secret)) for secret, _ in keys]
            public = [node.getdescriptorinfo(desc)['descriptor'] for desc in descriptors]
            outpoints, previous = zip(*(self.fund(node.deriveaddresses(desc)[0]) for desc in descriptors))
            base = PSBT.from_base64(node.createpsbt(list(outpoints), {destination: Decimal('0.995'), other_destination: Decimal('0.995')}))
            for i, transaction in enumerate(previous):
                base.i[i].map[PSBT_IN_NON_WITNESS_UTXO] = transaction
            filled = offline.descriptorprocesspsbt(base.to_base64(), public, 'ALL', False)['psbt']
            name = 'owner_' + str(templates.index(template))
            node.createwallet(name, blank=True)
            wallet = node.get_wallet_rpc(name)
            assert wallet.importdescriptors([{'desc': descriptors[1], 'timestamp': 'now'}])[0]['success']
            for mode in ('ALL', 'NONE', 'SINGLE', 'ALL|ANYONECANPAY'):
                for result in (wallet.walletprocesspsbt(filled, True, mode, False),
                               offline.descriptorprocesspsbt(filled, [descriptors[1]], mode, False)):
                    foreign_map = PSBT.from_base64(result['psbt']).i[0].map
                    assert PSBT_IN_SIGHASH_TYPE not in foreign_map
                    assert not any(isinstance(key, bytes) and key[:1] == b'\x02' for key in foreign_map)
            mixed = PSBT.from_base64(filled)
            mixed.i[0].map[PSBT_IN_SIGHASH_TYPE] = (0x83).to_bytes(4, 'little')
            for reverse in (False, True):
                request = PSBT.from_base64(mixed.to_base64())
                if reverse:
                    request.tx.vin.reverse()
                    request.i.reverse()
                    request.g.map[PSBT_GLOBAL_UNSIGNED_TX] = request.tx.serialize()
                foreign, owned = (1, 0) if reverse else (0, 1)
                for explicit in (False, True):
                    mode = {'sighashtype': 'ALL'} if explicit else {}
                    for signed in (wallet.walletprocesspsbt(request.to_base64(), finalize=False, **mode)['psbt'],
                                   offline.descriptorprocesspsbt(request.to_base64(), [descriptors[1]], finalize=False, **mode)['psbt']):
                        decoded = node.decodepsbt(signed)['inputs']
                        assert 'partial_signatures' not in decoded[foreign]
                        assert_equal(decoded[foreign]['sighash'], 'SINGLE|ANYONECANPAY')
                        assert all(bytes.fromhex(sig)[-1] == 1 for sig in decoded[owned]['partial_signatures'].values())
            # Omitted public mode preserves absent declarations; explicit ALL records them.
            updated = wallet.walletprocesspsbt(filled, False, finalize=False)['psbt']
            assert all(PSBT_IN_SIGHASH_TYPE not in item.map for item in PSBT.from_base64(updated).i)
            declared = wallet.walletprocesspsbt(filled, False, 'ALL', False)['psbt']
            assert all(item.map[PSBT_IN_SIGHASH_TYPE] == (1).to_bytes(4, 'little') for item in PSBT.from_base64(declared).i)
            assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt, mixed.to_base64(), False, 'ALL', False)
            # Separate signers' nondefault declarations survive combining, in both orders.
            for mode in ('NONE', 'SINGLE'):
                partials = [offline.descriptorprocesspsbt(filled, [desc], mode, False)['psbt'] for desc in descriptors]
                # Omitted public updates preserve declarations and signatures.
                for partial in partials:
                    updated = wallet.walletprocesspsbt(partial, False, finalize=False)['psbt']
                    before_inputs = node.decodepsbt(partial)['inputs']
                    after_inputs = node.decodepsbt(updated)['inputs']
                    for before, after in zip(before_inputs, after_inputs):
                        assert_equal(before.get('sighash'), after.get('sighash'))
                        assert_equal(before.get('partial_signatures'), after.get('partial_signatures'))
                for order in (partials, partials[::-1]):
                    combined = offline.combinepsbt(order)
                    assert offline.finalizepsbt(combined)['complete']
                    assert node.testmempoolaccept([offline.finalizepsbt(combined)['hex']])[0]['allowed']
                conflict = PSBT.from_base64(partials[0])
                conflict.i[0].map[PSBT_IN_SIGHASH_TYPE] = (1).to_bytes(4, 'little')
                assert_raises_rpc_error(-8, 'not compatible', offline.combinepsbt, [partials[0], conflict.to_base64()])
                # Both inputs have sufficient signatures, so this failure
                # specifically tests the changed declaration.
                conflict = PSBT.from_base64(offline.combinepsbt(partials))
                conflict.i[1].map[PSBT_IN_SIGHASH_TYPE] = (1).to_bytes(4, 'little')
                if 'wsh512' in template:
                    missing_scripts = PSBT.from_base64(conflict.to_base64())
                    missing_scripts.i[1].map.pop(5, None)  # witness script
                    missing_scripts.i[1].map.pop(1, None)  # witness UTXO
                    missing_scripts.i[1].map[PSBT_IN_NON_WITNESS_UTXO] = previous[1]
                    updated = PSBT.from_base64(wallet.walletprocesspsbt(missing_scripts.to_base64(), False, finalize=False)['psbt'])
                    assert 5 in updated.i[1].map and 1 in updated.i[1].map
                    assert 7 not in updated.i[1].map and 8 not in updated.i[1].map
                assert not offline.finalizepsbt(conflict.to_base64())['complete']
                assert not wallet.walletprocesspsbt(conflict.to_base64(), False)['complete']
                assert not offline.descriptorprocesspsbt(conflict.to_base64(), descriptors)['complete']
                assert_equal(offline.analyzepsbt(conflict.to_base64())['inputs'][1]['issue'], 'sighash_mismatch')
                conflict.i[1].map.pop(PSBT_IN_SIGHASH_TYPE)
                assert not offline.finalizepsbt(conflict.to_base64())['complete']
                assert not wallet.walletprocesspsbt(conflict.to_base64())['complete']
                # Explicit public declaration must check the partial byte too.
                isolated = PSBT.from_base64(conflict.to_base64())
                # Remove input 0's declaration and partials: only input 1's
                # non-ALL partial can conflict with this public ALL request.
                isolated.i[0].map.pop(PSBT_IN_SIGHASH_TYPE, None)
                for key in list(isolated.i[0].map):
                    if isinstance(key, bytes) and key[:1] == b'\x02':
                        del isolated.i[0].map[key]
                assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt, isolated.to_base64(), False, 'ALL', False)
                control = PSBT.from_base64(isolated.to_base64())
                for key in list(control.i[1].map):
                    if isinstance(key, bytes) and key[:1] == b'\x02':
                        del control.i[1].map[key]
                declared = PSBT.from_base64(wallet.walletprocesspsbt(control.to_base64(), False, 'ALL', False)['psbt'])
                assert all(item.map[PSBT_IN_SIGHASH_TYPE] == (1).to_bytes(4, 'little') for item in declared.i)
                # A visited foreign cached signature cannot authorize finalization.
                foreign = PSBT.from_base64(partials[0])
                foreign.i[0].map.pop(PSBT_IN_SIGHASH_TYPE)
                visited = wallet.walletprocesspsbt(foreign.to_base64(), finalize=False)['psbt']
                decoded = node.decodepsbt(visited)['inputs']
                assert 'final_scriptSig' not in decoded[0] and 'final_scriptwitness' not in decoded[0]
                assert 'sighash' not in decoded[0]
                assert all(bytes.fromhex(sig)[-1] == 1 for sig in decoded[1]['partial_signatures'].values())
                if 'wsh512' in template:
                    assert all('non_witness_utxo' not in row for row in node.decodepsbt(offline.combinepsbt(partials))['inputs'])
            # A target at input 1 without output 1 must not produce any signature.
            no_output = PSBT.from_base64(filled)
            no_output.tx.vout = no_output.tx.vout[:1]
            no_output.o = no_output.o[:1]
            no_output.g.map[PSBT_GLOBAL_UNSIGNED_TX] = no_output.tx.serialize()
            for mode in ('SINGLE', 'SINGLE|ANYONECANPAY'):
                assert_raises_rpc_error(-22, 'requires an output', offline.descriptorprocesspsbt, no_output.to_base64(), [descriptors[1]], mode, False)
                assert_raises_rpc_error(-22, 'requires an output', wallet.walletprocesspsbt, no_output.to_base64(), True, mode, False)
                no_output.i[1].map[PSBT_IN_SIGHASH_TYPE] = (3 if mode == 'SINGLE' else 0x83).to_bytes(4, 'little')
                analysis = offline.analyzepsbt(no_output.to_base64())
                assert_equal(analysis['inputs'][1]['issue'], 'single_without_output')
                assert_equal(analysis['next'], 'creator')
                assert 'error' not in analysis
                assert 'fee' in analysis and 'estimated_vsize' not in analysis
            # Supplied no-output partials must not become new finals, even if
            # their legacy/v0 signature would verify under consensus rules.
            for mode in (3, 0x83):
                existing = PSBT.from_base64(no_output.to_base64())
                if template == 'wpkh({})':
                    digest = SegwitV0SignatureHash(key_to_p2pkh_script(keys[1][1]), existing.tx, 1, mode, 100_000_000)
                else:
                    digest = b'\x01' + bytes(31)
                signature = bytes.fromhex(subprocess.check_output([_get_testkeys_path(), '--sign-key=' + keys[1][0], '--sign-hash=' + digest.hex()], text=True).strip()) + bytes([mode])
                existing.i[1].map[b'\x02' + keys[1][1]] = signature
                existing.i[1].map[PSBT_IN_SIGHASH_TYPE] = mode.to_bytes(4, 'little')
                assert_equal(offline.analyzepsbt(existing.to_base64())['inputs'][1]['issue'], 'single_without_output')
                for processed in (offline.finalizepsbt(existing.to_base64(), False), wallet.walletprocesspsbt(existing.to_base64(), False), offline.descriptorprocesspsbt(existing.to_base64(), [], finalize=True)):
                    input_map = PSBT.from_base64(processed['psbt']).i[1].map
                    assert 7 not in input_map and 8 not in input_map
                    assert_equal(input_map[b'\x02' + keys[1][1]], signature)
            raw = no_output.tx.serialize().hex()
            metadata = node.decodepsbt(filled)['inputs']
            prevouts = []
            for i, item in enumerate(metadata):
                tx = tx_from_hex(previous[i].hex())
                row = dict(outpoints[i], amount=1, scriptPubKey=tx.vout[outpoints[i]['vout']].scriptPubKey.hex())
                for key, field in [('redeem_script', 'redeemScript'), ('witness_script', 'witnessScript')]:
                    if key in item:
                        row[field] = item[key]['hex']
                prevouts.append(row)
            signed = offline.signrawtransactionwithkey(raw, [keys[1][0]], prevouts, 'SINGLE')
            assert 'requires an output' in next(e['error'] for e in signed['errors'] if e['vout'] == outpoints[1]['vout'] and e['txid'] == outpoints[1]['txid'])
            def input_bytes(transaction, index):
                witness = transaction.wit.vtxinwit[index].scriptWitness.stack if len(transaction.wit.vtxinwit) > index else []
                return transaction.vin[index].scriptSig, witness
            assert_equal(input_bytes(tx_from_hex(signed['hex']), 1), input_bytes(no_output.tx, 1))
            for extra_manager in (False, True):
                if extra_manager:
                    unused, _ = generate_keypair(wif=True, scheme='7')
                    assert wallet.importdescriptors([{'desc': descsum_create(f'wpkh({unused})'), 'timestamp': 'now'}])[0]['success']
                refused = wallet.signrawtransactionwithwallet(raw, prevouts, 'SINGLE')
                assert any('requires an output' in e['error'] for e in refused['errors'])
                assert_equal(input_bytes(tx_from_hex(refused['hex']), 1), input_bytes(no_output.tx, 1))
            missing_own = [prevouts[0], {k: v for k, v in prevouts[1].items() if k != 'amount'}]
            if template != 'pkh({})' and template != 'sh(pk({}))':
                try:
                    offline.signrawtransactionwithkey(raw, [keys[1][0]], missing_own, 'ALL')
                except JSONRPCException as error:
                    assert_equal(error.error['code'], -3)
                    point = outpoints[1]
                    assert_equal(error.error['message'], f"Missing amount for input 1 ({point['txid']}:{point['vout']}), scriptPubKey={prevouts[1]['scriptPubKey']}")
                else:
                    raise AssertionError('Missing amount at input 1 was accepted')
            refused = offline.signrawtransactionwithkey(raw, [keys[1][0]], missing_own, 'SINGLE')
            assert any('requires an output' in e['error'] for e in refused['errors'])
            assert_equal(input_bytes(tx_from_hex(refused['hex']), 1), input_bytes(no_output.tx, 1))
            foreign = offline.signrawtransactionwithkey(raw, [keys[0][0]], missing_own, 'SINGLE|ANYONECANPAY')
            assert not any('requires an output' in e['error'] or 'Missing amount' in e['error'] for e in foreign['errors'])
            assert_equal(input_bytes(tx_from_hex(foreign['hex']), 1), input_bytes(no_output.tx, 1))
            rules = '-rules=pre-auxpow' if self.options.preactivation else '-rules=post-auxpow'
            for verify in ([], ['-verify']):
                command = self.get_binaries().tx_argv() + ['-regtest', rules] + verify + [raw, 'set=privatekeys:' + json.dumps([keys[1][0]]), 'set=prevtxs:' + json.dumps(prevouts), 'sign=SINGLE']
                result = subprocess.run(command, capture_output=True, text=True)
                assert result.returncode != 0 and not result.stdout.strip()
                assert 'requires an output' in result.stderr, result.stderr
            foreign_command = self.get_binaries().tx_argv() + ['-regtest', rules, raw, 'set=privatekeys:' + json.dumps([keys[0][0]]), 'set=prevtxs:' + json.dumps(missing_own), 'sign=SINGLE|ANYONECANPAY']
            result = subprocess.run(foreign_command, capture_output=True, text=True)
            assert_equal(result.returncode, 0)
            assert_equal(input_bytes(tx_from_hex(result.stdout.strip()), 1), input_bytes(no_output.tx, 1))
            for byte in (0, 0xffffffff, 0x101, 4, 0x22, 0x41, 0x43):
                for partial in (False, True):
                    diagnostic = PSBT.from_base64(filled)
                    if partial:
                        diagnostic = PSBT.from_base64(offline.descriptorprocesspsbt(filled, [descriptors[1]], 'ALL', False)['psbt'])
                    diagnostic.i[1].map[PSBT_IN_SIGHASH_TYPE] = byte.to_bytes(4, 'little')
                    analysis = offline.analyzepsbt(diagnostic.to_base64())
                    assert_equal(analysis['inputs'][1]['issue'], 'unsupported_sighash')
                    assert 'fee' in analysis and 'estimated_vsize' not in analysis and 'estimated_feerate' not in analysis
                    assert 'error' not in analysis
                    assert_equal(len(analysis['inputs']), 2)
                    if not partial:
                        assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt, diagnostic.to_base64(), True, 'ALL', False)
                        assert_raises_rpc_error(-22, 'sighash', offline.descriptorprocesspsbt, diagnostic.to_base64(), [descriptors[1]], 'ALL', False)
                    else:
                        # A cached signature does not ask the creator for a new
                        # signature. It stays unfinished with its metadata intact.
                        for result in (wallet.walletprocesspsbt(diagnostic.to_base64()),
                                       offline.descriptorprocesspsbt(diagnostic.to_base64(), [descriptors[1]])):
                            after = PSBT.from_base64(result['psbt']).i[1].map
                            assert 7 not in after and 8 not in after
                            assert_equal(after[PSBT_IN_SIGHASH_TYPE], byte.to_bytes(4, 'little'))
                            for key, value in diagnostic.i[1].map.items():
                                if isinstance(key, bytes) and key[:1] == b'\x02':
                                    assert_equal(after[key], value)
            if 'wsh512' in template:
                missing = [prevouts[0], {k: v for k, v in prevouts[1].items() if k != 'amount'}]
                raw = base.tx.serialize().hex()
                ordinary = offline.signrawtransactionwithkey(raw, [keys[0][0]], missing)
                assert not tx_from_hex(ordinary['hex']).wit.vtxinwit[0].scriptWitness.stack
                assert any('Missing amount for another input' in e['error'] for e in ordinary['errors'])
                anyone = offline.signrawtransactionwithkey(raw, [keys[0][0]], missing, 'ALL|ANYONECANPAY')
                assert tx_from_hex(anyone['hex']).wit.vtxinwit[0].scriptWitness.stack
                known = node.signrawtransactionwithkey(raw, [keys[0][0]], missing)
                assert tx_from_hex(known['hex']).wit.vtxinwit[0].scriptWitness.stack
                combined = node.signrawtransactionwithkey(known['hex'], [keys[1][0]], prevouts)
                assert combined['complete']
                assert node.testmempoolaccept([combined['hex']])[0]['allowed']
                wrong = [dict(prevouts[0], amount=2), prevouts[1]]
                assert_raises_rpc_error(-22, 'amount mismatch', node.signrawtransactionwithkey, raw, [keys[0][0]], wrong)
                utility = self.get_binaries().tx_argv() + ['-regtest', rules]
                refused = subprocess.run(utility + [raw, 'set=privatekeys:' + json.dumps([keys[0][0]]), 'set=prevtxs:' + json.dumps(missing), 'sign=ALL'], capture_output=True, text=True)
                assert refused.returncode != 0 and not refused.stdout.strip()
                assert 'Missing amount' in refused.stderr
                permitted = subprocess.run(utility + [raw, 'set=privatekeys:' + json.dumps([keys[0][0]]), 'set=prevtxs:' + json.dumps(missing), 'sign=ALL|ANYONECANPAY'], capture_output=True, text=True)
                assert_equal(permitted.returncode, 0)
                assert tx_from_hex(permitted.stdout.strip()).wit.vtxinwit[0].scriptWitness.stack
                for partial_hex in (anyone['hex'], permitted.stdout.strip()):
                    finished = node.signrawtransactionwithkey(partial_hex, [keys[1][0]], prevouts)
                    assert finished['complete']
                    assert node.testmempoolaccept([finished['hex']])[0]['allowed']
                complete = subprocess.run(utility + [raw, 'set=privatekeys:' + json.dumps([key[0] for key in keys]), 'set=prevtxs:' + json.dumps(prevouts), 'sign=ALL'], capture_output=True, text=True)
                assert_equal(complete.returncode, 0)
                assert node.testmempoolaccept([complete.stdout.strip()])[0]['allowed']
                checked = subprocess.run(utility + ['-verify', complete.stdout.strip(), 'set=prevtxs:' + json.dumps(prevouts)], capture_output=True, text=True)
                assert_equal(checked.returncode, 0)
        # Synthetic maximum amounts are ordinary supplied values, not absence.
        secret, pubkey = generate_keypair(wif=True, scheme='7')
        descriptor = descsum_create(f'wpkh({secret})')
        address = node.deriveaddresses(descriptor)[0]
        outpoint, _ = self.fund(address)
        raw = offline.createrawtransaction([outpoint], {destination: Decimal('0.99')})
        previous = dict(outpoint, scriptPubKey=node.validateaddress(address)['scriptPubKey'])
        for amount in (0, Decimal('0.00000001'), Decimal('20999999.99999999'), 21000000):
            supplied = dict(previous, amount=amount)
            result = offline.signrawtransactionwithkey(raw, [secret], [supplied])
            assert result['complete']
            rules = '-rules=pre-auxpow' if self.options.preactivation else '-rules=post-auxpow'
            checked = subprocess.run(self.get_binaries().tx_argv() + ['-regtest', rules, '-verify', result['hex'], 'set=prevtxs:' + json.dumps([supplied], default=str)], capture_output=True, text=True)
            assert_equal(checked.returncode, 0)
            utility_signed = subprocess.run(self.get_binaries().tx_argv() + ['-regtest', rules, raw, 'set=prevtxs:' + json.dumps([supplied], default=str), 'set=privatekeys:' + json.dumps([secret]), 'sign=ALL'], capture_output=True, text=True)
            assert_equal(utility_signed.returncode, 0)
            checked = subprocess.run(self.get_binaries().tx_argv() + ['-regtest', rules, '-verify', utility_signed.stdout.strip(), 'set=prevtxs:' + json.dumps([supplied], default=str)], capture_output=True, text=True)
            assert_equal(checked.returncode, 0)
        try:
            offline.signrawtransactionwithkey(raw, [secret], [previous])
        except JSONRPCException as error:
            assert_equal(error.error['code'], -3)
            assert_equal(error.error['message'], f"Missing amount for input 0 ({outpoint['txid']}:{outpoint['vout']}), scriptPubKey={previous['scriptPubKey']}")
        else:
            raise AssertionError('Missing amount was accepted')
        for amount in (-1, 21000001):
            assert_raises_rpc_error(-3, 'Amount out of range', offline.signrawtransactionwithkey, raw, [secret], [dict(previous, amount=amount)])
            refused = subprocess.run(self.get_binaries().tx_argv() + ['-regtest', rules, raw, 'set=prevtxs:' + json.dumps([dict(previous, amount=amount)]), 'set=privatekeys:' + json.dumps([secret]), 'sign=ALL'], capture_output=True, text=True)
            assert refused.returncode != 0 and not refused.stdout.strip()
            assert 'out of range' in refused.stderr.lower()
        self.check_utility_boundary_amounts(destination)
        self.check_wallet_mode_refusal(destination)
        # A keyless coordinator can declare modes even without previous outputs.
        node.createwallet('coordinator', disable_private_keys=True, blank=True)
        coordinator = node.get_wallet_rpc('coordinator')
        bare = node.createpsbt(list(outpoints), {destination: Decimal('1.99')})
        public = coordinator.walletprocesspsbt(bare, False, finalize=False)['psbt']
        assert all(PSBT_IN_SIGHASH_TYPE not in item.map for item in PSBT.from_base64(public).i)
        for mode, byte in [('ALL', 1), ('NONE', 2), ('SINGLE|ANYONECANPAY', 0x83)]:
            declared = coordinator.walletprocesspsbt(bare, False, mode, False)['psbt']
            assert all(item.map[PSBT_IN_SIGHASH_TYPE] == byte.to_bytes(4, 'little') for item in PSBT.from_base64(declared).i)
            assert_equal(coordinator.walletprocesspsbt(declared, False, mode, False)['psbt'], declared)
            other_mode = 'NONE' if mode == 'ALL' else 'ALL'
            assert_raises_rpc_error(-22, 'sighash', coordinator.walletprocesspsbt, declared, False, other_mode, False)
        # Final inputs are exempt from coordinator declarations, while every
        # unfinished foreign input receives the explicit constraint.
        final = PSBT.from_base64(offline.descriptorprocesspsbt(filled, [descriptors[0]])['psbt'])
        before_final = dict(final.i[0].map)
        declared = PSBT.from_base64(coordinator.walletprocesspsbt(final.to_base64(), False, 'NONE', False)['psbt'])
        assert_equal(declared.i[0].map, before_final)
        assert_equal(declared.i[1].map[PSBT_IN_SIGHASH_TYPE], (2).to_bytes(4, 'little'))
        if not self.options.preactivation:
            self.check_multisig_targets(destination)
            self.check_foreign_pkh_amount(destination)
            self.check_wrapped_wallet_fees()
        wallet.encryptwallet('test-passphrase')
        assert all(item.map[PSBT_IN_SIGHASH_TYPE] == (2).to_bytes(4, 'little') for item in PSBT.from_base64(wallet.walletprocesspsbt(bare, False, 'NONE', False)['psbt']).i)
        self.log.info('Signing intent, declaration merging, SINGLE refusal, utility errors, and amount provenance verified')

    def check_utility_boundary_amounts(self, destination):
        offline = self.nodes[1]
        point = {'txid': '01' * 32, 'vout': 0}
        raw = offline.createrawtransaction([point], {destination: Decimal('0.99')})
        rules = '-rules=pre-auxpow' if self.options.preactivation else '-rules=post-auxpow'
        utility = self.get_binaries().tx_argv() + ['-regtest', rules]
        count = 0
        for scheme in (range(7, 8) if self.options.preactivation else range(7, 12)):
            secret, pubkey = generate_keypair(wif=True, scheme=str(scheme))
            script = CScript([pubkey, OP_CHECKSIG])
            program = CScript([OP_1, sha512(script).digest()])
            for kind in (('v0',) if self.options.preactivation else ('v0', 'v1', 'wrapped')):
                previous = dict(point)
                if kind == 'v0':
                    previous['scriptPubKey'] = key_to_p2wpkh_script(pubkey).hex()
                else:
                    previous['scriptPubKey'] = (script_to_p2sh_script(program) if kind == 'wrapped' else program).hex()
                    previous['witnessScript'] = script.hex()
                    if kind == 'wrapped':
                        previous['redeemScript'] = program.hex()
                for amount in (0, Decimal('0.00000001'), Decimal('20999999.99999999'), 21000000):
                    metadata = 'set=prevtxs:' + json.dumps([dict(previous, amount=amount)], default=str)
                    for mode in ('ALL', 'NONE', 'SINGLE', 'ALL|ANYONECANPAY', 'NONE|ANYONECANPAY', 'SINGLE|ANYONECANPAY'):
                        signed = subprocess.run(utility + [raw, metadata, 'set=privatekeys:' + json.dumps([secret]), 'sign=' + mode], capture_output=True, text=True)
                        assert_equal(signed.returncode, 0)
                        checked = subprocess.run(utility + ['-verify', signed.stdout.strip(), metadata], capture_output=True, text=True)
                        assert_equal(checked.returncode, 0)
                        count += 1
        self.log.info(f'Utility boundary amounts: {count} independently verified signatures')

    def check_wallet_mode_refusal(self, destination):
        node, offline = self.nodes
        keys = [generate_keypair(wif=True, scheme='7') for _ in range(2)]
        descriptors = [descsum_create(f'wpkh({secret})') for secret, _ in keys]
        points, previous = zip(*(self.fund(node.deriveaddresses(d)[0]) for d in descriptors))
        node.createwallet('two_owned_modes', blank=True)
        wallet = node.get_wallet_rpc('two_owned_modes')
        assert all(row['success'] for row in wallet.importdescriptors([{'desc': d, 'timestamp': 'now'} for d in descriptors]))
        request = PSBT.from_base64(node.createpsbt(list(points), {destination: Decimal('1.99')}))
        for i, tx in enumerate(previous):
            request.i[i].map[PSBT_IN_NON_WITNESS_UTXO] = tx
        request.i[0].map[PSBT_IN_SIGHASH_TYPE] = (1).to_bytes(4, 'little')
        request.i[1].map[PSBT_IN_SIGHASH_TYPE] = (2).to_bytes(4, 'little')
        for reverse in (False, True):
            if reverse:
                request.tx.vin.reverse()
                request.i.reverse()
                request.g.map[PSBT_GLOBAL_UNSIGNED_TX] = request.tx.serialize()
            for mode in ('ALL', 'NONE'):
                assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt, request.to_base64(), True, mode, False)
        # The RPC returns an error, never a partially updated PSBT. The unit
        # test additionally compares the caller's in-memory object byte for byte.
        for item in request.i:
            item.map[PSBT_IN_SIGHASH_TYPE] = (1).to_bytes(4, 'little')
        assert wallet.walletprocesspsbt(request.to_base64())['complete']

    def check_multisig_targets(self, destination):
        node, offline = self.nodes
        keys = [generate_keypair(wif=True, scheme='7') for _ in range(4)]
        public = [descsum_create(f'wsh512(multi(2,{keys[i][1].hex()},{keys[i + 1][1].hex()}))') for i in (0, 2)]
        owned = descsum_create(f'wsh512(multi(2,{keys[2][0]},{keys[3][1].hex()}))')
        points, previous = zip(*(self.fund(node.deriveaddresses(d)[0]) for d in public))
        base = PSBT.from_base64(node.createpsbt(list(points), {destination: Decimal('1.99')}))
        for i, transaction in enumerate(previous):
            base.i[i].map[PSBT_IN_NON_WITNESS_UTXO] = transaction
        base = PSBT.from_base64(offline.descriptorprocesspsbt(base.to_base64(), public, finalize=False)['psbt'])
        base.i[0].map[PSBT_IN_SIGHASH_TYPE] = (0x83).to_bytes(4, 'little')
        for fallback in (False, True):
            name = 'multisig_fallback' if fallback else 'multisig_managers'
            node.createwallet(name, blank=True)
            wallet = node.get_wallet_rpc(name)
            descriptor = descsum_create(f'pk({keys[2][0]})') if fallback else owned
            # Separate unrelated manager checks iteration as well as the
            # provider lookup for a key enrolled under another output script.
            extra, _ = generate_keypair(wif=True, scheme='7')
            assert all(row['success'] for row in wallet.importdescriptors([{'desc': descriptor, 'timestamp': 'now'}, {'desc': descsum_create(f'wpkh({extra})'), 'timestamp': 'now'}]))
            for reverse in (False, True):
                request = PSBT.from_base64(base.to_base64())
                if reverse:
                    request.tx.vin.reverse()
                    request.i.reverse()
                    request.g.map[PSBT_GLOBAL_UNSIGNED_TX] = request.tx.serialize()
                foreign, target = (1, 0) if reverse else (0, 1)
                for explicit in (False, True):
                    options = {'sighashtype': 'ALL'} if explicit else {}
                    result = wallet.walletprocesspsbt(request.to_base64(), finalize=False, **options)
                    assert not result['complete']
                    inputs = node.decodepsbt(result['psbt'])['inputs']
                    assert_equal(inputs[foreign]['sighash'], 'SINGLE|ANYONECANPAY')
                    assert 'partial_signatures' not in inputs[foreign]
                    assert_equal(list(inputs[target]['partial_signatures']), [keys[2][1].hex()])
                    assert_equal(bytes.fromhex(inputs[target]['partial_signatures'][keys[2][1].hex()])[-1], 1)
                    assert 'sighash' not in inputs[target]

    def check_foreign_pkh_amount(self, destination):
        node, offline = self.nodes
        keys = [generate_keypair(wif=True, scheme='7') for _ in range(2)]
        for wrapper in ('wsh512(pk({}))', 'sh(wsh512(pk({})))'):
            descriptors = [descsum_create(wrapper.format(keys[0][0])), descsum_create(f'pkh({keys[1][0]})')]
            points, previous = zip(*(self.fund(node.deriveaddresses(d)[0]) for d in descriptors))
            base = PSBT.from_base64(node.createpsbt(list(points), {destination: Decimal('1.99')}))
            for i, transaction in enumerate(previous):
                base.i[i].map[PSBT_IN_NON_WITNESS_UTXO] = transaction
            filled = offline.descriptorprocesspsbt(base.to_base64(), [node.getdescriptorinfo(d)['descriptor'] for d in descriptors], finalize=False)['psbt']
            inputs = node.decodepsbt(filled)['inputs']
            supplied = []
            for i in range(2):
                row = dict(points[i], amount=1, scriptPubKey=tx_from_hex(previous[i].hex()).vout[points[i]['vout']].scriptPubKey.hex())
                for key, field in [('redeem_script', 'redeemScript'), ('witness_script', 'witnessScript')]:
                    if key in inputs[i]:
                        row[field] = inputs[i][key]['hex']
                supplied.append(row)
            missing = [supplied[0], {k: v for k, v in supplied[1].items() if k != 'amount'}]
            raw = base.tx.serialize().hex()
            refused = offline.signrawtransactionwithkey(raw, [keys[0][0]], missing)
            witness = tx_from_hex(refused['hex']).wit.vtxinwit
            assert not witness or not witness[0].scriptWitness.stack
            assert any('Missing amount for another input' in e['error'] for e in refused['errors'])
            utility = self.get_binaries().tx_argv() + ['-regtest', '-rules=post-auxpow']
            result = subprocess.run(utility + [raw, 'set=privatekeys:' + json.dumps([keys[0][0]]), 'set=prevtxs:' + json.dumps(missing), 'sign=ALL'], capture_output=True, text=True)
            assert result.returncode != 0 and not result.stdout.strip()
            assert f"Missing amount for input 1 ({points[1]['txid']}:{points[1]['vout']})" in result.stderr
            for rpc in (node, offline):
                signed = rpc.signrawtransactionwithkey(raw, [key[0] for key in keys], missing if rpc is node else supplied)
                assert signed['complete']
                assert node.testmempoolaccept([signed['hex']])[0]['allowed']
                checked = subprocess.run(utility + ['-verify', signed['hex'], 'set=prevtxs:' + json.dumps(supplied)], capture_output=True, text=True)
                assert_equal(checked.returncode, 0)

    def check_wrapped_wallet_fees(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        for scheme in ('7', '9'):
            for index, template in enumerate(('wsh512(pk({}))', 'sh(wsh512(pk({})))', 'sh(wsh512(multi(1,{})))')):
                secret, _ = generate_keypair(wif=True, scheme=scheme)
                descriptor = descsum_create(template.format(secret))
                name = f'fee_{scheme}_{index}'
                node.createwallet(name, blank=True)
                wallet = node.get_wallet_rpc(name)
                assert wallet.importdescriptors([{'desc': descriptor, 'timestamp': 'now'}])[0]['success']
                address = node.deriveaddresses(descriptor)[0]
                self.fund(address)
                self.generate(node, 1, sync_fun=self.no_op)
                result = wallet.send(outputs=[{miner.getnewaddress(): Decimal('0.5')}], options={'fee_rate': 10, 'add_to_wallet': False, 'change_address': miner.getnewaddress()})
                tx = node.decoderawtransaction(result['hex'])
                accepted = node.testmempoolaccept([result['hex']])[0]
                assert accepted['allowed']
                # Construct the wallet's fixed signature-size estimate
                # independently, retaining the actual native/wrapped scriptSig.
                estimated_tx = tx_from_hex(result['hex'])
                signature_index = 1 if 'multi' in template else 0
                estimated_tx.wit.vtxinwit[0].scriptWitness.stack[signature_index] = bytes(667 if scheme == '7' else 2421)
                estimate = estimated_tx.get_vsize()
                assert_equal(int(accepted['fees']['base'] * 100_000_000 / 10), estimate)
                assert estimate >= tx['vsize']
                coins = wallet.listunspent()
                assert coins
                assert all(item['solvable'] and item['spendable'] for item in coins)


if __name__ == '__main__':
    PSBTSigningPolicyTest(__file__).main()
