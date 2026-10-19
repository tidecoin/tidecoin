#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""PQ-only external signing: enrollment, response binding, verified completion and recovery."""
import copy
import json
import sys
from decimal import Decimal
from pathlib import Path

from test_framework.descriptors import descsum_create
from test_framework.messages import CTransaction, CTxOut, CTxIn, COutPoint, from_binary
from test_framework.psbt import PSBT, PSBTMap, PSBT_GLOBAL_UNSIGNED_TX, PSBT_IN_WITNESS_UTXO, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_FINAL_SCRIPTWITNESS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair_at_index
from test_framework.script_util import key_to_p2pkh_script


class WalletSignerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        mock = Path(__file__).resolve().parent / 'mocks' / 'pq_signer.py'
        command = f'"{sys.executable}" "{mock}" --state signer_state.json'
        self.extra_args = [['-keypool=2', '-auxpowactivationheight=4'],
                           ['-keypool=2', '-auxpowactivationheight=4', f'-signer={command}']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def run_test(self):
        holder, node = self.nodes
        private = holder.get_wallet_rpc(self.default_wallet_name)
        self.generate(holder, 101)
        seed = private.listpqhdseeds()[0]['seed_id']
        # The harness also imports a fixed mining key, whose private export is
        # deliberately different. PQHD entries themselves never export seeds.
        pq_entries = lambda result: [d for d in result['descriptors'] if 'pqhd(' in d['desc']]
        assert_equal(pq_entries(private.listdescriptors(True)), pq_entries(private.listdescriptors(False)))
        state_path = Path(node.cwd) / 'signer_state.json'
        calls_path = Path(str(state_path) + '.calls')
        state = {}

        def save():
            state_path.write_text(json.dumps(state))

        def count_signs():
            return calls_path.read_text().splitlines().count('signtx')

        for scheme in (7, 8, 9, 10, 11):
            self.log.info(f'Provision finite public scripts and sign with PQ scheme {scheme}')
            wrap = lambda key: f'sh(wpkh({key}))' if scheme == 7 else f'wpkh({key})'
            branch_addresses = []
            for branch in (0, 1):
                desc = descsum_create(wrap(f'pqhd({seed})/10007h/6868h/{scheme}h/72h/{branch}h/*h'))
                assert private.importdescriptors([{'desc': desc, 'timestamp': 'now', 'range': [0, 0], 'internal': bool(branch)}])[0]['success']
                branch_addresses.append(private.deriveaddresses(desc, [0, 0])[0])
            receive, change = branch_addresses
            receive_desc = private.getaddressinfo(receive)['desc']
            change_desc = private.getaddressinfo(change)['desc']
            state.clear()
            state.update(descriptors={'receive': [receive_desc], 'internal': [change_desc]},
                         addresses={receive_desc: receive, change_desc: change})
            save()
            name = f'hww{scheme}'
            node.createwallet(wallet_name=name, disable_private_keys=True, external_signer=True)
            wallet = node.get_wallet_rpc(name)
            assert wallet.getwalletinfo()['external_signer']
            assert not wallet.getwalletinfo()['private_keys_enabled']
            assert_equal(wallet.listpqhdseeds(), [])
            assert_equal(wallet.walletdisplayaddress(receive), {'address': receive})
            # Fixed public descriptors monitor provisioned scripts; they cannot derive a pool.
            assert_raises_rpc_error(-4, 'This wallet has no available keys', wallet.getnewaddress)
            txid = private.sendtoaddress(receive, 1)
            self.generate(holder, 1)
            payment = private.gettransaction(txid, verbose=True)['decoded']
            vout = next(i for i, out in enumerate(payment['vout']) if out['scriptPubKey'].get('address') == receive)
            blank = holder.createpsbt([{'txid': txid, 'vout': vout}], {change: Decimal('0.999')})
            # Origins come from the seed holder, never from a seed copied to the external wallet.
            request = private.walletprocesspsbt(blank, False, 'ALL', False, True)['psbt']
            request = wallet.walletprocesspsbt(request, False, 'ALL', False, False)['psbt']
            signed = private.walletprocesspsbt(request, True, 'ALL', True, False)
            assert signed['complete']

            def response(value):
                state['response'] = {'psbt': value, 'complete': True}
                save()

            def reject(value):
                response(value)
                before = wallet.listdescriptors()
                assert_raises_rpc_error(-25, 'External signer failed', wallet.walletprocesspsbt, request)
                assert_equal(wallet.listdescriptors(), before)

            # Existing verified finals never cause another device request.
            response(signed['psbt'])
            before = count_signs()
            assert wallet.walletprocesspsbt(signed['psbt'])['complete']
            assert_equal(count_signs(), before)

            # Exercise all response attacks on one scheme; every scheme signs and spends below.
            if scheme == 7:
                # walletprocesspsbt(sign=true) must prepare all managers' solving
                # data, including the separate nested-witness change descriptor.
                response(private.walletprocesspsbt(blank)['psbt'])
                assert wallet.walletprocesspsbt(blank)['complete']
                self.log.info('Reject transaction substitution, protected metadata changes and invalid final scripts')
                for field in ('amount', 'script', 'sequence', 'locktime', 'input', 'version'):
                    bad = PSBT.from_base64(signed['psbt'])
                    tx = from_binary(CTransaction, bad.g.map[PSBT_GLOBAL_UNSIGNED_TX])
                    if field == 'amount':
                        tx.vout[0].nValue -= 1
                    elif field == 'script':
                        tx.vout[0].scriptPubKey = b'\x51'
                    elif field == 'sequence':
                        tx.vin[0].nSequence -= 1
                    elif field == 'locktime':
                        tx.nLockTime += 1
                    elif field == 'input':
                        tx.vin[0].prevout.n += 1
                    else:
                        tx.version += 1
                    bad.g.map[PSBT_GLOBAL_UNSIGNED_TX] = tx.serialize()
                    reject(bad.to_base64())
                for target in ('utxo', 'input_origin', 'output_origin', 'global', 'output', 'signature'):
                    bad = PSBT.from_base64(signed['psbt'])
                    if target == 'utxo':
                        value = bytearray(bad.i[0].map[PSBT_IN_WITNESS_UTXO])
                        value[0] ^= 1
                        bad.i[0].map[PSBT_IN_WITNESS_UTXO] = bytes(value)
                    elif target.endswith('origin'):
                        records = (bad.i if target.startswith('input') else bad.o)[0].map
                        key = next(k for k in records if isinstance(k, bytes) and k.startswith(b'\xfc\x08tidecoin\x01'))
                        value = bytearray(records[key])
                        value[0] ^= 1
                        records[key] = bytes(value)
                    elif target == 'global':
                        bad.g.map[b'\xaa'] = b'new metadata'
                    elif target == 'output':
                        bad.o[0].map[b'\xaa'] = b'new metadata'
                    else:
                        value = bytearray(bad.i[0].map[PSBT_IN_FINAL_SCRIPTWITNESS])
                        value[15] ^= 1
                        bad.i[0].map[PSBT_IN_FINAL_SCRIPTWITNESS] = bytes(value)
                    reject(bad.to_base64())
                    if target == 'signature':
                        assert not node.finalizepsbt(bad.to_base64())['complete']
                        assert not node.descriptorprocesspsbt(bad.to_base64(), [])['complete']
                        assert not wallet.walletprocesspsbt(bad.to_base64(), False)['complete']

                # Correct signatures with the wrong requested sighash are also rejected.
                undeclared = PSBT.from_base64(request)
                for item in undeclared.i:
                    item.map.pop(3, None)
                weak = private.walletprocesspsbt(undeclared.to_base64(), True, 'NONE', True, False)
                reject(weak['psbt'])
                response(weak['psbt'])
                before = count_signs()
                assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt, request, True, 'NONE')
                assert_equal(count_signs(), before)
                assert wallet.walletprocesspsbt(undeclared.to_base64(), True, 'NONE')['complete']
                declared_none = PSBT.from_base64(undeclared.to_base64())
                for item in declared_none.i:
                    item.map[3] = (2).to_bytes(4, 'little')
                before = count_signs()
                assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt, declared_none.to_base64())
                assert_equal(count_signs(), before)
                assert wallet.walletprocesspsbt(declared_none.to_base64(), True, 'NONE')['complete']
                no_output = PSBT.from_base64(undeclared.to_base64())
                no_output.tx.vout.clear()
                no_output.o.clear()
                no_output.g.map[PSBT_GLOBAL_UNSIGNED_TX] = no_output.tx.serialize()
                before = count_signs()
                assert_raises_rpc_error(-22, 'requires an output', wallet.walletprocesspsbt, no_output.to_base64(), True, 'SINGLE')
                assert_equal(count_signs(), before)
                # Both enrolled managers must be checked before the device is
                # called, regardless of where the conflicting input is placed.
                extra_txid = private.sendtoaddress(change, 1)
                self.generate(holder, 1)
                extra_tx = private.gettransaction(extra_txid, verbose=True)['decoded']
                extra_vout = next(i for i, out in enumerate(extra_tx['vout']) if out['scriptPubKey'].get('address') == change)
                two = holder.createpsbt([{'txid': txid, 'vout': vout}, {'txid': extra_txid, 'vout': extra_vout}], {receive: Decimal('1.999')})
                two = PSBT.from_base64(private.walletprocesspsbt(psbt=two, sign=False, finalize=False)['psbt'])
                for reverse in (False, True):
                    test = PSBT.from_base64(two.to_base64())
                    test.i[1].map[3] = (2).to_bytes(4, 'little')
                    if reverse:
                        test.tx.vin.reverse()
                        test.i.reverse()
                        test.g.map[PSBT_GLOBAL_UNSIGNED_TX] = test.tx.serialize()
                    before = count_signs()
                    assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt, test.to_base64())
                    assert_equal(count_signs(), before)

                # A foreign declaration must survive while the enrolled input
                # receives ALL, with both transaction input orders.
                _, foreign_pubkey = generate_keypair_at_index(9999, scheme='7')
                for reverse in (False, True):
                    mixed = PSBT.from_base64(undeclared.to_base64())
                    mixed.tx.vin.append(CTxIn(COutPoint(123, 0)))
                    mixed.i.append(PSBTMap({PSBT_IN_WITNESS_UTXO: CTxOut(100_000_000, key_to_p2pkh_script(foreign_pubkey)).serialize(), 3: (0x83).to_bytes(4, 'little')}))
                    if reverse:
                        mixed.tx.vin.reverse()
                        mixed.i.reverse()
                    mixed.g.map[PSBT_GLOBAL_UNSIGNED_TX] = mixed.tx.serialize()
                    expected = private.walletprocesspsbt(psbt=mixed.to_base64(), finalize=False)['psbt']
                    response(expected)
                    foreign_index, owned_index = (0, 1) if reverse else (1, 0)
                    for explicit in (False, True):
                        result = wallet.walletprocesspsbt(psbt=mixed.to_base64(), finalize=False, **({'sighashtype': 'ALL'} if explicit else {}))
                        inputs = node.decodepsbt(result['psbt'])['inputs']
                        assert_equal(inputs[foreign_index]['sighash'], 'SINGLE|ANYONECANPAY')
                        assert 'partial_signatures' not in inputs[foreign_index]
                        assert all(bytes.fromhex(sig)[-1] == 1 for sig in inputs[owned_index]['partial_signatures'].values())
                        assert 'sighash' not in inputs[owned_index]
                response(request)  # The bridge's complete=true claim is insufficient.
                assert not wallet.walletprocesspsbt(request)['complete']
                self.log.info('An unchanged signer label cannot substitute different enrolled keys')
                enrolled = copy.deepcopy(state['descriptors'])
                state['descriptors'] = {'receive': [change_desc], 'internal': [change_desc]}
                response(signed['psbt'])
                before = count_signs()
                assert_raises_rpc_error(-25, 'External signer failed', wallet.walletprocesspsbt, request)
                assert_equal(count_signs(), before)
                assert_raises_rpc_error(-1, 'enrolled public descriptor', wallet.walletdisplayaddress, receive)
                state['descriptors'] = enrolled
                state['devices'] = []
                save()
                assert_raises_rpc_error(-25, 'External signer not found', wallet.walletprocesspsbt, request)
                state.pop('devices')
                state['display_override'] = 'wrong_address'
                save()
                assert_raises_rpc_error(-1, 'Signer echoed unexpected address', wallet.walletdisplayaddress, receive)
                state.pop('display_override')
                # Finalizers can omit metadata; the host retains its original records.
                stripped = PSBT.from_base64(signed['psbt'])
                for item in stripped.i + stripped.o:
                    for key in list(item.map):
                        if isinstance(key, bytes) and key.startswith(b'\xfc'):
                            del item.map[key]
                response(stripped.to_base64())
                retained = wallet.walletprocesspsbt(request)
                decoded = node.decodepsbt(retained['psbt'])
                assert_equal(len(decoded['inputs'][0]['pqhd_origins']), 1)
                assert_equal(len(decoded['outputs'][0]['pqhd_origins']), 1)

            response(signed['psbt'])
            # Enrollment survives reopen without retaining a seed or relying on a device label.
            node.unloadwallet(name)
            node.loadwallet(name)
            wallet = node.get_wallet_rpc(name)
            result = wallet.walletprocesspsbt(request)
            assert result['complete']
            assert_equal(wallet.listpqhdseeds(), [])
            final = node.finalizepsbt(result['psbt'])
            assert final['complete']
            spend = node.sendrawtransaction(final['hex'])
            self.sync_mempools()
            self.generate(holder, 1)
            assert_equal(wallet.gettransaction(spend)['confirmations'], 1)
            if scheme == 7:
                self.log.info('Replenish finite public monitoring with another trusted fixed descriptor')
                more = descsum_create(wrap(f'pqhd({seed})/10007h/6868h/7h/72h/0h/*h'))
                # Observing the earlier payment may already have replenished the
                # seed holder's range. Preserve that larger range on reimport.
                current = next(d for d in private.listdescriptors()['descriptors'] if d['desc'] == more)
                result = private.importdescriptors([{'desc': more, 'timestamp': 'now',
                                                     'range': [0, max(1, current['range'][1])]}])[0]
                assert result['success'], result
                fresh = private.deriveaddresses(more, [1, 1])[0]
                fresh_desc = private.getaddressinfo(fresh)['desc']
                assert wallet.importdescriptors([{'desc': fresh_desc, 'timestamp': 'now', 'active': False}])[0]['success']
                state['descriptors']['receive'].append(fresh_desc)
                state['addresses'][fresh_desc] = fresh
                save()
                assert wallet.getaddressinfo(receive)['ismine']
                assert_equal(wallet.walletdisplayaddress(fresh), {'address': fresh})
                funding = private.sendtoaddress(fresh, Decimal('0.5'))
                self.generate(holder, 1)
                outputs = private.gettransaction(funding, verbose=True)['decoded']['vout']
                index = next(i for i, out in enumerate(outputs) if out['scriptPubKey'].get('address') == fresh)
                replenished = holder.createpsbt([{'txid': funding, 'vout': index}],
                                               {private.getnewaddress(): Decimal('0.499')})
                replenished = private.walletprocesspsbt(replenished, False, 'ALL', False, True)['psbt']
                replenished = wallet.walletprocesspsbt(replenished, False, 'ALL', False)['psbt']
                response(private.walletprocesspsbt(replenished)['psbt'])
                assert wallet.walletprocesspsbt(replenished)['complete']
                node.unloadwallet(name)
                node.loadwallet(name)
                wallet = node.get_wallet_rpc(name)
                result = wallet.walletprocesspsbt(replenished)
                assert result['complete']
                spend = node.sendrawtransaction(node.finalizepsbt(result['psbt'])['hex'])
                self.sync_mempools()
                self.generate(holder, 1)
                assert_equal(wallet.gettransaction(spend)['confirmations'], 1)

        self.test_signing_utxos(holder, node, state, save, count_signs)

        self.log.info('Reject ambiguous device selection')
        state['devices'] = [{'fingerprint': 'one'}, {'fingerprint': 'two'}]
        save()
        assert_raises_rpc_error(-1, 'More than one external signer found', node.createwallet,
                                wallet_name='multiple_devices', disable_private_keys=True, external_signer=True)
        state.pop('devices')
        self.log.info('Reject private and seed-dependent provisioning without creating usable wallets')
        state['descriptors'] = {'receive': [desc], 'internal': [desc]}
        save()
        assert_raises_rpc_error(-1, 'fixed public descriptors', node.createwallet,
                                wallet_name='seed_reference', disable_private_keys=True, external_signer=True)
        secret = private.dumpprivkey(receive)
        state['descriptors'] = {'receive': [descsum_create(f'wpkh({secret})')], 'internal': [change_desc]}
        save()
        assert_raises_rpc_error(-1, 'public descriptors only', node.createwallet,
                                wallet_name='private_descriptor', disable_private_keys=True, external_signer=True)

    def test_signing_utxos(self, holder, node, state, save, count_signs):
        self.log.info('External signing requires full legacy transactions before any device request')
        templates = ['pkh({})', 'sh(pk({}))', 'wpkh({})', 'sh(wpkh({}))', 'wsh512(pk({}))', 'sh(wsh512(pk({})))']
        for number, template in enumerate(templates):
            keys = [generate_keypair_at_index(9100 + 2 * number + i, scheme='7') for i in range(2)]
            secrets = [descsum_create(template.format(secret)) for secret, _ in keys]
            public = [holder.getdescriptorinfo(desc)['descriptor'] for desc in secrets]
            addresses = [holder.deriveaddresses(desc)[0] for desc in public]
            state.clear()
            state.update(descriptors={'receive': [public[0]], 'internal': [public[1]]},
                         addresses=dict(zip(public, addresses)))
            save()
            name = f'utxo_signer_{number}'
            node.createwallet(wallet_name=name, disable_private_keys=True, external_signer=True)
            wallet = node.get_wallet_rpc(name)
            # The funding transaction has never been broadcast or stored in either
            # wallet. Only the PSBT can supply it; no wallet lookup can mask the test.
            previous = CTransaction()
            previous.vin = [CTxIn(COutPoint(9000 + number, 0))]
            previous.vout = [CTxOut(100_000_000, bytes.fromhex(holder.validateaddress(address)['scriptPubKey'])) for address in addresses]
            blank = holder.createpsbt([{'txid': previous.txid_hex, 'vout': i} for i in range(2)], {addresses[0]: Decimal('1.99')})
            full = PSBT.from_base64(blank)
            for i in range(2):
                full.i[i].map[PSBT_IN_NON_WITNESS_UTXO] = previous.serialize()
                full.i[i].map[PSBT_IN_WITNESS_UTXO] = previous.vout[i].serialize()
            full = PSBT.from_base64(holder.descriptorprocesspsbt(full.to_base64(), public, 'ALL', False)['psbt'])
            legacy = number < 2
            if legacy:
                for missing in ((0,), (1,), (0, 1)):
                    for reverse in (False, True):
                        request = PSBT.from_base64(full.to_base64())
                        for index in missing:
                            del request.i[index].map[PSBT_IN_NON_WITNESS_UTXO]
                        if reverse:
                            request.tx.vin.reverse()
                            request.i.reverse()
                            request.g.map[PSBT_GLOBAL_UNSIGNED_TX] = request.tx.serialize()
                        before = count_signs()
                        assert_raises_rpc_error(-25, 'Full previous transaction required for this signing input; supply non_witness_utxo', wallet.walletprocesspsbt, request.to_base64())
                        assert_equal(count_signs(), before)
            else:
                for entry in full.i:
                    entry.map.pop(PSBT_IN_NON_WITNESS_UTXO, None)

            two_inputs = full
            # Each device response is restricted to the current manager's targets.
            # Use one target for the successful response; the two-manager cases
            # above check refusal before either manager contacts the device.
            full = PSBT.from_base64(full.to_base64())
            full.tx.vin = full.tx.vin[:1]
            full.i = full.i[:1]
            full.tx.vout[0].nValue = 99_000_000
            full.g.map[PSBT_GLOBAL_UNSIGNED_TX] = full.tx.serialize()
            for final in (False, True):
                expected = holder.descriptorprocesspsbt(full.to_base64(), secrets, 'ALL', final)
                state['response'] = {'psbt': expected['psbt']}
                save()
                before = count_signs()
                result = wallet.walletprocesspsbt(psbt=full.to_base64(), finalize=final)
                assert count_signs() > before
                if final:
                    assert result['complete']
                    # Existing verified legacy finals need not reacquire full
                    # transactions, and must not cause another signing request.
                    existing = PSBT.from_base64(result['psbt'])
                    for i, entry in enumerate(existing.i):
                        entry.map.pop(PSBT_IN_NON_WITNESS_UTXO, None)
                        entry.map[PSBT_IN_WITNESS_UTXO] = previous.vout[i].serialize()
                    before = count_signs()
                    assert wallet.walletprocesspsbt(existing.to_base64())['complete']
                    assert_equal(count_signs(), before)
                else:
                    assert all('partial_signatures' in entry for entry in node.decodepsbt(result['psbt'])['inputs'])
            if legacy:
                conflicting = PSBT.from_base64(two_inputs.to_base64())
                conflicting.i[1].map[PSBT_IN_WITNESS_UTXO] = CTxOut(1, previous.vout[1].scriptPubKey).serialize()
                before = count_signs()
                assert_raises_rpc_error(-22, 'inconsistent', wallet.walletprocesspsbt, conflicting.to_base64())
                assert_equal(count_signs(), before)


if __name__ == '__main__':
    WalletSignerTest(__file__).main()
