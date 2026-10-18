#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Separate witness-v1 signing, finalization and commitments to spent outputs."""

from decimal import Decimal
from hashlib import sha256, sha512
from io import BytesIO
import json
import subprocess

from test_framework.address import script_to_p2sh
from test_framework.descriptors import descsum_create
from test_framework.messages import CTransaction, CTxInWitness, CTxOut
from test_framework.psbt import (
    PSBT,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT,
    PSBT_IN_WITNESS_UTXO,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class WitnessV1PSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=1', '-auxpowactivationheight=1']] * 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # The second node supplies no chain data to the descriptor signer.
        self.setup_nodes()

    def fund(self, address):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        txid = miner.sendtoaddress(address, 1)
        previous = miner.gettransaction(txid, verbose=True)
        index = next(out['n'] for out in previous['decoded']['vout'] if out['scriptPubKey'].get('address') == address)
        return {'txid': txid, 'vout': index}, bytes.fromhex(previous['hex'])

    def check_analysis(self, psbt, next_role, *, fee=Decimal('0.01'), vsize=None):
        analysis = self.nodes[1].analyzepsbt(psbt)
        assert_equal(analysis['next'], next_role)
        assert_equal(analysis['fee'], fee)
        assert analysis['estimated_vsize'] > 0
        if vsize is not None:
            assert_equal(analysis['estimated_vsize'], vsize)
        expected_feerate = Decimal(int(fee * 100_000_000) * 1000 // analysis['estimated_vsize']) / 100_000_000
        assert_equal(analysis['estimated_feerate'], expected_feerate)
        return analysis

    def check_finalization(self, scheme):
        node, offline = self.nodes
        secret, _ = generate_keypair(wif=True, scheme=str(scheme))
        for kind in ('v0', 'v1', 'wrapped_v1'):
            template = 'wsh' if kind == 'v0' else 'wsh512'
            descriptor = descsum_create(f'{template}(pk({secret}))')
            public = node.getdescriptorinfo(descriptor)['descriptor']
            address = node.deriveaddresses(public)[0]
            wrapper = bytes.fromhex(node.validateaddress(address)['scriptPubKey']) if kind == 'wrapped_v1' else None
            if wrapper is not None:
                address = script_to_p2sh(wrapper)
            outpoint, previous = self.fund(address)
            psbt = PSBT.from_base64(node.createpsbt([outpoint], {self.destination: Decimal('0.99')}))
            psbt.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
            if wrapper is not None:
                psbt.i[0].map[PSBT_IN_REDEEM_SCRIPT] = wrapper
            partial = offline.descriptorprocesspsbt(psbt=psbt.to_base64(), descriptors=[descriptor], finalize=False)['psbt']
            decoded = offline.decodepsbt(partial)['inputs'][0]
            assert 'partial_signatures' in decoded
            assert_equal('non_witness_utxo' in decoded, kind == 'v0')
            final = offline.finalizepsbt(partial)
            assert final['complete']
            assert node.testmempoolaccept([final['hex']])[0]['allowed']
            vsize = node.decoderawtransaction(final['hex'])['vsize']
            ready_analysis = self.check_analysis(partial, 'finalizer', vsize=vsize)
            assert not ready_analysis['inputs'][0]['is_final']
            finalized = offline.finalizepsbt(partial, False)['psbt']
            final_analysis = self.check_analysis(finalized, 'extractor', vsize=vsize)
            assert final_analysis['inputs'][0]['is_final']
            unsigned = PSBT.from_base64(partial)
            unsigned.i[0].map = {key: value for key, value in unsigned.i[0].map.items()
                                 if not isinstance(key, bytes) or key[0] != PSBT_IN_PARTIAL_SIG}
            self.check_analysis(unsigned.to_base64(), 'signer')
            merged = node.combinerawtransaction([final['hex'], final['hex']])
            assert node.testmempoolaccept([merged])[0]['allowed']

            prevout = dict(outpoint, amount=1, scriptPubKey=node.validateaddress(address)['scriptPubKey'],
                           witnessScript=decoded['witness_script']['hex'])
            if wrapper is not None:
                prevout['redeemScript'] = wrapper.hex()
            command = self.get_binaries().tx_argv() + ['-regtest', '-rules=post-auxpow']
            result = subprocess.run(command + [psbt.tx.serialize().hex(), 'set=privatekeys:' + json.dumps([secret]),
                                    'set=prevtxs:' + json.dumps([prevout]), 'sign=ALL'], capture_output=True, text=True)
            assert_equal(result.returncode, 0)
            assert node.testmempoolaccept([result.stdout.strip()])[0]['allowed']
            result = subprocess.run(command + ['-verify', final['hex'], 'set=prevtxs:' + json.dumps([prevout])], capture_output=True, text=True)
            assert_equal(result.returncode, 0)

            for script in (None, b'\x51'):
                bad = PSBT.from_base64(partial)
                if script is None:
                    del bad.i[0].map[PSBT_IN_WITNESS_SCRIPT]
                else:
                    bad.i[0].map[PSBT_IN_WITNESS_SCRIPT] = script
                assert not offline.finalizepsbt(bad.to_base64())['complete']
                analysis = offline.analyzepsbt(bad.to_base64())
                witness_script = bytes.fromhex(decoded['witness_script']['hex'])
                commitment = (sha256 if kind == 'v0' else sha512)(witness_script).hexdigest()
                assert_equal(analysis['inputs'][0]['missing']['witnessscript'], commitment)
                assert_equal(analysis['next'], 'updater')
                assert 'estimated_vsize' not in analysis
                assert 'estimated_feerate' not in analysis

            # Both representations must agree, before and after finalization.
            with_full = PSBT.from_base64(partial)
            with_full.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
            for source in (with_full.to_base64(), offline.finalizepsbt(with_full.to_base64(), False)['psbt']):
                for change_script in (False, True):
                    bad = PSBT.from_base64(source)
                    output = CTxOut()
                    output.deserialize(BytesIO(bad.i[0].map[PSBT_IN_WITNESS_UTXO]))
                    if change_script:
                        output.scriptPubKey = b'\x51'
                    else:
                        output.nValue -= 1
                    bad.i[0].map[PSBT_IN_WITNESS_UTXO] = output.serialize()
                    assert_raises_rpc_error(-22, 'previous output information is inconsistent', offline.decodepsbt, bad.to_base64())
                    full_only = PSBT.from_base64(source)
                    del full_only.i[0].map[PSBT_IN_WITNESS_UTXO]
                    del bad.i[0].map[PSBT_IN_NON_WITNESS_UTXO]
                    for pair in ([full_only.to_base64(), bad.to_base64()], [bad.to_base64(), full_only.to_base64()]):
                        assert_raises_rpc_error(-8, 'PSBTs not compatible', offline.combinepsbt, pair)

            updated = offline.utxoupdatepsbt(partial)
            assert_equal(PSBT.from_base64(updated).i[0].map.get(PSBT_IN_NON_WITNESS_UTXO),
                         PSBT.from_base64(partial).i[0].map.get(PSBT_IN_NON_WITNESS_UTXO))
            node.sendrawtransaction(final['hex'])

    def check_multisig(self, scheme):
        node, offline = self.nodes
        secret0, pub0 = generate_keypair(wif=True, scheme=str(scheme))
        secret1, pub1 = generate_keypair(wif=True, scheme=str(scheme))
        descriptors = [descsum_create(f'wsh512(multi(2,{secret0},{pub1.hex()}))'),
                       descsum_create(f'wsh512(multi(2,{pub0.hex()},{secret1}))')]
        for wrapped in (False, True):
            address = node.deriveaddresses(descriptors[0])[0]
            wrapper = bytes.fromhex(node.validateaddress(address)['scriptPubKey'])
            if wrapped:
                address = script_to_p2sh(wrapper)
            outpoint, previous = self.fund(address)
            psbt = PSBT.from_base64(node.createpsbt([outpoint], {self.destination: Decimal('0.99')}))
            psbt.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
            if wrapped:
                psbt.i[0].map[PSBT_IN_REDEEM_SCRIPT] = wrapper
            partials = [offline.descriptorprocesspsbt(psbt=psbt.to_base64(), descriptors=[desc], finalize=False)['psbt'] for desc in descriptors]
            for partial in partials:
                assert not offline.finalizepsbt(partial)['complete']
                self.check_analysis(partial, 'signer')
            combined = offline.combinepsbt(partials)
            final = offline.finalizepsbt(combined)
            assert final['complete']
            assert node.testmempoolaccept([final['hex']])[0]['allowed']
            vsize = node.decoderawtransaction(final['hex'])['vsize']
            self.check_analysis(combined, 'finalizer', vsize=vsize)
            self.check_analysis(offline.finalizepsbt(combined, False)['psbt'], 'extractor', vsize=vsize)
            decoded = offline.decodepsbt(partials[0])['inputs'][0]
            prevout = dict(outpoint, amount=1, scriptPubKey=node.validateaddress(address)['scriptPubKey'],
                           witnessScript=decoded['witness_script']['hex'])
            if wrapped:
                prevout['redeemScript'] = wrapper.hex()
            raw_partials = [node.signrawtransactionwithkey(psbt.tx.serialize().hex(), [secret], [prevout])
                            for secret in (secret0, secret1)]
            assert all(not part['complete'] for part in raw_partials)
            combined_raw = node.combinerawtransaction([part['hex'] for part in raw_partials])
            assert node.testmempoolaccept([combined_raw])[0]['allowed']
            node.sendrawtransaction(final['hex'])

    def check_mixed_analysis(self, scheme):
        node, offline = self.nodes
        for kinds in (('v1', 'v0'), ('wrapped_v1', 'v1')):
            descriptors, inputs, previous, wrappers = [], [], [], []
            for kind in kinds:
                secret, _ = generate_keypair(wif=True, scheme=str(scheme))
                template = 'wsh' if kind == 'v0' else 'wsh512'
                descriptor = descsum_create(f'{template}(pk({secret}))')
                address = node.deriveaddresses(descriptor)[0]
                wrapper = bytes.fromhex(node.validateaddress(address)['scriptPubKey']) if kind == 'wrapped_v1' else None
                if wrapper is not None:
                    address = script_to_p2sh(wrapper)
                outpoint, transaction = self.fund(address)
                descriptors.append(descriptor)
                inputs.append(outpoint)
                previous.append(transaction)
                wrappers.append(wrapper)
            psbt = PSBT.from_base64(node.createpsbt(inputs, {self.destination: Decimal('1.99')}))
            for index, transaction in enumerate(previous):
                psbt.i[index].map[PSBT_IN_NON_WITNESS_UTXO] = transaction
                if wrappers[index] is not None:
                    psbt.i[index].map[PSBT_IN_REDEEM_SCRIPT] = wrappers[index]
            public = [node.getdescriptorinfo(desc)['descriptor'] for desc in descriptors]
            unsigned = offline.descriptorprocesspsbt(psbt=psbt.to_base64(), descriptors=public, finalize=False)['psbt']
            self.check_analysis(unsigned, 'signer')
            mixed = offline.descriptorprocesspsbt(psbt=unsigned, descriptors=[descriptors[0]])['psbt']
            analysis = self.check_analysis(mixed, 'signer')
            assert_equal([item['is_final'] for item in analysis['inputs']], [True, False])
            signed = offline.descriptorprocesspsbt(psbt=mixed, descriptors=[descriptors[1]])['psbt']
            final = offline.finalizepsbt(signed)
            assert final['complete']
            self.check_analysis(signed, 'extractor', vsize=node.decoderawtransaction(final['hex'])['vsize'])
            assert node.testmempoolaccept([final['hex']])[0]['allowed']

            # Invalid final signatures must not be used for a size estimate.
            bad = PSBT.from_base64(mixed)
            witness = CTxInWitness()
            witness.deserialize(BytesIO(bad.i[0].map[PSBT_IN_FINAL_SCRIPTWITNESS]))
            signature = bytearray(witness.scriptWitness.stack[0])
            signature[0] ^= 1
            witness.scriptWitness.stack[0] = bytes(signature)
            bad.i[0].map[PSBT_IN_FINAL_SCRIPTWITNESS] = witness.serialize()
            analysis = offline.analyzepsbt(bad.to_base64())
            assert_equal(analysis['next'], 'updater')
            assert not analysis['inputs'][0]['is_final']
            assert 'estimated_vsize' not in analysis
            assert 'estimated_feerate' not in analysis
            node.sendrawtransaction(final['hex'])

    def check_two_signers(self, scheme):
        node = self.nodes[0]
        wallets, inputs, previous = [], [], []
        for owner in range(2):
            name = f'signer_{scheme}_{owner}'
            node.createwallet(name, blank=True)
            wallet = node.get_wallet_rpc(name)
            secret, _ = generate_keypair(wif=True, scheme=str(scheme))
            descriptor = descsum_create(f'wsh512(pk({secret}))')
            assert wallet.importdescriptors([{'desc': descriptor, 'timestamp': 'now'}])[0]['success']
            address = node.deriveaddresses(descriptor)[0]
            outpoint, transaction = self.fund(address)
            inputs.append(outpoint)
            previous.append(transaction)
            wallets.append(wallet)
        self.generate(node, 1, sync_fun=self.no_op)
        honest = PSBT.from_base64(node.createpsbt(inputs, {self.destination: Decimal('1.99')}))
        for index, transaction in enumerate(previous):
            honest.i[index].map[PSBT_IN_NON_WITNESS_UTXO] = transaction
        for wallet in wallets:
            honest = PSBT.from_base64(wallet.walletprocesspsbt(honest.to_base64(), False)['psbt'])
        assert all(PSBT_IN_NON_WITNESS_UTXO not in item.map for item in honest.i)

        # Missing other-input information must not produce an ordinary v1 signature.
        missing = PSBT.from_base64(honest.to_base64())
        missing.i[1].map.clear()
        incomplete = wallets[0].walletprocesspsbt(missing.to_base64(), True, 'ALL', False)
        assert not incomplete['complete']
        assert 'partial_signatures' not in node.decodepsbt(incomplete['psbt'])['inputs'][0]

        # Each signer sees its own true amount, but incorrect foreign data.
        for change_script in (False, True):
            finals = []
            for owner, wallet in enumerate(wallets):
                request = PSBT.from_base64(honest.to_base64())
                for item in request.i:
                    item.map.pop(PSBT_IN_NON_WITNESS_UTXO, None)
                other = 1 - owner
                output = CTxOut()
                output.deserialize(BytesIO(request.i[other].map[PSBT_IN_WITNESS_UTXO]))
                if change_script:
                    output.scriptPubKey = b'\x51'
                else:
                    output.nValue = 99_010_000
                request.i[other].map[PSBT_IN_WITNESS_UTXO] = output.serialize()
                if not change_script:
                    assert_equal(node.decodepsbt(request.to_base64())['fee'], Decimal('0.0001'))
                result = PSBT.from_base64(wallet.walletprocesspsbt(request.to_base64())['psbt'])
                finals.append(result.i[owner].map[PSBT_IN_FINAL_SCRIPTWITNESS])
            combined = PSBT.from_base64(honest.to_base64())
            raw = CTransaction(combined.tx)
            raw.wit.vtxinwit = []
            for index, witness in enumerate(finals):
                combined.i[index].map[PSBT_IN_FINAL_SCRIPTWITNESS] = witness
                parsed = CTxInWitness()
                parsed.deserialize(BytesIO(witness))
                raw.wit.vtxinwit.append(parsed)
            assert not node.finalizepsbt(combined.to_base64())['complete']
            rejected = node.testmempoolaccept([raw.serialize().hex()])[0]
            assert not rejected['allowed']
            assert 'script' in rejected.get('reject-reason', '') or 'script' in rejected.get('reject-details', '')

        # Genuine separate signing, combining and standalone finalization succeeds.
        partials = [wallet.walletprocesspsbt(honest.to_base64(), True, 'ALL', False)['psbt'] for wallet in wallets]
        combined = node.combinepsbt(partials)
        final = node.finalizepsbt(combined)
        assert final['complete']
        accepted = node.testmempoolaccept([final['hex']])[0]
        assert accepted['allowed']
        assert_equal(accepted['fees']['base'], Decimal('0.01'))
        node.sendrawtransaction(final['hex'])

    def check_multisig_foreign_data(self, scheme):
        from test_framework.psbt import PSBT_IN_FINAL_SCRIPTSIG
        node, offline = self.nodes
        for wrapped in (False, True):
            descriptors, inputs, previous = [], [], []
            for owner in range(2):
                keys = [generate_keypair(wif=True, scheme=str(scheme))[0] for _ in range(2)]
                desc = f'wsh512(multi(2,{keys[0]},{keys[1]}))'
                if wrapped:
                    desc = f'sh({desc})'
                descriptors.append(descsum_create(desc))
                outpoint, transaction = self.fund(node.deriveaddresses(descriptors[-1])[0])
                inputs.append(outpoint)
                previous.append(transaction)
            base = PSBT.from_base64(node.createpsbt(inputs, {self.destination: Decimal('0.995'), node.get_wallet_rpc(self.default_wallet_name).getnewaddress(): Decimal('0.995')}))
            for i, transaction in enumerate(previous):
                base.i[i].map[PSBT_IN_NON_WITNESS_UTXO] = transaction
            public = [node.getdescriptorinfo(desc)['descriptor'] for desc in descriptors]
            filled = offline.descriptorprocesspsbt(base.to_base64(), public, 'ALL', False)['psbt']
            for mode in ('ALL', 'NONE', 'SINGLE', 'ALL|ANYONECANPAY', 'NONE|ANYONECANPAY', 'SINGLE|ANYONECANPAY'):
                for change_script in (False, True):
                    raw = CTransaction(base.tx)
                    raw.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
                    for owner in range(2):
                        request = PSBT.from_base64(filled)
                        for item in request.i:
                            item.map.pop(PSBT_IN_NON_WITNESS_UTXO, None)
                        foreign = request.i[1 - owner]
                        output = CTxOut()
                        output.deserialize(BytesIO(foreign.map[PSBT_IN_WITNESS_UTXO]))
                        if change_script:
                            output.scriptPubKey = b'\x51'
                        else:
                            output.nValue -= 1000
                        foreign.map[PSBT_IN_WITNESS_UTXO] = output.serialize()
                        response = PSBT.from_base64(offline.descriptorprocesspsbt(request.to_base64(), [descriptors[owner]], mode)['psbt'])
                        raw.vin[owner].scriptSig = response.i[owner].map.get(PSBT_IN_FINAL_SCRIPTSIG, b'')
                        raw.wit.vtxinwit[owner].deserialize(BytesIO(response.i[owner].map[PSBT_IN_FINAL_SCRIPTWITNESS]))
                    assert_equal(node.testmempoolaccept([raw.serialize().hex()])[0]['allowed'], 'ANYONECANPAY' in mode)

    def run_test(self):
        self.generate(self.nodes[0], 201, sync_fun=self.no_op)
        self.destination = self.nodes[0].getnewaddress()
        for scheme in range(7, 12):
            self.log.info(f'Checking scheme {scheme}: finalization and separately supplied input data')
            self.check_finalization(scheme)
            self.check_multisig(scheme)
            self.check_mixed_analysis(scheme)
            self.check_two_signers(scheme)
            self.check_multisig_foreign_data(scheme)
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)


if __name__ == '__main__':
    WitnessV1PSBTTest(__file__).main()
