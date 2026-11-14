#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying COPYING file.
"""Legacy PSBT finals need the full previous transaction, including for fee analysis."""

from decimal import Decimal
from hashlib import sha256
from io import BytesIO

from rpc_psbt_witness_v1 import WitnessV1PSBTTest
from test_framework.descriptors import descsum_create
from test_framework.messages import CTransaction, CTxInWitness, CTxOut
from test_framework.psbt import PSBT, PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_UTXO
from test_framework.script import CScript, OP_2DROP, OP_TRUE
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class PSBTPreviousTransactionTest(WitnessV1PSBTTest):
    def add_options(self, parser):
        parser.add_argument('--preactivation', action='store_true')

    def set_test_params(self):
        super().set_test_params()
        if self.options.preactivation:
            self.extra_args = [['-keypool=1', '-auxpowactivationheight=never']] * 2

    def check_processing(self, psbt, complete):
        node, offline = self.nodes
        value = psbt.to_base64()
        for finalize in (False, True):
            result = offline.finalizepsbt(value, finalize)
            assert_equal(result['complete'], complete)
            assert_equal('hex' in result, complete and finalize)
            result = offline.descriptorprocesspsbt(psbt=value, descriptors=[], finalize=finalize)
            assert_equal(result['complete'], complete)
            assert_equal('hex' in result, complete)
        for sign in (False, True):
            result = offline.walletprocesspsbt(value, sign)
            assert_equal(result['complete'], complete)
            assert_equal('hex' in result, complete)
        if complete:
            assert node.testmempoolaccept([offline.finalizepsbt(value)['hex']])[0]['allowed']

    def run_test(self):
        node, offline = self.nodes
        self.generate(node, 201, sync_fun=self.no_op)
        destination = node.getnewaddress()
        forms = [('pkh({})', False), ('sh(pk({}))', False), ('wpkh({})', True),
                 ('sh(wpkh({}))', True), ('wsh(pk({}))', True), ('sh(wsh(pk({})))', True)]
        if not self.options.preactivation:
            forms.append(('wsh512(pk({}))', True))
        mixed = []
        for scheme in ([7] if self.options.preactivation else range(7, 12)):
            secret, _ = generate_keypair(wif=True, scheme=str(scheme))
            for template, witness in forms:
                self.log.info(f'Previous transaction for {template}, scheme {scheme}')
                descriptor = descsum_create(template.format(secret))
                outpoint, previous_bytes = self.fund(node.deriveaddresses(descriptor)[0])
                self.generate(node, 1, sync_fun=self.no_op)
                previous = CTransaction()
                previous.deserialize(BytesIO(previous_bytes))
                utxo = previous.vout[outpoint['vout']]
                base = PSBT.from_base64(node.createpsbt([outpoint], {destination: Decimal('0.995')}))
                base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous_bytes
                signed = PSBT.from_base64(offline.descriptorprocesspsbt(base.to_base64(), [descriptor])['psbt'])
                # V1 processing may drop the full record; explicitly test it too.
                signed.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous_bytes
                signed.i[0].map[PSBT_IN_WITNESS_UTXO] = utxo.serialize()
                assert PSBT_IN_REDEEM_SCRIPT not in signed.i[0].map
                self.check_processing(signed, True)

                summary = PSBT.from_base64(signed.to_base64())
                del summary.i[0].map[PSBT_IN_NON_WITNESS_UTXO]
                self.check_processing(summary, witness)
                analysis = offline.analyzepsbt(summary.to_base64())
                assert analysis['inputs'][0]['has_utxo']
                assert_equal(analysis['inputs'][0]['is_final'], witness)
                assert_equal(analysis['next'], 'extractor' if witness else 'updater')
                for field in ('fee', 'estimated_vsize', 'estimated_feerate'):
                    assert_equal(field in analysis, witness)
                if witness:
                    assert_equal(analysis['fee'], Decimal('0.005'))

                # The funding wallet knows the full transaction even when it
                # has no signing key for the recipient and the input is final.
                for sign in (False, True):
                    recovered = node.walletprocesspsbt(summary.to_base64(), sign)
                    assert recovered['complete']
                    if not witness:
                        assert_equal(PSBT.from_base64(recovered['psbt']).i[0].map[PSBT_IN_NON_WITNESS_UTXO], previous.serialize_without_witness())
                    assert_equal(node.analyzepsbt(recovered['psbt'])['fee'], Decimal('0.005'))

                false_amount = PSBT.from_base64(summary.to_base64())
                false_amount.i[0].map[PSBT_IN_WITNESS_UTXO] = CTxOut(123 * 100_000_000, utxo.scriptPubKey).serialize()
                self.check_processing(false_amount, False)
                if not witness:
                    analysis = offline.analyzepsbt(false_amount.to_base64())
                    assert 'fee' not in analysis
                    assert 'estimated_feerate' not in analysis
                    # decodepsbt is a diagnostic dump, not verification of the
                    # supplied output amounts. Its help explicitly says so.
                    assert_equal(offline.decodepsbt(false_amount.to_base64())['fee'], Decimal('122.005'))
                    assert_raises_rpc_error(-22, 'inconsistent', node.walletprocesspsbt, false_amount.to_base64(), False)
                    false_script = PSBT.from_base64(summary.to_base64())
                    # Both legacy forms have two pushes in final_script_sig.
                    # This replacement script would succeed without checking them.
                    false_script.i[0].map[PSBT_IN_WITNESS_UTXO] = CTxOut(utxo.nValue, CScript([OP_2DROP, OP_TRUE])).serialize()
                    self.check_processing(false_script, False)
                    assert 'fee' not in offline.analyzepsbt(false_script.to_base64())
                    assert_raises_rpc_error(-22, 'inconsistent', node.walletprocesspsbt, false_script.to_base64(), False)

                    # A supplied witness script cannot decide whether the wallet
                    # looks up a known previous transaction. The offline node
                    # cannot establish the actual output from this summary alone.
                    false_witness = PSBT.from_base64(summary.to_base64())
                    script = CScript([OP_TRUE])
                    false_witness.i[0].map[PSBT_IN_WITNESS_UTXO] = CTxOut(utxo.nValue, CScript([0, sha256(script).digest()])).serialize()
                    false_witness.i[0].map.pop(PSBT_IN_FINAL_SCRIPTSIG, None)
                    final_witness = CTxInWitness()
                    final_witness.scriptWitness.stack = [script]
                    false_witness.i[0].map[PSBT_IN_FINAL_SCRIPTWITNESS] = final_witness.serialize()
                    assert offline.finalizepsbt(false_witness.to_base64())['complete']
                    for sign in (False, True):
                        assert_raises_rpc_error(-22, 'inconsistent', node.walletprocesspsbt, false_witness.to_base64(), sign)

                # A verified existing nondefault final keeps its mode. The
                # default ALL processing request must not re-sign that input.
                none = PSBT.from_base64(offline.descriptorprocesspsbt(base.to_base64(), [descriptor], 'NONE')['psbt'])
                none.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous_bytes
                self.check_processing(none, True)

                if scheme == 7 and template in ('pkh({})', 'wpkh({})'):
                    mixed.append((outpoint, previous_bytes, utxo, descriptor))

        self.log.info('One legacy input without its full transaction keeps a mixed PSBT incomplete')
        base = PSBT.from_base64(node.createpsbt([item[0] for item in mixed], {destination: Decimal('1.99')}))
        for item, (_, previous_bytes, utxo, _) in zip(base.i, mixed):
            item.map[PSBT_IN_NON_WITNESS_UTXO] = previous_bytes
            item.map[PSBT_IN_WITNESS_UTXO] = utxo.serialize()
        signed = PSBT.from_base64(offline.descriptorprocesspsbt(base.to_base64(), [item[3] for item in mixed])['psbt'])
        self.check_processing(signed, True)
        del signed.i[0].map[PSBT_IN_NON_WITNESS_UTXO]
        self.check_processing(signed, False)
        assert 'fee' not in offline.analyzepsbt(signed.to_base64())
        assert node.walletprocesspsbt(signed.to_base64(), False)['complete']


if __name__ == '__main__':
    PSBTPreviousTransactionTest(__file__).main()
