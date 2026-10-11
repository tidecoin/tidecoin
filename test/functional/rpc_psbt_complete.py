#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""PSBT completeness verifies every PQ input under the current activation flags."""
from io import BytesIO

from test_framework.descriptors import descsum_create
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, COIN
from test_framework.psbt import PSBT, PSBT_GLOBAL_UNSIGNED_TX, PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_IN_NON_WITNESS_UTXO
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class PSBTCompletenessTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=1', '-auxpowactivationheight=4']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def make_psbt(self, descriptor):
        node = self.nodes[0]
        address = node.deriveaddresses(descriptor)[0]
        script = bytes.fromhex(node.validateaddress(address)['scriptPubKey'])
        # Synthetic previous transactions isolate completeness from mempool
        # admission; the PSBT includes the full previous transaction for each input.
        previous = CTransaction()
        previous.vin = [CTxIn(COutPoint(1, 0))]
        previous.vout = [CTxOut(COIN, script), CTxOut(COIN, script)]
        unsigned = node.createpsbt([{'txid': previous.txid_hex, 'vout': i} for i in range(2)], {address: 1.99})
        psbt = PSBT.from_base64(unsigned)
        for item in psbt.i:
            item.map[PSBT_IN_NON_WITNESS_UTXO] = previous.serialize()
        return psbt.to_base64()

    def check_complete(self, value, expected):
        node = self.nodes[0]
        for finalize in (False, True):
            result = node.descriptorprocesspsbt(psbt=value, descriptors=[], finalize=finalize)
            assert_equal(result['complete'], expected)
            assert_equal('hex' in result, expected)
        result = node.finalizepsbt(value)
        assert_equal(result['complete'], expected)
        assert_equal('hex' in result, expected)

    def run_test(self):
        node = self.nodes[0]
        blocks = self.generate(node, 3)  # next block activates strict PQ / witness v1
        for scheme in range(7, 12):
            self.log.info(f'All inputs must verify for scheme {scheme}')
            private, _ = generate_keypair(wif=True, scheme=str(scheme))
            descriptor = descsum_create(f'wpkh({private})')
            blank = self.make_psbt(descriptor)
            self.check_complete(blank, False)
            partial = node.descriptorprocesspsbt(psbt=blank, descriptors=[descriptor], finalize=False)
            assert_equal(partial['complete'], False)
            assert 'hex' not in partial
            signed = node.descriptorprocesspsbt(psbt=blank, descriptors=[descriptor])
            assert_equal(signed['complete'], True)
            self.check_complete(signed['psbt'], True)

            missing = PSBT.from_base64(signed['psbt'])
            del missing.i[1].map[PSBT_IN_FINAL_SCRIPTWITNESS]
            self.check_complete(missing.to_base64(), False)
            for index in range(2):
                for malformed in (False, True):
                    bad = PSBT.from_base64(signed['psbt'])
                    witness = CTxInWitness()
                    witness.deserialize(BytesIO(bad.i[index].map[PSBT_IN_FINAL_SCRIPTWITNESS]))
                    signature = bytearray(witness.scriptWitness.stack[0])
                    if malformed:
                        witness.scriptWitness.stack[0] = b'\x01'
                    else:
                        signature[len(signature) // 2] ^= 1
                        witness.scriptWitness.stack[0] = bytes(signature)
                    bad.i[index].map[PSBT_IN_FINAL_SCRIPTWITNESS] = witness.serialize()
                    self.check_complete(bad.to_base64(), False)
            changed = PSBT.from_base64(signed['psbt'])
            changed.tx.vout[0].nValue -= 1
            changed.g.map[PSBT_GLOBAL_UNSIGNED_TX] = changed.tx.serialize()
            self.check_complete(changed.to_base64(), False)

        self.log.info('Finalized witness-v1 PSBTs respect activation and reorgs')
        private, _ = generate_keypair(wif=True, scheme='7')
        descriptor = descsum_create(f'wsh512(pk({private}))')
        blank = self.make_psbt(descriptor)
        signed = node.descriptorprocesspsbt(psbt=blank, descriptors=[descriptor])
        assert_equal(signed['complete'], True)
        self.check_complete(signed['psbt'], True)
        node.invalidateblock(blocks[-1])
        assert_equal(node.getblockcount(), 2)
        self.check_complete(signed['psbt'], False)
        node.reconsiderblock(blocks[-1])
        assert_equal(node.getblockcount(), 3)
        self.check_complete(signed['psbt'], True)
        assert_raises_rpc_error(-22, 'decode', node.descriptorprocesspsbt, psbt='not a psbt', descriptors=[])


if __name__ == '__main__':
    PSBTCompletenessTest(__file__).main()
