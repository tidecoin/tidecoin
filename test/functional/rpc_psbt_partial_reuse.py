#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying COPYING file.
"""Signing checks partial signatures already in a PSBT before reusing them.

A partial signature that cannot verify must not block signing or stand in for
the signer's own signature. A valid partial by one of the signer's own keys is
reused only when its mode matches the request, like a new signature.
"""

from decimal import Decimal

from rpc_psbt_witness_v1 import WitnessV1PSBTTest
from test_framework.descriptors import descsum_create
from test_framework.psbt import PSBT, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_SIGHASH_TYPE
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair

SIGHASH_ALL = 1
SIGHASH_NONE = 2


def garbage(mode):
    return bytes([0x55] * 666) + bytes([mode])


class PSBTPartialReuseTest(WitnessV1PSBTTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        node, offline = self.nodes
        self.generate(node, 201, sync_fun=self.no_op)
        destination = node.getnewaddress()
        for n, template in enumerate(['pkh({})', 'wpkh({})', 'wsh512(pk({}))', 'sh(wpkh({}))']):
            self.log.info(f'Checking {template}')
            secret, pub = generate_keypair(wif=True, scheme='7')
            _, unrelated = generate_keypair(wif=True, scheme='7')
            desc = descsum_create(template.format(secret))
            outpoint, previous = self.fund(node.deriveaddresses(desc)[0])
            base = PSBT.from_base64(node.createpsbt([outpoint], {destination: Decimal('0.995')}))
            base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
            public = node.getdescriptorinfo(desc)['descriptor']
            filled = offline.descriptorprocesspsbt(base.to_base64(), [public], 'ALL', False)['psbt']
            node.createwallet(f'owner_{n}', blank=True)
            wallet = node.get_wallet_rpc(f'owner_{n}')
            assert wallet.importdescriptors([{'desc': desc, 'timestamp': 'now'}])[0]['success']

            def sign(psbt, *mode):
                """Sign with the descriptor and the wallet, which must agree."""
                results = [offline.descriptorprocesspsbt(psbt, [desc], *mode), wallet.walletprocesspsbt(psbt, True, *mode)]
                assert_equal(results[0]['complete'], results[1]['complete'])
                return results[0]

            def assert_accepted(result):
                assert result['complete']
                assert node.testmempoolaccept([result['hex']])[0]['allowed']

            self.log.info('An own partial in another mode is not reused for an ALL request')
            none_signed = offline.descriptorprocesspsbt(filled, [desc], 'NONE', False)['psbt']
            assert_equal(PSBT.from_base64(none_signed).i[0].map[PSBT_IN_SIGHASH_TYPE], SIGHASH_NONE.to_bytes(4, 'little'))
            assert_raises_rpc_error(-22, 'sighash', offline.descriptorprocesspsbt, none_signed, [desc])
            assert_raises_rpc_error(-22, 'sighash', wallet.walletprocesspsbt, none_signed)
            # The matching explicit request finalizes it.
            assert sign(none_signed, 'NONE')['complete']
            # Finalizing honors the declaration rather than a signing request.
            assert offline.finalizepsbt(none_signed)['complete']

            self.log.info("An invalid partial for an unrelated key does not block signing")
            blocker = PSBT.from_base64(filled)
            blocker.i[0].map[b'\x02' + unrelated] = garbage(SIGHASH_NONE)
            assert_accepted(sign(blocker.to_base64()))
            # Without the key, the entry is left in place.
            kept = PSBT.from_base64(offline.descriptorprocesspsbt(blocker.to_base64(), [], 'ALL', False)['psbt'])
            assert_equal(kept.i[0].map[b'\x02' + unrelated], garbage(SIGHASH_NONE))

            self.log.info("An invalid partial for the signer's own key is replaced")
            stale = PSBT.from_base64(filled)
            stale.i[0].map[b'\x02' + pub] = garbage(SIGHASH_ALL)
            assert_accepted(sign(stale.to_base64()))
            unfinished = PSBT.from_base64(offline.descriptorprocesspsbt(stale.to_base64(), [desc], 'ALL', False)['psbt'])
            replaced = unfinished.i[0].map[b'\x02' + pub]
            assert replaced != garbage(SIGHASH_ALL) and replaced[-1] == SIGHASH_ALL
            # Without the key, the entry is left in place.
            kept = PSBT.from_base64(offline.descriptorprocesspsbt(stale.to_base64(), [], 'ALL', False)['psbt'])
            assert_equal(kept.i[0].map[b'\x02' + pub], garbage(SIGHASH_ALL))

            self.log.info('A valid partial is still reused, so finalizing needs no key')
            signed = offline.descriptorprocesspsbt(filled, [desc], 'ALL', False)['psbt']
            assert_accepted(offline.descriptorprocesspsbt(signed, []))

        self.log.info('A wallet checks every descriptor before any finalizes a cached partial')
        # Each key has its own descriptor manager. Managers are visited in an
        # unspecified order, and one without the key could finalize its input
        # first; trying each owner in turn makes every order fail without the check.
        descs = [descsum_create(f'wpkh({generate_keypair(wif=True, scheme="7")[0]})') for _ in range(4)]
        node.createwallet('multi', blank=True)
        multi = node.get_wallet_rpc('multi')
        assert all(r['success'] for r in multi.importdescriptors([{'desc': d, 'timestamp': 'now'} for d in descs]))
        for d in descs:
            outpoint, previous = self.fund(node.deriveaddresses(d)[0])
            base = PSBT.from_base64(node.createpsbt([outpoint], {destination: Decimal('0.995')}))
            base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
            none_signed = offline.descriptorprocesspsbt(base.to_base64(), [d], 'NONE', False)['psbt']
            assert_raises_rpc_error(-22, 'sighash', multi.walletprocesspsbt, none_signed)
            result = multi.walletprocesspsbt(none_signed, True, 'NONE')
            assert result['complete'] and node.testmempoolaccept([result['hex']])[0]['allowed']

        self.log.info('The same holds for keys a PQHD wallet derives from its seed')
        node.createwallet('pqhd')
        pqhd = node.get_wallet_rpc('pqhd')
        for address_type in ('legacy', 'p2sh-segwit', 'bech32', 'bech32pq'):
            for address in (pqhd.getnewaddress('', address_type), pqhd.getrawchangeaddress(address_type)):
                outpoint, previous = self.fund(address)
                base = PSBT.from_base64(node.createpsbt([outpoint], {destination: Decimal('0.995')}))
                # Signing must not depend on the asynchronous mempool notification
                # having reached this recipient wallet yet.
                base.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = previous
                none_signed = pqhd.walletprocesspsbt(base.to_base64(), True, 'NONE', False)['psbt']
                signed_input = node.decodepsbt(none_signed)['inputs'][0]
                assert_equal(signed_input['sighash'], 'NONE')
                assert_equal(len(signed_input['partial_signatures']), 1)
                assert_raises_rpc_error(-22, 'sighash', pqhd.walletprocesspsbt, none_signed)
                result = pqhd.walletprocesspsbt(none_signed, True, 'NONE')
                assert result['complete'] and node.testmempoolaccept([result['hex']])[0]['allowed']


if __name__ == '__main__':
    PSBTPartialReuseTest(__file__).main()
