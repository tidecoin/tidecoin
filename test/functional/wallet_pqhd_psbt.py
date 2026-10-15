#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Public PQHD PSBT updates, per-key origins and explicit conflict rejection."""
from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.psbt import PSBT
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class PQHDPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2', '-auxpowactivationheight=4']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 101)
        node.createwallet('origins')
        wallet = node.get_wallet_rpc('origins')
        seed = wallet.listpqhdseeds()[0]['seed_id']
        ref = lambda scheme, account: f'pqhd({seed})/10007h/6868h/{scheme}h/{account}h/0h/*h'
        desc = descsum_create(f'wsh(multi(2,{ref(7, 42)},{ref(9, 43)}))')
        assert wallet.importdescriptors([{'desc': desc, 'timestamp': 'now', 'range': [0, 2]}])[0]['success']
        address, destination = wallet.deriveaddresses(desc, [0, 1])
        txid = miner.sendtoaddress(address, 1)
        self.generate(node, 1)
        payment = miner.gettransaction(txid, verbose=True)['decoded']
        vout = next(i for i, out in enumerate(payment['vout']) if out['scriptPubKey'].get('address') == address)
        blank = node.createpsbt([{'txid': txid, 'vout': vout}], {destination: Decimal('0.999')})

        def update(psbt, origins=False):
            return wallet.walletprocesspsbt(psbt, False, 'ALL', False, origins)['psbt']

        self.log.info('Default public updates preserve privacy; opt-in emits each multikey origin')
        private = node.decodepsbt(update(blank))
        for item in private['inputs'] + private['outputs']:
            assert 'pqhd_origins' not in item
            assert 'partial_signatures' not in item
        public = update(blank, True)
        decoded = node.decodepsbt(public)
        for index, item in enumerate(decoded['inputs'] + decoded['outputs']):
            origins = item['pqhd_origins']
            assert_equal(len(origins), 2)
            assert_equal({origin['seed_id'] for origin in origins}, {seed})
            assert_equal({origin['path'].replace("'", 'h') for origin in origins},
                         {f'm/10007h/6868h/7h/42h/0h/{index}h', f'm/10007h/6868h/9h/43h/0h/{index}h'})
            assert 'partial_signatures' not in item
        assert_equal(update(public, True), public)
        assert_equal(update(public, False), public)
        assert_equal(node.combinepsbt([public, public]), public)

        self.log.info('Reloaded locked cache supplies the same public metadata and rejects conflicting origins')
        wallet.encryptwallet('pass')
        wallet.unloadwallet()
        node.loadwallet('origins')
        wallet = node.get_wallet_rpc('origins')
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        state = wallet.listdescriptors()
        assert_equal(update(blank, True), public)
        assert_equal(wallet.listdescriptors(), state)
        for output in (False, True):
            for change_seed in (False, True):
                modified = PSBT.from_base64(public)
                records = (modified.o if output else modified.i)[0].map
                origin_key = next(key for key in records if isinstance(key, bytes) and key.startswith(b'\xfc\x08tidecoin\x01'))
                value = bytearray(records[origin_key])
                value[0 if change_seed else -4] ^= 1
                records[origin_key] = bytes(value)
                conflicting = modified.to_base64()
                for opt_in in (False, True):
                    assert_raises_rpc_error(-22, 'PQHD origin conflicts with wallet metadata', update, conflicting, opt_in)
                assert_raises_rpc_error(-8, 'PSBTs not compatible (different transactions, previous outputs or PQHD origins)', node.combinepsbt, [public, conflicting])
                assert_equal(wallet.listdescriptors(), state)
        # Malformed origin values are rejected by combination as well.
        malformed = PSBT.from_base64(public)
        key = next(key for key in malformed.i[0].map if isinstance(key, bytes) and key.startswith(b'\xfc\x08tidecoin\x01'))
        malformed.i[0].map[key] = b'bad'
        assert_raises_rpc_error(-8, 'PSBTs not compatible (different transactions, previous outputs or PQHD origins)', node.combinepsbt, [malformed.to_base64()])

        self.log.info('Successful signing still spends the mixed-scheme script after rejected updates')
        wallet.walletpassphrase('pass', 60)
        signed = wallet.walletprocesspsbt(public)
        assert signed['complete']
        # Finalization must not bypass the origin check for a locally resolved
        # input, even though no further private-key work is needed for it.
        finalized_conflict = PSBT.from_base64(signed['psbt'])
        records = finalized_conflict.i[0].map
        key = next(key for key in records if isinstance(key, bytes) and key.startswith(b'\xfc\x08tidecoin\x01'))
        value = bytearray(records[key])
        value[0] ^= 1
        records[key] = bytes(value)
        for opt_in in (False, True):
            assert_raises_rpc_error(-22, 'PQHD origin conflicts with wallet metadata', update,
                                    finalized_conflict.to_base64(), opt_in)
        final = node.finalizepsbt(signed['psbt'])
        assert final['complete']
        spend = node.sendrawtransaction(final['hex'])
        self.generate(node, 1)
        assert_equal(wallet.gettransaction(spend)['confirmations'], 1)


if __name__ == '__main__':
    PQHDPSBTTest(__file__).main()
