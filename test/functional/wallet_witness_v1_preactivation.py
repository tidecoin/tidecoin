#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native v1 issuance and spending require activation; wrapped v1 is unsupported."""
from decimal import Decimal

from test_framework.address import script_to_p2sh
from test_framework.descriptors import descsum_create
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.test_framework import BitcoinTestFramework

ACTIVATION_HEIGHT = 200


class WalletWitnessV1PreactivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2', f'-auxpowactivationheight={ACTIVATION_HEIGHT}']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet('funder')
        funder = node.get_wallet_rpc('funder')
        self.generatetoaddress(node, 110, funder.getnewaddress())
        node.createwallet('w')
        w = node.get_wallet_rpc('w')
        funder.sendtoaddress(w.getnewaddress(), 10)
        self.generate(node, 1)
        assert node.getblockcount() + 1 < ACTIVATION_HEIGHT

        self.log.info('Importing an active native-v1 descriptor succeeds with a warning')
        seed_id = w.listpqhdseeds()[0]['seed_id']
        descs = {}
        for internal in (False, True):
            desc = descsum_create(f"wsh512(pk(pqhd({seed_id})/10087h/1h/7h/0h/{int(internal)}h/*h))")
            res = w.importdescriptors([{'desc': desc, 'timestamp': 'now', 'active': True, 'internal': internal}])[0]
            assert_equal(res['success'], True)
            assert any('witness v1' in warning for warning in res['warnings'])
            descs[internal] = desc

        self.log.info('Native-v1 addresses are not issued for receive or change before activation')
        assert_raises_rpc_error(-12, 'PQ v1 outputs not allowed', w.getnewaddress, '', 'bech32pq')
        assert_raises_rpc_error(-12, 'PQ v1 outputs not allowed', w.getrawchangeaddress, 'bech32pq')
        assert_raises_rpc_error(-4, 'PQ v1 outputs not allowed', w.send,
                                {funder.getnewaddress(): 1}, options={'change_type': 'bech32pq'})

        native_v1 = w.deriveaddresses(self.registered(w, descs[False]), [0, 0])[0]
        assert_raises_rpc_error(-6, 'Cannot send to a witness v1 address', w.sendtoaddress, native_v1, 1)
        assert_raises_rpc_error(-4, 'Cannot use a witness v1 change address', w.send,
                                {funder.getnewaddress(): 1}, options={'change_address': native_v1})
        assert_raises_rpc_error(-5, 'Cannot send to a witness v1 address', w.sendall, [native_v1])

        pubkey = w.getaddressinfo(w.getnewaddress())['pubkey']
        native_desc = descsum_create(f'wsh512(pk({pubkey}))')
        wrapped_desc = descsum_create(f'sh(wsh512(pk({pubkey})))')
        self.log.info('Wrapped-v1 descriptors are rejected and decodescript does not suggest them')
        res = w.importdescriptors([{'desc': wrapped_desc, 'timestamp': 'now'}])[0]
        assert_equal(res['success'], False)
        assert 'Can only have wsh512() at top level' in res['error']['message']
        assert_raises_rpc_error(-5, 'Can only have wsh512() at top level', node.deriveaddresses, wrapped_desc)
        redeem_script = node.validateaddress(native_v1)['scriptPubKey']
        assert 'p2sh' not in node.decodescript(redeem_script)
        wrapped_v1 = script_to_p2sh(bytes.fromhex(redeem_script))
        solving_data = {'scripts': [redeem_script]}

        self.log.info('Mining RPCs refuse native witness v1 coinbase outputs before activation')
        for output in (native_v1, native_desc):
            assert_raises_rpc_error(-5, 'Witness v1 coinbase outputs are not allowed', node.generateblock,
                                    output, [], called_by_framework=True)
        assert_raises_rpc_error(-5, 'Witness v1 coinbase outputs are not allowed', node.generatetoaddress,
                                1, native_v1, called_by_framework=True)
        assert_raises_rpc_error(-5, 'Witness v1 coinbase outputs are not allowed', node.generatetodescriptor,
                                1, native_desc, called_by_framework=True)
        assert_raises_rpc_error(-5, 'Can only have wsh512() at top level', node.generatetodescriptor,
                                1, wrapped_desc, called_by_framework=True)

        self.log.info('Importing a literal native v1 output warns')
        node.createwallet('watch', disable_private_keys=True)
        watch = node.get_wallet_rpc('watch')
        for desc in (f'addr({native_v1})', f'raw({redeem_script})'):
            res = watch.importdescriptors([{'desc': descsum_create(desc), 'timestamp': 'now'}])[0]
            assert_equal(res['success'], True)
            assert any('witness v1' in warning for warning in res['warnings'])

        self.log.info('A native-v1 coin created directly in a block is not selected before activation')
        coin = next(c for c in funder.listunspent() if c['amount'] > 3)
        raw = node.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}],
                                        {native_v1: 2, funder.getnewaddress(): coin['amount'] - Decimal('2.01')})
        signed = funder.signrawtransactionwithwallet(raw)
        assert signed['complete']
        decoded = node.decoderawtransaction(signed['hex'])
        txid = decoded['txid']
        vout = next(o['n'] for o in decoded['vout'] if o['scriptPubKey'].get('address') == native_v1)
        self.generateblock(node, funder.getnewaddress(), [signed['hex']])
        assert all(u['txid'] != txid for u in w.listunspent())
        assert_raises_rpc_error(-4, 'is a witness v1 output', w.send, {funder.getnewaddress(): 1},
                                options={'inputs': [{'txid': txid, 'vout': vout}], 'add_inputs': False})
        assert_raises_rpc_error(-8, 'is a witness v1 output', w.sendall, [funder.getnewaddress()],
                                options={'inputs': [{'txid': txid, 'vout': vout}]})
        w.sendall([funder.getnewaddress()])
        self.generate(node, 1)
        assert_equal(w.listunspent(), [])

        for active in (False, True):
            if active:
                self.generate(node, ACTIVATION_HEIGHT - node.getblockcount())
            self.log.info('Known wrapped-v1 outputs remain unsupported, active=%s', active)
            assert_raises_rpc_error(-4, 'P2SH-wrapped witness v1 is not supported', funder.send,
                                    {wrapped_v1: 1}, options={'solving_data': solving_data})
            assert_raises_rpc_error(-4, 'P2SH-wrapped witness v1 is not supported', funder.send,
                                    {funder.getnewaddress(): 1}, options={'change_address': wrapped_v1, 'solving_data': solving_data})

        self.log.info('After activation, native v1 addresses and spends work')
        w.getnewaddress('', 'bech32pq')
        w.getrawchangeaddress('bech32pq')
        assert_equal([(u['txid'], u['vout']) for u in w.listunspent()], [(txid, vout)])
        spend = w.send({funder.getnewaddress(): 1}, options={'inputs': [{'txid': txid, 'vout': vout}], 'add_inputs': False,
                                                         'change_type': 'bech32pq'})
        assert_equal(spend['complete'], True)
        self.generate(node, 1)
        assert_equal(w.gettransaction(spend['txid'])['confirmations'], 1)
        w.sendtoaddress(native_v1, Decimal('0.1'))
        self.generatetoaddress(node, 1, native_v1)
        self.generatetodescriptor(node, 1, native_desc)
        self.generateblock(node, native_desc, [])

    def registered(self, wallet, desc):
        """Return the wallet's canonical form of an imported descriptor."""
        body = desc.split('#')[0]
        return next(d['desc'] for d in wallet.listdescriptors()['descriptors'] if d['desc'].split('#')[0] == body)


if __name__ == '__main__':
    WalletWitnessV1PreactivationTest(__file__).main()
