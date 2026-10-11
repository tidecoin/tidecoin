#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Public PQHD resolution in existing RPCs and durable active descriptor bindings."""
from decimal import Decimal
from itertools import count

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from wallet_pqhd_seed_restrictions import records


class PQHDRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=2', '-auxpowactivationheight=4']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        source = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet('gate')
        gate = node.get_wallet_rpc('gate')
        seed = gate.listpqhdseeds()[0]['seed_id']

        def ref(seed_id, account, scheme=7, branch=0, index='*h'):
            return f'pqhd({seed_id})/10007h/6868h/{scheme}h/{account}h/{branch}h/{index}'

        def import_desc(wallet, body, **options):
            desc = descsum_create(body)
            result = wallet.importdescriptors([{'desc': desc, 'timestamp': 'now', **options}])[0]
            assert result['success'], result
            return desc

        self.log.info('Mixed-scheme active descriptors cannot bypass activation gating')
        mixed = import_desc(gate, f'wsh(multi(1,{ref(seed, 70)},{ref(seed, 71, 9)}))', range=[0, 1], active=True)
        before = gate.listdescriptors()
        assert_raises_rpc_error(-12, 'not allowed at height', gate.getnewaddress, '', 'bech32')
        assert_equal(gate.listdescriptors(), before)
        self.generate(node, 101)
        assert_equal(gate.getnewaddress('', 'bech32'), gate.deriveaddresses(mixed, [0, 0])[0])
        # An output type absent before activation can still be created on demand.
        assert gate.getnewaddress('', 'bech32pq')

        node.createwallet('resolve')
        wallet = node.get_wallet_rpc('resolve')
        node.createwallet('other')
        other = node.get_wallet_rpc('other')
        seed = wallet.listpqhdseeds()[0]['seed_id']
        desc = import_desc(wallet, f'wsh(multi(1,{ref(seed, 42)},{ref(seed, 43)}))', range=[4, 5])
        fixed = import_desc(wallet, f'wpkh({ref(seed, 44, index="7h")})')
        fixed_address = wallet.deriveaddresses(fixed)[0]
        address = wallet.deriveaddresses(desc, [4, 4])[0]
        destination = source.getnewaddress()
        txid = source.sendtoaddress(address, 1)
        self.generate(node, 1)
        transaction = source.gettransaction(txid, verbose=True)['decoded']
        vout = next(i for i, output in enumerate(transaction['vout']) if output['scriptPubKey'].get('address') == address)
        inputs = [{'txid': txid, 'vout': vout}]
        outputs = {destination: Decimal('0.999')}
        psbt = node.createpsbt(inputs, outputs)
        raw = node.createrawtransaction(inputs, outputs)
        objects = [{'desc': desc, 'range': [4, 4]}]
        wallet.encryptwallet('pass')
        wallet.walletpassphrase('pass', 60)
        wallet.walletlock()
        serial = count()

        def state():
            wallet.getwalletinfo()  # Synchronize incoming notifications before backup.
            path = node.datadir_path / f'public-resolution-{next(serial)}.dat'
            wallet.backupwallet(path)
            return wallet.listdescriptors(), wallet.listpqhdseeds(), wallet.listlockunspent(), records(path)

        self.log.info('PSBT public resolution requires the explicitly selected owning wallet')
        baseline = state()
        explicit = descsum_create(f"wpkh({wallet.getaddressinfo(fixed_address)['pubkey']})")
        for rpc in [node, wallet, other, node.get_wallet_rpc('missing')]:
            rpc.utxoupdatepsbt(psbt, [explicit])
        for method in ['utxoupdatepsbt', 'descriptorprocesspsbt']:
            assert_raises_rpc_error(-5, 'Select the owning wallet explicitly', getattr(node, method), psbt, objects)
            assert_raises_rpc_error(-5, 'not registered', getattr(other, method), psbt, objects)
            assert_raises_rpc_error(-18, 'not loaded', getattr(node.get_wallet_rpc('missing'), method), psbt, objects)
            assert_raises_rpc_error(-13, 'not cached', getattr(wallet, method), psbt, [{'desc': desc, 'range': [500, 500]}])
        updated = wallet.utxoupdatepsbt(psbt, objects)
        decoded = node.decodepsbt(updated)
        assert decoded['inputs'][0]['witness_script']
        assert 'partial_signatures' not in decoded['inputs'][0]
        processed = wallet.descriptorprocesspsbt(psbt, objects)
        assert_equal(processed['complete'], False)
        assert 'partial_signatures' not in node.decodepsbt(processed['psbt'])['inputs'][0]
        assert_equal(state(), baseline)

        self.log.info('Funding resolves public ranges and rejects failures before locking coins or reserving change')
        options = {'add_inputs': False, 'changeAddress': destination, 'fee_rate': 1,
                   'solving_data': {'descriptors': objects}}
        funded = wallet.fundrawtransaction(raw, options)
        assert funded['fee'] > 0
        assert_equal(state(), baseline)
        bad_options = {**options, 'lockUnspents': True,
                       'solving_data': {'descriptors': objects + [{'desc': desc, 'range': [500, 500]}]}}
        assert_raises_rpc_error(-13, 'not cached', wallet.fundrawtransaction, raw, bad_options)
        altered = descsum_create(desc.split('#')[0].replace('/42h/', '/99h/'))
        automatic_change = {key: value for key, value in options.items() if key != 'changeAddress'}
        assert_raises_rpc_error(-5, 'not registered', wallet.fundrawtransaction, raw,
                                {**automatic_change, 'lockUnspents': True, 'solving_data': {'descriptors': [altered]}})
        assert_raises_rpc_error(-8, 'Unable to parse descriptor', wallet.fundrawtransaction, raw,
                                {**options, 'solving_data': {'descriptors': [desc.split('#')[0]]}})
        assert_equal(state(), baseline)
        wallet.walletpassphrase('pass', 60)
        unlocked = state()
        # Fresh public derivation is permitted without changing monitoring or keypool.
        wallet.utxoupdatepsbt(psbt, [{'desc': desc, 'range': [500, 500]}])
        wallet.fundrawtransaction(raw, {**options, 'solving_data': {'descriptors': [desc]}})
        processed = wallet.descriptorprocesspsbt(psbt, objects)
        assert_equal(processed['complete'], False)
        assert 'partial_signatures' not in node.decodepsbt(processed['psbt'])['inputs'][0]
        assert_equal(state(), unlocked)
        # Wallet signing requires the explicitly signing RPC, even while unlocked.
        signed = wallet.walletprocesspsbt(updated)
        assert_equal(signed['complete'], True)
        final = node.finalizepsbt(signed['psbt'])
        node.sendrawtransaction(final['hex'])
        wallet.walletlock()

        self.log.info('Fixed mining descriptors reuse verified public cache; ranged mining stays rejected')
        assert_raises_rpc_error(-5, 'Select the owning wallet explicitly', lambda *args: self.generatetodescriptor(node, *args), 1, fixed)
        assert_raises_rpc_error(-5, 'not registered', other.generatetodescriptor, 1, fixed)
        for rpc in [wallet, node.get_wallet_rpc(self.default_wallet_name)]:
            assert_raises_rpc_error(-8, 'Ranged descriptor not accepted', rpc.generatetodescriptor, 1, desc)
            assert_raises_rpc_error(-8, 'Ranged descriptor not accepted', rpc.generateblock, desc, [])
        blockhash = wallet.generatetodescriptor(1, fixed)[0]
        assert_equal(node.getblock(blockhash, 2)['tx'][0]['vout'][0]['scriptPubKey']['address'], fixed_address)
        blockhash = wallet.generateblock(fixed, [])['hash']
        assert_equal(node.getblock(blockhash, 2)['tx'][0]['vout'][0]['scriptPubKey']['address'], fixed_address)
        wallet.unloadwallet()
        node.loadwallet('resolve')
        wallet = node.get_wallet_rpc('resolve')
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        blockhash = wallet.generatetodescriptor(1, fixed)[0]
        assert_equal(node.getblock(blockhash, 2)['tx'][0]['vout'][0]['scriptPubKey']['address'], fixed_address)
        wallet.utxoupdatepsbt(psbt, objects)

        self.log.info('Active imports control receive/change issuance through reload and policy changes')
        node.createwallet('active', passphrase='pass')
        active = node.get_wallet_rpc('active')
        active.walletpassphrase('pass', 60)
        seed = active.listpqhdseeds()[0]['seed_id']
        customs = [import_desc(active, f'wpkh({ref(seed, 80, branch=branch)})', range=[5, 8], active=True, internal=bool(branch))
                   for branch in [0, 1]]
        expected = [active.deriveaddresses(custom, [5, 8]) for custom in customs]
        for index in [0, 1, 2]:
            assert_equal(active.getnewaddress('', 'bech32'), expected[0][index])
            assert_equal(active.getrawchangeaddress('bech32'), expected[1][index])
            if index == 0:
                active.walletlock()
                active.unloadwallet()
                node.loadwallet('active')
                active = node.get_wallet_rpc('active')
                assert_equal(active.getwalletinfo()['unlocked_until'], 0)
            elif index == 1:
                self.restart_node(0)
                node.loadwallet('active')
                active = node.get_wallet_rpc('active')
                assert_equal(active.getwalletinfo()['unlocked_until'], 0)
        active.walletpassphrase('pass', 60)
        active.setpqhdpolicy('falcon512', 'falcon512')
        assert active.getnewaddress('', 'bech32') not in expected[0]
        assert active.getrawchangeaddress('bech32') not in expected[1]
        assert all(not d['active'] for d in active.listdescriptors()['descriptors'] if d['desc'] in customs)


if __name__ == '__main__':
    PQHDRPCTest(__file__).main()
