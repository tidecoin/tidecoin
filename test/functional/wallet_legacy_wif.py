#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Historical WIF bytes, key agreement, and encrypted import persistence."""

import json
import sqlite3
import subprocess
from contextlib import closing
from decimal import Decimal
from pathlib import Path

from test_framework.address import base58_to_byte, byte_to_base58
from test_framework.descriptors import descsum_create
from test_framework.messages import ser_string
from test_framework.script_util import key_to_p2wpkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair_at_index


class LegacyWIFTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [['-keypool=1', '-auxpowactivationheight=never']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_tidecoin_tx()

    def run_test(self):
        node = self.nodes[0]
        fixture = json.loads((Path(self.config['environment']['SRCDIR']) / 'src/test/data/falcon512_legacy_wif.json').read_text(encoding='utf8'))
        network = next(row for row in fixture['networks'] if row['chain'] == 'regtest')
        wif = network['wif']
        payload, prefix = base58_to_byte(wif)
        assert_equal(len(payload), 2179)
        raw_secret = bytes.fromhex(fixture['raw_secret'])
        pubkey = bytes.fromhex(fixture['pubkey'])
        assert_equal(payload, raw_secret + b'\x01' + pubkey[1:])
        modern = byte_to_base58(b'\x07' + raw_secret, prefix)
        other_wif, other_pub = generate_keypair_at_index(1, scheme='7')
        assert other_pub != pubkey

        node.createwallet('imported', blank=True, passphrase='test-passphrase')
        wallet = node.get_wallet_rpc('imported')
        wallet.walletpassphrase('test-passphrase', 60)
        control_desc = descsum_create(f'wpkh({other_wif})')
        assert wallet.importdescriptors([{'desc': control_desc, 'timestamp': 'now'}])[0]['success']
        control_addr = node.deriveaddresses(control_desc)[0]
        before = wallet.listdescriptors(private=True)

        def key_records():
            snapshot = Path(self.options.tmpdir) / 'key-records.dat'
            wallet.backupwallet(str(snapshot))
            prefixes = [ser_string(name) for name in (
                b'mkey', b'key', b'ckey', b'walletdescriptor',
                b'walletdescriptorkey', b'walletdescriptorckey',
            )]
            with closing(sqlite3.connect(snapshot)) as db:
                return {key: value for key, value in db.execute('SELECT key, value FROM main')
                        if any(key.startswith(p) for p in prefixes)}

        records_before = key_records()
        assert records_before

        self.log.info('Reject malformed and mismatched WIFs before saving descriptors or keys')
        bad_keys = {
            'other public key': raw_secret + b'\x01' + other_pub[1:],
            'inner header': raw_secret + b'\x01\x0a' + pubkey[2:],
            'coefficient': raw_secret + b'\x01' + pubkey[1:2] + b'\xff\xff' + pubkey[4:],
            'marker': raw_secret + b'\x00' + pubkey[1:],
            'truncated': payload[:-1],
            'extra byte': payload + b'\x00',
            'rc-only layout': raw_secret + b'\x01' + pubkey,
            'rc-only mismatched pair': raw_secret + b'\x01' + other_pub,
        }
        for label, data in bad_keys.items():
            self.log.debug('Checking %s', label)
            bad_wif = byte_to_base58(data, prefix)
            desc = descsum_create(f'wpkh({bad_wif})')
            result = wallet.importdescriptors([{'desc': desc, 'timestamp': 'now'}])[0]
            assert_equal(result['success'], False)
            assert_equal(result['error']['code'], -5)
            assert_equal(wallet.listdescriptors(private=True), before)
            assert_equal(key_records(), records_before)
            assert_raises_rpc_error(-5, 'Invalid private key', node.signmessagewithprivkey, bad_wif, 'WIF import test')

        self.log.info('Import old-format keys and export exact v0.18.3 bytes by address and descriptor')
        addresses = []
        for template in ('pkh({})', 'wpkh({})', 'sh(wpkh({}))'):
            desc = descsum_create(template.format(wif))
            assert wallet.importdescriptors([{'desc': desc, 'timestamp': 'now'}])[0]['success']
            address = node.deriveaddresses(desc)[0]
            addresses.append(address)
            assert_equal(node.deriveaddresses(descsum_create(template.format(modern))), [address])
            assert_equal(wallet.dumpprivkey(address), modern)
            assert_equal(wallet.dumpprivkey(address, {'format': 'legacy'}), wif)
            assert_equal(wallet.dumpprivkey(desc, {'format': 'legacy'}), wif)
        assert_equal(addresses[0], network['p2pkh'])
        message = 'Historical WIF identity'
        assert node.verifymessage(addresses[0], node.signmessagewithprivkey(wif, message), message)
        saved = wallet.listdescriptors(private=True)

        self.log.info('Correct passphrase and saved keys survive lock, unload, and daemon restart')
        wallet.walletlock()
        assert_raises_rpc_error(-14, 'incorrect', wallet.walletpassphrase, 'wrong-passphrase', 60)
        wallet.walletpassphrase('test-passphrase', 60)
        assert_equal(wallet.listdescriptors(private=True), saved)
        assert_equal(wallet.dumpprivkey(control_addr), other_wif)
        wallet.walletlock()
        node.unloadwallet('imported')
        self.restart_node(0)
        node.loadwallet('imported')
        wallet = node.get_wallet_rpc('imported')
        wallet.walletpassphrase('test-passphrase', 600)
        assert_equal(wallet.listdescriptors(private=True), saved)
        assert_equal(wallet.dumpprivkey(control_addr), other_wif)
        assert_equal(wallet.dumpprivkey(addresses[0], {'format': 'legacy'}), wif)

        self.log.info('Spend historical-key coins with wallet, direct RPC, and offline utility')
        mini = MiniWallet(node)
        self.generate(mini, 101)
        for address in addresses + [control_addr]:
            script = bytes.fromhex(wallet.getaddressinfo(address)['scriptPubKey'])
            funding = mini.send_to(from_node=node, scriptPubKey=script, amount=100_000_000)
            self.generate(mini, 1)
            inputs = [{'txid': funding['txid'], 'vout': funding['sent_vout']}]
            raw = node.createrawtransaction(inputs, {mini.get_address(): Decimal('0.99')})
            previous = [{**inputs[0], 'scriptPubKey': script.hex(), 'amount': 1}]
            if address == addresses[2]:
                previous[0]['redeemScript'] = key_to_p2wpkh_script(pubkey).hex()
            key = other_wif if address == control_addr else wif
            direct = node.signrawtransactionwithkey(raw, [key], previous)
            signed = wallet.signrawtransactionwithwallet(raw)
            assert direct['complete'] and signed['complete']
            for tx in (direct['hex'], signed['hex']):
                assert node.testmempoolaccept([tx])[0]['allowed']
            command = self.get_binaries().tx_argv() + [
                '-regtest', '-rules=pre-auxpow', '-',
                'set=privatekeys:' + json.dumps([key]),
                'set=prevtxs:' + json.dumps(previous), 'sign=ALL',
            ]
            result = subprocess.run(command, input=raw, text=True, capture_output=True, timeout=60)
            assert_equal(result.returncode, 0)
            assert_equal(result.stderr, '')
            assert node.testmempoolaccept([result.stdout.strip()])[0]['allowed']
            wallet.sendrawtransaction(signed['hex'])
            self.generate(mini, 1)


if __name__ == '__main__':
    LegacyWIFTest(__file__).main()
