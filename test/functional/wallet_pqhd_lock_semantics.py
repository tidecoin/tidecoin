#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify PQHD seed lock semantics for descriptor address derivation."""

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import WalletUnlock


def pubkey_scheme_prefix(wallet, address):
    info = wallet.getaddressinfo(address)
    assert "pubkey" in info
    return int(info["pubkey"][:2], 16)


class WalletPQHDLockSemanticsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Keep keypool tiny so exhaustion (and thus derivation attempts) is deterministic.
        self.extra_args = [["-keypool=1", "-auxpowactivationheight=4"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        wallet_name = "pqhdlock"
        self.nodes[0].createwallet(wallet_name=wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)

        self.log.info("Address metadata exposes PQHD origin")
        first_addr = wallet.getnewaddress("", "bech32")
        first_info = wallet.getaddressinfo(first_addr)
        assert "pqhd_seedid" in first_info
        assert "pqhd_path" in first_info

        self.log.info("Encrypt wallet, then refill exactly one key per pool")
        wallet.encryptwallet("pass")
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
        with WalletUnlock(wallet, "pass"):
            wallet.keypoolrefill(1)

        self.log.info("Consume one external and one internal key while wallet is locked")
        ext_locked = wallet.getnewaddress("", "bech32")
        chg_locked = wallet.getrawchangeaddress("bech32")
        assert_equal(pubkey_scheme_prefix(wallet, ext_locked), 0x07)
        assert_equal(pubkey_scheme_prefix(wallet, chg_locked), 0x07)

        self.log.info("With depleted keypool, locked wallet cannot derive new PQHD addresses")
        assert_raises_rpc_error(-12, "Keypool ran out", wallet.getnewaddress, "", "bech32")
        assert_raises_rpc_error(-12, "Keypool ran out", wallet.getrawchangeaddress, "bech32")

        self.log.info("Unlock restores PQHD seed availability; derivation works again")
        with WalletUnlock(wallet, "pass"):
            wallet.keypoolrefill(1)
            ext_unlocked = wallet.getnewaddress("", "bech32")
            chg_unlocked = wallet.getrawchangeaddress("bech32")
            assert_equal(pubkey_scheme_prefix(wallet, ext_unlocked), 0x07)
            assert_equal(pubkey_scheme_prefix(wallet, chg_unlocked), 0x07)
            assert ext_unlocked != ext_locked
            assert chg_unlocked != chg_locked

        self.check_reloaded_caches()

    def check_reloaded_caches(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generate(node, 101)
        fixtures = []
        for scheme in range(7, 12):
            name = f'cache-{scheme}'
            node.createwallet(name, passphrase='pass')
            wallet = node.get_wallet_rpc(name)
            wallet.walletpassphrase('pass', 60)
            seed = wallet.listpqhdseeds()[0]['seed_id']
            descriptors = [descsum_create(f'wpkh(pqhd({seed})/10007h/6868h/{scheme}h/42h/{branch}h/*h)')
                           for branch in (0, 1)]
            for branch, desc in enumerate(descriptors):
                result = wallet.importdescriptors([{'desc': desc, 'timestamp': 'now', 'range': [4, 6],
                                                   'active': True, 'internal': bool(branch)}])[0]
                assert_equal(result['success'], True)
            expected = [wallet.deriveaddresses(desc, [4, 6]) for desc in descriptors]
            wallet.unloadwallet()
            node.loadwallet(name)
            wallet = node.get_wallet_rpc(name)
            self.log.info(f'Locked reload supplies cached receive/change addresses for scheme {scheme}')
            assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
            baseline = wallet.listdescriptors()
            assert_raises_rpc_error(-14, 'incorrect', wallet.walletpassphrase, 'wrong', 60)
            for desc, addresses in zip(descriptors, expected):
                assert_equal(wallet.deriveaddresses(desc, [4, 6]), addresses)
                assert_raises_rpc_error(-13, 'not cached', wallet.deriveaddresses, desc, [7, 7])
            # A same-range import may use the persisted cache while locked too.
            result = wallet.importdescriptors([{'desc': descriptors[0], 'timestamp': 'now',
                                               'range': [4, 6], 'active': True}])[0]
            assert_equal(result['success'], True)
            assert_equal(wallet.listdescriptors(), baseline)
            assert_equal(wallet.getnewaddress('', 'bech32'), expected[0][0])
            assert_equal(wallet.getrawchangeaddress('bech32'), expected[1][0])
            assert_equal(pubkey_scheme_prefix(wallet, expected[0][0]), scheme)
            fixtures.append((name, scheme, descriptors, expected))

        self.restart_node(0)
        if self.default_wallet_name not in node.listwallets():
            node.loadwallet(self.default_wallet_name)
        miner = node.get_wallet_rpc(self.default_wallet_name)
        for name, scheme, descriptors, expected in fixtures:
            node.loadwallet(name)
            wallet = node.get_wallet_rpc(name)
            assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
            # Reservations must survive a process restart without repeating index 4.
            assert_equal(wallet.getnewaddress('', 'bech32'), expected[0][1])
            assert_equal(wallet.getrawchangeaddress('bech32'), expected[1][1])
            txid = miner.sendtoaddress(expected[0][0], 1)
            self.generate(node, 1)
            assert_equal(wallet.getreceivedbyaddress(expected[0][0]), 1)
            tx = miner.gettransaction(txid, verbose=True)['decoded']
            vout = next(i for i, out in enumerate(tx['vout']) if out['scriptPubKey'].get('address') == expected[0][0])
            blank = node.createpsbt([{'txid': txid, 'vout': vout}], {expected[0][2]: Decimal('0.999')})
            public = wallet.walletprocesspsbt(blank, False, 'ALL', False, True)
            assert_equal(public['complete'], False)
            decoded = node.decodepsbt(public['psbt'])
            for item in decoded['inputs'] + decoded['outputs']:
                assert_equal(len(item['pqhd_origins']), 1)
                assert 'partial_signatures' not in item
            assert_raises_rpc_error(-13, 'walletpassphrase', wallet.walletprocesspsbt, public['psbt'])
            assert_equal(wallet.getnewaddress('', 'bech32'), expected[0][2])
            assert_equal(wallet.getrawchangeaddress('bech32'), expected[1][2])
            assert_raises_rpc_error(-12, 'Keypool ran out', wallet.getnewaddress, '', 'bech32')
            assert_raises_rpc_error(-12, 'Keypool ran out', wallet.getrawchangeaddress, 'bech32')
            assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
            wallet.walletpassphrase('pass', 60)
            signed = wallet.walletprocesspsbt(public['psbt'])
            assert_equal(signed['complete'], True)
            spend = node.sendrawtransaction(node.finalizepsbt(signed['psbt'])['hex'])
            self.generate(node, 1)
            assert_equal(wallet.gettransaction(spend)['confirmations'], 1)
            wallet.walletlock()


if __name__ == "__main__":
    WalletPQHDLockSemanticsTest(__file__).main()
