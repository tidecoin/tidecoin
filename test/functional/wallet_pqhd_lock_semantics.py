#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify PQHD seed lock semantics for descriptor address derivation."""

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
        self.extra_args = [["-keypool=1"]]

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


if __name__ == "__main__":
    WalletPQHDLockSemanticsTest(__file__).main()
