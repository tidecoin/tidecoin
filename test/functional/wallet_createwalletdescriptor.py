#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet createwalletdescriptor RPC (PQHD-only build)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class WalletCreateDescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        help_text = self.nodes[0].help('createwalletdescriptor')
        assert "always returns an error" in help_text
        assert 'setpqhdpolicy' in help_text
        assert 'importdescriptors' in help_text

        for wallet_name in (self.default_wallet_name, "blank"):
            if wallet_name != self.default_wallet_name:
                self.nodes[0].createwallet(wallet_name, blank=True)
            wallet = self.nodes[0].get_wallet_rpc(wallet_name)
            assert_raises_rpc_error(
                -8,
                "BIP32/xpub descriptors are disabled (PQHD-only)",
                wallet.createwalletdescriptor,
                "bech32",
            )



if __name__ == '__main__':
    WalletCreateDescriptorTest(__file__).main()
