#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet gethdkeys RPC (PQHD-only build)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class WalletGetHDKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        help_text = self.nodes[0].help('gethdkeys')
        assert "always returns an error" in help_text
        assert 'listpqhdseeds' in help_text
        assert 'listdescriptors' in help_text

        for wallet_name in (self.default_wallet_name, "basic"):
            if wallet_name != self.default_wallet_name:
                self.nodes[0].createwallet(wallet_name)
            wallet = self.nodes[0].get_wallet_rpc(wallet_name)
            assert_raises_rpc_error(
                -8,
                "BIP32/xpub descriptors are disabled (PQHD-only)",
                wallet.gethdkeys,
            )


if __name__ == '__main__':
    WalletGetHDKeyTest(__file__).main()
