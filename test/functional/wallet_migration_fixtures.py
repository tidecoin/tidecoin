#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test migrating local 0.18.3 BDB wallet fixtures to descriptor wallets.

This test intentionally does not rely on old-release binaries. It validates
that known legacy BDB fixtures can be migrated by current Tidecoin builds.
"""

import shutil
import struct
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


BTREE_MAGIC = 0x053162
LEGACY_WARNING = "This wallet is a legacy wallet and will need to be migrated with migratewallet before it can be loaded"
FIXTURE_PASSPHRASE = "fixture-passphrase"


class WalletMigrationFixturesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-walletcrosschain"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _assert_is_bdb(self, wallet_name: str):
        wallet_path = self.nodes[0].wallets_path / wallet_name / self.wallet_data_filename
        with open(wallet_path, "rb") as f:
            data = f.read(16)
        _, _, magic = struct.unpack("QII", data)
        assert_equal(magic, BTREE_MAGIC)

    def _assert_migrated_wallet(self, wallet_name: str):
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)
        info = wallet.getwalletinfo()
        assert_equal(info["descriptors"], True)
        assert_equal(info["format"], "sqlite")

    def run_test(self):
        node = self.nodes[0]
        fixtures_root = Path(__file__).resolve().parent / "data" / "wallet_migration"
        basic_wallet = "legacy_0_18_3_bdb_autocreated_a"
        encrypted_wallet = "legacy_0_18_3_bdb_encrypted"

        self.log.info("Copy legacy BDB fixtures into walletdir")
        for wallet_name in [basic_wallet, encrypted_wallet]:
            src = fixtures_root / wallet_name
            assert src.is_dir(), f"Missing wallet fixture directory: {src}"
            dst = node.wallets_path / wallet_name
            shutil.copytree(src, dst, dirs_exist_ok=True)
            self._assert_is_bdb(wallet_name)

        self.log.info("Verify legacy wallet migration warnings are present")
        listwalletdir = node.listwalletdir()["wallets"]
        warning_by_wallet = {w["name"]: w.get("warnings", []) for w in listwalletdir}
        assert_equal(warning_by_wallet[basic_wallet], [LEGACY_WARNING])
        assert_equal(warning_by_wallet[encrypted_wallet], [LEGACY_WARNING])

        self.log.info("Migrate unencrypted fixture")
        basic_migration = node.migratewallet(wallet_name=basic_wallet)
        assert Path(basic_migration["backup_path"]).exists()
        self._assert_migrated_wallet(basic_wallet)

        self.log.info("Verify encrypted fixture requires passphrase")
        assert_raises_rpc_error(
            -4,
            "Wallet decryption failed",
            node.migratewallet,
            wallet_name=encrypted_wallet,
        )

        self.log.info("Migrate encrypted fixture with passphrase")
        encrypted_migration = node.migratewallet(
            wallet_name=encrypted_wallet,
            passphrase=FIXTURE_PASSPHRASE,
        )
        assert Path(encrypted_migration["backup_path"]).exists()
        self._assert_migrated_wallet(encrypted_wallet)


if __name__ == '__main__':
    WalletMigrationFixturesTest(__file__).main()
