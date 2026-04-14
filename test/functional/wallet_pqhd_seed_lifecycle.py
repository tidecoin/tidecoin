#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify PQHD seed import/list/select/remove lifecycle behavior."""

from decimal import Decimal
import re

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import WalletUnlock


def active_bech32_pqhd_descriptors(wallet):
    active = {}
    pattern = re.compile(r"wpkh\(pqhd\(([0-9a-f]{64})\)/(\d+)h/(\d+)h/(\d+)h/0h/([01])h/\*h\)")
    for entry in wallet.listdescriptors()["descriptors"]:
        if not entry.get("active", False):
            continue
        if "internal" not in entry:
            continue
        match = pattern.search(entry["desc"])
        if not match:
            continue
        internal = entry["internal"]
        chain_index = int(match.group(5))
        assert_equal(chain_index, 1 if internal else 0)
        active[internal] = {
            "seed_id": match.group(1),
            "scheme": int(match.group(4)),
        }
    assert False in active
    assert True in active
    return active


class WalletPQHDSeedLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        wallet_name = "pqhdseed"
        self.nodes[0].createwallet(wallet_name=wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)

        self.log.info("Initial descriptor wallet has exactly one default PQHD seed")
        initial = wallet.listpqhdseeds()
        assert_equal(len(initial), 1)
        initial_seed_id = initial[0]["seed_id"]
        assert initial[0]["default_receive"]
        assert initial[0]["default_change"]

        self.log.info("Import two deterministic seeds; re-import is idempotent")
        seed_a_hex = "11" * 32
        seed_b_hex = "22" * 32
        imported_a = wallet.importpqhdseed(seed_a_hex)
        assert imported_a["inserted"]
        imported_a_again = wallet.importpqhdseed(seed_a_hex)
        assert not imported_a_again["inserted"]
        assert_equal(imported_a_again["seed_id"], imported_a["seed_id"])
        imported_b = wallet.importpqhdseed(seed_b_hex)
        assert imported_b["inserted"]

        self.log.info("Unknown seed id must be rejected by setpqhdseed")
        assert_raises_rpc_error(
            -4,
            "Receive seed id not found in wallet",
            wallet.setpqhdseed,
            "00" * 32,
        )

        self.log.info("Switch defaults to imported seed and verify policy flags")
        wallet.setpqhdseed(imported_a["seed_id"])
        listed = wallet.listpqhdseeds()
        defaults = {entry["seed_id"]: (entry["default_receive"], entry["default_change"]) for entry in listed}
        assert_equal(defaults[imported_a["seed_id"]], (True, True))
        assert_equal(defaults[initial_seed_id], (False, False))
        active = active_bech32_pqhd_descriptors(wallet)
        assert_equal(active[False]["seed_id"], imported_a["seed_id"])
        assert_equal(active[True]["seed_id"], imported_a["seed_id"])
        assert_equal(active[False]["scheme"], 0x07)
        assert_equal(active[True]["scheme"], 0x07)

        self.log.info("Default getnewaddress/getrawchangeaddress must use selected default seed")
        receive_default_addr = wallet.getnewaddress("", "bech32")
        receive_default_info = wallet.getaddressinfo(receive_default_addr)
        assert_equal(receive_default_info["pqhd_seedid"], imported_a["seed_id"])
        change_default_addr = wallet.getrawchangeaddress("bech32")
        change_default_info = wallet.getaddressinfo(change_default_addr)
        assert_equal(change_default_info["pqhd_seedid"], imported_a["seed_id"])

        self.log.info("Scheme-override derivation uses current default seed id")
        addr = wallet.getnewaddress("", "bech32", "falcon512")
        info = wallet.getaddressinfo(addr)
        assert_equal(info["pqhd_seedid"], imported_a["seed_id"])
        info_no_origin = wallet.getaddressinfo(addr, {"include_pqhd_origin": False})
        assert "pqhd_seedid" not in info_no_origin
        assert "pqhd_path" not in info_no_origin

        self.log.info("walletprocesspsbt can suppress PQHD origin metadata")
        self.generatetoaddress(self.nodes[0], 101, wallet.getnewaddress())
        outpoint = self.create_outpoints(wallet, outputs=[{wallet.getnewaddress(): 1}])[0]
        self.generate(self.nodes[0], 1)
        psbt = wallet.createpsbt([outpoint], {wallet.getnewaddress(): 0.999})
        default_no_origin = wallet.walletprocesspsbt(psbt, False, "ALL", False)
        with_origin = wallet.walletprocesspsbt(psbt, False, "ALL", False, True)
        without_origin = wallet.walletprocesspsbt(psbt, False, "ALL", False, False)
        decoded_default = self.nodes[0].decodepsbt(default_no_origin["psbt"])
        decoded_with_origin = self.nodes[0].decodepsbt(with_origin["psbt"])
        decoded_without_origin = self.nodes[0].decodepsbt(without_origin["psbt"])
        assert "pqhd_origins" not in decoded_default["inputs"][0]
        assert "pqhd_origins" not in decoded_default["outputs"][0]
        assert "pqhd_origins" in decoded_with_origin["inputs"][0]
        assert "pqhd_origins" in decoded_with_origin["outputs"][0]
        assert "pqhd_origins" not in decoded_without_origin["inputs"][0]
        assert "pqhd_origins" not in decoded_without_origin["outputs"][0]

        def has_any_pqhd_origins(decoded_psbt):
            for psbt_in in decoded_psbt["inputs"]:
                if "pqhd_origins" in psbt_in:
                    return True
            for psbt_out in decoded_psbt["outputs"]:
                if "pqhd_origins" in psbt_out:
                    return True
            return False

        self.log.info("walletcreatefundedpsbt defaults to no PQHD origins and supports explicit opt-in")
        funded_default = wallet.walletcreatefundedpsbt([], [{wallet.getnewaddress(): Decimal("0.2")}])["psbt"]
        funded_with_origin = wallet.walletcreatefundedpsbt(
            [],
            [{wallet.getnewaddress(): Decimal("0.2")}],
            0,
            {"include_pqhd_origins": True},
        )["psbt"]
        assert not has_any_pqhd_origins(self.nodes[0].decodepsbt(funded_default))
        assert has_any_pqhd_origins(self.nodes[0].decodepsbt(funded_with_origin))

        self.log.info("send(..., options.psbt=true) defaults to no PQHD origins and supports explicit opt-in")
        send_default = wallet.send(
            outputs=[{wallet.getnewaddress(): Decimal("0.15")}],
            options={"psbt": True},
        )["psbt"]
        send_with_origin = wallet.send(
            outputs=[{wallet.getnewaddress(): Decimal("0.15")}],
            options={"psbt": True, "include_pqhd_origins": True},
        )["psbt"]
        assert not has_any_pqhd_origins(self.nodes[0].decodepsbt(send_default))
        assert has_any_pqhd_origins(self.nodes[0].decodepsbt(send_with_origin))

        self.log.info("psbtbumpfee defaults to no PQHD origins and supports explicit opt-in")
        rbf_txid = wallet.send(
            outputs=[{wallet.getnewaddress(): Decimal("0.05")}],
            options={"replaceable": True},
        )["txid"]
        bumped_default = wallet.psbtbumpfee(rbf_txid)["psbt"]
        bumped_with_origin = wallet.psbtbumpfee(rbf_txid, {"include_pqhd_origins": True})["psbt"]
        assert not has_any_pqhd_origins(self.nodes[0].decodepsbt(bumped_default))
        assert has_any_pqhd_origins(self.nodes[0].decodepsbt(bumped_with_origin))

        self.log.info("Spending a witness v1 (bech32pq) UTXO succeeds post-activation")
        pq_addr = wallet.getnewaddress("", "bech32pq")
        pq_outpoint = self.create_outpoints(wallet, outputs=[{pq_addr: 1}])[0]
        self.generate(self.nodes[0], 1)
        spend_dest = wallet.getnewaddress("", "bech32")
        spend_res = wallet.send(
            outputs=[{spend_dest: Decimal("0.5")}],
            options={"inputs": [pq_outpoint], "add_inputs": False},
        )
        assert spend_res["complete"]
        spend_tx = wallet.gettransaction(spend_res["txid"], verbose=True)["decoded"]
        assert_equal(len(spend_tx["vin"]), 1)
        assert_equal(spend_tx["vin"][0]["txid"], pq_outpoint["txid"])
        assert_equal(spend_tx["vin"][0]["vout"], pq_outpoint["vout"])

        self.log.info("Removing an unreferenced non-default seed succeeds")
        removed = wallet.removepqhdseed(imported_b["seed_id"])
        assert removed["removed"]
        remaining_ids = {entry["seed_id"] for entry in wallet.listpqhdseeds()}
        assert imported_b["seed_id"] not in remaining_ids

        self.log.info("Cannot remove default seed; cannot remove descriptor-referenced seed")
        assert_raises_rpc_error(
            -4,
            "Cannot remove active default PQHD seed",
            wallet.removepqhdseed,
            imported_a["seed_id"],
        )
        wallet.setpqhdseed(initial_seed_id)
        assert_raises_rpc_error(
            -4,
            "Cannot remove PQHD seed referenced by wallet descriptors",
            wallet.removepqhdseed,
            imported_a["seed_id"],
        )

        self.log.info("Encrypted wallet import path requires unlock")
        locked_wallet_name = "pqhdseedlocked"
        self.nodes[0].createwallet(wallet_name=locked_wallet_name, passphrase="pass")
        locked_wallet = self.nodes[0].get_wallet_rpc(locked_wallet_name)
        locked_initial_seeds = locked_wallet.listpqhdseeds()
        locked_default_receive_seed = next(entry["seed_id"] for entry in locked_initial_seeds if entry["default_receive"])
        locked_default_change_seed = next(entry["seed_id"] for entry in locked_initial_seeds if entry["default_change"])
        locked_active_before = active_bech32_pqhd_descriptors(locked_wallet)
        assert_raises_rpc_error(
            -4,
            "Cannot import PQHD seed while wallet is locked",
            locked_wallet.importpqhdseed,
            "33" * 32,
        )
        with WalletUnlock(locked_wallet, "pass"):
            imported_locked = locked_wallet.importpqhdseed("33" * 32)
            assert imported_locked["inserted"]
        imported_locked_seed = imported_locked["seed_id"]

        self.log.info("Locked-wallet policy updates must fail atomically when descriptor sync cannot create missing descriptors")
        assert_raises_rpc_error(
            -4,
            "Missing PQHD descriptor",
            locked_wallet.setpqhdseed,
            imported_locked_seed,
            imported_locked_seed,
        )
        locked_after_setseed = locked_wallet.listpqhdseeds()
        assert_equal(next(entry["seed_id"] for entry in locked_after_setseed if entry["default_receive"]), locked_default_receive_seed)
        assert_equal(next(entry["seed_id"] for entry in locked_after_setseed if entry["default_change"]), locked_default_change_seed)
        assert_equal(active_bech32_pqhd_descriptors(locked_wallet), locked_active_before)

        assert_raises_rpc_error(
            -4,
            "Missing PQHD descriptor",
            locked_wallet.setpqhdpolicy,
            "mldsa44",
            "mldsa65",
        )
        locked_after_setpolicy = locked_wallet.listpqhdseeds()
        assert_equal(next(entry["seed_id"] for entry in locked_after_setpolicy if entry["default_receive"]), locked_default_receive_seed)
        assert_equal(next(entry["seed_id"] for entry in locked_after_setpolicy if entry["default_change"]), locked_default_change_seed)
        assert_equal(active_bech32_pqhd_descriptors(locked_wallet), locked_active_before)


if __name__ == "__main__":
    WalletPQHDSeedLifecycleTest(__file__).main()
