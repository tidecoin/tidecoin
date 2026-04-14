#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the scantxoutset rpc call."""
from test_framework.address import address_to_scriptpubkey, key_to_p2wpkh
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import (
    MiniWallet,
    getnewdestination,
)
from test_framework.wallet_util import generate_keypair


def descriptors(out):
    return sorted(u['desc'] for u in out['unspents'])


class ScantxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def sendtodestination(self, destination, amount):
        # interpret strings as addresses, assume scriptPubKey otherwise
        if isinstance(destination, str):
            destination = address_to_scriptpubkey(destination)
        return self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=destination, amount=int(COIN * amount))

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.log.info("Test if we find coinbase outputs.")
        assert_equal(sum(u["coinbase"] for u in self.nodes[0].scantxoutset("start", [self.wallet.get_descriptor()])["unspents"]), 49)

        self.log.info("Create UTXOs...")
        pubk1, spk_P2SH_SEGWIT, addr_P2SH_SEGWIT = getnewdestination("p2sh-segwit")
        pubk2, spk_LEGACY, addr_LEGACY = getnewdestination("legacy")
        pubk3, spk_BECH32, addr_BECH32 = getnewdestination("bech32")
        tx_p2sh = self.sendtodestination(spk_P2SH_SEGWIT, 0.001)
        tx_legacy = self.sendtodestination(spk_LEGACY, 0.002)
        tx_bech32 = self.sendtodestination(spk_BECH32, 0.004)
        wif, pub = generate_keypair()
        tx_wpkh = self.sendtodestination(key_to_p2wpkh(pub), 0.008)

        self.generate(self.nodes[0], 1)

        scan = self.nodes[0].scantxoutset("start", [])
        info = self.nodes[0].gettxoutsetinfo()
        assert_equal(scan['success'], True)
        assert_equal(scan['height'], info['height'])
        assert_equal(scan['txouts'], info['txouts'])
        assert_equal(scan['bestblock'], info['bestblock'])

        self.log.info("Test if we have found the non HD unspent outputs.")
        def has_sent_outpoint(scan_result, tx):
            return any(u["txid"] == tx["txid"] and u["vout"] == tx["sent_vout"] for u in scan_result["unspents"])

        scan_pkh = self.nodes[0].scantxoutset("start", ["pkh(" + pubk1.hex() + ")", "pkh(" + pubk2.hex() + ")", "pkh(" + pubk3.hex() + ")"])
        assert has_sent_outpoint(scan_pkh, tx_legacy)

        scan_wpkh = self.nodes[0].scantxoutset("start", ["wpkh(" + pubk1.hex() + ")", "wpkh(" + pubk2.hex() + ")", "wpkh(" + pubk3.hex() + ")"])
        assert has_sent_outpoint(scan_wpkh, tx_bech32)

        scan_sh_wpkh = self.nodes[0].scantxoutset("start", ["sh(wpkh(" + pubk1.hex() + "))", "sh(wpkh(" + pubk2.hex() + "))", "sh(wpkh(" + pubk3.hex() + "))"])
        assert has_sent_outpoint(scan_sh_wpkh, tx_p2sh)

        scan_combo = self.nodes[0].scantxoutset("start", ["combo(" + pubk1.hex() + ")", "combo(" + pubk2.hex() + ")", "combo(" + pubk3.hex() + ")"])
        assert has_sent_outpoint(scan_combo, tx_p2sh)
        assert has_sent_outpoint(scan_combo, tx_legacy)
        assert has_sent_outpoint(scan_combo, tx_bech32)

        scan_addr = self.nodes[0].scantxoutset("start", ["addr(" + addr_P2SH_SEGWIT + ")", "addr(" + addr_LEGACY + ")", "addr(" + addr_BECH32 + ")"])
        assert has_sent_outpoint(scan_addr, tx_p2sh)
        assert has_sent_outpoint(scan_addr, tx_legacy)
        assert has_sent_outpoint(scan_addr, tx_bech32)

        scan_mixed = self.nodes[0].scantxoutset("start", ["addr(" + addr_P2SH_SEGWIT + ")", "addr(" + addr_LEGACY + ")", "combo(" + pubk3.hex() + ")"])
        assert has_sent_outpoint(scan_mixed, tx_p2sh)
        assert has_sent_outpoint(scan_mixed, tx_legacy)
        assert has_sent_outpoint(scan_mixed, tx_bech32)

        self.log.info("Test range validation.")
        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": -1}])
        assert_raises_rpc_error(-8, "Range should be greater or equal than 0", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [-1, 10]}])
        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [(2 << 31 + 1) - 1000000, (2 << 31 + 1)]}])
        assert_raises_rpc_error(-8, "Range specified as [begin,end] must not have begin after end", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [2, 1]}])
        assert_raises_rpc_error(-8, "Range is too large", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [0, 1000001]}])

        self.log.info("Test simple descriptor scans with raw pubkeys.")
        scan_wpkh_single = self.nodes[0].scantxoutset("start", [f"wpkh({pub.hex()})"])
        assert has_sent_outpoint(scan_wpkh_single, tx_wpkh)
        assert_equal(self.nodes[0].scantxoutset("start", [f"combo({pub.hex()})"])["success"], True)

        # Check that status and abort don't need second arg
        assert_equal(self.nodes[0].scantxoutset("status"), None)
        assert_equal(self.nodes[0].scantxoutset("abort"), False)

        # Check that the blockhash and confirmations fields are correct
        self.generate(self.nodes[0], 2)
        unspent = next(
            u for u in self.nodes[0].scantxoutset("start", ["addr(" + addr_BECH32 + ")"])["unspents"]
            if u["txid"] == tx_bech32["txid"] and u["vout"] == tx_bech32["sent_vout"]
        )
        blockhash = self.nodes[0].getblockhash(info["height"])
        assert_equal(unspent["height"], info["height"])
        assert_equal(unspent["blockhash"], blockhash)
        assert_equal(unspent["confirmations"], 3)

        # Check that first arg is needed
        assert_raises_rpc_error(-1, "scantxoutset \"action\" ( [scanobjects,...] )", self.nodes[0].scantxoutset)

        # Check that second arg is needed for start
        assert_raises_rpc_error(-1, "scanobjects argument is required for the start action", self.nodes[0].scantxoutset, "start")

        # Check that invalid command give error
        assert_raises_rpc_error(-8, "Invalid action 'invalid_command'", self.nodes[0].scantxoutset, "invalid_command")


if __name__ == "__main__":
    ScantxoutsetTest(__file__).main()
