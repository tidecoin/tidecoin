#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Miniscript descriptors integration in the wallet."""

from test_framework.descriptors import descsum_create
from test_framework.psbt import PSBT, PSBT_IN_SHA256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet_util import generate_keypair


class WalletMiniscriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def watchonly_test(self, desc):
        self.log.info(f"Importing descriptor '{desc}'")
        desc = descsum_create(f"{desc}")
        result = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": desc,
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert result["success"], result

        self.log.info("Testing we can derive and detect funds for it")
        addr = self.funder.deriveaddresses(desc)[0]

        self.log.info("Testing we detect funds sent to one of them")
        txid = self.funder.sendtoaddress(addr, 0.01)
        self.wait_until(
            lambda: len(self.ms_wo_wallet.listunspent(minconf=0, addresses=[addr])) == 1
        )
        utxo = self.ms_wo_wallet.listunspent(minconf=0, addresses=[addr])[0]
        assert utxo["txid"] == txid and utxo["solvable"]

    def signing_test(
        self, desc, sequence, locktime, sigs_count, stack_size, sha256_preimages
    ):
        self.log.info(f"Importing private Miniscript descriptor '{desc}'")
        desc = descsum_create(desc)
        res = self.ms_sig_wallet.importdescriptors(
            [
                {
                    "desc": desc,
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )
        assert res[0]["success"], res

        self.log.info("Generating an address for it and testing it detects funds")
        addr = self.funder.deriveaddresses(desc)[0]
        txid = self.funder.sendtoaddress(addr, 0.01)
        self.wait_until(lambda: txid in self.funder.getrawmempool())
        self.funder.generatetoaddress(1, self.funder.getnewaddress())
        utxo = self.ms_sig_wallet.listunspent(addresses=[addr])[0]
        assert txid == utxo["txid"] and utxo["solvable"]

        self.log.info("Creating a transaction spending these funds")
        dest_addr = self.funder.getnewaddress()
        seq = sequence if sequence is not None else 0xFFFFFFFF - 2
        lt = locktime if locktime is not None else 0
        psbt = self.ms_sig_wallet.createpsbt(
            [
                {
                    "txid": txid,
                    "vout": utxo["vout"],
                    "sequence": seq,
                }
            ],
            [{dest_addr: 0.009}],
            lt,
        )

        self.log.info("Signing it and checking the satisfaction.")
        if sha256_preimages is not None:
            psbt = PSBT.from_base64(psbt)
            for (h, preimage) in sha256_preimages.items():
                k = PSBT_IN_SHA256.to_bytes(1, "big") + bytes.fromhex(h)
                psbt.i[0].map[k] = bytes.fromhex(preimage)
            psbt = psbt.to_base64()
        res = self.ms_sig_wallet.walletprocesspsbt(psbt=psbt, finalize=False)
        psbtin = self.nodes[0].decodepsbt(res["psbt"])["inputs"][0]
        sigs_field_name = "partial_signatures"
        actual_sigs_count = len(psbtin[sigs_field_name])
        expected_sigs_counts = sigs_count if isinstance(sigs_count, tuple) else (sigs_count,)
        assert actual_sigs_count in expected_sigs_counts, (
            f"unexpected signature count for descriptor {desc}: "
            f"expected={expected_sigs_counts} got={actual_sigs_count}"
        )
        res = self.ms_sig_wallet.finalizepsbt(res["psbt"])
        assert res["complete"] == (stack_size is not None)

        if stack_size is not None:
            txin = self.nodes[0].decoderawtransaction(res["hex"])["vin"][0]
            assert len(txin["txinwitness"]) == stack_size, txin["txinwitness"]
            self.log.info("Broadcasting the transaction.")
            # If necessary, satisfy a relative timelock
            if sequence is not None:
                self.funder.generatetoaddress(sequence, self.funder.getnewaddress())
            # If necessary, satisfy an absolute timelock
            height = self.funder.getblockcount()
            if locktime is not None and height < locktime:
                self.funder.generatetoaddress(
                    locktime - height, self.funder.getnewaddress()
                )
            self.ms_sig_wallet.sendrawtransaction(res["hex"])

    def run_test(self):
        self.log.info("Making a descriptor wallet")
        self.funder = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet(
            wallet_name="ms_wo", disable_private_keys=True
        )
        self.ms_wo_wallet = self.nodes[0].get_wallet_rpc("ms_wo")
        self.nodes[0].createwallet(wallet_name="ms_sig")
        self.ms_sig_wallet = self.nodes[0].get_wallet_rpc("ms_sig")

        # Sanity check we wouldn't let an insane Miniscript descriptor in
        res = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": descsum_create(
                        "wsh(and_b(ripemd160(1fd9b55a054a2b3f658d97e6b84cf3ee00be429a),a:1))"
                    ),
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert not res["success"]
        assert "is not sane: witnesses without signature exist" in res["error"]["message"]

        # Sanity check we wouldn't let an unspendable Miniscript descriptor in
        res = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": descsum_create("wsh(0)"),
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert not res["success"] and "is not satisfiable" in res["error"]["message"]

        priv_keys = [generate_keypair(wif=True) for _ in range(3)]
        tprvs = [k[0] for k in priv_keys]
        tpubs = [k[1].hex() for k in priv_keys]
        pubkeys = [generate_keypair(wif=True)[1].hex() for _ in range(7)]

        p2wsh_miniscripts = [
            # One of two keys
            f"or_b(pk({tpubs[0]}),s:pk({tpubs[1]}))",
            # A script similar (same spending policy) to BOLT3's offered HTLC (with anchor outputs)
            f"or_d(pk({tpubs[0]}),and_v(and_v(v:pk({tpubs[1]}),or_c(pk({tpubs[2]}),v:hash160(7f999c905d5e35cefd0a37673f746eb13fba3640))),older(1)))",
            # Revault-style policy adapted to PQ sizes with fewer keys
            f"andor(multi(2,{tpubs[0]},{tpubs[1]}),and_v(v:multi(2,{pubkeys[0]},{pubkeys[1]}),after(424242)),thresh(2,pkh({pubkeys[4]}),a:pkh({pubkeys[5]}),a:pkh({pubkeys[6]})))",
            # Federated-like branch with emergency recovery, reduced key count for PQ feasibility
            f"or_i(and_b(pk({pubkeys[2]}),s:pk({pubkeys[3]})),and_v(v:thresh(2,pkh({tpubs[0]}),a:pkh({pubkeys[4]}),a:pkh({pubkeys[5]})),older(4200)))",
        ]

        descs = [f"wsh({ms})" for ms in p2wsh_miniscripts]

        descs_priv = [
            # One of two keys, of which one private key is known
            {
                "desc": f"wsh(or_i(pk({tprvs[0]}),pk({tpubs[1]})))",
                "sequence": None,
                "locktime": None,
                "sigs_count": 1,
                "stack_size": 3,
            },
            # A more complex policy, that can't be satisfied through the first branch (need for a preimage)
            {
                "desc": f"wsh(andor(ndv:older(2),and_v(v:pk({tprvs[0]}),sha256(2a8ce30189b2ec3200b47aeb4feaac8fcad7c0ba170389729f4898b0b7933bcb)),and_v(v:pkh({tprvs[1]}),pk({tprvs[2]}))))",
                "sequence": 2,
                "locktime": None,
                "sigs_count": 3,
                "stack_size": 5,
            },
            # The same policy but we provide the preimage. This path will be chosen as it's a smaller witness.
            {
                "desc": f"wsh(andor(ndv:older(2),and_v(v:pk({tprvs[0]}),sha256(61e33e9dbfefc45f6a194187684d278f789fd4d5e207a357e79971b6519a8b12)),and_v(v:pkh({tprvs[1]}),pk({tprvs[2]}))))",
                "sequence": 2,
                "locktime": None,
                "sigs_count": 3,
                "stack_size": 4,
                "sha256_preimages": {
                    "61e33e9dbfefc45f6a194187684d278f789fd4d5e207a357e79971b6519a8b12": "e8774f330f5f330c23e8bbefc5595cb87009ddb7ac3b8deaaa8e9e41702d919c"
                },
            },
            # Signature with a relative timelock
            {
                "desc": f"wsh(and_v(v:older(2),pk({tprvs[0]})))",
                "sequence": 2,
                "locktime": None,
                "sigs_count": 1,
                "stack_size": 2,
            },
            # Signature with an absolute timelock
            {
                "desc": f"wsh(and_v(v:after(20),pk({tprvs[0]})))",
                "sequence": None,
                "locktime": 20,
                "sigs_count": 1,
                "stack_size": 2,
            },
            # Signature with both
            {
                "desc": f"wsh(and_v(v:older(4),and_v(v:after(30),pk({tprvs[0]}))))",
                "sequence": 4,
                "locktime": 30,
                "sigs_count": 1,
                "stack_size": 2,
            },
            # We have one key on each branch; Core signs both (can't finalize)
            {
                "desc": f"wsh(c:andor(pk({tprvs[0]}),pk_k({pubkeys[0]}),and_v(v:pk({tprvs[1]}),pk_k({pubkeys[1]}))))",
                "sequence": None,
                "locktime": None,
                "sigs_count": 2,
                "stack_size": None,
            },
            # We have all the keys, wallet selects the timeout path to sign since it's smaller and sequence is set
            {
                "desc": f"wsh(andor(pk({tprvs[0]}),pk({tprvs[2]}),and_v(v:pk({tprvs[1]}),older(10))))",
                "sequence": 10,
                "locktime": None,
                "sigs_count": 3,
                "stack_size": 3,
            },
            # We have all the keys, wallet selects the primary path to sign unconditionally since nsequence wasn't set to be valid for timeout path
            {
                "desc": f"wsh(andor(pk({tprvs[0]}),pk({tprvs[2]}),and_v(v:pkh({tprvs[1]}),older(10))))",
                "sequence": None,
                "locktime": None,
                "sigs_count": 3,
                "stack_size": 3,
            },
            # Finalizes to the smallest valid witness, regardless of sequence
            {
                "desc": f"wsh(or_d(pk({tprvs[0]}),and_v(v:pk({tprvs[1]}),and_v(v:pk({tprvs[2]}),older(10)))))",
                "sequence": 12,
                "locktime": None,
                "sigs_count": 3,
                "stack_size": 2,
            },
            # Liquid-like federated pegin with emergency recovery privkeys
            {
                "desc": f"wsh(or_i(and_b(pk({pubkeys[0]}),a:and_b(pk({pubkeys[1]}),a:and_b(pk({pubkeys[2]}),a:and_b(pk({pubkeys[3]}),s:pk({pubkeys[4]}))))),and_v(v:thresh(2,pk({tprvs[0]}),a:pk({tprvs[1]}),a:pk({tpubs[2]})),older(1))))",
                "sequence": 1,
                "locktime": None,
                "sigs_count": (2, 3),
                "stack_size": 5,
            },
        ]

        # Test we can track any type of Miniscript
        for desc in descs:
            self.watchonly_test(desc)

        # Test we can sign for any Miniscript.
        for desc in descs_priv:
            self.signing_test(
                desc["desc"],
                desc["sequence"],
                desc["locktime"],
                desc["sigs_count"],
                desc["stack_size"],
                desc.get("sha256_preimages"),
            )


if __name__ == "__main__":
    WalletMiniscriptTest(__file__).main()
