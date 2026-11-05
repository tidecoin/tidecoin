#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the importdescriptors RPC.

Test importdescriptors by generating keys on node0, importing the corresponding
descriptors on node1 and then testing the address info for the different address
variants.

- `get_generate_key()` is called to generate keys and return the privkeys,
  pubkeys and all variants of scriptPubKey and address.
- `test_importdesc()` is called to send an importdescriptors call to node1, test
  success, and (if unsuccessful) test the error code and error message returned.
- `test_address()` is called to call getaddressinfo for an address on node1
  and test the values returned."""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import descsum_create
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import (
    get_generate_key,
    test_address,
    WalletUnlock,
)

class ImportDescriptorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True
        self.extra_args = [["-addresstype=legacy"],
                           ["-addresstype=bech32", "-keypool=5"]
                          ]
        self.setup_clean_chain = True
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_importdesc(self, req, success, error_code=None, error_message=None, warnings=None, wallet=None):
        """Run importdescriptors and assert success"""
        if warnings is None:
            warnings = []
        wrpc = self.nodes[1].get_wallet_rpc('w1')
        if wallet is not None:
            wrpc = wallet

        result = wrpc.importdescriptors([req])
        observed_warnings = []
        if 'warnings' in result[0]:
            observed_warnings = result[0]['warnings']
        assert_equal("\n".join(sorted(warnings)), "\n".join(sorted(observed_warnings)))
        assert_equal(result[0]['success'], success)
        if error_code is not None:
            assert_equal(result[0]['error']['code'], error_code)
            assert_equal(result[0]['error']['message'], error_message)

    def run_test(self):
        self.log.info('Setting up wallets')
        self.nodes[0].createwallet(wallet_name='w0', disable_private_keys=False)
        w0 = self.nodes[0].get_wallet_rpc('w0')

        self.nodes[1].createwallet(wallet_name='w1', disable_private_keys=True, blank=True)
        w1 = self.nodes[1].get_wallet_rpc('w1')
        assert_equal(w1.getwalletinfo()['keypoolsize'], 0)

        self.nodes[1].createwallet(wallet_name="wpriv", disable_private_keys=False, blank=True)
        wpriv = self.nodes[1].get_wallet_rpc("wpriv")
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 0)

        self.log.info('Mining coins')
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 1, w0.getnewaddress())

        # RPC importdescriptors -----------------------------------------------

        # # Test import fails if no descriptor present
        self.log.info("Import should fail if a descriptor is not provided")
        self.test_importdesc({"timestamp": "now"},
                             success=False,
                             error_code=-8,
                             error_message='Descriptor not found.')

        # # Test importing of a P2PKH descriptor
        key = get_generate_key()
        self.log.info("Should import a p2pkh descriptor")
        import_request = {"desc": descsum_create("pkh(" + key.pubkey + ")"),
                 "timestamp": "now",
                 "label": "Descriptor import test"}
        self.test_importdesc(import_request, success=True)
        test_address(w1,
                     key.p2pkh_addr,
                     solvable=True,
                     ismine=True,
                     labels=["Descriptor import test"])
        assert_equal(w1.getwalletinfo()['keypoolsize'], 0)

        self.log.info("Test can import same descriptor with public key twice")
        self.test_importdesc(import_request, success=True)

        self.log.info("Test can update descriptor label")
        self.test_importdesc({**import_request, "label": "Updated label"}, success=True)
        test_address(w1, key.p2pkh_addr, solvable=True, ismine=True, labels=["Updated label"])

        self.log.info("Internal addresses cannot have labels")
        self.test_importdesc({**import_request, "internal": True},
                             success=False,
                             error_code=-8,
                             error_message="Internal addresses should not have a label")

        self.log.info("Internal addresses should be detected as such")
        key = get_generate_key()
        self.test_importdesc({"desc": descsum_create("pkh(" + key.pubkey + ")"),
                              "timestamp": "now",
                              "internal": True},
                             success=True)
        info = w1.getaddressinfo(key.p2pkh_addr)
        assert_equal(info["ismine"], True)
        assert_equal(info["ischange"], True)

        self.log.info("Should not import a descriptor with an invalid public key due to whitespace")
        self.test_importdesc({"desc": descsum_create("pkh( " + key.pubkey + ")"),
                                    "timestamp": "now",
                                    "internal": True},
                                    error_code=-5,
                                    error_message=f"pkh(): Key ' {key.pubkey}' is invalid due to whitespace",
                                    success=False)
        self.test_importdesc({"desc": descsum_create("pkh(" + key.pubkey + " )"),
                                    "timestamp": "now",
                                    "internal": True},
                                    error_code=-5,
                                    error_message=f"pkh(): Key '{key.pubkey} ' is invalid due to whitespace",
                                    success=False)

        # # Test importing of a P2SH-P2WPKH descriptor
        key = get_generate_key()
        self.log.info("Should not import a p2sh-p2wpkh descriptor without checksum")
        self.test_importdesc({"desc": "sh(wpkh(" + key.pubkey + "))",
                              "timestamp": "now"
                              },
                             success=False,
                             error_code=-5,
                             error_message="Missing checksum")

        self.log.info("Should not import a p2sh-p2wpkh descriptor that has range specified")
        self.test_importdesc({"desc": descsum_create("sh(wpkh(" + key.pubkey + "))"),
                               "timestamp": "now",
                               "range": 1,
                              },
                              success=False,
                              error_code=-8,
                              error_message="Range should not be specified for an un-ranged descriptor")

        self.log.info("Should not import a p2sh-p2wpkh descriptor and have it set to active")
        self.test_importdesc({"desc": descsum_create("sh(wpkh(" + key.pubkey + "))"),
                               "timestamp": "now",
                               "active": True,
                              },
                              success=False,
                              error_code=-8,
                              error_message="Active descriptors must be ranged")

        self.log.info("Should import a (non-active) p2sh-p2wpkh descriptor")
        self.test_importdesc({"desc": descsum_create("sh(wpkh(" + key.pubkey + "))"),
                               "timestamp": "now",
                               "active": False,
                              },
                              success=True)
        assert_equal(w1.getwalletinfo()['keypoolsize'], 0)

        test_address(w1,
                     key.p2sh_p2wpkh_addr,
                     ismine=True,
                     solvable=True)

        # Check persistence of data and that loading works correctly
        w1.unloadwallet()
        self.nodes[1].loadwallet('w1')
        test_address(w1,
                     key.p2sh_p2wpkh_addr,
                     ismine=True,
                     solvable=True)

        # # Test importing of a multisig descriptor
        key1 = get_generate_key()
        key2 = get_generate_key()
        self.log.info("Should import a 1-of-2 bare multisig from descriptor")
        self.test_importdesc({"desc": descsum_create("multi(1," + key1.pubkey + "," + key2.pubkey + ")"),
                              "timestamp": "now"},
                             success=True)
        self.log.info("Should not treat individual keys from the imported bare multisig as watchonly")
        test_address(w1,
                     key1.p2pkh_addr,
                     ismine=False)

        # # Test importing a descriptor containing a WIF private key
        wif_key = get_generate_key()
        desc = "sh(wpkh(" + wif_key.privkey + "))"
        self.log.info("Should import a descriptor with a WIF private key as spendable")
        self.test_importdesc({"desc": descsum_create(desc),
                               "timestamp": "now"},
                              success=True,
                              wallet=wpriv)

        self.log.info('Test can import same descriptor with private key twice')
        self.test_importdesc({"desc": descsum_create(desc), "timestamp": "now"}, success=True, wallet=wpriv)

        test_address(wpriv,
                     wif_key.p2sh_p2wpkh_addr,
                     solvable=True,
                     ismine=True)
        txid = w0.sendtoaddress(wif_key.p2sh_p2wpkh_addr, 9.99995540)
        self.generatetoaddress(self.nodes[0], 6, w0.getnewaddress())
        decoded = w0.gettransaction(txid=txid, verbose=True)['decoded']
        vout = next(i for i, out in enumerate(decoded['vout']) if out['scriptPubKey'].get('address') == wif_key.p2sh_p2wpkh_addr)
        tx = wpriv.createrawtransaction([{"txid": txid, "vout": vout}], {w0.getnewaddress(): 9.999})
        signed_tx = wpriv.signrawtransactionwithwallet(tx)
        assert_equal(signed_tx['complete'], True)
        w1.sendrawtransaction(signed_tx['hex'])

        self.log.info("Descriptor-address dumpprivkey parity for imported private descriptor")
        dump_key = get_generate_key()
        dump_desc = descsum_create("wpkh(" + dump_key.privkey + ")")
        self.test_importdesc({"desc": dump_desc, "timestamp": "now"}, success=True, wallet=wpriv)
        dump_addr = self.nodes[1].deriveaddresses(dump_desc)[0]
        assert_equal(wpriv.dumpprivkey(dump_desc, {"index": 0}), dump_key.privkey)
        assert_equal(wpriv.dumpprivkey(dump_addr), dump_key.privkey)

        self.log.info("dumpprivkey negative matrix: watch-only and not-owned")
        watch_key = get_generate_key()
        watch_desc = descsum_create("wpkh(" + watch_key.pubkey + ")")
        self.test_importdesc({"desc": watch_desc, "timestamp": "now"}, success=True, wallet=w1)
        watch_addr = self.nodes[1].deriveaddresses(watch_desc)[0]
        assert_raises_rpc_error(
            -4,
            "Private key not available in wallet",
            w1.dumpprivkey,
            watch_addr,
        )
        not_owned = get_generate_key().p2wpkh_addr
        assert_raises_rpc_error(
            -4,
            "Private key not available (address not found in wallet)",
            wpriv.dumpprivkey,
            not_owned,
        )

        self.log.info("dumpprivkey negative matrix: encrypted locked wallet")
        self.nodes[1].createwallet(wallet_name="wlocked", passphrase="passphrase")
        wlocked = self.nodes[1].get_wallet_rpc("wlocked")
        locked_addr = wlocked.getnewaddress()
        assert_raises_rpc_error(
            -13,
            "Please enter the wallet passphrase",
            wlocked.dumpprivkey,
            locked_addr,
        )
        with WalletUnlock(wlocked, "passphrase"):
            unlocked_wif = wlocked.dumpprivkey(locked_addr)
            assert unlocked_wif

        # Make sure that we can import a simple WIF multisig and spend from it
        self.log.info('Test that multisigs can be imported and signed for (WIF-based)')
        self.nodes[1].createwallet(wallet_name="wmulti_priv", disable_private_keys=False, blank=True)
        wmulti_priv = self.nodes[1].get_wallet_rpc("wmulti_priv")
        assert_equal(wmulti_priv.getwalletinfo()['keypoolsize'], 0)

        k1 = get_generate_key()
        k2 = get_generate_key()
        desc = f"wsh(multi(2,{k1.privkey},{k2.privkey}))"
        self.test_importdesc({"desc": descsum_create(desc),
                              "timestamp": "now"},
                             success=True,
                             wallet=wmulti_priv)
        addr = self.nodes[1].deriveaddresses(descsum_create(desc))[0]
        w0.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 6)
        txid = wmulti_priv.sendall(recipients=[w0.getnewaddress()])["txid"]
        decoded = wmulti_priv.gettransaction(txid=txid, verbose=True)['decoded']
        # dummy + 2 sigs + witness script
        assert_equal(len(decoded['vin'][0]['txinwitness']), 4)

if __name__ == '__main__':
    ImportDescriptorsTest(__file__).main()
