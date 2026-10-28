#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test multisig RPCs"""
import decimal
import itertools

from test_framework.address import address_to_scriptpubkey
from test_framework.authproxy import JSONRPCException
from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.psbt import PSBT, PSBT_IN_PARTIAL_SIG
from test_framework.script_util import keys_to_multisig_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_raises_rpc_error,
    assert_equal,
)
from test_framework.wallet_util import generate_keypair
from test_framework.wallet import (
    MiniWallet,
    getnewdestination,
)

class RpcCreateMultiSigTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def create_keys(self, num_keys):
        self.pub = []
        self.priv = []
        for _ in range(num_keys):
            privkey, pubkey = generate_keypair(wif=True)
            self.pub.append(pubkey.hex())
            self.priv.append(privkey)

    def run_test(self):
        node0, node1, _node2 = self.nodes
        self.wallet = MiniWallet(test_node=node0)
        self.test_pubkey_encodings()

        self.log.info('Generating blocks ...')
        self.generate(self.wallet, 149)

        self.create_keys(21)  # max number of allowed keys + 1
        # Legacy spends hit scriptSig policy limits much earlier with PQ keys.
        vectors_by_output = {
            "bech32": [(2, 3), (3, 3), (2, 5), (3, 5), (5, 9), (9, 9)],
            "p2sh-segwit": [(2, 3), (3, 3), (2, 5), (3, 5), (5, 9), (9, 9)],
            "legacy": [(2, 3), (3, 3), (2, 5), (3, 5)],
        }
        for output_type, vectors in vectors_by_output.items():
            for sigs, keys in vectors:
                self.do_multisig(keys, sigs, output_type)

        self.test_multisig_script_limit()
        self.test_sortedmulti_descriptors_bip67()

        # Check that bech32m is not a supported address type
        assert_raises_rpc_error(-5, "Unknown address type 'bech32m'", self.nodes[0].createmultisig, 2, self.pub, "bech32m")

        self.log.info('Check correct encoding of multisig script up to script size limit')
        for nkeys in range(1, 20+1):
            keys = [self.pub[0]]*nkeys
            expected_ms_script = keys_to_multisig_script(keys, k=nkeys)  # simply use n-of-n
            try:
                # We use bech32 purely as a script-construction path.
                res = self.nodes[0].createmultisig(nrequired=nkeys, keys=keys, address_type='bech32')
            except JSONRPCException as e:
                assert "redeemScript exceeds size limit" in e.error["message"]
                break
            assert_equal(res['redeemScript'], expected_ms_script.hex())

    def test_pubkey_encodings(self):
        self.log.info('Check full public-key encodings at RPC, descriptor and PSBT entry points')
        node = self.nodes[0]
        original = node.createpsbt([{"txid": "00" * 31 + "01", "vout": 0}], {self.wallet.get_address(): 1})
        for scheme in range(7, 12):
            _, pubkey = generate_keypair(scheme=str(scheme))
            valid = [pubkey]
            invalid = []
            if scheme in (7, 8):
                header = bytearray(pubkey)
                header[1] = 0
                invalid.append(bytes(header))
                for coefficient in (12289, 16383):
                    packed = bytearray(pubkey)
                    packed[2] = coefficient >> 6
                    packed[3] = (packed[3] & 3) | ((coefficient & 63) << 2)
                    invalid.append(bytes(packed))
            else:
                # No coefficient values are excluded in an ML-DSA public key.
                valid += [bytes([scheme]) + bytes([fill]) * (len(pubkey) - 1) for fill in (0, 255)]
            for key in valid + invalid:
                accepted = key in valid
                keyhex = key.hex()
                if accepted:
                    node.createmultisig(1, [keyhex], "bech32")
                else:
                    assert_raises_rpc_error(-5, "must be cryptographically valid", node.createmultisig, 1, [keyhex], "bech32")
                for desc in (f"pkh({keyhex})", f"wpkh({keyhex})", f"wsh(multi(1,{keyhex},{pubkey.hex()}))"):
                    if accepted:
                        canonical = node.getdescriptorinfo(desc)["descriptor"]
                        assert_equal(node.getdescriptorinfo(canonical)["descriptor"], canonical)
                    else:
                        assert_raises_rpc_error(-5, "is invalid", node.getdescriptorinfo, desc)
                psbt = PSBT.from_base64(original)
                psbt.i[0].map[bytes([PSBT_IN_PARTIAL_SIG]) + key] = b"\x01"
                if accepted:
                    decoded = node.decodepsbt(psbt.to_base64())
                    assert_equal(decoded["inputs"][0]["partial_signatures"], {keyhex: "01"})
                else:
                    assert_raises_rpc_error(-22, "Invalid pubkey", node.decodepsbt, psbt.to_base64())

    def test_multisig_script_limit(self):
        node1 = self.nodes[1]
        pubkeys = self.pub[0:20]

        self.log.info('Test redeem script max size limit for large PQ multisig')
        assert_raises_rpc_error(-8, "redeemScript exceeds size limit", node1.createmultisig, 16, pubkeys, 'legacy')

        self.log.info('Test valid high multisig within size limit (no wallet)')
        self.do_multisig(nkeys=9, nsigs=9, output_type="p2sh-segwit")
        self.do_multisig(nkeys=9, nsigs=9, output_type="bech32")

        self.log.info('Test invalid key-count bound (still capped at 20)')
        assert_raises_rpc_error(-8, "Number of keys involved in the multisignature address creation > 20", node1.createmultisig, 16, self.pub, 'p2sh-segwit')
        assert_raises_rpc_error(-8, "Number of keys involved in the multisignature address creation > 20", node1.createmultisig, 16, self.pub, 'bech32')

    def do_multisig(self, nkeys, nsigs, output_type):
        node0, _node1, node2 = self.nodes
        pub_keys = self.pub[0: nkeys]
        priv_keys = self.priv[0: nkeys]

        # Construct the expected descriptor
        desc = 'multi({},{})'.format(nsigs, ','.join(pub_keys))
        if output_type == 'legacy':
            desc = 'sh({})'.format(desc)
        elif output_type == 'p2sh-segwit':
            desc = 'sh(wsh({}))'.format(desc)
        elif output_type == 'bech32':
            desc = 'wsh({})'.format(desc)
        desc = descsum_create(desc)

        msig = node2.createmultisig(nsigs, pub_keys, output_type)
        assert 'warnings' not in msig
        madd = msig["address"]
        mredeem = msig["redeemScript"]
        assert_equal(desc, msig['descriptor'])
        if output_type == 'bech32':
            # Tidecoin uses a different HRP than Bitcoin regtest; assert semantics instead.
            addr_info = node2.validateaddress(madd)
            assert_equal(addr_info["iswitness"], True)
            assert_equal(addr_info["witness_version"], 0)

        spk = address_to_scriptpubkey(madd)
        value = decimal.Decimal("0.00100000")
        tx = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=spk, amount=int(value * COIN))
        prevtxs = [{"txid": tx["txid"], "vout": tx["sent_vout"], "scriptPubKey": spk.hex(), "redeemScript": mredeem, "amount": value}]

        self.generate(node0, 1)

        outval = value - decimal.Decimal("0.00002000")  # deduce fee (must be higher than the min relay fee)
        out_addr = getnewdestination('bech32')[2]
        rawtx = node2.createrawtransaction([{"txid": tx["txid"], "vout": tx["sent_vout"]}], [{out_addr: outval}])

        prevtx_err = dict(prevtxs[0])
        del prevtx_err["redeemScript"]

        assert_raises_rpc_error(-8, "Missing redeemScript/witnessScript", node2.signrawtransactionwithkey, rawtx, priv_keys[0:nsigs-1], [prevtx_err])

        # if witnessScript specified, all ok
        prevtx_err["witnessScript"] = prevtxs[0]["redeemScript"]
        node2.signrawtransactionwithkey(rawtx, priv_keys[0:nsigs-1], [prevtx_err])

        # both specified, also ok
        prevtx_err["redeemScript"] = prevtxs[0]["redeemScript"]
        node2.signrawtransactionwithkey(rawtx, priv_keys[0:nsigs-1], [prevtx_err])

        # redeemScript mismatch to witnessScript
        prevtx_err["redeemScript"] = "6a" # OP_RETURN
        assert_raises_rpc_error(-8, "redeemScript does not correspond to witnessScript", node2.signrawtransactionwithkey, rawtx, priv_keys[0:nsigs-1], [prevtx_err])

        # redeemScript does not match scriptPubKey
        del prevtx_err["witnessScript"]
        assert_raises_rpc_error(-8, "redeemScript/witnessScript does not match scriptPubKey", node2.signrawtransactionwithkey, rawtx, priv_keys[0:nsigs-1], [prevtx_err])

        # witnessScript does not match scriptPubKey
        prevtx_err["witnessScript"] = prevtx_err["redeemScript"]
        del prevtx_err["redeemScript"]
        assert_raises_rpc_error(-8, "redeemScript/witnessScript does not match scriptPubKey", node2.signrawtransactionwithkey, rawtx, priv_keys[0:nsigs-1], [prevtx_err])

        rawtx2 = node2.signrawtransactionwithkey(rawtx, priv_keys[0:nsigs - 1], prevtxs)
        assert_equal(rawtx2["complete"], False)
        rawtx3 = node2.signrawtransactionwithkey(rawtx, [priv_keys[-1]], prevtxs)
        assert_equal(rawtx3["complete"], False)
        assert_raises_rpc_error(-22, "TX decode failed", node2.combinerawtransaction, [rawtx2['hex'], rawtx3['hex'] + "00"])
        assert_raises_rpc_error(-22, "Missing transactions", node2.combinerawtransaction, [])
        combined_rawtx = node2.combinerawtransaction([rawtx2["hex"], rawtx3["hex"]])

        tx = node0.sendrawtransaction(combined_rawtx, 0)
        blk = self.generate(node0, 1)[0]
        assert tx in node0.getblock(blk)["tx"]

        assert_raises_rpc_error(-25, "Input not found or already spent", node2.combinerawtransaction, [rawtx2['hex'], rawtx3['hex']])

        txinfo = node0.getrawtransaction(tx, True, blk)
        self.log.info("n/m=%d/%d %s size=%d vsize=%d weight=%d" % (nsigs, nkeys, output_type, txinfo["size"], txinfo["vsize"], txinfo["weight"]))

    def test_sortedmulti_descriptors_bip67(self):
        self.log.info('Testing sortedmulti deterministic ordering with PQ keys')
        node = self.nodes[0]
        pq_keys = self.pub[0:5]

        for key_perm in itertools.permutations(pq_keys, 3):
            key_str = ','.join(key_perm)
            sorted_desc = descsum_create('wsh(sortedmulti(2,{}))'.format(key_str))
            sorted_addr = node.deriveaddresses(sorted_desc)[0]

            manually_sorted = ','.join(sorted(key_perm))
            manual_desc = descsum_create('wsh(multi(2,{}))'.format(manually_sorted))
            assert_equal(node.deriveaddresses(manual_desc)[0], sorted_addr)


if __name__ == '__main__':
    RpcCreateMultiSigTest(__file__).main()
