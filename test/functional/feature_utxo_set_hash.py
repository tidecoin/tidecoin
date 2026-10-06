#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test UTXO set hash value calculation in gettxoutsetinfo."""

from test_framework.messages import (
    CBlock,
    COutPoint,
    from_hex,
)
from test_framework.crypto.muhash import MuHash3072
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

class UTXOSetHashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def test_muhash_implementation(self):
        self.log.info("Test MuHash implementation consistency")

        node = self.nodes[0]
        wallet = MiniWallet(node)
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)

        # Generate 100 blocks and remove the first since we plan to spend its
        # coinbase
        block_hashes = self.generate(wallet, 1) + self.generate(node, 99)
        blocks = list(map(lambda block: from_hex(CBlock(), node.getblock(block, False)), block_hashes))
        blocks.pop(0)

        # Create a spending transaction and mine a block which includes it
        txid = wallet.send_self_transfer(from_node=node)['txid']
        tx_block = self.generateblock(node, output=wallet.get_address(), transactions=[txid])
        blocks.append(from_hex(CBlock(), node.getblock(tx_block['hash'], False)))

        # Serialize the outputs that should be in the UTXO set and add them to
        # a MuHash object
        muhash = MuHash3072()

        for height, block in enumerate(blocks):
            # The Genesis block coinbase is not part of the UTXO set and we
            # spent the first mined block
            height += 2

            for tx in block.vtx:
                for n, tx_out in enumerate(tx.vout):
                    coinbase = 1 if not tx.vin[0].prevout.hash else 0

                    # Skip witness commitment
                    if (coinbase and n > 0):
                        continue

                    data = COutPoint(tx.txid_int, n).serialize()
                    data += (height * 2 + coinbase).to_bytes(4, "little")
                    data += tx_out.serialize()

                    muhash.insert(data)

        finalized = muhash.digest()
        node_muhash = node.gettxoutsetinfo("muhash")['muhash']

        assert_equal(finalized[::-1].hex(), node_muhash)

        self.log.info("Test deterministic UTXO set hash results")
        assert_equal(node.gettxoutsetinfo()['hash_serialized_3'], "95671a8696fa7e8e935c0b008490831a31ad4c4b53eb997a74bc7856be4f0142")
        assert_equal(node.gettxoutsetinfo("muhash")['muhash'], "4b4177837b72c867eebfb59241b30a0b5c23bd4fe7666ea485015d40bd8c1dc6")

    def run_test(self):
        self.test_muhash_implementation()
        self.test_compaction_preserves_utxos()

    def test_compaction_preserves_utxos(self):
        self.log.info("Check UTXO contents across full database compaction and reopening")
        node = self.nodes[0]
        expected = node.gettxoutsetinfo("muhash")
        expected.pop("disk_size")
        for cache in (4, 8):
            # The existing startup option exercises the same full-compaction
            # operation. Async scheduling and lifetime races have unit coverage.
            with node.assert_debug_log(["Starting database compaction of", "Finished database compaction of"]):
                self.restart_node(0, extra_args=["-forcecompactdb", f"-dbcache={cache}"])
            actual = node.gettxoutsetinfo("muhash")
            actual.pop("disk_size")
            assert_equal(actual, expected)
            assert_equal(node.verifychain(4, 0), True)


if __name__ == '__main__':
    UTXOSetHashTest(__file__).main()
