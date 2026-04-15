#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logic for skipping signature validation on old blocks.

Test logic for skipping signature validation on blocks which we've assumed
valid (https://github.com/bitcoin/bitcoin/pull/9484)

We build a chain that includes and invalid signature for one of the
transactions:

    0:        genesis block
    1:        block 1 with coinbase transaction output.
    2-101:    bury that block with 100 blocks so the coinbase transaction
              output can be spent
    102:      a block containing a transaction spending the coinbase
              transaction output. The transaction has an invalid signature.
    103-22102: bury the bad block with just over two weeks' worth of blocks
               for Tidecoin's 60-second target spacing (~20160 blocks)

Start three nodes:

    - node0 has no -assumevalid parameter. Try to sync to the final tip. It will
      reject block 102 and only sync as far as block 101
    - node1 has -assumevalid set to the hash of block 102. Try to sync to
      the final tip. node1 will sync all the way.
    - node2 has -assumevalid set to the hash of block 102. Try to sync to
      block 200. node2 will reject block 102 since it's assumed valid, but it
      isn't buried by at least two weeks' work.
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    msg_block,
    msg_headers,
)
from test_framework.p2p import (
    P2PDataStore,
    P2PInterface,
)
from test_framework.script import (
    CScript,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair


class BaseNode(P2PInterface):
    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in new_blocks]
        self.send_without_ping(headers_message)


class BlockServingNode(P2PDataStore):
    def add_blocks(self, new_blocks):
        for block in new_blocks:
            self.block_store[block.hash_int] = block
            self.last_block_hash = block.hash_int

    def send_header_for_blocks(self, new_blocks):
        self.add_blocks(new_blocks)
        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in new_blocks]
        self.send_without_ping(headers_message)


class AssumeValidTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.rpc_timeout = 120

    def setup_network(self):
        self.add_nodes(3)
        # Start node0. We don't start the other nodes yet since
        # we need to pre-mine a block with an invalid transaction
        # signature so we can pass in the block hash as assumevalid.
        self.start_node(0)

    def send_blocks(self, p2p_conn, blocks, *, sync_every=25, timeout=240):
        """Send blocks with periodic pings so slow CI nodes keep up."""
        for i, block in enumerate(blocks, start=1):
            p2p_conn.send_without_ping(msg_block(block))
            if sync_every and i % sync_every == 0:
                p2p_conn.sync_with_ping(timeout=timeout)
        p2p_conn.sync_with_ping(timeout=timeout)

    def send_rejected_block(self, p2p_conn, block):
        """Send one rejected block and wait until the node disconnects us."""
        try:
            p2p_conn.send_without_ping(msg_block(block))
            self.wait_until(lambda: not p2p_conn.is_connected)
        except IOError:
            assert not p2p_conn.is_connected

    @staticmethod
    def send_headers_in_chunks(p2p_conn, blocks, chunk_size=2000):
        for i in range(0, len(blocks), chunk_size):
            p2p_conn.send_header_for_blocks(blocks[i:i + chunk_size])

    def run_test(self):
        # Build the blockchain
        self.tip = int(self.nodes[0].getbestblockhash(), 16)
        self.block_time = self.nodes[0].getblock(self.nodes[0].getbestblockhash())['time'] + 1

        self.blocks = []

        # Get a pubkey for the coinbase TXO
        _, coinbase_pubkey = generate_keypair()

        # Create the first block with a coinbase output to our key
        height = 1
        block = create_block(self.tip, create_coinbase(height, coinbase_pubkey), self.block_time)
        self.blocks.append(block)
        self.block_time += 1
        block.solve()
        # Save the coinbase for later
        self.block1 = block
        self.tip = block.hash_int
        height += 1

        # Bury the block 100 deep so the coinbase output is spendable
        for _ in range(100):
            block = create_block(self.tip, create_coinbase(height), self.block_time)
            block.solve()
            self.blocks.append(block)
            self.tip = block.hash_int
            self.block_time += 1
            height += 1

        # Create a transaction spending the coinbase output with an invalid (null) signature
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.block1.vtx[0].txid_int, 0), scriptSig=b""))
        # Keep this tx value-valid on Tidecoin (40-coin subsidy at height 1),
        # so the intended failure mode remains "bad signature", not bad amount.
        tx.vout.append(CTxOut(39 * 100000000, CScript([OP_TRUE])))

        block102 = create_block(self.tip, create_coinbase(height), self.block_time, txlist=[tx])
        self.block_time += 1
        block102.solve()
        self.blocks.append(block102)
        self.tip = block102.hash_int
        self.block_time += 1
        height += 1

        # Bury the assumed-valid block deep enough for Tidecoin's 60s target spacing.
        ASSUMEVALID_BURY_DEPTH = 22000
        for _ in range(ASSUMEVALID_BURY_DEPTH):
            block = create_block(self.tip, create_coinbase(height), self.block_time)
            block.solve()
            self.blocks.append(block)
            self.tip = block.hash_int
            self.block_time += 1
            height += 1

        # Start node1 and node2 with assumevalid so they accept a block with a bad signature.
        self.start_node(1, extra_args=["-assumevalid=" + block102.hash_hex])
        self.start_node(2, extra_args=["-assumevalid=" + block102.hash_hex])

        invalid_block_chain = self.blocks[:COINBASE_MATURITY + 2]
        valid_blocks = invalid_block_chain[:-1]
        invalid_block = invalid_block_chain[-1]

        p2p0 = self.nodes[0].add_p2p_connection(BaseNode())
        self.send_headers_in_chunks(p2p0, invalid_block_chain)

        # Send blocks to node0. Block 102 will be rejected.
        self.send_blocks(p2p0, valid_blocks)
        assert_equal(self.nodes[0].getblockcount(), COINBASE_MATURITY + 1)
        self.send_rejected_block(p2p0, invalid_block)
        assert_equal(self.nodes[0].getblockcount(), COINBASE_MATURITY + 1)

        p2p1 = self.nodes[1].add_p2p_connection(BlockServingNode())
        p2p1.add_blocks(self.blocks)
        self.send_headers_in_chunks(p2p1, self.blocks)
        with self.nodes[1].assert_debug_log(expected_msgs=['Disabling signature validations at block #1', 'Enabling signature validations at block #103']):
            # Send all blocks to node1. All blocks will be accepted.
            self.send_blocks(p2p1, self.blocks, sync_every=1000, timeout=960)
        assert_equal(self.nodes[1].getblock(self.nodes[1].getbestblockhash())['height'], len(self.blocks))

        p2p2 = self.nodes[2].add_p2p_connection(BaseNode())
        p2p2.send_header_for_blocks(self.blocks[0:200])

        # Send blocks to node2. Block 102 will be rejected.
        self.send_blocks(p2p2, valid_blocks)
        assert_equal(self.nodes[2].getblockcount(), COINBASE_MATURITY + 1)
        self.send_rejected_block(p2p2, invalid_block)
        assert_equal(self.nodes[2].getblockcount(), COINBASE_MATURITY + 1)


if __name__ == '__main__':
    AssumeValidTest(__file__).main()
