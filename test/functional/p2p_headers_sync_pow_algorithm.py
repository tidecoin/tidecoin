#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Buffered ordinary headers must satisfy the work algorithm at their height."""

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CBlock, CBlockHeader, from_hex, msg_headers, uint256_from_compact
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


BATCH_SIZE = 2000


class HeadersPeer(P2PInterface):
    def on_getheaders(self, message):
        # Deliver each pass explicitly so the test observes the waiting state.
        pass


class HeadersSyncPowAlgorithmTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--reverse", action="store_true", help="Reject yespower after activation")

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3 if self.options.reverse else 2
        self.rpc_timeout *= 4
        common = ["-checkblockindex=1"]
        activation = "2001" if self.options.reverse else "never"
        self.extra_args = [common + ["-auxpowactivationheight=never", "-minimumchainwork=0"]]
        if self.options.reverse:
            self.extra_args.append(common + [f"-auxpowactivationheight={activation}", "-minimumchainwork=0"])
        self.extra_args.append(common + [f"-auxpowactivationheight={activation}", "-minimumchainwork=0xc800"])

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        miner, buffered = self.nodes[0], self.nodes[-1]
        control = self.nodes[1] if self.options.reverse else miner
        self.log.info("Build the first batch using the required yespower algorithm")
        self.generate(miner, BATCH_SIZE, sync_fun=self.no_op)
        valid_blocks = [miner.getblock(miner.getblockhash(height), 0) for height in range(1, BATCH_SIZE + 1)]
        if self.options.reverse:
            for block in valid_blocks:
                assert_equal(control.submitblock(block), None)
        valid_headers = [
            from_hex(CBlockHeader(), control.getblockheader(control.getblockhash(height), False))
            for height in range(1, BATCH_SIZE + 1)
        ]
        tip = valid_headers[-1]

        if self.options.reverse:
            self.log.info("Mine a yespower-only extension using the node with activation disabled")
            for attempt in range(100):
                miner.setmocktime(tip.nTime + 1 + attempt)
                result = self.generateblock(miner, ADDRESS_BCRT1_P2WSH_OP_TRUE, [], submit=False, sync_fun=self.no_op)
                wrong_block = from_hex(CBlock(), result["hex"])
                if wrong_block.scrypt_pow_int() > uint256_from_compact(wrong_block.nBits):
                    break
            else:
                raise AssertionError("Could not find a yespower-only block")
            assert_raises_rpc_error(-25, "high-hash", control.submitheader, CBlockHeader(wrong_block).serialize().hex())
            assert_equal(miner.submitblock(wrong_block.serialize().hex()), None)
            self.generate(miner, BATCH_SIZE - 1, sync_fun=self.no_op)
            wrong_headers = [
                from_hex(CBlockHeader(), miner.getblockheader(miner.getblockhash(height), False))
                for height in range(BATCH_SIZE + 1, 2 * BATCH_SIZE + 1)
            ]
        else:
            self.log.info("Construct a scrypt-valid block that the height-specific check rejects")
            wrong_block = create_block(
                tip.hash_int,
                create_coinbase(BATCH_SIZE + 1, halving_period=20),
                tip.nTime + 1,
                version=0x20000000,
            )
            wrong_block.nBits = tip.nBits
            for _ in range(100):
                wrong_block.solve_scrypt()
                try:
                    control.submitheader(CBlockHeader(wrong_block).serialize().hex())
                except JSONRPCException as error:
                    assert_equal(error.error["message"], "high-hash")
                    break
                wrong_block.nNonce += 1
            else:
                raise AssertionError("Could not find a scrypt-only block")

            wrong_headers = [CBlockHeader(wrong_block)]
            for _ in range(BATCH_SIZE - 1):
                previous = wrong_headers[-1]
                header = CBlockHeader()
                header.nVersion = 0x20000000
                header.hashPrevBlock = previous.hash_int
                header.hashMerkleRoot = 1
                header.nTime = previous.nTime + 1
                header.nBits = previous.nBits
                block = CBlock(header)
                block.solve_scrypt()
                wrong_headers.append(CBlockHeader(block))

        self.log.info("Direct P2P and RPC submission reject the wrong algorithm")
        direct_peer = control.add_p2p_connection(HeadersPeer())
        with control.assert_debug_log(["header with invalid proof of work"]):
            direct_peer.send_without_ping(msg_headers(wrong_headers))
            direct_peer.wait_for_disconnect()
        assert_equal(control.submitblock(wrong_block.serialize().hex()), "high-hash")
        assert_equal(control.getblockcount(), BATCH_SIZE)

        self.log.info("Reject on arrival while the predecessor is only in the first-pass state")
        peer = buffered.add_p2p_connection(HeadersPeer())
        peer.send_and_ping(msg_headers(valid_headers))
        assert_equal(buffered.getblockchaininfo()["headers"], 0)
        with buffered.assert_debug_log(["header with invalid proof of work"]):
            peer.send_without_ping(msg_headers(wrong_headers))
            peer.wait_for_disconnect()
        assert_equal(buffered.getblockchaininfo()["headers"], 0)
        for header in [wrong_headers[0], wrong_headers[-1]]:
            assert_raises_rpc_error(-5, "Block not found", buffered.getblockheader, header.hash_hex)

        self.log.info("Full-block delivery agrees with header validation")
        for block in valid_blocks:
            assert_equal(buffered.submitblock(block), None)
        assert_equal(buffered.submitblock(wrong_block.serialize().hex()), "high-hash")
        assert_equal(buffered.getblockcount(), BATCH_SIZE)

        self.log.info("A valid replacement is accepted and survives restart")
        replacement = self.generate(control, 1, sync_fun=self.no_op)[0]
        assert_equal(buffered.submitblock(control.getblock(replacement, 0)), None)
        self.restart_node(self.num_nodes - 1)
        assert_equal(buffered.getbestblockhash(), replacement)
        assert_equal(buffered.verifychain(4, 0), True)


if __name__ == '__main__':
    HeadersSyncPowAlgorithmTest(__file__).main()
