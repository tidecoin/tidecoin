#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Historical block versions and ordinary chain-ID bits across AuxPoW activation."""

from io import BytesIO
from pathlib import Path
import time

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.authproxy import JSONRPCException
from test_framework.messages import CBlock, CBlockHeader, MAGIC_BYTES, msg_headers
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, util_xor


class HeaderVersionActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.extra_args = [
            ["-auxpowactivationheight=4"],
            ["-auxpowactivationheight=4"],
            ["-auxpowactivationheight=never", "-testactivationheight=segwit@2"],
            ["-auxpowactivationheight=4"],
        ]
        for args in self.extra_args:
            args.append("-checkblockindex=1")

    def setup_network(self):
        self.setup_nodes()  # Deliberately disconnected, including equal-rule nodes.

    def candidate(self, node, version):
        self.block_time += 1
        node.setmocktime(self.block_time)
        result = self.generateblock(
            node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [], submit=False, sync_fun=self.no_op,
        )
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(result["hex"])))
        block.nVersion = version
        block.nNonce = 0
        return block

    def check_header(self, node, block, reason=None):
        # The Python block helper only mines scrypt. Let the actual node check
        # yespower too; difficulty is low, and invalid versions fail after PoW.
        for _ in range(1000):
            try:
                node.submitheader(CBlockHeader(block).serialize().hex())
            except JSONRPCException as error:
                if error.error["message"] == "high-hash":
                    block.nNonce += 1
                    continue
                assert_equal(error.error["message"], reason)
                assert_equal(error.error["code"], -25)
            else:
                assert_equal(reason, None)
            return
        raise AssertionError("Could not find valid proof of work")

    def run_test(self):
        rpc, network, disabled, importer = self.nodes
        self.block_time = int(time.time())
        records = []
        accepted = []
        rejected = []

        self.log.info("Before activation, enforce the old minimum and accept ordinary version bits")
        for height, version in [(1, 0x20010004), (2, 0x20080004), (3, 0x201f0004)]:
            for low_version in [4, 0x1fe00004, -0x7ffffffc]:
                block = self.candidate(rpc, low_version)
                reason = f"bad-version(0x{low_version & 0xffffffff:08x})"
                self.check_header(rpc, block, reason)
                assert_equal(rpc.submitblock(block.serialize().hex()), reason)
                records.append(block)
                rejected.append((block, reason))
            block = self.candidate(rpc, version)
            self.check_header(rpc, block)
            assert_equal(rpc.submitblock(block.serialize().hex()), None)
            assert_equal(rpc.getblockcount(), height)
            records.append(block)
            accepted.append(block)

        self.log.info("At and after activation, accept version 4 and retain the chain-ID restriction")
        for height in [4, 5]:
            for version in [0x20010004, 0x20080004, 0x201f0004]:
                block = self.candidate(rpc, version)
                self.check_header(rpc, block, "auxpow-chainid")
                assert_equal(rpc.submitblock(block.serialize().hex()), "auxpow-chainid")
                records.append(block)
                rejected.append((block, "auxpow-chainid"))
            block = self.candidate(rpc, 4)
            self.check_header(rpc, block)
            assert_equal(rpc.submitblock(block.serialize().hex()), None)
            assert_equal(rpc.getblockcount(), height)
            records.append(block)
            accepted.append(block)

        self.log.info("A mixed-era P2P headers batch and its blocks produce the same chain")
        peer = network.add_p2p_connection(P2PDataStore())
        peer.send_blocks_and_test(accepted, network)
        for block, reason in [rejected[0], rejected[-1]]:
            # A fresh connection for each invalid message; the node may close it.
            network.disconnect_p2ps()
            peer = network.add_p2p_connection(P2PDataStore())
            with network.assert_debug_log([reason]):
                peer.send_without_ping(msg_headers([CBlockHeader(block)]))
                peer.wait_for_disconnect()
            assert_equal(network.getbestblockhash(), accepted[-1].hash_hex)
            network.disconnect_p2ps()
            peer = network.add_p2p_connection(P2PDataStore())
            peer.send_blocks_and_test(
                [block], network, success=False, force_send=True,
                reject_reason=reason, expect_disconnect=True,
            )

        self.log.info("Activation disabled: the minimum starts with configured witness activation")
        block = self.candidate(disabled, 4)
        self.check_header(disabled, block)
        assert_equal(disabled.submitblock(block.serialize().hex()), None)
        for height in range(2, 6):
            block = self.candidate(disabled, 4)
            self.check_header(disabled, block, "bad-version(0x00000004)")
            assert_equal(disabled.submitblock(block.serialize().hex()), "bad-version(0x00000004)")
            block = self.candidate(disabled, 0x20080004)
            self.check_header(disabled, block)
            assert_equal(disabled.submitblock(block.serialize().hex()), None)
            assert_equal(disabled.getblockcount(), height)

        self.log.info("Import and reindex preserve the same acceptance rules and original bytes")
        bootstrap = Path(self.options.tmpdir) / "header-versions.dat"
        with bootstrap.open("wb") as output:
            for block in records:
                data = block.serialize()
                output.write(MAGIC_BYTES[self.chain] + len(data).to_bytes(4, "little") + data)
        self.restart_node(3, extra_args=self.extra_args[3] + [f"-loadblock={bootstrap}"])
        assert_equal(importer.getbestblockhash(), accepted[-1].hash_hex)
        for block, _ in rejected:
            assert_raises_rpc_error(-5, "Block not found", importer.getblockheader, block.hash_hex)
        # Reindex the same records in reverse order after genesis, including
        # rejected candidates. Ancestry must determine their rules even when
        # their parents appear later in the file.
        genesis = bytes.fromhex(importer.getblock(importer.getblockhash(0), 0))
        self.stop_node(3)
        xor_key = importer.read_xor_key()
        with (importer.blocks_path / "blk00000.dat").open("wb") as output:
            for data in [genesis] + [block.serialize() for block in reversed(records)]:
                record = MAGIC_BYTES[self.chain] + len(data).to_bytes(4, "little") + data
                output.write(util_xor(record, xor_key, offset=output.tell()))
        with importer.assert_debug_log([
            "bad-version(0x00000004)", "auxpow-chainid",
            "Out of order block", "Processing out of order child",
        ]):
            self.start_node(3, extra_args=self.extra_args[3] + ["-reindex"])
        assert_equal(importer.getbestblockhash(), accepted[-1].hash_hex)
        for block, _ in rejected:
            assert_raises_rpc_error(-5, "Block not found", importer.getblockheader, block.hash_hex)
        for block in accepted:
            assert_equal(importer.getblock(block.hash_hex, 0), block.serialize().hex())
        self.restart_node(0)
        assert_equal(rpc.getbestblockhash(), accepted[-1].hash_hex)


if __name__ == "__main__":
    HeaderVersionActivationTest(__file__).main()
