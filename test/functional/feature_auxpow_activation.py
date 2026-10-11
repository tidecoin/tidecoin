#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Regtest-only AuxPoW activation overrides, CLI/config, and PoW transition."""

from io import BytesIO
import time

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.auxpow_testing import computeAuxpow
from test_framework.messages import CAuxPow, CBlock, uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class AuxpowActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [[], ["-auxpowactivationheight=4"], []]

    def setup_network(self):
        # Different consensus settings must not exchange blocks automatically.
        self.add_nodes(self.num_nodes, self.extra_args)
        with self.nodes[2].tidecoinconf.open("a", encoding="utf8") as conf:
            conf.write("\n[regtest]\nauxpowactivationheight=never\n")
        self.start_nodes()

    def candidate(self, node, *, yespower_only=False):
        for _ in range(100):
            self.block_time += 1
            node.setmocktime(self.block_time)
            result = self.generateblock(
                node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [], submit=False, sync_fun=self.no_op,
            )
            block = CBlock()
            block.deserialize(BytesIO(bytes.fromhex(result["hex"])))
            if not yespower_only or block.scrypt_pow_int() > uint256_from_compact(block.nBits):
                return block
        raise AssertionError("Could not produce a yespower block that fails scrypt")

    def assert_auxpow_unavailable(self, node):
        assert_raises_rpc_error(
            -1, "mining auxblock method is not yet available",
            node.createauxblock, ADDRESS_BCRT1_P2WSH_OP_TRUE,
        )

    @staticmethod
    def attach_auxpow(block):
        block.set_auxpow_version(True)
        target = f"{uint256_from_compact(block.nBits):064x}"
        proof = computeAuxpow(block.hash_hex, target, True)
        block.auxpow = CAuxPow()
        block.auxpow.deserialize(BytesIO(bytes.fromhex(proof)))
        return block

    def run_test(self):
        default, activation, disabled = self.nodes
        self.block_time = int(time.time())

        self.log.info("Default regtest remains post-activation; config disables activation")
        assert_equal(default.createauxblock(ADDRESS_BCRT1_P2WSH_OP_TRUE)["height"], 1)
        self.assert_auxpow_unavailable(activation)
        self.assert_auxpow_unavailable(disabled)
        default_block = self.candidate(default)
        assert default_block.scrypt_pow_int() <= uint256_from_compact(default_block.nBits)
        assert_equal(default.submitblock(default_block.serialize().hex()), None)

        self.log.info("CLI overrides the regtest config setting on a fresh chain")
        self.restart_node(2, extra_args=["-auxpowactivationheight=0"])
        assert_equal(disabled.createauxblock(ADDRESS_BCRT1_P2WSH_OP_TRUE)["height"], 1)
        self.restart_node(2, extra_args=[])
        self.assert_auxpow_unavailable(disabled)

        self.log.info("Valid AuxPoW is rejected before activation")
        aux_block = self.attach_auxpow(self.candidate(disabled))
        for node in [activation, disabled]:
            assert_equal(node.submitblock(aux_block.serialize().hex()), "auxpow-pre-activation")

        self.log.info("Blocks 1 through 3 use yespower on both delayed/disabled nodes")
        initial_bits = activation.getblockheader(activation.getbestblockhash())["bits"]
        for height in [1, 2, 3]:
            block = self.candidate(disabled, yespower_only=True)
            for node in [activation, disabled]:
                assert_equal(node.submitblock(block.serialize().hex()), None)
                assert_equal(node.getblockcount(), height)
                assert_equal(node.getblockheader(node.getbestblockhash())["bits"], initial_bits)
            if height < 3:
                self.assert_auxpow_unavailable(activation)
            self.assert_auxpow_unavailable(disabled)

        # The RPC opens when the *next* block is at the activation height.
        assert_equal(activation.createauxblock(ADDRESS_BCRT1_P2WSH_OP_TRUE)["height"], 4)
        self.log.info("At height 4, a yespower-only block is rejected by the activated node")
        block = self.candidate(disabled, yespower_only=True)
        assert_equal(activation.submitblock(block.serialize().hex()), "high-hash")
        assert_equal(activation.getblockcount(), 3)
        assert_equal(disabled.submitblock(block.serialize().hex()), None)
        self.assert_auxpow_unavailable(disabled)

        self.log.info("At and after activation, standalone blocks use scrypt")
        for height in [4, 5]:
            block = self.candidate(activation)
            assert block.scrypt_pow_int() <= uint256_from_compact(block.nBits)
            assert_equal(activation.submitblock(block.serialize().hex()), None)
            assert_equal(activation.getblockcount(), height)
            assert_equal(activation.getblockheader(activation.getbestblockhash())["bits"], initial_bits)
        block = self.attach_auxpow(self.candidate(activation))
        assert_equal(activation.submitblock(block.serialize().hex()), None)
        assert "auxpow" in activation.getblock(block.hash_hex)

        # Disabled mode keeps rejecting valid AuxPoW after passing the chosen H.
        block = self.attach_auxpow(self.candidate(disabled))
        assert_equal(disabled.submitblock(block.serialize().hex()), "auxpow-pre-activation")
        self.restart_node(1)
        assert_equal(activation.getblockcount(), 6)
        self.restart_node(2, extra_args=[])
        self.assert_auxpow_unavailable(disabled)

        self.log.info("Reject malformed values and use outside regtest")
        self.stop_node(0)
        for value in ["", "-1", "foo", "1.5", "2147483647", "2147483648"]:
            default.assert_start_raises_init_error(
                extra_args=[f"-auxpowactivationheight={value}"],
                expected_msg=f"Error: Invalid value ({value}) for -auxpowactivationheight: expected an integer from 0 to 2147483646, or 'never'.",
            )
        for argument, message in [
            ("-auxpowactivationheight", "Can not set -auxpowactivationheight with no value. Please specify value with -auxpowactivationheight=value."),
            ("-noauxpowactivationheight", "Negating of -auxpowactivationheight is meaningless and therefore forbidden"),
        ]:
            default.assert_start_raises_init_error(
                extra_args=[argument],
                expected_msg=f"Error: Error parsing command line arguments: {message}",
            )
        for chain in ["main", "test"]:
            default.assert_start_raises_init_error(
                extra_args=["-regtest=0", f"-chain={chain}", "-auxpowactivationheight=never"],
                expected_msg="Error: -auxpowactivationheight is only supported on regtest.",
            )
        self.start_node(0)


if __name__ == "__main__":
    AuxpowActivationTest(__file__).main()
