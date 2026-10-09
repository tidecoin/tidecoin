#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""A failed AuxPoW proof must not retire the header.

One header is submitted, then a different proof for that same header is
rejected. The original proof is submitted afterwards and must still be
accepted. Covers the weight check on ordinary submitblock, and the length
and parent-proof checks on -loadblock, which call AcceptBlock directly.
"""

from io import BytesIO
from pathlib import Path

from test_framework.auxpow_testing import computeAuxpow
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (
    CAuxPow,
    CBlock,
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    MAGIC_BYTES,
    MAX_BLOCK_WEIGHT,
    uint256_from_compact,
)
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def make_auxpow(block_hash_hex, nbits, extra):
    """Parent proof for block_hash_hex. extra is appended after the merge-mine trailer."""
    script = (
        b"\xfa\xbe\x6d\x6d"
        + bytes.fromhex(block_hash_hex)
        + (1).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + extra
    )
    tx = CTransaction()
    tx.version = 1
    tx.vin = [CTxIn(COutPoint(0, 0xFFFFFFFF), CScript(script), 0xFFFFFFFF)]
    parent = CBlockHeader()
    parent.nVersion = 1
    parent.hashPrevBlock = 0
    parent.hashMerkleRoot = tx.txid_int
    parent.nTime = 0
    parent.nBits = nbits
    parent.nNonce = 0
    target = uint256_from_compact(nbits)
    while parent.scrypt_pow_int() > target:
        parent.nNonce = (parent.nNonce + 1) & 0xFFFFFFFF
    proof = CAuxPow()
    proof.coinbase_tx = tx
    proof.parent_block = parent
    return proof


def block_with_proof(template, proof):
    block = CBlock(template)
    block.vtx = template.vtx
    block.auxpow = proof
    return block


def proof_for_stripped_size(template, target_stripped):
    """Return a valid parent proof that makes the block's stripped size exact."""
    # Both probes are far past the 3-byte compact-size boundary, so changing
    # the padding does not change the script length prefix.
    probe_len = 1_490_000
    probe = block_with_proof(template, make_auxpow(template.hash_hex, template.nBits, b"\x00" * probe_len))
    stripped = len(probe.serialize(with_witness=False))
    extra_len = probe_len + (target_stripped - stripped)
    assert extra_len > 65535
    return make_auxpow(template.hash_hex, template.nBits, b"\x00" * extra_len)


def write_blocks(path, blocks):
    magic = MAGIC_BYTES["regtest"]
    with open(path, "wb") as handle:
        for block in blocks:
            raw = block.serialize()
            handle.write(magic)
            handle.write(len(raw).to_bytes(4, "little"))
            handle.write(raw)


class AuxpowAlternateProofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def make_block(self, prev_hash, height, ntime, coinbase_value):
        coinbase = create_coinbase(height)
        coinbase.vout[0].nValue = coinbase_value
        block = create_block(prev_hash, coinbase, ntime)
        add_witness_commitment(block)
        block.set_auxpow_version(True)
        block.auxpow = make_auxpow(block.hash_hex, block.nBits, b"")
        return block

    def run_test(self):
        node = self.nodes[0]
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        coinbase_value = tmpl["coinbasevalue"]
        tip = node.getbestblockhash()
        tip_time = node.getblock(tip)["time"]

        self.log.info("Weight failure for one proof leaves the header acceptable")
        first = self.make_block(int(tip, 16), 1, tip_time + 1, coinbase_value)
        heavy = block_with_proof(first, proof_for_stripped_size(first, 1_500_000))
        assert_equal(len(heavy.serialize(with_witness=False)), 1_500_000)
        assert heavy.get_weight() > MAX_BLOCK_WEIGHT
        node.submitheader(CBlockHeader(first).serialize().hex())
        assert_equal(node.submitblock(heavy.serialize().hex()), "bad-blk-weight")
        assert_equal(node.submitblock(first.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), first.hash_hex)

        self.log.info("Importing a bad parent proof and an oversized proof does not retire the headers")
        second = self.make_block(first.hash_int, 2, tip_time + 2, coinbase_value)
        third = self.make_block(second.hash_int, 3, tip_time + 3, coinbase_value)
        node.submitheader(CBlockHeader(second).serialize().hex())
        node.submitheader(CBlockHeader(third).serialize().hex())

        bad_parent = CBlock(second)
        bad_parent.vtx = second.vtx
        target = b"%064x" % uint256_from_compact(second.nBits)
        bad_parent.auxpow = CAuxPow()
        bad_parent.auxpow.deserialize(BytesIO(bytes.fromhex(computeAuxpow(second.hash_hex, target, False))))

        oversized = block_with_proof(third, proof_for_stripped_size(third, 1_500_001))
        assert_equal(len(oversized.serialize(with_witness=False)) * 4 > MAX_BLOCK_WEIGHT, True)

        bootstrap = Path(self.options.tmpdir) / "auxpow-bad-proofs.dat"
        write_blocks(bootstrap, [bad_parent, oversized])
        self.restart_node(0, extra_args=[f"-loadblock={bootstrap}"])
        node = self.nodes[0]

        assert_equal(node.submitblock(second.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), second.hash_hex)
        assert_equal(node.submitblock(third.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), third.hash_hex)


if __name__ == "__main__":
    AuxpowAlternateProofTest(__file__).main()
