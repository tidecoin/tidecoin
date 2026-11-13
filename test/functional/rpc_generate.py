#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test generate* RPCs."""

from concurrent.futures import ThreadPoolExecutor

from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import descsum_create
from test_framework.wallet import MiniWallet
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import generate_keypair


class RPCGenerateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.test_generatetoaddress()
        self.test_maxtries()
        self.test_generate()
        self.test_generateblock()

    def test_generatetoaddress(self):
        valid_addr = MiniWallet(self.nodes[0]).get_address()
        self.generatetoaddress(self.nodes[0], 1, valid_addr)
        assert_raises_rpc_error(-5, "Invalid address", self.generatetoaddress, self.nodes[0], 1, '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')

    def test_maxtries(self):
        self.log.info('Both mining RPCs validate the full unsigned 64-bit attempt budget before mining')
        node = self.nodes[0]
        address = MiniWallet(node).get_address()
        for generate, destination in [(self.generatetoaddress, address), (self.generatetodescriptor, f'addr({address})')]:
            tip = node.getbestblockhash()
            for invalid in [-1, -(2**63), 2**64, 1.5]:
                assert_raises_rpc_error(-1, 'JSON integer out of range', generate, node, 1, destination, invalid)
                assert_equal(node.getbestblockhash(), tip)
            assert_equal(generate(node, 1, destination, 0), [])
            assert_equal(node.getbestblockhash(), tip)
            # Exercise range boundaries without attempting that many hashes.
            for budget in [1, 2**31 - 1, 2**31, 2**63 - 1, 2**63, 2**64 - 1]:
                assert_equal(generate(node, 0, destination, budget), [])
                assert_equal(node.getbestblockhash(), tip)
            # A small budget may or may not solve this template; it must not
            # produce more than the requested block, and zero above produces none.
            height = node.getblockcount()
            hashes = generate(node, 1, destination, 1)
            assert len(hashes) <= 1
            assert_equal(node.getblockcount(), height + len(hashes))
            if hashes:
                assert_equal(node.getbestblockhash(), hashes[0])
            assert_equal(len(generate(node, 1, destination)), 1)

    def test_generateblock(self):
        node = self.nodes[0]
        miniwallet = MiniWallet(node)

        self.log.info('Mine an empty block to address and return the hex')
        address = miniwallet.get_address()
        generated_block = self.generateblock(node, output=address, transactions=[], submit=False)
        node.submitblock(hexdata=generated_block['hex'])
        assert_equal(generated_block['hash'], node.getbestblockhash())

        self.log.info('Generate an empty block to address')
        hash = self.generateblock(node, output=address, transactions=[])['hash']
        block = node.getblock(blockhash=hash, verbose=2)
        assert_equal(len(block['tx']), 1)
        assert_equal(block['tx'][0]['vout'][0]['scriptPubKey']['address'], address)

        self.log.info('Generate an empty block to a descriptor')
        hash = self.generateblock(node, 'addr(' + address + ')', [])['hash']
        block = node.getblock(blockhash=hash, verbosity=2)
        assert_equal(len(block['tx']), 1)
        assert_equal(block['tx'][0]['vout'][0]['scriptPubKey']['address'], address)

        self.log.info('Generate an empty block to a combo descriptor with PQ key')
        combo_privkey, _ = generate_keypair(wif=True)
        combo_desc = descsum_create(f"combo({combo_privkey})")
        # combo() derives [pkh, wpkh, sh(wpkh)] while generateblock uses the
        # witness form when multiple destinations are available.
        combo_address = node.deriveaddresses(combo_desc)[1]
        hash = self.generateblock(node, combo_desc, [])['hash']
        block = node.getblock(hash, 2)
        assert_equal(len(block['tx']), 1)
        assert_equal(block['tx'][0]['vout'][0]['scriptPubKey']['address'], combo_address)

        # Generate some extra mempool transactions to verify they don't get mined
        for _ in range(10):
            miniwallet.send_self_transfer(from_node=node)

        self.log.info('Generate block with txid')
        txid = miniwallet.send_self_transfer(from_node=node)['txid']
        hash = self.generateblock(node, address, [txid])['hash']
        block = node.getblock(hash, 1)
        assert_equal(len(block['tx']), 2)
        assert_equal(block['tx'][1], txid)

        self.log.info('Generate block with raw tx')
        rawtx = miniwallet.create_self_transfer()['hex']
        hash = self.generateblock(node, address, [rawtx])['hash']

        block = node.getblock(hash, 1)
        assert_equal(len(block['tx']), 2)
        txid = block['tx'][1]
        assert_equal(node.getrawtransaction(txid=txid, verbose=False, blockhash=hash), rawtx)

        # Ensure that generateblock can be called concurrently by many threads.
        self.log.info('Generate blocks in parallel')
        generate_50_blocks = lambda n: [n.generateblock(output=address, transactions=[]) for _ in range(50)]
        rpcs = [node.cli for _ in range(6)]
        with ThreadPoolExecutor(max_workers=len(rpcs)) as threads:
            list(threads.map(generate_50_blocks, rpcs))

        self.log.info('Fail to generate block with out of order txs')
        txid1 = miniwallet.send_self_transfer(from_node=node)['txid']
        utxo1 = miniwallet.get_utxo(txid=txid1)
        rawtx2 = miniwallet.create_self_transfer(utxo_to_spend=utxo1)['hex']
        assert_raises_rpc_error(-25, 'TestBlockValidity failed: bad-txns-inputs-missingorspent', self.generateblock, node, address, [rawtx2, txid1])

        self.log.info('Fail to generate block with txid not in mempool')
        missing_txid = '0000000000000000000000000000000000000000000000000000000000000000'
        assert_raises_rpc_error(-5, 'Transaction ' + missing_txid + ' not in mempool.', self.generateblock, node, address, [missing_txid])

        self.log.info('Fail to generate block with invalid raw tx')
        invalid_raw_tx = '0000'
        assert_raises_rpc_error(-22, 'Transaction decode failed for ' + invalid_raw_tx, self.generateblock, node, address, [invalid_raw_tx])

        self.log.info('Fail to generate block with invalid address/descriptor')
        assert_raises_rpc_error(-5, 'Invalid address or descriptor', self.generateblock, node, '1234', [])

        self.log.info('Fail to generate block with a ranged descriptor')
        ranged_descriptor = descsum_create("wpkh(pqhd(" + ("00" * 32) + ")/10007h/6868h/7h/0h/0h/*h)")
        assert_raises_rpc_error(-8, 'Ranged descriptor not accepted. Maybe pass through deriveaddresses first?',
                                self.generateblock, node, ranged_descriptor, [])

    def test_generate(self):
        message = (
            "generate\n\n"
            "has been replaced by the -generate "
            "cli option. Refer to -help for more information.\n"
        )

        if not self.options.usecli:
            self.log.info("Test rpc generate raises with message to use cli option")
            assert_raises_rpc_error(-32601, message, self.nodes[0]._rpc.generate)

            self.log.info("Test rpc generate help prints message to use cli option")
            assert_equal(message, self.nodes[0].help("generate"))

        self.log.info("Test rpc generate is a hidden command not discoverable in general help")
        assert message not in self.nodes[0].help()


if __name__ == "__main__":
    RPCGenerateTest(__file__).main()
