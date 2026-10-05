#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test getblockstats rpc call
#

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import COIN, CTxOut
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet
from decimal import Decimal
import json
import os
import time

TESTSDIR = os.path.dirname(os.path.realpath(__file__))

class GetblockstatsTest(BitcoinTestFramework):

    start_height = 101
    max_stat_pos = 2

    def add_options(self, parser):
        parser.add_argument('--gen-test-data', dest='gen_test_data',
                            default=False, action='store_true',
                            help='Generate test data')
        parser.add_argument('--test-data', dest='test_data',
                            default='data/rpc_getblockstats.json',
                            action='store', metavar='FILE',
                            help='Test data file')

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def get_stats(self):
        return [self.nodes[0].getblockstats(hash_or_height=self.start_height + i) for i in range(self.max_stat_pos+1)]

    def generate_test_data(self, filename):
        self._prepare_chain_with_local_data()

        blocks = []
        tip = self.nodes[0].getbestblockhash()
        blockhash = None
        height = 0
        while tip != blockhash:
            blockhash = self.nodes[0].getblockhash(height)
            blocks.append(self.nodes[0].getblock(blockhash, 0))
            height += 1

        to_dump = {
            'blocks': blocks,
            'mocktime': self.mocktime,
            'stats': self.expected_stats,
        }
        with open(filename, 'w', encoding="utf8") as f:
            json.dump(to_dump, f, sort_keys=True, indent=2)

    def _prepare_chain_with_local_data(self):
        mocktime = int(time.time())
        self.mocktime = int(mocktime)
        self.nodes[0].setmocktime(mocktime)
        miniwallet = MiniWallet(self.nodes[0])

        self.nodes[0].generatetodescriptor(COINBASE_MATURITY + 1, miniwallet.get_descriptor(), called_by_framework=True)
        miniwallet.rescan_utxos()

        miniwallet.send_self_transfer(from_node=self.nodes[0], fee_rate=Decimal("0.001"))
        self.nodes[0].generatetodescriptor(1, miniwallet.get_descriptor(), called_by_framework=True)
        miniwallet.rescan_utxos()

        miniwallet.send_self_transfer(from_node=self.nodes[0], fee_rate=Decimal("0.001"))
        miniwallet.send_self_transfer(from_node=self.nodes[0], fee_rate=Decimal("0.002"))
        miniwallet.send_self_transfer(from_node=self.nodes[0], fee_rate=Decimal("0.003"))
        # Send to OP_RETURN output to test its exclusion from statistics
        opret_tx = miniwallet.create_self_transfer(fee_rate=Decimal("0.003"))["tx"]
        opret_tx.vout.append(CTxOut(0, CScript([OP_RETURN, bytes.fromhex("21")])))
        miniwallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=opret_tx.serialize().hex())
        self.sync_all()
        self.nodes[0].generatetodescriptor(1, miniwallet.get_descriptor(), called_by_framework=True)
        miniwallet.rescan_utxos()

        self.expected_stats = self.get_stats()

    def load_test_data(self, filename):
        with open(filename, 'r', encoding="utf8") as f:
            d = json.load(f)
            blocks = d['blocks']
            mocktime = d['mocktime']
            self.expected_stats = d['stats']

        # Set the timestamps from the file so that the nodes can get out of Initial Block Download
        self.nodes[0].setmocktime(mocktime)
        self.sync_all()

        for b in blocks:
            self.nodes[0].submitblock(b)

        return self.nodes[0].getblockcount()


    def check_utxo_size_estimates(self, tip):
        # Independent expectation from block outputs and spent prevouts. Coin height
        # and coinbase flag share four bytes; the outpoint contributes 32 + 4.
        overhead = 32 + 4 + 4
        unspent = {}
        for height in range(tip + 1):
            block = self.nodes[0].getblock(self.nodes[0].getblockhash(height), 2)
            total_size = actual_size = 0
            total_count = actual_count = 0
            for tx in block["tx"]:
                for txin in tx["vin"]:
                    if "coinbase" in txin:
                        continue
                    spent_size = unspent.pop((txin["txid"], txin["vout"]))
                    total_size -= spent_size
                    actual_size -= spent_size
                    total_count -= 1
                    actual_count -= 1
                for index, output in enumerate(tx["vout"]):
                    script = bytes.fromhex(output["scriptPubKey"]["hex"])
                    # This fixture uses small scripts, so only OP_RETURN is unspendable.
                    assert len(script) < 10000
                    size = len(CTxOut(int(output["value"] * COIN), script).serialize()) + overhead
                    total_size += size
                    total_count += 1
                    if height != 0 and not script.startswith(bytes([OP_RETURN])):
                        unspent[(tx["txid"], index)] = size
                        actual_size += size
                        actual_count += 1
            stats = self.nodes[0].getblockstats(height)
            assert_equal(stats["utxo_increase"], total_count)
            assert_equal(stats["utxo_increase_actual"], actual_count)
            assert_equal(stats["utxo_size_inc"], total_size)
            assert_equal(stats["utxo_size_inc_actual"], actual_size)

    def run_test(self):
        test_data = os.path.join(TESTSDIR, self.options.test_data)
        if self.options.gen_test_data:
            self.generate_test_data(test_data)
        else:
            loaded_tip = self.load_test_data(test_data)
            if loaded_tip < self.start_height + self.max_stat_pos:
                self.log.info("Fixture blocks are incompatible with this chain; generating local test data")
                self._prepare_chain_with_local_data()

        self.sync_all()
        stats = self.get_stats()

        # Make sure all valid statistics are included but nothing else is
        expected_keys = self.expected_stats[0].keys()
        assert_equal(set(stats[0].keys()), set(expected_keys))

        assert_equal(stats[0]['height'], self.start_height)
        assert_equal(stats[self.max_stat_pos]['height'], self.start_height + self.max_stat_pos)

        for i in range(self.max_stat_pos+1):
            self.log.info('Checking block %d' % (i))
            assert_equal(stats[i], self.expected_stats[i])

            # Check selecting block by hash too
            blockhash = self.expected_stats[i]['blockhash']
            stats_by_hash = self.nodes[0].getblockstats(hash_or_height=self.convert_to_json_for_cli(blockhash))
            assert_equal(stats_by_hash, self.expected_stats[i])

        # Make sure each stat can be queried on its own
        for stat in expected_keys:
            for i in range(self.max_stat_pos+1):
                result = self.nodes[0].getblockstats(hash_or_height=self.start_height + i, stats=[stat])
                assert_equal(list(result.keys()), [stat])
                if result[stat] != self.expected_stats[i][stat]:
                    self.log.info('result[%s] (%d) failed, %r != %r' % (
                        stat, i, result[stat], self.expected_stats[i][stat]))
                assert_equal(result[stat], self.expected_stats[i][stat])

        # Make sure only the selected statistics are included (more than one)
        some_stats = {'minfee', 'maxfee'}
        stats = self.nodes[0].getblockstats(hash_or_height=1, stats=list(some_stats))
        assert_equal(set(stats.keys()), some_stats)

        # Test invalid parameters raise the proper json exceptions
        tip = self.start_height + self.max_stat_pos
        assert_raises_rpc_error(-8, 'Target block height %d after current tip %d' % (tip+1, tip),
                                self.nodes[0].getblockstats, hash_or_height=tip+1)
        assert_raises_rpc_error(-8, 'Target block height %d is negative' % (-1),
                                self.nodes[0].getblockstats, hash_or_height=-1)

        # Make sure not valid stats aren't allowed
        inv_sel_stat = 'asdfghjkl'
        inv_stats = [
            [inv_sel_stat],
            ['minfee', inv_sel_stat],
            [inv_sel_stat, 'minfee'],
            ['minfee', inv_sel_stat, 'maxfee'],
        ]
        for inv_stat in inv_stats:
            assert_raises_rpc_error(-8, f"Invalid selected statistic '{inv_sel_stat}'",
                                    self.nodes[0].getblockstats, hash_or_height=1, stats=inv_stat)

        # Make sure we aren't always returning inv_sel_stat as the culprit stat
        assert_raises_rpc_error(-8, f"Invalid selected statistic 'aaa{inv_sel_stat}'",
                                self.nodes[0].getblockstats, hash_or_height=1, stats=['minfee', f'aaa{inv_sel_stat}'])
        # Mainchain's genesis block shouldn't be found on regtest
        assert_raises_rpc_error(-5, 'Block not found', self.nodes[0].getblockstats,
                                hash_or_height=self.convert_to_json_for_cli('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'))

        # Invalid number of args
        assert_raises_rpc_error(-1, 'getblockstats hash_or_height ( stats )', self.nodes[0].getblockstats, self.convert_to_json_for_cli('00'), 1, 2)
        assert_raises_rpc_error(-1, 'getblockstats hash_or_height ( stats )', self.nodes[0].getblockstats)

        self.check_utxo_size_estimates(tip)

        self.log.info('Test block height 0')
        genesis_stats = self.nodes[0].getblockstats(0)
        assert_equal(genesis_stats["blockhash"], self.nodes[0].getblockhash(0))
        assert_equal(genesis_stats["utxo_increase"], 1)
        assert genesis_stats["utxo_size_inc"] > 0
        assert_equal(genesis_stats["utxo_increase_actual"], 0)
        assert_equal(genesis_stats["utxo_size_inc_actual"], 0)

        self.log.info('Test tip including OP_RETURN')
        tip_stats = self.nodes[0].getblockstats(tip)
        assert tip_stats["utxo_increase"] > tip_stats["utxo_increase_actual"]
        assert tip_stats["utxo_size_inc"] > tip_stats["utxo_size_inc_actual"]

        self.log.info("Test when only header is known")
        block = self.generateblock(self.nodes[0], output="raw(55)", transactions=[], submit=False)
        self.nodes[0].submitheader(block["hex"])
        assert_raises_rpc_error(-1, "Block not available (not fully downloaded)", lambda: self.nodes[0].getblockstats(self.convert_to_json_for_cli(block['hash'])))

        self.log.info('Test when block is missing')
        (self.nodes[0].blocks_path / 'blk00000.dat').rename(self.nodes[0].blocks_path / 'blk00000.dat.backup')
        assert_raises_rpc_error(-1, 'Block not found on disk', self.nodes[0].getblockstats, hash_or_height=1)
        (self.nodes[0].blocks_path / 'blk00000.dat.backup').rename(self.nodes[0].blocks_path / 'blk00000.dat')


if __name__ == '__main__':
    GetblockstatsTest(__file__).main()
