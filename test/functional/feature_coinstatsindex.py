#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test coinstatsindex across nodes.

Test that the values returned by gettxoutsetinfo are consistent
between a node running the coinstatsindex and a node without
the index.
"""

from decimal import Decimal

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
    _tidecoin_subsidy,
    TIDECOIN_SUBSIDY_INTERVAL,
)
from test_framework.messages import (
    COIN,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_FALSE,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_not_equal,
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    getnewdestination,
)


class CoinStatsIndexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            [],
            ["-coinstatsindex"]
        ]

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self._test_coin_stats_index()
        self._test_use_index_option()
        self._test_reorg_index()
        self._test_index_rejects_hash_serialized()
        self._test_init_index_after_reorg()

    def _subsidy(self, height):
        return Decimal(_tidecoin_subsidy(height, TIDECOIN_SUBSIDY_INTERVAL)) / COIN

    def block_sanity_check(self, block_info, *, height):
        block_subsidy = self._subsidy(height)
        assert_equal(
            block_info['prevout_spent'] + block_subsidy,
            block_info['new_outputs_ex_coinbase'] + block_info['coinbase'] + block_info['unspendable']
        )

    def sync_index_node(self):
        self.wait_until(lambda: self.nodes[1].getindexinfo()['coinstatsindex']['synced'] is True)

    def set_mocktime_after_blocks(self, node, *blocks):
        """Set mocktime after both the active tip and the provided stale blocks."""
        block_times = [node.getblockheader(node.getbestblockhash())["time"]]
        block_times.extend(node.getblockheader(block)["time"] for block in blocks)
        node.setmocktime(max(block_times) + 1)

    def _test_coin_stats_index(self):
        node = self.nodes[0]
        index_node = self.nodes[1]
        # Both none and muhash options allow the usage of the index
        index_hash_options = ['none', 'muhash']

        # Generate a normal transaction and mine it
        self.generate(self.wallet, COINBASE_MATURITY + 1)
        self_tx = self.wallet.send_self_transfer(from_node=node)
        self_tx_fee = node.getmempoolentry(self_tx["txid"])["fees"]["base"]
        self_tx_output_sum = sum(v["value"] for v in node.decoderawtransaction(self_tx["hex"])["vout"])
        self_tx_prevout_spent = self_tx_output_sum + self_tx_fee
        self.generate(node, 1)

        self.log.info("Test that gettxoutsetinfo() output is consistent with or without coinstatsindex option")
        res0 = node.gettxoutsetinfo('none')

        # The fields 'disk_size' and 'transactions' do not exist on the index
        del res0['disk_size'], res0['transactions']

        for hash_option in index_hash_options:
            res1 = index_node.gettxoutsetinfo(hash_option)
            # The fields 'block_info' and 'total_unspendable_amount' only exist on the index
            del res1['block_info'], res1['total_unspendable_amount']
            res1.pop('muhash', None)

            # Everything left should be the same
            assert_equal(res1, res0)

        self.log.info("Test that gettxoutsetinfo() can get fetch data on specific heights with index")

        # Generate a new tip
        self.generate(node, 5)

        for hash_option in index_hash_options:
            # Fetch old stats by height
            res2 = index_node.gettxoutsetinfo(hash_option, 102)
            del res2['block_info'], res2['total_unspendable_amount']
            res2.pop('muhash', None)
            assert_equal(res0, res2)

            # Fetch old stats by hash
            res3 = index_node.gettxoutsetinfo(hash_option, self.convert_to_json_for_cli(res0['bestblock']))
            del res3['block_info'], res3['total_unspendable_amount']
            res3.pop('muhash', None)
            assert_equal(res0, res3)

            # It does not work without coinstatsindex
            assert_raises_rpc_error(-8, "Querying specific block heights requires coinstatsindex", node.gettxoutsetinfo, hash_option, 102)

        self.log.info("Test gettxoutsetinfo() with index and verbose flag")

        for hash_option in index_hash_options:
            # Genesis block is unspendable
            genesis_subsidy = self._subsidy(0)
            res4 = index_node.gettxoutsetinfo(hash_option, 0)
            assert_equal(res4['total_unspendable_amount'], genesis_subsidy)
            assert_equal(res4['block_info'], {
                'unspendable': genesis_subsidy,
                'prevout_spent': 0,
                'new_outputs_ex_coinbase': 0,
                'coinbase': 0,
                'unspendables': {
                    'genesis_block': genesis_subsidy,
                    'bip30': 0,
                    'scripts': 0,
                    'unclaimed_rewards': 0
                }
            })
            self.block_sanity_check(res4['block_info'], height=0)

            # Test an older block height that included a normal tx
            res5 = index_node.gettxoutsetinfo(hash_option, 102)
            subsidy_102 = self._subsidy(102)
            assert_equal(res5['total_unspendable_amount'], genesis_subsidy)
            assert_equal(res5['block_info'], {
                'unspendable': 0,
                'prevout_spent': self_tx_prevout_spent,
                'new_outputs_ex_coinbase': self_tx_output_sum,
                'coinbase': subsidy_102 + self_tx_fee,
                'unspendables': {
                    'genesis_block': 0,
                    'bip30': 0,
                    'scripts': 0,
                    'unclaimed_rewards': 0,
                }
            })
            self.block_sanity_check(res5['block_info'], height=102)

        # Generate and send a normal tx with two outputs
        tx1 = self.wallet.send_to(
            from_node=node,
            scriptPubKey=self.wallet.get_output_script(),
            amount=21 * COIN,
        )
        tx1_fee = node.getmempoolentry(tx1["txid"])["fees"]["base"]
        tx1_output_sum = sum(v["value"] for v in node.decoderawtransaction(tx1["hex"])["vout"])

        # Find the right position of the 21 BTC output
        tx1_out_21 = self.wallet.get_utxo(txid=tx1["txid"], vout=tx1["sent_vout"])

        # Generate and send another tx with an OP_RETURN output (which is unspendable)
        tx2 = self.wallet.create_self_transfer(utxo_to_spend=tx1_out_21)['tx']
        tx2_val = '20.99'
        tx2.vout = [CTxOut(int(Decimal(tx2_val) * COIN), CScript([OP_RETURN] + [OP_FALSE] * 30))]
        tx2_hex = tx2.serialize().hex()
        tx2_txid = self.nodes[0].sendrawtransaction(tx2_hex, 0, tx2_val)
        tx2_fee = self.nodes[0].getmempoolentry(tx2_txid)["fees"]["base"]
        tx2_output_sum = sum(v["value"] for v in self.nodes[0].decoderawtransaction(tx2_hex)["vout"])
        unspendable_scripts = Decimal(tx2_val)

        # Include both txs in a block
        self.generate(self.nodes[0], 1)

        for hash_option in index_hash_options:
            # Check all amounts were registered correctly
            subsidy_108 = self._subsidy(108)
            total_fees = tx1_fee + tx2_fee
            prevout_spent = tx1_output_sum + tx1_fee + tx2_output_sum + tx2_fee
            outputs_ex_coinbase = tx1_output_sum + tx2_output_sum
            new_outputs_ex_coinbase = outputs_ex_coinbase - unspendable_scripts
            res6 = index_node.gettxoutsetinfo(hash_option, 108)
            assert_equal(res6['total_unspendable_amount'], genesis_subsidy + unspendable_scripts)
            assert_equal(res6['block_info'], {
                'unspendable': unspendable_scripts,
                'prevout_spent': prevout_spent,
                'new_outputs_ex_coinbase': new_outputs_ex_coinbase,
                'coinbase': subsidy_108 + total_fees,
                'unspendables': {
                    'genesis_block': 0,
                    'bip30': 0,
                    'scripts': unspendable_scripts,
                    'unclaimed_rewards': 0,
                }
            })
            self.block_sanity_check(res6['block_info'], height=108)

        # Create a coinbase that does not claim full subsidy and also
        # has two outputs
        subsidy_109_sat = _tidecoin_subsidy(109, TIDECOIN_SUBSIDY_INTERVAL)
        unclaimed_sat = subsidy_109_sat // 4
        extra_output_sat = subsidy_109_sat // 2
        main_output_sat = subsidy_109_sat - unclaimed_sat - extra_output_sat
        cb = create_coinbase(109)
        cb.vout[0].nValue = int(main_output_sat)
        cb.vout.append(CTxOut(int(extra_output_sat), CScript([OP_FALSE])))

        # Generate a block that includes previous coinbase
        tip = self.nodes[0].getbestblockhash()
        block_time = self.nodes[0].getblock(tip)['time'] + 1
        block = create_block(int(tip, 16), cb, block_time)
        block.solve()
        self.nodes[0].submitblock(block.serialize().hex())
        self.sync_all()

        for hash_option in index_hash_options:
            unclaimed_rewards = Decimal(unclaimed_sat) / COIN
            coinbase_value = Decimal(main_output_sat + extra_output_sat) / COIN
            res7 = index_node.gettxoutsetinfo(hash_option, 109)
            assert_equal(res7['total_unspendable_amount'], genesis_subsidy + unspendable_scripts + unclaimed_rewards)
            assert_equal(res7['block_info'], {
                'unspendable': unclaimed_rewards,
                'prevout_spent': 0,
                'new_outputs_ex_coinbase': 0,
                'coinbase': coinbase_value,
                'unspendables': {
                    'genesis_block': 0,
                    'bip30': 0,
                    'scripts': 0,
                    'unclaimed_rewards': unclaimed_rewards
                }
            })
            self.block_sanity_check(res7['block_info'], height=109)

        self.log.info("Test that the index is robust across restarts")

        res8 = index_node.gettxoutsetinfo('muhash')
        self.restart_node(1, extra_args=self.extra_args[1])
        res9 = index_node.gettxoutsetinfo('muhash')
        assert_equal(res8, res9)

        self.generate(index_node, 1, sync_fun=self.no_op)
        res10 = index_node.gettxoutsetinfo('muhash')
        assert res8['txouts'] < res10['txouts']

        self.log.info("Test that the index works with -reindex")

        self.restart_node(1, extra_args=["-coinstatsindex", "-reindex"])
        self.sync_index_node()
        res11 = index_node.gettxoutsetinfo('muhash')
        assert_equal(res11, res10)

        self.log.info("Test that the index works with -reindex-chainstate")

        self.restart_node(1, extra_args=["-coinstatsindex", "-reindex-chainstate"])
        self.sync_index_node()
        res12 = index_node.gettxoutsetinfo('muhash')
        assert_equal(res12, res10)

        self.log.info("Test obtaining info for a non-existent block hash")
        assert_raises_rpc_error(-5, "Block not found", index_node.gettxoutsetinfo, hash_type="none", hash_or_height=self.convert_to_json_for_cli("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), use_index=True)

    def _test_use_index_option(self):
        self.log.info("Test use_index option for nodes running the index")

        self.connect_nodes(0, 1)
        self.nodes[0].waitforblockheight(110)
        res = self.nodes[0].gettxoutsetinfo('muhash')
        option_res = self.nodes[1].gettxoutsetinfo(hash_type='muhash', hash_or_height=None, use_index=False)
        del res['disk_size'], option_res['disk_size']
        assert_equal(res, option_res)

    def _test_reorg_index(self):
        self.log.info("Test that index can handle reorgs")

        # Generate two block, let the index catch up, then invalidate the blocks
        index_node = self.nodes[1]
        reorg_blocks = self.generatetoaddress(index_node, 2, getnewdestination()[2])
        reorg_block = reorg_blocks[1]
        self.sync_index_node()
        res_invalid = index_node.gettxoutsetinfo('muhash')
        index_node.invalidateblock(reorg_blocks[0])
        assert_equal(index_node.gettxoutsetinfo('muhash')['height'], 110)

        # Add two new blocks
        block = self.generate(index_node, 2, sync_fun=self.no_op)[1]
        res = index_node.gettxoutsetinfo(hash_type='muhash', hash_or_height=None, use_index=False)

        # Test that the result of the reorged block is not returned for its old block height
        res2 = index_node.gettxoutsetinfo(hash_type='muhash', hash_or_height=112)
        assert_equal(res["bestblock"], block)
        assert_equal(res["muhash"], res2["muhash"])
        assert_not_equal(res["muhash"], res_invalid["muhash"])

        # Test that requesting reorged out block by hash is still returning correct results
        res_invalid2 = index_node.gettxoutsetinfo(hash_type='muhash', hash_or_height=self.convert_to_json_for_cli(reorg_block))
        assert_equal(res_invalid2["muhash"], res_invalid["muhash"])
        assert_not_equal(res["muhash"], res_invalid2["muhash"])

        # Add another block, so we don't depend on reconsiderblock remembering which
        # blocks were touched by invalidateblock
        self.generate(index_node, 1)

        # Ensure that removing and re-adding blocks yields consistent results
        block = index_node.getblockhash(99)
        index_node.invalidateblock(block)
        index_node.reconsiderblock(block)
        res3 = index_node.gettxoutsetinfo(hash_type='muhash', hash_or_height=112)
        assert_equal(res2, res3)

    def _test_index_rejects_hash_serialized(self):
        self.log.info("Test that the rpc raises if the legacy hash is passed with the index")

        msg = "hash_serialized_3 hash type cannot be queried for a specific block"
        assert_raises_rpc_error(-8, msg, self.nodes[1].gettxoutsetinfo, hash_type='hash_serialized_3', hash_or_height=111)

        for use_index in {True, False, None}:
            assert_raises_rpc_error(-8, msg, self.nodes[1].gettxoutsetinfo, hash_type='hash_serialized_3', hash_or_height=111, use_index=use_index)

    def _test_init_index_after_reorg(self):
        self.log.info("Test a reorg while the index is deactivated")
        index_node = self.nodes[1]
        block = self.nodes[0].getbestblockhash()
        self.generate(index_node, 2, sync_fun=self.no_op)
        self.sync_index_node()

        # Restart without index
        self.restart_node(1, extra_args=[])
        self.connect_nodes(0, 1)
        index_node.invalidateblock(block)
        self.set_mocktime_after_blocks(index_node, block)
        self.generatetoaddress(index_node, 5, getnewdestination()[2])
        res = index_node.gettxoutsetinfo(hash_type='muhash', hash_or_height=None, use_index=False)

        # Restart with index that still has its best block on the old chain
        self.restart_node(1, extra_args=self.extra_args[1])
        self.sync_index_node()
        res1 = index_node.gettxoutsetinfo(hash_type='muhash', hash_or_height=None, use_index=True)
        assert_equal(res["muhash"], res1["muhash"])

        self.log.info("Test index with an unclean restart after a reorg")
        self.restart_node(1, extra_args=self.extra_args[1])
        committed_height = index_node.getblockcount()
        self.generate(index_node, 2, sync_fun=self.no_op)
        self.sync_index_node()
        block2 = index_node.getbestblockhash()
        index_node.invalidateblock(block2)
        self.set_mocktime_after_blocks(index_node, block2)
        self.generatetoaddress(index_node, 1, getnewdestination()[2], sync_fun=self.no_op)
        self.sync_index_node()
        index_node.kill_process()
        self.start_node(1, extra_args=self.extra_args[1])
        self.sync_index_node()
        # Because of the unclean shutdown above, indexes reset to the point we last committed them to disk.
        assert_equal(index_node.getindexinfo()['coinstatsindex']['best_block_height'], committed_height)
        index_node.setmocktime(0)


if __name__ == '__main__':
    CoinStatsIndexTest(__file__).main()
