#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the generation of UTXO snapshots using `dumptxoutset`.
"""

import hashlib
import os
import select
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet
from test_framework.util import (
    assert_equal,
    get_rpc_proxy,
    rpc_url,
    assert_raises_rpc_error,
    sha256sum_file,
)


class DumptxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.uses_wallet = None  # Exercise signed PQ undo when wallet support is available.

    def check_expected_network(self, node, active):
        rev_file = node.blocks_path / "rev00000.dat"
        bogus_file = node.blocks_path / "bogus.dat"
        rev_file.rename(bogus_file)
        tip = node.getbestblockhash()
        tips = node.getchaintips()
        try:
            assert_raises_rpc_error(
                -32603, 'Failed to roll back block at height', node.dumptxoutset, 'utxos.dat', rollback=99)
            assert_equal(node.getnetworkinfo()['networkactive'], active)
            assert_equal(node.getbestblockhash(), tip)
            assert_equal(node.getchaintips(), tips)
            assert not (node.chain_path / 'utxos.dat').exists()
            assert_equal(list(node.chain_path.glob('temp_utxo_*')), [])
        finally:
            bogus_file.rename(rev_file)

    def test_dumptxoutset_with_fork(self):
        # Adapted from upstream's stale-fork regression: exporting must not
        # activate a sibling branch instead of stopping at the requested block.
        node = self.nodes[0]
        self.generate(MiniWallet(node), COINBASE_MATURITY + 1)
        tip = node.getbestblockhash()
        target_height = COINBASE_MATURITY
        target_hash = node.getblockhash(target_height)
        invalid_block = node.getblockhash(target_height + 1)
        node.invalidateblock(invalid_block)
        node.setmocktime(0)
        self.generate(node, 2)
        node.reconsiderblock(invalid_block)
        self.wait_until(lambda: node.getbestblockhash() == tip)

        mini = MiniWallet(node)
        mini.send_self_transfer(from_node=node)
        before_pool = node.getrawmempool(mempool_sequence=True)
        before_tips = node.getchaintips()
        before_utxos = node.gettxoutsetinfo()['hash_serialized_3']
        # Leave a preexisting directory using the original upstream naming
        # convention. Export must neither reuse nor remove it.
        leftover = node.chain_path / f'temp_utxo_{target_height}'
        leftover.mkdir()
        marker = leftover / 'keep'
        marker.write_text('preexisting data')
        for network_active in [True, False]:
            node.setnetworkactive(network_active)
            filename = f'txoutset_fork_{network_active}.dat'
            out = node.dumptxoutset(filename, 'rollback', {'rollback': target_height})
            assert_equal(out['base_height'], target_height)
            assert_equal(out['base_hash'], target_hash)
            assert_equal(sha256sum_file(node.chain_path / filename), sha256sum_file(node.chain_path / 'txoutset.dat'))
            assert_equal(node.getbestblockhash(), tip)
            assert_equal(node.getchaintips(), before_tips)
            assert_equal(node.getrawmempool(mempool_sequence=True), before_pool)
            assert_equal(node.gettxoutsetinfo()['hash_serialized_3'], before_utxos)
            assert_equal(node.getnetworkinfo()['networkactive'], network_active)
            assert_equal(list(node.chain_path.glob('temp_utxo_*')), [leftover])
            assert_equal(marker.read_text(), 'preexisting data')
        marker.unlink()
        leftover.rmdir()
        node.setnetworkactive(True)
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.gettxoutsetinfo()['hash_serialized_3'], before_utxos)
        assert_equal(set(node.getrawmempool()), set(before_pool['txids']))

    def test_signed_pq_undo(self):
        if not self.is_wallet_compiled():
            self.log.info('Skipping signed PQ undo check without wallet support')
            return
        node = self.nodes[0]
        node.createwallet('snapshot-pq')
        wallet = node.get_wallet_rpc('snapshot-pq')
        mini = MiniWallet(node)
        funded = []
        for scheme in ['falcon512', 'falcon1024', 'mldsa44', 'mldsa65', 'mldsa87']:
            address = wallet.getnewaddress('', 'bech32pq', scheme)
            coin = mini.send_to(from_node=node,
                                scriptPubKey=bytes.fromhex(node.validateaddress(address)['scriptPubKey']),
                                amount=1000000)
            funded.append((address, coin))
        self.generate(mini, 1)
        expected = node.dumptxoutset('pq-reference.dat', 'latest')
        for address, coin in funded:
            raw = node.createrawtransaction([{'txid': coin['txid'], 'vout': coin['sent_vout']}],
                                            [{address: Decimal('0.0099')}])
            signed = wallet.signrawtransactionwithwallet(raw)
            assert signed['complete']
            node.sendrawtransaction(signed['hex'], 0)
        self.generate(mini, 2)
        tip = node.getbestblockhash()
        result = node.dumptxoutset('pq-rollback.dat', rollback=expected['base_height'])
        assert_equal(result['txoutset_hash'], expected['txoutset_hash'])
        assert_equal(sha256sum_file(node.chain_path / 'pq-reference.dat'),
                     sha256sum_file(node.chain_path / 'pq-rollback.dat'))
        assert_equal(node.getbestblockhash(), tip)
        wallet.unloadwallet()

    def test_pruning_during_export(self):
        # Use a small pipe to hold the exporter in its final write phase without
        # a production-only test hook. Other RPCs use a separate connection.
        if os.name != 'posix':
            self.log.info('Skipping FIFO concurrency check on this platform')
            return
        import fcntl
        if not hasattr(fcntl, 'F_SETPIPE_SZ'):
            self.log.info('Skipping controlled pipe-capacity check on this platform')
            return
        node = self.nodes[0]
        self.restart_node(0, extra_args=['-prune=1', '-fastprune'])
        self.generate(node, 600 - node.getblockcount())
        expected = node.dumptxoutset('prune-reference.dat', 'latest')
        expected_hash = sha256sum_file(node.chain_path / 'prune-reference.dat')
        self.generate(node, 500)
        tip = node.getbestblockhash()
        required_hash = node.getblockhash(601)
        output = node.chain_path / 'prune-export.dat'
        pipe = node.chain_path / 'prune-export.dat.incomplete'
        os.mkfifo(pipe)
        reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
        fcntl.fcntl(reader, fcntl.F_SETPIPE_SZ, 4096)
        data = bytearray()
        rpc = get_rpc_proxy(rpc_url(node.datadir_path, node.index, node.chain, node.rpchost), node.index, timeout=120)
        try:
            with ThreadPoolExecutor(max_workers=1) as threads:
                future = threads.submit(rpc.dumptxoutset, str(output), 'rollback', {'rollback': 600})
                try:
                    self.wait_until(lambda: bool(select.select([reader], [], [], 0)[0]))
                    assert not future.done()
                    assert_equal(node.getbestblockhash(), tip)
                    assert_equal(node.getnetworkinfo()['networkactive'], True)
                    assert_raises_rpc_error(-1, 'UTXO snapshot export already in progress',
                                            node.dumptxoutset, 'concurrent.dat', 'latest')
                    assert node.pruneblockchain(900) < 600
                    node.getblock(required_hash)  # Still protected by export's prune lock.
                finally:
                    # Drain on assertion failure too, so the RPC worker can exit.
                    while True:
                        if select.select([reader], [], [], 1)[0]:
                            chunk = os.read(reader, 65536)
                            if not chunk:
                                break
                            data.extend(chunk)
                        elif future.done():
                            break
                result = future.result(timeout=120)
        finally:
            os.close(reader)
        assert_equal(result['txoutset_hash'], expected['txoutset_hash'])
        assert_equal(hashlib.sha256(data).digest(), expected_hash)
        assert_equal(list(node.chain_path.glob('temp_utxo_*')), [])
        output.unlink()  # Completed output is the FIFO used only by this test.
        assert node.pruneblockchain(900) >= 601  # Lock must have been released.
        assert_raises_rpc_error(-1, 'Block not available (pruned data)', node.getblock, required_hash)
        assert_raises_rpc_error(-1, 'necessary block data is already pruned',
                                node.dumptxoutset, 'pruned.dat', rollback=600)
        assert not (node.chain_path / 'pruned.dat').exists()
        assert_equal(list(node.chain_path.glob('temp_utxo_*')), [])
        assert_equal(node.getbestblockhash(), tip)

    def run_test(self):
        """Test a trivial usage of the dumptxoutset RPC command."""
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)
        self.generate(node, COINBASE_MATURITY)

        FILENAME = 'txoutset.dat'
        out = node.dumptxoutset(FILENAME, "latest")
        expected_path = node.chain_path / FILENAME

        assert expected_path.is_file()

        assert_equal(out['coins_written'], 100)
        assert_equal(out['base_height'], 100)
        assert_equal(out['path'], str(expected_path))
        # Blockhash should be deterministic based on mocked time.
        assert_equal(
            out['base_hash'],
            '3c2bc3358eb6fd398f4d55bfbd31e07f6b5aa7f02b6829a1bef964d31c9bd425')

        # UTXO snapshot hash should be deterministic based on mocked time.
        assert_equal(
            sha256sum_file(str(expected_path)).hex(),
            'a274b560a96f91aefe24051f91ceb77a8b6d9a25d6c1e9ab623b04c26939be5c')

        assert_equal(
            out['txoutset_hash'], '222a2795892e49129b221e52fd93f1e9e82d4a8e1ea1357de45698cbf81b4e04')
        assert_equal(out['nchaintx'], 101)

        # Specifying a path to an existing or invalid file will fail.
        assert_raises_rpc_error(
            -8, '{} already exists'.format(FILENAME),  node.dumptxoutset, FILENAME, "latest")
        invalid_path = node.datadir_path / "invalid" / "path"
        assert_raises_rpc_error(
            -8, "Couldn't open file {}.incomplete for writing".format(invalid_path), node.dumptxoutset, invalid_path, "latest")

        self.log.info("Test that dumptxoutset with unknown dump type fails")
        assert_raises_rpc_error(
            -8, 'Invalid snapshot type "bogus" specified. Please specify "rollback" or "latest"', node.dumptxoutset, 'utxos.dat', "bogus")

        self.log.info("Test that dumptxoutset failure does not leave the network activity suspended when it was on previously")
        self.check_expected_network(node, True)

        self.log.info("Test that dumptxoutset failure leaves the network activity suspended when it was off")
        node.setnetworkactive(False)
        self.check_expected_network(node, False)
        node.setnetworkactive(True)
        self.test_dumptxoutset_with_fork()
        self.test_signed_pq_undo()
        self.test_pruning_during_export()


if __name__ == '__main__':
    DumptxoutsetTest(__file__).main()
