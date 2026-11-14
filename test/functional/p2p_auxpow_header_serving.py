#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Bound AuxPoW header replies, continue both sync passes, and handle unavailable proofs."""

import http.client
import time
from urllib.parse import urlsplit

from auxpow_alternate_proof import make_auxpow
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CBlock, CBlockHeader, from_hex, msg_getheaders, msg_headers, msg_sendheaders
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class HeaderPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.announced = set()
        self.header_sizes = []

    def on_inv(self, message):
        # Observe announcements without requesting blocks automatically.
        self.announced.update(inv.hash for inv in message.inv)

    def on_headers(self, message):
        self.announced.update(header.hash_int for header in message.headers)
        self.header_sizes.append(len(message.serialize()))


class AuxpowHeaderServingTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--mixed-era", action="store_true", help="Include ordinary headers before activation")

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.activation_height = 3 if self.options.mixed_era else 1
        common = [f'-auxpowactivationheight={self.activation_height}', '-checkblockindex=1', '-rest']
        self.extra_args = [
            common + ['-blocksxor=0'],
            common + ['-minimumchainwork=0x100', '-prune=1', '-fastprune'],
            common + ['-minimumchainwork=0x100', '-whitelist=noban,in,out@127.0.0.1'],
        ]

    def setup_network(self):
        self.setup_nodes()  # Connect deliberately after building the large-proof chain.

    def rest(self, node, block_hash, extension, status):
        url = urlsplit(node.url)
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
        conn.request('GET', f'/rest/headers/{block_hash}.{extension}?count=1')
        response = conn.getresponse()
        body = response.read()
        conn.close()
        assert_equal(response.status, status)
        return body

    def request_headers(self, peer, previous, stop=0):
        with p2p_lock:
            peer.last_message.pop('headers', None)
        request = msg_getheaders()
        request.locator.vHave = [previous]
        request.hashstop = stop
        peer.send_and_ping(request)
        peer.wait_until(lambda: 'headers' in peer.last_message)
        with p2p_lock:
            return peer.last_message['headers']

    def run_test(self):
        source, pruned, receiver = self.nodes
        genesis = source.getblockhash(0)
        block_time = int(time.time())
        previous = int(genesis, 16)
        blocks = []
        if self.options.mixed_era:
            hashes = self.generatetodescriptor(source, 2, 'raw(6a)', sync_fun=lambda: None)
            blocks = [from_hex(CBlock(), source.getblock(h, 0)) for h in hashes]
            previous = blocks[-1].hash_int
            for block in blocks:
                receiver.submitheader(CBlockHeader(block).serialize().hex())
        for height in range(self.activation_height, 21):
            coinbase = create_coinbase(height)
            coinbase.vout[0].scriptPubKey = CScript([OP_RETURN])
            block = create_block(previous, coinbase, block_time + height)
            add_witness_commitment(block)
            block.set_auxpow_version(True)
            block.auxpow = make_auxpow(block.hash_hex, block.nBits, b'\x00' * 900_000)
            assert_equal(source.submitblock(block.serialize().hex()), None)
            blocks.append(block)
            previous = block.hash_int
        first = blocks[self.activation_height - 1]

        self.log.info('Header-only raw data is unavailable, including after restart')
        boundary = CBlockHeader(first)
        boundary.auxpow = make_auxpow(first.hash_hex, first.nBits, b'\x00' * 1_500_000)
        overhead = len(boundary.serialize()) - 1_500_000
        boundary.auxpow = make_auxpow(first.hash_hex, first.nBits, b'\x00' * (1_500_001 - overhead))
        assert_equal(len(boundary.serialize()), 1_500_001)
        assert_raises_rpc_error(-25, 'auxpow-header-too-large', receiver.submitheader, boundary.serialize().hex())
        assert_raises_rpc_error(-5, 'Block not found', receiver.getblockheader, first.hash_hex)
        boundary.auxpow = make_auxpow(first.hash_hex, first.nBits, b'\x00' * (1_500_000 - overhead))
        assert_equal(len(boundary.serialize()), 1_500_000)
        receiver.submitheader(boundary.serialize().hex())
        receiver.submitheader(CBlockHeader(first).serialize().hex())
        for restart in [False, True]:
            if restart:
                self.restart_node(2)
            assert_equal(receiver.getblockheader(first.hash_hex)['height'], self.activation_height)
            assert_raises_rpc_error(-1, 'not fully downloaded', receiver.getblockheader, first.hash_hex, False)
        self.log.info('A byte-full outbound peer is not mistaken for an exhausted low-work chain')
        # Already indexed headers bypass presync for this outbound peer. Their
        # work is still below the node's minimum, so byte fullness must prevent
        # the insufficient-work disconnect.
        batch = [CBlockHeader(b) for b in blocks[:9 if self.options.mixed_era else 7]]
        for header in batch:
            receiver.submitheader(header.serialize().hex())
        outbound = receiver.add_outbound_p2p_connection(HeaderPeer(), p2p_idx=0, connection_type="outbound-full-relay")
        outbound.send_and_ping(msg_headers(batch))
        assert outbound.is_connected
        assert_equal(receiver.getblockchaininfo()['headers'], 9 if self.options.mixed_era else 7)
        receiver.disconnect_p2ps()
        source.syncwithvalidationinterfacequeue()
        assert_equal(source.getblockheader(first.hash_hex, False), CBlockHeader(first).serialize().hex())
        for ext in ['bin', 'hex', 'json']:
            self.rest(source, first.hash_hex, ext, 200)

        self.log.info('A short-by-count reply is byte-full; pagination preserves continuity and hashStop')
        peer = source.add_p2p_connection(HeaderPeer())
        previous = int(genesis, 16)
        received = []
        for count in ([9, 7, 4] if self.options.mixed_era else [7, 7, 6]):
            reply = self.request_headers(peer, previous)
            assert_equal(len(reply.headers), count)
            assert len(reply.serialize()) <= 8_000_000
            for header in reply.headers:
                assert_equal(header.hashPrevBlock, previous)
                previous = header.hash_int
                received.append(previous)
        assert_equal(received, [b.hash_int for b in blocks])
        assert_equal(self.request_headers(peer, previous).headers, [])
        assert_equal(len(self.request_headers(peer, int(genesis, 16), blocks[1].hash_int).headers), 2)
        source.disconnect_p2ps()

        self.log.info('Reconnected blocks are announced, followed by bounded getheaders')
        source.invalidateblock(blocks[12].hash_hex)
        source.syncwithvalidationinterfacequeue()
        peer = source.add_p2p_connection(HeaderPeer())
        self.request_headers(peer, blocks[10].hash_int, blocks[11].hash_int)
        peer.send_and_ping(msg_sendheaders())
        with p2p_lock:
            peer.announced.clear()
            peer.header_sizes.clear()
        source.reconsiderblock(blocks[12].hash_hex)
        source.syncwithvalidationinterfacequeue()
        # Reconnection and the message thread run concurrently. Either one
        # oversized batch falls back to inv or smaller headers batches fit.
        # auxpow_announcement_size tests the byte-boundary decision directly.
        peer.wait_until(lambda: blocks[-1].hash_int in peer.announced)
        with p2p_lock:
            assert all(size < 6_000_000 for size in peer.header_sizes)
        assert_equal(len(self.request_headers(peer, blocks[11].hash_int).headers), 7)
        assert_equal(len(self.request_headers(peer, blocks[18].hash_int).headers), 1)
        source.disconnect_p2ps()

        self.log.info('A native peer completes both low-work passes across byte-full batches')
        # With two ordinary headers, sufficient work is reached in the second
        # byte-full batch; ordinary continuation then fetches the remaining four.
        released_height = 16 if self.options.mixed_era else 20
        with pruned.assert_debug_log(['Initial headers sync started', 'redownloading from height=0', f'releasing all at height={released_height}']):
            self.connect_nodes(1, 0)
            self.sync_blocks([source, pruned])
        assert_equal(pruned.getblockchaininfo()['headers'], 20)
        transport = 'v2' if self.options.v2transport else 'v1'
        assert_equal(pruned.getpeerinfo()[0]['transport_protocol_type'], transport)

        self.log.info('Read failures are errors, not successful raw or zero-filled responses')
        # Source block files deliberately have XOR disabled. Alter identity, then restore immediately.
        path = source.chain_path / 'blocks' / 'blk00000.dat'
        with open(path, 'r+b') as file:
            offset = file.read().index(CBlockHeader(first).serialize()[:80]) + 76
            file.seek(offset)
            original = file.read(1)
            file.seek(offset)
            file.write(bytes([original[0] ^ 1]))
            file.flush()
            try:
                assert_raises_rpc_error(-1, 'Error reading AuxPoW header', source.getblockheader, first.hash_hex, False)
                for ext in ['bin', 'hex']:
                    self.rest(source, first.hash_hex, ext, 500)
                self.rest(source, first.hash_hex, 'json', 200)
            finally:
                file.seek(offset)
                file.write(original)
                file.flush()

        self.log.info('Pruned source declines headers; a third node continues from a full-data source')
        self.generatetodescriptor(source, 300, 'raw(6a)', sync_fun=lambda: self.sync_blocks([source, pruned]))
        self.disconnect_nodes(1, 0)
        assert pruned.pruneblockchain(20) > 0
        for ext in ['bin', 'hex']:
            self.rest(pruned, first.hash_hex, ext, 404)
        self.rest(pruned, first.hash_hex, 'json', 200)
        assert_raises_rpc_error(-1, 'pruned data', pruned.getblockheader, first.hash_hex, False)
        assert_equal(pruned.getblockheader(genesis, False), source.getblockheader(genesis, False))
        with pruned.assert_debug_log(['Cannot serve headers']):
            self.connect_nodes(2, 1, wait_for_connect=False)
        self.wait_until(lambda: not receiver.getpeerinfo())
        # NoBan bypasses low-work presync here, exercising ordinary continuation and peer-state fullness.
        self.connect_nodes(2, 0)
        self.sync_blocks([source, receiver])
        assert_equal(receiver.getblockheader(first.hash_hex, False), CBlockHeader(first).serialize().hex())

        self.log.info('Oversized alternative proof never retires an already indexed child hash')
        oversized = CBlockHeader(first)
        oversized.auxpow = make_auxpow(first.hash_hex, first.nBits, b'\x00' * 1_500_000)
        assert len(oversized.serialize()) > 1_500_000
        assert_raises_rpc_error(-25, 'auxpow-header-too-large', source.submitheader, oversized.serialize().hex())
        peer = source.add_p2p_connection(HeaderPeer())
        peer.send_without_ping(msg_headers([oversized]))
        peer.wait_for_disconnect()
        source.disconnect_p2ps()
        self.restart_node(0)
        source.submitheader(CBlockHeader(first).serialize().hex())
        assert_equal(source.getblockheader(first.hash_hex)['height'], self.activation_height)


if __name__ == '__main__':
    AuxpowHeaderServingTest(__file__).main()
