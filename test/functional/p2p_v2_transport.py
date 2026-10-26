#!/usr/bin/env python3
# Copyright (c) 2021-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test v2 transport
"""
from io import BytesIO
import socket
import time

from test_framework.messages import MAGIC_BYTES, NODE_P2P_V2
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_not_equal,
    assert_equal,
    p2p_port,
    assert_raises_rpc_error
)
from test_framework.v2_p2p import EncryptedP2PState, KEM_CIPHERTEXT_LEN, KEM_PUBLIC_KEY_LEN


class V2TransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        self.extra_args = [["-v2transport=1"], ["-v2transport=1"], ["-v2transport=0"], ["-v2transport=0"], ["-v2transport=0"]]
        self.extra_args[0].append("-peertimeout=60")

    def run_test(self):
        sending_handshake = "start sending v2 handshake to peer"
        downgrading_to_v1 = "retrying with v1 transport protocol for peer"
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)
        self.disconnect_nodes(2, 3)
        self.disconnect_nodes(3, 4)

        self.test_outbound_handshake_info()

        # verify local services
        network_info = self.nodes[2].getnetworkinfo()
        assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V2, 0)
        assert "P2P_V2" not in network_info["localservicesnames"]
        network_info = self.nodes[1].getnetworkinfo()
        assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V2, NODE_P2P_V2)
        assert "P2P_V2" in network_info["localservicesnames"]

        # V2 nodes can sync with V2 nodes
        assert_equal(self.nodes[0].getblockcount(), 0)
        assert_equal(self.nodes[1].getblockcount(), 0)
        with self.nodes[0].assert_debug_log(expected_msgs=[sending_handshake],
                                            unexpected_msgs=[downgrading_to_v1]):
            self.connect_nodes(0, 1, peer_advertises_v2=True)
        self.generate(self.nodes[0], 5, sync_fun=lambda: self.sync_all(self.nodes[0:2]))
        assert_equal(self.nodes[1].getblockcount(), 5)
        # verify there is a v2 connection between node 0 and 1
        node_0_info = self.nodes[0].getpeerinfo()
        node_1_info = self.nodes[1].getpeerinfo()
        assert_equal(len(node_0_info), 1)
        assert_equal(len(node_1_info), 1)
        assert_equal(node_0_info[0]["transport_protocol_type"], "v2")
        assert_equal(node_1_info[0]["transport_protocol_type"], "v2")
        assert_equal(len(node_0_info[0]["session_id"]), 64)
        assert_equal(len(node_1_info[0]["session_id"]), 64)
        assert_equal(node_0_info[0]["session_id"], node_1_info[0]["session_id"])

        # V1 nodes can sync with each other
        assert_equal(self.nodes[2].getblockcount(), 0)
        assert_equal(self.nodes[3].getblockcount(), 0)

        # addnode rpc error when v2transport requested but not enabled
        ip_port = "127.0.0.1:{}".format(p2p_port(3))
        assert_raises_rpc_error(-8, "Error: v2transport requested but not enabled (see -v2transport)", self.nodes[2].addnode, node=ip_port, command='add', v2transport=True)

        with self.nodes[2].assert_debug_log(expected_msgs=[],
                                            unexpected_msgs=[sending_handshake, downgrading_to_v1]):
            self.connect_nodes(2, 3, peer_advertises_v2=False)
        self.generate(self.nodes[2], 8, sync_fun=lambda: self.sync_all(self.nodes[2:4]))
        assert_equal(self.nodes[3].getblockcount(), 8)
        assert_not_equal(self.nodes[0].getbestblockhash(), self.nodes[2].getbestblockhash())
        # verify there is a v1 connection between node 2 and 3
        node_2_info = self.nodes[2].getpeerinfo()
        node_3_info = self.nodes[3].getpeerinfo()
        assert_equal(len(node_2_info), 1)
        assert_equal(len(node_3_info), 1)
        assert_equal(node_2_info[0]["transport_protocol_type"], "v1")
        assert_equal(node_3_info[0]["transport_protocol_type"], "v1")
        assert_equal(len(node_2_info[0]["session_id"]), 0)
        assert_equal(len(node_3_info[0]["session_id"]), 0)

        # V1 nodes can sync with V2 nodes
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(2, 3)
        with self.nodes[2].assert_debug_log(expected_msgs=[],
                                            unexpected_msgs=[sending_handshake, downgrading_to_v1]):
            self.connect_nodes(2, 1, peer_advertises_v2=False) # cannot enable v2 on v1 node
        self.sync_all(self.nodes[1:3])
        assert_equal(self.nodes[1].getblockcount(), 8)
        assert_not_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
        # verify there is a v1 connection between node 1 and 2
        node_1_info = self.nodes[1].getpeerinfo()
        node_2_info = self.nodes[2].getpeerinfo()
        assert_equal(len(node_1_info), 1)
        assert_equal(len(node_2_info), 1)
        assert_equal(node_1_info[0]["transport_protocol_type"], "v1")
        assert_equal(node_2_info[0]["transport_protocol_type"], "v1")
        assert_equal(len(node_1_info[0]["session_id"]), 0)
        assert_equal(len(node_2_info[0]["session_id"]), 0)

        # V2 nodes can sync with V1 nodes
        self.disconnect_nodes(1, 2)
        with self.nodes[0].assert_debug_log(expected_msgs=[],
                                            unexpected_msgs=[sending_handshake, downgrading_to_v1]):
            self.connect_nodes(0, 3, peer_advertises_v2=False)
        self.sync_all([self.nodes[0], self.nodes[3]])
        assert_equal(self.nodes[0].getblockcount(), 8)
        # verify there is a v1 connection between node 0 and 3
        node_0_info = self.nodes[0].getpeerinfo()
        node_3_info = self.nodes[3].getpeerinfo()
        assert_equal(len(node_0_info), 1)
        assert_equal(len(node_3_info), 1)
        assert_equal(node_0_info[0]["transport_protocol_type"], "v1")
        assert_equal(node_3_info[0]["transport_protocol_type"], "v1")
        assert_equal(len(node_0_info[0]["session_id"]), 0)
        assert_equal(len(node_3_info[0]["session_id"]), 0)

        # V2 node mines another block and everyone gets it
        self.connect_nodes(0, 1, peer_advertises_v2=True)
        self.connect_nodes(1, 2, peer_advertises_v2=False)
        self.generate(self.nodes[1], 1, sync_fun=lambda: self.sync_all(self.nodes[0:4]))
        assert_equal(self.nodes[0].getblockcount(), 9) # sync_all() verifies tip hashes match

        # V1 node mines another block and everyone gets it
        self.generate(self.nodes[3], 2, sync_fun=lambda: self.sync_all(self.nodes[0:4]))
        assert_equal(self.nodes[2].getblockcount(), 11) # sync_all() verifies tip hashes match

        assert_equal(self.nodes[4].getblockcount(), 0)
        # Peer 4 is v1 p2p, but is falsely advertised as v2.
        with self.nodes[1].assert_debug_log(expected_msgs=[sending_handshake, downgrading_to_v1]):
            self.connect_nodes(1, 4, peer_advertises_v2=True)
        self.sync_all()
        assert_equal(self.nodes[4].getblockcount(), 11)

        # Check v1 prefix detection
        V1_PREFIX = MAGIC_BYTES["regtest"] + b"version\x00\x00\x00\x00\x00"
        assert_equal(len(V1_PREFIX), 16)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            with self.nodes[0].wait_for_new_peer():
                s.connect(("127.0.0.1", p2p_port(0)))
            s.sendall(V1_PREFIX[:-1])
            assert_equal(self.nodes[0].getpeerinfo()[-1]["transport_protocol_type"], "detecting")
            s.sendall(bytes([V1_PREFIX[-1]]))  # send out last prefix byte
            self.wait_until(lambda: self.nodes[0].getpeerinfo()[-1]["transport_protocol_type"] == "v1")

        # Check wrong network prefix detection (hits if the next 12 bytes correspond to a v1 version message)
        wrong_network_magic_prefix = MAGIC_BYTES["testnet"] + V1_PREFIX[4:]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            with self.nodes[0].wait_for_new_peer():
                s.connect(("127.0.0.1", p2p_port(0)))
            peer_id = self.nodes[0].getpeerinfo()[-1]["id"]
            # Tide can reject this either in v2 detection (wrong MessageStart) or after falling
            # back to v1 header parsing. Both paths must disconnect the peer.
            with self.nodes[0].assert_debug_log(["disconnecting peer"]):
                s.sendall(wrong_network_magic_prefix + b"somepayload")
                self.wait_until(lambda: peer_id not in [p["id"] for p in self.nodes[0].getpeerinfo()])

        # Refuse noncanonical ML-KEM public-key coefficients before sending a ciphertext.
        # Test both packed positions, including the end of the coefficient region.
        for index in (0, 1, 510, 511):
            key = bytearray(800)
            offset = (index // 2) * 3
            if index % 2 == 0:
                key[offset] = 3329 & 0xff
                key[offset + 1] = 3329 >> 8
            else:
                key[offset + 1] = (3329 & 0xf) << 4
                key[offset + 2] = 3329 >> 4
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.options.timeout_factor * 10)
                with self.nodes[0].wait_for_new_peer():
                    s.connect(("127.0.0.1", p2p_port(0)))
                peer_id = self.nodes[0].getpeerinfo()[-1]["id"]
                s.sendall(key)
                self.wait_until(lambda: peer_id not in [p["id"] for p in self.nodes[0].getpeerinfo()])
                assert_equal(s.recv(1), b"")

        # Check detection of missing garbage terminator (hits after fixed amount of data if terminator never matches garbage)
        MAX_KEY_GARB_AND_GARBTERM_LEN = 800 + 4095 + 16
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            with self.nodes[0].wait_for_new_peer():
                s.connect(("127.0.0.1", p2p_port(0)))
            s.sendall(b'\x00' * (MAX_KEY_GARB_AND_GARBTERM_LEN - 1))
            self.wait_until(lambda: self.nodes[0].getpeerinfo()[-1]["bytesrecv"] == MAX_KEY_GARB_AND_GARBTERM_LEN - 1)
            with self.nodes[0].assert_debug_log(["V2 transport error: missing garbage terminator"]):
                peer_id = self.nodes[0].getpeerinfo()[-1]["id"]
                s.sendall(b'\x00')  # send out last byte
                # should disconnect immediately
                self.wait_until(lambda: not peer_id in [p["id"] for p in self.nodes[0].getpeerinfo()])

    def test_outbound_handshake_info(self):
        self.log.info("Check outgoing transport status through a partial handshake and timeout")
        node = self.nodes[0]
        start = int(time.time())
        node.setmocktime(start)
        try:
            for complete in (True, False):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                    listener.settimeout(self.options.timeout_factor * 10)
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    address = "%s:%d" % listener.getsockname()
                    node.addconnection(address, "outbound-full-relay", v2transport=True)
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(self.options.timeout_factor * 10)
                        self.wait_until(lambda: any(p["addr"] == address for p in node.getpeerinfo()))
                        peer_id = next(p["id"] for p in node.getpeerinfo() if p["addr"] == address)

                        def peer_info():
                            return next(p for p in node.getpeerinfo() if p["id"] == peer_id)

                        def check_detecting():
                            info = peer_info()
                            assert_equal(info["transport_protocol_type"], "detecting")
                            assert_equal(info["session_id"], "")

                        check_detecting()
                        key = b""
                        while len(key) < KEM_PUBLIC_KEY_LEN:
                            chunk = conn.recv(KEM_PUBLIC_KEY_LEN - len(key))
                            assert chunk
                            key += chunk
                        state = EncryptedP2PState(initiating=False, net=self.chain)
                        consumed, reply = state.respond_v2_handshake(BytesIO(key))
                        assert_equal(consumed, KEM_PUBLIC_KEY_LEN)
                        sent = KEM_CIPHERTEXT_LEN - 1
                        conn.sendall(reply[:sent])
                        self.wait_until(lambda: peer_info()["bytesrecv"] == sent)
                        check_detecting()
                        if complete:
                            # Complete the ciphertext, then all but the last byte of the version packet.
                            for end in (KEM_CIPHERTEXT_LEN, len(reply) - 1):
                                conn.sendall(reply[sent:end])
                                sent = end
                                self.wait_until(lambda: peer_info()["bytesrecv"] == sent)
                                check_detecting()
                            conn.sendall(reply[-1:])
                            self.wait_until(lambda: peer_info()["transport_protocol_type"] == "v2")
                            assert_equal(peer_info()["session_id"], state.peer["session_id"].hex())
                            node.disconnectnode(nodeid=peer_id)
                        else:
                            with node.assert_debug_log(
                                expected_msgs=[f"V2 handshake timeout, disconnecting peer={peer_id}"],
                                unexpected_msgs=[f"version handshake timeout, disconnecting peer={peer_id}"],
                            ):
                                node.setmocktime(start + 61)
                                self.wait_until(lambda: all(p["id"] != peer_id for p in node.getpeerinfo()))
                        self.wait_until(lambda: all(p["id"] != peer_id for p in node.getpeerinfo()))
        finally:
            node.setmocktime(0)


if __name__ == '__main__':
    V2TransportTest(__file__).main()
