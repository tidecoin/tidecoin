#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bound Tor control replies and recover using a synthetic control endpoint.

Boundary scenarios adapted from Bitcoin Core PR 35087 for Tidecoin's
libevent reader. No running Tor daemon or public network is needed.
"""
from contextlib import contextmanager
import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

MAX_LINE_COUNT = 1000
MAX_LINE_LENGTH = 100000
ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"


class ControlPeer:
    def __init__(self, listener):
        self.conn, _ = listener.accept()
        self.conn.settimeout(10)
        self.buffer = b""
        assert_equal(self.command(), "PROTOCOLINFO 1")

    def command(self):
        while b"\r\n" not in self.buffer:
            data = self.conn.recv(4096)
            assert data, "Control connection closed before command"
            self.buffer += data
        line, self.buffer = self.buffer.split(b"\r\n", 1)
        return line.decode()

    def send(self, data):
        self.conn.sendall(data.encode())

    def expect_no_command(self):
        self.conn.settimeout(0.2)
        try:
            self.conn.recv(1)
        except socket.timeout:
            pass
        else:
            raise AssertionError("Unterminated reply was dispatched or connection closed")
        finally:
            self.conn.settimeout(10)

    def close(self):
        self.conn.close()

    def expect_closed(self):
        assert_equal(self.buffer, b"")
        assert_equal(self.conn.recv(4096), b"")
        self.close()


class TorControlTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    @contextmanager
    def endpoint(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            self.restart_node(0, extra_args=[
                f"-torcontrol=127.0.0.1:{listener.getsockname()[1]}",
                "-listenonion=1", "-debug=tor",
            ])
            peer = ControlPeer(listener)
            try:
                yield listener, peer
            finally:
                peer.close()
                self.stop_node(0)

    def finish_handshake(self, peer, *, boundary=False):
        # Exactly 1,000 lines including the terminal line must be accepted.
        padding = "250-Continuing\r\n" * (MAX_LINE_COUNT - 3) if boundary else ""
        peer.send("250-PROTOCOLINFO 1\r\n" + padding + "250-AUTH METHODS=NULL\r\n250 OK\r\n")
        assert_equal(peer.command(), "AUTHENTICATE")
        # A second reply at the boundary proves the count resets per reply.
        padding = "250-Continuing\r\n" * (MAX_LINE_COUNT - 1) if boundary else ""
        peer.send(padding + "250 OK\r\n")
        assert_equal(peer.command(), "GETINFO net/listeners/socks")
        assert peer.command().startswith("ADD_ONION ")
        # Coalesced replies must dispatch to their respective queued handlers.
        peer.send('250-net/listeners/socks="127.0.0.1:9050"\r\n250 OK\r\n'
                  f"250-ServiceID={ONION.removesuffix('.onion')}\r\n250 OK\r\n")
        self.wait_until(lambda: any(a["address"] == ONION for a in self.nodes[0].getnetworkinfo()["localaddresses"]))

    def recover(self, listener, peer):
        peer.expect_closed()
        recovered = ControlPeer(listener)
        try:
            # Completion, not merely a new PROTOCOLINFO, catches stale handlers.
            self.finish_handshake(recovered)
        finally:
            recovered.close()

    def test_line_count(self):
        self.log.info("Accept two consecutive replies of exactly 1,000 lines")
        with self.endpoint() as (_, peer):
            self.finish_handshake(peer, boundary=True)

        for final in ["250-Continuing\r\n", "250 OK\r\n"]:
            self.log.info("Reject line 1,001 and complete a fresh handshake after reconnect")
            with self.endpoint() as (listener, peer):
                with self.nodes[0].assert_debug_log(["MAX_LINE_COUNT exceeded"]):
                    # Deliver the overflow separately from the first 1,000 lines.
                    peer.send("250-Continuing\r\n" * MAX_LINE_COUNT)
                    peer.send(final)
                    self.recover(listener, peer)

    def test_partial_reply(self):
        self.log.info("Buffer a split terminal line; discard partial replies on EOF")
        with self.endpoint() as (_, peer):
            peer.send("250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250 OK")
            peer.expect_no_command()
            peer.send("\r\n")
            assert_equal(peer.command(), "AUTHENTICATE")

        with self.endpoint() as (listener, peer):
            peer.send("250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n")
            peer.close()
            recovered = ControlPeer(listener)
            try:
                self.finish_handshake(recovered)
            finally:
                recovered.close()

    def test_line_length(self):
        self.log.info("Accept a complete line at the existing length limit")
        with self.endpoint() as (_, peer):
            peer.send("250-" + "A" * (MAX_LINE_LENGTH - 4) + "\r\n")
            self.finish_handshake(peer)

        self.log.info("Accept a boundary line when CR and LF arrive separately")
        with self.endpoint() as (_, peer):
            peer.send("250-" + "A" * (MAX_LINE_LENGTH - 4) + "\r")
            peer.expect_no_command()
            peer.send("\n")
            self.finish_handshake(peer)

        for ending in ["", "\r\n"]:
            self.log.info("Reject an oversized line, complete or incomplete, and recover")
            with self.endpoint() as (listener, peer):
                with self.nodes[0].assert_debug_log(["MAX_LINE_LENGTH exceeded"]):
                    peer.send("250-" + "A" * (MAX_LINE_LENGTH - 3) + ending)
                    self.recover(listener, peer)

    def run_test(self):
        self.test_line_count()
        self.test_partial_reply()
        self.test_line_length()


if __name__ == '__main__':
    TorControlTest(__file__).main()
