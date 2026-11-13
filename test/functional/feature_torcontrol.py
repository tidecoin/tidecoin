#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bound Tor control replies and recover using a synthetic control endpoint.

Boundary scenarios adapted from Bitcoin Core PR 35087 for Tidecoin's
libevent reader. No running Tor daemon or public network is needed.
"""
from contextlib import contextmanager
import base64
import os
import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

MAX_LINE_COUNT = 1000
MAX_LINE_LENGTH = 100000
ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
PRIVATE_KEY = "ED25519-V3:" + base64.b64encode(bytes(range(64))).decode()


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

    def authenticate(self, peer, *, boundary=False):
        # Exactly 1,000 lines including the terminal line must be accepted.
        padding = "250-Continuing\r\n" * (MAX_LINE_COUNT - 3) if boundary else ""
        peer.send("250-PROTOCOLINFO 1\r\n" + padding + "250-AUTH METHODS=NULL\r\n250 OK\r\n")
        assert_equal(peer.command(), "AUTHENTICATE")
        # A second reply at the boundary proves the count resets per reply.
        padding = "250-Continuing\r\n" * (MAX_LINE_COUNT - 1) if boundary else ""
        peer.send(padding + "250 OK\r\n")
        assert_equal(peer.command(), "GETINFO net/listeners/socks")

    def finish_handshake(self, peer, *, boundary=False, private_key=PRIVATE_KEY, advertise=True, expected_key=None):
        self.authenticate(peer, boundary=boundary)
        command = peer.command()
        assert command.startswith("ADD_ONION ")
        if expected_key is not None:
            assert_equal(command.split()[1], expected_key)
        # Coalesced replies must dispatch to their respective queued handlers.
        key_reply = f"250-PrivateKey={private_key}\r\n" if private_key is not None else ""
        peer.send('250-net/listeners/socks="127.0.0.1:9050"\r\n250 OK\r\n'
                  f"250-ServiceID={ONION.removesuffix('.onion')}\r\n{key_reply}250 OK\r\n")
        if advertise:
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
        self.test_identity_persistence()

    def test_identity_persistence(self):
        node = self.nodes[0]
        key_file = node.chain_path / "onion_v3_private_key"
        temporary = key_file.with_name(key_file.name + ".tmp")

        self.log.info("Reusing a saved Tor identity does not rewrite it")
        assert_equal(key_file.read_text(), PRIVATE_KEY)
        os.utime(key_file, ns=(1_000_000_000, 1_000_000_000))
        timestamp = key_file.stat().st_mtime_ns
        with self.endpoint() as (_, peer):
            self.finish_handshake(peer, private_key=None, expected_key=PRIVATE_KEY)
            assert_equal(key_file.stat().st_mtime_ns, timestamp)

        self.log.info("A failed save is not advertised and is retried with the same key on reconnect")
        key_file.unlink()
        temporary.mkdir()
        with self.endpoint() as (listener, peer):
            with node.assert_debug_log(["not advertising onion service"]):
                self.finish_handshake(peer, advertise=False, expected_key="NEW:ED25519-V3")
            assert_equal(node.getnetworkinfo()["localaddresses"], [])
            assert not key_file.exists()
            peer.close()
            recovered = ControlPeer(listener)
            try:
                # It must retry the failed write even though Tor returns no new key.
                with node.assert_debug_log(["not advertising onion service"]):
                    self.finish_handshake(recovered, private_key=None, advertise=False, expected_key=PRIVATE_KEY)
                assert_equal(node.getnetworkinfo()["localaddresses"], [])
                assert not key_file.exists()
            finally:
                recovered.close()
            temporary.rmdir()
            recovered = ControlPeer(listener)
            try:
                self.finish_handshake(recovered, private_key=None, expected_key=PRIVATE_KEY)
                assert_equal(key_file.read_text(), PRIVATE_KEY)
            finally:
                recovered.close()

        self.log.info("Invalid and unreadable identity files never request a replacement")
        for contents in ["", "NEW:ED25519-V3", "ED25519-V3:bad", PRIVATE_KEY + "x",
                         PRIVATE_KEY + "\r", PRIVATE_KEY + "\n\n", PRIVATE_KEY + "\r\n\n",
                         PRIVATE_KEY[:20] + "\n" + PRIVATE_KEY[20:]]:
            key_file.write_bytes(contents.encode())
            with node.assert_debug_log(["onion service disabled"]):
                with self.endpoint() as (_, peer):
                    self.authenticate(peer)
                    peer.send('250-net/listeners/socks="127.0.0.1:9050"\r\n250 OK\r\n')
                    peer.expect_no_command()
                    assert_equal(node.getnetworkinfo()["localaddresses"], [])
                    assert_equal(key_file.read_bytes(), contents.encode())
        key_file.unlink()
        key_file.mkdir()
        with self.endpoint() as (_, peer):
            self.authenticate(peer)
            peer.expect_no_command()
            assert key_file.is_dir()
        key_file.rmdir()
        # Restoring the original file and restarting recovers the same address.
        key_file.write_text(PRIVATE_KEY)
        with self.endpoint() as (_, peer):
            self.finish_handshake(peer, private_key=None, expected_key=PRIVATE_KEY)
        for key in [PRIVATE_KEY, PRIVATE_KEY.rstrip("=")]:
            for ending in [b"", b"\n", b"\r\n"]:
                contents = key.encode() + ending
                key_file.write_bytes(contents)
                with self.endpoint() as (_, peer):
                    self.finish_handshake(peer, private_key=None, expected_key=key)
                    # Normalizing an optional line ending must not cause a rewrite.
                    assert_equal(key_file.read_bytes(), contents)

        if os.name != "nt":
            self.test_linked_identity(key_file)

    def test_linked_identity(self, key_file):
        node = self.nodes[0]
        directory = node.datadir_path / "mounted-onion-key"
        directory.mkdir()
        target = directory / "key"
        target.write_bytes(PRIVATE_KEY.encode() + b"\r\n")
        key_file.unlink()
        key_file.symlink_to(os.path.relpath(target, key_file.parent))
        target.chmod(0o400)
        directory.chmod(0o100)
        try:
            with self.endpoint() as (_, peer):
                self.finish_handshake(peer, private_key=None, expected_key=PRIVATE_KEY)
                assert key_file.is_symlink()
                assert_equal(target.read_bytes(), PRIVATE_KEY.encode() + b"\r\n")
        finally:
            directory.chmod(0o700)
            target.chmod(0o600)

        self.log.info("A changed linked identity updates its target and preserves the link")
        changed_key = "ED25519-V3:" + base64.b64encode(bytes(range(1, 65))).decode()
        with self.endpoint() as (_, peer):
            self.finish_handshake(peer, private_key=changed_key, expected_key=PRIVATE_KEY)
            assert key_file.is_symlink()
            assert_equal(target.read_text(), changed_key)
            assert not target.with_name("key.tmp").exists()

        self.log.info("A dangling identity link never requests a new key")
        target.unlink()
        with self.endpoint() as (_, peer):
            self.authenticate(peer)
            peer.expect_no_command()
            assert key_file.is_symlink()
            assert not target.exists()
            assert_equal(node.getnetworkinfo()["localaddresses"], [])
        key_file.unlink()


if __name__ == '__main__':
    TorControlTest(__file__).main()
