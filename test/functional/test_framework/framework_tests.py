#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression tests for functional-test process and socket ownership."""

import asyncio
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from interface_ipc import connect_unix_socket
import test_runner
from .socks5 import Socks5Configuration, Socks5Connection, Socks5Server, recvall, sendall
from .test_framework import Binaries, BitcoinTestFramework
from .util import PortSeed


class FrameworkTests(unittest.TestCase):
    def test_binary_instrumentation(self):
        paths = SimpleNamespace(tidecoin_bin='/tools with spaces/tidecoin', tidecoin_cmd=None)
        for name in ('tidecoind', 'tidecoincli', 'tidecointx', 'tidecoinutil', 'tidecoinwallet', 'tidecoinchainstate'):
            setattr(paths, name, '/tools with spaces/' + name)
        with patch.dict(os.environ, {'VALGRIND_SUPPRESSIONS_FILE': '/custom suppressions'}):
            binaries = Binaries(paths, None, use_valgrind=True)
        for method, attr in [('node_argv', 'tidecoind'), ('rpc_argv', 'tidecoincli'), ('tx_argv', 'tidecointx'),
                             ('util_argv', 'tidecoinutil'), ('wallet_argv', 'tidecoinwallet'), ('chainstate_argv', 'tidecoinchainstate')]:
            with self.subTest(method=method):
                args = getattr(binaries, method)()
                self.assertEqual(args[:len(binaries.valgrind_cmd)], binaries.valgrind_cmd)
                self.assertEqual(args[len(binaries.valgrind_cmd)], getattr(paths, attr))
                self.assertEqual(args.count('valgrind'), 1)
        self.assertIn('--suppressions=/custom suppressions', binaries.valgrind_cmd)
        self.assertEqual(binaries.node_argv(need_ipc=True)[-3:], [paths.tidecoin_bin, '-m', 'node'])
        paths.tidecoin_cmd = [paths.tidecoin_bin, '-m']
        self.assertEqual(binaries.node_argv()[-3:], [paths.tidecoin_bin, '-m', 'node'])
        self.assertEqual(Binaries(paths, '/old release', use_valgrind=True).node_argv(), [os.path.join('/old release', 'tidecoind')])
        self.assertEqual(Binaries(paths, None).node_argv(), paths.tidecoin_cmd + ['node'])

    def test_skip_reason_and_failure_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'skip.py').write_text("import sys; sys.stdout.buffer.write(b'Test Skipped: unavailable\\r\\n'); sys.exit(77)\n", encoding='utf8')
            (root / 'fail.py').write_text('import sys; sys.exit(9)\n', encoding='utf8')
            handler = test_runner.TestHandler(num_tests_parallel=2, tests_dir=tmp + os.sep, tmpdir=tmp,
                                             test_list=['skip.py', 'fail.py'], flags=[], use_term_control=False)
            results = []
            while not handler.done():
                results.extend(handler.get_next())
            results = {r[0].name: r for r in results}
            self.assertEqual(results['skip.py'][0].status, 'Skipped')
            self.assertEqual(results['skip.py'][4], 'unavailable')
            self.assertEqual(results['fail.py'][0].status, 'Failed')

    def test_gil_in_cache_tests_and_grandchildren(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'PYTHON_GIL': '0'}), patch.object(sys, 'path', list(sys.path)):
            root = Path(tmp)
            scripts = root / 'test/functional'
            scripts.mkdir(parents=True)
            run_dir = root / 'runs'
            run_dir.mkdir()
            code = "import os, subprocess, sys\nassert os.environ['PYTHON_GIL'] == '1'\nsubprocess.run([sys.executable, '-c', \"import os; assert os.environ['PYTHON_GIL'] == '1'\"], check=True)\n"
            for name in ['create_cache.py', 'one.py', 'two.py']:
                (scripts / name).write_text(code, encoding='utf8')
            with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
                test_runner.run_tests(test_list=['one.py', 'two.py'], build_dir=tmp, src_dir=tmp,
                                      tmpdir=str(run_dir), jobs=2, use_term_control=False)
            self.assertEqual(result.exception.code, 0)

    def test_chainstate_timeout_reaps_child(self):
        from tool_tidecoin_chainstate import BitcoinChainstateTest
        children = []
        real_popen = subprocess.Popen
        def popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child
        fixture = SimpleNamespace(
            options=SimpleNamespace(timeout_factor=0.02),
            get_binaries=lambda: SimpleNamespace(chainstate_argv=lambda: [sys.executable, '-c', 'import time; time.sleep(60)']),
        )
        try:
            with patch('tool_tidecoin_chainstate.subprocess.Popen', side_effect=popen):
                with self.assertRaises(subprocess.TimeoutExpired):
                    BitcoinChainstateTest.add_block(fixture, 'unused', '', '')
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll(), 'Timed-out tool was left running')
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate()

    def test_reconnect_waits_for_both_old_peers(self):
        # Both peers initially report a stale connection. addnode must not be
        # called until both disappear; the new connection must still handshake.
        events = []
        connected = False
        class Node:
            use_v2transport = False
            def __init__(self, name, inbound):
                self.name, self.inbound, self.stale = name, inbound, 2
            def getnetworkinfo(self):
                return {'subversion': self.name}
            def getpeerinfo(self):
                nonlocal connected
                if self.stale:
                    self.stale -= 1
                    events.append(self.name)
                    return [{'subver': 'b' if self.name == 'a' else 'a', 'inbound': self.inbound}]
                if connected:
                    return [{'subver': 'b' if self.name == 'a' else 'a', 'inbound': self.inbound, 'bytesrecv_per_msg': {'pong': 29}}]
                return []
            def addnode(self, *args, **kwargs):
                nonlocal connected
                self_test.assertEqual([a.stale, b.stale], [0, 0])
                connected = True
        def wait_until(predicate):
            for _ in range(10):
                if predicate():
                    return
            self.fail('Connection predicate did not complete')
        self_test = self
        for wait_for_connect in (True, False):
            with self.subTest(wait_for_connect=wait_for_connect), patch.object(PortSeed, 'n', 1, create=True):
                connected = False
                a, b = Node('a', False), Node('b', True)
                framework = SimpleNamespace(nodes=[a, b], wait_until=wait_until)
                BitcoinTestFramework.connect_nodes(framework, 0, 1, wait_for_connect=wait_for_connect)
                self.assertTrue(connected)
        self.assertEqual(events, ['a', 'a', 'b', 'b'] * 2)


class Socks5Tests(unittest.TestCase):
    def server(self, *, keep_alive=False, destination=None):
        conf = Socks5Configuration()
        conf.addr = ('127.0.0.1', 0)
        conf.unauth = True
        conf.keep_alive = keep_alive
        conf.destinations_factory = destination
        server = Socks5Server(conf)
        conf.addr = server.s.getsockname()
        self.addCleanup(server.stop)
        server.start()
        return server

    def client(self, server):
        client = socket.create_connection(server.conf.addr, timeout=2)
        self.addCleanup(client.close)
        client.sendall(b'\x05\x01\x00')
        self.assertEqual(recvall(client, 2), b'\x05\x00')
        return client

    def request(self, client):
        client.sendall(b'\x05\x01\x00\x03\x09localhost\x00\x50')
        self.assertEqual(recvall(client, 10), b'\x05\x00\x00\x01' + bytes(6))

    def test_stop_stalled_handshake_and_release_port(self):
        for _ in range(10):
            server = self.server()
            client = self.client(server)  # Handler is blocked waiting for CONNECT.
            server.stop()
            self.assertEqual(client.recv(1), b'')
            self.assertFalse(server.thread.is_alive())
            with socket.socket() as rebound:
                rebound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rebound.bind(server.conf.addr)
                rebound.listen()
            server.stop()  # Idempotent cleanup.

    def test_stop_keep_alive(self):
        server = self.server(keep_alive=True)
        client = self.client(server)
        self.request(client)
        self.assertEqual(server.queue.get(timeout=2).port, 80)
        client.settimeout(0.05)
        with self.assertRaises(socket.timeout):
            client.recv(1)
        server.stop()
        client.settimeout(2)
        self.assertEqual(client.recv(1), b'')

    def test_stop_idle_forwarding(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(2)
            server = self.server(destination=lambda addr, port: {'actual_to_addr': '127.0.0.1', 'actual_to_port': listener.getsockname()[1]})
            client = self.client(server)
            self.request(client)
            remote, _ = listener.accept()
            with remote:
                remote.settimeout(2)
                client.sendall(b'forward')
                self.assertEqual(recvall(remote, 7), b'forward')
                remote.sendall(b'reverse')
                self.assertEqual(recvall(client, 7), b'reverse')
                server.stop()
                self.assertEqual(client.recv(1), b'')
                self.assertEqual(remote.recv(1), b'')

    def test_error_is_reported_and_connection_closed(self):
        server = self.server()
        with self.assertLogs('TestFramework.socks5', level='ERROR'):
            with socket.create_connection(server.conf.addr, timeout=2) as client:
                client.sendall(b'\x04')
                self.assertIsInstance(server.queue.get(timeout=2), OSError)
                self.assertEqual(client.recv(1), b'')
        server.stop()

    def test_stop_idle_forwarding_without_socket_shutdown(self):
        # Exercise the fallback even on platforms where shutdown wakes select.
        with patch.object(Socks5Connection, 'shutdown'):
            self.test_stop_idle_forwarding()

    def test_stop_stalled_handshake_without_socket_shutdown(self):
        with patch.object(Socks5Connection, 'shutdown'):
            self.test_stop_stalled_handshake_and_release_port()

    def test_stop_forwarding_with_full_send_buffer(self):
        running = threading.Event()
        running.set()

        def wait_for_write(readers, writers, errors, timeout=None):
            # Simulate a destination that stays unwritable while we stop.
            self.assertEqual((readers, writers, errors), ([], [sock], []))
            self.assertIsNotNone(timeout)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 1)
            running.clear()
            return [], [], []

        with socket.socket() as sock, patch('test_framework.socks5.select.select', side_effect=wait_for_write) as wait:
            sendall(sock, b'pending', running.is_set)
            wait.assert_called_once()

    def test_blocked_callback_does_not_report_successful_stop(self):
        entered, release = threading.Event(), threading.Event()
        def destination(addr, port):
            entered.set()
            release.wait(5)
        server = self.server(destination=destination)
        client = self.client(server)
        self.request(client)
        self.assertTrue(entered.wait(2))
        try:
            with self.assertRaisesRegex(AssertionError, 'handler did not stop'):
                server.stop(timeout=0.3)
        finally:
            release.set()
            server.stop()


# These cases exercise Linux Unix-socket queue behavior and /proc descriptor counts.
@unittest.skipUnless(sys.platform == "linux", "requires Linux Unix sockets")
class IPCConnectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='tide-ipc-connect-')
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'socket'
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.server.close)
        self.server.bind(str(self.path))
        self.server.listen(5)
        self.server.setblocking(False)

    def fill_queue(self):
        # Linux allows backlog + 1 completed connections to wait for accept().
        for _ in range(6):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(self.path))

    async def test_connected_socket_transfers_data(self):
        client = await connect_unix_socket(self.path, 1)
        self.addCleanup(client.close)
        peer, _ = self.server.accept()
        self.addCleanup(peer.close)
        peer.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(client, b'connected')
        self.assertEqual(await asyncio.wait_for(loop.sock_recv(peer, 9), 1), b'connected')

    async def test_full_queue_waits_for_accept(self):
        self.fill_queue()
        pending = asyncio.create_task(connect_unix_socket(self.path, 1))
        try:
            await asyncio.sleep(0.05)
            self.assertFalse(pending.done())
            peer, _ = self.server.accept()
            peer.close()
            client = await pending
            self.addCleanup(client.close)
            self.assertEqual(client.getpeername(), str(self.path))
        finally:
            if not pending.done():
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await pending

    async def test_full_queue_times_out_without_leaking(self):
        self.fill_queue()
        before = len(list(Path('/proc/self/fd').iterdir()))
        with self.assertRaises(asyncio.TimeoutError):
            await connect_unix_socket(self.path, 0.05)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)

    async def test_cancel_closes_socket(self):
        self.fill_queue()
        before = len(list(Path('/proc/self/fd').iterdir()))
        pending = asyncio.create_task(connect_unix_socket(self.path, 10))
        await asyncio.sleep(0.02)
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)

    async def test_closed_listener_fails(self):
        self.server.close()
        with self.assertRaises(ConnectionRefusedError):
            await connect_unix_socket(self.path, 1)

    async def test_missing_listener_fails(self):
        with self.assertRaises(FileNotFoundError):
            await connect_unix_socket(self.path.with_name('missing'), 1)
