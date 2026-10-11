#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Dummy Socks5 server for testing."""

import select
import socket
import threading
import queue
import logging
import time

from .netutil import (
    format_addr_port
)

logger = logging.getLogger("TestFramework.socks5")

# Protocol constants
class Command:
    CONNECT = 0x01

class AddressType:
    IPV4 = 0x01
    DOMAINNAME = 0x03
    IPV6 = 0x04

# Utility functions
def recvall(s, n, *, is_running=None):
    """Receive n bytes from a socket, or fail."""
    rv = bytearray()
    while n > 0:
        if is_running is not None:
            if not is_running():
                raise IOError('SOCKS server stopped')
            readable, _, _ = select.select([s], [], [], 0.1)
            if not readable:
                continue
        d = s.recv(n)
        if not d:
            raise IOError('Unexpected end of stream')
        rv.extend(d)
        n -= len(d)
    return rv

def sendall(s, data, is_running):
    """Send all data to a socket, or stop when the server stops."""
    sent = 0
    while sent < len(data) and is_running():
        _, wlist, _ = select.select([], [s], [], 0.1)
        if not is_running():
            return
        if len(wlist) > 0:
            n = s.send(data[sent:])
            if n == 0:
                raise IOError('send() on socket returned 0')
            sent += n

def forward_sockets(a, b, is_running):
    """Forward data in both directions until EOF or server shutdown."""
    # Mark as non-blocking so that we do not end up in a deadlock-like situation
    # where we block and wait on data from `a` while there is data ready to be
    # received on `b` and forwarded to `a`. And at the same time the application
    # at `a` is not sending anything because it waits for the data from `b` to
    # respond.
    a.setblocking(False)
    b.setblocking(False)
    sockets = [a, b]
    done = False
    while not done and is_running():
        # Socket shutdown does not wake select on every platform. Bound both
        # read and write waits so stop() can join the handler even when idle.
        rlist, _, xlist = select.select(sockets, [], sockets, 0.1)
        if not is_running():
            return
        if len(xlist) > 0:
            raise IOError('Exceptional condition on socket')
        for s in rlist:
            data = s.recv(4096)
            if data is None or len(data) == 0:
                done = True
                break
            if s == a:
                sendall(b, data, is_running)
            else:
                sendall(a, data, is_running)

# Implementation classes
class Socks5Configuration():
    """Proxy configuration."""
    def __init__(self):
        self.addr = None # Bind address (must be set)
        self.af = socket.AF_INET # Bind address family
        self.unauth = False  # Support unauthenticated
        self.auth = False  # Support authentication
        self.keep_alive = False  # Do not automatically close connections
        # This function is called whenever a new connection arrives to the proxy
        # and it decides where the connection is redirected to. It is passed:
        # - the address the client requested to connect to
        # - the port the client requested to connect to
        # It is supposed to return an object like:
        # {
        #     "actual_to_addr": "127.0.0.1"
        #     "actual_to_port": 28276
        # }
        # or None.
        # If it returns an object then the connection is redirected to actual_to_addr:actual_to_port.
        # If it returns None, or destinations_factory itself is None then the connection is closed.
        self.destinations_factory = None

class Socks5Command():
    """Information about an incoming socks5 command."""
    def __init__(self, cmd, atyp, addr, port, username, password):
        self.cmd = cmd # Command (one of Command.*)
        self.atyp = atyp # Address type (one of AddressType.*)
        self.addr = addr # Address
        self.port = port # Port to connect to
        self.username = username
        self.password = password
    def __repr__(self):
        return 'Socks5Command(%s,%s,%s,%s,%s,%s)' % (self.cmd, self.atyp, self.addr, self.port, self.username, self.password)

class Socks5Connection():
    def __init__(self, serv, conn):
        self.serv = serv
        self.conn = conn
        self._sockets = [conn]
        self._sockets_lock = threading.Lock()

    def shutdown(self):
        # Interrupt socket I/O without closing a descriptor still in use by its
        # handler thread. Handshake reads and forwarding also check the server's
        # running state, since shutdown does not reliably wake every platform.
        with self._sockets_lock:
            for sock in self._sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        with self._sockets_lock:
            for sock in self._sockets:
                sock.close()
            self._sockets.clear()

    def handle(self):
        """Handle socks5 request according to RFC1928."""
        def recv(n):
            return recvall(self.conn, n, is_running=self.serv.is_running)

        try:
            # Verify socks version
            ver = recv(1)[0]
            if ver != 0x05:
                raise IOError('Invalid socks version %i' % ver)
            # Choose authentication method
            nmethods = recv(1)[0]
            methods = bytearray(recv(nmethods))
            method = None
            if 0x02 in methods and self.serv.conf.auth:
                method = 0x02 # username/password
            elif 0x00 in methods and self.serv.conf.unauth:
                method = 0x00 # unauthenticated
            if method is None:
                raise IOError('No supported authentication method was offered')
            # Send response
            self.conn.sendall(bytearray([0x05, method]))
            # Read authentication (optional)
            username = None
            password = None
            if method == 0x02:
                ver = recv(1)[0]
                if ver != 0x01:
                    raise IOError('Invalid auth packet version %i' % ver)
                ulen = recv(1)[0]
                username = str(recv(ulen))
                plen = recv(1)[0]
                password = str(recv(plen))
                # Send authentication response
                self.conn.sendall(bytearray([0x01, 0x00]))

            # Read connect request
            ver, cmd, _, atyp = recv(4)
            if ver != 0x05:
                raise IOError('Invalid socks version %i in connect request' % ver)
            if cmd != Command.CONNECT:
                raise IOError('Unhandled command %i in connect request' % cmd)

            if atyp == AddressType.IPV4:
                addr = recv(4)
            elif atyp == AddressType.DOMAINNAME:
                n = recv(1)[0]
                addr = recv(n)
            elif atyp == AddressType.IPV6:
                addr = recv(16)
            else:
                raise IOError('Unknown address type %i' % atyp)
            port_hi,port_lo = recv(2)
            port = (port_hi << 8) | port_lo

            # Send dummy response
            self.conn.sendall(bytearray([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

            cmdin = Socks5Command(cmd, atyp, addr, port, username, password)
            self.serv.queue.put(cmdin)
            logger.debug('Proxy: %s', cmdin)

            requested_to_addr = addr.decode("utf-8")
            requested_to = format_addr_port(requested_to_addr, port)

            if self.serv.conf.destinations_factory is not None:
                dest = self.serv.conf.destinations_factory(requested_to_addr, port)
                if dest is not None:
                    logger.debug(f"Serving connection to {requested_to}, will redirect it to "
                                 f"{dest['actual_to_addr']}:{dest['actual_to_port']} instead")
                    with socket.create_connection((dest["actual_to_addr"], dest["actual_to_port"]), timeout=2) as conn_to:
                        with self._sockets_lock:
                            if not self.serv.is_running():
                                return
                            self._sockets.append(conn_to)
                        forward_sockets(self.conn, conn_to, self.serv.is_running)
                else:
                    logger.debug(f"Can't serve the connection to {requested_to}: the destinations factory returned None")
            else:
                logger.debug(f"Can't serve the connection to {requested_to}: no destinations factory")

            # Fall through to disconnect
        except Exception as e:
            if self.serv.is_running():
                logger.exception("socks5 request handling failed.")
                self.serv.queue.put(e)
        finally:
            if not self.serv.keep_alive or not self.serv.is_running():
                self.close()
            else:
                logger.debug("Keeping client connection alive")

class Socks5Server():
    def __init__(self, conf):
        self.conf = conf
        self.s = socket.socket(conf.af)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(conf.addr)
        self.conf.addr = self.s.getsockname()
        self.s.listen(5)
        self.s.settimeout(0.1)
        self._running = threading.Event()
        self._closed = False
        self.thread = None
        self.queue = queue.Queue() # report connections and exceptions to client
        self.keep_alive = conf.keep_alive
        # The listener owns this list until it is joined. Keep completed
        # handlers too, so keep_alive sockets remain owned until stop().
        self._handlers = []

    def is_running(self):
        return self._running.is_set()

    def run(self):
        while self.is_running():
            try:
                sockconn, _ = self.s.accept()
            except socket.timeout:
                continue
            if not self.is_running():
                sockconn.close()
                break
            conn = Socks5Connection(self, sockconn)
            thread = threading.Thread(target=conn.handle, name="Socks5Connection", daemon=True)
            self._handlers.append((thread, conn))
            thread.start()

    def start(self):
        assert self.thread is None and not self._closed
        self._running.set()
        self.thread = threading.Thread(target=self.run, name="Socks5Server", daemon=True)
        self.thread.start()

    def stop(self, *, timeout=5):
        if self._closed:
            return
        self._running.clear()
        deadline = time.monotonic() + timeout
        if self.thread is not None:
            self.thread.join(max(0, deadline - time.monotonic()))
            if self.thread.is_alive():
                raise AssertionError("SOCKS listener did not stop")
        self.s.close()
        # No handler can be added after the listener has joined.
        for _, conn in self._handlers:
            conn.shutdown()
        for thread, conn in self._handlers:
            thread.join(max(0, deadline - time.monotonic()))
            if thread.is_alive():
                raise AssertionError("SOCKS connection handler did not stop")
            conn.close()
        self._handlers.clear()
        self._closed = True
