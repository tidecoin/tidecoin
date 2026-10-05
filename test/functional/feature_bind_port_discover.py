#!/usr/bin/env python3
# Copyright (c) 2020-2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test interface discovery for implicit, wildcard and specific binds.

Based on Bitcoin Core PR 32757. Requires two routable addresses on UP,
non-loopback interfaces. Configure these only in a suitable test environment:
  ip addr add 1.1.1.1/32 dev INTERFACE
  ip addr add 2.2.2.2/32 dev INTERFACE
Remove the addresses after testing. This test never changes host interfaces.
"""
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

ADDR1 = '1.1.1.1'
ADDR2 = '2.2.2.2'


class BindPortDiscoverTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False
        self.num_nodes = 1

    def add_options(self, parser):
        parser.add_argument('--ihave1111and2222', action='store_true',
                            help=f'Run with {ADDR1} and {ADDR2} configured on non-loopback interfaces')

    def skip_test_if_missing_module(self):
        if not self.options.ihave1111and2222:
            raise SkipTest(f'Requires {ADDR1} and {ADDR2} on non-loopback interfaces and --ihave1111and2222')

    def setup_network(self):
        # No inter-node connections or implicit framework-injected bind options.
        self.add_nodes(1)
        self.nodes[0].has_explicit_bind = True

    def run_test(self):
        node = self.nodes[0]
        port = p2p_port(0)
        base = ['-listen=1', '-listenonion=0', '-networkactive=0', f'-port={port}']
        cases = [
            ('implicit', [], {ADDR1, ADDR2}),
            ('IPv4 wildcard', [f'-bind=0.0.0.0:{port}'], {ADDR1, ADDR2}),
            ('IPv6 wildcard', [f'-bind=[::]:{port}'], {ADDR1, ADDR2}),
            ('IPv4 whitebind', [f'-whitebind=download@0.0.0.0:{port}'], {ADDR1, ADDR2}),
            ('IPv6 whitebind', [f'-whitebind=download@[::]:{port}'], {ADDR1, ADDR2}),
            ('specific bind', [f'-bind={ADDR1}:{port}'], {ADDR1}),
            ('specific whitebind', [f'-whitebind=download@{ADDR1}:{port}'], {ADDR1}),
            ('onion wildcard only', [f'-bind=0.0.0.0:{port}=onion'], set()),
        ]
        for name, binds, expected in cases:
            for discover in [True, False]:
                self.log.info('%s, discover=%s', name, discover)
                node.start(base + binds + [f'-discover={int(discover)}'])
                node.wait_for_rpc_connection()
                # Other host addresses can exist; verify both controlled addresses.
                actual = {a['address']: a['port'] for a in node.getnetworkinfo()['localaddresses']
                          if a['address'] in {ADDR1, ADDR2}}
                assert_equal(actual, {addr: port for addr in expected} if discover else {})
                node.stop_node()


if __name__ == '__main__':
    BindPortDiscoverTest(__file__).main()
