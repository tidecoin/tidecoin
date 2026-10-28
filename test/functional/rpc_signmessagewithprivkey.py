#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC commands for signing messages with private key."""

import base64
import json
from pathlib import Path

from test_framework.address import key_to_p2pkh, keyhash_to_p2pkh
from test_framework.descriptors import (
    descsum_create,
)
from test_framework.falcon import falcon512_alternates
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import generate_keypair


class SignMessagesWithPrivTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-auxpowactivationheight=10']]

    def check_fixed_messages(self):
        """Replay public fixtures, including alternate old Falcon encodings."""
        path = Path(self.config['environment']['SRCDIR']) / 'src/test/data/falcon512_messages.json'
        other_address = keyhash_to_p2pkh(bytes(20))
        for row in json.loads(path.read_text(encoding='utf8')):
            blob = base64.b64decode(row['signature'])
            signature, raw_key = blob[:-897], blob[-897:]
            address = key_to_p2pkh(b'\x07' + raw_key)
            message = row['message']

            def verify(sig):
                return self.nodes[0].verifymessage(address, base64.b64encode(sig + raw_key).decode(), message)

            assert verify(signature)
            if row['strict']:
                # This existing helper takes a transaction sighash byte, which
                # message signatures do not carry. Add/remove it only here.
                alternates = falcon512_alternates(signature + b'\x01')
                assert alternates is not None
                for alternate in alternates:
                    assert verify(alternate[:-1])
            for size in [len(signature) + 1, 666]:
                assert size > len(signature)
                assert not verify(signature.ljust(size, b'\x00'))
            assert not verify(signature[:-1])
            assert not verify(b'\x00' + signature[1:])
            assert not self.nodes[0].verifymessage(address, row['signature'], message + '!')
            assert not self.nodes[0].verifymessage(other_address, row['signature'], message)
            wrong_key = signature + b'\x00' + raw_key[1:]
            assert not self.nodes[0].verifymessage(address, base64.b64encode(wrong_key).decode(), message)

    def check_current_schemes(self):
        message = 'Current message signatures for every scheme'
        for scheme in range(7, 12):
            secret, pubkey = generate_keypair(wif=True, scheme=str(scheme))
            address = key_to_p2pkh(pubkey)
            signature = self.nodes[0].signmessagewithprivkey(secret, message)
            assert self.nodes[0].verifymessage(address, signature, message)
            assert not self.nodes[0].verifymessage(address, signature, message + '!')

    def addresses_from_privkey(self, priv_key):
        '''Return addresses for a given WIF private key in legacy (P2PKH),
           nested segwit (P2SH-P2WPKH) and native segwit (P2WPKH) formats.'''
        descriptors = f'pkh({priv_key})', f'sh(wpkh({priv_key}))', f'wpkh({priv_key})'
        return [self.nodes[0].deriveaddresses(descsum_create(desc))[0] for desc in descriptors]

    def run_test(self):
        message = 'This is just a test message'

        self.log.info('test signing with priv_key')
        priv_key, _ = generate_keypair(wif=True)
        signature = self.nodes[0].signmessagewithprivkey(priv_key, message)

        self.log.info('test that verifying with P2PKH address succeeds')
        addresses = self.addresses_from_privkey(priv_key)
        assert self.nodes[0].verifymessage(addresses[0], signature, message)

        self.log.info('test that verifying with non-P2PKH addresses throws error')
        for non_p2pkh_address in addresses[1:]:
            assert_raises_rpc_error(-3, "Address does not refer to key", self.nodes[0].verifymessage, non_p2pkh_address, signature, message)

        self.log.info('test parameter validity and error codes')
        # signmessagewithprivkey has two required parameters
        for num_params in [0, 1, 3, 4, 5]:
            param_list = ["dummy"]*num_params
            assert_raises_rpc_error(-1, "signmessagewithprivkey", self.nodes[0].signmessagewithprivkey, *param_list)
        # verifymessage has three required parameters
        for num_params in [0, 1, 2, 4, 5]:
            param_list = ["dummy"]*num_params
            assert_raises_rpc_error(-1, "verifymessage", self.nodes[0].verifymessage, *param_list)
        # invalid key or address provided
        assert_raises_rpc_error(-5, "Invalid private key", self.nodes[0].signmessagewithprivkey, "invalid_key", message)
        assert_raises_rpc_error(-5, "Invalid address", self.nodes[0].verifymessage, "invalid_addr", signature, message)
        # malformed signature provided
        assert_raises_rpc_error(-3, "Malformed base64 encoding", self.nodes[0].verifymessage, addresses[0], "invalid_sig", message)

        self.log.info('Verify fixed old-compatible and current messages before activation')
        assert_equal(self.nodes[0].getblockcount(), 0)
        self.check_fixed_messages()
        self.check_current_schemes()
        blocks = self.generatetoaddress(self.nodes[0], 10, addresses[0])
        assert_equal(self.nodes[0].getblockcount(), 10)
        self.log.info('Verify the same messages after activation')
        self.check_fixed_messages()
        self.check_current_schemes()
        self.nodes[0].invalidateblock(blocks[8])
        assert_equal(self.nodes[0].getblockcount(), 8)
        self.log.info('Verify the same messages after rollback below activation')
        self.check_fixed_messages()
        self.check_current_schemes()


if __name__ == '__main__':
    SignMessagesWithPrivTest(__file__).main()
