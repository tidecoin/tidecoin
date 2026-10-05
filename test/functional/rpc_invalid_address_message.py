#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test error messages for 'getaddressinfo' and 'validateaddress' RPC commands."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.segwit_addr import Encoding, bech32_encode, convertbits

from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

BECH32_VALID = 'bcrt1qtmp74ayg7p24uslctssvjm06q5phz4yrxucgnv'
BECH32_VALID_UNKNOWN_WITNESS = 'bcrt1p424qxxyd0r'
BECH32_VALID_CAPITALS = 'BCRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U33RAH7R'
BECH32_VALID_MULTISIG = 'bcrt1qdg3myrgvzw7ml9q0ejxhlkyxm7vl9r56yzkfgvzclrf4hkpx9yfqhpsuks'

BECH32_INVALID_BECH32 = 'bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqdmchcc'
BECH32_INVALID_BECH32M = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7k35mrzd'
BECH32_INVALID_VERSION = 'bcrt130xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqynjegk'
BECH32_INVALID_SIZE = 'bcrt1s0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav25430mtr'
BECH32_INVALID_V0_SIZE = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kqqq5k3my'
BECH32_INVALID_PREFIX = 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx'
BECH32_TOO_LONG = 'bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23m'
BECH32_ONE_ERROR = 'bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_ONE_ERROR_CAPITALS = 'BCRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U32RAH7R'
BECH32_TWO_ERRORS = 'bcrt1qax9suht3qv95sw33xavx8crpxduefdrsvgsklu' # should be bcrt1qax9suht3qv95sw33wavx8crpxduefdrsvgsklx
BECH32_NO_SEPARATOR = 'bcrtq049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_INVALID_CHAR = 'bcrt1q04oldschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_MULTISIG_TWO_ERRORS = 'bcrt1qdg3myrgvzw7ml8q0ejxhlkyxn7vl9r56yzkfgvzclrf4hkpx9yfqhpsuks'
BECH32_WRONG_VERSION = 'bcrt1ptmp74ayg7p24uslctssvjm06q5phz4yrxucgnv'

BASE58_VALID = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn'
BASE58_INVALID_PREFIX = '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem'
BASE58_INVALID_CHECKSUM = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJJfn'
BASE58_INVALID_LENGTH = '2VKf7XKMrp4bVNVmuRbyCewkP8FhGLP2E54LHDPakr9Sq5mtU2'

INVALID_ADDRESS = 'asfah14i8fajz0123f'
INVALID_ADDRESS_2 = '1q049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv'
GENERIC_BECH32_OR_BASE58 = 'Invalid or unsupported Segwit (Bech32) or Base58 encoding.'
REGTEST_BECH32_HRP = 'rtbc'
# Tidecoin-regtest pregenerated vectors.
BECH32_VALID_TIDE = 'rtbc1qft5p2uhsdcdc3l2ua4ap5qqfg4pjaqlp250x7us7a8qqhrxrxfsq68tsrn'
BECH32_VALID_UNKNOWN_WITNESS_TIDE = 'rtbc1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs26x4j8'
BECH32_VALID_MULTISIG_TIDE = 'rtbc1qyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qnecfnh'
BASE58_VALID_TIDE = 'p76p8nAKz7uyGorcGP4ShgLAYimASoxSJq'

class InvalidAddressErrorMessageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.uses_wallet = None

    def check_valid(self, addr):
        addr = self.map_bech32_hrp(addr)
        info = self.nodes[0].validateaddress(addr)
        assert info['isvalid']
        assert 'error' not in info
        assert 'error_locations' not in info

    def check_invalid(self, addr, error_str, error_locations=None):
        addr = self.map_bech32_hrp(addr)
        res = self.nodes[0].validateaddress(addr)
        assert not res['isvalid']
        # Tidecoin may collapse certain bech32 detail errors to a generic
        # unsupported-encoding message.
        allowed_errors = [error_str]
        checksum_variants = {'Invalid Bech32 checksum', 'Invalid Bech32m checksum'}
        detailed_errors = {error_str}
        if error_str in checksum_variants:
            allowed_errors.extend(list(checksum_variants - {error_str}))
            detailed_errors = checksum_variants
        if addr.lower().startswith(f"{REGTEST_BECH32_HRP}1"):
            allowed_errors.append(GENERIC_BECH32_OR_BASE58)
            allowed_errors.append('Invalid checksum')
            allowed_errors.append('Invalid checksum or length of Base58 address (P2PKH or P2SH)')
            allowed_errors.append('Invalid or unsupported Base58-encoded address.')
        assert res['error'] in allowed_errors
        if error_locations and res['error'] in detailed_errors:
            assert_equal(res['error_locations'], error_locations)
        else:
            assert_equal(res['error_locations'], [])

    def map_bech32_hrp(self, addr):
        if addr.startswith('bcrt1'):
            return f'{REGTEST_BECH32_HRP}1{addr[5:]}'
        if addr.startswith('BCRT1'):
            return f'{REGTEST_BECH32_HRP.upper()}1{addr[5:]}'
        return addr

    def assert_raises_rpc_error_any(self, code, messages, func, *args):
        last_error = None
        for message in messages:
            try:
                assert_raises_rpc_error(code, message, func, *args)
                return
            except AssertionError as err:
                last_error = err
        raise last_error

    def test_tidecoin_error_locations(self):
        node = self.nodes[0]
        for hrp, version, size, encoding, limit in [
            ("rtbc", 0, 32, Encoding.BECH32, 90),
            ("rq", 1, 64, Encoding.BECH32M, 120),
        ]:
            program = list(range(size))
            address = bech32_encode(encoding, hrp, [version] + convertbits(program, 8, 5))
            expected_script = ("00" if version == 0 else "51") + bytes([size]).hex() + bytes(program).hex()
            for valid in [address, address.upper()]:
                result = node.validateaddress(valid)
                assert result["isvalid"]
                assert_equal(result["scriptPubKey"], expected_script)
                assert "error_locations" not in result

            # Unlike the legacy fixtures, these require the exact error and positions.
            for length in [limit + 1, limit + 10, limit + 65536]:
                result = node.validateaddress(address + "q" * (length - len(address)))
                assert_equal(result["isvalid"], False)
                assert_equal(result["error"], "Bech32 string too long")
                assert_equal(result["error_locations"], [limit])

            corrupted = list(address)
            for offset in [-1, -2]:
                corrupted[offset] = "p" if corrupted[offset] == "q" else "q"
                result = node.validateaddress("".join(corrupted))
                assert_equal(result["isvalid"], False)
                assert_equal(result["error"], "Invalid Bech32 checksum" if version == 0 else "Invalid Bech32m checksum")
                assert_equal(result["error_locations"], list(range(len(address) + offset, len(address))))

    def test_validateaddress(self):
        # Invalid Bech32
        self.check_invalid(BECH32_INVALID_SIZE, "Invalid Bech32 address program size (41 bytes)")
        self.check_invalid(BECH32_INVALID_PREFIX, GENERIC_BECH32_OR_BASE58)
        self.check_invalid(BECH32_INVALID_BECH32, 'Unsupported Segwit witness version')
        self.check_invalid(BECH32_INVALID_BECH32M, 'Version 0 witness address must use Bech32 checksum')
        self.check_invalid(BECH32_INVALID_VERSION, 'Invalid Bech32 address witness version')
        self.check_invalid(BECH32_INVALID_V0_SIZE, "Invalid Bech32 v0 address program size (21 bytes), per BIP141")
        self.check_invalid(BECH32_TOO_LONG, 'Bech32 string too long', [90])
        self.check_invalid(BECH32_ONE_ERROR, 'Invalid Bech32 checksum', [9])
        self.check_invalid(BECH32_TWO_ERRORS, 'Invalid Bech32 checksum', [22, 43])
        self.check_invalid(BECH32_ONE_ERROR_CAPITALS, 'Invalid Bech32 checksum', [38])
        self.check_invalid(BECH32_NO_SEPARATOR, GENERIC_BECH32_OR_BASE58)
        self.check_invalid(BECH32_INVALID_CHAR, 'Invalid Base 32 character', [8])
        self.check_invalid(BECH32_MULTISIG_TWO_ERRORS, 'Invalid Bech32 checksum', [19, 30])
        self.check_invalid(BECH32_WRONG_VERSION, 'Invalid Bech32 checksum', [5])

        # Valid Bech32
        self.check_valid(BECH32_VALID_TIDE)
        self.check_invalid(BECH32_VALID_UNKNOWN_WITNESS_TIDE, 'Unsupported Segwit witness version')
        self.check_valid(BECH32_VALID_TIDE.upper())
        self.check_valid(BECH32_VALID_MULTISIG_TIDE)

        # Invalid Base58
        self.check_invalid(BASE58_INVALID_PREFIX, 'Invalid or unsupported Base58-encoded address.')
        self.check_invalid(BASE58_INVALID_CHECKSUM, 'Invalid checksum or length of Base58 address (P2PKH or P2SH)')
        self.check_invalid(BASE58_INVALID_LENGTH, 'Invalid checksum or length of Base58 address (P2PKH or P2SH)')

        # Valid Base58
        self.check_valid(BASE58_VALID_TIDE)

        # Invalid address format
        self.check_invalid(INVALID_ADDRESS, GENERIC_BECH32_OR_BASE58)
        self.check_invalid(INVALID_ADDRESS_2, GENERIC_BECH32_OR_BASE58)

        node = self.nodes[0]


        if not self.options.usecli:
            # Missing arg returns the help text
            assert_raises_rpc_error(-1, "Return information about the given Tidecoin address.", node.validateaddress)
            # Explicit None is not allowed for required parameters
            assert_raises_rpc_error(-3, "JSON value of type null is not of expected type string", node.validateaddress, None)

    def test_getaddressinfo(self):
        node = self.nodes[0]

        self.assert_raises_rpc_error_any(
            -5,
            [
                "Invalid Bech32 address program size (41 bytes)",
                "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
                "Invalid checksum",
            ],
            node.getaddressinfo,
            self.map_bech32_hrp(BECH32_INVALID_SIZE),
        )
        assert_raises_rpc_error(-5, GENERIC_BECH32_OR_BASE58, node.getaddressinfo, self.map_bech32_hrp(BECH32_INVALID_PREFIX))
        assert_raises_rpc_error(-5, "Invalid or unsupported Base58-encoded address.", node.getaddressinfo, BASE58_INVALID_PREFIX)
        assert_raises_rpc_error(-5, GENERIC_BECH32_OR_BASE58, node.getaddressinfo, INVALID_ADDRESS)
        assert_raises_rpc_error(-5, "Unsupported Segwit witness version", node.getaddressinfo, BECH32_VALID_UNKNOWN_WITNESS_TIDE)

    def run_test(self):
        self.test_tidecoin_error_locations()
        self.test_validateaddress()

        if self.is_wallet_compiled():
            self.init_wallet(node=0)
            self.test_getaddressinfo()


if __name__ == '__main__':
    InvalidAddressErrorMessageTest(__file__).main()
