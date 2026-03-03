#!/usr/bin/env python3
# Copyright (c) 2018-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Useful util functions for testing the wallet"""
from collections import namedtuple
import json
import os
import subprocess
import unittest

from test_framework.address import (
    key_to_p2pkh,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
)
from test_framework.messages import (
    CTxIn,
    CTxInWitness,
    WITNESS_SCALE_FACTOR,
    tx_from_hex,
)
from test_framework.script import (
    sighash_type_to_str,
)
from test_framework.script_util import (
    key_to_p2pkh_script,
    key_to_p2wpkh_script,
    script_to_p2sh_script,
)

Key = namedtuple('Key', ['privkey',
                         'pubkey',
                         'p2pkh_script',
                         'p2pkh_addr',
                         'p2wpkh_script',
                         'p2wpkh_addr',
                         'p2sh_p2wpkh_script',
                         'p2sh_p2wpkh_redeem_script',
                         'p2sh_p2wpkh_addr'])

_testkeys_path = None
_pq_key_index = 0
_pq_seed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
_pq_default_scheme = os.environ.get("TIDECOIN_TEST_SCHEME", "falcon-512")

def set_keygen_node(node):
    """Set the node used for PQHD-backed key generation in tests."""
    global _testkeys_path
    # Derive tool path from the node's binary location if available.
    try:
        tidecoind_path = node.binaries.paths.tidecoind
        _testkeys_path = os.path.join(os.path.dirname(tidecoind_path), "tidecoin-testkeys")
    except Exception:
        pass

def _get_testkeys_path():
    if _testkeys_path is not None and os.path.exists(_testkeys_path):
        return _testkeys_path
    env_path = os.environ.get("TIDECOIN_TESTKEYS")
    if env_path and os.path.exists(env_path):
        return env_path
    builddir = os.environ.get("BUILDDIR")
    if builddir:
        candidate = os.path.join(builddir, "bin", "tidecoin-testkeys")
        if os.path.exists(candidate):
            return candidate
    # Fallback to common in-repo build directories.
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    for build_dir in ("build", "build_dev_mode"):
        candidate = os.path.join(repo_root, build_dir, "bin", "tidecoin-testkeys")
        if os.path.exists(candidate):
            return candidate
    raise FileNotFoundError("tidecoin-testkeys not found; set TIDECOIN_TESTKEYS or BUILDDIR")

def _run_testkeys(*, scheme: str, count: int = 1):
    global _pq_key_index
    path = _get_testkeys_path()
    cmd = [
        path,
        f"--scheme={scheme}",
        f"--seed={_pq_seed_hex}",
        f"--index={_pq_key_index}",
        f"--count={count}",
    ]
    _pq_key_index += count
    out = subprocess.check_output(cmd, text=True)
    data = json.loads(out)
    return data

def get_generate_key():
    """Generate a fresh key

    Returns a named tuple of privkey, pubkey and all address and scripts."""
    privkey, pubkey = generate_keypair(wif=True)
    return Key(privkey=privkey,
               pubkey=pubkey.hex(),
               p2pkh_script=key_to_p2pkh_script(pubkey).hex(),
               p2pkh_addr=key_to_p2pkh(pubkey),
               p2wpkh_script=key_to_p2wpkh_script(pubkey).hex(),
               p2wpkh_addr=key_to_p2wpkh(pubkey),
               p2sh_p2wpkh_script=script_to_p2sh_script(key_to_p2wpkh_script(pubkey)).hex(),
               p2sh_p2wpkh_redeem_script=key_to_p2wpkh_script(pubkey).hex(),
               p2sh_p2wpkh_addr=key_to_p2sh_p2wpkh(pubkey))

def test_address(node, address, **kwargs):
    """Get address info for `address` and test whether the returned values are as expected."""
    addr_info = node.getaddressinfo(address)
    for key, value in kwargs.items():
        if value is None:
            if key in addr_info.keys():
                raise AssertionError("key {} unexpectedly returned in getaddressinfo.".format(key))
        elif addr_info[key] != value:
            raise AssertionError("key {} value {} did not match expected value {}".format(key, addr_info[key], value))

def generate_keypair(compressed=True, wif=False, scheme=None):
    """Generate a new PQ keypair and return (privkey_wif, pubkey_bytes).

    scheme: optional scheme name/id (e.g. "falcon-512", "ml-dsa-65", "7").
    """
    use_scheme = scheme if scheme is not None else _pq_default_scheme
    data = _run_testkeys(scheme=use_scheme, count=1)
    item = data[0] if isinstance(data, list) else data
    privkey_wif = item["privkey_wif"]
    pubkey = bytes.fromhex(item["pubkey_hex"])
    if wif:
        return privkey_wif, pubkey
    return privkey_wif, pubkey

def generate_keypair_at_index(index, scheme=None):
    """Generate a deterministic PQ keypair at a fixed index without advancing the global counter."""
    use_scheme = scheme if scheme is not None else _pq_default_scheme
    path = _get_testkeys_path()
    cmd = [
        path,
        f"--scheme={use_scheme}",
        f"--seed={_pq_seed_hex}",
        f"--index={index}",
        "--count=1",
    ]
    out = subprocess.check_output(cmd, text=True)
    data = json.loads(out)
    item = data[0] if isinstance(data, list) else data
    return item["privkey_wif"], bytes.fromhex(item["pubkey_hex"])

def sign_tx_with_key(node, tx, privkeys, prevtxs=None, sighash_type=None, require_complete=True):
    """Sign a transaction using signrawtransactionwithkey RPC."""
    prevtxs = prevtxs or []
    kwargs = {}
    if sighash_type is not None:
        kwargs["sighashtype"] = sighash_type_to_str(sighash_type)
    result = node.signrawtransactionwithkey(tx.serialize().hex(), privkeys, prevtxs, **kwargs)
    if require_complete:
        assert result.get("complete", False)
    return tx_from_hex(result["hex"])

def calculate_input_weight(scriptsig_hex, witness_stack_hex=None):
    """Given a scriptSig and a list of witness stack items for an input in hex format,
       calculate the total input weight. If the input has no witness data,
       `witness_stack_hex` can be set to None."""
    tx_in = CTxIn(scriptSig=bytes.fromhex(scriptsig_hex))
    witness_size = 0
    if witness_stack_hex is not None:
        tx_inwit = CTxInWitness()
        for witness_item_hex in witness_stack_hex:
            tx_inwit.scriptWitness.stack.append(bytes.fromhex(witness_item_hex))
        witness_size = len(tx_inwit.serialize())
    return len(tx_in.serialize()) * WITNESS_SCALE_FACTOR + witness_size

class WalletUnlock():
    """
    A context manager for unlocking a wallet with a passphrase and automatically locking it afterward.
    """

    MAXIMUM_TIMEOUT = 999000

    def __init__(self, wallet, passphrase, timeout=MAXIMUM_TIMEOUT):
        self.wallet = wallet
        self.passphrase = passphrase
        self.timeout = timeout

    def __enter__(self):
        self.wallet.walletpassphrase(self.passphrase, self.timeout)

    def __exit__(self, *args):
        _ = args
        self.wallet.walletlock()


class TestFrameworkWalletUtil(unittest.TestCase):
    def test_calculate_input_weight(self):
        SKELETON_BYTES = 32 + 4 + 4  # prevout-txid, prevout-index, sequence
        SMALL_LEN_BYTES = 1  # bytes needed for encoding scriptSig / witness item lengths < 253
        LARGE_LEN_BYTES = 3  # bytes needed for encoding scriptSig / witness item lengths >= 253

        # empty scriptSig, no witness
        self.assertEqual(calculate_input_weight(""),
                         (SKELETON_BYTES + SMALL_LEN_BYTES) * WITNESS_SCALE_FACTOR)
        self.assertEqual(calculate_input_weight("", None),
                         (SKELETON_BYTES + SMALL_LEN_BYTES) * WITNESS_SCALE_FACTOR)
        # small scriptSig, no witness
        scriptSig_small = "00"*252
        self.assertEqual(calculate_input_weight(scriptSig_small, None),
                         (SKELETON_BYTES + SMALL_LEN_BYTES + 252) * WITNESS_SCALE_FACTOR)
        # small scriptSig, empty witness stack
        self.assertEqual(calculate_input_weight(scriptSig_small, []),
                         (SKELETON_BYTES + SMALL_LEN_BYTES + 252) * WITNESS_SCALE_FACTOR + SMALL_LEN_BYTES)
        # large scriptSig, no witness
        scriptSig_large = "00"*253
        self.assertEqual(calculate_input_weight(scriptSig_large, None),
                         (SKELETON_BYTES + LARGE_LEN_BYTES + 253) * WITNESS_SCALE_FACTOR)
        # large scriptSig, empty witness stack
        self.assertEqual(calculate_input_weight(scriptSig_large, []),
                         (SKELETON_BYTES + LARGE_LEN_BYTES + 253) * WITNESS_SCALE_FACTOR + SMALL_LEN_BYTES)
        # empty scriptSig, 5 small witness stack items
        self.assertEqual(calculate_input_weight("", ["00", "11", "22", "33", "44"]),
                         ((SKELETON_BYTES + SMALL_LEN_BYTES) * WITNESS_SCALE_FACTOR) + SMALL_LEN_BYTES + 5 * SMALL_LEN_BYTES + 5)
        # empty scriptSig, 253 small witness stack items
        self.assertEqual(calculate_input_weight("", ["00"]*253),
                         ((SKELETON_BYTES + SMALL_LEN_BYTES) * WITNESS_SCALE_FACTOR) + LARGE_LEN_BYTES + 253 * SMALL_LEN_BYTES + 253)
        # small scriptSig, 3 large witness stack items
        self.assertEqual(calculate_input_weight(scriptSig_small, ["00"*253]*3),
                         ((SKELETON_BYTES + SMALL_LEN_BYTES + 252) * WITNESS_SCALE_FACTOR) + SMALL_LEN_BYTES + 3 * LARGE_LEN_BYTES + 3*253)
        # large scriptSig, 3 large witness stack items
        self.assertEqual(calculate_input_weight(scriptSig_large, ["00"*253]*3),
                         ((SKELETON_BYTES + LARGE_LEN_BYTES + 253) * WITNESS_SCALE_FACTOR) + SMALL_LEN_BYTES + 3 * LARGE_LEN_BYTES + 3*253)
