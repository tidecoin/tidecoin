#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying COPYING file.
"""Defined hash bytes: consensus for active v1, mempool policy for legacy/v0."""

from decimal import Decimal
from hashlib import sha512
import json
import subprocess

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_string
from test_framework.psbt import PSBT, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS
from test_framework.script import CScript, OP_1, OP_2, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_NOT, LegacySignatureHash, SegwitV0SignatureHash
from test_framework.script_util import key_to_p2pkh_script, key_to_p2wpkh_script, script_to_p2sh_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair, _get_testkeys_path


def witness_v1_hash(tx, script, amount, prev_script, mode):
    """Independent single-input v1 serializer, including spent-output commitments."""
    zero = bytes(64)
    anyone = bool(mode & 0x80)
    base = mode & 0x1f
    tag = sha512(b'TidecoinSighashV1_512').digest()
    msg = tag + tag + tx.version.to_bytes(4, 'little')
    msg += zero if anyone else sha512(tx.vin[0].prevout.serialize()).digest()
    if not anyone:
        msg += sha512(amount.to_bytes(8, 'little')).digest()
        msg += sha512(ser_string(prev_script)).digest()
    msg += zero if anyone or base in (2, 3) else sha512(tx.vin[0].nSequence.to_bytes(4, 'little')).digest()
    msg += tx.vin[0].prevout.serialize() + ser_string(script)
    msg += amount.to_bytes(8, 'little') + tx.vin[0].nSequence.to_bytes(4, 'little')
    msg += zero if base == 2 else sha512(tx.vout[0].serialize()).digest()
    msg += tx.nLockTime.to_bytes(4, 'little') + mode.to_bytes(4, 'little')
    return sha512(msg).digest()


class WitnessV1HashTypesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-auxpowactivationheight=110']]

    def candidate(self, raw):
        return self.generateblock(self.nodes[0], ADDRESS_BCRT1_P2WSH_OP_TRUE, [raw], submit=False, sync_fun=self.no_op)

    def check_existing_final(self, tx, funding, index, value, kind, script, output, secret, active):
        """Relay rejection must not alter verification or existing signatures."""
        node = self.nodes[0]
        raw = tx.serialize().hex()
        psbt = PSBT.from_base64(node.converttopsbt(raw, True))
        psbt.i[0].map[PSBT_IN_NON_WITNESS_UTXO] = funding.serialize()
        if tx.vin[0].scriptSig:
            psbt.i[0].map[PSBT_IN_FINAL_SCRIPTSIG] = bytes(tx.vin[0].scriptSig)
        if not tx.wit.is_null():
            psbt.i[0].map[PSBT_IN_FINAL_SCRIPTWITNESS] = tx.wit.vtxinwit[0].serialize()
        encoded = psbt.to_base64()
        final = node.finalizepsbt(encoded)
        assert_equal(final['complete'], True)
        assert_equal(final['hex'], raw)
        analysis = node.analyzepsbt(encoded)
        assert_equal(analysis['next'], 'extractor')
        assert_equal(analysis['inputs'][0]['is_final'], True)
        assert 'error' not in analysis

        prevout = dict(txid=funding.txid_hex, vout=index, amount=Decimal(value) / 100_000_000, scriptPubKey=output.hex())
        if kind == 'legacy_multi':
            prevout['redeemScript'] = script.hex()
        if kind == 'v0_multi':
            prevout['witnessScript'] = script.hex()
        for keys in ([], [secret]):
            signed = node.signrawtransactionwithkey(raw, keys, [prevout])
            assert_equal(signed['complete'], True)
            assert_equal(signed['hex'], raw)
            assert 'errors' not in signed
        if self.is_tidecoin_tx_compiled():
            rules = '-rules=post-auxpow' if active else '-rules=pre-auxpow'
            command = self.get_binaries().tx_argv() + ['-regtest', rules, '-verify', raw,
                                                      'set=prevtxs:' + json.dumps([prevout], default=str)]
            result = subprocess.run(command, capture_output=True, text=True)
            assert_equal(result.returncode, 0)
            assert_equal(result.stdout.strip(), 'OK')

    def run_test(self):
        node = self.nodes[0]
        if not self.is_tidecoin_tx_compiled():
            self.log.info('Skipping utility verification: tidecoin-tx was not built')
        mini = MiniWallet(node)
        self.generate(mini, 101)
        rows = []
        value = 1_000_000
        funding = mini.create_self_transfer()
        total = funding['tx'].vout[0].nValue
        for scheme in range(7, 12):
            secret, pubkey = generate_keypair(scheme=str(scheme))
            kinds = ['legacy', 'v0', 'legacy_multi', 'v0_multi'] + [prefix + form for prefix in ('', 'wrapped_') for form in ('v1', 'verify', 'not', 'multi', 'multi_verify', 'multi_not', 'multi_unreached', 'multi_unreached_not')]
            for kind in kinds:
                if 'multi' in kind:
                    count = OP_2 if 'unreached' in kind else OP_1
                    script = CScript([count] + [pubkey] * (2 if 'unreached' in kind else 1) + [count, OP_CHECKMULTISIGVERIFY if 'verify' in kind else OP_CHECKMULTISIG])
                else:
                    script = CScript([pubkey, OP_CHECKSIGVERIFY if 'verify' in kind else OP_CHECKSIG])
                if 'verify' in kind:
                    script = CScript(bytes(script) + bytes(CScript([OP_1])))
                if 'not' in kind:
                    script = CScript(bytes(script) + bytes(CScript([OP_NOT])))
                program = CScript([OP_1, sha512(script).digest()])
                if kind == 'legacy':
                    output = key_to_p2pkh_script(pubkey)
                elif kind == 'v0':
                    output = key_to_p2wpkh_script(pubkey)
                elif kind == 'legacy_multi':
                    output = script_to_p2sh_script(script)
                elif kind == 'v0_multi':
                    output = script_to_p2wsh_script(script)
                elif kind.startswith('wrapped'):
                    output = script_to_p2sh_script(program)
                else:
                    output = program
                rows.append((kind, secret, pubkey, script, program, output))
        funding['tx'].vout = [CTxOut(value, row[-1]) for row in rows] + [CTxOut(total - len(rows) * value - 10_000, mini.get_output_script())]
        self.generateblock(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, [funding['tx'].serialize().hex()])
        self.generate(mini, 6)
        assert_equal(node.getblockcount(), 108)
        # Before activation the 64-byte programs are ordinary scripts.
        # Blocks accept their witness-free form and reject unexpected witness.
        for index, (kind, _, _, script, program, _) in enumerate(rows):
            if kind.startswith(('legacy', 'v0')):
                continue
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(funding['tx'].txid_hex, 16), index))]
            tx.vout = [CTxOut(value - 10_000, mini.get_output_script())]
            tx.vin[0].scriptSig = CScript([program]) if kind.startswith('wrapped') else b''
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x04', bytes(script)]
            raw = tx.serialize().hex()
            assert_raises_rpc_error(-25, 'Witness provided for non-witness script', self.candidate, raw)
            tx.wit.vtxinwit = []
            assert 'hex' in self.candidate(tx.serialize().hex())
            admission = node.testmempoolaccept([raw])[0]
            assert not admission['allowed']
            assert 'Signature hash type missing or not understood' not in admission['reject-reason']
        for active in (False, True):
            if active:
                self.generate(mini, 1)
            assert_equal(node.getblockcount(), 109 if active else 108)
            for index, (kind, secret, pubkey, script, program, output) in enumerate(rows):
                legacy_or_v0 = kind.startswith(('legacy', 'v0'))
                if not active and (not legacy_or_v0 or pubkey[0] != 7):
                    continue
                self.log.debug('Checking active=%s, scheme %s, form %s', active, pubkey[0], kind)
                tx = CTransaction()
                tx.vin = [CTxIn(COutPoint(int(funding['tx'].txid_hex, 16), index))]
                tx.vout = [CTxOut(value - 10_000, mini.get_output_script())]
                modes = (1, 4) if 'unreached' in kind else (1, 2, 3, 0x81, 0x82, 0x83, 0, 4, 0x22, 0x41, 0x43, 0x80, 0x84, 0xff)
                for mode in modes:
                    if 'not' in kind or 'unreached' in kind:
                        sig = bytes([mode])  # Nonempty, invalid under both byte choices.
                    else:
                        if kind.startswith('legacy'):
                            digest, error = LegacySignatureHash(script if kind == 'legacy_multi' else output, tx, 0, mode)
                            assert error is None
                        elif kind.startswith('v0'):
                            digest = SegwitV0SignatureHash(script if kind == 'v0_multi' else key_to_p2pkh_script(pubkey), tx, 0, mode, value)
                        else:
                            digest = witness_v1_hash(tx, script, value, output, mode)
                        sig = bytes.fromhex(subprocess.check_output([_get_testkeys_path(), '--sign-key=' + secret, '--sign-hash=' + digest.hex()], text=True).strip()) + bytes([mode])
                    if kind == 'legacy':
                        tx.vin[0].scriptSig = CScript([sig, pubkey])
                    elif kind == 'legacy_multi':
                        tx.vin[0].scriptSig = CScript([b'', sig, bytes(script)])
                    else:
                        tx.vin[0].scriptSig = CScript([program]) if kind.startswith('wrapped') else b''
                        tx.wit.vtxinwit = [CTxInWitness()]
                        stack = [sig, pubkey if kind == 'v0' else bytes(script)]
                        if 'multi' in kind:
                            stack.insert(0, b'')
                        if 'unreached' in kind:
                            stack.insert(-1, b'')  # First attempted signature fails before the undefined argument.
                        tx.wit.vtxinwit[0].scriptWitness.stack = stack
                    raw = tx.serialize().hex()
                    defined = mode in (1, 2, 3, 0x81, 0x82, 0x83)
                    # Blocks retain legacy/v0 hash-type behavior even when
                    # mempool policy and active v1 require defined bytes.
                    allowed = legacy_or_v0 or defined
                    ordinary_false = 'unreached' in kind and 'not' not in kind
                    hash_error = not defined and not legacy_or_v0
                    if ordinary_false:
                        allowed = False
                    if allowed:
                        assert 'hex' in self.candidate(raw), (kind, mode)
                    else:
                        assert_raises_rpc_error(-25, 'Signature hash type missing or not understood' if hash_error else 'block-script-verify-flag-failed', self.candidate, raw)
                    admission = node.testmempoolaccept([raw])[0]
                    assert_equal(admission['allowed'], allowed and defined and 'not' not in kind)
                    if not defined:
                        assert_equal(admission['reject-reason'], 'mempool-script-verify-flag-failed (Signature hash type missing or not understood)')
                        if legacy_or_v0:
                            self.check_existing_final(tx, funding['tx'], index, value, kind, script, output, secret, active)
        self.log.info('All five schemes: defined/undefined bytes, native/wrapped v1, legacy/v0 single-signature and multisig controls, and negated checks verified')


if __name__ == '__main__':
    WitnessV1HashTypesTest(__file__).main()
