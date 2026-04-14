#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate raw PQ script-assets corpus entries for script_assets minimization.

Run with --dumptests and set TEST_DUMP_DIR to emit one JSON object line per file,
formatted for src/test/fuzz/script_assets_test_minimizer.cpp merge flow.
"""

from decimal import Decimal
import json
import os
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.messages import (
    COIN,
    MAX_SEQUENCE_NONFINAL,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    sha256,
    tx_from_hex,
)
from test_framework.script import (
    CScript,
    LOCKTIME_THRESHOLD,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    OP_EQUAL,
    OP_HASH160,
    OP_0,
    OP_TRUE,
    bn2vch,
    hash160,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than

FLAG_ORDER = (
    "P2SH",
    "NULLDUMMY",
    "CHECKLOCKTIMEVERIFY",
    "CHECKSEQUENCEVERIFY",
    "WITNESS",
    "PQ_STRICT",
)

SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22


class PQScriptAssetsDumper(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.uses_wallet = True
        self.setup_clean_chain = False

    def add_options(self, parser):
        parser.add_argument(
            "--dumptests",
            action="store_true",
            default=False,
            help="Dump raw script-assets corpus entries into TEST_DUMP_DIR",
        )

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _to_sats(self, amount):
        return int(Decimal(str(amount)) * COIN)

    def _mutate_hex(self, hex_data):
        raw = bytearray.fromhex(hex_data)
        if not raw:
            return "00"
        raw[0] ^= 0x01
        return raw.hex()

    def _mutate_witness(self, witness_stack_hex):
        mutated = list(witness_stack_hex)
        for i, item in enumerate(mutated):
            if item:
                mutated[i] = self._mutate_hex(item)
                return mutated
        mutated.append("00")
        return mutated

    def _to_tx_without_witness(self, signed_hex):
        tx = tx_from_hex(signed_hex)
        return tx, tx.serialize_without_witness().hex()

    def _make_asset_entry(self, *, signed_hex, utxo, flags, comment):
        tx, tx_nowit_hex = self._to_tx_without_witness(signed_hex)
        vin_index = 0

        script_sig_hex = tx.vin[vin_index].scriptSig.hex()
        witness = []
        if vin_index < len(tx.wit.vtxinwit):
            witness = [item.hex() for item in tx.wit.vtxinwit[vin_index].scriptWitness.stack]

        bad_script_sig = script_sig_hex
        bad_witness = list(witness)
        if bad_witness:
            bad_witness = self._mutate_witness(bad_witness)
        elif bad_script_sig:
            bad_script_sig = self._mutate_hex(bad_script_sig)
        else:
            bad_script_sig = "00"

        prevout = CTxOut(
            nValue=self._to_sats(utxo["amount"]),
            scriptPubKey=bytes.fromhex(utxo["scriptPubKey"]),
        ).serialize().hex()

        return {
            "tx": tx_nowit_hex,
            "prevouts": [prevout],
            "index": vin_index,
            "flags": flags,
            "comment": comment,
            "success": {
                "scriptSig": script_sig_hex,
                "witness": witness,
            },
            "failure": {
                "scriptSig": bad_script_sig,
                "witness": bad_witness,
            },
        }

    def _make_static_tx(self, *, version, locktime, sequence):
        tx = CTransaction()
        tx.version = version
        tx.vin = [CTxIn(COutPoint(1, 0), b"", sequence)]
        tx.vout = [CTxOut(1000, CScript([OP_TRUE]))]
        tx.nLockTime = locktime
        return tx.serialize_without_witness().hex()

    def _make_static_script_entry(
        self,
        *,
        tx_hex,
        script_pub_key,
        flags,
        comment,
        success_script_sig,
        failure_script_sig,
    ):
        prevout = CTxOut(nValue=1000, scriptPubKey=script_pub_key).serialize().hex()
        return {
            "tx": tx_hex,
            "prevouts": [prevout],
            "index": 0,
            "flags": flags,
            "comment": comment,
            "success": {
                "scriptSig": success_script_sig.hex(),
                "witness": [],
            },
            "failure": {
                "scriptSig": failure_script_sig.hex(),
                "witness": [],
            },
        }

    def _make_static_witness_entry(
        self,
        *,
        tx_hex,
        script_pub_key,
        flags,
        comment,
        success_witness,
        failure_witness,
        success_script_sig=None,
        failure_script_sig=None,
    ):
        success_script_sig = success_script_sig or CScript([])
        failure_script_sig = failure_script_sig or CScript([])
        prevout = CTxOut(nValue=1000, scriptPubKey=script_pub_key).serialize().hex()
        return {
            "tx": tx_hex,
            "prevouts": [prevout],
            "index": 0,
            "flags": flags,
            "comment": comment,
            "success": {
                "scriptSig": success_script_sig.hex(),
                "witness": [item.hex() for item in success_witness],
            },
            "failure": {
                "scriptSig": failure_script_sig.hex(),
                "witness": [item.hex() for item in failure_witness],
            },
        }

    def _merge_flags(self, *flag_groups):
        enabled = set()
        for group in flag_groups:
            if not group:
                continue
            for flag in group.split(","):
                flag = flag.strip()
                if flag:
                    enabled.add(flag)
        return ",".join(flag for flag in FLAG_ORDER if flag in enabled)

    def _p2sh_script(self, redeem_script):
        return CScript([OP_HASH160, hash160(bytes(redeem_script)), OP_EQUAL])

    def _p2wsh_script(self, witness_script):
        return CScript([OP_0, sha256(bytes(witness_script))])

    def _build_timelock_entries(self):
        entries = []

        cltv_script = CScript([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_TRUE])
        cltv_tx = self._make_static_tx(version=2, locktime=10, sequence=MAX_SEQUENCE_NONFINAL)
        entries.append(
            self._make_static_script_entry(
                tx_hex=cltv_tx,
                script_pub_key=cltv_script,
                flags="CHECKLOCKTIMEVERIFY,PQ_STRICT",
                comment="PQ static CLTV spend",
                success_script_sig=CScript([5]),
                failure_script_sig=CScript([11]),
            )
        )

        cltv_time_tx = self._make_static_tx(
            version=2,
            locktime=LOCKTIME_THRESHOLD + 20,
            sequence=MAX_SEQUENCE_NONFINAL,
        )
        entries.append(
            self._make_static_script_entry(
                tx_hex=cltv_time_tx,
                script_pub_key=cltv_script,
                flags="CHECKLOCKTIMEVERIFY,PQ_STRICT",
                comment="PQ static CLTV time-lock spend",
                success_script_sig=CScript([LOCKTIME_THRESHOLD + 5]),
                failure_script_sig=CScript([LOCKTIME_THRESHOLD + 30]),
            )
        )

        csv_script = CScript([OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_TRUE])
        csv_tx = self._make_static_tx(version=2, locktime=0, sequence=5)
        entries.append(
            self._make_static_script_entry(
                tx_hex=csv_tx,
                script_pub_key=csv_script,
                flags="CHECKSEQUENCEVERIFY,PQ_STRICT",
                comment="PQ static CSV spend",
                success_script_sig=CScript([5]),
                failure_script_sig=CScript([6]),
            )
        )

        csv_time_tx = self._make_static_tx(
            version=2,
            locktime=0,
            sequence=SEQUENCE_LOCKTIME_TYPE_FLAG | 12,
        )
        entries.append(
            self._make_static_script_entry(
                tx_hex=csv_time_tx,
                script_pub_key=csv_script,
                flags="CHECKSEQUENCEVERIFY,PQ_STRICT",
                comment="PQ static CSV time-lock spend",
                success_script_sig=CScript([SEQUENCE_LOCKTIME_TYPE_FLAG | 7]),
                failure_script_sig=CScript([11]),
            )
        )

        cltv_csv_script = CScript([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_TRUE])
        cltv_csv_tx = self._make_static_tx(version=2, locktime=12, sequence=6)
        entries.append(
            self._make_static_script_entry(
                tx_hex=cltv_csv_tx,
                script_pub_key=cltv_csv_script,
                flags="CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,PQ_STRICT",
                comment="PQ static CLTV+CSV spend",
                success_script_sig=CScript([6, 10]),
                failure_script_sig=CScript([6, 13]),
            )
        )

        p2sh_cltv_tx = self._make_static_tx(version=2, locktime=18, sequence=MAX_SEQUENCE_NONFINAL)
        p2sh_cltv_redeem = CScript([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_TRUE])
        entries.append(
            self._make_static_script_entry(
                tx_hex=p2sh_cltv_tx,
                script_pub_key=self._p2sh_script(p2sh_cltv_redeem),
                flags="P2SH,CHECKLOCKTIMEVERIFY,PQ_STRICT",
                comment="PQ static P2SH CLTV spend",
                success_script_sig=CScript([12, bytes(p2sh_cltv_redeem)]),
                failure_script_sig=CScript([21, bytes(p2sh_cltv_redeem)]),
            )
        )

        p2sh_csv_tx = self._make_static_tx(version=2, locktime=0, sequence=9)
        p2sh_csv_redeem = CScript([OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_TRUE])
        entries.append(
            self._make_static_script_entry(
                tx_hex=p2sh_csv_tx,
                script_pub_key=self._p2sh_script(p2sh_csv_redeem),
                flags="P2SH,CHECKSEQUENCEVERIFY,PQ_STRICT",
                comment="PQ static P2SH CSV spend",
                success_script_sig=CScript([8, bytes(p2sh_csv_redeem)]),
                failure_script_sig=CScript([10, bytes(p2sh_csv_redeem)]),
            )
        )

        p2sh_cltv_csv_tx = self._make_static_tx(version=2, locktime=24, sequence=11)
        p2sh_cltv_csv_redeem = CScript([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_TRUE])
        entries.append(
            self._make_static_script_entry(
                tx_hex=p2sh_cltv_csv_tx,
                script_pub_key=self._p2sh_script(p2sh_cltv_csv_redeem),
                flags="P2SH,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,PQ_STRICT",
                comment="PQ static P2SH CLTV+CSV spend",
                success_script_sig=CScript([10, 20, bytes(p2sh_cltv_csv_redeem)]),
                failure_script_sig=CScript([10, 25, bytes(p2sh_cltv_csv_redeem)]),
            )
        )

        p2wsh_cltv_tx = self._make_static_tx(version=2, locktime=22, sequence=MAX_SEQUENCE_NONFINAL)
        p2wsh_cltv_script = CScript([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_TRUE])
        entries.append(
            self._make_static_witness_entry(
                tx_hex=p2wsh_cltv_tx,
                script_pub_key=self._p2wsh_script(p2wsh_cltv_script),
                flags=self._merge_flags("P2SH,WITNESS,PQ_STRICT", "CHECKLOCKTIMEVERIFY"),
                comment="PQ static P2WSH CLTV spend",
                success_witness=[bn2vch(19), bytes(p2wsh_cltv_script)],
                failure_witness=[bn2vch(23), bytes(p2wsh_cltv_script)],
            )
        )

        p2wsh_csv_tx = self._make_static_tx(version=2, locktime=0, sequence=13)
        p2wsh_csv_script = CScript([OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_TRUE])
        entries.append(
            self._make_static_witness_entry(
                tx_hex=p2wsh_csv_tx,
                script_pub_key=self._p2wsh_script(p2wsh_csv_script),
                flags=self._merge_flags("P2SH,WITNESS,PQ_STRICT", "CHECKSEQUENCEVERIFY"),
                comment="PQ static P2WSH CSV spend",
                success_witness=[bn2vch(12), bytes(p2wsh_csv_script)],
                failure_witness=[bn2vch(14), bytes(p2wsh_csv_script)],
            )
        )

        p2wsh_cltv_csv_tx = self._make_static_tx(version=2, locktime=30, sequence=14)
        p2wsh_cltv_csv_script = CScript([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_TRUE])
        entries.append(
            self._make_static_witness_entry(
                tx_hex=p2wsh_cltv_csv_tx,
                script_pub_key=self._p2wsh_script(p2wsh_cltv_csv_script),
                flags=self._merge_flags("P2SH,WITNESS,PQ_STRICT", "CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY"),
                comment="PQ static P2WSH CLTV+CSV spend",
                success_witness=[bn2vch(13), bn2vch(28), bytes(p2wsh_cltv_csv_script)],
                failure_witness=[bn2vch(13), bn2vch(32), bytes(p2wsh_cltv_csv_script)],
            )
        )

        return entries

    def _find_exact_utxo(self, node, *, address, txid):
        utxos = node.listunspent(1, 9999999, [address])
        for utxo in utxos:
            if utxo["txid"] == txid:
                return utxo
        raise AssertionError(f"UTXO for address {address} and txid {txid} not found")

    def _create_signed_single_input_spend(self, node, *, utxo, destination, sighashtype):
        amount_out = Decimal(str(utxo["amount"])) - Decimal("0.00005")
        assert_greater_than(amount_out, Decimal("0"))
        raw = node.createrawtransaction(
            inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]}],
            outputs=[{destination: amount_out}],
        )
        signed = node.signrawtransactionwithwallet(raw, [], sighashtype)
        assert signed["complete"]
        tx = tx_from_hex(signed["hex"])
        assert len(tx.vin) == 1
        return signed["hex"]

    def _get_destination_address(self, node, *, tag):
        for address_type in ("bech32", "legacy"):
            try:
                return node.getnewaddress(f"pq-assets-dst-{tag}", address_type)
            except JSONRPCException:
                continue
        raise AssertionError("No supported destination address type found")

    def _build_entries(self, node):
        templates = [
            ("legacy", "legacy"),
            ("p2sh-segwit", "p2sh-witness"),
            ("bech32", "witness"),
        ]
        sighash_modes = [
            ("ALL", "SIGHASH_ALL"),
            ("NONE", "SIGHASH_NONE"),
            ("SINGLE", "SIGHASH_SINGLE"),
            ("ALL|ANYONECANPAY", "SIGHASH_ALL|ANYONECANPAY"),
            ("NONE|ANYONECANPAY", "SIGHASH_NONE|ANYONECANPAY"),
            ("SINGLE|ANYONECANPAY", "SIGHASH_SINGLE|ANYONECANPAY"),
        ]
        flag_profiles = [
            ("", "base"),
            ("NULLDUMMY", "nulldummy"),
            ("CHECKLOCKTIMEVERIFY", "cltv-flag"),
            ("CHECKSEQUENCEVERIFY", "csv-flag"),
            ("CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY", "cltv-csv-flags"),
            ("NULLDUMMY,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY", "nulldummy-cltv-csv-flags"),
        ]
        funded = []

        for address_type, tag in templates:
            try:
                recv_addr = node.getnewaddress(f"pq-assets-{tag}", address_type)
            except JSONRPCException as e:
                self.log.info(f"Skipping unsupported address type '{address_type}': {e.error['message']}")
                continue
            fund_txid = node.sendtoaddress(recv_addr, Decimal("1.0"))
            funded.append((address_type, tag, recv_addr, fund_txid))

        assert funded, "No supported address types available for PQ script-assets dump generation"
        self.generate(node, 1)

        entries = []
        for address_type, tag, recv_addr, fund_txid in funded:
            utxo = self._find_exact_utxo(node, address=recv_addr, txid=fund_txid)
            spend_addr = self._get_destination_address(node, tag=tag)
            base_flags = "PQ_STRICT" if address_type == "legacy" else "P2SH,WITNESS,PQ_STRICT"

            for rpc_mode, label in sighash_modes:
                signed_hex = self._create_signed_single_input_spend(
                    node,
                    utxo=utxo,
                    destination=spend_addr,
                    sighashtype=rpc_mode,
                )
                for profile_flags, profile_label in flag_profiles:
                    flags = self._merge_flags(base_flags, profile_flags)
                    entries.append(
                        self._make_asset_entry(
                            signed_hex=signed_hex,
                            utxo=utxo,
                            flags=flags,
                            comment=f"PQ {tag} spend ({label}, {profile_label})",
                        )
                    )

        entries.extend(self._build_timelock_entries())

        return entries

    def _write_entries(self, entries, output_dir):
        output_dir.mkdir(parents=True, exist_ok=True)
        existing = sorted(output_dir.glob("pq_script_assets_*.json"))
        start = 0
        if existing:
            last = existing[-1].stem.rsplit("_", 1)[-1]
            start = int(last) + 1
        for i, entry in enumerate(entries):
            path = output_dir / f"pq_script_assets_{start + i:04d}.json"
            path.write_text(json.dumps(entry, sort_keys=True) + ",\n", encoding="utf-8")

    def _validate_dump_files(self, output_dir):
        files = sorted(output_dir.glob("pq_script_assets_*.json"))
        assert files, f"No script-assets dump files written to {output_dir}"
        for path in files:
            data = path.read_text(encoding="utf-8")
            assert data.endswith(",\n")
            json.loads(data[:-2])
        return files

    def run_test(self):
        node = self.nodes[0]
        entries = self._build_entries(node)
        assert_greater_than(len(entries), 0)

        if self.options.dumptests:
            dump_dir_env = os.getenv("TEST_DUMP_DIR")
            assert dump_dir_env, "TEST_DUMP_DIR must be set when using --dumptests"
            dump_dir = Path(dump_dir_env)
            self._write_entries(entries, dump_dir)
            files = self._validate_dump_files(dump_dir)
            self.log.info(f"Wrote {len(files)} script-assets raw corpus entries to {dump_dir}")
            return

        # Non-dump mode performs an internal schema sanity check in the temp dir.
        sanity_dir = Path(self.options.tmpdir) / "script_assets_dump_sanity"
        self._write_entries(entries, sanity_dir)
        files = self._validate_dump_files(sanity_dir)
        self.log.info(f"Validated {len(files)} script-assets corpus entries")


if __name__ == "__main__":
    PQScriptAssetsDumper(__file__).main()
