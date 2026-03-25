#!/usr/bin/env python3
"""Generate Tide mainnet vectors for test/functional/mining_mainnet.py.

This script mines 7199 blocks on a clean main-chain datadir with deterministic
mocktime spacing and stores full block hex + header fields. The functional test
replays those blocks through submitblock and verifies the historical retarget
for block 7200 via getmininginfo.next.
"""

from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "test" / "functional"))

from test_framework.test_framework import BitcoinTestFramework


COINBASE_SCRIPT_PUBKEY = "76a914eadbac7f36c37e39361168b7aaee3cb24a25312d88ac"
RETARGET_INTERVAL = 7200
START_MOCKTIME = 1609074600


class GenerateMiningMainnetAltTide(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = ""  # main
        self.extra_args = [[f"-mocktime={START_MOCKTIME}"]]

    def add_options(self, parser):
        parser.add_argument(
            "--output",
            default=str(pathlib.Path(__file__).resolve().parents[2] / "test" / "functional" / "data" / "mainnet_tide_alt.json"),
            help="Output JSON file path",
        )

    def run_test(self):
        node = self.nodes[0]
        genesis_hash = node.getblockhash(0)
        genesis_time = node.getblockheader(genesis_hash)["time"]
        descriptor = node.getdescriptorinfo(f"raw({COINBASE_SCRIPT_PUBKEY})")["descriptor"]

        blocks = []
        for height in range(1, RETARGET_INTERVAL):
            block_hash = node.generateblock(descriptor, [], called_by_framework=True)["hash"]
            header = node.getblockheader(block_hash)
            blocks.append({
                "hash": block_hash,
                "hex": node.getblock(block_hash, 0),
                "time": header["time"],
                "nonce": header["nonce"],
                "bits": header["bits"],
                "version": header["version"],
            })
            if height % 500 == 0:
                self.log.info(f"Generated {height}/{RETARGET_INTERVAL} blocks")

        vectors = {
            "chain": "tidecoin-main",
            "genesis_hash": genesis_hash,
            "retarget_interval": RETARGET_INTERVAL,
            "initial_nbits": f"0x{blocks[0]['bits']}",
            "expected_next_bits": node.getmininginfo()["next"]["bits"],
            "block_version": hex(blocks[0]["version"]),
            "coinbase_script_pubkey": COINBASE_SCRIPT_PUBKEY,
            "genesis_time": genesis_time,
            "start_mocktime": START_MOCKTIME,
            "blocks": blocks,
        }

        output_path = pathlib.Path(self.options.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")
        self.log.info(f"Wrote vectors to {output_path}")


if __name__ == "__main__":
    GenerateMiningMainnetAltTide(__file__).main()
