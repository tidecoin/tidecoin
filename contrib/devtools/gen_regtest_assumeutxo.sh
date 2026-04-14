#!/usr/bin/env bash
#
# Generate regtest assumeutxo parameters for Tidecoin's deterministic unit-test chain.
#
# This reuses the existing unit test that writes a UTXO snapshot at height 110 and
# prints the needed fields (base_hash/txoutset_hash/nchaintx).
#
# Usage:
#   ./contrib/devtools/gen_regtest_assumeutxo.sh
#
export LC_ALL=C

set -euo pipefail

cd "$(dirname "$0")/../.."

OUT="$(./build/bin/test_tidecoin \
  --run_test=validation_chainstatemanager_tests/chainstatemanager_activate_snapshot \
  --report_level=no \
  -- \
  --printtoconsole=1 2>&1 || true)"

SNAPSHOT_OUTPUT="$OUT" python3 - <<'PY'
import json, os, re, sys
text = os.environ["SNAPSHOT_OUTPUT"]
m = re.search(r'Wrote UTXO snapshot to .*?: (\{.*\})\s*$', text, re.M)
if not m:
    print("error: could not find snapshot JSON in test output", file=sys.stderr)
    sys.exit(1)
obj = json.loads(m.group(1))
print("Add this to CRegTestParams::m_assumeutxo_data in src/kernel/chainparams.cpp:")
print()
print(f'{{.height = {obj["base_height"]}, .hash_serialized = AssumeutxoHash{{uint256{{"{obj["txoutset_hash"]}"}}}}, .m_chain_tx_count = {obj["nchaintx"]}U, .blockhash = consteval_ctor(uint256{{"{obj["base_hash"]}"}})}},')
PY
