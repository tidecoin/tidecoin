# Regtest AuxPoW activation

Regtest defaults to AuxPoW activation at height **0**, preserving its existing
scrypt mining behavior. Override the height to test the mainnet-style yespower
path or a transition between the two rule sets:

```sh
tidecoind -regtest -datadir=/path/to/fresh-test-data -auxpowactivationheight=500
tidecoind -regtest -datadir=/path/to/fresh-test-data -auxpowactivationheight=never
```

The same setting is available in `tidecoin.conf`:

```ini
[regtest]
auxpowactivationheight=never
```

Accepted values are integers from 0 through 2147483646, or the literal `never`.
Command-line settings take precedence over configuration-file settings. Mainnet
and testnet reject an explicitly applied override; their defaults are unchanged.
A value under `[regtest]` is only applied when regtest is selected.

The fixed regtest genesis block retains its original scrypt proof of work and
block hash for every setting. For activation height `H`, subsequent blocks below
`H` use yespower 1.0, N=2048, r=8 without personalization and reject AuxPoW.
Starting at block `H`, ordinary
blocks use scrypt and AuxPoW blocks may prove work through a scrypt parent.
AuxPoW mining RPC availability follows the **next block's height**.

This changes the shared activation boundary, not just the mining algorithm.
It also selects the legacy/post-activation difficulty code and gates strict PQ
verification, witness-v1 and SHA512 script rules. Regtest's no-retargeting flag
and easy proof-of-work limit remain unchanged. `never` selects pre-activation
behavior throughout the usable height range.

Use fresh test data when changing rules for already stored blocks. Nodes that
exchange blocks must use matching activation settings. This setting neither
revalidates an existing chainstate nor isolates peers automatically.

The node's generation RPCs select the appropriate hash for the candidate height.
Existing Python `CBlock.solve()` helpers still solve scrypt; for yespower tests,
use the node's `generateblock(..., submit=false)` and submit the returned block,
or a yespower-capable external miner.

Tests:

```sh
cmake -B build
cmake --build build --target tidecoind test_tidecoin -j4
ctest --test-dir build --output-on-failure -R '^(pow_tests|auxpow_tests|auxpow_serialization_tests|yespower_tests|argsman_tests|getarg_tests|versionbits_tests|blockmanager_tests)$'
python3 build/test/functional/test_runner.py feature_auxpow_activation.py auxpow_mining.py auxpow_invalidpow.py auxpow_zerohash.py feature_config_args.py --jobs=3
```

The activation test starts isolated nodes with default, delayed, and disabled
activation. It checks genesis startup, CLI/config precedence, yespower-only block
acceptance before activation and rejection at activation, scrypt and AuxPoW
acceptance after activation, unchanged target bits, restart, and invalid options.
