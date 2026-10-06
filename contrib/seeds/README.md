# Tidecoin fixed seeds

`makeseeds.py` selects candidate endpoints from a Tidecoin DNS seeder's crawler
report. `generate-seeds.py` converts reviewed `nodes_main.txt` and `nodes_test.txt`
files into the arrays used by [src/chainparamsseeds.h](/src/chainparamsseeds.h).
These are maintenance tools; the running daemon does not execute the agent filter.

## Supported agents

The explicit `PATTERN_AGENT` allowlist accepts:

- `/Tidecoin:1.0.0/` from the current implementation.
- `/TidecoinCore:0.18.3/` from the legacy implementation.

Both may include the optional comments emitted by `-uacomment`, for example
`/Tidecoin:1.0.0(node one; archive)/`. The complete agent must match. Bitcoin's
`/Satoshi:.../`, other client names, unlisted versions and malformed suffixes
are excluded. Review the allowlist when releasing another version.

Agent strings are self-reported and do not prove network membership, software
identity or transport capability. The existing block-height, network-service,
uptime, duplicate, multiport and ASN-diversity filters still apply. This utility
does not require V2 support; legacy V1 peers remain eligible.

## Crawler input and generation

Obtain crawler reports for the intended **Tidecoin** network from its seed
operator. A DNS address response alone lacks the required fields. Do not use
Bitcoin seed reports. This repository does not specify a verified public URL
for downloading Tidecoin crawler reports.

The expected whitespace-separated columns are endpoint, good flag, last-success
Unix timestamp, five uptime percentages (2h, 8h, 1d, 7d, 30d), block height,
hexadecimal services, protocol version, and the final double-quoted user agent.
The agent may contain spaces. Lines beginning with `#` are comments. For example:

```text
1.1.1.1:8755 1 1791280800 99% 99% 99% 99% 99% 3000000 40d 70015 "/TidecoinCore:0.18.3(example node)/"
```

This is a synthetic format example, not a seed recommendation. Validate the
operator's report format before processing it. Use a suitable ASN map for
diversity filtering. Choose `--minblocks` separately for each network based on
its current chain; the retained default is 910000, not a current-tip assertion.
The mainnet and testnet default P2P ports are 8755 and 18755; the tools preserve
the port in each input endpoint rather than substituting a default.

From this directory, with local reports, ASN data and selected height thresholds:

```bash
python3 makeseeds.py -a asmap-filled.dat -s seeds_main.txt --minblocks "$MAIN_MIN_BLOCKS" > nodes_main.candidate.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_test.txt --minblocks "$TEST_MIN_BLOCKS" > nodes_test.candidate.txt
```

Inspect the candidates and filter counts. Check network membership, reachability,
required services and diversity before replacing the corresponding `nodes_*.txt`.
In particular, compare services with `SeedsServiceFlags()` when its requirements
change. A successful command with empty output is not a usable seed list.
After reviewing both input lists, generate a candidate header:

```bash
python3 generate-seeds.py . > chainparamsseeds.h.new
```

Review it before replacing `../../src/chainparamsseeds.h`. Generation does not
contact peers or verify the selected addresses. The checked-in mainnet candidate
list records its DNS-sampling provenance in `nodes_main.txt`; these instructions
do not claim it was generated from a retained crawler report.

## Offline regression tests

From the repository root:

```bash
python3 contrib/seeds/test_makeseeds.py -v
```

Tests cover both implementations' agents, comments containing spaces, rejected
agents and truncated input, plus the complete selection-to-header workflow using
synthetic crawler records and an ASN map. They do not change the checked-in seeds
or contact the network.
