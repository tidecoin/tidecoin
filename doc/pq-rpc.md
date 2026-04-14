# Tidecoin-Specific RPC Commands

This document covers RPC commands that are specific to Tidecoin extensions, in
particular AuxPoW merge-mining flows and PQHD wallet policy/seed management.

## Overview

| Command | Scope | Purpose |
| --- | --- | --- |
| `createauxblock` | Node RPC (`mining`) | Create an AuxPoW candidate block for merge-mining. |
| `submitauxblock` | Node RPC (`mining`) | Submit solved AuxPoW for a previously created candidate. |
| `getauxblock` | Wallet RPC (`wallet`) | Wallet-assisted create/submit flow for merge-mining. |
| `setpqhdpolicy` | Wallet RPC (`wallet`) | Set default PQ scheme policy for receive/change addresses. |
| `listpqhdseeds` | Wallet RPC (`wallet`) | List PQHD seeds tracked by the wallet. |
| `importpqhdseed` | Wallet RPC (`wallet`) | Import a 32-byte PQHD master seed. |
| `setpqhdseed` | Wallet RPC (`wallet`) | Select default PQHD seed ids for receive/change derivation. |
| `removepqhdseed` | Wallet RPC (`wallet`) | Remove a non-default, unreferenced PQHD seed. |

## AuxPoW RPCs

### `createauxblock`

Create a merge-mining candidate with a specified payout address.

```bash
tidecoin-cli createauxblock "<tidecoin_address>"
```

Example:

```bash
tidecoin-cli createauxblock "tTidecoinAddressHere"
```

Notes:

- Fails if node is disconnected or in IBD (except `-regtest`/on-demand mining).
- Fails before AuxPoW activation height.
- Returns object fields including `hash`, `chainid`, `previousblockhash`,
  `coinbasevalue`, `bits`, `height`.

### `submitauxblock`

Submit solved auxpow for a candidate from `createauxblock`.

```bash
tidecoin-cli submitauxblock "<block_hash>" "<auxpow_hex>"
```

Example:

```bash
tidecoin-cli submitauxblock \
  "0000000000000000000000000000000000000000000000000000000000000000" \
  "<serialized_auxpow_hex>"
```

Returns `true` if accepted, otherwise `false`.

### `getauxblock`

Wallet-assisted AuxPoW flow.

- Without arguments: create candidate block using a wallet-derived coinbase
  payout script.
- With `hash` and `auxpow`: submit solved auxpow.

Create:

```bash
tidecoin-cli -rpcwallet="<wallet>" getauxblock
```

Submit:

```bash
tidecoin-cli -rpcwallet="<wallet>" getauxblock "<block_hash>" "<auxpow_hex>"
```

Notes:

- Requires a loaded wallet with private keys enabled.
- On successful submit, the wallet rotates mining key state for the candidate.

## PQHD Wallet RPCs

### `setpqhdpolicy`

Set default PQ scheme for new receive/change addresses.

```bash
tidecoin-cli -rpcwallet="<wallet>" setpqhdpolicy "<receive_scheme>" "<change_scheme>"
```

Examples:

```bash
tidecoin-cli -rpcwallet="<wallet>" setpqhdpolicy "falcon-512" "falcon-512"
tidecoin-cli -rpcwallet="<wallet>" setpqhdpolicy "mldsa65" "mldsa65"
```

Accepted scheme inputs:

- Name forms such as `falcon-512`, `falcon1024`, `mldsa44`, `mldsa65`,
  `mldsa87`
- Numeric scheme prefix byte (0-255) for a known Tidecoin PQ scheme

Returns selected scheme ids and names.

### `listpqhdseeds`

List PQHD seeds known to the wallet.

```bash
tidecoin-cli -rpcwallet="<wallet>" listpqhdseeds
```

Each entry contains:

- `seed_id` (hex)
- `created_at` (timestamp)
- `encrypted` (bool)
- `default_receive` (bool)
- `default_change` (bool)

### `importpqhdseed`

Import a 32-byte PQHD master seed (idempotent for existing seeds).

```bash
tidecoin-cli -rpcwallet="<wallet>" importpqhdseed "<32_byte_seed_hex>"
```

Example:

```bash
tidecoin-cli -rpcwallet="<wallet>" importpqhdseed \
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
```

Returns derived `seed_id` and whether a new record was inserted.

### `setpqhdseed`

Set default receive/change seed ids for PQHD derivation policy.

```bash
tidecoin-cli -rpcwallet="<wallet>" setpqhdseed "<receive_seed_id>" "<change_seed_id>"
```

If `change_seed_id` is omitted, receive seed id is used for both.

### `removepqhdseed`

Remove a seed that is not default and not referenced by wallet descriptors.

```bash
tidecoin-cli -rpcwallet="<wallet>" removepqhdseed "<seed_id>"
```

Returns removed `seed_id` and `removed=true` on success.

## Related RPC Options

These are not separate commands, but Tidecoin-specific options on existing RPCs:

- `getaddressinfo` option `include_pqhd_origin`
- `walletprocesspsbt` option `include_pqhd_origins`

Use `help <command>` for full argument and result schemas.
