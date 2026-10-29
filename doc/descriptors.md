# Output Descriptors in Tidecoin

Tidecoin supports output descriptors for describing script templates used by RPCs
and descriptor wallets.

This document describes Tidecoin descriptor behavior. It is intentionally
PQHD-first and does not describe disabled BIP32/xpub flows from legacy
descriptor designs.

## Descriptor RPCs

Common RPCs that consume or produce descriptors include:

- `getdescriptorinfo`
- `deriveaddresses`
- `importdescriptors`
- `listdescriptors`
- `scantxoutset`
- `getaddressinfo`
- `listunspent`
- `createmultisig`

`createmultisig` constructs a multisig address and descriptor from supplied public
keys; it does not add them to a wallet. To track the outputs, import the descriptor
with `importdescriptors`. A public-only descriptor can be imported into a
watch-only wallet. For local signing, the signing wallet must have the relevant
private keys or PQHD seeds; importing public keys does not supply them. Fixed-key
descriptors are imported with `active=false`, and their addresses are obtained
with `deriveaddresses`.

See the [multisig tutorial](multisig-tutorial.md) for a complete descriptor-wallet
and PSBT workflow, including constructing descriptors directly with
`getdescriptorinfo` and signing with separate participant wallets.

## Tidecoin-Specific Differences

- Descriptors are PQ-only. Keys must map to a recognized Tidecoin PQ scheme.
- BIP32/xpub/xprv descriptor keys are disabled.
- Key origin metadata (`[fingerprint/path]`) is disabled in descriptor parsing.
- Tidecoin adds `wsh512(...)` for witness v1 64-byte script-hash outputs.
- Ranged wallet descriptors are expected to use `pqhd(...)` with hardened
  wildcard derivation (`*h`).

## Supported Script Functions

Top-level descriptor is `SCRIPT` or `SCRIPT#CHECKSUM`.

Supported functions:

- `pk(KEY)`
- `pkh(KEY)`
- `wpkh(KEY)`
- `combo(KEY)`
- `multi(k,KEY_1,...,KEY_n)`
- `sortedmulti(k,KEY_1,...,KEY_n)`
- `sh(SCRIPT)`
- `wsh(SCRIPT)`
- `wsh512(SCRIPT)`
- `addr(ADDR)`
- `raw(HEX)`

Parser context rules:

- `sh(...)`: top-level only.
- `wsh(...)`: top-level or inside `sh(...)`.
- `wsh512(...)`: top-level only; `sh(wsh512(...))` is not supported.
- `wpkh(...)`: top-level or inside `sh(...)`.
- `combo(...)`, `addr(...)`, `raw(...)`: top-level only.
- `multi(...)` / `sortedmulti(...)`: top-level, inside `sh(...)`, inside
  `wsh(...)`, and inside `wsh512(...)`.
- Miniscript expressions are accepted only inside `wsh(...)` or `wsh512(...)`.

## KEY Expressions

### 1) Raw PQ public key (hex)

`KEY` may be a hex-encoded Tidecoin public key. It must include a valid PQ
scheme prefix byte.

### 2) WIF private key

`KEY` may be a WIF private key when private key material is intended to be
embedded in the descriptor input.

The default WIF format contains the scheme-prefixed private key. Historical
v0.18.3 Falcon-512 WIFs are also accepted: their Base58Check payload, after the
network prefix, is 1281 raw private-key bytes, the byte `01`, and 897 raw
public-key bytes. Neither key in that historical payload has a Tidecoin scheme
prefix. Import validates the embedded public key and requires it to match the
public key derived from the private bytes; inconsistent pairs are rejected.

`dumpprivkey TARGET {"format":"legacy"}` exports this v0.18.3 layout for
Falcon-512. The default `privonly` export remains available for all five schemes.

### 3) PQHD key expression

Tidecoin descriptor wallets use `pqhd(...)`:

`pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/indexh`

or ranged form:

`pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/*h`

Rules enforced by parser:

- `SEEDID32` must be 32-byte hex (64 hex characters).
- Exactly 6 hardened path elements after `pqhd(SEEDID32)`.
- Hardened-only derivation (`h` or `'` suffix).
- Wildcard form must be final `*h` (or `*'`) and then exactly 5 fixed hardened
  elements before it.
- `purpose` must be one of the PQHD purposes listed below.
- `cointype` must be `6868` (mainnet) or `1` (test networks). Either value is
  accepted on any network; default descriptors use the current network's value.
- `scheme` must fit in `uint8` and be a recognized PQ scheme prefix.
- `change` must be `0` or `1`.
- Multipath derivation (`<...;...>`) is not supported in `pqhd(...)`.

Recognized scheme prefixes are currently `7, 8, 9, 10, 11`.

Each standard script family has its own purpose, so one seed and index never
give the same key to two families:

| Purpose | Family |
| --- | --- |
| `10044` | `pkh(KEY)` |
| `10049` | `sh(wpkh(KEY))` |
| `10084` | `wpkh(KEY)` |
| `10087` | `wsh512(pk(KEY))` |
| `10007` | custom and multisig descriptors |

Wallets generate default descriptors with their family purpose and the coin
type of their network. The parser accepts any listed purpose with any script, so
custom descriptors may choose their own paths.

### Disabled key forms

The following are intentionally unsupported in Tidecoin descriptor parsing:

- BIP32/xpub/xprv key expressions
- key-origin bracket metadata (`[abcd1234/...]key`)

## Examples

Single-key examples:

- `pk(<pq_pubkey_hex>)`
- `pkh(<pq_pubkey_hex>)`
- `wpkh(<pq_pubkey_hex>)`
- `sh(wpkh(<pq_pubkey_hex>))`
- `wsh512(pk(<pq_pubkey_hex>))`

Multisig examples:

- `multi(2,<pq_pubkey_hex_1>,<pq_pubkey_hex_2>,<pq_pubkey_hex_3>)`
- `wsh(sortedmulti(2,<pq_pubkey_hex_1>,<pq_pubkey_hex_2>,<pq_pubkey_hex_3>))`
- `wsh512(sortedmulti(2,<pq_pubkey_hex_1>,<pq_pubkey_hex_2>,<pq_pubkey_hex_3>))`

PQHD examples:

- `wpkh(pqhd(<seedid32>)/10084h/6868h/7h/0h/0h/*h)`
- `sh(wpkh(pqhd(<seedid32>)/10049h/6868h/7h/0h/1h/*h))`
- `wsh512(pk(pqhd(<seedid32>)/10087h/6868h/9h/0h/0h/*h))`
- `wsh(sortedmulti(2,pqhd(<seedid_a>)/10007h/6868h/7h/0h/0h/*h,pqhd(<seedid_b>)/10007h/6868h/7h/0h/0h/*h))`

Native witness v1 descriptors (`wsh512`) parse and derive at any height, but
signature checks for their outputs begin at AuxPoW activation. Before that
height, wallets do not issue their addresses, select their coins, or send to
those addresses. Importing a native v1 descriptor is allowed with a warning.

`wsh512` is native only. The descriptor parser rejects `sh(wsh512(...))`, and
signing, PSBT processing and descriptor inference do not support it.
`decodescript` does not suggest a P2SH address for a 64-byte v1 program.
A P2SH wrapper would replace the output's direct SHA-512 commitment with a
20-byte HASH160 commitment.

At consensus, a 64-byte v1 program inside P2SH remains an ordinary script,
just as before activation. With a truthy program and its redeem script, an
empty-witness spend needs no signature. Nonempty witness data fails with
`WITNESS_UNEXPECTED`. Existing relay policy rejects the empty-witness spend
through `CLEANSTACK`; miners can still include it directly. Wallets refuse a
known wrapped-v1 recipient or change address at any height, including when
`solving_data` supplies the redeem script. Opaque P2SH addresses and raw
transaction construction can still express these outputs, so they must not be
used as a receiving format.

Short v1 programs (2–40 bytes), native or inside P2SH, retain unknown-witness
behavior before and after activation. They have no witness spending conditions
at consensus and are not supported receiving formats. Relay policy continues
to refuse their spends.

## Checksums

Descriptors can be suffixed with `#CHECKSUM` (8 characters).

- `getdescriptorinfo` returns canonical descriptor form and checksum.
- `deriveaddresses` requires a checksum on input descriptors.
- Checksums are strongly recommended for all exported/imported descriptors.

## Practical Notes

- `pk(...)` descriptors do not map to a standard address string for
  `deriveaddresses`.
- Ranged descriptors require an explicit range in `deriveaddresses`.
- PQHD seeds are wallet-local; descriptor strings keep public derivation intent,
  while key material remains in wallet storage.

## Wallet local PQHD descriptors in existing RPCs

`deriveaddresses`, `scantxoutset`, `scanblocks`, and `getdescriptoractivity` can
resolve registered PQHD descriptors through an explicitly selected wallet. Use
`-rpcwallet=<name>` or the `/wallet/<name>` RPC endpoint, with a public descriptor
from that wallet's `listdescriptors` result. The descriptor is matched in its
canonical public form. Scanners continue to accept descriptors without a
checksum; `deriveaddresses` continues to require one.

```text
tidecoin-cli -rpcwallet=mywallet deriveaddresses "<public descriptor>" '[0,9]'
tidecoin-cli -rpcwallet=mywallet scantxoutset start '[{"desc":"<public descriptor>","range":[0,9]}]'
tidecoin-cli -rpcwallet=mywallet scanblocks start '[{"desc":"<public descriptor>","range":[0,9]}]'
tidecoin-cli -rpcwallet=mywallet getdescriptoractivity '["<block hash>"]' '[{"desc":"<public descriptor>","range":[0,9]}]'
```

Arguments and result formats are unchanged. Self-contained descriptors continue
to work without any wallet, even if a wallet endpoint is present. PQHD resolution
does not select a default wallet or search other wallets for a matching seed.
Unregistered PQHD paths are rejected. These calls require their existing RPC
method permissions; returned addresses and scripts are wallet public metadata.

Verified cached indices work while the wallet is locked. After an encrypted
wallet is reloaded, unlock it once to verify cached keys against its PQHD seeds;
it may then be locked again. A seed/cache mismatch is rejected without rewriting
the records. An uncached index requires the
seed in the selected wallet and, for an encrypted wallet, a valid unlock via
`walletpassphrase`. Fresh derivation checks the unlock deadline even if the
scheduled relock callback has not run yet. Seeds and private keys are not
returned or handed to the node's scanner. No seed argument is added to these RPCs.

Derivation does not reserve a receiving address, advance the next-address index,
refill the keypool, persist fresh cache entries, or extend wallet monitoring.
Scanning also does not import discovered transactions into the wallet. Use
`getnewaddress` to allocate a receiving address. Calculating an address outside
the monitored range does not make the wallet track payments to it.

The existing range rules apply: indices run from zero through `2147483647`,
with at most 1,000,000 indices in an explicit range. `deriveaddresses` requires a
range for ranged descriptors. Scanners retain their default inclusive range
`[0,1000]`. Fresh PQHD key generation can be expensive; use small ranges when
possible. There is no separate 100-index expansion limit.

One wallet-backed expansion runs per wallet at a time. Wallet locks are released
between indices and before the subsequent blockchain scan. `scantxoutset abort`
and `scanblocks abort` also interrupt their descriptor expansion stage; during
that stage status reports zero scan progress, and interruption returns an error
without a partial scan result. The existing scan-stage result semantics remain
unchanged. `deriveaddresses` and `getdescriptoractivity` have no new abort action.
Wallet locking cancels an active wallet expansion, and shutdown is checked
between indices. An individual cryptographic derivation is not interrupted
midway. Client disconnection alone does not cancel a request.
