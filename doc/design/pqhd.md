# PQHD Specification (Implemented)

This document defines Tidecoin PQHD (Post-Quantum Hierarchical Deterministic
wallet) as implemented in the current codebase.

PQHD is a descriptor-wallet key derivation and policy system for post-quantum
signature schemes. It replaces BIP32/xpub-style public derivation in Tidecoin.

## 1. Scope

This specification covers:

- PQHD v1 key derivation and deterministic key generation
- Descriptor syntax and semantics for `pqhd(...)`
- Wallet storage records and policy behavior
- AuxPoW height-gated scheme policy
- PSBT proprietary PQHD origin metadata
- RPC-visible PQHD behavior

This specification does not define consensus script rules. It defines wallet,
descriptor, and metadata behavior.

## 2. Normative References

Primary implementation touchpoints:

- `src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`
- `src/pq/pqhd_params.h`
- `src/pq/pqhd_keygen.cpp`, `src/pq/pq_api.h`
- `src/pq/pq_scheme.h`
- `src/script/descriptor.h`, `src/script/descriptor.cpp`
- `src/wallet/pqhd.h`
- `src/wallet/wallet.cpp`, `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`
- `src/wallet/walletutil.cpp`
- `src/wallet/scriptpubkeyman.cpp`
- `src/wallet/rpc/wallet.cpp`, `src/wallet/rpc/addresses.cpp`,
  `src/wallet/rpc/spend.cpp`, `src/wallet/rpc/util.cpp`
- `src/psbt.h`, `src/psbt.cpp`

## 3. Scheme Registry

PQHD uses Tidecoin scheme prefix bytes from `src/pq/pq_scheme.h`:

| Scheme | Prefix (hex) | Prefix (dec) |
| --- | --- | ---: |
| Falcon-512 | `0x07` | 7 |
| Falcon-1024 | `0x08` | 8 |
| ML-DSA-44 | `0x09` | 9 |
| ML-DSA-65 | `0x0A` | 10 |
| ML-DSA-87 | `0x0B` | 11 |

`pq::SchemeFromPrefix()` is authoritative for recognizing scheme ids.

## 4. Path Constants and Shape

Constants from `src/pq/pqhd_params.h`:

- `PURPOSE = 10007`
- `COIN_TYPE = 6868`

PQHD v1 leaf paths MUST satisfy:

- exactly 6 elements
- every element hardened (bit 31 set)
- element 0 = `10007h`
- element 1 = `6868h`
- element 2 = known scheme prefix as hardened integer
- element 4 (`change`) MUST be `0h` or `1h`

Validation function: `pqhd::ValidateV1LeafPath()`.
This validation is enforced by KDF leaf derivation and reused by PSBT origin
decode; descriptor parsing applies the same path semantics.

## 5. Seed and Node Derivation (PQHD v1)

### 5.1 Master seed

PQHD master seed is exactly 32 bytes.

### 5.2 SeedID32

`SeedID32 = SHA256("Tidecoin PQHD seedid v1" || master_seed32)`

Implementation function: `pqhd::ComputeSeedID32()`.

#### 5.2.1 Representation and byte order

Canonical `SeedID32` is a 32-byte digest in big-endian hex form.

Wallet storage uses `uint256`, whose byte-array constructor expects little-endian
byte order. Therefore PQHD defines explicit conversion helpers:

- `seedid_be = ComputeSeedID32(master_seed32)` (canonical bytes)
- `seed_id_uint256 = SeedID32ToUint256(seedid_be)`
- `seed_id_uint256.ToString()` yields canonical `SeedID32` hex

Reverse conversion is `SeedID32FromUint256(seed_id_uint256)`.

Implementation reference: `src/pq/pqhd_kdf.{h,cpp}`.

For the master-seed test vector
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
`ComputeSeedID32()` returns:

- `13f45473287a2920f659a303dfc449ab5bf97cba2e23024c61439348ae0eb602`

The same canonical hex is what wallet/RPC surfaces for seed ids.

Tooling guidance:

- treat `seed_id` / `pqhd_seedid` strings as canonical `SeedID32` hex
- do not reinterpret them as raw internal `uint256` little-endian bytes
- if comparing against raw `uint256` byte arrays, apply the same reversal rule

### 5.3 Master node

`I = HMAC_SHA512(key="Tidecoin PQHD seed", msg=master_seed32)`

- `node_secret = I[0..31]`
- `chain_code = I[32..63]`

Implementation function: `pqhd::MakeMasterNode()`.

### 5.4 Child derivation

PQHD v1 is hardened-only.

Given parent `(node_secret, chain_code)` and hardened index `i`:

- `data = 0x00 || parent.node_secret || ser32be(i)`
- `I = HMAC_SHA512(key=parent.chain_code, msg=data)`
- child split as in master node

Implementation functions:

- `pqhd::DeriveChild()`
- `pqhd::DerivePath()`

## 6. Leaf Material and Stream Key

Given leaf `node_secret_leaf` and validated 6-element path:

1. `prk_full = HMAC_SHA512(key="Tidecoin PQHD hkdf v1", msg=node_secret_leaf)`
2. `scheme = path[2] & 0x7fffffff`
3. `info = "Tidecoin PQHD stream key v1" || ser32be(scheme) || ser32be(path[0]) || ... || ser32be(path[5]) || 0x01`
4. `stream_key64 = HMAC_SHA512(key=prk_full, msg=info)`

Output type:

- `LeafMaterialV1 { scheme_id, stream_key64 }`

Implementation functions:

- `pqhd::DeriveLeafMaterialV1()`
- `pqhd::DeriveKeygenStreamKey()`

## 7. Deterministic Key Generation

PQHD deterministic keygen entry points:

- `pq::KeyGenFromSeed()`
- `pq::KeyGenFromSeedBytes()`
- `pq::KeyGenFromLeafMaterial()`

Current supported version:

- `pqhd_version = 1` only

Algorithm (per `KeyGenFromSeed`):

1. Determine per-scheme deterministic seed length:
   - Falcon-512/1024: 48 bytes
   - ML-DSA-44/65/87: 32 bytes
2. For `ctr = 0..1023`:
   - `block64 = HMAC_SHA512(key=stream_key64, msg="Tidecoin PQHD rng v1" || ser32be(ctr))`
   - `seed = block64[0:seed_len]`
   - call scheme-specific deterministic PQClean keypair generator
3. First successful attempt is used.
4. If all attempts fail, keygen fails.

This deterministic retry loop is part of PQHD v1 behavior.

## 8. Descriptor Syntax and Semantics

### 8.1 PQHD key expression

Supported forms:

- fixed leaf:
  - `pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/indexh`
- ranged leaf:
  - `pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/*h`

Parser constraints in `src/script/descriptor.cpp`:

- Seed id must be 32-byte hex.
- Exactly 6 hardened elements in fixed form.
- Wildcard form must have exactly 5 fixed hardened elements before `*h`.
- Multipath (`<...;...>`) is rejected.
- Non-hardened derivation is rejected.
- `purpose` and `coin_type` must match constants.
- `scheme` must be recognized and fit in `uint8`.
- `change` must be 0 or 1.

KDF/derivation constraints in `src/pq/pqhd_kdf.cpp`:

- `DeriveLeafMaterialV1()` requires `ValidateV1LeafPath(path)` to pass.
- Therefore `change` outside `{0,1}` is rejected by derivation as well.

Both `h` and apostrophe input are accepted by parser; canonical descriptor
printing uses `h`.

### 8.2 Expansion behavior

`PQHDPubkeyProvider` derives pubkeys/private keys by:

1. loading wallet-local seed by seed id (`SigningProvider::GetPQHDSeed`)
2. deriving leaf material via PQHD KDF
3. generating deterministic keypair via `KeyGenFromLeafMaterial(..., v1)`
4. serializing pubkey as prefixed TidePubKey bytes (`scheme_prefix || raw_pubkey`)

`pqhd(...)` is wallet-private key source syntax. No seed bytes are embedded in
descriptor strings.

### 8.3 Key origin metadata

Descriptor key-origin bracket metadata (`[fingerprint/path]`) is not supported
for PQHD descriptors in parser (`"Key origin metadata is not supported"`).

## 9. Wallet Storage and State

### 9.1 DB records

Wallet DB record keys (`src/wallet/walletdb.cpp`):

- `pqhdseed`: plaintext PQHD seed record (`PQHDSeed`)
- `cpqhdseed`: encrypted PQHD seed record (`PQHDCryptedSeed`)
- `pqhdpolicy`: policy record (`PQHDPolicy`)

Unlocking an encrypted wallet requires a 32-byte candidate wallet encryption
key. Before accepting it, the wallet decrypts every `cpqhdseed` record and checks
that its plaintext is exactly 32 bytes and hashes to the record's seed ID.
Encrypted individual private keys, when present, are checked as well. The same
validation protects passphrase changes: invalid candidate keys or damaged seed
records must not cause the existing master-key record to be replaced.

A genuinely empty encrypted wallet has no seed or private-key record against
which to verify the candidate. Its existing encryption format is retained, with
the exact master-key length check; seed verification applies once it contains
seeds. This validation does not repair a wallet whose usable master-key record
has already been overwritten; recovery requires an intact backup or separately
preserved seed material and the information needed to restore its history.

Seed, encrypted-seed, and policy records reject unsupported versions before
interpreting their payloads. Version 1 encrypted seeds require exactly 48 bytes
of AES-CBC ciphertext (32 seed bytes plus a full padding block); decryption still
checks the plaintext length and seed identity. Rejected records are not upgraded
or rewritten.

`PQHDPolicy` fields:

- `default_receive_scheme`
- `default_change_scheme`
- `default_seed_id`
- `default_change_seed_id`

### 9.2 Metadata records

`CKeyMetadata` version includes PQHD origin fields:

- `has_pqhd_origin`
- `pqhd_seed_id`
- `pqhd_path`

Current metadata version: `VERSION_WITH_PQHD_ORIGIN = 13`.

### 9.3 Seed lifecycle

Import behavior (`ImportPQHDSeed`):

- descriptor wallet required
- seed length must be 32 bytes
- re-import is idempotent (`inserted=false`)
- encrypted wallets require unlocked state for import
- first imported seed initializes default PQHD policy if missing

Wallets with private keys disabled, including external-signer wallets, reject
local private-seed import, generation, and default-seed/policy changes at the
wallet APIs. Plaintext or encrypted seed records in such a wallet cause loading
to fail without rewriting those records or deleting its encryption keys. This
is an inconsistent wallet requiring deliberate recovery; loading does not
silently convert it into a signing wallet or erase its secrets. Public keys and
scripts supplied by an external signer remain separate from local private seeds.

Removal behavior (`RemovePQHDSeed`):

- descriptor wallet required
- cannot remove non-existent seed
- cannot remove last seed
- cannot remove default receive/change seed
- cannot remove seed referenced by existing descriptors

## 10. Wallet Descriptor Provisioning

For descriptor wallets with local keys (`SetupOwnDescriptorScriptPubKeyMans`):

- wallet creates one random 32-byte PQHD seed
- default scheme is Falcon-512 for receive and change
- default seed ids for receive and change are that seed
- descriptors are generated for output types in `OUTPUT_TYPES`
- `BECH32PQ` descriptors are not created before AuxPoW activation height

Descriptor template from `GeneratePQHDWalletDescriptor`:

`pqhd(SEEDID32)/10007h/6868h/<scheme>h/0h/<change>h/*h`

Address wrappers by output type:

- `LEGACY` -> `pkh(...)`
- `P2SH_SEGWIT` -> `sh(wpkh(...))`
- `BECH32` -> `wpkh(...)`
- `BECH32PQ` -> `wsh512(pk(...))`

When a cached script is observed in an incoming transaction, its consumed index
is persisted before attempting to replenish the cache. A locked wallet can
therefore retain consumption across reload without deriving fresh keys. If the
index write fails, processing reports the error and retains the advanced index
in memory; retrying the observation retries persistence. A failed observation
also disables address issuance and reservation returns for that loaded wallet.
Later blocks, backup, and unload cannot advance its saved scan checkpoint past
the failure. Restore database access and reload the wallet: startup replays from
the previous durable checkpoint before exposing the wallet for use. Retrying
one output alone does not clear this state, because other outputs or transactions
may not have been processed.

Failed or interrupted startup scans cannot save the merely observed chain tip
as completed progress, and release their notification registration on failure.
Explicit historical rescans rewind an existing later checkpoint before observing
transactions; this safety rewind also applies when incremental progress saving
is disabled. Reload honors a stored replay checkpoint without skipping forward
to descriptor birthdays. Old checkpoints can therefore require more history to
be read than the previous birthday-based startup optimization did.
Recovery requires the relevant block history; unavailable/pruned history must
not be reported as a successful restoration. This does not reconstruct indices
lost by older versions, addresses shared but never used on-chain, or a failed
unconfirmed observation whose transaction is no longer available in the mempool
or other recovery material. It also does not repair physical database corruption.

Address allocation returns an address only after its reservation write succeeds.
If returning an unused reservation fails to persist, the address remains
reserved. These checks do not make all cache/top-up writes one atomic operation
by themselves or replace database and storage durability guarantees.

### 10.1 Transaction boundaries

Each descriptor top-up runs in a database transaction. Wallet-wide keypool
refill includes all active descriptor managers in one transaction. Failed derivation, writes,
or commit abort the operation and restore the descriptor, range, cache, script
and public-key maps, and cached signing providers. No partial top-up is reported
as committed. Descriptor import includes private-key records, descriptor/cache
updates, labels, and requested active bindings in one transaction per import
request; separate objects in an `importdescriptors` request array retain separate
success/failure results. Updates discard stale signing-provider entries while
preserving existing public cache data and its validation state.

Wallet notifications and birth-time/active-binding changes are published after
commit. Abandoned transactions run their rollback callbacks when the batch is
destroyed. If rollback repeatedly fails, the process terminates rather than
continuing with unresolved database and memory state. Reopening relies on the
database's transaction recovery; these guarantees do not cover hardware that
loses or falsely acknowledges durable writes.

### 10.2 Index bounds

PQHD child indices are in `[0, 2147483647]`. Descriptor providers reject negative
positions, and `dumpprivkey` validates its wide RPC index before narrowing it.
In particular, `4294967296` cannot alias index zero.

Wallet descriptors retain their existing signed 32-bit on-disk fields. Because
`range_end` is exclusive, their largest managed child index is `2147483646`, with
`2147483647` representing the exhausted endpoint. Import rejects ranges needing
a larger endpoint. Top-up uses wide arithmetic, caps growth at this endpoint,
and issuance fails when exhausted. Generic non-mutating descriptor expansion
still supports child `2147483647`; there is no serialized-field migration.

### 10.3 Cache validation and locked reload

Loading checks descriptor range/next-index invariants and validates every public
cache expression, index, scheme prefix, and required coverage. Cache position is
the actual derivation index, including for ranges starting above zero.

For a wallet with available local seeds, loading also compares each cached key
against its seed/path derivation. Encrypted wallets defer that comparison until
unlock; a mismatch prevents unlock without changing records. Verification reuses
public results for identical leaf paths across wrappers and is retained for the
current in-memory cache.

After an encrypted wallet is reloaded while locked, structurally validated
persisted public cache data is trusted for monitoring, cached address issuance,
public signing-provider lookup, descriptor expansion, and public PSBT metadata.
These operations do not require a verification unlock. Fresh hardened derivation
and private signing still require the corresponding unlocked seed/private key.
Issuing addresses durably advances allocation indices; read-only expansion does
not. Exhausting the cache while locked requires unlocking to replenish it.

Unchecked and known-inconsistent caches are distinct states. If seed comparison
detects a mismatch, further expansion, issuance, top-up and provider lookup from
that manager are rejected for the loaded instance, including after transaction
rollback. No automatic repair or persistent trust marker is written. This policy
accepts that a structurally valid but incorrect persisted cache may supply an
incorrect address or origin before unlock detects the inconsistency. Public use
does not prove that the cached keys belong to the encrypted seed. Reload cannot
preserve knowledge of a mismatch without a new persistent record; recover from
trusted data instead of treating reload as a repair.

Explicit public-key/script descriptors remain the finite watch-only import
format. A seed identifier cannot authenticate a separately supplied PQHD public
cache, and this change introduces no seedless ranged-import protocol. Cache
validation checks consistency with the wallet's seeds, not the authenticity of
an entire wallet file: it cannot authenticate a file whose seeds, descriptors,
and keys have all been replaced consistently. Mismatches are rejected, not
silently repaired or overwritten; preserve the original file and recover using
trusted backups and appropriate history/range information.

## 11. Height-Gated Scheme Policy

Policy function: `pq::IsSchemeAllowedAtHeight(id, params, height)`.

Rules:

- if `height < nAuxpowStartHeight`: only Falcon-512 allowed
- otherwise: all known schemes allowed

Wallet uses target height `tip + 1` for output policy decisions
(`GetTargetHeightForOutputs`). If no chain context is available, target height
falls back to 0.

The target height is initialized from the chain before wallet-load
reconciliation, without advancing the wallet's saved rescan position. Loading
preserves known receive/change scheme preferences even below activation or
after a reorg. Unknown nonzero scheme identifiers are rejected; zero retains
its legacy default interpretation. Existing descriptor bindings matching those
preferences are preserved. Missing descriptors whose scheme or output type is
ineligible are deferred until eligible generation is possible.

Activation eligibility is enforced in:

- `setpqhdpolicy`
- descriptor generation and setup
- address/change issuance, including scheme override validation

Preserving an ineligible preference does not permit issuing addresses using it.
Issuance fails until the chain permits it or the user chooses an eligible scheme.

## 12. RPC Surface

Primary PQHD wallet RPCs:

- `setpqhdpolicy`
- `listpqhdseeds`
- `importpqhdseed`
- `setpqhdseed`
- `removepqhdseed`

Scheme parsing (`ParsePQSchemePrefix`) accepts:

- numeric ids (0-255, recognized only)
- normalized names: `falcon512`, `falcon1024`, `mldsa44`, `mldsa65`, `mldsa87`
  (hyphen/underscore/space-insensitive)

Related options:

- `getaddressinfo(..., {"include_pqhd_origin": bool})`
- `walletprocesspsbt(..., include_pqhd_origins=false)` (default; privacy-preserving)

### 12.1 Descriptor import and capabilities

`importdescriptors` resolves the descriptor's actual seed references against the
selected wallet. Private seed bytes need not (and cannot) be placed in a PQHD
descriptor. Explicit private keys can be supplied in the descriptor or reused
from the wallet. Unrelated keys and seeds do not establish ownership.

These capabilities are separate:

| Capability | Required evidence |
| --- | --- |
| Public script expansion | Explicit public keys, or every required PQHD public key in a structurally validated cache with no detected seed mismatch, or available matching seeds for fresh derivation |
| Private-key ownership (`HavePrivateKeys`) | At least one referenced explicit private key or matching seed, including encrypted material while locked |
| Private derivation / partial signing | The particular private key or matching unlocked seed; missing keys do not prevent producing other available signatures |
| Complete transaction signing | Enough valid signatures and all other script conditions for each actual input; the signing result's `complete` field is authoritative |

For example, one available key may complete a 1-of-2 multisig but only partially
sign a 2-of-2 multisig. The import warning about missing private keys reports key
coverage; it is not a verdict on every possible transaction's satisfiability.
`CanGetAddresses` rejects known cache mismatches and checks either cached range
availability or possession of **all** referenced seeds for potential fresh
derivation (ignoring encryption).
It does not substitute for the actual expansion/issuance checks.

Import validates and populates every index in the requested inclusive range,
without probing index zero or extending that range to meet the keypool target.
Rescan observations, later issuance, and keypool top-ups may extend it normally. Non-ranged imports
populate their one script set. Importing a descriptor registers its scripts for
monitoring; `deriveaddresses` alone still does not.

A locked wallet can update an existing descriptor within its usable cached
range, including immediately after reload. Fresh derivation requires unlocking.
Importing explicit private key bytes, or copying an explicit private key from another
manager, requires unlocking. Requests that cannot expand their entire range fail
atomically, retaining the existing records, bindings, maps, and range positions.
The RPC returns individual results for each request object, including lock-state
failures; a locked call no longer fails the whole array before inspecting it.

Explicit public-only descriptors remain supported in wallets with private keys
disabled. A private-key-enabled wallet still requires at least one referenced
private key or seed, preserving its existing partial-signing wallet policy. A
seed identifier alone cannot provision public keys in another wallet. This RPC
does not introduce a seedless ranged-cache import protocol.

### 12.2 Public resolution in existing RPCs

The same registered-descriptor public resolver is used by `deriveaddresses`,
`scantxoutset`, `scanblocks`, `getdescriptoractivity`, `utxoupdatepsbt`,
`descriptorprocesspsbt`, and fixed-descriptor mining. Node RPCs require explicit
wallet selection (`-rpcwallet` / `/wallet/<name>`) for PQHD references. Merely
knowing a wallet's seed ID does not authorize an arbitrary descriptor/path: the
canonical public descriptor must be registered in that wallet. Self-contained
public/private-key descriptors continue to work independently of wallet selection.

Public resolution uses structurally validated cache entries without known
mismatches while locked and can derive fresh public keys while unlocked. It does not persist new cache entries, extend wallet
monitoring, or allocate/reserve addresses. Cancellation is checked between indices
and before returning the resolved data. Chain changes made by mining and the
ordinary effects of funding remain separate from descriptor resolution.

`utxoupdatepsbt` never signs with wallet keys. `descriptorprocesspsbt` may sign
with private keys explicitly supplied in its descriptor arguments; selecting a
wallet supplies only public expansion data and does not authorize wallet signing.
Use `walletprocesspsbt` for that operation. These calls retain their existing
finalization/signature-completeness behavior; public resolution does not add an
external-signer trust model.

Funding RPCs resolve `solving_data.descriptors` against the wallet already
selected for funding. Existing checksummed string arguments still expand index
zero. A checksummed `{"desc": "...", "range": [begin, end]}` object can select a
bounded inclusive range; the default is index zero. All requested expansions must
succeed before funding can reserve change or lock coins. Only public solving data
is retained in coin control. Successful funding can still allocate change and
lock inputs according to its ordinary options.

`generatetodescriptor` and `generateblock` accept fixed registered PQHD
descriptors through an explicitly selected wallet. Ranged and multipath mining
descriptors remain rejected. A fixed descriptor must itself be registered; to
mine to a child of a registered ranged descriptor without importing another
descriptor, obtain its address with `deriveaddresses` and use the existing
address-based mining interface.

`gethdkeys` and `createwalletdescriptor` retain their unsupported BIP32/xpub
compatibility errors. Their help now describes that boundary instead of promising
extended-key export/creation. Use `listpqhdseeds`, `listdescriptors`,
`setpqhdpolicy`, `setpqhdseed`, and `importdescriptors` for the supported PQHD
operations. A seed identifier is not an extended public key or a seed backup.

### 12.3 Active imports and policy defaults

An `active` import selects the descriptor used for ordinary address issuance for
that output type and receive/change branch. Valid stored bindings survive reload
and restart. Loading fills missing bindings from PQHD policy instead of replacing
existing custom bindings. A stored binding with an incompatible descriptor output
type fails loading without being rewritten. Every referenced key scheme must be
eligible at the current height, including mixed-scheme descriptors.

Explicit `setpqhdpolicy` / `setpqhdseed` operations select policy defaults again;
failed policy updates restore the previous custom binding. An explicit address
scheme override continues to select the policy seed's descriptor for that scheme.
If an output type has no active binding, the policy descriptor can still be found
or created on demand when eligible. Absence of an active binding is therefore not
a persistent instruction to disable that policy output type.

First encryption retains its existing security behavior: it generates a new
policy seed and selects its default descriptors. It can consequently replace
custom active bindings. Install/reactivate custom descriptors after encryption
if they are to remain the issuance choice. Historical descriptors remain in the
wallet; importing an older seed/path deliberately reuses that older key material.

### 12.4 Seed and descriptor recovery

`importpqhdseed` stores secret material and returns its identifier. It does not
register the seed's historical scripts or scan the blockchain. Its `inserted`
result is not a restoration-completeness result. Importing a seed records the
current import time; historical scan times belong to the descriptors supplied
for recovery. Selecting a current seed or scheme policy does not reconstruct all
previous policies, accounts or scripts.

A bounded restoration uses existing interfaces:

1. Create a fresh descriptor wallet with private keys enabled and `blank=true`.
   Import **all** required seeds with `importpqhdseed`. Separately imported
   private keys must also be supplied where the original scripts require them.
2. Import the historical descriptors using `importdescriptors`. Restore their
   original `desc`, inclusive `range`, `timestamp`, `next_index`, and applicable
   `active`/`internal` settings. `listdescriptors` supplies these fields for
   existing wallet descriptors; the legacy `next` field is redundant. Keep any
   additional branch/classification metadata needed for inactive custom scripts:
   `internal` is only exported for active managers. Do not activate every
   historical descriptor: each output type has one active receive and one active
   change binding.
3. Include each historical scheme, account, receive/change branch and script
   construction. The standard path is
   `10007h/6868h/<scheme>h/0h/<branch>h/*h`; custom accounts and multikey scripts
   require their exact descriptors. Schemes 7, 8, 9, 10 and 11 are Falcon-512,
   Falcon-1024, ML-DSA-44, ML-DSA-65 and ML-DSA-87 respectively. Consensus
   activation restrictions still apply to spending and new address issuance.
4. Choose a timestamp at or before the earliest possible payment. Use `0` when
   history is unknown; use `"now"` only when no historical search is needed.
   `rescanblockchain` can repeat a scan using explicit block heights after the
   required scripts have been registered.
5. Check every import result. A successful scan covers the supplied scripts,
   ranges and historical interval. It does not prove that an omitted account,
   script or child range was unused. Confirm recovered transactions/balances
   before treating restoration as complete.

Ranges are explicit discovery bounds. An address beyond the bound or beyond a
large unused gap is not guaranteed to be found by automatic keypool top-up.
Increase the imported range and repeat the historical scan when expanding the
search. Do not shrink a range already registered in the wallet. The managed
maximum remains child `2147483646` with exclusive endpoint `2147483647`; an
exhausted exported range may have `next_index` equal to that exclusive endpoint.
Reimport preserves the greater existing `next_index` and the earlier existing
descriptor timestamp. This avoids address reuse or loss of scan history when
applying stale metadata. A seed and chain scan cannot reveal previously issued
but unpaid addresses; preserve allocation metadata to avoid reissuing those.

A cancelled scan or missing/pruned block data is incomplete recovery.
Successfully registered descriptors and transactions already discovered remain
in the wallet; scanning failure does not roll back successful registrations.
Retry `importdescriptors` with the original historical timestamps, or use
`rescanblockchain` over the required history. Shutdown interruption is also
reported as incomplete. Required historical blocks must be available to finish
recovery; seed import cannot replace missing blockchain data.

`listdescriptors(true)` does not embed PQHD seed bytes. Preserve the actual seed
material separately, or use a complete wallet backup. The descriptor set and
one seed are insufficient if scripts refer to other seeds or independently
imported keys. Multisignature recovery also needs the complete public script and
enough signing keys to meet its threshold. Labels and other transaction metadata
are not reconstructed by seed/descriptor recovery.

### 12.5 Finite public watch-only provisioning

No seedless wallet can freshly derive hardened PQHD children from a seed ID.
Finite watch-only transfer uses fixed public descriptors through existing RPCs:

1. On the seed-holding wallet, register the intended bounded range with
   `importdescriptors` if it is not already monitored. `deriveaddresses` alone
   does not register scripts, consume indices, or reserve addresses.
2. For each address in the range, obtain `getaddressinfo(address).desc`. For a
   solvable monitored script this is a fixed descriptor containing its public
   keys and script structure, with no seed reference or private key. Transfer
   `desc`, not `parent_desc` (which can retain the PQHD seed reference).
3. Create the watching wallet with `disable_private_keys=true` and import those
   fixed descriptors with suitable historical timestamps. Omit `range`,
   `next_index` and `active`: these are fixed scripts, not an active ranged
   address generator. Specify `internal` where desired for change scripts.
4. Replenish by transferring further fixed descriptors from the seed holder and
   rescanning far enough back to include any earlier payments to them. The
   watching wallet can recognize and supply solving data for provisioned scripts
   but cannot sign or derive the next PQHD child.

For address-only monitoring, `addr(address)` descriptors are also possible, but
these do not supply the complete public script needed for general solving or
PSBT construction. Public provisioning is trusted input: a descriptor checksum
checks transcription, not ownership by a particular seed or signer. Preserve
that source/identity relationship outside the seedless wallet; no imported
public cache is asserted to be authenticated by a seed identifier.

## 13. PSBT Proprietary PQHD Origin

Namespace (`src/psbt.h`):

- identifier: `"tidecoin"`
- subtype: `0x01` (`SUBTYPE_PQHD_ORIGIN`)

Data model (`psbt::tidecoin::PQHDOrigin`):

- `pubkey`: prefixed TidePubKey (`CPubKey`)
- `seed_id`: `uint256` carrying canonical `SeedID32` value
- `path_hardened`: vector of hardened `uint32`

Value encoding (`MakePQHDOriginValue`):

- `seed_id`
- compactsize `path_len`
- `path_len` serialized `uint32` elements

`seed_id` textual rendering (RPC/decode output) uses `uint256::ToString()` and is
the same canonical `SeedID32` hex defined in section 5.2.1.

Decode checks (`DecodePQHDOrigin`):

- identifier and subtype must match
- pubkey must be valid non-hybrid CPubKey
- path length must be exactly `6` (PQHD v1 leaf path shape)
- every path element must be hardened
- path[0] must be `10007h` (`PURPOSE`)
- path[1] must be `6868h` (`COIN_TYPE`)
- path[4] (`change`) must be `0h` or `1h`
- scheme from `path[2]` must be recognized
- pubkey prefix must equal scheme in `path[2]`
- trailing bytes are rejected

Emission (`DescriptorScriptPubKeyMan::FillPSBT`):

- controlled by `include_pqhd_origins`
- records can be emitted on input and output proprietary maps
- records are per key, including multikey scripts
- metadata comes from descriptor paths matched to each public key in the
  local PQHD cache and descriptor paths (which are not seed-authenticated before
  unlock after an encrypted reload); supplied PSBT origins never select
  derivation paths
- existing origins for locally resolved keys must agree with those paths,
  including when new origin emission is disabled

Origin emission is opt-in. Disabling it preserves existing records rather than
stripping metadata provided by other participants. Unknown origins remain
untrusted: shape validation and a seed identifier do not prove ownership, and a
seedless wallet holding fixed public descriptors cannot authenticate a claimed
PQHD path to its seed. Inputs without usable UTXO/script information may not be
resolvable locally and therefore may not receive a local-origin check.

`combinepsbt` rejects malformed PQHD origins and different values for the same
origin key before publishing the combined result. Identical records are
idempotent. This does not establish the authenticity of an otherwise consistent
third-party origin or change the merge rules for other proprietary namespaces.
Wallet PSBT filling stages changes and preserves the caller's PSBT on error.

With `sign=false`, cached public provider lookups, including public-key fallback
for unregistered scripts, do not fetch private keys or generate deterministic
keypairs. Verified cached operations remain available while locked. This is
separate from fresh hardened derivation, which still requires the seed, and
from finalizing signatures already present when finalization is requested.

## 14. Address Metadata Exposure

`getaddressinfo` may include:

- `pqhd_seedid`
- `pqhd_path` (string form `m/...h/...`)

This is controlled by `include_pqhd_origin` (default `true`).

## 15. Compatibility and Invariants

The following are protocol-level wallet invariants and MUST be treated as
stable for PQHD v1:

- `PURPOSE = 10007`, `COIN_TYPE = 6868`
- hardened-only derivation model
- SeedID32 tag and KDF domain-separation strings
- path element layout and scheme-in-path semantics
- deterministic keygen retry model (up to 1024 counters)
- scheme activation gating semantics relative to `nAuxpowStartHeight`
- descriptor grammar for `pqhd(...)`
- PSBT proprietary identifier/subtype and validation rules

Any incompatible change requires an explicit new PQHD version and coordinated
migration logic.

## 16. Test Coverage Anchors

Current test files covering PQHD behavior include:

- `src/test/pqhd_kdf_tests.cpp`
- `src/test/pqhd_keygen_tests.cpp`
- `src/test/descriptor_tests.cpp`
- `src/test/psbt_pqhd_origin_tests.cpp`
- `src/wallet/test/psbt_wallet_tests.cpp`
- `src/wallet/test/scriptpubkeyman_tests.cpp`
- `src/wallet/test/wallet_tests.cpp`
- `test/functional/wallet_pqhd_seed_lifecycle.py`
- `test/functional/wallet_pqhd_lock_semantics.py`
- `test/functional/wallet_pqhd_encryption.py`
- `test/functional/wallet_pqhd_seed_restrictions.py`
- `test/functional/wallet_pqhd_consumption.py`
- `test/functional/wallet_pqhd_activation.py`
- `test/functional/wallet_pqhd_integrity.py`
- `test/functional/wallet_pqhd_psbt.py`
- `src/wallet/test/wallet_persistence_tests.cpp`

## 17. Secret Lifetime Boundaries

PQHD KDF nodes clean their owned secret and chain-code buffers on destruction
and clear moved-from objects. Stream keys and stream blocks are move-only
cleansing objects. Scoped guards cover seed-import buffers, KDF concatenation
buffers, deterministic keygen seeds, and named seed-ID hash state. HMAC-SHA512
cleans its keyed states on destruction and its key and intermediate buffers on
scope exit.

The deterministic Falcon and ML-DSA entry-point workspaces are overwritten
before return. Falcon encoding failures also clear partial key outputs.
Allocated SHAKE/SHA3 contexts are overwritten before release, and one-shot
SHAKE tail buffers are cleared. These changes preserve derivation bytes,
key-generation retry ordering, and signature algorithms.

These are bounded lifetime improvements, not a proof that every copy of a
secret disappears. Lower-level arithmetic helpers, compiler registers or stack
spills, JSON/RPC input strings, crash dumps, and operating-system copies are
outside this guarantee. Fatal process exits need not run C++ destructors.
Fresh PQHD public derivation still generates a keypair; it cannot be replaced
with public-only derivation in this hardened-only design. Cleanup does not
establish a new constant-time guarantee for the full key-generation process.
