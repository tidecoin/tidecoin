Tidecoin v1.0.0rc2 Release Notes
===============================

Downloads:

  <https://github.com/tidecoin/tidecoin/releases>

This release updates Tidecoin's node, wallet and mining infrastructure, including
PQHD wallets, encrypted peer connections, merged mining support, and additional
signature schemes and script extensions activated with AuxPoW. Falcon-512 remains
the mainnet signature scheme.

**Mainnet AuxPoW remains disabled.** Testnet activation remains at height 1,000.
This release does not change either activation setting.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/tidecoin/tidecoin/issues>

How to Upgrade
==============

Back up your wallets and shut down the old node completely before replacing the
executables. See [wallet backup and migration](managing-wallets.md) for legacy
wallet migration instructions.

This release records an overall database storage-format version. Existing
databases without that version, including those created by earlier development
builds, require a one-time full rebuild of the block index, chainstate and undo
records. An unpruned node performs this rebuild automatically from its local
block files. This can take time, but does not require downloading those blocks
again if all required files are present. A node that has pruned blocks must
restart with `-reindex` and download any missing blocks. `-reindex-chainstate`
alone is insufficient for this migration.

Offline transaction utility
---------------------------

Offline transaction signing and script verification with `tidecoin-tx` now
require an explicit `-rules=pre-auxpow` or `-rules=post-auxpow` option. Update
existing commands and scripts to select the rules for the intended spend.
There is no default, and network selection does not select the rule era.
For example:

```sh
tidecoin-tx -rules=pre-auxpow -verify "$TX_HEX" load=prevtxs:prevtxs.json
tidecoin-tx -rules=post-auxpow "$TX_HEX" load=prevtxs:prevtxs.json load=privatekeys:keys.json sign=ALL
```

Creating or editing a transaction without signing or verification does not
require this option. The utility supports native witness-v1
signing with `witnessScript`; P2SH-wrapped v0 remains supported. A witness script
may be up to the 65536-byte script size, as consensus allows, so large PQ
multisig scripts can be signed; a P2SH redeem script remains limited to one
8192-byte stack element. `-verify` checks
input scripts against the supplied previous outputs and selected rules; it
does not establish that the outputs exist or are unspent, or that the whole
transaction is eligible for mining. Without `-verify`, signing may still return
a partially signed transaction. These utility changes require no reindex or
chain restart.

Regtest activation setting
--------------------------

Regtest development option: `-auxpowactivationheight=<height|never>` can move or
disable the shared AuxPoW/PoW/PQ activation boundary. The default remains 0;
mainnet and testnet do not accept this override. See [regtest activation testing](regtest-auxpow.md).

Compatibility
==============

Build instructions and dependencies are documented for [Linux and Unix](build-unix.md),
[macOS](build-osx.md), and [Windows](build-windows.md).

Post-Quantum Cryptography
=========================

Multi-scheme signature support
------------------------------

Tidecoin supports five post-quantum signature schemes. Before AuxPoW activation,
only Falcon-512 can authorize transaction signatures. Falcon-1024 and the three
ML-DSA schemes become eligible at the configured AuxPoW activation height, when
strict Falcon verification also starts. AuxPoW remains disabled on mainnet.

| Scheme | Prefix | Standard | Signature size |
|--------|--------|----------|----------------|
| Falcon-512 | 0x07 | NIST Draft FIPS 206 (FN-DSA) | 666 bytes |
| Falcon-1024 | 0x08 | NIST Draft FIPS 206 (FN-DSA) | 1,280 bytes |
| ML-DSA-44 | 0x09 | NIST FIPS 204 | 2,420 bytes |
| ML-DSA-65 | 0x0A | NIST FIPS 204 | 3,309 bytes |
| ML-DSA-87 | 0x0B | NIST FIPS 204 | 4,627 bytes |

Falcon-512 has been the default scheme since genesis (December 27, 2020). Wallet
address generation follows scheme activation. This release corrects early
acceptance of additional schemes in transaction and block validation; current
public-key prefix and length parsing is unchanged.

Legacy and strict Falcon verification
--------------------------------------

Falcon-512 signatures operate in two modes:

- **Legacy mode** (pre-AuxPoW): Relaxed norm bound verification with header
  byte 0x39. All existing mainnet signatures use this mode.
- **Strict mode** (post-AuxPoW): PQClean verification with exact compressed
  encoding, activated by the `SCRIPT_VERIFY_PQ_STRICT` consensus flag.

Keys are identical in both modes. Only signature creation and verification
bounds differ.

Strict Falcon-512 and Falcon-1024 verification rejects extra trailing bytes,
including zero padding to 666 or 1280 bytes. The decoder must consume the
entire compressed signature, as legacy Falcon-512 verification already
requires. This consensus rule prevents changing a transaction's txid (for
scriptSig signatures) or wtxid (for witness signatures) by adding or removing
Falcon padding. It applies to all strict Falcon transaction signatures, not
only witness v1. Signing continues to produce variable-length, unpadded
signatures; this change does not impose the wallet's size estimates as new
consensus length limits.

Local Falcon signing retries compressed signatures longer than 666 bytes for
Falcon-512 or 1280 bytes for Falcon-1024, so the wallet's smaller signature
size estimates are now upper bounds. This applies to both 32-byte and 64-byte
messages, including legacy Falcon-512 signing. Signatures remain unpadded;
the transaction sighash byte is accounted for separately. Signing returns a
failure if the retry limit is exhausted. External-signing estimates retain
the larger PQClean bounds, and verification still accepts valid compressed
signatures above the local signing bounds.

PQHD Wallet
============

A new Post-Quantum Hierarchical Deterministic (PQHD) wallet system replaces
the BIP-32 HD wallet for post-quantum key derivation:

- **Hash-based KDF** using SHA-512 for deterministic key generation
- **Hardened-only derivation** — deriving child keys requires the seed
- **Multi-seed support** with independent seeds and per-seed scheme policies
- **Configurable default schemes** for receive and change addresses
- **Encrypted seed storage** when wallet encryption is enabled
- **Separate keys per address type** — each script family has its own path
  purpose (`pkh` 10044, `sh(wpkh)` 10049, `wpkh` 10084, `wsh512` 10087;
  10007 for custom and multisig descriptors), so addresses
  of different types are not linkable through a shared key
- **Separate test-network keys** — testnet and regtest use coin type 1; mainnet
  uses 6868

Default descriptor paths changed after 1.0.0rc2, which derived every address
type from `10007h/6868h`. Wallets created by rc1 or rc2 keep their existing
descriptors; their seeds' older keys are recovered only by importing those
descriptors. Move funds received by an rc wallet to a wallet created by this
release.

Native witness v1 descriptors (`wsh512`) are not usable before
AuxPoW activation: their outputs can be spent without a signature until the
witness v1 rules take effect. Before activation the wallet does not issue their
addresses, select their coins, or send to witness v1 addresses it recognizes.
`importdescriptors` still accepts them and returns a warning. A witness v1 coin
the wallet receives before activation, for example when someone pays an address
of an imported descriptor, is counted by `getbalances` but cannot be spent until
the activation height.

A wallet created before activation gains its `bech32pq` (`wsh512`) descriptors
after activation, when such an address is first requested or when the wallet is
next loaded; an encrypted wallet must be unlocked for this. Witness v1 is
native only: `sh(wsh512(...))` descriptors are rejected, including when loading
wallet records, and have no signing or PSBT support. `decodescript` no longer
suggests P2SH wrappers for native v1. Known wrapped-v1 recipients and change
addresses are refused at every height. See [descriptors](descriptors.md).

Native witness v1 addresses are 112 or 113 characters long. At that length the
Bech32m checksum guarantees detecting changes of up to three characters, not
four as for addresses of at most 90 characters, so two valid v1 addresses can
differ in only four characters. Copy or scan these addresses rather than
retyping them.

The PQHD system is documented in detail in the [whitepaper](whitepaper.md).

ML-KEM-512 Encrypted P2P Transport
====================================

Tidecoin's V2 transport protocol uses ML-KEM-512 (NIST FIPS 203) for
post-quantum key encapsulation during the peer-to-peer handshake:

- **Enabled by default** (`-v2transport=1`)
- Post-quantum key encapsulation replaces the X25519 key exchange
- 800-byte public keys, 768-byte ciphertexts, 32-byte shared secrets

Script Extensions (Post-AuxPoW)
================================

The following script extensions are implemented but gated behind AuxPoW
activation:

OP_SHA512
---------

- New opcode at position 0xb3
- Takes the top stack item and replaces it with its 64-byte SHA-512 hash
- Controlled by `SCRIPT_VERIFY_SHA512` consensus flag

Witness v1 with 512-bit script hashing
---------------------------------------

- Native 64-byte witness v1 script hash validation via `SCRIPT_VERIFY_WITNESS_V1_512`
- Extended `PrecomputedTransactionData` with SHA-512 variants:
  `hashPrevouts_512`, `hashSequence_512`, `hashOutputs_512`
- Native payments supported by signing RPCs and `tidecoin-tx`

Activation only gives new spending rules to native 64-byte v1 programs.
A 64-byte v1 program inside P2SH remains an ordinary script at every height:
an empty-witness spend with a truthy redeem program is consensus-valid, while
nonempty witness data is rejected. Existing `CLEANSTACK` relay policy still
refuses the ordinary spend. P2SH hides the redeem script when the output is
created, so its funding cannot be excluded by that relay check.

Short v1 programs (2–40 bytes), native or inside P2SH, remain unknown witness
versions after activation. They are not frozen by activation and acquire no
signature requirements. Existing relay restrictions remain in place. These
unsupported forms must not be used to receive payments.

Mining
======

YespowerTIDE
------------

Before AuxPoW activation, Tidecoin uses YespowerTIDE for proof-of-work.
After activation, ordinary blocks use scrypt and merged-mined blocks use
scrypt parent work.

- YespowerTIDE parameters: N=2048, r=8

Subsidy schedule
----------------

- Initial block reward: 40 TDC
- Halving interval: 262,800 blocks (~6 months at 60-second blocks)
- Quartering with doubling intervals (not standard halving)
- Maximum supply: ~21,000,000 TDC

AuxPoW merged mining infrastructure
------------------------------------

Infrastructure for scrypt-based merged mining with Litecoin is implemented
and available for activation:

- AuxPoW chain ID: 8
- `createauxblock` and `submitauxblock` RPC commands
- Currently disabled on mainnet (`nAuxpowStartHeight = AUXPOW_DISABLED`)
- Active at block 1000 on testnet for testing

Mining and IPC reliability
--------------------------

- Mining IPC requests wait for startup to connect the chain tip. Shutdown or
  failed initialization releases clients waiting for the mining interface.
- `BlockTemplate.interruptWait()` cancels a pending `waitNext()` call. A queued
  interruption is consumed by the next wait; repeated interruptions coalesce.
  Clients must serialize waits on each template. Cancellation is cooperative
  and does not stop a block assembly operation already in progress.
- `waitNext()` with a zero fee threshold can return an empty template when the
  mempool is empty.
- Explicit IPC reserved-weight values take precedence over `-blockreservedweight`.
  RPC mining continues to use the startup setting. IPC clients must supply a
  valid reserved weight; zero is rejected. Invalid runtime weight and sigops
  settings now raise errors instead of being silently clamped. Startup rejects
  `-blockmaxweight` below `-blockreservedweight`.
- Invalid JSON received over IPC is rejected. Failed JSON parsing clears the
  destination value instead of leaving partially parsed data.
- The bundled Cap'n Proto dependency handles aborted macOS socket accepts without
  stopping the IPC listener. Builds using a system Cap'n Proto need the equivalent
  dependency correction.

Block validation and synchronization
====================================

- Ordinary headers are checked with the work algorithm required at their height,
  including during both passes of initial header synchronization. Full-block
  validation also checks the height-specific rules.
- Header checks run in parallel before headers enter the synchronization buffer.
  Buffered headers no longer retain AuxPoW proofs, reducing memory use during
  synchronization. Proofs received with full blocks are checked independently.
- Reindexing and block connection avoid repeating an ordinary work check within
  the same validation operation. Block retrieval, serving, wallet rescans and
  standalone disk checks retain their existing work checks.
- An invalid or oversized AuxPoW proof no longer permanently rejects another
  valid proof for the same block header. Parent-coinbase witness size accounting
  is unchanged.
- Preactivation header checks preserve the historical minimum version rule and
  allow ordinary headers with nonzero chain-identifier bits. The corresponding
  postactivation restrictions remain in place.

Activation and pending transactions
==================================

Additional signature schemes, strict Falcon verification, `OP_SHA512` and the
native 64-byte witness-v1 script rules take effect at the configured AuxPoW
height. Witness-v1 interpretation and signature-operation counting now
consistently follow that boundary.

Mempool admission uses the rules for the next block, allowing newly enabled
transactions to be included in the first activation block. When the next block
changes rule era, including after a rollback, pending transactions are checked
again. Transactions that no longer satisfy the rules, and their dependent
transactions, are removed from the mempool. This includes transactions that
create witness v1 outputs when a rollback moves the next block below
activation, because those outputs would not be enforced there. A block built
outside the mempool can still contain such outputs, as pre-activation consensus
rules allow.

Before activation, transactions creating witness v1 outputs are not accepted to
the mempool (`witness-v1-pre-auxpow`), and `generatetoaddress`,
`generatetodescriptor` and `generateblock` refuse a witness v1 coinbase output.
The mining RPCs check the height of each generated block, so a rollback during a
call is also covered.

After activation, a transaction spending a native 64-byte v1 output that is
received without its witness is treated as witness-stripped, as for witness v0:
it is not cached as rejected, so the transaction can still be accepted when
received with its witness.

Network Parameters
==================

| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| Default port | 8755 | 18755 |
| Bech32 HRP | tbc | ttbc |
| Bech32 PQ HRP | q | tq |
| Block time target | 60 seconds | 60 seconds |
| Difficulty adjustment | 17-block window | 17-block window |
| AuxPoW | Disabled | Block 1000 |

Genesis block
-------------

- Timestamp: December 27, 2020 (1609074580)
- Message: "spectrum.ieee.org 09/Dec/2020 Photonic Quantum Computer Displays
  'Supremacy' Over Supercomputers."
- Hash: `480ecc7602d8989f32483377ed66381c391dda6215aeef9e80486a7fd3018075`

Networking and transaction relay
================================

- Improved relay of one-parent, one-child transaction packages.
- Limits on stored transactions with missing parents, based on their weight
  and the number retained per peer.
- NAT-PMP/PCP enabled by default for automatic port mapping.
- Extended `-proxy` syntax for per-network proxy configuration.

RPC, REST and command-line tools
===============================

The new REST endpoint `/rest/spenttxouts/BLOCKHASH` provides spent output queries.

New `tidecoin` command
----------------------

A new `tidecoin` command line tool has been added:

- `tidecoin node` is a synonym for `tidecoind`
- `tidecoin gui` is a synonym for `tidecoin-qt`
- `tidecoin rpc` is a synonym for `tidecoin-cli -named`
- `tidecoin test` runs the test suite

Wallet and node changes
=======================

Wallet and GUI
--------------

- The GUI moves from Qt 5 to Qt 6, with Windows dark mode support and the macOS
  Metal backend.
- Legacy BDB wallets require migration to descriptor wallets using `migratewallet`.
  See [wallet migration instructions](managing-wallets.md).
- The wallet supports TRUC transactions.
- `bumpfee` and `psbtbumpfee` estimate signatures on inputs from outside the
  wallet at the maximum size for their signature scheme. They previously assumed
  72-byte ECDSA signatures, so a replacement spending such inputs could pay
  less than the requested fee rate.

Logging
-------

Unconditional logging is limited to 1 MiB per hour per source location.

Legacy wallet migration recovery
--------------------------------

Legacy wallets recovered without a saved block locator can now migrate and
rescan their history. Malformed locator records and database read errors still
fail migration. Required historical blocks must be available for the rescan.
Failed migration preserves existing wallet startup settings; newly created
auxiliary wallets are registered only after all migrated wallets load. The
`migratewallet` result reports warnings if their startup settings cannot be saved.

Block invalidation and reconsideration
--------------------------------------

Invalid blocks and all descendants now use one in-memory failure state. This
prevents a branch-specific `reconsiderblock` sequence from violating block-index
invariants and terminating the node when consistency checking is enabled. On
startup, the node converts the legacy descendant-failure flag in existing
block-index records to the unified state.

Chainstate database maintenance
------------------------------

Read-triggered LevelDB compaction is disabled to reduce unnecessary database
rewrites. Size-triggered compaction remains enabled. After initial synchronization,
each completed full chainstate flush has a 1-in-320 chance to start background
full compaction. An unfinished job is reused instead of starting another one.
Cache resizing and shutdown wait as needed for compaction to finish using the
database handle. Resizing reopens the existing database without deleting its
records. Maintenance introduces no database-format change or reindex requirement.

Cluster mempool policy
----------------------

The mempool now uses connected transaction clusters for dependency accounting, replacement, block
assembly and eviction. Defaults are 64 entries and 242,000 virtual-byte-equivalent adjusted weight
per cluster (968,000 weight units). Ordinary transaction limits remain 800,000 weight units and
package submission remains 25 entries / 808,000 weight units. TRUC, PQ signatures and activation
rules are unchanged.

`-limitclustercount` accepts 1–64 and `-limitclustersize` accepts 1–242 decimal kilobytes. The old
ancestor/descendant size options are ignored with a warning; count options remain wallet selection
preferences. The blocks-only default mempool budget is now 10 MB; a nonzero budget must be at least
40 times the configured cluster size. `-maxmempool=0` is supported explicitly.

Single and package replacements must improve the complete affected fee diagram, in addition to
paying the required fees. Tidecoin retains a 100-unique-removed-transaction guard alongside the
100-conflicting-cluster limit. CPFP/RBF ancestry carveouts are replaced by final staged cluster
checks. Local fee-priority RPC behavior and base-fee relay ordering are preserved. Existing
`getmempoolentry` and `getmempoolinfo` responses include chunk and cluster-limit metadata; no new
RPC is required.

Some previously accepted connected groups exceeding the new cluster limits will be rejected,
including when reloading unconfirmed transactions. Conversely, small chains longer than 25 entries
can fit the new policy. Older peers may not relay them. These changes do not alter block consensus
or transaction/wallet formats and require no reindex.

Mempool default on 32-bit builds
--------------------------------

The default mempool budget is now 500 MB on 32-bit builds, matching their existing
maximum. The 64-bit default remains 1,024 MB, and the blocks-only default remains
10 MB. The 32-bit cap also applies to inherited budgets when `-maxmempool` is
omitted. These are local memory settings; consensus and cluster limits are unchanged.

Witness-v1 signature verification cache
---------------------------------------

PQ witness-v1 signatures now use the existing bounded individual-signature cache,
avoiding repeated verification of the same valid signature. Cache entries use the
full 512-bit signature hash and a separate domain from 256-bit signature checks.
Strict verification, consensus rules, transaction formats and cache-size settings
are unchanged.

Historical UTXO snapshot export
-------------------------------

`dumptxoutset` historical exports now copy the UTXO database and undo blocks in
that temporary copy. They no longer invalidate the active chain or disconnect
peers, and they work when a competing stale branch exists. Existing RPC arguments
and snapshot formats are preserved. No reindex or consensus change is required.

The temporary database requires additional disk space alongside the output file.
Required block and undo data are protected from pruning during export; data that
was already pruned remains unavailable. Only one export can run at a time.
Cancellation is cooperative, and an abrupt shutdown can leave temporary files
requiring manual cleanup. See [snapshot export documentation](assumeutxo.md).

Credits
========

Tidecoin is derived from Bitcoin Core and maintained independently. We thank
the Bitcoin Core developers for their foundational work.

The post-quantum cryptographic integration, PQHD wallet, ML-KEM transport,
YespowerTIDE mining, AuxPoW infrastructure, and script extensions were
developed by the Tidecoin contributors.

### PSBT signing and witness-v1 hash types

Compared with rc1, witness-v1 signatures without ANYONECANPAY now commit to all
spent amounts and locking scripts, in input order. External v1 signers must use
the updated message format; signatures made with the rc1 format for these inputs
must be regenerated. ANYONECANPAY signatures do not gain these aggregate fields.
Witness-v1 SINGLE without a corresponding output is now rejected, including with
ANYONECANPAY. These are consensus changes for active witness v1.

External signing now requires the full previous transaction before requesting a
new legacy signature, including legacy P2SH inputs. Requests missing that data
are refused before contacting the signing device, with an explicit request to
supply `non_witness_utxo`. GUI per-input errors show mode details only for
signing-mode refusals. Native witness inputs and P2SH-wrapped v0
inputs retain their existing data requirements, and unchanged verified finals
remain usable. Newly returned legacy partial signatures and finals enforce the
same previous-transaction requirement. This does not independently authenticate
every other input amount used in a displayed fee.

PSBT analysis retains missing public-key and script details alongside signing-mode
issues, while continuing to omit requests for signatures until the issue is fixed.

New signatures refuse SINGLE when the input has no corresponding output.
PSBT inspection uses per-input declarations, while signing requires explicit
matching consent for nondefault modes on signing targets. Public wallet updates
can deliberately declare modes, including ALL; combining preserves declarations.
This also applies when the signer's own partial signature is already in the
PSBT: reusing one made in another mode is refused with a sighash mismatch, as
creating a new one would be. Partial signatures that cannot verify are ignored
when signing, so they no longer block it; the signer replaces its own, and other
keys' entries are left in the PSBT.
Raw signing tracks missing amounts separately and preserves known node amounts.
Qt displays missing/zero fees and excessive totals correctly.

Active witness-v1 nonempty signature arguments are restricted to hash-type
bytes 01, 02, 03, 81, 82 and 83. Other bytes
cause SIG_HASHTYPE, including unused arguments of an executed multisig opcode.
Empty signatures, legacy and witness-v0 verification remain unchanged. Activation
heights are unchanged. Include the v1 message and hash-type changes in the planned
testnet relaunch; deploying after that relaunch requires a further
coordinated restart. Existing testnet history is not a supported migration path.

Mempool admission and relay also require the six defined hash-type bytes for
nonempty legacy and witness-v0 signature arguments. This policy does not change
block validity, existing-final verification, or raw signing, and requires no
activation or chain restart. Transactions from other software using undefined
bytes will no longer relay through upgraded nodes, but may still appear in valid
blocks. Empty signatures retain their existing behavior.
