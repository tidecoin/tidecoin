Tidecoin v1.0.0rc3 Release Notes
===============================

This is the third release candidate for Tidecoin 1.0.0; version 1.0.0 final has
not been released.

Published builds:

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

Testnet restart
---------------

This candidate is intended for the coordinated testnet restart. Existing
testnet history is not a supported upgrade path. Stop the old testnet node,
retain its wallet backups and data separately, and start the candidate with a
fresh data directory and new test wallets. Connect initially only to the peers
agreed by the testnet operators. Do not copy old testnet blocks, chainstate,
indexes or peer records into the new directory.

The candidate keeps testnet's existing genesis block, message-start bytes and
ports; upgrading the executable alone does not distinguish the restarted chain
from the old one. Operators must coordinate the software, peer set and restart.
AuxPoW and the associated script rules activate at block 1,000 on the restarted
chain. Mainnet data and activation settings are unchanged.

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

Transaction-processing rule selection
-------------------------------------

`walletprocesspsbt`, `descriptorprocesspsbt`, `finalizepsbt`, `analyzepsbt`,
`signrawtransactionwithkey`, `signrawtransactionwithwallet`, `utxoupdatepsbt` and
`combinerawtransaction` accept an optional final `rules` argument: `pre-auxpow` or
`post-auxpow`. Existing calls and JSON `null` use the local next-block rules. An
explicit choice supports offline processing for the destination era and applies
to cached signatures, new signing, verification and extraction throughout the
request. The six object results include `rules` and, for explicit local-era
mismatches, `warnings`. The two string results retain their format.

Local pre-AuxPoW signing creates only Falcon-512 signatures for supported
legacy/v0 inputs. Newer schemes and native-v1 inputs require post-AuxPoW rules,
including when processing offline. Eligible partial work in a mixed request is
retained. Cached signatures excluded by the selected era remain in incomplete
PSBTs but do not displace eligible alternatives during assembly or constrain
their signing modes. Explicit input declarations and eligible partials still
have to match. For incomplete inputs, `analyzepsbt` reports excluded key IDs in
`excluded_signatures`, separately from missing signatures, with a `rules_excluded`
issue unless a more specific mode issue applies. An incomplete result can contain
signatures. External devices receive the entire PSBT without
an era restriction; the host verifies their returned results under its selection.

These arguments do not change consensus, activation, address issuance, ordinary
sending, or admission. Completion checks scripts with the required input data;
it does not promise destination acceptance. No PSBT format or external-device
protocol change is introduced. `tidecoin-tx` continues to require its explicit
`-rules` setting. See [PSBT processing](psbt.md#selecting-script-rules) and the
[offline-signing tutorial](offline-signing-tutorial.md).

External-signer fee bumps and GUI signing retain one local rule selection
through processing and extraction if the chain crosses activation while the
operation is running. GUI PSBT analysis uses the same selection as signing;
a later Broadcast action checks the current rules again.

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

| Scheme | Prefix | Standard | Signature encoding | Local signing maximum | External-signing estimate |
|--------|--------|----------|--------------------|-----------------------|---------------------------|
| Falcon-512 | 0x07 | FIPS 206 (FN-DSA) in preparation | Variable-length compressed, unpadded | 666 bytes | 752 bytes |
| Falcon-1024 | 0x08 | FIPS 206 (FN-DSA) in preparation | Variable-length compressed, unpadded | 1,280 bytes | 1,462 bytes |
| ML-DSA-44 | 0x09 | NIST FIPS 204 | Fixed length | 2,420 bytes | 2,420 bytes |
| ML-DSA-65 | 0x0A | NIST FIPS 204 | Fixed length | 3,309 bytes | 3,309 bytes |
| ML-DSA-87 | 0x0B | NIST FIPS 204 | Fixed length | 4,627 bytes | 4,627 bytes |

Sizes are detached signatures, including the Falcon header and nonce; a
transaction signature adds one sighash byte. The external-signing estimates are
the PQClean output-buffer bounds used when the wallet cannot sign locally.
For Falcon, neither size column is a consensus length limit. ML-DSA verification
requires the exact fixed length listed for its parameter set.

Falcon-512 has been the default scheme since genesis (December 27, 2020). Wallet
address generation follows scheme activation. This release corrects early
acceptance of additional schemes in transaction and block validation; current
public-key prefix and length parsing is unchanged.

RPCs, descriptors, PSBT partial-signature parsing and `tidecoin-tx` check supplied
Falcon public keys for the correct inner header and canonical coefficient
encoding. A correctly sized key with malformed contents is rejected. ML-DSA
public keys retain their prefix and length checks. These checks validate the
encoding, not possession of a matching private key. Existing script spending
rules are unchanged, and legacy watch-only scripts remain tracked even when an
embedded key cannot be extracted as a valid public key.

Historical Falcon-512 WIF import and `dumpprivkey`'s `legacy` export use the
v0.18.3 layout: raw private key, `01`, and raw public key, without Tidecoin scheme
prefixes inside the payload. Import requires a valid embedded public key that
matches the key derived from the private bytes, before any wallet records are
saved. The default private-only export is unchanged. These checks apply to new
imports; they do not repair inconsistent key pairs already saved in a wallet.

`dumpprivkey` supports native `wsh512(pk(KEY))` address targets, including
PQHD-derived addresses. Descriptor targets now require one distinct public key:
previously, a multi-key descriptor could export whichever key was the only
private key held by the wallet. That case now returns error `-8`, regardless of
whether the wallet holds none, one or several of the private keys.

Other script-address targets remain unsupported. For a single-key script such
as `wsh512(multi(1,KEY))`, `wsh512(pkh(KEY))`, conditional Miniscript,
`wsh(pk(KEY))`, or `sh(wsh(pk(KEY)))`, use the wallet descriptor instead of its
address. These descriptor exports remain supported. Unsupported or ambiguous
address targets known to the wallet now return `-8` instead of incorrectly
reporting that the wallet is watch-only or locked. Missing private keys return
`-4`; a locked wallet returns `-13`. WIF formats are unchanged.

Legacy and strict Falcon verification
--------------------------------------

Falcon-512 signatures operate in two modes:

- **Legacy mode** (pre-AuxPoW): Relaxed norm bound verification with header
  byte 0x39. All existing mainnet signatures use this mode.
- **Strict mode** (post-AuxPoW): PQClean verification with exact compressed
  encoding, activated by the `SCRIPT_VERIFY_PQ_STRICT` consensus flag.

Keys are identical in both modes; verification bounds and encoding rules differ.
Both signing modes produce canonical signatures within the strict norm bound
and the same 666-byte local size limit.

Before AuxPoW activation, Falcon-512 block verification preserves the signature
encodings accepted by Tidecoin 0.18.3. Relay requires canonical compressed
encoding, including when `-acceptnonstdtxn=1` is used. After activation, a
successful signature check requires canonical encoding under the strict block
rules. Extra trailing signature bytes remain invalid in both eras. Local signing
continues to produce canonical signatures.

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

Signed-message verification accepts Falcon-512 signatures accepted by the legacy
verifier, including its wider norm bound and older encoding variants. It tries
strict verification first and falls back only for Falcon-512, independently of
chain height. Other schemes remain strict. Appended padding is still rejected;
current message signing and transaction verification rules are unchanged.

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
  10007 for custom and multisig descriptors), so default addresses
  of different types are not linkable through a shared key
- **Separate test-network keys** — default descriptors use coin type 1 on
  testnet and regtest and 6868 on mainnet. Descriptors and PSBT key origins
  accept either coin type on any network, so an explicitly imported path can
  derive the other network's keys from the same seed

`setpqhdpolicy` and `setpqhdseed` reapply policy defaults to both receive and
change descriptor bindings, including when the selected values are unchanged.
This can replace imported active descriptors as the source of new addresses;
older descriptors and their funds remain tracked. An encrypted wallet must be
unlocked when missing policy descriptors need to be created. The RPC help and
PQHD RPC documentation describe these effects.

Wallet encryption saves the encrypted existing keys and seeds. For non-blank
wallets, it then sets up a new seed and descriptors. If that setup fails, its
changes are rolled back and the wallet remains encrypted and locked. The error
reports this state; the supplied passphrase still unlocks the saved wallet and
its existing descriptors.
Existing active descriptors continue to supply addresses; no replacement seed
was installed. After resolving the write error, unlock, run `createpqhdseed`,
and select its returned `seed_id` with `setpqhdseed` to use fresh key material.
Make a new wallet backup. Existing coins retain their original keys.

Blank-wallet encryption retains any existing seeds and policy without generating
a seed or descriptors. Its result reports this and still requests a new backup.
To provision addresses, unlock, create or import a seed if needed, then use
`setpqhdseed` or reapply the existing policy with `setpqhdpolicy`.

`createpqhdseed` generates and saves a random 32-byte PQHD seed inside the wallet,
returning only its ID. It leaves existing defaults and active descriptors
unchanged; selecting the seed is a separate operation. An encrypted wallet must
be unlocked. Watch-only and external-signer wallets cannot generate local seeds.

If initialization fails after `createwallet` has encrypted a new wallet, its
encrypted blank file is retained and the error explains recovery. Resolve the
write error, then use `loadwallet`, `walletpassphrase`, `createpqhdseed` and
`setpqhdseed`, followed by a backup. Repeating `createwallet` does not overwrite
the retained file.

Native witness v1 descriptors (`wsh512`) are not usable before
AuxPoW activation: their outputs can be spent without a signature until the
witness v1 rules take effect. Before activation the wallet does not issue their
addresses, select their coins, or send to witness v1 addresses it recognizes.
`importdescriptors` still accepts them and returns a warning. A witness v1 coin
the wallet receives before activation, for example when someone pays an address
of an imported descriptor, is counted by `getbalances` but cannot be spent until
the activation height.

A wallet created before activation gains its `bech32pq` (`wsh512`) descriptors
after activation, when such an address is first requested or when an unencrypted
wallet is next loaded. Locked encrypted wallets load successfully and
create missing eligible descriptors on their next successful unlock, preserving
existing active imports. This includes encrypted wallets containing only a PQHD
seed and policy. A failed creation is rolled back and leaves the
wallet locked so unlocking can be retried. Witness v1 is
native only: `sh(wsh512(...))` descriptors are rejected, including when loading
wallet records, and have no signing or PSBT support. `decodescript` no longer
suggests P2SH wrappers for native v1. Known wrapped-v1 recipients and change
addresses are refused at every height. See [descriptors](descriptors.md).

`walletpassphrase` and `walletpassphrasechange` distinguish wallet operation
failures from incorrect passphrases. Database writes, deferred descriptor setup
and other wallet operation failures return error `-4` with their specific reason;
incorrect passphrases retain error `-14`. If saving a new passphrase fails, the
previous saved passphrase remains valid. The GUI displays the operation failure
instead of reporting an incorrect passphrase.

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
- Post-quantum key encapsulation replaces BIP324's secp256k1 ECDH key exchange
- 800-byte public keys, 768-byte ciphertexts, 32-byte shared secrets

Encryption is opportunistic. Inbound connections that start with a v1 message
are still accepted. Regular outbound peers selected from the address manager
use v2 when both sides advertise support. Address-fetch and explicitly configured
connections can attempt v2 without prior peer advertisement. An unsuccessful
outbound v2 attempt can retry with v1 while networking remains active, provided
it has received no bytes and has sent at least a v1 header's worth of bytes.
An established v2 connection
encrypts messages and detects their modification, but the handshake does not
verify the remote peer's identity: an active attacker can relay between two
peers without detection unless they compare session IDs (`getpeerinfo`) through
another channel. The initiator sends its raw 800-byte ML-KEM public key, whose
encoding has a recognizable structure, so v2 connections are not designed to
look like random traffic.

`getpeerinfo` reports `detecting` with an empty session ID until the v2 transport
handshake is complete, including while an outgoing connection waits for the
peer's ciphertext reply. This also corrects the timeout description for a
partially received ciphertext reply.

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

AuxPoW header replies use byte/count batching with matching continuation,
including both header-sync passes. Large announcements fall back to inventory
announcements, and outgoing messages exceeding the network limit are refused.
Header retrieval reads only a bounded block-file prefix. Missing or pruned
proofs return explicit raw RPC/REST errors; a P2P header range that cannot be
served closes the connection so the requester can use another peer. No separate
proof store is added. Verbose header metadata remains available. Oversized
individual proof representations are refused without permanently rejecting the
child hash. See [AuxPoW header synchronization](auxpow-header-sync.md) for the
continuation convention and storage limits.

Infrastructure for scrypt-based merged mining with Litecoin is implemented
and available for activation:

- AuxPoW chain ID: 8
- `createauxblock` and `submitauxblock` RPC commands
- Currently disabled on mainnet (`nAuxpowStartHeight = AUXPOW_DISABLED`)
- Active at block 1000 on testnet for testing

`createauxblock` and `getauxblock` reuse the latest template for each payout
address. If the mempool changes, that payout's template can refresh after more
than 60 seconds; requests for other payout addresses do not reset its refresh
interval. Previously issued templates remain available for submission until a
later work request observes a different chain tip, or the node restarts.
Refreshing work does not expire older templates, and no count, age or memory limit
is imposed on this cache.

`submitauxblock` and `getauxblock` accept lowercase, uppercase and mixed-case
hexadecimal spellings of the same block hash. Successful `getauxblock`
submissions advance the wallet's payout address regardless of hash spelling.

Wallet-selected mining payouts are tied to the loaded wallet instance. Unloading
a wallet clears its payout reservation, so loading a different wallet under the
same name cannot reuse the old wallet's address. Previously issued work keeps its
original payout and remains submittable under the template-retention rules above;
submitting it does not clear a replacement wallet's new reservation.

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

- Both passes of initial header synchronization check legacy difficulty
  transitions before AuxPoW activation, including when activation is disabled.
  These preliminary checks preserve the historical retarget and minimum-
  difficulty exceptions; full header acceptance still checks the exact target.
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
| Difficulty adjustment | Legacy retarget every 7,200 blocks (AuxPoW disabled) | Legacy retarget before block 1000; per-block 17-block averaging window from block 1000 |
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
- On Windows, macOS and BSD, TCP urgent data no longer causes reads while
  receiving from a peer is paused.
- Connections whose send queues remain paused for more than 20 minutes are
  disconnected, including peers using older protocol versions.

Block and undo storage
======================

Block and undo file positions use 64-bit values. File positioning and truncation
also support large offsets on Windows and supported 32-bit Unix builds. This
prevents position overflow when an undo file grows beyond 4 GiB and the earlier
2 GiB positioning failure on those platforms.

These changes preserve existing position encodings and require no additional
database migration. They do not repair undo records already overwritten or
truncated by an older build; those require `-reindex` with a corrected build.
Store block data on a filesystem supporting files larger than 4 GiB; FAT32's
file-size limit remains a limitation.

RPC, REST and command-line tools
===============================

The new REST endpoint `/rest/spenttxouts/BLOCKHASH` provides spent output queries.

`decodepsbt` looks up the complete declared input sighash value. A value such as
`0x101` is no longer displayed as `ALL`: any value that is not a recognized
sighash type shows an empty `sighash` string and the declared 32-bit value in
the new `sighash_value` field. Recognized types are displayed as before.

The mempool RPC help now states that `vsize`, `ancestorsize`, `descendantsize`
and `getmempoolinfo` `bytes` are sigops-adjusted using `-bytespersigop`, as are
the `testmempoolaccept` `vsize`. They can exceed the virtual size reported by
`decoderawtransaction`. The returned values are unchanged.

PSBT signing and witness-v1 hash types
-------------------------------------

Witness-v1 signatures without ANYONECANPAY commit to all spent amounts and
locking scripts, in input order. External v1 signers must use this message
format. ANYONECANPAY signatures omit these aggregate fields. Witness-v1 SINGLE
without a corresponding output is rejected, including with ANYONECANPAY. These
rules apply when native witness v1 activates.

External signing now requires the full previous transaction before requesting a
new legacy signature, including legacy P2SH inputs. Requests missing that data
are refused before contacting the signing device, with an explicit request to
supply `non_witness_utxo`. GUI per-input errors show mode details only for
signing-mode refusals. Native witness inputs and P2SH-wrapped v0
inputs retain their existing data requirements, and unchanged verified finals
remain usable with sufficient previous-output data. Existing legacy finals also
require the matching full previous transaction; an output summary alone is not
enough to report completion or extract the transaction. Wallet processing fills
that record from known transactions when available. PSBT analysis omits fee and
size estimates when required previous-transaction data is missing. Finalized
wrapped-v0 inputs remain usable with output summaries, using the redeem program
in the final scriptSig. `decodepsbt` remains a diagnostic dump whose fee is
calculated from supplied records without verifying them.
Newly returned legacy partial signatures and finals enforce the
same previous-transaction requirement. This does not independently establish
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
- Fee estimates include the full redeem-script push header for P2SH inputs,
  including larger PQ single-key and multisignature scripts.
- `sendall` rejects the unsupported `solving_data` option, including when nested
  inside `options`, instead of silently ignoring it. `send`, `fundrawtransaction`
  and `walletcreatefundedpsbt` continue to support externally supplied solving data.
- `bumpfee` and `psbtbumpfee` estimate signatures on inputs from outside the
  wallet at the maximum size for their signature scheme. They previously assumed
  72-byte ECDSA signatures, so a replacement spending such inputs could pay
  less than the requested fee rate.

Logging
-------

Unconditional logging is limited to 1 MiB per hour per source location.

Ban expiry limits
-----------------

`setban` rejects an explicit relative duration whose expiry would exceed a signed
64-bit timestamp with RPC error `-8`. Absolute timestamps retain their existing
range. Configured default durations and other callers cap an overflowing expiry
at the largest supported timestamp.

Genesis statistics
------------------

`getblockstats 0` reports the genesis coinbase value of 50 TDC. The optional
`-coinstatsindex` also accounts for those 50 TDC as unspendable genesis outputs.
The genesis block, subsidy schedule and UTXO hashes are unchanged.

Development note: testers who enabled `-coinstatsindex` in an earlier release
candidate must rebuild that index. With the node stopped, remove only
`indexes/coinstatsindex` from the relevant network's data directory, then restart
with `-coinstatsindex`. Rebuilding requires historical blocks; pruned nodes may
need to obtain missing blocks. No index migration or automatic rebuild is added.

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

`fees.chunk` retains the full 64-bit amount in `getmempoolentry` and verbose
`getrawmempool`, `getmempoolancestors` and `getmempooldescendants` results. This
includes fees above 21.47483647 TDC and large positive or negative local fee
adjustments. Transaction fees and mining selection are unchanged.

`prioritisetransaction` accepts signed 64-bit increments and caps each accumulated
adjustment at +/-2,100,000,000,000,000 satoshis (`MAX_MONEY`). Repeated calls and
saved adjustments use the same limit, and live modified fees reflect the capped
value. Adjustments for transactions not yet in the mempool are still retained.
Replacement comparisons use exact wider arithmetic for totals spanning multiple
clusters. Actual transaction fees and the `mempool.dat` format are unchanged.

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
