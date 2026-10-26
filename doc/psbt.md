# PSBT Howto for Tidecoin

Since Tidecoin includes an RPC interface for Partially Signed Tidecoin
Transactions (PSBTs, as specified in
[BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)).

This document describes the overall workflow for producing signed transactions
through the use of PSBT, and the specific RPC commands used in typical
scenarios.

## PSBT in general

PSBT is an interchange format for Tidecoin transactions that are not fully signed
yet, together with relevant metadata to help entities work towards signing it.
It is intended to simplify workflows where multiple parties need to cooperate to
produce a transaction. Examples include hardware wallets, multisig setups, and
[CoinJoin](https://bitcointalk.org/?topic=279249) transactions.

### Overall workflow

Overall, the construction of a fully signed Tidecoin transaction goes through the
following steps:

- A **Creator** proposes a particular transaction to be created. They construct
  a PSBT that contains certain inputs and outputs, but no additional metadata.
- For each input, an **Updater** adds information about the UTXOs being spent by
  the transaction to the PSBT. They also add information about the scripts and
  public keys involved in each of the inputs (and possibly outputs) of the PSBT.
- **Signers** inspect the transaction and its metadata to decide whether they
  agree with the transaction. They can use amount information from the UTXOs
  to assess the values and fees involved. If they agree, they produce a
  partial signature for the inputs for which they have relevant key(s).
- A **Finalizer** is run for each input to convert the partial signatures and
  possibly script information into a final `scriptSig` and/or `scriptWitness`.
- An **Extractor** produces a valid Tidecoin transaction (in network format)
  from a PSBT for which all inputs are finalized.

Generally, each of the above (excluding Creator and Extractor) will simply
add more and more data to a particular PSBT, until all inputs are fully signed.
In a naive workflow, they all have to operate sequentially, passing the PSBT
from one to the next, until the Extractor can convert it to a real transaction.
In order to permit parallel operation, **Combiners** can be employed which merge
metadata from different PSBTs for the same unsigned transaction.

The names above in bold are the names of the roles defined in BIP174. They're
useful in understanding the underlying steps, but in practice, software and
hardware implementations will typically implement multiple roles simultaneously.

## PSBT in Tidecoin

### RPCs

- **`converttopsbt` (Creator)** is a utility RPC that converts an
  unsigned raw transaction to PSBT format. It ignores existing signatures.
- **`createpsbt` (Creator)** is a utility RPC that takes a list of inputs and
  outputs and converts them to a PSBT with no additional information. It is
  equivalent to calling `createrawtransaction` followed by `converttopsbt`.
- **`walletcreatefundedpsbt` (Creator, Updater)** is a wallet RPC that creates a
  PSBT with the specified inputs and outputs, adds additional inputs and change
  to it to balance it out, and adds relevant metadata. In particular, for inputs
  that the wallet knows about (counting towards its normal or watch-only
  balance), UTXO information will be added. For outputs and inputs with UTXO
  information present, key and script information will be added which the wallet
  knows about. It is equivalent to running `createrawtransaction`, followed by
  `fundrawtransaction`, and `converttopsbt`.
- **`walletprocesspsbt` (Updater, Signer, Finalizer)** is a wallet RPC that takes as
  input a PSBT, adds UTXO, key, and script data to inputs and outputs that miss
  it, and optionally signs inputs. Where possible it also finalizes the partial
  signatures.
- **`descriptorprocesspsbt` (Updater, Signer, Finalizer)** is a node RPC that takes
  as input a PSBT and a list of descriptors. It updates SegWit inputs with
  information available from the UTXO set and the mempool and signs the inputs using
  the provided descriptors. Where possible it also finalizes the partial signatures.
- **`utxoupdatepsbt` (Updater)** is a node RPC that takes a PSBT and updates it
  to include information available from the UTXO set (works only for SegWit
  inputs).
- **`finalizepsbt` (Finalizer, Extractor)** is a utility RPC that finalizes any
  partial signatures, and if all inputs are finalized, converts the result to a
  fully signed transaction which can be broadcast with `sendrawtransaction`.
- **`combinepsbt` (Combiner)** is a utility RPC that implements a Combiner. It
  can be used at any point in the workflow to merge information added to
  different versions of the same PSBT. In particular it is useful to combine the
  output of multiple Updaters or Signers.
- **`joinpsbts`** (Creator) is a utility RPC that joins multiple PSBTs together,
  concatenating the inputs and outputs. This can be used to construct CoinJoin
  transactions.
- **`decodepsbt`** is a diagnostic utility RPC which will show all information in
  a PSBT in human-readable form. Its fee is calculated from supplied UTXO records
  without verifying their amounts or transaction validity; it is not an approval
  of that fee. Use `analyzepsbt` to check what data the processing workflow needs.
- **`analyzepsbt`** is a utility RPC that examines a PSBT and reports the
  current status of its inputs, the next step in the workflow if known, and if
  possible, computes the fee of the resulting transaction and estimates the
  final weight and feerate.

### Selecting script rules

Eight processing RPCs accept an optional final `rules` argument:

| RPC | Position (counting from one) | Result |
| --- | --- | --- |
| `walletprocesspsbt` | 6 | Object |
| `descriptorprocesspsbt` | 5 | Object |
| `finalizepsbt` | 3 | Object |
| `analyzepsbt` | 2 | Object |
| `signrawtransactionwithkey` | 5 | Object |
| `signrawtransactionwithwallet` | 4 | Object |
| `utxoupdatepsbt` | 3 | Base64 PSBT string |
| `combinerawtransaction` | 2 | Transaction hex string |

The accepted strings are `pre-auxpow` and `post-auxpow`. Omitted or JSON `null`
selects the local next-block era once for the request. At activation height H,
a tip at H−1 selects post-activation rules. Disabled activation selects pre rules.
An explicit choice takes precedence even on an offline node or a network with
activation disabled. It changes only this processing request: standard script
checks remain enabled, and post rules additionally enable strict PQ verification,
native witness v1 and `OP_SHA512`.

Use the same explicit era for offline analysis, signing and finalization:

```sh
tidecoin-cli -named analyzepsbt psbt="$PSBT" rules=post-auxpow
tidecoin-cli -rpcwallet=offline_wallet -named walletprocesspsbt psbt="$PSBT" rules=post-auxpow
tidecoin-cli -named finalizepsbt psbt="$SIGNED_PSBT" rules=post-auxpow
```

The six object results include `rules`, including incomplete results. An explicit
choice different from the local next-block era adds a `warnings` array explaining
both eras. A genesis-only host processing post-activation transactions normally
receives this notice. The two string results keep their existing format and have
no metadata or notices. `combinerawtransaction` still requires the input coins in
its local view. No rule field is stored in a PSBT or sent to an external signer.
The standalone `tidecoin-tx` tool uses these same names but requires an explicit
`-rules` argument for signing and verification; it has no chain-derived default.

One selection governs cached partial checks, new signatures, existing finals,
analysis, transaction-record cleanup and extraction. A partial that fails the
selected rules is excluded from reusable signing data; when signing with its
owner's key it can be replaced. Foreign entries are preserved. Explicit sighash
requests and required previous-output data still apply. A supplied invalid final
remains incomplete; processing does not clear it to automatically re-sign it.

For example, `pre-auxpow` processing can complete an older valid Falcon-512
encoding with a negative-zero coefficient sign or nonzero unused final bits.
Current relay policy refuses these encodings even before activation. Obtain
fresh canonical signatures through the ordinary signing workflow for relay;
processing an already valid final does not rewrite it. `post-auxpow` processing
rejects these encodings for successful signature checks and can replace an
invalid owned partial, but leaves an invalid supplied final incomplete. Extra
trailing bytes, including zero padding, are invalid under both selections.

`complete: true` means that all input scripts verify under the selected rules
with the required supplied input data. It does not establish confirmation,
unspentness, maturity, finality, sufficient fees or acceptance by the destination.
Use the destination node's `testmempoolaccept` before broadcasting. Sending,
address issuance, mining and admission do not accept this override; ordinary
wallet sends and external-signer fee bumps use one local selection through
PSBT filling, signing and extraction. GUI PSBT processing also retains one
selection for each open or sign action, including its analysis and status
display. A later Broadcast action selects current local rules again; mempool
admission always follows the current chain. See the
[offline tutorial](offline-signing-tutorial.md) for separate address provisioning.

### Tidecoin-specific PSBT behavior

- Legacy inputs, including legacy P2SH, require the matching full previous
  transaction (`non_witness_utxo`) for signing and for verification of existing
  final fields. A `witness_utxo` summary alone does not establish a legacy input's
  amount or locking script. Without the full record, finalization/extraction
  remains incomplete and `analyzepsbt` omits fee and size estimates and requests
  an updater. `has_utxo` still reports whether an output record is present.
  Wallet processing supplies the full record when the wallet knows the previous
  transaction, including for already finalized inputs. Contradictory supplied
  summaries are rejected, not replaced silently.
- Supported native witness inputs and wrapped v0 may still use output summaries.
  Finalized wrapped-v0 inputs are classified using the redeem program in their
  final scriptSig, since finalization removes the separate `redeem_script` field.
  Witness-only amounts are not independently checked against the chain, and a
  complete PSBT does not establish confirmation, unspentness or relay acceptance.
- External signing checks every enrolled unfinished legacy target for its full
  previous transaction before contacting a device. New legacy partial signatures
  and all legacy finals enforce the same requirement on device-result merging.
  Verified existing finals retain their modes and unrelated partial signatures
  remain unchanged. See [external signing](external-signer.md#signing-responses-and-completion).
- Existing legacy/v0 finals with undefined hash-type bytes remain verifiable
  and extractable. Mempool admission and relay require nonempty signatures to
  use `ALL`, `NONE` or `SINGLE`, optionally with `ANYONECANPAY`, so verification
  does not guarantee broadcast acceptance. Active witness v1 enforces these
  six bytes as a consensus rule as well.
- Witness-v1 signatures without `ANYONECANPAY` commit to every input's amount
  and locking script, in input order. Signing and verification require all spent
  outputs; missing data does not fall back to an older signature calculation.
  Incorrect supplied amounts or scripts therefore cannot produce signatures that
  validate against the actual outputs. Witness-v0 signature hashing is unchanged.
- `ANYONECANPAY` continues to cover only the current input's amount and script
  code. `NONE` and `SINGLE` do not cover all outputs. These modes do not approve a
  fixed total fee. Witness-v1 `SINGLE` fails if its corresponding output is absent.
- A full previous transaction and a separate witness output, when both present,
  must agree on the amount and locking script. Contradictory records are rejected,
  including when combining PSBTs or adding wallet information.
- `analyzepsbt` verifies finalized inputs using the supplied spent outputs and
  uses dummy signatures to estimate unfinished inputs when enough solving data
  is available. Its `missing.witnessscript` field reports the expected SHA-256
  hash for witness v0 or SHA-512 hash for witness v1, as 64 or 128 hex characters
  respectively.
- Wallet and descriptor processing can omit full previous transactions when
  witness-v1 is active and every input qualifies: native 64-byte v1 with
  defined `ALL`, `NONE` or `SINGLE` modes and no `ANYONECANPAY`. Unfinished
  native inputs need no witness script to classify their output. P2SH inputs
  never qualify for this cleanup.
  Final inputs require full script verification and at least one successful v1
  signature check. All executed nonempty checks must use eligible modes, and
  any present declaration must agree. Signatureless finals retain full records.
  Separate previous-output records are preserved. One excluded or inconsistent
  input retains every full transaction. Standalone `finalizepsbt` does not run
  this cleanup.
- Cleanup is a storage policy, not authentication of witness-only fee data.
  An absent declaration still permits a later explicitly requested
  `ANYONECANPAY` signature. For offline/device signing in that mode, foreign
  witness-only amounts do not provide authenticated fee evidence. Keep available
  full transactions when preparing such requests.
- New signing, explicit public declarations and size estimation support exactly
  `ALL`, `NONE`, `SINGLE`, and those three modes with `ANYONECANPAY`.
  Omitted signing mode means `ALL`; the stored field does not authorize a
  different mode. Consent is checked only for inputs whose keys are used.
  Foreign inputs retain their own modes. A single call cannot authorize
  different modes for multiple owned inputs.
- `walletprocesspsbt(sign=false)` with omitted mode preserves declarations.
  An explicit mode atomically declares every unfinished input, including inputs
  with no UTXO or wallet keys. Explicit public `ALL` is recorded; ordinary default
  ALL signing does not add it. Existing declarations and partial signatures must
  agree. New nondefault signing declarations are published only with valid new
  signatures. Verified finals are preserved. `descriptorprocesspsbt` has no
  public-only switch; use `utxoupdatepsbt` for public updates and the wallet's
  explicit public-declaration operation for coordinator requests.
- Signing ignores partial signatures that do not verify against the input, so
  they neither block signing nor constrain its mode. The signer replaces an
  invalid partial signature for its own key; invalid entries for other keys
  stay in the PSBT. A valid partial signature from the signer's own key made in
  a different mode than requested is refused with a sighash mismatch.
- Combining PSBTs preserves declarations and rejects conflicting declarations.
  Finalization checks existing signature bytes even for ALL. An absent declaration
  means ALL for standalone finalization; an undeclared NONE partial is unfinished.
- SINGLE without a corresponding output is refused for new signatures in every
  signature version, including external signing. Existing such partials are not
  newly finalized. Already verified finals keep their consensus validity.
  `analyzepsbt` reports per-input `issue` and `issue_message`, including on finals.
  An impossible SINGLE layout reports `next=creator` with no top-level error;
  unsupported metadata reports `next=updater`. Independently computable fees are
  retained, while unresolved size/fee-rate estimates are omitted. Consumers must
  inspect issues regardless of the aggregate role.
- Active witness-v1 signature opcodes require every nonempty signature argument
  to end in `01`, `02`, `03`, `81`, `82` or `83` (hex). Other bytes cause a
  `SIG_HASHTYPE` script error, including arguments a multisig matching loop would
  not reach. Empty signatures retain their existing behavior. This consensus
  restriction does not apply to legacy or witness v0; their valid final signatures
  with other bytes remain verifiable even though new signing requests are narrower.
- This witness-v1 signature calculation changes the earlier development/testnet
  rules. Existing ordinary witness-v1 signatures must be regenerated. Deployment
  requires a restarted testnet; this is not a transition for the old testnet's
  history. Mainnet witness-v1 remains gated by AuxPoW activation. No activation
  setting or witness-v0 signature rule is changed by this correction.
- Tidecoin wallet PSBT RPCs do not expose a `bip32derivs` toggle.
- `walletprocesspsbt` supports `include_pqhd_origins` (default `false`) to
  control emission of Tidecoin proprietary PQHD origin records.
- `walletcreatefundedpsbt`, `send`/`sendall` (when returning PSBT), and
  `psbtbumpfee` also support `include_pqhd_origins` (default `false`) for the
  same metadata emission control.
- When enabled, wallet-owned single-key inputs/outputs may include
  `tidecoin/PQHD_ORIGIN` metadata in PSBT proprietary keyspaces; disabling this
  flag suppresses metadata emission without changing signing/finalization behavior.
- Wallet signing fallback for descriptor/miniscript paths includes:
  - pubkey discovery from pushed script elements in redeem/witness scripts,
  - key lookup fallback by `CKeyID` when pubkey-index mapping is absent.


### Workflows

#### Multisig with multiple Tidecoin instances

For a quick start see [Basic M-of-N multisig example using descriptor wallets and PSBTs](./descriptors.md#basic-multisig-example).
