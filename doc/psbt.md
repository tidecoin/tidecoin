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
  a PSBT in human-readable form, as well as compute its eventual fee if known.
- **`analyzepsbt`** is a utility RPC that examines a PSBT and reports the
  current status of its inputs, the next step in the workflow if known, and if
  possible, computes the fee of the resulting transaction and estimates the
  final weight and feerate.

### Tidecoin-specific PSBT behavior

- Witness-v1 signatures without `ANYONECANPAY` commit to every input's amount
  and locking script, in input order. Signing and verification require all spent
  outputs; missing data does not fall back to an older signature calculation.
  Incorrect supplied amounts or scripts therefore cannot produce signatures that
  validate against the actual outputs. Witness-v0 rules are unchanged.
- `ANYONECANPAY` continues to cover only the current input's amount and script
  code. `NONE` and `SINGLE` do not cover all outputs. These modes do not approve a
  fixed total fee. Witness-v1 `SINGLE` fails if its corresponding output is absent.
- A full previous transaction and a separate witness output, when both present,
  must agree on the amount and locking script. Contradictory records are rejected,
  including when combining PSBTs or adding wallet information.
- Wallet and descriptor processing can omit full previous transactions when
  witness-v1 is active and every input is native witness-v1 with a 64-byte
  program, all declared and partial-signature modes are `ALL`, and no input has
  final signature fields. Separate previous-output records are kept. Other cases,
  including mixed witness-v0 inputs, wrapped inputs, `ANYONECANPAY`, finalized
  inputs and unknown witness versions, retain supplied full transactions.
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
