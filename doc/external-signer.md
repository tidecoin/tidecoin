# Support for signing transactions outside of Tidecoin

Builds with external signer support provide a command interface for PQ signing.
A bounded workflow using fixed public descriptors is covered by software tests
for all five PQ schemes. This does not establish compatibility with any hardware
wallet. Hardware provisioning, trusted displays and device-specific integration
require separate validation.

## Configuring the command

`-signer` specifies an executable followed by any fixed arguments. Tidecoin adds
the operation-specific arguments and starts the process directly. It does not
invoke a shell. The executable can be an absolute path or a name resolved through
the process search path.

The command uses the same quoting rules on all platforms:

- Spaces, tabs and line breaks separate arguments outside quotes.
- Single quotes or double quotes group an argument containing spaces. Adjacent
  quoted and unquoted text forms one argument. `""` passes an empty argument,
  except that the executable must not be empty.
- Inside single quotes, backslashes and double quotes are literal.
- Inside double quotes, `\\` produces one backslash and `\"` produces a double
  quote. All other backslashes are literal. Outside quotes, backslashes are
  literal too; use quotes to include spaces in a path.
- Unmatched quotes, an empty executable and NUL characters are rejected.
- Environment variables, `~`, wildcards, pipes, redirection and command
  substitutions are not expanded or interpreted.

For example, the value in `tidecoin.conf` can include a path with spaces and a
fixed argument with spaces:

```ini
signer="/opt/signer tools/signer" --device "device name"
```

A Python-based tool can specify both the interpreter and script paths:

```ini
signer="/opt/python tools/python3" -u "/opt/signer tools/signer.py"
```

The configuration file's normal comment rules still apply: `#` starts a comment,
including inside quotes. Use the command-line option for a path containing `#`.

Single quotes preserve Windows paths, including network paths, literally:

```ini
signer='C:\Program Files\Signer\signer.exe'
signer='\\server\share\Signer\signer.exe'
```

These are alternative settings; specify only the command you intend to use.
For command-line invocation, the surrounding shell must also preserve the
quotes intended for Tidecoin. For example, in a POSIX shell:

```sh
tidecoind -signer='"/opt/signer tools/signer" --device "device name"'
```

An unquoted executable path containing spaces remains ambiguous and must be
quoted. Commands without spaces or quote characters continue to work as before.
Literal quotes in existing commands now need to follow the quoting rules above.

## PQ provisioning and device matching

The bridge implements the existing `enumerate`, `getdescriptors --account 0`,
`displayaddress --desc <descriptor>` and `signtx <psbt>` operations. Signing uses
`--stdin`: the operation and PSBT are delivered on standard input. Network and
`--fingerprint` arguments select the network and enumerated device. The
`fingerprint` field is an opaque bridge/device selector, not cryptographic proof
of ownership and not a PQHD seed identifier.

Keep seeds on the signing side. A PQHD descriptor containing only a seed ID
cannot supply fresh hardened derivation to a seedless host. Initial enrollment
accepts fixed public descriptors in `receive` and `internal` arrays, with one
usable descriptor per output type in each array. Private-key descriptors and
PQHD seed-reference descriptors are rejected. Verify the public scripts through
a trusted enrollment process and preserve their association with the signing
device, its seed(s), full derivation paths and account information on the signing
side. Those associations are not inferred or authenticated by a seed ID.

The host persists the enrolled descriptors in its existing wallet records.
Before sending a PSBT for a managed input or displaying its address, it requests
account-0 descriptors and checks that the connected signer still advertises the
enrolled descriptor. A different device advertising different keys is rejected,
even if it uses the same selector. A malicious bridge can falsely advertise the
same public descriptor; this matching is not device attestation. Actual completed
spends must still verify against the enrolled keys/scripts.

Fixed public descriptors provide finite monitoring and solving data. They do
not create a ranged address generator: `getnewaddress`, automatic change
allocation and automatic keypool replenishment are unavailable from those fixed
descriptors. Use explicitly provisioned receiving scripts and a separately
provisioned change address (for example, `changeAddress` with
`walletcreatefundedpsbt`). Replenish monitoring with further trusted fixed public
descriptors using `importdescriptors`, inactive and with an appropriate historical
timestamp; keep them advertised by the signer for later matching. Reprovisioning
does not remove monitoring of earlier scripts. Do not reuse a fixed address as a
substitute for provisioning fresh scripts.

The device must independently resolve each requested key/path to its own seed,
verify the transaction and input amounts, identify change from its own trusted
public scripts, and present recipients, amounts and fees for approval. Host
origin records are hints; they must not authorize an arbitrary path, a seed
selection or a change classification. This interface does not add a standardized
hardware enrollment/attestation protocol or an authenticated public derivation
root. Multiple simultaneously connected devices remain unsupported by automatic
selection.

## Signing responses and completion

Before any device signing request, the wallet checks all enrolled signing
targets. An unfinished legacy input, including a legacy P2SH input, requires
the full previous transaction (`non_witness_utxo`). Its transaction ID, output
index and any separate output summary must agree. Native and wrapped witness
inputs may use an output summary under their applicable rules. Missing legacy
transaction data is reported with a request to supply `non_witness_utxo` before
any signing device is contacted; unchanged
verified finals and unrelated inputs do not acquire a new signing requirement.
This check does not independently establish every other input amount used in a
displayed fee.

The host retains its requested unsigned transaction and metadata. A response may
omit metadata removed by finalization, but any metadata it returns must already
match the request. A witness UTXO exactly matching the original full previous
transaction is also accepted. Changed transactions, UTXOs, sighash requests,
scripts, origins, unknown or proprietary metadata are rejected; added protected
metadata is rejected as well. Prepare required solving data before signing.

Only partial signatures and final scripts/witnesses are merged. Existing
signature fields cannot be replaced with conflicting values. New signature
hash types must match the request (ALL by default). Previously verified finalized
inputs retain their existing hash types even if finalization removed their
sighash metadata. Every returned final script
must verify against the retained transaction and UTXO under the applicable
Tidecoin script rules. Each new partial signature is checked against the retained
transaction and script, and new legacy partials and finals require the full
previous transaction. The signer's `complete` claim is ignored. Partial updates
can remain incomplete even when their individual signatures verify; a completed
result requires full script verification. Rejection preserves the host's original
PSBT.

`finalizepsbt`, `descriptorprocesspsbt` and wallet completion checks do not treat
the mere presence of final fields as proof of validity. Verification is relative
to supplied/locally known UTXO data and applicable script flags; it is not proof
that inputs are currently unspent or that a transaction satisfies every mempool
policy. Use normal transaction validation before broadcast.

`listdescriptors true` does not export PQHD seeds. Save every required seed and
recovery metadata separately, or retain a full wallet backup. Public-only fixed
keys may prevent private descriptor serialization. The compatibility RPCs
`gethdkeys` and `createwalletdescriptor` do not provide BIP32/xpub operations in
Tidecoin; their help directs callers to PQHD seed IDs and public descriptors.
