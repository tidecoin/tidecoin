# Changelog

Tidecoin is independently maintained software derived from Bitcoin Core.
This changelog documents notable changes to Tidecoin, including post-quantum
integration, Tidecoin-specific development, and selected upstream updates.

## v1.0.0rc4 (2026-11-23)

Fourth release candidate for Tidecoin 1.0.0. See the
[release notes](doc/release-notes.md#changes-since-v100rc3) for details.

- Correct wallet funding and fee bumping at input/output count encoding
  boundaries, including 253 inputs and 252 recipients plus change
- Reconcile fee shortfalls with change while preserving recipient amounts
  unless fee subtraction was requested
- Enforce maximum signed-weight estimates for explicit and default limits,
  including the complete 16,000-WU child limit for version 3 transactions
  spending an unconfirmed parent; near-limit batches may need to be reduced
- Reject provably undersized explicit input weights before virtual-size rounding
- Use actual scripts, fee-subtraction settings and ancestor fees in GUI
  coin-control estimates; show unavailable estimates instead of guessed fees
- Restore CMake 4.5 configuration compatibility without disabling build checks

Mainnet AuxPoW remains disabled, testnet activation remains at height 1,000,
and consensus rules are unchanged. Upgrading from rc3 requires no new wallet
migration or database rebuild.

## v1.0.0rc3 (2026-11-15)

Third test candidate for the first major release line (`1.x`), initially based on
Bitcoin Core v30 and maintained independently. Version 1.0.0 final has not been
released. See the [rc3 release notes](https://github.com/tidecoin/tidecoin/blob/v1.0.0rc3/doc/release-notes.md) for upgrade instructions,
activation settings, RPC changes and the complete candidate description.

### Candidate corrections

- Preserve pre-activation Falcon-512 block verification compatible with 0.18.3,
  while requiring canonical signature encoding for relay
- Keep strict Falcon signatures unpadded and bound locally generated sizes
- Separate default PQHD keys by script family and network
- Preserve encrypted-wallet loading across activation and recover cleanly from
  failed wallet initialization or post-encryption setup
- Add explicit pre/post-AuxPoW rule selection for offline transaction processing
- Correct PSBT previous-output checks, partial-signature reuse and fee estimates
- Correct activation rollback handling, mining template refreshes and RPC reporting
- Apply compiler checks to the C implementations and make PQ source reconstruction
  and script-fixture generation reproducible
- Bound local priority adjustments, compare replacement diagrams without fee-total
  overflow, check ban expiry arithmetic and report the actual genesis issuance
- Restore historical 0.18.3 WIF import and export compatibility, validate embedded
  public keys against private keys, and clarify private-key export restrictions
- Enforce the selected transaction era when creating and assembling signatures,
  and improve PSBT missing-key and excluded-signature diagnostics
- Synchronize wallet address, policy, GUI send and fee-bump requests with chain
  notifications before checking activation eligibility
- Bound AuxPoW header messages and disk reads, handle unavailable proofs explicitly,
  and isolate mining payout reservations across wallet unloads and replacements
- Incorporate upstream socket-event, stalled-peer and large undo-file fixes
- Save Tor/I2P identities, settings and block-storage metadata safely; validate
  block-file numbers and preserve shutdown requests during reindex retries
- Apply compiler options to macOS Objective-C++ sources and correct cross-platform
  CI and functional-test assumptions

### Post-Quantum Signatures

- Integrate Falcon-512 as the default signature scheme since genesis
- Add Falcon-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87 (five NIST-selected schemes;
  ML-DSA is FIPS 204, while Falcon's FN-DSA standard is in preparation)
- Implement scheme registry with prefix bytes 0x07-0x0B
- Add legacy Falcon verification mode (relaxed norm bound, header 0x39)
- Add strict PQClean verification mode (gated by `SCRIPT_VERIFY_PQ_STRICT`, post-AuxPoW)
- Implement Falcon signing retry (up to 10,000 attempts for randomness)
- Remove ECDSA, Schnorr, x-only pubkeys, and Taproot/MuSig entirely
- Remove secp256k1 key derivation, replace with PQ scheme selection
- Remove SIGHASH_DEFAULT; enforce strict ALL/NONE/SINGLE policy end-to-end

### PQHD Wallet

- Implement PQHD KDF primitives with SHA-512 and test vectors
- Add deterministic key generation (KeyGenFromSeed) for all 5 schemes
- Build PQHD wallet with hardened-only derivation
- Add multi-seed support with per-seed scheme policies
- Add configurable default receive/change schemes
- Add legacy Falcon WIF support and `dumpprivkey` RPC
- Add wallet creation progress bar
- Fix PQHD signing seed access and coin selection for PQ transactions

### ML-KEM-512 Encrypted Transport

- Replace BIP324's secp256k1 ECDH exchange with ML-KEM-512 (NIST FIPS 203)
  in V2 transport; encryption is opportunistic and does not establish peer identity
- Enable V2 PQ transport by default (`-v2transport=1`)
- Add ML-KEM V2 Python library for functional test coverage

### Script Extensions (Post-AuxPoW)

- Add OP_SHA512 opcode (0xb3) gated by `SCRIPT_VERIFY_SHA512`
- Add witness v1 512-bit script hash validation (`SCRIPT_VERIFY_WITNESS_V1_512`)
- Extend `PrecomputedTransactionData` with SHA-512 sighash variants
- Implement PQ-native address format with bech32 HRP "q" (mainnet) / "tq" (testnet)

### AuxPoW Merged Mining Infrastructure

- Implement AuxPoW block validation with chain ID 8
- Add `createauxblock` and `submitauxblock` RPC commands
- Wire scrypt validation for parent chain proof-of-work
- Add window-aware retarget in headers presync for AuxPoW compatibility
- Set activation: block 1000 (testnet), disabled (mainnet)
- Suppress unknown versionbit warnings until AuxPoW activation height

### Mining and Consensus

- Add YespowerTIDE proof-of-work (N=2048, r=8, CPU-only)
- Set Tidecoin chain parameters: 60s blocks, 40 TDC reward, quartering schedule
- Set genesis block (Dec 27, 2020): photonic quantum supremacy headline
- Preserve the legacy 7,200-block retarget before AuxPoW activation; use a
  17-block window with asymmetric limits after activation
- Parallelize header PoW validation for faster initial sync
- Expand signature cache to 64 MiB
- Fix subsidy calculation for quartering with doubling intervals

### Network

- Set mainnet port 8755, testnet port 18755
- Configure bech32 HRPs: "tbc" (mainnet), "ttbc" (testnet)
- Set message start bytes: 0xec 0xfa 0xce 0xa5
- Remove Signet and Testnet4; simplify to single testnet
- Update DNS seeds and testnet settings

### Build and Packaging

- Rename all binaries from bitcoin-* to tidecoin-*
- Update Guix reproducible build system for Tidecoin
- Fix macOS deployment and code signing
- Fix Guix install binary component
- Sync IPC/build fixes and refresh tooling

### Testing

- Add unit tests for all PQ signature schemes
- Add PQHD KDF and keygen test vectors
- Add AuxPoW functional tests
- Add ML-KEM V2 transport functional tests
- Normalize Falcon signatures for txpackages tests
- Fix and gate wallet tests behind PQ flag
- Set regtest parameters and assumeUTXO data
- Expand functional test coverage across all subsystems
