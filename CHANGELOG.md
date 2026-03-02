# Changelog

All notable Tidecoin-specific changes are documented in this file.
Tidecoin is built on Bitcoin Core v30. This changelog covers the
post-quantum integration and Tidecoin-specific development only.

## v1.0.0 (2026-03-02)

First major release line (`1.x`) rebased on Bitcoin Core v30 with full
post-quantum cryptographic integration.

### Post-Quantum Signatures

- Integrate Falcon-512 as the default signature scheme since genesis
- Add Falcon-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87 (5 NIST-standardized schemes)
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

- Replace X25519 key exchange with ML-KEM-512 (NIST FIPS 203) in V2 transport
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
- Configure difficulty adjustment: 17-block window, asymmetric limits
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
