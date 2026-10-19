# AGENTS.md

Instructions for AI coding assistants working with this repository.

## Project Overview

Tidecoin is an independently maintained post-quantum cryptocurrency derived from
Bitcoin Core. It replaces ECDSA entirely with NIST-standardized post-quantum
signature schemes. The network has been operational since December 27, 2020.

The Tidecoin 1.x codebase was initially based on Bitcoin Core v30 and has since
evolved through Tidecoin-specific development and selected updates from later
Bitcoin Core development. Tidecoin maintains its own releases, consensus rules,
and compatibility requirements. Check behavior against this repository before
assuming that an upstream implementation or recommendation applies.

**This is NOT Bitcoin Core.** All classical cryptographic signing has been
replaced. Do not suggest ECDSA, Schnorr, Taproot, or secp256k1 solutions — none of
these exist in Tidecoin.

## Build

```bash
cmake -B build
cmake --build build -j$(nproc)
```

## Test

```bash
# Unit tests
ctest --test-dir build

# Functional tests
build/test/functional/test_runner.py
```

## Architecture

### Cryptographic Schemes

Five NIST-standardized PQ signature schemes (defined in `src/pq/pq_scheme.h`):

| Scheme | Prefix | Standard |
|--------|--------|----------|
| Falcon-512 | 0x07 | Draft FIPS 206 |
| Falcon-1024 | 0x08 | Draft FIPS 206 |
| ML-DSA-44 | 0x09 | FIPS 204 |
| ML-DSA-65 | 0x0A | FIPS 204 |
| ML-DSA-87 | 0x0B | FIPS 204 |

Falcon-512 is the default and has been used since genesis.

### Key Directories

| Path | Purpose |
|------|---------|
| `src/pq/` | PQ crypto implementations (Falcon, ML-DSA, ML-KEM, PQHD KDF) |
| `src/pq/falcon-512/` | PQClean Falcon-512 (integer emulation, NOT native float) |
| `src/pq/falcon-1024/` | PQClean Falcon-1024 |
| `src/pq/ml-dsa-*/` | ML-DSA implementations |
| `src/pq/ml-kem-512/` | ML-KEM-512 for P2P transport encryption |
| `src/crypto/yespower/` | YespowerTIDE proof-of-work |
| `src/wallet/pqhd.h` | PQHD wallet structures |
| `src/kernel/chainparams.cpp` | Chain parameters and genesis config |
| `src/validation.cpp` | Consensus rules and subsidy schedule |

### Key Concepts

- **PQHD Wallet**: Post-Quantum Hierarchical Deterministic wallet using SHA-512
  KDF with hardened-only derivation. Replaces BIP-32.
- **Legacy vs Strict Falcon**: Pre-AuxPoW uses relaxed norm bounds (header 0x39).
  Post-AuxPoW activates strict PQClean verification.
- **AuxPoW**: Merged mining infrastructure (chain ID 8). Currently disabled on
  mainnet. Gates activation of multi-scheme support, witness v1, OP_SHA512,
  and strict PQ verification.
- **ML-KEM-512 Transport**: V2 P2P encryption uses post-quantum key encapsulation
  instead of X25519. Enabled by default.

### Binaries

| Binary | Purpose |
|--------|---------|
| `tidecoind` | Full node daemon |
| `tidecoin-qt` | GUI wallet |
| `tidecoin-cli` | RPC client |
| `tidecoin-wallet` | Wallet utility |
| `tidecoin-tx` | Transaction utility |
| `tidecoin-util` | General utility |

## Coding Conventions

- Follow existing Bitcoin Core style: 4-space indentation in C++, snake_case
  for functions and variables, CamelCase for classes.
- PQ crypto code in `src/pq/` follows PQClean conventions.
- All new features must have unit tests (`src/test/`) and functional tests
  (`test/functional/`) where applicable.
- Do not introduce floating-point arithmetic in cryptographic code. Falcon uses
  integer emulation (`fpr` = `uint64_t`) for constant-time operation.
- Do not add ECDSA, secp256k1, Schnorr, or Taproot code.

## Documentation

- [Whitepaper](doc/whitepaper.md) — Full technical whitepaper
- [Developer notes](doc/developer-notes.md) — Coding style and guidelines
- [Release notes](doc/release-notes.md) — Current release details
