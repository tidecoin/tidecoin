Tidecoin v1.0.0 Release Notes
============================

Tidecoin v1.0.0 is now available from:

  <https://github.com/tidecoin/tidecoin/releases>

This is a major release that rebases Tidecoin onto Bitcoin Core v30, bringing
post-quantum cryptography, a new PQHD wallet system, ML-KEM encrypted
transport, and script extensions alongside all upstream improvements.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/tidecoin/tidecoin/issues>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Tidecoin-Qt` (on macOS)
or `tidecoind`/`tidecoin-qt` (on Linux).

Compatibility
==============

Tidecoin is supported and tested on operating systems using the
Linux Kernel 3.17+, macOS 13+, and Windows 10+. Tidecoin should also work on
most other Unix-like systems but is not as frequently tested on them.

Post-Quantum Cryptography
=========================

Multi-scheme signature support
------------------------------

Tidecoin supports five NIST-standardized post-quantum signature schemes,
all active on the network:

| Scheme | Prefix | Standard | Signature size |
|--------|--------|----------|----------------|
| Falcon-512 | 0x07 | NIST Draft FIPS 206 (FN-DSA) | 666 bytes |
| Falcon-1024 | 0x08 | NIST Draft FIPS 206 (FN-DSA) | 1,280 bytes |
| ML-DSA-44 | 0x09 | NIST FIPS 204 | 2,420 bytes |
| ML-DSA-65 | 0x0A | NIST FIPS 204 | 3,309 bytes |
| ML-DSA-87 | 0x0B | NIST FIPS 204 | 4,627 bytes |

Falcon-512 has been the default scheme since genesis (December 27, 2020). All
five schemes are available for new addresses. No ECDSA exists anywhere in the
protocol.

Legacy and strict Falcon verification
--------------------------------------

Falcon-512 signatures operate in two modes:

- **Legacy mode** (pre-AuxPoW): Relaxed norm bound verification with header
  byte 0x39. All existing mainnet signatures use this mode.
- **Strict mode** (post-AuxPoW): Standard PQClean verification activated by
  the `SCRIPT_VERIFY_PQ_STRICT` consensus flag.

Keys are identical in both modes. Only signature creation and verification
bounds differ.

PQHD Wallet
============

A new Post-Quantum Hierarchical Deterministic (PQHD) wallet system replaces
the BIP-32 HD wallet for post-quantum key derivation:

- **Hash-based KDF** using SHA-512 for deterministic key generation
- **Hardened-only derivation** — no public key derivation (which is inherently
  unsafe for lattice-based schemes)
- **Multi-seed support** with independent seeds and per-seed scheme policies
- **Configurable default schemes** for receive and change addresses
- **Encrypted storage** via `PQHDCryptedSeed` for wallet-at-rest security

The PQHD system is documented in detail in the [whitepaper](whitepaper.md).

ML-KEM-512 Encrypted P2P Transport
====================================

Tidecoin's V2 transport protocol uses ML-KEM-512 (NIST FIPS 203) for
post-quantum key encapsulation during the peer-to-peer handshake:

- **Enabled by default** (`-v2transport=1`)
- Post-quantum key encapsulation replaces the X25519 key exchange
- 800-byte public keys, 768-byte ciphertexts, 32-byte shared secrets
- Secure memory handling with `secure_allocator` and `memory_cleanse`

This ensures that P2P traffic is protected against both classical and quantum
eavesdroppers, including "harvest now, decrypt later" attacks on network
traffic.

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

- 64-byte witness v1 script hash validation via `SCRIPT_VERIFY_WITNESS_V1_512`
- Extended `PrecomputedTransactionData` with SHA-512 variants:
  `hashPrevouts_512`, `hashSequence_512`, `hashOutputs_512`
- Provides 256-bit security under Grover's quantum algorithm (vs 128-bit
  from SHA-256)

Mining
======

YespowerTIDE
------------

Tidecoin uses the YespowerTIDE algorithm for proof-of-work, a memory-hard
function designed for CPU mining fairness:

- Parameters: N=2048, r=8
- No ASIC or GPU advantage — all coins earned through CPU mining
- No premine, no ICO

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
- Activation will increase 51% attack cost by approximately 10,000x

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

Inherited from Bitcoin Core v30
================================

Tidecoin v1.0.0 inherits all applicable improvements from Bitcoin Core v30.
Notable upstream changes include:

- **GUI migrated from Qt 5 to Qt 6** with Windows dark mode support and macOS
  Metal backend.
- **Legacy BDB wallets removed.** Use `migratewallet` RPC to migrate to
  descriptor wallets.
- **Improved 1p1c package relay** supporting broader topologies.
- **Enhanced orphanage DoS protections** with weight-based and per-peer limits.
- **NAT-PMP/PCP enabled by default** for automatic firewall traversal.
- **Extended `-proxy` syntax** for per-network proxy configuration.
- **Rate-limited unconditional logging** (1 MiB/hour per source location).
- **New REST endpoint** `/rest/spenttxouts/BLOCKHASH` for spent output queries.
- **TRUC transaction support** in the wallet.

For the complete list of upstream changes, see the
[Bitcoin Core v30.0 release notes](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-30.0.md).

New `tidecoin` command
----------------------

A new `tidecoin` command line tool has been added:

- `tidecoin node` is a synonym for `tidecoind`
- `tidecoin gui` is a synonym for `tidecoin-qt`
- `tidecoin rpc` is a synonym for `tidecoin-cli -named`
- `tidecoin test` runs the test suite

Credits
=======

Tidecoin is built on Bitcoin Core. We thank the Bitcoin Core developers for
their foundational work.

The post-quantum cryptographic integration, PQHD wallet, ML-KEM transport,
YespowerTIDE mining, AuxPoW infrastructure, and script extensions were
developed by the Tidecoin contributors.
