# Tidecoin (TDC)

Tidecoin is an independently maintained post-quantum cryptocurrency derived from Bitcoin Core. It replaces ECDSA with Falcon-512 signatures from genesis, provides an upgrade path to Falcon-1024 and ML-DSA, has a 21 million TDC supply, and is CPU-mineable via YespowerTIDE in its pre-AuxPoW phase.

## What is Tidecoin?

Tidecoin is a decentralized peer-to-peer cryptocurrency engineered from block zero to resist attacks from both classical and quantum computers. While Bitcoin and virtually all major blockchains rely on ECDSA or Schnorr signatures over secp256k1 — which Shor's algorithm will break once sufficiently powerful quantum computers exist — Tidecoin replaces ECDSA entirely with post-quantum signature schemes from the NIST PQC process.

The network has been in continuous operation since December 27, 2020, with over 2.7 million blocks produced. No security incident, consensus failure, or cryptographic vulnerability has been reported. Tidecoin uses finalized NIST standards where available and NIST-selected schemes still in standardization where appropriate.

| | |
|---|---|
| **Ticker** | TDC |
| **Algorithm** | YespowerTIDE (CPU-friendly, memory-hard) |
| **Block time** | 60 seconds |
| **Max supply** | ~21,000,000 TDC |
| **Premine/ICO** | None — all coins earned through mining |
| **Genesis date** | December 27, 2020 |
| **Default port** | 8755 |
| **License** | MIT |

## Why Does Post-Quantum Matter?

NIST Interagency Report 8547 recommends that all systems migrate to post-quantum cryptography by 2030, with mandatory compliance by 2035. Blockchain data is uniquely vulnerable due to the "Harvest Now, Decrypt Later" threat — the Federal Reserve's 2025 analysis (FEDS 2025-093) specifically examines this risk for distributed ledger networks.

The core problem: an adversary can record today's public blockchain data and derive private keys once cryptographically relevant quantum computers (CRQCs) become available. For Bitcoin, approximately 5.9 million BTC (~25% of supply) sits in quantum-vulnerable address formats, including Satoshi's estimated 968,000 BTC in P2PK addresses with no possibility of migration.

Tidecoin eliminates this entire problem class by using post-quantum signatures from block zero.

## What Post-Quantum Cryptography Does Tidecoin Use?

Tidecoin applies post-quantum cryptography beyond transaction signatures. There is no ECDSA anywhere in the protocol:

| Layer | Algorithm | Standard | Purpose |
|-------|-----------|----------|---------|
| Signatures (active since genesis) | Falcon-512 | NIST-selected; FIPS 206 (FN-DSA) in preparation | Variable-length lattice signatures, at most 666 bytes when signed locally |
| Signatures (post-AuxPoW) | Falcon-1024 | NIST-selected; FIPS 206 (FN-DSA) in preparation | Higher-security Falcon parameter set, at most 1,280 bytes when signed locally |
| Signatures (post-AuxPoW) | ML-DSA-44/65/87 | NIST FIPS 204 | Module-lattice digital signatures, fixed 2,420/3,309/4,627 bytes |
| P2P transport encryption | ML-KEM-512 | NIST FIPS 203 | Post-quantum key encapsulation for opportunistic v2 encryption |
| Witness script hashing (post-AuxPoW) | SHA-512 | NIST FIPS 180-4 | P2WSH-512 witness scripts, 256-bit security under Grover's algorithm |
| Wallet key derivation | PQHD | Tidecoin design | Hardened-only, hash-based HD wallet for PQ schemes |

Falcon-512's security is proven in the Quantum Random Oracle Model under the assumption that the SIS problem over NTRU lattices is hard — a problem studied since 1996 (Hoffstein, Pipher, Silverman) with no known efficient quantum algorithm.

## Design Positioning

Post-quantum blockchain designs generally fall into three groups:

| Approach | Description | Trade-offs |
|----------|-------------|------------|
| Signature-only retrofit | Replace the signing algorithm on an existing chain | Requires coordinated migration; prior transactions remain exposed; political and block-space costs |
| Stateful PQ | Use hash-based signatures such as XMSS or LMS | Conservative assumptions, but key reuse limits and state tracking add operational complexity |
| Full-stack PQ from genesis | Apply PQ design across signing, wallet, transport, and script extensions from launch | No migration debt; smaller network initially |

Tidecoin is a full-stack PQ design on a Bitcoin-architecture chain. Falcon and ML-DSA handle transaction signing, while PQHD wallet derivation, SHA-512 witness extensions, opportunistic ML-KEM-encrypted peer transport, and height-gated consensus upgrades aim to close quantum-era exposure across the transaction lifecycle.

See the [whitepaper design positioning](doc/whitepaper.md#13-design-positioning) for the detailed trade-off analysis.

## Key Features

- **Full-stack post-quantum security** — Signatures, P2P transport, script hashing, and wallet derivation are designed for the quantum era, not only the signing layer.
- **NIST standards and selected schemes** — ML-DSA and ML-KEM are finalized NIST standards (FIPS 204 and FIPS 203). Falcon is a NIST-selected scheme whose FN-DSA standard, FIPS 206, is in preparation; Tidecoin uses the pinned PQClean Falcon implementation of the Round 3 specification.
- **Multi-scheme cryptographic agility** — Five NIST-track signature parameter sets. If a vulnerability is found in one lattice construction, alternative schemes are available through height-gated consensus upgrade.
- **Bitcoin-derived architecture** — Retains the UTXO model and adapts Bitcoin Core's script, networking, and validation architecture, with Tidecoin-specific tests for PQ signatures, PQHD, AuxPoW, and transport code.
- **CPU-friendly mining** — YespowerTIDE is the pre-AuxPoW memory-hard proof-of-work algorithm for fair distribution without specialized hardware.
- **No premine, no ICO** — All coins earned through proof-of-work mining from block zero.
- **Merged mining ready** — AuxPoW infrastructure enables the Phase 2 transition to scrypt-based merged mining with Litecoin.

## What Is Tidecoin's Track Record?

| Metric | Value |
|--------|-------|
| Years of operation | 5+ (since December 2020) |
| Blocks produced | ~2,380,000+ |
| Security incidents | 0 |
| Consensus failures | 0 |

Tidecoin was discussed on the official NIST Post-Quantum Cryptography mailing list (pqc-forum).

## How Do I Build Tidecoin?

Tidecoin uses CMake. See the platform-specific build guides:

| Platform | Guide |
|----------|-------|
| Linux/Unix | [doc/build-unix.md](doc/build-unix.md) |
| macOS | [doc/build-osx.md](doc/build-osx.md) |
| Windows | [doc/build-windows.md](doc/build-windows.md) |
| Windows (MSVC) | [doc/build-windows-msvc.md](doc/build-windows-msvc.md) |
| FreeBSD | [doc/build-freebsd.md](doc/build-freebsd.md) |
| OpenBSD | [doc/build-openbsd.md](doc/build-openbsd.md) |
| NetBSD | [doc/build-netbsd.md](doc/build-netbsd.md) |

### Quick Build (Linux)

```bash
git clone https://github.com/tidecoin/tidecoin.git
cd tidecoin
cmake -B build
cmake --build build
```

### Running

```bash
# Start the Tidecoin daemon
./build/bin/tidecoind

# Start with the GUI (when built with -DBUILD_GUI=ON)
./build/bin/tidecoin-qt

# CLI interface
./build/bin/tidecoin-cli getblockchaininfo
```

These paths assume the default CMake runtime output directory.

## How Do I Run Tests?

```bash
# Unit tests
ctest --test-dir build

# Functional tests
build/test/functional/test_runner.py
```

See [src/test/README.md](src/test/README.md) for unit test details and [test/](test/) for functional and regression tests.

## Development Process

The Tidecoin 1.x codebase was initially based on Bitcoin Core v30 and has since evolved through Tidecoin-specific development and selected updates from later Bitcoin Core development. Tidecoin maintains its own releases, consensus rules, and compatibility requirements.

The `master` branch is regularly built and tested but is not guaranteed to be completely stable. See the build guides above for compilation instructions.

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code and submit new unit tests for old code. There are also [regression and integration tests](test/) written in Python.

Further developer documentation is available in the [doc folder](doc/).

## Frequently Asked Questions

### What makes Tidecoin quantum-resistant?

Tidecoin replaces Bitcoin's ECDSA with Falcon-512, a lattice-based digital signature scheme selected by NIST for post-quantum standardization (FN-DSA/FIPS 206, in preparation). The underlying hard problem — Short Integer Solution (SIS) over NTRU lattices — has no known efficient quantum algorithm. Tidecoin also supports a height-gated upgrade path to Falcon-1024 and the finalized FIPS 204 ML-DSA parameter sets.

### How does Falcon-512 compare to Bitcoin's ECDSA?

Falcon-512 produces variable-length compressed signatures, at most 666 bytes when signed locally and without padding, versus ECDSA's roughly 71-byte DER signatures, but ECDSA is broken by Shor's quantum algorithm once cryptographically relevant quantum computers exist. Falcon-512 is a NIST PQC winner with compact lattice signatures and QROM security under the hardness of SIS over NTRU lattices.

### Can I mine Tidecoin with a CPU?

Yes. Tidecoin uses the YespowerTIDE algorithm, a memory-hard proof-of-work specifically designed for CPU mining. No specialized hardware (ASICs or GPUs) is required, enabling fair distribution.

### Is Falcon the same as NIST's FN-DSA?

FN-DSA is the standard being developed from Falcon (Fast Fourier Lattice-based Compact Signatures over NTRU) as FIPS 206. Tidecoin uses the pinned PQClean implementation of the Round 3 Falcon specification, with Falcon-512 active on mainnet since genesis. Compatibility with the final FN-DSA standard will need a separate evaluation.

### What is PQHD?

PQHD (Post-Quantum Hierarchical Deterministic) is Tidecoin's custom wallet key derivation system. It extends Bitcoin's BIP-32 HD wallet concept to post-quantum signature schemes using hardened-only key derivation with hash-based KDF, ensuring quantum-resistant wallet generation.

### What happens when FIPS 206 is finalized?

FIPS 206 will standardize Falcon under the FN-DSA name. Tidecoin currently uses vendored PQClean Falcon based on the original Round 3 specification; final FIPS 206 details may inform future compatibility or upgrade work.

## Documentation

- [Whitepaper](doc/whitepaper.md) — Tidecoin: A Post-Quantum Secure Peer-to-Peer Cryptocurrency v2.0
- [doc/](doc/) — Developer documentation, build guides, and design notes

## Network

| Resource | Link |
|----------|------|
| Website | https://tidecoin.org |
| Explorer | https://explorer.tidecoin.org |
| Source code | https://github.com/tidecoin/tidecoin |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow. Useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).
Community standards and enforcement are described in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

If you discover a security vulnerability, please report it responsibly. Do **not** open a public issue.

See [SECURITY.md](SECURITY.md) for reporting instructions.

## License

Tidecoin is released under the MIT License. See [COPYING](COPYING) for details.

## References

- NIST FIPS 203: ML-KEM Standard. August 2024. https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204: ML-DSA Standard. August 2024. https://csrc.nist.gov/pubs/fips/204/final
- NIST Post-Quantum Cryptography project: FN-DSA/FIPS 206 (Falcon) standardization in preparation. https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST IR 8547: Transition to Post-Quantum Cryptography Standards. 2024.
- Federal Reserve FEDS 2025-093: Harvest Now Decrypt Later. 2025.
- Shor, P. "Algorithms for Quantum Computation." FOCS 1994.
- Hoffstein, J., Pipher, J., Silverman, J.H. "NTRU: A Ring-Based Public Key Cryptosystem." ANTS-III 1998.
