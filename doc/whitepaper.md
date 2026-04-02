# Tidecoin: A Post-Quantum Secure Peer-to-Peer Cryptocurrency

**Version 2.0 -- February 2026**

---

## Abstract

Tidecoin is a decentralized cryptocurrency engineered from genesis to resist attacks from both classical and quantum computers. Built on Bitcoin Core, it replaces ECDSA with post-quantum signature schemes from the NIST PQC process -- Falcon-512/1024 and ML-DSA-44/65/87 -- while preserving the UTXO model, scripting system, and 15+ years of peer-reviewed consensus logic. Post-quantum design extends beyond signatures to include a hardened-only PQHD wallet, SHA-512 witness scripts, ML-KEM-512 peer-to-peer transport encryption, and a two-phase proof-of-work strategy transitioning from CPU-friendly YespowerTIDE to scrypt-based merged mining with Litecoin. The network has been in continuous operation since December 27, 2020.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [The Quantum Threat to Cryptocurrency](#2-the-quantum-threat-to-cryptocurrency)
3. [Design Philosophy](#3-design-philosophy)
4. [Post-Quantum Signature Schemes](#4-post-quantum-signature-schemes)
5. [PQHD: Post-Quantum Hierarchical Deterministic Wallet](#5-pqhd-post-quantum-hierarchical-deterministic-wallet)
6. [Consensus Mechanism and Proof-of-Work](#6-consensus-mechanism-and-proof-of-work)
7. [Script System Extensions](#7-script-system-extensions)
8. [Post-Quantum Peer-to-Peer Transport](#8-post-quantum-peer-to-peer-transport)
9. [Auxiliary Proof-of-Work (Merged Mining)](#9-auxiliary-proof-of-work-merged-mining)
10. [Economic Model](#10-economic-model)
11. [Network Parameters](#11-network-parameters)
12. [Security Analysis](#12-security-analysis)
13. [Design Positioning](#13-design-positioning)
14. [Conclusion](#14-conclusion)
15. [References](#15-references)

---

## 1. Introduction

The security of nearly every cryptocurrency in existence depends on the assumed hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP). Bitcoin, Ethereum, and the vast majority of blockchain systems use ECDSA or Schnorr signatures over the secp256k1 curve. In 1994, Peter Shor demonstrated a polynomial-time quantum algorithm that solves the discrete logarithm problem, which means a sufficiently powerful quantum computer could derive any ECDSA private key from its corresponding public key.

This is not a speculative concern. The U.S. National Institute of Standards and Technology (NIST) launched a formal Post-Quantum Cryptography (PQC) standardization process in 2016, selected its first winners in 2022, and published final standards (FIPS 203, 204, 205) in August 2024. NIST Interagency Report 8547 recommends that all systems migrate to post-quantum cryptography by 2030, with mandatory compliance by 2035. The U.S. Federal Reserve published a 2025 analysis specifically examining the "Harvest Now, Decrypt Later" threat to distributed ledger networks.

Tidecoin was conceived in direct response to these realities. Its genesis block, mined on December 27, 2020, carries the timestamp message:

> *"spectrum.ieee.org 09/Dec/2020 Photonic Quantum Computer Displays 'Supremacy' Over Supercomputers."*

This references the breakthrough by the University of Science and Technology of China, whose photonic quantum computer Jiuzhang demonstrated quantum computational advantage -- an event that underscored the urgency of quantum-safe cryptography.

Since that genesis block, Tidecoin has produced over 2.3 million blocks across more than five years of continuous operation, with every single transaction secured by post-quantum signatures. No security incident, consensus failure, or cryptographic vulnerability has been reported.

---

## 2. The Quantum Threat to Cryptocurrency

### 2.1 Shor's Algorithm and ECDSA

Shor's algorithm solves the ECDLP in polynomial time on a quantum computer. For the secp256k1 curve used by Bitcoin:

- **Classical best attack:** Requires approximately 2^128 operations (Pollard's rho)
- **Quantum attack:** Requires approximately 2,500 logical qubits, equivalent to roughly 10^5 to 10^6 physical qubits with current error-correction overhead (surface codes)

Current quantum hardware (Google Willow at 105 qubits, IBM Eagle at 127 qubits) is orders of magnitude away from this threshold. However, conservative timelines from NIST and academic research place cryptographically relevant quantum computers (CRQCs) at 10-20 years away, with some optimistic estimates suggesting 5-10 years.

### 2.2 The Harvest Now, Decrypt Later Problem

Blockchain data is uniquely vulnerable because it is public and immutable. An adversary can:

1. Download the entire blockchain today (all transaction data is public)
2. Record every public key exposed in transactions
3. Store this data indefinitely at negligible cost
4. Derive private keys once CRQCs become available

The Federal Reserve's 2025 paper, "Harvest Now Decrypt Later: Examining Post-Quantum Cryptography and the Data Privacy Risks for Distributed Ledger Networks," specifically analyzes this scenario. Their key finding: even after a blockchain migrates to PQC, **previously recorded transaction data remains permanently vulnerable**. The immutability of blockchains -- normally their greatest strength -- becomes their greatest weakness in the quantum context.

For Bitcoin specifically (estimates from Deloitte [44], the Federal Reserve [13], and on-chain analyses [45]):

| Category | BTC Exposed | Risk Level |
|----------|-------------|------------|
| P2PK addresses (public key directly visible) | ~1.7-1.9 million BTC | Immediate on Q-Day |
| Reused addresses (public key exposed after first spend) | ~4 million BTC | Immediate on Q-Day |
| Total quantum-vulnerable | ~5.9 million BTC (~25% of supply) | Critical |

This includes the estimated 968,000 BTC in addresses attributed to Satoshi Nakamoto, all held in P2PK format with no possibility of migration.

### 2.3 Why Migration Is Hard

Bitcoin's BIP-360 (P2QRH) and QBIP proposals for post-quantum migration face severe obstacles:

- **Political inertia:** Bitcoin's conservative governance model requires global consensus. The SegWit activation took approximately two years; Taproot took three. Post-quantum migration is far more complex.
- **Block space pressure:** Post-quantum signatures are 10-100x larger than ECDSA (666 bytes for Falcon-512 vs. 64 bytes for ECDSA). Migration would consume significant block space for potentially years.
- **Unrecoverable funds:** Coins in P2PK addresses (including Satoshi's holdings) cannot migrate because the keys are presumably lost.
- **Timeline mismatch:** The Bitcoin community's estimated migration timeline is 5-10 years. If CRQCs arrive on the optimistic timeline, Bitcoin may not be ready.

Tidecoin eliminates this entire problem class by using post-quantum signatures from block zero.

---

## 3. Design Philosophy

Tidecoin's architecture follows four principles:

### 3.1 NIST Standards, Not Experiments

Every post-quantum cryptographic primitive in Tidecoin is either a finalized NIST standard or a NIST competition winner in active standardization:

- **ML-DSA** (FIPS 204, August 2024) -- Digital signatures
- **ML-KEM** (FIPS 203, August 2024) -- Key encapsulation
- **Falcon** (Draft FIPS 206) -- Digital signatures with compact sizes
- **SHA-512** -- FIPS 180-4 hash function

We deliberately avoided exotic, unvetted algorithms. The NIST PQC competition ran for eight years (2016-2024), with 69 initial submissions narrowed to 4 winners through extensive cryptanalysis by the global academic community.

### 3.2 Bitcoin Heritage, Not Reinvention

Tidecoin is built on Bitcoin Core v30, preserving:

- The UTXO transaction model
- Script-based programmable spending conditions
- The peer-to-peer network protocol
- The validated block relay and mempool architecture
- Extensive unit and functional test coverage across consensus, script validation, wallet, networking, PQ signatures, PQHD, AuxPoW, and transport code.

This is 15+ years of battle-tested, peer-reviewed code. We replaced only what quantum computers break (ECDSA) and extended only what quantum security demands (witness versions, opcodes, HD wallet derivation).

### 3.3 Defense in Depth

Tidecoin applies post-quantum security at every layer:

| Layer | Classical (Bitcoin) | Post-Quantum (Tidecoin) |
|-------|-------------------|------------------------|
| Transaction signing | ECDSA (secp256k1) | Falcon-512/1024, ML-DSA-44/65/87 |
| Witness script hashing | SHA-256 (Category 1) | SHA-512 (Category 5) |
| Peer-to-peer encryption | ECDH (secp256k1) | ML-KEM-512 (FIPS 203) |
| Proof-of-work | SHA-256d (no memory barrier) | YespowerTIDE -> scrypt (memory-hard, merged-mined) |
| HD wallet derivation | BIP32 (ECDSA-based xpub) | PQHD (hardened-only, hash-based) |

### 3.4 Conservative Activation

New signature schemes are activated through height-gated consensus upgrades, not all at once. Falcon-512 has been active since genesis. Additional schemes (Falcon-1024, ML-DSA-44/65/87) activate at a defined consensus height, following the precedent of Bitcoin's SegWit and CSV activations. This approach minimizes risk while providing a clear upgrade path.

---

## 4. Post-Quantum Signature Schemes

### 4.1 Falcon-512 and Falcon-1024

Falcon (**F**ast-Fourier **L**attice-based **C**ompact Signatures **o**ver **N**TRU) is a NIST PQC Round 3 winner, designated for standardization as **FIPS 206 (FN-DSA)**. The draft standard was described as "basically written, awaiting approval" at the 6th PQC Standardization Conference in September 2025.

Falcon-512 has been the active signature scheme on Tidecoin's mainnet since genesis (December 2020), making Tidecoin one of the earliest live blockchains to use this lattice-based signature family later designated for standardization as FN-DSA (Draft FIPS 206).

#### 4.1.1 Mathematical Foundation: NTRU Lattices and the GPV Framework

Falcon combines two fundamental constructions:

**NTRU lattices.** Falcon operates over the cyclotomic polynomial ring R_q = Z_q[x] / (x^n + 1), where n is a power of 2 (512 or 1024) and q = 12,289 is a prime modulus chosen for efficient Number Theoretic Transform (NTT) computation. An NTRU lattice is defined by a public polynomial h in R_q. The public key h hides the factorization h = g * f^(-1) mod q, where f and g are polynomials with small coefficients -- the "short secret basis" of the lattice. The resulting lattice Lambda_h = { (u, v) in R^2 : u + h*v = 0 mod q } has rank 2n in Z^(2n). Because a full basis can be obtained by rotating coefficients of a few initial vectors, the public key compresses to a single polynomial h -- under 897 bytes for Falcon-512, under 1,793 bytes for Falcon-1024.

**GPV hash-then-sign framework.** The Gentry-Peikert-Vaikuntanathan (GPV) framework (STOC 2008) provides a provably secure method for constructing lattice-based hash-and-sign signatures:

1. **Key generation:** Generate a lattice together with a *short basis* B (the trapdoor). Publish a compact representation (the polynomial h) as the public key.
2. **Signing:** Hash the message to a target point c in the lattice's ambient space. Use the short basis B to *sample a short vector* from a discrete Gaussian distribution centered on c. The signature is derived from this short vector.
3. **Verification:** Check that the signature is short enough and that the corresponding point lies on the lattice.

The critical asymmetry: finding a short vector near an arbitrary target is easy with the short basis (trapdoor), but computationally intractable with only the public polynomial h. This is the **Short Integer Solution (SIS) problem** over NTRU lattices, studied since 1996 (Hoffstein, Pipher, Silverman) with no known polynomial-time quantum algorithm. Security is proven in both the Random Oracle Model (ROM) and the Quantum Random Oracle Model (QROM).

#### 4.1.2 Key Generation

1. **Sample short polynomials f, g** from R with small integer coefficients, ensuring f is invertible modulo q.
2. **Compute public key:** h = g * f^(-1) mod q in R_q.
3. **Solve the NTRU equation:** Find additional polynomials F, G satisfying f*G - g*F = q (mod x^n + 1), using the recursive NTRUSolve algorithm with LLL-like size reduction.
4. **Form the secret basis:** B = [[g, -f], [G, -F]] -- a 2x2 matrix of polynomials that, interpreted as a 2n x 2n integer matrix, forms a short basis for the NTRU lattice with determinant q.

Key generation uses less than 30 KB of RAM -- a hundredfold improvement over earlier NTRU signature designs.

#### 4.1.3 Signing: Fast Fourier Sampling

Signing a message m with Falcon proceeds through:

1. **Salt generation:** A random 40-byte nonce r is generated, ensuring that signing the same message twice produces different signatures.
2. **Hash-to-point:** c = SHAKE-256(r || m) is expanded into a polynomial in R_q -- the target point that the signer must approach with a short lattice vector.
3. **Fast Fourier Sampling (ffSampling):** This is the core of Falcon and its most security-critical component. Using the secret basis B, the signer samples a short vector (s1, s2) such that s1 + h * s2 = c mod q:
   - The Gram-Schmidt orthogonalization of B is precomputed as a binary "Falcon tree" in the FFT (splitting) domain.
   - ffSampling recursively splits the problem into sub-problems of half dimension at each level, exploiting the algebraic structure of x^n + 1.
   - At each leaf, a single integer is sampled from a **discrete Gaussian distribution** D_{Z, sigma, center} with standard deviation sigma = 165.74 (Falcon-512) or sigma = 168.39 (Falcon-1024).
   - This achieves O(n log n) complexity versus the generic GPV sampler's O(n^2).
4. **Signature encoding:** The signature (r, s2) is output in compressed format.

**Why the Gaussian sampler is security-critical:** If the sampler deviates from a true discrete Gaussian distribution, signatures carry a statistical bias correlated with the secret basis B. Over many signatures, an attacker can exploit this bias for key recovery. A theoretically perfect Gaussian sampler leaks less than 2^(-64) bits per signature, allowing safely more than 2^64 signatures per key. The sampler requires high-precision floating-point arithmetic (53-bit IEEE-754 binary64), creating both implementation and side-channel challenges addressed below.

#### 4.1.4 Verification

Verification is remarkably simple and fast:

1. Recompute c = SHAKE-256(r || m) (the hash-to-point target).
2. Recover s1 = c - s2 * h mod q (one polynomial multiplication and subtraction).
3. Accept if ||(s1, s2)||^2 <= bound (a norm check against a precomputed threshold).

Verification uses only **integer arithmetic** -- no floating-point, no Gaussian sampling, no secret key involvement. On typical hardware, Falcon-512 verification achieves ~28,000 verifications/second, approximately 5-10x faster than signing.

#### 4.1.5 NIST PQC Security Categories

NIST defines five security categories for post-quantum schemes, each referenced against a specific classical primitive under quantum attack:

| Category | Reference Problem | Approximate Quantum Security |
|----------|------------------|------------------------------|
| 1 | AES-128 key search (Grover) | 2^128 gate operations |
| 2 | SHA-256 collision (BHT/Grover) | 2^128 gate operations (different cost model) |
| 3 | AES-192 key search (Grover) | 2^192 gate operations |
| 5 | AES-256 key search (Grover) | 2^256 gate operations |

Odd categories (1, 3, 5) measure resistance to block cipher key search. Even categories (2) measure resistance to hash collision finding. Categories 1 and 2 both provide roughly 128-bit quantum security but against different attack models. NIST does not use Category 4 for PQC selections.

#### 4.1.6 Size Comparison

| Parameter | Falcon-512 | Falcon-1024 | ML-DSA-44 | ML-DSA-65 |
|-----------|-----------|-------------|-----------|-----------|
| NIST Security Category | 1 | 5 | 2 | 3 |
| Public Key | 897 bytes | 1,793 bytes | 1,312 bytes | 1,952 bytes |
| Signature (padded) | 666 bytes | 1,280 bytes | 2,420 bytes | 3,309 bytes |
| **PK + Sig** | **~1,563 bytes** | **~3,073 bytes** | **3,732 bytes** | **5,261 bytes** |
| Verification speed | ~28,000 ver/s | ~13,700 ver/s | Fast | Fast |

Falcon's combined public key + signature size is the **smallest of any NIST PQC lattice signature**, which is decisive for bandwidth-constrained blockchain transactions.

#### 4.1.7 Signature Formats: Compressed vs. Padded

The Falcon specification defines multiple signature encoding formats:

- **Compressed (format code 1):** Variable-length signatures using Golomb-Rice-like compression. Falcon-512: average ~652 bytes, maximum 752 bytes. This is the most bandwidth-efficient encoding.
- **Padded (format code 2):** Fixed-length signatures (666 bytes for Falcon-512, 1,280 bytes for Falcon-1024). If a compressed signature exceeds the target size, signing restarts. Fixed size simplifies protocol design and prevents information leakage through signature length variation.
- **Constant-time (CT, format code 3):** Fixed-length with constant-time encoding/decoding (809 bytes for Falcon-512). Each coefficient is encoded over a fixed number of bits, eliminating timing side-channels during encoding. Rarely needed but available for high-sensitivity scenarios.

FIPS 206 will include both padded and compressed formats with domain separation to maintain strong unforgeability when multiple encodings coexist.

#### 4.1.8 Integer Emulation: Eliminating Floating-Point Side Channels

The discrete Gaussian sampler at the heart of Falcon signing requires high-precision floating-point arithmetic for its FFT computations. Native hardware FPU operations are fast but vulnerable to **electromagnetic emanation**, **power analysis**, and **timing side-channels** -- demonstrated by the FALCON DOWN attack (2021, ePrint 2021/772) which achieved full key recovery through electromagnetic measurements of FFT multiplications, and the SHIFT SNARE attack (2025) which achieved 100% key recovery from a single power trace on ARM Cortex-M4.

Tidecoin's implementation uses the **PQClean "clean" constant-time implementation** by Thomas Pornin, which employs **integer emulation** (FALCON_FPEMU) rather than native floating-point:

- **All floating-point arithmetic is emulated using `uint64_t` integer operations.** The C `double` type is never used. Instead, IEEE-754 binary64 format is represented as a 64-bit unsigned integer (bit 63: sign, bits 52-62: exponent, bits 51-0: mantissa), with all arithmetic (addition, subtraction, multiplication, division, square root, rounding) implemented as sequences of integer operations.
- **Constant-time shifts:** Custom functions `fpr_ursh()`, `fpr_irsh()`, and `fpr_ulsh()` handle 64-bit shifts with "possibly secret shift count" using barrel-shifter emulation through XOR masking, avoiding variable-time software shift routines.
- **No branching on secrets:** Table lookups read all elements (no early exit), and value tests use constant-time bitwise operations.
- **Fully portable:** Works on any platform with a C99-compliant compiler -- no FPU required. Successfully tested on 32-bit and 64-bit systems, both little-endian (x86, ARM) and big-endian (PowerPC).

The integer emulation approach makes signing approximately 20x slower than native floating-point with AVX2, but this tradeoff is accepted for **provable constant-time behavior** -- the critical security property for a cryptocurrency where keys protect real value. The formal correctness of Falcon's emulated floating-point has been verified (ePrint 2024/321).

#### 4.1.9 Tidecoin's Legacy vs. Strict Signature Modes

Tidecoin's Falcon-512 implementation supports two verification modes:

- **Legacy mode** (active since genesis): Uses the original Falcon signature format with a relaxed norm bound derived from the pre-2019-fix acceptance threshold (`floor((7085 * 12289) >> (10 - logn))`). This preserves backward compatibility with all signatures created since genesis block zero. The legacy format uses header byte `0x39` (0x30 + 9 for degree-9 = 512).

- **Strict mode** (activated with AuxPoW): Uses the standard PQClean `crypto_sign_verify()` with the tighter acceptance bound. New signatures after activation use the standard format with improved security margins.

**Keys remain identical in both modes.** The public key format (polynomial h encoded as 14 bits per coefficient with header byte `0x09`) and private key format (f, g, F polynomials with header byte `0x59`) are unchanged. Only signature *creation* and *verification bounds* differ. This means existing wallets require no key migration -- the same keys simply produce and verify tighter signatures after AuxPoW activation.

#### 4.1.10 From Falcon to FN-DSA (FIPS 206): What Changes

FIPS 206 standardizes Falcon under the name **FN-DSA** (FFT over NTRU-Lattice-Based Digital Signature Algorithm). Key changes from the original Falcon specification:

1. **BUFF security via public key hashing:** FN-DSA computes hm = SHAKE-256(nonce || hpk || 0x00 || len(ctx) || ctx || message), where hpk is a 64-byte hash of the public key. This achieves Beyond UnForgeability Features (BUFF) security at zero size cost -- no change to public key or signature sizes (ePrint 2024/710).

2. **Context string support:** A `ctx` parameter enables domain separation between different applications using the same key pair.

3. **Nonce regeneration on restart:** When the signing loop restarts (signature too large or vector not short enough), FN-DSA generates a new nonce each time, eliminating a subtle information leakage present in original Falcon where the same nonce was reused.

4. **Fixed-point NTRUSolve:** Key generation replaces the `Reduce()` algorithm with an approach from the Hawk scheme, avoiding floating-point arithmetic in keygen (signing still requires emulated floating-point).

5. **Pre-hashing support:** FN-DSA supports pre-hashed messages with collision-resistant hash functions.

**Key compatibility:** Public key encoding remains unchanged between original Falcon and FN-DSA (same polynomial h, same sizes). However, FN-DSA signatures are **not backward-compatible** with original Falcon signatures because the hash input changed (includes hpk and context). Tidecoin's transition plan: existing keys work in both modes; the legacy verification path accepts pre-activation signatures, while post-activation signatures will use the stricter format that aligns with FN-DSA's direction.

#### 4.1.11 The 2019 Sampler Bug and PQClean Security History

In August 2019, Thomas Pornin published a new constant-time Falcon implementation. Shortly after, **Markku-Juhani O. Saarinen** discovered two severe bugs in the Gaussian sampler:

1. **Incorrect lookup table:** The implementation used probability distribution (PD) values instead of the correct reverse cumulative distribution (RCD) values.
2. **Wrong rejection sampling probability:** A scaling factor was applied at the wrong place, causing the sampler to reject too infrequently.

**Consequences:** Produced signatures were technically valid but **leaked information about the private key**. Performance was artificially inflated (signing was ~17% too fast), and signatures were slightly shorter than correct (~651 vs ~657 bytes average for Falcon-512). A 2025 retrospective analysis (ACM CCS 2025, "How Bad Was The Falcon Bug of 2019?") demonstrated that improved attack techniques combined with PCA methodology could achieve **full key recovery from approximately 50 million buggy signatures**.

Thomas Pornin published the fix on September 18, 2019. PQClean integrated the corrected code via PR #210; the project's security notes confirm that "all Falcon implementations before PR #235 got merged were insecure."

**Tidecoin's timeline:** Tidecoin's genesis block was mined on December 27, 2020 -- **over 15 months after the sampler bug was fixed.** Tidecoin has always used the post-fix PQClean implementation with the correct RCD table and proper rejection sampling. No Tidecoin signature was ever produced by the vulnerable code.

Additionally, the PQClean "clean" implementation used by Tidecoin specifically avoids the aarch64 `fmla` (fused multiply-add) precision issue documented in PQClean Issue #522 (November 2023), because the clean variant uses integer emulation rather than native floating-point instructions.

### 4.2 ML-DSA-44, ML-DSA-65, and ML-DSA-87

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is standardized as **FIPS 204**, finalized August 13, 2024. Formerly known as CRYSTALS-Dilithium, ML-DSA is NIST's **recommended default** for general-purpose post-quantum digital signatures. Tidecoin supports all three ML-DSA security levels, activated via consensus upgrade at AuxPoW height.

#### 4.2.1 Mathematical Foundation: Module-LWE and Module-SIS

ML-DSA is built on two hard problems over **module lattices**:

- **Module-LWE (Module Learning With Errors):** Given a random matrix **A** and a vector **t** = **A** * **s** + **e** (where **s** and **e** have small coefficients), it is computationally infeasible to recover **s**. This underpins the hiding of the secret key within the public key.
- **Module-SIS (Module Short Integer Solution):** Given a random matrix **A**, it is hard to find a short vector **z** such that **A** * **z** = **0** (or some target). This underpins the unforgeability of signatures.

Both problems operate over the polynomial ring R_q = Z_q[x] / (x^256 + 1), where:
- n = 256 (polynomial degree, fixed for all ML-DSA parameter sets)
- q = 8,380,417 = 2^23 - 2^13 + 1 (a prime chosen to enable efficient NTT; it is congruent to 1 mod 512, admitting a primitive 512th root of unity r = 1753)

Module lattices generalize both standard (unstructured) lattices and ideal lattices (Ring-LWE/Ring-SIS). The "module" structure uses vectors of ring elements parameterized by dimensions (k, l) -- the rows and columns of matrix **A**. This interpolation provides more conservative security assumptions than Ring-LWE (the algebraic structure gives attackers less to exploit) while remaining more efficient than plain LWE (which would require enormous matrices). The worst-case to average-case reductions for Module-LWE/SIS were established by Langlois and Stehle (2015).

#### 4.2.2 Key Generation

1. Sample a random seed rho and expand it to generate the public matrix **A** in R_q^{k x l} using SHAKE-128/SHAKE-256. Only the seed needs storage -- **A** is derived deterministically.
2. Sample secret vectors **s_1** in R_q^l and **s_2** in R_q^k, with each polynomial coefficient drawn uniformly from [-eta, +eta] (eta = 2 or 4 depending on security level).
3. Compute **t** = **A** * **s_1** + **s_2** mod q -- the Module-LWE instance.
4. Split **t** into high-order bits **t_1** and low-order bits **t_0** by dropping the d=13 least significant bits from each coefficient.
5. Compute tr = H(rho || **t_1**) -- a 64-byte hash of the public key (increased from 32 bytes in the original Dilithium).
6. **Public key:** pk = (rho, **t_1**). **Secret key:** sk = (rho, K, tr, **s_1**, **s_2**, **t_0**).

#### 4.2.3 Signing: Fiat-Shamir with Aborts

ML-DSA signing implements **Lyubashevsky's Fiat-Shamir with Aborts** paradigm (ASIACRYPT 2009). This converts an interactive zero-knowledge identification protocol into a non-interactive signature scheme, with the critical addition of **rejection sampling** (the "aborts"):

1. **Masking (Commitment):** Sample a random masking vector **y** with coefficients uniformly from [-gamma_1 + 1, gamma_1]. gamma_1 is large enough to hide the secret key.
2. **Compute commitment:** **w** = **A** * **y** mod q. Extract high-order bits **w_1** = HighBits(**w**).
3. **Challenge:** Compute c_tilde = SHAKE-256(tr || M || **w_1**). Derive a sparse ternary challenge polynomial c with exactly tau coefficients equal to +/-1 and all others zero.
4. **Response:** Compute **z** = **y** + c * **s_1**.
5. **Rejection tests (the "abort" conditions):** Check that ||**z**||_inf < gamma_1 - beta (ensures **z** does not leak information about **s_1**); check low-order bits of **A** * **z** - c * **t**; check that the hint vector **h** has at most omega nonzero entries. **If any test fails, restart from step 1.**
6. **Output:** sigma = (c_tilde, **z**, **h**).

The rejection sampling is the key innovation: without it, **z** = **y** + c * **s_1** would carry a statistical bias revealing the secret key **s_1** through the distribution of **z**. By aborting when **z** falls too close to the boundary, the algorithm ensures that the distribution of valid signatures is **statistically independent of the secret key**. The expected number of iterations per signature is approximately 4.25 (ML-DSA-44), 5.1 (ML-DSA-65), or 3.85 (ML-DSA-87).

**Hedged vs. deterministic signing (FIPS 204 addition):** In the default "hedged" mode, the masking vector **y** incorporates both fresh randomness (from an RNG) and precomputed secret randomness from the private key. This provides defense-in-depth against faulty RNGs, side-channel attacks, and fault attacks simultaneously. In deterministic mode, only secret key material is used. Both modes produce interoperable signatures verified by the same algorithm.

#### 4.2.4 Verification

Verification is single-pass with no retry loop:

1. Parse sigma = (c_tilde, **z**, **h**) and pk = (rho, **t_1**).
2. Reconstruct **A** from rho. Recover challenge polynomial c from c_tilde.
3. Compute **w'_1** = UseHint(**h**, **A** * **z** - c * **t_1** * 2^d) to recover the high-order bits.
4. Recompute c_tilde' = SHAKE-256(tr || M || **w'_1**).
5. Accept if c_tilde' == c_tilde and ||**z**||_inf < gamma_1 - beta and the hint **h** has at most omega nonzero entries.

**Why this works:** By the key relation **t** = **A** * **s_1** + **s_2**, the expression **A** * **z** - c * **t** simplifies to **A** * **y** - c * **s_2**, recovering the original commitment shifted by a small error. The high-order bits match when the rejection conditions were satisfied, allowing the verifier to reconstruct the same challenge. Verification is significantly faster than signing -- a single matrix-vector multiplication, one polynomial multiplication, hashing, and norm checks.

#### 4.2.5 Parameters and Sizes

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| **NIST Security Category** | **2** | **3** | **5** |
| (k, l) matrix dimensions | (4, 4) | (6, 5) | (8, 7) |
| eta (secret key coefficient range) | 2 | 4 | 2 |
| tau (nonzero coefficients in challenge) | 39 | 49 | 60 |
| gamma_1 (masking range) | 2^17 | 2^19 | 2^19 |
| Expected signing iterations | ~4.25 | ~5.1 | ~3.85 |
| **Public Key** | **1,312 bytes** | **1,952 bytes** | **2,592 bytes** |
| **Secret Key** | **2,560 bytes** | **4,032 bytes** | **4,896 bytes** |
| **Signature** | **2,420 bytes** | **3,309 bytes** | **4,627 bytes** |

(Source: FIPS 204 Table 1)

#### 4.2.6 Advantages Over Falcon

ML-DSA complements Falcon with several distinct advantages:

- **No floating-point arithmetic at all:** All operations are integer-based (modular arithmetic, NTT butterfly operations, comparisons). No FPU, no emulation, no floating-point side channels. This makes constant-time implementation straightforward and eliminates the entire vulnerability class that affects Falcon's sampler.
- **No Gaussian sampling:** ML-DSA uses only uniform sampling from bounded integer ranges. Gaussian sampling is difficult to implement in constant time and has been the source of numerous side-channel attacks on other lattice schemes.
- **Simpler implementation:** The core operations are SHAKE hashing, NTT-based polynomial multiplication, and coefficient-wise arithmetic with norm checks. No complex number-theoretic operations like FFT tree construction.
- **Hedged signing by default:** FIPS 204 mixes fresh randomness with secret key material, providing simultaneous defense against faulty RNGs, side channels, and fault injection.
- **Already finalized:** FIPS 204 was published August 13, 2024 and is effective immediately. Falcon's FIPS 206 remains in draft with projected finalization in 2026-2027.
- **Strong unforgeability (SUF-CMA):** An adversary cannot produce a new valid signature even for a message that has already been signed.

The tradeoff: ML-DSA signatures (2,420-4,627 bytes) are roughly 3.6x larger than the corresponding Falcon signatures (666-1,280 bytes). In blockchain contexts where bandwidth is constrained, Falcon's compactness remains valuable -- which is why Tidecoin supports both families, allowing users to choose the appropriate tradeoff.

#### 4.2.7 From CRYSTALS-Dilithium to ML-DSA (FIPS 204)

The standard is based on Dilithium specification version 3.1, with changes made by NIST:

- **Renaming:** CRYSTALS-Dilithium -> ML-DSA; parameter sets Dilithium2/3/5 -> ML-DSA-44/65/87.
- **Hedged signing as default:** Original Dilithium was fully deterministic. FIPS 204 changed the default to hedged.
- **Increased tr size:** Public key hash increased from 32 to 64 bytes for stronger binding.
- **Context string support:** Optional domain separation for different applications using the same key.
- **Pre-hash API:** HashML-DSA variant for compatibility with existing protocols.
- **No substantive algorithmic changes:** The underlying mathematics, parameter choices, and security levels remained the same.

### 4.3 Scheme Registry and Consensus Integration

All five signature schemes are registered in a compile-time scheme registry. Each scheme has:

- A unique one-byte prefix (0x07-0x0B) prepended to serialized public keys
- Fixed metadata: public key size, secret key size, maximum and fixed signature sizes
- A human-readable name

The verification path through consensus code is:

```
EvalScript() -> EvalChecksig() -> CheckPostQuantumSignature()
  -> VerifyPostQuantumSignature() -> CPubKey::Verify() -> pq::VerifyPrefixed()
```

Three consensus script verification flags control PQ behavior:

- `SCRIPT_VERIFY_PQ_STRICT` (bit 13): Reject legacy signature formats
- `SCRIPT_VERIFY_WITNESS_V1_512` (bit 14): Enable 64-byte witness v1 scripthash
- `SCRIPT_VERIFY_SHA512` (bit 15): Enable OP_SHA512 opcode

---

## 5. PQHD: Post-Quantum Hierarchical Deterministic Wallet

### 5.1 The BIP32 Problem

Bitcoin's BIP32 HD wallet standard relies on elliptic curve arithmetic for key derivation. The extended public key (xpub) mechanism enables watch-only wallets and gap-limit-free address generation by deriving child public keys from a parent public key without the private key.

In a quantum setting, this is catastrophic: Shor's algorithm can derive the private key from any public key, meaning an exposed xpub is equivalent to an exposed xpriv. Furthermore, no NIST post-quantum signature scheme supports the homomorphic public key derivation that BIP32's non-hardened derivation requires.

### 5.2 PQHD Design

Tidecoin implements a custom Post-Quantum Hierarchical Deterministic wallet (PQHD) that replaces BIP32 entirely. The design uses hardened-only derivation with hash-based key material generation.

**Path structure:**

```
m / purpose' / coin_type' / scheme' / account' / change' / index'
```

All path elements are hardened (high bit set), with fixed values:
- `purpose'` = 10007' (Tidecoin PQHD purpose)
- `coin_type'` = 6868' (Tidecoin coin type)
- `scheme'` = PQ scheme identifier
- `account'`, `change'`, `index'` = User-controlled derivation

### 5.3 Key Derivation

The derivation chain from master seed to leaf key is:

1. **Seed ID computation:** `SeedID = SHA-256("Tidecoin PQHD seedid v1" || master_seed)` -- domain-separated identifier
2. **Master node derivation:** HMAC-SHA-512 based master node creation from 32-byte master seed
3. **Hardened child derivation (CKD):** HMAC-SHA-512 chained derivation using parent secret material
4. **Leaf material extraction:** HKDF-based stream key derivation with scheme-specific domain separation
5. **Deterministic key generation:** Scheme-specific conversion of leaf material to PQ keypair:
   - Falcon: Uses first 48 bytes as deterministic seed
   - ML-DSA: Uses first 32 bytes as deterministic seed

**Memory safety:** All secret material is cleansed via `memory_cleanse()` after use. RAII destructors ensure cleanup even on early returns. Secure allocators are used for private key storage.

### 5.4 Wallet Integration

PQHD is fully integrated with Bitcoin Core's descriptor wallet framework:

- **Descriptor format:** `wpkh(pqhd(SEEDID)/purpose'/cointype'/scheme'/account'/change'/index')`
- **PSBT support:** Proprietary fields (identifier: "tidecoin", subtype 0x01) carry PQHD origin metadata for offline signers
- **Encrypted storage:** Seeds are encrypted with the wallet master key; decryption occurs only when spending
- **Policy management:** The `setpqhdpolicy` RPC command allows setting default receive and change signature schemes

---

## 6. Consensus Mechanism and Proof-of-Work

Tidecoin employs a **two-phase proof-of-work strategy** designed to maximize both fairness during early distribution and long-term network security against quantum adversaries.

### 6.1 Phase 1: YespowerTIDE (Pre-AuxPoW -- CPU Mining)

During its initial phase, Tidecoin uses **YespowerTIDE**, a memory-hard proof-of-work algorithm from the yespower/yescrypt family designed by Solar Designer (Alexander Peslyak) of the Openwall Project. Yespower is a PoW-focused fork of yescrypt, which itself builds on Colin Percival's scrypt.

**Properties:**
- **Memory-hard:** Requires 1-16 MB of RAM per hash evaluation
- **CPU-friendly:** Optimized for general-purpose CPU L2 cache access patterns, promoting mining decentralization
- **GPU-unfriendly:** Memory access patterns map poorly to GPU architectures, preventing GPU mining farms from dominating
- **ASIC-neutral:** While dedicated hardware can eventually be built, the advantage over CPUs is far smaller than Bitcoin's SHA-256d, where ASICs outperform CPUs by factors of 10^6+

**Purpose of Phase 1:** YespowerTIDE ensures fair initial coin distribution. Anyone with a standard CPU -- including mobile devices -- can participate in mining. This prevents the concentration of supply in the hands of ASIC or GPU farm operators during the critical early years when the coin supply is being distributed.

### 6.2 Phase 2: Scrypt via Merged Mining with Litecoin (Post-AuxPoW Activation)

Upon AuxPoW activation, Tidecoin transitions from standalone YespowerTIDE mining to **scrypt-based merged mining with Litecoin**. This is a deliberate security architecture decision. The AuxPoW activation simultaneously enables:

1. **Scrypt proof-of-work** via Litecoin's parent chain
2. **Multi-scheme signature support** (Falcon-1024, ML-DSA-44/65/87 join Falcon-512)
3. **Witness version 1** with SHA-512-based 64-byte script hashing
4. **OP_SHA512** opcode activation
5. **Strict PQ signature validation** (rejecting legacy formats)

This bundled activation ensures that the network's most significant post-quantum upgrades deploy together in a single, well-tested consensus transition.

### 6.3 Why Scrypt: Deep Dive into Memory-Hard Quantum Resistance

The choice of scrypt as the long-term PoW algorithm is motivated by its **provable, quantifiable resistance to quantum attack** -- a property that Bitcoin's SHA-256d fundamentally lacks.

#### 6.3.1 How Scrypt Works Internally

Scrypt (RFC 7914), created by Colin Percival in 2009, is a password-based key derivation function turned proof-of-work. For Litecoin's parameters (N=1024, r=1, p=1), each hash evaluation proceeds in three stages:

**Stage 1 -- Key Expansion (PBKDF2-SHA-256):**
The 80-byte block header is expanded to 128 bytes via PBKDF2-HMAC-SHA-256.

**Stage 2 -- ROMix (the memory-hard core):**
This is where scrypt's security originates. ROMix operates in two phases:

*Phase A -- Scratchpad Construction (sequential writes):*
```
X = B  (128-byte initial block)
for i = 0 to N-1:           // N = 1024 iterations
    V[i] = X                 // Store current state in scratchpad
    X = BlockMix(X)          // Advance state via Salsa20/8
```
This builds an array V of 1,024 entries, each 128 bytes, totaling **128 KB** of pseudorandom data.

*Phase B -- Memory-Dependent Mixing (data-dependent random reads):*
```
for i = 0 to N-1:           // N = 1024 iterations
    j = Integerify(X) mod N  // Index derived FROM current state
    T = X XOR V[j]           // Fetch V[j] and XOR with state
    X = BlockMix(T)          // Mix the result via Salsa20/8
```
The function `Integerify(X)` reads the last 64 bytes of the current state X and interprets them as a little-endian integer, then takes `mod N` to produce the scratchpad index j. **Each memory address depends on the result of the previous computation.** There is no way to predict which V[j] will be read next without actually performing the preceding BlockMix and XOR.

**Stage 3 -- Final Compression (PBKDF2-SHA-256):**
The mixed state is compressed back to a 32-byte hash via PBKDF2.

**Per-hash computation summary:**
- 2 x N = 2,048 BlockMix calls (each containing 2 Salsa20/8 evaluations) = **4,096 Salsa20/8 invocations**
- **1,024 sequential data-dependent memory reads** from the 128 KB scratchpad
- Each memory read address depends on the result of all previous reads

#### 6.3.2 Why Data-Dependent Access Prevents Parallelization

The sequential dependency chain j_0 -> j_1 -> ... -> j_1023 has depth exactly N = 1,024. No amount of parallel hardware -- classical or quantum -- can reduce this depth because:

1. Computing j_k requires the output of iteration k-1
2. Iteration k-1 requires reading V[j_{k-1}] from memory
3. j_{k-1} is unknown until iteration k-2 completes
4. Memory read latency is irreducible

This creates a chain of 1,024 sequential memory reads where each address is a pseudorandom function of the entire computation history.

#### 6.3.3 Grover's Algorithm vs. SHA-256d (Bitcoin)

For Bitcoin's SHA-256d PoW, each Grover oracle call is computationally straightforward. The quantum circuit for SHA-256 requires:

- **~2,402-6,063 logical qubits** for the oracle circuit (Amy et al., 2016; ePrint 2016/992)
- **~16,000-109,000 T-depth** per oracle evaluation (Lee et al., 2023)
- **Zero memory (QRAM)** -- SHA-256 is a stateless function
- Grover provides a clean **quadratic speedup**: 2^256 classical -> 2^128 quantum oracle calls

With surface code error correction at ~1,000 physical qubits per logical qubit, the full SHA-256 Grover attack requires approximately **2.4-10 million physical qubits** -- enormous by today's standards, but involving no fundamental architectural barriers beyond scale.

#### 6.3.4 Grover's Algorithm vs. Scrypt (Litecoin / Tidecoin post-AuxPoW)

For scrypt, the quantum oracle must implement the **entire memory-hard function** in quantum superposition. This creates three compounding barriers:

**Barrier 1 -- The QRAM Requirement:**

The 128 KB scratchpad must exist in quantum superposition. When Grover evaluates scrypt on a superposition of inputs |x_1> + |x_2> + ... + |x_M>, each input produces a *different* scratchpad. The quantum circuit must maintain all scratchpad states simultaneously.

QRAM requirements for 128 KB (bucket-brigade architecture):

| Component | Logical Qubits |
|-----------|---------------|
| Data qubits (128 KB = 1,048,576 bits) | **~1,048,576** |
| Routing qubits (bucket-brigade) | **~131,072** |
| Address qubits | ~17 |
| Ancilla per query (O(N)) | **~131,072** |
| **QRAM subtotal** | **~1.2 million logical qubits** |

With surface code error correction (~1,000:1 ratio), the QRAM alone requires approximately **1.2 billion physical qubits** -- before accounting for the computational qubits needed for SHA-256 and Salsa20/8 sub-circuits.

For comparison, Google's Willow chip (2024) has 105 physical qubits. IBM's largest announced roadmap target is ~100,000 qubits by 2033. The QRAM requirement for scrypt exceeds projected quantum hardware by **four orders of magnitude**.

**Barrier 2 -- The Sequential Depth Barrier:**

Each of the 1,024 data-dependent memory lookups must be performed as a sequential QRAM query. After each lookup, the scratchpad state becomes **entangled** with the computation state. The memory read at step k depends on data read at step k-1, forming an irreducible sequential chain.

Furthermore, because quantum computation must be **reversible** (unitary), intermediate scratchpad states cannot be discarded -- they must be properly uncomputed through the reverse sequence of memory lookups. This effectively doubles the sequential depth.

**Barrier 3 -- The Cumulative Memory Complexity (CMC) Barrier:**

Alwen, Chen, Pietrzak, Reyzin, and Tessaro proved at EUROCRYPT 2017 (Best Paper Award) that scrypt is **maximally memory-hard**: its cumulative memory complexity is Omega(n^2 * w), where n is the number of hash invocations and w is the output length. This is tight -- no algorithm, no matter how clever with time-memory tradeoffs, can compute scrypt with lower total memory-time cost.

This result extends to quantum computation. Blocki, Holman, and Lee (2022) introduced the **parallel reversible pebbling game** to formally analyze post-quantum security of memory-hard functions. The reversibility constraint of quantum circuits means that intermediate values cannot be freely discarded, adding additional overhead beyond the classical CMC bound.

**Time-memory tradeoffs don't help:**

An attacker can reduce QRAM by storing only every k-th scratchpad entry and recomputing missing entries on demand:
- Memory reduces by factor k
- Time (circuit depth) increases by factor k
- The time-memory product remains constant: Omega(n^2 * w)

Even with aggressive tradeoffs, the quantum attacker needs at minimum Omega(sqrt(N) * 128r) bytes of QRAM, with circuit depth Omega(sqrt(N)) per oracle call.

#### 6.3.5 Quantitative Comparison: SHA-256d vs. Scrypt Under Quantum Attack

| Parameter | SHA-256d (Bitcoin) | Scrypt N=1024,r=1,p=1 (Tidecoin) | Overhead Factor |
|-----------|-------------------|-----------------------------------|-----------------|
| Oracle logical qubits | ~2,402-6,063 | ~1,200,000+ (incl. QRAM) | **~200x** |
| Oracle physical qubits (surface code) | ~2.4M-10M | **~1.2 billion+** | **~200x** |
| QRAM requirement | **None** | 128 KB in superposition | Infinite (new resource) |
| Sequential oracle depth | 1 SHA-256d call (~16K T-depth) | 2,048 BlockMix + 1,024 QRAM queries (~100M+ T-depth) | **~2,000x** |
| Hash sub-calls per oracle | 2 (double SHA-256) | ~4,096 (Salsa20/8) + PBKDF2 | **~2,000x** |
| Grover iterations needed | 2^128 (for 256-bit preimage) | 2^128 (same search space) | 1x |
| Effective quantum speedup | Full quadratic (sqrt) | **Substantially subquadratic** | Degraded |
| Estimated total attack cost | ~2^166 logical-qubit-cycles | **>> 2^180 logical-qubit-cycles** | **> 16,000x** |
| Nearest feasibility | Decades away | **Further decades beyond SHA-256** | -- |

**The key insight:** Bitcoin's SHA-256d requires zero QRAM -- the quantum oracle is a pure computation circuit. Scrypt requires a **128 KB QRAM operating in quantum superposition** -- an entirely new hardware resource that does not exist, cannot be simulated classically, and faces fundamental physical scaling challenges. This is not a difference of degree; it is a difference of kind.

#### 6.3.6 Fault-Tolerant QRAM: The Hidden Problem

A critical finding in the QRAM literature: under fault-tolerant operation (required for any useful quantum computation), the bucket-brigade QRAM **loses its theoretical efficiency advantage**. In the noiseless model, bucket-brigade QRAM has only O(log N) "active" gates per query. But under fault-tolerant operation, **all** O(N) components must be actively error-corrected, making the gate cost per QRAM query at least O(N). This means each of the 1,024 QRAM queries in scrypt's Phase B costs at least O(131,072) fault-tolerant gates -- a devastating overhead multiplier.

### 6.4 Difficulty Adjustment

**Pre-AuxPoW (legacy retarget):** Tidecoin uses a Bitcoin-style periodic difficulty retarget. Difficulty is recalculated every 7,200 blocks (~5 days at 60-second targets), comparing actual elapsed time against the 5-day target timespan and clamping the adjustment to prevent large swings.

**Post-AuxPoW (averaging-window retarget):** Upon AuxPoW activation, Tidecoin switches to a Zcash-derived averaging-window algorithm that adjusts difficulty every block using median time past (MTP), resisting time-warp attacks.

| Parameter | Pre-AuxPoW | Post-AuxPoW |
|-----------|------------|-------------|
| Target block time | 60 seconds | 60 seconds |
| Retarget interval | Every 7,200 blocks (~5 days) | Every block |
| Method | Periodic (Bitcoin-style) | Averaging window (Zcash-derived, MTP) |
| Averaging window | N/A | 17 blocks |
| Max adjustment down | Per-period clamp | 32% |
| Max adjustment up | Per-period clamp | 16% |
| Min difficulty blocks | Disabled on mainnet | Disabled on mainnet |

---

## 7. Script System Extensions

### 7.1 OP_SHA512

Tidecoin introduces `OP_SHA512` (opcode 0xb3), which computes the SHA-512 hash of the top stack element.

**Post-quantum justification:** Under Grover's algorithm:

| Hash Function | Classical Preimage Security | Post-Quantum Preimage Security (Grover) |
|--------------|---------------------------|---------------------------------------|
| SHA-256 | 256 bits | 128 bits |
| SHA-512 | 512 bits | 256 bits |

SHA-256 provides 128-bit post-quantum security (NIST Category 1), but with no margin. SHA-512 provides 256-bit post-quantum security (NIST Category 5), offering the maximum security margin against future quantum algorithmic improvements.

NIST explicitly states that existing symmetric cryptography and hash functions "are less vulnerable to attacks by quantum computers" and "NIST does not expect to need to transition away from these standards." By choosing SHA-512, Tidecoin aligns with NIST's highest security category for hash-based security.

### 7.2 Witness Version 1 with 512-bit Script Hash

Tidecoin extends Bitcoin's witness program with a new witness version 1 type: **P2WSH-512** (Pay-to-Witness-Script-Hash-512). This uses a 64-byte (512-bit) SHA-512 hash of the witness script, compared to Bitcoin's 32-byte SHA-256 hash.

Tidecoin defines the following witness program sizes:

```
WITNESS_V0_SCRIPTHASH_SIZE = 32   // Bitcoin-compatible (SHA-256)
WITNESS_V0_KEYHASH_SIZE = 20      // Bitcoin-compatible (HASH160)
WITNESS_V1_SCRIPTHASH_512_SIZE = 64  // Tidecoin PQ (SHA-512)
```

The v1 witness is activated by the `SCRIPT_VERIFY_WITNESS_V1_512` consensus flag, height-gated for safe deployment.

### 7.3 Post-Quantum Address Formats

Tidecoin uses two bech32 address families:

| Address Type | HRP | Witness Version | Use Case |
|-------------|-----|-----------------|----------|
| Standard | `tbc` | v0 | SegWit-compatible PQ addresses |
| Post-Quantum | `q` | v1 | PQ-native SHA-512 witness addresses |

Testnet uses `ttbc` and `tq`; regtest uses `rtbc` and `rq`.

---

## 8. Post-Quantum Peer-to-Peer Transport

### 8.1 ML-KEM-512 Key Encapsulation

Tidecoin's v2 peer-to-peer transport protocol replaces Bitcoin's ECDH-based key exchange with **ML-KEM-512** (FIPS 203), a Module-Lattice-Based Key-Encapsulation Mechanism.

ML-KEM-512 parameters (NIST Security Category 1):

| Parameter | Size |
|-----------|------|
| Encapsulation (public) key | 800 bytes |
| Decapsulation (private) key | 1,632 bytes |
| Ciphertext | 768 bytes |
| Shared secret | 32 bytes |

The ML-KEM handshake establishes a 256-bit shared secret that is then used for authenticated encryption of all subsequent peer-to-peer communication. As with Bitcoin's BIP 324 v2 transport, the primary purpose is peer privacy and censorship resistance — preventing ISP-level traffic analysis, connection fingerprinting, and selective relay censorship. Tidecoin replaces the ECDH key exchange with ML-KEM so that this protection does not become a quantum-era weakness.

### 8.2 Why P2P Encryption Matters for PQ

In a post-quantum setting, P2P encryption makes it harder for a passive network adversary to:

1. Intercept unconfirmed transactions in transit between peers
2. Collect exposed public keys from transaction relay traffic without participating as a receiving peer
3. Correlate transport-layer metadata with observed transaction propagation

---

## 9. Auxiliary Proof-of-Work (Merged Mining)

### 9.1 The 51% Attack Problem for Small Chains

Every proof-of-work cryptocurrency faces a fundamental security equation: the cost of a 51% attack must exceed the profit an attacker could extract. For small standalone chains, this equation is often unfavorable.

**Illustrative rental-market benchmarks (Crypto51/NiceHash snapshots, 2025-2026):**

| Chain | Algorithm | Approximate 1-Hour Rental Benchmark | Interpretation |
|-------|-----------|--------------------------------------|----------------|
| Bitcoin | SHA-256d | Million-dollar-plus | Rental attack infeasible at market scale |
| Litecoin | Scrypt | Tens-of-thousands of dollars | Meaningful benchmark, but not evidence that majority hashpower is rentable on demand |
| Small standalone chains | Various | Tens to low hundreds of dollars | Often cheap enough to be threatened if rental supply exists |

These figures are lower-bound market heuristics, not full real-world attack budgets. Crypto51 derives them from NiceHash pricing and separately reports available rental capacity; in observed snapshots, rentable scrypt supply is far below Litecoin's total network hashrate. For Tidecoin, the key point is comparative scale: merged mining anchors security to a much larger scrypt mining base than a standalone small chain can typically sustain.

### 9.2 How Merged Mining Works

Auxiliary Proof-of-Work (AuxPoW) allows miners working on one blockchain (the "parent chain") to simultaneously secure additional blockchains ("auxiliary chains") using the same computational work, at near-zero marginal cost.

**Protocol mechanics:**

1. **Block assembly:** The miner constructs block candidates for both the parent chain (Litecoin) and the auxiliary chain (Tidecoin)
2. **Coinbase embedding:** The hash of Tidecoin's block header is inserted into the coinbase field of Litecoin's coinbase transaction, prefixed with magic bytes `0xfabe6d6d`
3. **Mining:** The miner performs scrypt PoW on Litecoin's block header as normal
4. **Dual submission:** If the solved block meets Litecoin's difficulty, it is submitted to Litecoin. If it meets Tidecoin's difficulty (which can be lower), the parent's coinbase transaction, merkle branch, and block header are included in Tidecoin's AuxPoW header as proof.
5. **Multiple auxiliary chains:** A merkle tree of auxiliary chain hashes can be embedded in a single coinbase, allowing simultaneous merged mining of many chains

The parent chain (Litecoin) requires no awareness of Tidecoin. No protocol changes to Litecoin are needed.

### 9.3 The Dogecoin-Litecoin Precedent

The effectiveness of AuxPoW is demonstrated by historical data. Dogecoin activated merged mining with Litecoin in August 2014:

- Mining difficulty increased by **+1,500%** within one month
- **~90% of Dogecoin's total hashrate** now comes from Litecoin mining pools
- The correlation between Dogecoin and Litecoin hashrate is **0.95** (near-perfect)
- Before AuxPoW, Dogecoin was vulnerable to 51% attacks; after AuxPoW, attacking Dogecoin requires attacking Litecoin's full hashrate

### 9.4 Why Merged Mining with Litecoin

The choice of Litecoin as the parent chain is deliberate:

**Security inheritance:** Litecoin's multi-petahash scrypt network provides a far higher security ceiling than a small standalone chain. NiceHash-based benchmarks place Litecoin in the tens-of-thousands-of-dollars-per-hour class, but observed rentable scrypt supply is far below Litecoin's full network hashrate. By merged mining with Litecoin, Tidecoin ties its PoW security to that much larger mining base rather than relying solely on its own standalone hashrate.

**Quantum-resistant PoW:** Litecoin uses scrypt, a provably maximally memory-hard function (see Section 6.3). Unlike Bitcoin's SHA-256d, which can be attacked by a quantum computer with only computational qubits (no QRAM), scrypt requires ~1.2 billion physical qubits including QRAM for a quantum Grover attack (see Section 6.3.5). Merged mining with Litecoin means Tidecoin's PoW layer inherits scrypt's quantum resistance.

**Aligned incentives:** Litecoin miners opt into merged mining voluntarily because Tidecoin block rewards provide additional revenue at negligible extra cost. This creates a positive-sum relationship where Litecoin miners earn more and Tidecoin gains security.

**Chain ID separation:** Tidecoin uses AuxPoW Chain ID 8 with strict chain ID enforcement, preventing cross-chain proof replay attacks.

### 9.5 AuxPoW Activation as the Upgrade Gate

AuxPoW activation is the single consensus transition that unlocks Tidecoin's full post-quantum feature set. At the activation height, the following changes take effect simultaneously:

| Feature | Before AuxPoW | After AuxPoW |
|---------|--------------|--------------|
| PoW algorithm | YespowerTIDE (CPU-mined) | Scrypt (merged-mined with LTC) |
| Signature schemes | Falcon-512 only | Falcon-512/1024 + ML-DSA-44/65/87 |
| Witness versions | v0 only (SHA-256 based) | v0 + v1 (SHA-512 based, 64-byte hash) |
| OP_SHA512 | Disabled | Enabled |
| PQ strict validation | Optional | Enforced (SCRIPT_VERIFY_PQ_STRICT) |

This bundled activation ensures that the most significant upgrades deploy together, reducing the number of consensus transitions and allowing comprehensive testing of the combined feature set.

AuxPoW and its associated consensus changes are defined as a single height-gated transition. Before activation, Tidecoin operates under its pre-AuxPoW ruleset; after activation, the AuxPoW ruleset takes effect.

### 9.6 Combined Quantum Security of Scrypt + Merged Mining

The quantum security argument for merged mining with Litecoin is twofold:

**Layer 1 -- Algorithmic resistance:** Scrypt requires ~1.2 million logical qubits (~1.2 billion physical qubits) for the quantum oracle, including QRAM for the 128 KB scratchpad. This is approximately **200x more qubits** than attacking SHA-256d. The QRAM technology required does not exist and faces fundamental engineering challenges with no clear timeline for realization.

**Layer 2 -- Economic resistance:** Even if a quantum adversary could somehow construct a scrypt quantum oracle, they must still outcompete the combined hashrate of all Litecoin and Tidecoin miners. NiceHash-style benchmarks place Litecoin in the tens-of-thousands-of-dollars-per-hour rental class, but those figures are only lower-bound market heuristics and do not imply that majority scrypt hashpower can actually be rented on demand. A quantum attacker would still need sustained, faster-than-classical PoW throughput against the live mining network -- a far harder problem than a single Grover search.

**The compound barrier:** An attacker must simultaneously solve two independent hard problems: (1) build a quantum computer with billion-qubit-scale QRAM, and (2) make that quantum computer evaluate scrypt faster than the entire Litecoin mining network's classical hardware. These barriers multiply rather than add.

---

## 10. Economic Model

### 10.1 Supply Schedule

Tidecoin uses a doubling-interval halving schedule with quartering rewards, designed to converge to a total supply of approximately 21 million TDC.

**Initial parameters:**
- Initial block reward: 40 TDC
- Initial halving interval: 262,800 blocks (~6 months at 60-second blocks)

**Schedule:**

| Era | Interval (blocks) | Duration | Block Reward | Cumulative Supply |
|-----|-------------------|----------|-------------|-------------------|
| 1 | 262,800 | ~6 months | 40 TDC | 10,512,000 TDC |
| 2 | 525,600 | ~1 year | 10 TDC | 15,768,000 TDC |
| 3 | 1,051,200 | ~2 years | 2.5 TDC | 18,396,000 TDC |
| 4 | 2,102,400 | ~4 years | 0.625 TDC | 19,710,000 TDC |
| 5 | 4,204,800 | ~8 years | 0.15625 TDC | 20,367,000 TDC |
| 6 | 8,409,600 | ~16 years | 0.0390625 TDC | 20,695,500 TDC |
| ... | doubling | doubling | quartering | converges to ~21M |

**Key properties:**
- Each halving interval is twice the length of the previous one (geometric progression)
- The block reward is quartered (right-shifted by 2 bits) at each step, not halved
- This front-loads emission while maintaining a hard supply cap
- The schedule converges to approximately 21 million TDC total supply

In code, the core reward update is:

```cpp
CAmount nSubsidy = 40 * COIN;
nSubsidy >>= (halvings * 2);  // Quarter at each step
```

### 10.2 No Premine, No ICO

Tidecoin had no premine, no initial coin offering, and no developer allocation. All coins in circulation were earned through proof-of-work mining, beginning from block zero.

---

## 11. Network Parameters

*Protocol parameters across both PoW phases. Features marked "post-AuxPoW" activate at the AuxPoW consensus height.*

| Parameter | Value |
|-----------|-------|
| **Ticker** | TDC |
| **Genesis timestamp** | December 27, 2020, 13:09:40 UTC |
| **Genesis hash** | `480ecc76...018075` |
| **Block time target** | 60 seconds |
| **Initial block reward** | 40 TDC |
| **Halving interval (initial)** | 262,800 blocks |
| **Total supply** | ~21,000,000 TDC |
| **PoW algorithms** | YespowerTIDE (pre-AuxPoW), scrypt via LTC merged mining (post-AuxPoW) |
| **Default port** | 8755 |
| **Network magic** | 0xecfacea5 |
| **Bech32 HRP** | `tbc` (mainnet), `q` (PQ witness, post-AuxPoW) |
| **Signature schemes** | Falcon-512 (genesis), Falcon-1024 / ML-DSA-44/65/87 (post-AuxPoW) |
| **P2P encryption** | ML-KEM-512 |
| **DNS seeds** | seed.tidecoin.co |
| **SegWit** | Active from block 1 |
| **AuxPoW Chain ID** | 8 |

---

## 12. Security Analysis

### 12.1 Signature Security

| Attack Vector | ECDSA (Bitcoin) | Falcon-512 (Tidecoin) |
|--------------|----------------|----------------------|
| Classical best attack | 2^128 (Pollard's rho) | 2^113+ (lattice reduction, provable) |
| Quantum attack (Shor) | Polynomial time -- **broken** | Not applicable (no ECDLP) |
| Quantum attack (Grover on hash) | N/A | Quadratic speedup on underlying hash |
| Underlying hard problem | ECDLP | SIS over NTRU lattices |
| NIST security level | N/A (deprecated) | Category 1 |

Falcon-512's security is proven in the Quantum Random Oracle Model under the assumption that the SIS problem over NTRU lattices is hard. The NTRU lattice problem has been studied since 1996 (Hoffstein, Pipher, Silverman) with no known polynomial-time quantum algorithm.

### 12.2 Hash Security

| Component | Bitcoin | Tidecoin | PQ Security Level |
|-----------|---------|----------|-------------------|
| Block hash | SHA-256d | SHA-256d | Category 1 |
| Witness script hash (v0) | SHA-256 | SHA-256 | Category 1 |
| Witness script hash (v1) | N/A | SHA-512 | Category 5 |
| Address hash (P2PKH) | HASH160 | HASH160 | 80-bit (legacy compat) |

NIST confirms: "The existing algorithm standards for symmetric cryptography are less vulnerable to attacks by quantum computers. NIST does not expect to need to transition away from these standards as part of the PQC migration."

### 12.3 Proof-of-Work Security

**Pre-AuxPoW phase (YespowerTIDE -- CPU mining):**

| Property | SHA-256d (Bitcoin) | YespowerTIDE (Tidecoin Phase 1) |
|----------|-------------------|---------------------------------|
| Memory requirement | ~0 (stateless) | 1-16 MB |
| ASIC advantage | ~10^6x over CPU | Moderate over CPU |
| Mining decentralization | ASIC-dominated | CPU-accessible |
| 51% attack benchmark | Million-dollar-plus/hour rental benchmark | Low as a standalone small chain |

**Post-AuxPoW phase (scrypt via Litecoin merged mining):**

| Property | SHA-256d (Bitcoin) | Scrypt (Tidecoin Phase 2) |
|----------|-------------------|---------------------------|
| Memory per hash | ~0 (stateless) | 128 KB |
| Oracle logical qubits | ~2,402-6,063 | **~1,200,000+** (incl. QRAM) |
| Oracle physical qubits | ~2.4M-10M | **~1.2 billion+** |
| QRAM needed | **None** | **128 KB in superposition** |
| Sequential oracle depth | ~16K T-depth | **~100M+ T-depth** |
| Effective Grover speedup | Full quadratic | **Substantially subquadratic** |
| 51% attack benchmark | Million-dollar-plus/hour rental benchmark | Tens-of-thousands/hour rental benchmark at Litecoin scale* |

* Benchmark figures are lower-bound rental-market heuristics, not guarantees that majority hashpower is rentable on demand.

The transition from YespowerTIDE to scrypt merged mining trades the Phase 1 advantage (CPU-accessible decentralization) for the Phase 2 advantage (inherited Litecoin-scale security + quantum-resistant memory-hard PoW). This is a deliberate lifecycle design: fair distribution first, maximum security second.

### 12.4 Transport Security

| Property | Bitcoin v2 | Tidecoin v2 |
|----------|-----------|-------------|
| Key exchange | ECDH (secp256k1) | ML-KEM-512 (FIPS 203) |
| Quantum security | Broken by Shor | NIST Category 1 |
| Shared secret | 32 bytes | 32 bytes |

### 12.5 Memory Safety

The PQ implementation applies defense-in-depth memory safety practices:

- `memory_cleanse()` on all secret material after use
- `secure_allocator<>` for private key storage
- RAII destructors with mandatory cleanup (including ML-KEM keypairs)
- Move-only or deleted copy constructors for sensitive objects
- No heap allocation for cryptographic temporaries where avoidable
- Retry loops for probabilistic operations (Falcon signing) with per-attempt cleanup

---

## 13. Design Positioning

Post-quantum blockchain projects differ in how deep the PQ commitment goes. Some swap the signature algorithm and stop there. Others retrofit PQ into an existing chain, where the real challenge is coordination and backward compatibility rather than cryptographic design. Tidecoin takes a third approach: PQ from genesis, applied beyond just signatures.

| Approach | Description | Trade-offs |
|----------|-------------|------------|
| **Signature-only retrofit** | Replace signing algorithm on an existing chain | Requires coordinated migration; prior transactions remain exposed; political and block-space costs |
| **Full-stack PQ (new chain)** | PQ across signing, wallet, transport from launch | No migration debt; smaller network initially |
| **Stateful PQ** | Hash-based signatures (XMSS, LMS) | Conservative assumptions, but key reuse limits and state tracking add operational complexity |

Tidecoin is a full-stack PQ design on a Bitcoin-architecture chain. Falcon and ML-DSA handle transaction signing, but Tidecoin also uses a hardened-only PQHD wallet, SHA-512 witness extensions, and ML-KEM-encrypted peer transport. The aim is to close quantum-era exposure across the full transaction lifecycle, not just at the signing step.

On the stateful-vs-stateless axis, Tidecoin chose stateless lattice signatures. Stateful schemes like XMSS have strong security properties but turn address reuse and signer state into consensus-level concerns -- operational complexity that is hard to justify when stateless alternatives exist. Lattice signatures avoid this entirely and preserve a wallet experience close to Bitcoin's.

Tidecoin supports five parameter sets across two NIST-track signature families (Falcon-512/1024, ML-DSA-44/65/87), providing scheme agility. If a vulnerability is found in one lattice construction, alternative schemes are available through consensus upgrade without a hard fork.

Architecturally, Tidecoin stays on the Bitcoin UTXO model, script system, and node design. It is not a new execution environment. The components that break under quantum attack -- signatures, key derivation, transport encryption -- were replaced or extended. Everything else was kept.

---

## 14. Conclusion

The quantum threat to cryptocurrency is not a question of *if* but *when*. NIST, the Federal Reserve, the NSA, and the UK NCSC all recommend migration to post-quantum cryptography within the next decade. Retrofitting post-quantum security onto existing blockchains is a significant engineering and coordination challenge, as the ongoing efforts around Bitcoin's BIP-360 and Ethereum's roadmap illustrate.

Tidecoin took a different approach: build quantum resistance in from the start. Every transaction on the Tidecoin blockchain, from genesis to the present, is protected by post-quantum signatures drawn from the NIST PQC process. The network has operated continuously for over five years, demonstrating that post-quantum cryptocurrency is not merely theoretical -- it is operational and production-ready.

By combining the proven foundation of Bitcoin Core with NIST's post-quantum cryptographic standards, Tidecoin provides a Bitcoin-architecture cryptocurrency with post-quantum security from genesis -- no migration required.

---

## 15. References

### NIST Standards and Publications

1. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM). August 2024. https://csrc.nist.gov/pubs/fips/203/final
2. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA). August 2024. https://csrc.nist.gov/pubs/fips/204/final
3. NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA). August 2024. https://csrc.nist.gov/pubs/fips/205/final
4. NIST Draft FIPS 206: FFT over NTRU-Lattice-Based Digital Signature Standard (FN-DSA/Falcon). In preparation. https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon
5. NIST IR 8547: Transition to Post-Quantum Cryptography Standards. 2024. https://csrc.nist.gov/pubs/ir/8547/ipd
6. NIST Post-Quantum Cryptography Standardization Process. https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization

### Academic Papers

7. Shor, P. "Algorithms for Quantum Computation: Discrete Logarithms and Factoring." FOCS 1994.
8. Alwen, J., Chen, B., Pietrzak, K., Reyzin, L., Tessaro, S. "Scrypt Is Maximally Memory-Hard." EUROCRYPT 2017. https://eprint.iacr.org/2016/989
9. Gentry, C., Peikert, C., Vaikuntanathan, V. "Trapdoors for Hard Lattices and New Cryptographic Constructions." STOC 2008. https://eprint.iacr.org/2007/432.pdf
10. Hoffstein, J., Pipher, J., Silverman, J.H. "NTRU: A Ring-Based Public Key Cryptosystem." ANTS-III 1998.
11. Song, G., Seo, H. "Grover on Scrypt." MDPI Electronics, vol. 13, no. 16, article 3167, 2024. https://www.mdpi.com/2079-9292/13/16/3167
12. Roetteler, M., Naehrig, M., Svore, K.M., Lauter, K. "Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms." 2017. https://eprint.iacr.org/2017/598
13. Mascelli, M.D., Rodden, T. "Harvest Now Decrypt Later: Examining Post-Quantum Cryptography and the Data Privacy Risks for Distributed Ledger Networks." Federal Reserve FEDS 2025-093, 2025. https://www.federalreserve.gov/econres/feds/harvest-now-decrypt-later-examining-post-quantum-cryptography-and-the-data-privacy-risks-for-distributed-ledger-networks.htm

### Tidecoin Sources

14. Tidecoin source code. https://github.com/tidecoin/tidecoin
15. Tidecoin original whitepaper. https://github.com/tidecoin-old/whitepaper/blob/master/tidecoin.pdf
16. Tidecoin official website. https://tidecoin.org/

### Quantum Attacks on PoW

17. Amy, M., Di Matteo, O., Gheorghiu, V., Mosca, M., Parent, A., Schanck, J. "Estimating the cost of generic quantum pre-image attacks on SHA-2 and SHA-3." 2016. https://arxiv.org/abs/1603.09383
18. Benkoczi, R., Gaur, D., et al. "Quantum Bitcoin Mining." Entropy 24(3):323, 2022. https://www.mdpi.com/1099-4300/24/3/323
19. Nerem, R., Gaur, D. "Conditions for Advantageous Quantum Bitcoin Mining." 2023. https://www.sciencedirect.com/science/article/pii/S2096720923000167
20. Lee, S., et al. "T-depth reduction method for efficient SHA-256 quantum circuit construction." IET Information Security, 2023. https://ietresearch.onlinelibrary.wiley.com/doi/full/10.1049/ise2.12074
21. Blocki, J., Holman, B., Lee, S. "The Parallel Reversible Pebbling Game: Analyzing the Post-quantum Security of iMHFs." 2022. https://eprint.iacr.org/2022/1503
22. Phalak, K., et al. "Quantum Random Access Memory for Dummies." 2023. https://pmc.ncbi.nlm.nih.gov/articles/PMC10490729/

### Falcon Algorithm and Implementation

23. Falcon specification. https://falcon-sign.info/falcon.pdf
24. Falcon implementation paper (Pornin, 2019). https://falcon-sign.info/falcon-impl-20190802.pdf
25. Abou Haidar, C., Tibouchi, M. "How Bad Was The Falcon Bug of 2019?" ACM CCS 2025. https://www.esat.kuleuven.be/cosic/blog/ccs25-falconbug/
26. Guerreau, M., et al. "FALCON Down: Breaking Falcon Post-Quantum Signature Scheme through Side-Channel Attacks." 2021. https://eprint.iacr.org/2021/772
27. Berzati, A., et al. "SHIFT SNARE: Uncovering Secret Keys in FALCON via Single-Trace Analysis." 2025. https://arxiv.org/html/2504.00320v1
28. Kim, S., Hong, S. "Improved Power Analysis Attacks on Falcon." EUROCRYPT 2023. https://dl.acm.org/doi/10.1007/978-3-031-30634-1_19
29. Howe, J., et al. "Do Not Disturb a Sleeping Falcon: Floating-Point Error Sensitivity." 2024. https://eprint.iacr.org/2024/1709
30. Becker, H., Howe, J. "Formal Verification of Emulated Floating-Point Arithmetic in Falcon." 2024. https://eprint.iacr.org/2024/321.pdf
31. Pornin, T., Prest, T. "BUFFing FALCON without Increasing the Signature Size." 2024. https://eprint.iacr.org/2024/710.pdf
32. PQClean: Clean, portable implementations of post-quantum cryptography. https://github.com/PQClean/PQClean
33. PQClean PR #210: Falcon integer-only constant-time implementations. https://github.com/PQClean/PQClean/pull/210
34. FIPS 206 Status Update slides (Perlner). https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf
35. Pornin, T. rust-fn-dsa: Rust implementation of FN-DSA. https://github.com/pornin/rust-fn-dsa

### ML-DSA Algorithm and Implementation

36. Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., Stehle, D. "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme." TCHES 2018. https://eprint.iacr.org/2017/633.pdf
37. Lyubashevsky, V. "Fiat-Shamir with Aborts: Applications to Lattice and Factoring-Based Signatures." ASIACRYPT 2009. https://link.springer.com/chapter/10.1007/978-3-642-10366-7_35
38. Langlois, A., Stehle, D. "Worst-Case to Average-Case Reductions for Module Lattices." Designs, Codes and Cryptography, 2015. https://perso.ens-lyon.fr/damien.stehle/downloads/MSIS.pdf
39. CRYSTALS-Dilithium Round 3 Specification (v3.1). https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
40. Regev, O. "The Learning with Errors Problem." Survey. https://cims.nyu.edu/~regev/papers/lwesurvey.pdf

### Other Cryptographic References

41. Percival, C. "Stronger Key Derivation via Sequential Memory-Hard Functions." BSDCan'09. https://www.tarsnap.com/scrypt.html
42. RFC 7914: The scrypt Password-Based Key Derivation Function. https://www.rfc-editor.org/rfc/rfc7914.html
43. Solar Designer. Yespower. https://www.openwall.com/yespower/

### Bitcoin Quantum Vulnerability Estimates

44. Deloitte. "Quantum computers could crack Bitcoin security by 2030." 2022. https://www2.deloitte.com/nl/nl/pages/innovatie/artikelen/quantum-computers-and-the-bitcoin-blockchain.html
45. Project Eleven. "A Look at Post-Quantum Proposals for Bitcoin." 2025. https://blog.projecteleven.com/posts/a-look-at-post-quantum-proposals-for-bitcoin

---

*Tidecoin is open-source software released under the MIT license.*
*Copyright (c) 2020-2026 The Tidecoin developers.*
*Copyright (c) 2009-2025 The Bitcoin Core developers.*
