# Original Falcon-512 Implementation Verification Report

**Date:** 2025-02-07
**Repository:** https://github.com/tidecoin/tidecoin (master branch)
**Purpose:** Verify that the Falcon-512 implementation shipping in Tidecoin since genesis (December 27, 2020) contains the post-fix PQClean code and was never affected by the 2019 Falcon sampler bug.

---

## 1. Executive Summary

**Verdict: CONFIRMED** — The Tidecoin Falcon-512 implementation at `https://github.com/tidecoin/tidecoin` uses the corrected PQClean "clean" implementation. The 2019 sampler bug (discovered by Markku-Juhani O. Saarinen, fixed by Thomas Pornin on September 18, 2019) is **not present**. Tidecoin's genesis block was created on December 27, 2020, more than 15 months after the fix was committed to the Falcon reference code and propagated to PQClean.

---

## 2. Background: The 2019 Falcon Sampler Bug

In 2019, Markku-Juhani O. Saarinen discovered two related bugs in the Falcon discrete Gaussian sampler:

1. **dist[] table error**: The `dist[]` lookup table in `sign.c` contained Probability Density (PD) values instead of the required Reverse Cumulative Distribution (RCD) values. These are related but numerically different — PD gives P(X=k) while RCD gives P(X≥k).

2. **Rejection scaling error**: The rejection sampling scaling factor (`ccs = sigma_min / sigma`) was applied in the wrong place within the BerExp computation, causing incorrect acceptance probabilities.

Both bugs were fixed by Thomas Pornin on September 18, 2019, and the fixes propagated to PQClean. The corrected code uses proper RCD values and correctly passes the `ccs` scaling factor to `BerExp`.

---

## 3. Repository Structure

The GitHub repository at `https://github.com/tidecoin/tidecoin` has Falcon source files directly in the `src/` directory with `.cpp` extensions:

```
src/sign.cpp       - Gaussian sampler and signing
src/fpr.h          - Integer emulation (FPEMU) type and operations
src/fpr.cpp        - FPR implementation
src/common.cpp     - Norm bound checking (legacy relaxed bound)
src/vrfy.cpp       - Verification
src/codec.cpp      - Encoding/decoding
src/keygen.cpp     - Key generation
src/pqclean.cpp    - PQClean wrapper API
src/api.h          - Public API constants
src/inner.h        - Internal declarations
src/Makefile.am    - Build system (lists all PQ source files)
```

**Note:** The local development repository has since been restructured to `src/pq/falcon-512/` with `.c` extensions following standard PQClean layout, but the **published** code at GitHub uses the structure above.

---

## 4. Verification: dist[] Table (Gaussian Sampler)

### 4.1 What Was Checked

The `dist[]` table in `src/sign.cpp` contains 54 uint32_t values (18 rows × 3 columns) used by the base Gaussian sampler `gaussian0_sampler()`. These must be Reverse Cumulative Distribution values for a discrete Gaussian with σ₀ = 1.8205.

### 4.2 Verified Values

The following dist[] table was fetched from `https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/sign.cpp`:

```c
static const uint32_t dist[] = {
    10745844u,  3068844u,  3741698u,
     5559083u,  1580863u,  8248194u,
     2260429u, 13669192u,  2736639u,
      708981u,  4421575u, 10046180u,
      169348u,  7122675u,  4136815u,
       30538u, 13063405u,  7650655u,
        4132u, 14505003u,  7826148u,
         417u, 16768101u, 11363290u,
          31u,  8444042u,  8086568u,
           1u, 12844466u,   265321u,
           0u,  1232676u, 13644283u,
           0u,    38047u,  9111839u,
           0u,      870u,  6138264u,
           0u,       14u, 12545723u,
           0u,        0u,  3104126u,
           0u,        0u,    28824u,
           0u,        0u,      198u,
           0u,        0u,        1u,
};
```

### 4.3 Comparison with Upstream PQClean

These values were compared against the upstream PQClean repository at `https://raw.githubusercontent.com/PQClean/PQClean/master/crypto_sign/falcon-512/clean/sign.c`:

**Result: IDENTICAL** — All 54 values match exactly. These are the correct post-fix RCD values.

The buggy (pre-fix) table would have had different values in the first column — PD values instead of RCD values. The corrected first column starts with `10745844u` (RCD), not the PD equivalent.

---

## 5. Verification: Rejection Sampling Formula

### 5.1 What Was Checked

The `sampler()` function in `src/sign.cpp` implements rejection sampling for the discrete Gaussian. The critical formula must:
1. Compute `x = (z - r)² / (2σ²) - z₀² / (2σ₀²)`
2. Pass `ccs = σ_min / σ` correctly to `BerExp()`

### 5.2 Verified Code

From `https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/sign.cpp`:

```c
/*
 * Compute the actual center and deviation used for this
 * temporary Gaussian distribution.
 */
z0 = fpr_rint(mu);
mu = fpr_sub(mu, fpr_of(z0));
dss = fpr_half(fpr_inv(isigma));
dss = fpr_mul(dss, dss);

/*
 * ... (Bernoulli trial with base sampler) ...
 */

x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(z), mu)), dss);
x = fpr_sub(x, fpr_mul(fpr_of(z0 * z0), fpr_inv_2sqrsigma0));
if (BerExp(&spc->p, x, ccs)) {
    return s + z;
}
```

Where `ccs` is set in the calling context as `sigma_min * isigma` (i.e., σ_min/σ).

### 5.3 Analysis

- `dss = 1/(2σ²)` — correct denominator for the exponent
- `x = (z-μ)² × dss - z₀²/(2σ₀²)` — correct rejection formula
- `ccs` passed to `BerExp` — correct placement of the scaling factor

**Result: CORRECT** — The rejection sampling formula matches the post-fix PQClean implementation exactly. The buggy version had `ccs` applied incorrectly (multiplied into `dss` rather than passed separately to `BerExp`).

---

## 6. Verification: Integer Emulation (FPEMU)

### 6.1 What Was Checked

Tidecoin claims to use integer emulation for all floating-point operations in Falcon, avoiding FPU side channels.

### 6.2 Verified Code

From `https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/fpr.h`:

```c
typedef uint64_t fpr;
```

This single typedef confirms that **all floating-point operations are emulated using 64-bit integers**. The fpr type is NOT a native `double` — it is a `uint64_t` that stores IEEE-754 binary64 representations and manipulates them via integer arithmetic only.

### 6.3 Key Constants Verified

```c
#define fpr_inv_2sqrsigma0   4594603506513722306
#define fpr_sigma_min_9      4608495221497168882
#define fpr_sigma_min_10     4608586345619182117
#define fpr_inv_sigma        4573359825155195350
```

These match the expected IEEE-754 binary64 bit patterns for the Falcon sampler parameters:
- `fpr_inv_2sqrsigma0` = 1/(2 × σ₀²) where σ₀ = 1.8205
- `fpr_sigma_min_9` = σ_min for logn=9 (Falcon-512) ≈ 1.2778
- `fpr_sigma_min_10` = σ_min for logn=10 (Falcon-1024)
- `fpr_inv_sigma` is the precomputed inverse of sigma

### 6.4 Constant-Time Shift Operations

The file also contains constant-time shift functions:
- `fpr_ursh()` — unsigned right shift (secret-count safe)
- `fpr_irsh()` — signed (arithmetic) right shift (secret-count safe)
- `fpr_ulsh()` — unsigned left shift (secret-count safe)

These ensure no timing side channels leak information about secret key material during signing.

**Result: CONFIRMED** — Tidecoin uses integer emulation (`typedef uint64_t fpr`) for all Falcon floating-point arithmetic. No native `double` or FPU instructions are used.

---

## 7. Verification: Legacy Norm Bound

### 7.1 What Was Checked

The Tidecoin whitepaper states that the original implementation uses a "relaxed" norm bound for signature verification, which will be tightened to the standard PQClean bound when AuxPoW activates.

### 7.2 Verified Code

From `https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/common.cpp`:

```c
static int
is_short(const int16_t *s1, const int16_t *s2, unsigned logn) {
    /*
     * ... (sum of squares computation) ...
     */
    s |= -(ng >> 31);

    return s < (((uint32_t)7085 * (uint32_t)12289) >> (10 - logn));
}
```

For Falcon-512 (logn = 9):
- **Tidecoin legacy bound**: `(7085 × 12289) >> (10 - 9)` = `87,067,565 >> 1` = **43,533,782**

From `https://raw.githubusercontent.com/PQClean/PQClean/master/crypto_sign/falcon-512/clean/common.c`:

```c
static const uint32_t l2bound[] = {
    /* ... */
    34034726,   /* logn = 9 (Falcon-512) */
    70265242,   /* logn = 10 (Falcon-1024) */
};

return s <= l2bound[logn];
```

- **Standard PQClean bound**: `l2bound[9]` = **34,034,726**

### 7.3 Analysis

The legacy bound (43,533,782) is approximately **1.28× larger** than the standard PQClean bound (34,034,726). This means:
- Legacy mode accepts some signatures that standard mode would reject
- All standard-mode signatures are valid under legacy mode (backward compatible)
- The tighter bound provides stronger security guarantees

**Result: CONFIRMED** — The GitHub repo uses a relaxed legacy bound. The local development codebase has been restructured to use the standard PQClean bound for strict mode, with legacy verification preserved in a separate code path (`src/pq/falcon512.c`).

---

## 8. Verification: Signature Size

### 8.1 What Was Checked

From `https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/api.h`:

```c
#define CRYPTO_BYTES         690
#define CRYPTO_PUBLICKEYBYTES 897
#define CRYPTO_SECRETKEYBYTES 1281
```

- **CRYPTO_BYTES = 690**: This is the legacy signed-message overhead bound. The detached signer reserves two bytes from that bound and returns compressed signatures of at most 688 bytes, excluding the transaction sighash byte.
- Standard PQClean uses **CRYPTO_BYTES = 752** (allows for slightly larger compressed signatures)
- Tidecoin uses variable-length compressed signatures before and after AuxPoW. Both legacy and strict verification require exact decoder consumption; appended zero padding is rejected.

The current local signer retries until a compressed signature is at most 666 bytes for Falcon-512 or 1280 bytes for Falcon-1024. This applies to both message lengths and to legacy Falcon-512 signing, making the wallet's local signing estimates upper bounds. Signatures are never padded, and the transaction sighash byte is additional. The shared retry loop returns failure after 10,000 unsuccessful attempts. External-signing estimates retain the larger PQClean bounds. Verification does not impose the local signing bounds as consensus maxima.

Signed messages have no transaction height. `CPubKey::Recover`, used by
`MessageVerify` and `verifymessage`, first checks a message signature using the
strict verifier. For Falcon-512 only, it then tries the legacy verifier. This
preserves compatibility with signatures accepted by v0.18.3, including its wider
combined norm bound, negative-zero coefficients and nonzero unused final bits.
Both paths reject appended bytes, including zero padding. Falcon-1024 and ML-DSA
use only their strict verifiers. The result does not change at AuxPoW activation
or rollback, and no transaction-verification rule is changed by this fallback.
Current message signing continues to produce strict-compatible signatures; the
fallback is for older accepted signatures and encodings. The fixed message test
vectors include a synthetic wider-norm example, not a signature captured from a
historical wallet.

---

## 9. Verification: Key Format Compatibility

### 9.1 Findings

Both the GitHub repo and the local development codebase use identical key formats:
- **Public key**: 897 bytes (1-byte header `0x09` + 896 bytes of polynomial h in mod-q encoding)
- **Secret key**: 1,281 bytes (1-byte header `0x59` + encoded f, g, F polynomials)

The key format does not depend on the norm bound or signature format. When AuxPoW activates and strict verification begins:
- **Public keys remain valid** — no re-keying required
- **Private keys remain valid** — signing produces different signatures (tighter bound) but uses the same key material
- **Old signatures under relaxed bound continue to verify** — historical transactions remain valid

**Result: CONFIRMED** — Keys are format-identical between legacy and strict modes.

---

## 10. Summary Table

| Component | GitHub Repo (Published) | Upstream PQClean | Match? |
|-----------|------------------------|------------------|--------|
| dist[] table (54 values) | RCD values (post-fix) | RCD values (post-fix) | YES |
| Rejection formula | `BerExp(&spc->p, x, ccs)` | `BerExp(&spc->p, x, ccs)` | YES |
| FPEMU type | `typedef uint64_t fpr` | `typedef uint64_t fpr` | YES |
| fpr_inv_2sqrsigma0 | 4594603506513722306 | 4594603506513722306 | YES |
| Constant-time shifts | fpr_ursh/irsh/ulsh | fpr_ursh/irsh/ulsh | YES |
| Norm bound | Relaxed: 43,533,782 | Standard: 34,034,726 | INTENTIONAL DIFFERENCE |
| CRYPTO_BYTES | 690 (legacy) | 752 (standard) | INTENTIONAL DIFFERENCE |
| Public key size | 897 bytes | 897 bytes | YES |
| Secret key size | 1,281 bytes | 1,281 bytes | YES |

The two intentional differences (norm bound and max signature size) are the "legacy" parameters that will be tightened when AuxPoW activates.

---

## 11. URLs Used for Verification

### 11.1 Tidecoin GitHub Repository

- **Repository root**: https://github.com/tidecoin/tidecoin
- **API - repo info**: https://api.github.com/repos/tidecoin/tidecoin
- **API - src/ directory listing**: https://api.github.com/repos/tidecoin/tidecoin/contents/src
- **API - full tree**: https://api.github.com/repos/tidecoin/tidecoin/git/trees/master?recursive=1
- **src/ directory (web)**: https://github.com/tidecoin/tidecoin/tree/master/src

#### Raw Source Files Fetched

- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/sign.cpp
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/fpr.h
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/fpr.cpp
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/common.cpp
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/api.h
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/pqclean.cpp
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/inner.h
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/keygen.cpp
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/vrfy.cpp
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/codec.cpp
- https://raw.githubusercontent.com/tidecoin/tidecoin/master/src/Makefile.am

#### URLs That Returned 404 (Structure Mismatch)

- https://github.com/tidecoin/tidecoin/blob/master/src/pq/falcon-512/sign.c (local structure, not present on GitHub)

### 11.2 Upstream PQClean Repository (Comparison Baseline)

- https://raw.githubusercontent.com/PQClean/PQClean/master/crypto_sign/falcon-512/clean/sign.c
- https://raw.githubusercontent.com/PQClean/PQClean/master/crypto_sign/falcon-512/clean/fpr.h
- https://raw.githubusercontent.com/PQClean/PQClean/master/crypto_sign/falcon-512/clean/common.c

### 11.3 Falcon Specification and Reference Implementation

- https://falcon-sign.info/
- https://falcon-sign.info/falcon.pdf
- https://falcon-sign.info/falcon-impl-20190802.pdf
- https://falcon-sign.info/impl/falcon.h.html
- https://falcon-sign.info/impl/config.h.html
- https://falcon-sign.info/impl/sign.c.html

### 11.4 PQClean Repository

- https://github.com/PQClean/PQClean
- https://github.com/PQClean/PQClean/pull/210 (Falcon integer-only CT implementation)
- https://github.com/PQClean/PQClean/issues/522 (aarch64 fmla bit-flip issue)
- https://github.com/PQClean/PQClean/security

### 11.5 2019 Falcon Sampler Bug Analysis

- https://www.esat.kuleuven.be/cosic/blog/ccs25-falconbug/ (How Bad Was The Falcon Bug of 2019? — CCS 2025)
- https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/7Z8x5AMXy8s/m/Spyv8VYoBQAJ (Falcon bug & fixes — NIST PQC Forum)
- https://cryptoservices.github.io/post-quantum/cryptography/2019/09/18/new-falcon-impl.html (NCC Group: New Falcon implementation)
- https://cryptoservices.github.io/post-quantum/cryptography/2019/10/21/falcon-implementation.html (NCC Group: Optimized Falcon)

### 11.6 FN-DSA (FIPS 206) Standardization

- https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon
- https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf
- https://csrc.nist.gov/csrc/media/Presentations/2024/falcon/images-media/prest-falcon-pqc2024.pdf
- https://csrc.nist.gov/csrc/media/presentations/2024/navigating-floating-point-challenges-in-falcon
- https://csrc.nist.gov/csrc/media/Presentations/Falcon/images-media/Falcon-April2018.pdf
- https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/selected-algos-2022/official-comments/falcon-selected-algo-official-comment.pdf
- https://csrc.nist.gov/csrc/media/Events/2022/fourth-pqc-standardization-conference/documents/papers/falcon-down-pqc2022.pdf
- https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/Dpr3tnTlKy0/m/X8z4uVw5AAAJ (Signature format feedback)
- https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/1HXzjlMUU6Y (FIPS 206 status)
- https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist
- https://www.inria.fr/en/nist-algorithm-falcon-post-quantum-cryptographic

### 11.7 Falcon Cryptanalysis and Side-Channel Research

- https://eprint.iacr.org/2007/432.pdf (GPV framework — foundational lattice-based signatures)
- https://eprint.iacr.org/2021/772 (FALCON DOWN — side-channel attack)
- https://eprint.iacr.org/2024/710.pdf (BUFFing Falcon / FN-DSA BUFF security)
- https://eprint.iacr.org/2024/1709 (Floating-point error sensitivity in Falcon)
- https://eprint.iacr.org/2024/1769.pdf (A Closer Look at Falcon)
- https://eprint.iacr.org/2024/321.pdf (Formal verification of emulated floating-point in Falcon)
- https://eprint.iacr.org/2025/1042 (Crowhammer: Rowhammer bit-flip key recovery)
- https://eprint.iacr.org/2025/351.pdf (Thorough power analysis on Falcon)
- https://eprint.iacr.org/2025/2159 (Single-trace key recovery)
- https://eprint.iacr.org/2021/1486.pdf (Mitaka: simpler Falcon variant)
- https://arxiv.org/html/2504.00320v1 (SHIFT SNARE — single-trace analysis)
- https://dl.acm.org/doi/10.1007/978-3-031-30634-1_19 (EUROCRYPT 2023 — power analysis)

### 11.8 Thomas Pornin FN-DSA Reference Implementations

- https://github.com/pornin/rust-fn-dsa
- https://github.com/pornin/c-fn-dsa

### 11.9 ML-DSA / CRYSTALS-Dilithium Research

- https://pq-crystals.org/dilithium/
- https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
- https://pq-crystals.org/dilithium/resources.shtml
- https://eprint.iacr.org/2017/633.pdf (CRYSTALS-Dilithium original paper)
- https://tches.iacr.org/index.php/TCHES/article/view/839
- https://link.springer.com/chapter/10.1007/978-3-642-10366-7_35 (Fiat-Shamir with Aborts)
- https://iacr.org/archive/asiacrypt2009/59120596/59120596.pdf
- https://link.springer.com/chapter/10.1007/978-3-031-38554-4_12 (Fixing Fiat-Shamir with Aborts proof — CRYPTO 2023)
- https://perso.ens-lyon.fr/damien.stehle/downloads/MSIS.pdf (Module lattice reductions)
- https://dl.acm.org/doi/10.1007/s10623-014-9938-4
- https://cims.nyu.edu/~regev/papers/lwesurvey.pdf (LWE survey)
- https://web.eecs.umich.edu/~cpeikert/pubs/LWsE.pdf (SIS/LWE with small parameters)
- https://arxiv.org/html/2409.02222v1 (Module-LWE/SIS digital signatures)
- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
- https://csrc.nist.gov/files/pubs/fips/204/ipd/docs/fips-204-initial-public-comments-2023.pdf
- https://github.com/pq-crystals/dilithium (reference implementation)

### 11.10 NIST Post-Quantum Cryptography Standards

- https://csrc.nist.gov/pubs/fips/203/final (FIPS 203: ML-KEM)
- https://csrc.nist.gov/pubs/fips/204/final (FIPS 204: ML-DSA)
- https://csrc.nist.gov/pubs/fips/205/final (FIPS 205: SLH-DSA)
- https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
- https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)
- https://csrc.nist.gov/projects/post-quantum-cryptography/workshops-and-timeline
- https://csrc.nist.gov/projects/post-quantum-cryptography/faqs
- https://csrc.nist.gov/pubs/ir/8547/ipd (IR 8547: Transition to PQC Standards)
- https://csrc.nist.gov/Presentations/2024/practical-cost-of-grover-for-aes-key-recovery
- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
- https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption
- https://www.federalregister.gov/documents/2024/08/14/2024-17956/announcing-issuance-of-federal-information-processing-standards-fips-fips-203-module-lattice-based

### 11.11 Open Quantum Safe and Other PQ Libraries

- https://openquantumsafe.org/liboqs/algorithms/sig/falcon.html
- https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html
- https://pqshield.com/falcon-a-post-quantum-signature-scheme/
- https://quarkslab.github.io/crypto-condor/latest/method/Falcon.html
- https://github.com/itzmeanjan/ml-kem

### 11.12 Quantum Computing Threat Research

- https://eprint.iacr.org/2017/598.pdf (Quantum resource estimates for ECDLP)
- https://eprint.iacr.org/2021/967.pdf
- https://eprint.iacr.org/2021/292.pdf
- https://eprint.iacr.org/2016/989 (Scrypt is maximally memory-hard)
- https://eprint.iacr.org/2023/062.pdf
- https://eprint.iacr.org/2022/1503
- https://eprint.iacr.org/2016/992.pdf
- https://arxiv.org/abs/1603.09383
- https://arxiv.org/pdf/1711.04235
- https://arxiv.org/pdf/2505.02239
- https://arxiv.org/pdf/2510.09271
- https://arxiv.org/pdf/2409.01358
- https://arxiv.org/abs/2301.05680
- https://arxiv.org/abs/2110.00878
- https://arxiv.org/html/2312.17483
- https://journals.aps.org/prxquantum/pdf/10.1103/PRXQuantum.5.020312
- https://www.nature.com/articles/s41534-024-00848-3
- https://www.nature.com/articles/s41586-022-05434-1
- https://www.nature.com/articles/s41586-024-08449-y
- https://www.amazon.science/publications/systems-architecture-for-quantum-random-access-memory
- https://www.scilit.com/publications/a073ad723dcb63ac9c9a13eb40515fb5
- https://kudelskisecurity.com/research/quantum-attack-resource-estimate-using-shors-algorithm-to-break-rsa-vs-dh-dsa-vs-ecc/
- https://postquantum.com/post-quantum/nist-pqc-security-categories/
- https://postquantum.com/post-quantum/grovers-algorithm/
- https://postquantum.com/post-quantum/brassard-hoyer-tapp-bht/
- https://en.wikipedia.org/wiki/Grover's_algorithm

### 11.13 Scrypt and YespowerTIDE (PoW Research)

- https://www.mdpi.com/2079-9292/13/16/3167 (Grover on Scrypt)
- https://www.mdpi.com/2079-9292/12/21/4485
- https://quantum-safeinternet.com/project/quantum-security-of-memory-hard-functions/
- https://link.springer.com/chapter/10.1007/978-3-319-56617-7_2
- https://link.springer.com/chapter/10.1007/978-981-99-8727-6_1
- https://dl.acm.org/doi/fullHtml/10.1145/3613424.3614270
- https://pmc.ncbi.nlm.nih.gov/articles/PMC10490729/
- https://sites.cs.ucsb.edu/~rich/class/old.cs290/papers/scrypt.pdf
- https://www.rfc-editor.org/rfc/rfc7914.html (RFC 7914: scrypt)
- https://www.tarsnap.com/scrypt.html
- https://www.tarsnap.com/scrypt/scrypt.pdf
- https://www.openwall.com/yespower/
- https://www.openwall.com/yescrypt/
- https://github.com/openwall/yespower
- https://en.wikipedia.org/wiki/Solar_Designer
- https://openwall.info/wiki/people/solar/bio
- https://en.wikipedia.org/wiki/Scrypt
- https://litecoin.info/docs/key-concepts/proof-of-work

### 11.14 Merged Mining Research

- https://en.bitcoin.it/wiki/Merged_mining_specification
- https://tlu.tarilabs.com/mining/MergedMiningIntroduction
- https://www.binance.com/en/research/analysis/merged-mining
- https://www.litecoinpool.org/news?id=59
- https://litecoin.com/news/how-litecoin-and-dogecoin-created-one-of-the-most-robust-pow-networks
- https://coincub.com/mining/merge-mining/
- https://www.coinspect.com/blog/merged-mining-security/
- https://earnednotgifted.medium.com/my-take-on-merged-mining-why-merged-mining-doesnt-increase-security-of-the-auxiliary-chain-ccd3bbc978b5
- https://blog.thirdweb.com/understanding-merged-mining-a-comprehensive-guide/

### 11.15 Bitcoin Quantum Resistance and BIP-360

- https://bitcoinops.org/en/topics/quantum-resistance/
- https://www.gopher.security/post-quantum/is-sha-256-secure-against-quantum-attacks
- https://bip360.org/bip360.html
- https://bip360.org/
- https://qbip.org/
- https://delvingbitcoin.org/t/proposing-a-p2qrh-bip-towards-a-quantum-resistant-soft-fork/956
- https://delvingbitcoin.org/t/post-quantum-hd-wallets-silent-payments-key-aggregation-and-threshold-signatures/1854
- https://chaincode.com/bitcoin-post-quantum.pdf
- https://blog.projecteleven.com/posts/a-look-at-post-quantum-proposals-for-bitcoin
- https://blog.projecteleven.com/posts/hd-wallets--quantum-risk-does-reusing-one-address-endanger-the-rest
- https://river.com/learn/will-quantum-computing-break-bitcoin/
- https://hrf.org/latest/the-quantum-threat-to-bitcoin/
- https://bitcoinmagazine.com/news/new-bitcoin-improvement-proposal-aims-to-solve-future-quantum-security-risks
- https://bitbo.io/news/quantum-resistant-bip-360-debate/
- https://thebitcoinmanual.com/articles/qramp/
- https://en.bitcoin.it/wiki/Quantum_computing_and_Bitcoin
- https://braiins.com/blog/can-quantum-computers-51-attack-bitcoin
- https://hackernoon.com/what-it-takes-for-quantum-computers-to-mine-bitcoin-efficiently
- https://conduition.io/cryptography/quantum-hbs/
- https://postquantum.com/post-quantum/quantum-cryptocurrencies-bitcoin/

### 11.16 Post-Quantum Blockchain Projects (Competitive Landscape)

- https://www.theqrl.org/
- https://docs.theqrl.org/what-is-qrl/
- https://www.theqrl.org/blog/techniques-for-efficient-post-quantum-finance-part-4-reducing-storage-requirements/
- https://algorand.co/technology/post-quantum
- https://algorand.co/blog/technical-brief-quantum-resistant-transactions-on-algorand-with-falcon-signatures
- https://algorand.co/blog/pioneering-falcon-post-quantum-technology-on-blockchain
- https://www.biometricupdate.com/202510/iota-adds-post-quantum-cryptography-to-its-identity-framework
- https://ethereum.org/roadmap/future-proofing/
- https://www.btq.com/blog/ethereums-roadmap-post-quantum-cryptography
- https://cointelegraph.com/news/why-vitalik-believes-quantum-computing-could-break-ethereum-s-cryptography-sooner-than-expected
- https://cointelegraph.com/news/ethereum-post-quantum-resilience-interview
- https://blockmanity.com/news/5-quantum-resistant-blockchain-projects-worth-watching-in-2026/
- https://www.webopedia.com/crypto/learn/post-quantum-crypto-projects/
- https://medium.com/mochimo-official/mcm-post-quantum-security-in-blockchain-820b3758fa83
- https://cellframe.net/
- https://www.amarchenkova.com/posts/quantum-secure-cryptocurrencies-qrl-mochimo-iota-cardano
- https://thequantumspace.org/2025/11/11/post-quantum-wallets/

### 11.17 Harvest Now, Decrypt Later (HNDL)

- https://www.federalreserve.gov/econres/feds/harvest-now-decrypt-later-examining-post-quantum-cryptography-and-the-data-privacy-risks-for-distributed-ledger-networks.htm
- https://www.federalreserve.gov/econres/feds/files/2025093pap.pdf
- https://a16zcrypto.com/posts/article/quantum-computing-misconceptions-realities-blockchains-planning-migrations/
- https://pmc.ncbi.nlm.nih.gov/articles/PMC8946996/
- https://www.sciencedirect.com/science/article/pii/S2096720923000167
- https://www.schneier.com/blog/archives/2022/02/breaking-245-bit-elliptic-curve-encryption-with-a-quantum-computer.html
- https://crypto.news/bitcoin-investors-face-harvest-now-decrypt-later-quantum-threat/
- https://forklog.com/en/secret-harvesters-why-quantum-computers-threaten-bitcoin-privacy/
- https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later
- https://thequantuminsider.com/2025/10/06/federal-reserve-warns-quantum-computers-could-expose-bitcoins-hidden-past/

### 11.18 Tidecoin Project Sources

- https://tidecoin.org/
- https://tdc-next.vercel.app/
- https://tidecoin.pqcsf.com/
- https://explorer.tidecoin.org/
- https://pool.tidecoin.exchange/
- https://github.com/tidecoin/tidecoin
- https://github.com/tidecoin-old/whitepaper
- https://github.com/tidecoin-old/whitepaper/blob/master/tidecoin.pdf
- https://github.com/tidecoin/tidecoin-android-miner
- https://bitcointalk.org/index.php?topic=5306694.0
- https://bitcourier.co.uk/news/tidecoin-interview
- https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/GZKDF25GYc8
- https://setcoinkr.medium.com/tidecoin-a-post-quantum-security-peer-to-peer-crypto-cash-4c181f55f753
- https://skybaseja.medium.com/tidecoin-a-post-quantum-security-peer-to-peer-crypto-cash-74cbca584140
- https://en.namu.wiki/w/%ED%83%80%EC%9D%B4%EB%93%9C%EC%BD%94%EC%9D%B8
- https://en.everybodywiki.com/Tidecoin
- https://tideidle.com/Tide_specifications/
- https://miningpoolstats.stream/tidecoin
- https://www.coingecko.com/en/coins/tidecoin
- https://coincodex.com/crypto/tidecoin/exchanges/
- https://coinpaprika.com/coin/tdc-tidecoin/
- https://www.livecoinwatch.com/price/Tidecoin-TDC
- https://bscscan.com/token/0x0e182bd5c8703632c4c1761e0496c66c2b5d3385
- https://disboard.org/server/796853997259849728
- https://x.com/tidecoin
- https://x.com/Tidecoin_go
- https://cputest.ru/store/yespower/tidecoin_yespowertide/33
- https://www.mexc.com/price/tidecoin

### 11.19 51% Attack Economics and Mining

- https://www.crypto51.app/
- https://www.crypto51.app/coins/LTC.html
- https://www.coindesk.com/tech/2023/08/02/why-you-should-care-about-litecoin-its-the-backbone-of-dogecoin

### 11.20 General PQC Industry and Educational Sources

- https://blog.cloudflare.com/post-quantum-signatures/
- https://blog.cloudflare.com/another-look-at-pq-signatures/
- https://electricdusk.com/ntt.html (NTT tutorial)
- https://kivicore.com/en/embedded-security-blog/ml-dsa-explained-quantum-safe-digital-signatures-for-secure-embedded-systems
- https://www.encryptionconsulting.com/how-ml-dsa-replaces-ecc-and-rsa-for-digital-signatures/
- https://www.encryptionconsulting.com/overview-of-fips-203/
- https://www.encryptionconsulting.com/decoding-nist-pqc-standards/
- https://utimaco.com/news/blog-posts/nists-final-pqc-standards-are-here-what-you-need-know
- https://hacken.io/insights/ml-dsa-crystals-dilithium/
- https://cloudsecurityalliance.org/blog/2024/08/15/nist-fips-203-204-and-205-finalized-an-important-step-towards-a-quantum-safe-future
- https://www.jbs.cam.ac.uk/2025/why-quantum-matters-now-for-blockchain/
- https://en.wikipedia.org/wiki/NIST_Post-Quantum_Cryptography_Standardization
- https://coinmarketcap.com/cmc-ai/quantum-resistant-ledger/what-is/
- https://www.binance.com/en/square/post/2024-10-29-vitalik-buterin-outlines-quantum-resistant-future-for-ethereum-in-new-roadmap-update-15509117799834
- https://bitcoinist.com/bitcoins-post-quantum-shift-could-take-a-decade-crypto-exec-says/
- https://www.ainvest.com/news/bitcoin-quantum-migration-decade-long-transition-investment-implications-2512/
- https://www.coindesk.com/tech/2025/12/20/bitcoin-s-quantum-debate-is-resurfacing-and-markets-are-starting-to-notice
- https://www.cointribune.com/en/bip-360-bitcoin-divides-over-quantum-challenge/
- https://finance.yahoo.com/news/coinshares-says-only-10-200-170531015.html
- https://ceur-ws.org/Vol-3460/papers/DLT_2023_paper_19.pdf
- https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1457000/full
- https://github.com/veracrypt/VeraCrypt/issues/1271

### 11.21 Academic Papers (Lattice Cryptography)

- https://link.springer.com/article/10.1186/s42400-024-00216-w
- https://www.sciencedirect.com/science/article/abs/pii/S0304397524002895
- https://ietresearch.onlinelibrary.wiley.com/doi/full/10.1049/ise2.12074
- https://www.mdpi.com/1099-4300/24/3/323

---

## 12. Conclusion

The Falcon-512 implementation in the published Tidecoin repository (`https://github.com/tidecoin/tidecoin`) is verified to be the **corrected PQClean "clean" implementation**. The 2019 sampler bug was fixed 15+ months before Tidecoin's genesis block (December 27, 2020). The implementation uses integer emulation (FPEMU) for all floating-point operations, providing constant-time execution with no FPU side channels. The only intentional deviations from upstream PQClean are the relaxed norm bound and corresponding signature size cap, which constitute the "legacy mode" that will be tightened to standard PQClean parameters when AuxPoW activates.

## 2026-10-26: preactivation encoding compatibility

This section concerns compressed-signature decoding, separately from the
historical sampler investigation above. Its source baselines are Tidecoin 0.18.3
at `7b525367e9ea1b614aa380a52394f0e3d3878aa9` (`src/codec.cpp`, `src/pqclean.cpp`)
and the 1.x tree at `fe1f24317b11f42178014c95a65c82c3492df6a3` before this change.

The old decoder accepts a sign bit on a zero coefficient and ignores unused
bits in the final consumed byte. These choices do not change the decoded
coefficients. The 1.x legacy wrapper previously used the canonical PQClean
decoder, which rejects both, although the wrapper already retained the old
norm bound. That made it reject some signatures accepted by 0.18.3 before
activation.

`src/pq/falcon512.c` now contains the old decoder, with its original attribution,
for legacy verification only. The wrapper still requires exact consumption of
the entire compressed body. No trailing bytes or padding are permitted. The
vendored canonical decoder and strict verifier are unchanged, as are local
signing bounds and encodings.

| Check | Canonical encoding | Negative zero / unused final bits | Extra trailing bytes |
| --- | --- | --- | --- |
| Preactivation block signature verification | Verify normally | Verify with old decoder | Reject |
| Preactivation relay signature argument | Verify normally | Hard script error | Existing verification failure |
| Strict signature verification | Verify normally | Reject | Reject |

The new `SCRIPT_VERIFY_FALCON_CANONICAL` flag is set only by mempool
`PolicyScriptChecks`, beside the existing relay-only hash-type flag. It is absent
from block flags, mandatory/shared standard flags and the shared transaction-rule
selector (`common::ScriptFlagsForEra`). It applies even with
`-acceptnonstdtxn=1` and becomes inert when `SCRIPT_VERIFY_PQ_STRICT` is set.
Strict verification retains its existing failed signature semantics, including
scripts that inspect a false signature result.

The format classifier returns true only when the complete detached Falcon-512
buffer decodes under the old rules but not under the canonical rules. It checks
neither the nonce/message/key nor the signature norm. Malformed buffers are left
to normal verification. The interpreter excludes the sighash byte, checks after
hash-type validation and before the signature checker/cache, and checks every
CHECKMULTISIG signature argument before matching. Unexecuted branches and
non-signature data are unaffected. The policy error cannot be inverted by
`OP_NOT`.

The signature cache retains its exact-byte and legacy/strict domains. The
whole-script cache includes the flag word and witness transaction hash. Block
acceptance must not bypass policy, and policy refusal must not prevent old-rule
block acceptance or fetching a canonical witness transaction with the same txid.
Disconnected transactions and persisted entries undergo ordinary admission.

The public fixed vector and dedicated unit tests cover all 128 encodings of one
signature, boundaries, script forms, negation and caches. Functional coverage is
in `feature_falcon_encoding.py` and `rpc_transaction_rules.py`. No old checkout
is required to run these tests. See [PSBT rule selection](../psbt.md) for why
pre-rules completion can succeed while relay refuses the extracted transaction.
