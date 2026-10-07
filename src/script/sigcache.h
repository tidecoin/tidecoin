// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGCACHE_H
#define BITCOIN_SCRIPT_SIGCACHE_H

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <cuckoocache.h>
#include <script/interpreter.h>
#include <span.h>
#include <uint256.h>
#include <uint512.h>
#include <util/hasher.h>

#include <cstddef>
#include <shared_mutex>
#include <vector>

class CPubKey;
class CTransaction;

// DoS prevention: limit cache size to 64MiB
static constexpr size_t DEFAULT_VALIDATION_CACHE_BYTES{64 << 20};
static constexpr size_t DEFAULT_SIGNATURE_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static constexpr size_t DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static_assert(DEFAULT_VALIDATION_CACHE_BYTES == DEFAULT_SIGNATURE_CACHE_BYTES + DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES);

/**
 * Valid signature cache, to avoid doing expensive Post Quantum signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class SignatureCache
{
private:
    //! Entries are SHA256(nonce || 'P' || 31 zero bytes || signature hash || legacy_tag || public key || signature):
    CSHA256 m_salted_hasher_pq;
    //! Strict 512-bit entries use a separate domain and the entire signature hash.
    CSHA256 m_salted_hasher_pq512;
    typedef CuckooCache::cache<uint256, SignatureCacheHasher> map_type;
    map_type setValid;
    std::shared_mutex cs_sigcache;

public:
    SignatureCache(size_t max_size_bytes);

    SignatureCache(const SignatureCache&) = delete;
    SignatureCache& operator=(const SignatureCache&) = delete;

    void ComputeEntryPQ(uint256& entry, const uint256& hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, bool allow_legacy) const;
    void ComputeEntryPQ512(uint256& entry, const uint512& hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey) const;

    bool Get(const uint256& entry, const bool erase);

    void Set(const uint256& entry);
};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    bool store;
    SignatureCache& m_signature_cache;

public:
    CachingTransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, bool storeIn, SignatureCache& signature_cache, PrecomputedTransactionData& txdataIn, bool allow_legacy = false) : TransactionSignatureChecker(txToIn, nInIn, amountIn, txdataIn, MissingDataBehavior::ASSERT_FAIL, allow_legacy), store(storeIn), m_signature_cache(signature_cache)  {}

    bool VerifyPostQuantumSignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const override;
    bool VerifyPostQuantumSignature512(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint512& sighash) const override;
};

#endif // BITCOIN_SCRIPT_SIGCACHE_H
