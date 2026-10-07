// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sigcache.h>

#include <crypto/sha256.h>
#include <logging.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <span.h>
#include <uint256.h>

#include <mutex>
#include <shared_mutex>
#include <vector>

SignatureCache::SignatureCache(const size_t max_size_bytes)
{
    uint256 nonce = GetRandHash();
    // We want the nonce to be 64 bytes long to force the hasher to process
    // this chunk, which makes later hash computations more efficient. We
    // write our 32-byte entropy, then pad with distinct PQ domain tags
    // (followed by 0 bytes) for 256-bit and strict 512-bit signature hashes.
    static constexpr unsigned char PADDING_PQ[32] = {'P'};
    static constexpr unsigned char PADDING_PQ512[32] = {'P', '5', '1', '2'};
    m_salted_hasher_pq.Write(nonce.begin(), 32);
    m_salted_hasher_pq.Write(PADDING_PQ, 32);
    m_salted_hasher_pq512.Write(nonce.begin(), 32);
    m_salted_hasher_pq512.Write(PADDING_PQ512, 32);

    const auto [num_elems, approx_size_bytes] = setValid.setup_bytes(max_size_bytes);
    LogInfo("Using %zu MiB out of %zu MiB requested for signature cache, able to store %zu elements",
              approx_size_bytes >> 20, max_size_bytes >> 20, num_elems);
}

void SignatureCache::ComputeEntryPQ(uint256& entry, const uint256& hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, bool allow_legacy) const
{
    CSHA256 hasher = m_salted_hasher_pq;
    const unsigned char legacy_tag = allow_legacy ? 1 : 0;
    hasher.Write(hash.begin(), 32).Write(&legacy_tag, 1).Write(pubkey.data(), pubkey.size()).Write(vchSig.data(), vchSig.size()).Finalize(entry.begin());
}

void SignatureCache::ComputeEntryPQ512(uint256& entry, const uint512& hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey) const
{
    CSHA256 hasher = m_salted_hasher_pq512;
    hasher.Write(hash.begin(), hash.size()).Write(pubkey.data(), pubkey.size()).Write(vchSig.data(), vchSig.size()).Finalize(entry.begin());
}

bool SignatureCache::Get(const uint256& entry, const bool erase)
{
    std::shared_lock<std::shared_mutex> lock(cs_sigcache);
    return setValid.contains(entry, erase);
}

void SignatureCache::Set(const uint256& entry)
{
    std::unique_lock<std::shared_mutex> lock(cs_sigcache);
    setValid.insert(entry);
}

bool CachingTransactionSignatureChecker::VerifyPostQuantumSignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    uint256 entry;
    m_signature_cache.ComputeEntryPQ(entry, sighash, vchSig, pubkey, AllowLegacy());
    if (m_signature_cache.Get(entry, !store))
        return true;
    if (!TransactionSignatureChecker::VerifyPostQuantumSignature(vchSig, pubkey, sighash))
        return false;
    if (store)
        m_signature_cache.Set(entry);
    return true;
}

bool CachingTransactionSignatureChecker::VerifyPostQuantumSignature512(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint512& sighash) const
{
    uint256 entry;
    m_signature_cache.ComputeEntryPQ512(entry, sighash, vchSig, pubkey);
    if (m_signature_cache.Get(entry, !store)) return true;
    if (!TransactionSignatureChecker::VerifyPostQuantumSignature512(vchSig, pubkey, sighash)) return false;
    if (store) m_signature_cache.Set(entry);
    return true;
}
