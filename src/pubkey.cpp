// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>

#include <hash.h>
#include <pq/pq_api.h>
#include <span.h>
#include <uint256.h>
#include <uint512.h>

#include <algorithm>
#include <cstring>
#include <cassert>
#include <vector>

bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig, bool legacy_mode) const {
    if (!IsValid()) {
        return false;
    }
    return pq::VerifyPrefixed(std::span<const unsigned char>{hash.begin(), 32},
                              vchSig,
                              std::span<const unsigned char>{begin(), size()},
                              legacy_mode);
}

bool CPubKey::Verify512(const uint512& hash, const std::vector<unsigned char>& vchSig, bool legacy_mode) const
{
    if (!IsValid()) {
        return false;
    }
    return pq::VerifyPrefixed64(std::span<const unsigned char>{hash.begin(), uint512::size()},
                                vchSig,
                                std::span<const unsigned char>{begin(), size()},
                                legacy_mode);
}

bool CPubKey::Recover(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    const auto msg32 = std::span<const unsigned char>{hash.begin(), 32};

    // Tidecoin does not have a recovery ID for PQ signatures. For message signing,
    // recovery is achieved by embedding the raw scheme pubkey bytes in the signature:
    //
    //   sig = signature_bytes || pubkey_bytes_without_prefix
    //
    // This function recovers by trying each known scheme and verifying.
    for (const pq::SchemeInfo* scheme : {&pq::kFalcon512Info, &pq::kFalcon1024Info, &pq::kMLDSA44Info, &pq::kMLDSA65Info, &pq::kMLDSA87Info}) {
        const size_t raw_pk_len = scheme->pubkey_bytes;
        if (vchSig.size() <= raw_pk_len) {
            continue;
        }
        const size_t sig_len = vchSig.size() - raw_pk_len;

        std::vector<unsigned char> prefixed_pubkey(raw_pk_len + 1);
        prefixed_pubkey[0] = scheme->prefix;
        std::memcpy(prefixed_pubkey.data() + 1, vchSig.data() + sig_len, raw_pk_len);

        const std::span<const unsigned char> prefixed_pk_span{prefixed_pubkey.data(), prefixed_pubkey.size()};
        const std::span<const unsigned char> sig_span{vchSig.data(), sig_len};

        // Signed messages have no activation height. Preserve compatibility
        // with the legacy Falcon-512 verifier after trying the strict rules.
        if (pq::VerifyPrefixed(msg32, sig_span, prefixed_pk_span, /*legacy_mode=*/false) ||
            (scheme->id == pq::SchemeId::FALCON_512 &&
             pq::VerifyPrefixed(msg32, sig_span, prefixed_pk_span, /*legacy_mode=*/true))) {
            Set(prefixed_pk_span.begin(), prefixed_pk_span.end());
            return true;
        }
    }

    return false;
}

bool CPubKey::IsFullyValid() const {
    return IsValid() && pq::IsValidPubKey(std::span<const unsigned char>{begin(), size()});
}
