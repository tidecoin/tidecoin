#ifndef TIDECOIN_PQ_PQ_SCHEME_H
#define TIDECOIN_PQ_PQ_SCHEME_H

#include <consensus/params.h>

#include <array>
#include <cstddef>
#include <cstdint>

extern "C" {
#include <pq/falcon-1024/api.h>
#include <pq/falcon-512/api.h>
#include <pq/ml-dsa-44/api.h>
#include <pq/ml-dsa-65/api.h>
#include <pq/ml-dsa-87/api.h>
}

namespace pq {

// Scheme ID prefixes for serialized public keys.
constexpr uint8_t kSchemePrefixFalcon512 = 0x07;
constexpr uint8_t kSchemePrefixFalcon1024 = 0x08;
constexpr uint8_t kSchemePrefixMLDSA44 = 0x09;
constexpr uint8_t kSchemePrefixMLDSA65 = 0x0A;
constexpr uint8_t kSchemePrefixMLDSA87 = 0x0B;


constexpr uint8_t kSchemePrefixExperimentalMin = 0xF0;
constexpr uint8_t kSchemePrefixExperimentalMax = 0xFF;

constexpr uint8_t kFalcon512SigHeader = 0x30 + 9;
constexpr uint8_t kFalcon1024SigHeader = 0x30 + 10;

enum class SchemeId : uint8_t {
    FALCON_512 = kSchemePrefixFalcon512,
    FALCON_1024 = kSchemePrefixFalcon1024,
    MLDSA_44 = kSchemePrefixMLDSA44,
    MLDSA_65 = kSchemePrefixMLDSA65,
    MLDSA_87 = kSchemePrefixMLDSA87,
};

struct SchemeInfo {
    SchemeId id;
    uint8_t prefix;
    size_t pubkey_bytes;
    size_t seckey_bytes;
    size_t sig_bytes_max;
    size_t sig_bytes_fixed;
    const char* name;
};

inline constexpr SchemeInfo kFalcon512Info{
    SchemeId::FALCON_512,
    kSchemePrefixFalcon512,
    PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES,
    PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES,
    "Falcon-512",
};

inline constexpr SchemeInfo kFalcon1024Info{
    SchemeId::FALCON_1024,
    kSchemePrefixFalcon1024,
    PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES,
    PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES,
    "Falcon-1024",
};

inline constexpr SchemeInfo kMLDSA44Info{
    SchemeId::MLDSA_44,
    kSchemePrefixMLDSA44,
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
    "ML-DSA-44",
};

inline constexpr SchemeInfo kMLDSA65Info{
    SchemeId::MLDSA_65,
    kSchemePrefixMLDSA65,
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES,
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES,
    "ML-DSA-65",
};

inline constexpr SchemeInfo kMLDSA87Info{
    SchemeId::MLDSA_87,
    kSchemePrefixMLDSA87,
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES,
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES,
    "ML-DSA-87",
};

inline constexpr std::array<const SchemeInfo*, 5> kKnownSchemes{
    &kFalcon512Info,
    &kFalcon1024Info,
    &kMLDSA44Info,
    &kMLDSA65Info,
    &kMLDSA87Info,
};

constexpr size_t MaxKnownSigBytes(bool use_max_sig)
{
    size_t max_len = 0;
    for (const auto* info : kKnownSchemes) {
        const size_t sig_len = use_max_sig ? info->sig_bytes_max : info->sig_bytes_fixed;
        if (sig_len > max_len) max_len = sig_len;
    }
    return max_len;
}

constexpr size_t MaxKnownSigBytesInScript(bool use_max_sig)
{
    return MaxKnownSigBytes(use_max_sig) + 1; // +1 for sighash byte
}

constexpr size_t MaxKnownPubKeyBytes()
{
    size_t max_len = 0;
    for (const auto* info : kKnownSchemes) {
        if (info->pubkey_bytes > max_len) max_len = info->pubkey_bytes;
    }
    return max_len;
}

constexpr size_t MaxKnownPubKeyBytesInScript()
{
    return MaxKnownPubKeyBytes() + 1; // +1 for scheme prefix
}

constexpr bool IsExperimentalPrefix(uint8_t prefix)
{
    return prefix >= kSchemePrefixExperimentalMin && prefix <= kSchemePrefixExperimentalMax;
}

constexpr const SchemeInfo* SchemeFromPrefix(uint8_t prefix)
{
    switch (prefix) {
    case kSchemePrefixFalcon512:
        return &kFalcon512Info;
    case kSchemePrefixFalcon1024:
        return &kFalcon1024Info;
    case kSchemePrefixMLDSA44:
        return &kMLDSA44Info;
    case kSchemePrefixMLDSA65:
        return &kMLDSA65Info;
    case kSchemePrefixMLDSA87:
        return &kMLDSA87Info;
    default:
        return nullptr;
    }
}

constexpr const SchemeInfo* SchemeFromId(SchemeId id)
{
    return SchemeFromPrefix(static_cast<uint8_t>(id));
}

inline bool IsSchemeAllowedAtHeight(SchemeId id, const Consensus::Params& params, int height)
{
    if (SchemeFromId(id) == nullptr) return false;
    if (height < params.nAuxpowStartHeight) {
        return id == SchemeId::FALCON_512;
    }
    return true;
}

} // namespace pq

#endif // TIDECOIN_PQ_PQ_SCHEME_H
