#ifndef TIDECOIN_PQ_API_H
#define TIDECOIN_PQ_API_H

#include <pq/pq_scheme.h>
#include <pq/pqhd_kdf.h>
#include <pq/randombytes.h>
#include <pq/ml-kem-512/api.h>

#include <support/allocators/secure.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <span>
#include <vector>

extern "C" {
int tidecoin_falcon512_pubkey_from_sk(const uint8_t* sk, size_t sklen,
                                      uint8_t* pk, size_t pklen);
int tidecoin_falcon512_sign_legacy(uint8_t* sig, size_t* siglen,
                                   const uint8_t* m, size_t mlen,
                                   const uint8_t* sk, size_t sklen);
int tidecoin_falcon512_verify(const uint8_t* sig, size_t siglen,
                              const uint8_t* m, size_t mlen,
                              const uint8_t* pk, size_t pklen,
                              int legacy_mode);
int tidecoin_falcon1024_pubkey_from_sk(const uint8_t* sk, size_t sklen,
                                       uint8_t* pk, size_t pklen);
int tidecoin_mldsa44_pubkey_from_sk(const uint8_t* sk, size_t sklen,
                                    uint8_t* pk, size_t pklen);
int tidecoin_mldsa65_pubkey_from_sk(const uint8_t* sk, size_t sklen,
                                    uint8_t* pk, size_t pklen);
int tidecoin_mldsa87_pubkey_from_sk(const uint8_t* sk, size_t sklen,
                                    uint8_t* pk, size_t pklen);
}

namespace pq {

/** Secure byte container (locked + cleansed on deallocation). */
using SecureKeyBytes = std::vector<uint8_t, secure_allocator<uint8_t>>;

constexpr unsigned int kFalconSignMaxAttempts = 10000;
constexpr unsigned int kDeterministicKeyGenMaxAttempts = 1024;

// Test-only override to force Falcon sign attempts to fail (simulates PQClean failures).
inline std::atomic<int> g_falcon_sign_test_fail_count{0};
// Test-only override to force deterministic PQHD keygen attempts to fail.
inline std::atomic<int> g_deterministic_keygen_test_fail_count{0};

inline void SetFalconSignTestFailCount(int count)
{
    g_falcon_sign_test_fail_count.store(count, std::memory_order_relaxed);
}

inline int GetFalconSignTestFailCount()
{
    return g_falcon_sign_test_fail_count.load(std::memory_order_relaxed);
}

inline void SetDeterministicKeyGenTestFailCount(int count)
{
    g_deterministic_keygen_test_fail_count.store(count, std::memory_order_relaxed);
}

inline int GetDeterministicKeyGenTestFailCount()
{
    return g_deterministic_keygen_test_fail_count.load(std::memory_order_relaxed);
}

inline bool ConsumeFalconSignTestFail()
{
    int expected = g_falcon_sign_test_fail_count.load(std::memory_order_relaxed);
    while (expected > 0) {
        if (g_falcon_sign_test_fail_count.compare_exchange_weak(
                expected, expected - 1, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

inline bool ConsumeDeterministicKeyGenTestFail()
{
    int expected = g_deterministic_keygen_test_fail_count.load(std::memory_order_relaxed);
    while (expected > 0) {
        if (g_deterministic_keygen_test_fail_count.compare_exchange_weak(
                expected, expected - 1, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

constexpr size_t MLKEM512_PUBLICKEY_BYTES = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES;
constexpr size_t MLKEM512_SECRETKEY_BYTES = PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES;
constexpr size_t MLKEM512_CIPHERTEXT_BYTES = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES;
constexpr size_t MLKEM512_SHARED_SECRET_BYTES = PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES;
constexpr size_t MLKEM512_KEYPAIR_COINS_BYTES = 2 * MLKEM512_SHARED_SECRET_BYTES;

class MLKEM512Keypair
{
public:
    MLKEM512Keypair() = default;
    ~MLKEM512Keypair();
    MLKEM512Keypair(const MLKEM512Keypair&) = delete;
    MLKEM512Keypair& operator=(const MLKEM512Keypair&) = delete;
    MLKEM512Keypair(MLKEM512Keypair&&) = delete;
    MLKEM512Keypair& operator=(MLKEM512Keypair&&) = delete;

    bool Generate();
    bool GenerateDeterministic(std::span<const uint8_t> coins);
    bool Set(std::span<const uint8_t> pk, std::span<const uint8_t> sk);

    bool IsInitialized() const noexcept { return m_initialized; }
    std::span<const uint8_t> PublicKey() const noexcept { return m_pk; }
    std::span<const uint8_t> SecretKey() const noexcept { return m_sk; }

private:
    std::array<uint8_t, MLKEM512_PUBLICKEY_BYTES> m_pk{};
    std::array<uint8_t, MLKEM512_SECRETKEY_BYTES> m_sk{};
    bool m_initialized{false};
};

bool MLKEM512Encaps(std::span<const uint8_t> pk,
                    std::span<uint8_t> ct,
                    std::span<uint8_t> ss);
bool MLKEM512EncapsDeterministic(std::span<const uint8_t> pk,
                                 std::span<const uint8_t> coins,
                                 std::span<uint8_t> ct,
                                 std::span<uint8_t> ss);
bool MLKEM512Decaps(std::span<const uint8_t> ct,
                    std::span<const uint8_t> sk,
                    std::span<uint8_t> ss);

inline bool ComputeMLDSA44PublicKey(std::span<const unsigned char> sk,
                                    std::span<unsigned char> pk_out)
{
    return tidecoin_mldsa44_pubkey_from_sk(sk.data(), sk.size(), pk_out.data(), pk_out.size()) == 0;
}

inline bool ComputeMLDSA65PublicKey(std::span<const unsigned char> sk,
                                    std::span<unsigned char> pk_out)
{
    return tidecoin_mldsa65_pubkey_from_sk(sk.data(), sk.size(), pk_out.data(), pk_out.size()) == 0;
}

inline bool ComputeMLDSA87PublicKey(std::span<const unsigned char> sk,
                                    std::span<unsigned char> pk_out)
{
    return tidecoin_mldsa87_pubkey_from_sk(sk.data(), sk.size(), pk_out.data(), pk_out.size()) == 0;
}

inline bool ComputeFalcon512PublicKey(std::span<const unsigned char> sk,
                                      std::span<unsigned char> pk_out)
{
    return tidecoin_falcon512_pubkey_from_sk(sk.data(), sk.size(), pk_out.data(), pk_out.size()) == 0;
}

inline bool ComputeFalcon1024PublicKey(std::span<const unsigned char> sk,
                                       std::span<unsigned char> pk_out)
{
    return tidecoin_falcon1024_pubkey_from_sk(sk.data(), sk.size(), pk_out.data(), pk_out.size()) == 0;
}

inline bool DecodePubKey(std::span<const unsigned char> raw,
                         SchemeId& id,
                         std::span<const unsigned char>& pk)
{
    if (raw.empty()) {
        return false;
    }
    const SchemeInfo* info = SchemeFromPrefix(raw[0]);
    if (!info) {
        return false;
    }
    const size_t expected = info->pubkey_bytes + 1;
    if (raw.size() != expected) {
        return false;
    }
    id = info->id;
    pk = raw.subspan(1);
    return true;
}

inline bool EncodePubKey(SchemeId id,
                         std::span<const unsigned char> pk,
                         std::vector<unsigned char>& out)
{
    const SchemeInfo* info = SchemeFromId(id);
    if (!info || pk.size() != info->pubkey_bytes) {
        return false;
    }
    out.resize(info->pubkey_bytes + 1);
    out[0] = info->prefix;
    std::copy(pk.begin(), pk.end(), out.begin() + 1);
    return true;
}

inline bool IsSecretKeyEncodingValid(const SchemeInfo& info,
                                     std::span<const unsigned char> sk)
{
    if (sk.size() != info.seckey_bytes) {
        return false;
    }
    switch (info.id) {
    case SchemeId::FALCON_512:
        return sk[0] == static_cast<unsigned char>(0x50 + 9);
    case SchemeId::FALCON_1024:
        return sk[0] == static_cast<unsigned char>(0x50 + 10);
    case SchemeId::MLDSA_44:
    case SchemeId::MLDSA_65:
    case SchemeId::MLDSA_87:
        return true;
    default:
        return false;
    }
}

inline const SchemeInfo* IdentifySecretKey(std::span<const unsigned char> sk)
{
    if (IsSecretKeyEncodingValid(kFalcon512Info, sk)) {
        return &kFalcon512Info;
    }
    if (IsSecretKeyEncodingValid(kFalcon1024Info, sk)) {
        return &kFalcon1024Info;
    }
    if (IsSecretKeyEncodingValid(kMLDSA44Info, sk)) {
        return &kMLDSA44Info;
    }
    if (IsSecretKeyEncodingValid(kMLDSA65Info, sk)) {
        return &kMLDSA65Info;
    }
    if (IsSecretKeyEncodingValid(kMLDSA87Info, sk)) {
        return &kMLDSA87Info;
    }
    return nullptr;
}

inline bool DecodeSecretKey(std::span<const unsigned char> input,
                            const SchemeInfo*& info,
                            std::span<const unsigned char>& raw,
                            bool allow_legacy = true)
{
    if (input.empty()) {
        return false;
    }

    if (const SchemeInfo* prefixed = SchemeFromPrefix(input[0])) {
        if (input.size() == prefixed->seckey_bytes + 1) {
            raw = input.subspan(1);
            if (!IsSecretKeyEncodingValid(*prefixed, raw)) {
                return false;
            }
            info = prefixed;
            return true;
        }
    }

    if (!allow_legacy) {
        return false;
    }

    info = IdentifySecretKey(input);
    if (!info) {
        return false;
    }
    raw = input;
    return true;
}

template <typename Alloc>
inline bool EncodeSecretKey(const SchemeInfo& info,
                            std::span<const unsigned char> raw,
                            std::vector<unsigned char, Alloc>& out,
                            bool include_prefix = true)
{
    if (!IsSecretKeyEncodingValid(info, raw)) {
        return false;
    }
    if (include_prefix) {
        out.resize(raw.size() + 1);
        out[0] = info.prefix;
        std::copy(raw.begin(), raw.end(), out.begin() + 1);
        return true;
    }
    out.assign(raw.begin(), raw.end());
    return true;
}

inline bool ComputePublicKeyFromSecret(const SchemeInfo& info,
                                       std::span<const unsigned char> sk,
                                       std::span<unsigned char> pk_out)
{
    if (!IsSecretKeyEncodingValid(info, sk) || pk_out.size() != info.pubkey_bytes) {
        return false;
    }
    switch (info.id) {
    case SchemeId::FALCON_512:
        return ComputeFalcon512PublicKey(sk, pk_out);
    case SchemeId::FALCON_1024:
        return ComputeFalcon1024PublicKey(sk, pk_out);
    case SchemeId::MLDSA_44:
        return ComputeMLDSA44PublicKey(sk, pk_out);
    case SchemeId::MLDSA_65:
        return ComputeMLDSA65PublicKey(sk, pk_out);
    case SchemeId::MLDSA_87:
        return ComputeMLDSA87PublicKey(sk, pk_out);
    default:
        break;
    }

    return false;
}

inline bool GenerateKeyPair(const SchemeInfo& info,
                            std::span<unsigned char> pk,
                            std::span<unsigned char> sk)
{
    if (pk.size() != info.pubkey_bytes || sk.size() != info.seckey_bytes) {
        return false;
    }

    // Non-deterministic key generation for ad-hoc keys (e.g. tests, legacy flows).
    // PQHD deterministic wallets must use `KeyGenFromSeed()` on PQHD-derived material.
    constexpr unsigned int kFalconKeypairMaxAttempts = 10000;
    switch (info.id) {
    case SchemeId::FALCON_512:
        for (unsigned int attempt = 0; attempt < kFalconKeypairMaxAttempts; ++attempt) {
            if (PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) == 0) {
                return true;
            }
        }
        return false;
    case SchemeId::FALCON_1024:
        for (unsigned int attempt = 0; attempt < kFalconKeypairMaxAttempts; ++attempt) {
            if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) == 0) {
                return true;
            }
        }
        return false;
    case SchemeId::MLDSA_44:
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) == 0;
    case SchemeId::MLDSA_65:
        return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) == 0;
    case SchemeId::MLDSA_87:
        return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) == 0;
    default:
        return false;
    }
}

inline bool Sign(const SchemeInfo& info,
                 std::span<const unsigned char> msg32,
                 std::span<const unsigned char> sk,
                 std::vector<unsigned char>& sig_out,
                 bool legacy_mode)
{
    if (msg32.size() != 32 || sk.size() != info.seckey_bytes) {
        return false;
    }
    switch (info.id) {
    case SchemeId::FALCON_512: {
        sig_out.resize(info.sig_bytes_max);
        if (legacy_mode) {
            size_t sig_len = 0;
            const int r = tidecoin_falcon512_sign_legacy(sig_out.data(), &sig_len,
                                                         msg32.data(), msg32.size(),
                                                         sk.data(), sk.size());
            if (r != 0) {
                return false;
            }
            sig_out.resize(sig_len);
            return true;
        }
        for (unsigned int attempt = 0; attempt < kFalconSignMaxAttempts; ++attempt) {
            if (ConsumeFalconSignTestFail()) {
                continue;
            }
            size_t sig_len = 0;
            const int r = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
                sig_out.data(), &sig_len, msg32.data(), msg32.size(), sk.data());
            if (r == 0) {
                sig_out.resize(sig_len);
                return true;
            }
        }
        return false;
    }
    case SchemeId::FALCON_1024: {
        sig_out.resize(info.sig_bytes_max);
        for (unsigned int attempt = 0; attempt < kFalconSignMaxAttempts; ++attempt) {
            if (ConsumeFalconSignTestFail()) {
                continue;
            }
            size_t sig_len = 0;
            const int r = PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
                sig_out.data(), &sig_len, msg32.data(), msg32.size(), sk.data());
            if (r == 0) {
                sig_out.resize(sig_len);
                return true;
            }
        }
        return false;
    }
    case SchemeId::MLDSA_44: {
        size_t sig_len = 0;
        sig_out.resize(info.sig_bytes_max);
        const int r = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
            sig_out.data(), &sig_len, msg32.data(), msg32.size(), sk.data());
        if (r != 0) {
            return false;
        }
        sig_out.resize(sig_len);
        return true;
    }
    case SchemeId::MLDSA_65: {
        size_t sig_len = 0;
        sig_out.resize(info.sig_bytes_max);
        const int r = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
            sig_out.data(), &sig_len, msg32.data(), msg32.size(), sk.data());
        if (r != 0) {
            return false;
        }
        sig_out.resize(sig_len);
        return true;
    }
    case SchemeId::MLDSA_87: {
        size_t sig_len = 0;
        sig_out.resize(info.sig_bytes_max);
        const int r = PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(
            sig_out.data(), &sig_len, msg32.data(), msg32.size(), sk.data());
        if (r != 0) {
            return false;
        }
        sig_out.resize(sig_len);
        return true;
    }
    default:
        return false;
    }
}

inline bool Sign64(const SchemeInfo& info,
                   std::span<const unsigned char> msg64,
                   std::span<const unsigned char> sk,
                   std::vector<unsigned char>& sig_out,
                   bool legacy_mode)
{
    if (msg64.size() != 64 || sk.size() != info.seckey_bytes) {
        return false;
    }
    switch (info.id) {
    case SchemeId::FALCON_512: {
        sig_out.resize(info.sig_bytes_max);
        if (legacy_mode) {
            size_t sig_len = 0;
            const int r = tidecoin_falcon512_sign_legacy(sig_out.data(), &sig_len,
                                                         msg64.data(), msg64.size(),
                                                         sk.data(), sk.size());
            if (r != 0) {
                return false;
            }
            sig_out.resize(sig_len);
            return true;
        }
        for (unsigned int attempt = 0; attempt < kFalconSignMaxAttempts; ++attempt) {
            if (ConsumeFalconSignTestFail()) {
                continue;
            }
            size_t sig_len = 0;
            const int r = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
                sig_out.data(), &sig_len, msg64.data(), msg64.size(), sk.data());
            if (r == 0) {
                sig_out.resize(sig_len);
                return true;
            }
        }
        return false;
    }
    case SchemeId::FALCON_1024: {
        sig_out.resize(info.sig_bytes_max);
        for (unsigned int attempt = 0; attempt < kFalconSignMaxAttempts; ++attempt) {
            if (ConsumeFalconSignTestFail()) {
                continue;
            }
            size_t sig_len = 0;
            const int r = PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
                sig_out.data(), &sig_len, msg64.data(), msg64.size(), sk.data());
            if (r == 0) {
                sig_out.resize(sig_len);
                return true;
            }
        }
        return false;
    }
    case SchemeId::MLDSA_44: {
        size_t sig_len = 0;
        sig_out.resize(info.sig_bytes_max);
        const int r = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
            sig_out.data(), &sig_len, msg64.data(), msg64.size(), sk.data());
        if (r != 0) {
            return false;
        }
        sig_out.resize(sig_len);
        return true;
    }
    case SchemeId::MLDSA_65: {
        size_t sig_len = 0;
        sig_out.resize(info.sig_bytes_max);
        const int r = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
            sig_out.data(), &sig_len, msg64.data(), msg64.size(), sk.data());
        if (r != 0) {
            return false;
        }
        sig_out.resize(sig_len);
        return true;
    }
    case SchemeId::MLDSA_87: {
        size_t sig_len = 0;
        sig_out.resize(info.sig_bytes_max);
        const int r = PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(
            sig_out.data(), &sig_len, msg64.data(), msg64.size(), sk.data());
        if (r != 0) {
            return false;
        }
        sig_out.resize(sig_len);
        return true;
    }
    default:
        return false;
    }
}

inline bool Verify(const SchemeInfo& info,
                   std::span<const unsigned char> msg32,
                   std::span<const unsigned char> sig,
                   std::span<const unsigned char> pk,
                   bool legacy_mode)
{
    (void)legacy_mode;
    if (msg32.size() != 32 || pk.size() != info.pubkey_bytes) {
        return false;
    }
    switch (info.id) {
    case SchemeId::FALCON_512:
        return tidecoin_falcon512_verify(sig.data(), sig.size(),
                                         msg32.data(), msg32.size(),
                                         pk.data(), pk.size(),
                                         legacy_mode) == 0;
    case SchemeId::FALCON_1024:
        return PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg32.data(), msg32.size(), pk.data()) == 0;
    case SchemeId::MLDSA_44:
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg32.data(), msg32.size(), pk.data()) == 0;
    case SchemeId::MLDSA_65:
        return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg32.data(), msg32.size(), pk.data()) == 0;
    case SchemeId::MLDSA_87:
        return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg32.data(), msg32.size(), pk.data()) == 0;
    default:
        return false;
    }
}

inline bool Verify64(const SchemeInfo& info,
                     std::span<const unsigned char> msg64,
                     std::span<const unsigned char> sig,
                     std::span<const unsigned char> pk,
                     bool legacy_mode)
{
    (void)legacy_mode;
    if (msg64.size() != 64 || pk.size() != info.pubkey_bytes) {
        return false;
    }
    switch (info.id) {
    case SchemeId::FALCON_512:
        return tidecoin_falcon512_verify(sig.data(), sig.size(),
                                         msg64.data(), msg64.size(),
                                         pk.data(), pk.size(),
                                         legacy_mode) == 0;
    case SchemeId::FALCON_1024:
        return PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg64.data(), msg64.size(), pk.data()) == 0;
    case SchemeId::MLDSA_44:
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg64.data(), msg64.size(), pk.data()) == 0;
    case SchemeId::MLDSA_65:
        return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg64.data(), msg64.size(), pk.data()) == 0;
    case SchemeId::MLDSA_87:
        return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg64.data(), msg64.size(), pk.data()) == 0;
    default:
        return false;
    }
}

inline bool VerifyPrefixed(std::span<const unsigned char> msg32,
                           std::span<const unsigned char> sig,
                           std::span<const unsigned char> prefixed_pubkey,
                           bool legacy_mode)
{
    SchemeId id{};
    std::span<const unsigned char> raw;
    if (!DecodePubKey(prefixed_pubkey, id, raw)) {
        return false;
    }
    const SchemeInfo* info = SchemeFromId(id);
    return info && Verify(*info, msg32, sig, raw, legacy_mode);
}

inline bool VerifyPrefixed64(std::span<const unsigned char> msg64,
                             std::span<const unsigned char> sig,
                             std::span<const unsigned char> prefixed_pubkey,
                             bool legacy_mode)
{
    SchemeId id{};
    std::span<const unsigned char> raw;
    if (!DecodePubKey(prefixed_pubkey, id, raw)) {
        return false;
    }
    const SchemeInfo* info = SchemeFromId(id);
    return info && Verify64(*info, msg64, sig, raw, legacy_mode);
}

/** PQHD v1+ deterministic key generation. */
[[nodiscard]] bool KeyGenFromSeed(uint32_t pqhd_version,
                                  SchemeId scheme_id,
                                  std::span<const uint8_t, 64> key_material,
                                  std::vector<uint8_t>& pk_out,
                                  SecureKeyBytes& sk_out);

/** PQHD v1+ key generation from an untrusted byte span (length must be 64). */
[[nodiscard]] bool KeyGenFromSeedBytes(uint32_t pqhd_version,
                                       SchemeId scheme_id,
                                       std::span<const uint8_t> key_material,
                                       std::vector<uint8_t>& pk_out,
                                       SecureKeyBytes& sk_out);

/** PQHD v1+ key generation from strongly-typed leaf material (scheme id + key material bound together). */
[[nodiscard]] bool KeyGenFromLeafMaterial(uint32_t pqhd_version,
                                          const pqhd::LeafMaterialV1& leaf_material,
                                          std::vector<uint8_t>& pk_out,
                                          SecureKeyBytes& sk_out);

} // namespace pq

#endif // TIDECOIN_PQ_API_H
