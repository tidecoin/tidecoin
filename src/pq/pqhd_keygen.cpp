#include <pq/pq_api.h>

#include <pq/pqhd_kdf.h>

#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <cstdint>

namespace pq {
namespace {

constexpr uint32_t PQHD_VERSION_V1 = 1;

void WipeAndResetSecret(pq::SecureKeyBytes& sk)
{
    if (sk.data() != nullptr && sk.capacity() > 0) {
        memory_cleanse(sk.data(), sk.capacity());
    }
    pq::SecureKeyBytes{}.swap(sk);
}

} // namespace

bool KeyGenFromSeed(uint32_t pqhd_version,
                    SchemeId scheme_id,
                    std::span<const uint8_t, 64> key_material,
                    std::vector<uint8_t>& pk_out,
                    SecureKeyBytes& sk_out)
{
    pk_out.clear();
    WipeAndResetSecret(sk_out);

    if (pqhd_version != PQHD_VERSION_V1) {
        return false;
    }

    const SchemeInfo* info = SchemeFromId(scheme_id);
    if (!info) {
        return false;
    }

    std::vector<uint8_t> pk_local(info->pubkey_bytes);
    SecureKeyBytes sk_local(info->seckey_bytes);

    size_t seed_len{0};
    switch (scheme_id) {
    case SchemeId::FALCON_512:
    case SchemeId::FALCON_1024:
        seed_len = 48;
        break;
    case SchemeId::MLDSA_44:
    case SchemeId::MLDSA_65:
    case SchemeId::MLDSA_87:
        seed_len = 32;
        break;
    default:
        memory_cleanse(sk_local.data(), sk_local.size());
        return false;
    }

    // Deterministic keypair generation can fail if the internal encoding does not fit in the
    // fixed-size secret key buffers (rare). To make PQHD key generation total and stable,
    // retry deterministically with subsequent stream blocks.
    //
    // This does not change outputs for inputs that already succeeded on the first try.
    int rc = -1;
    for (uint32_t ctr = 0; ctr < kDeterministicKeyGenMaxAttempts; ++ctr) {
        pqhd::KeygenStreamBlock64 block = pqhd::DeriveKeygenStreamBlock(key_material, ctr);

        // Seed is the first seed_len bytes of the stream block.
        std::array<uint8_t, 48> seed48{};
        std::array<uint8_t, 32> seed32{};
        const uint8_t* seed_ptr{nullptr};
        if (seed_len == seed48.size()) {
            std::copy_n(block.begin(), seed48.size(), seed48.begin());
            seed_ptr = seed48.data();
        } else {
            std::copy_n(block.begin(), seed32.size(), seed32.begin());
            seed_ptr = seed32.data();
        }

        if (ConsumeDeterministicKeyGenTestFail()) {
            rc = -1;
        } else {
            switch (scheme_id) {
            case SchemeId::FALCON_512:
                rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(
                    pk_local.data(), sk_local.data(), seed_ptr, seed_len);
                break;
            case SchemeId::FALCON_1024:
                rc = PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair_deterministic(
                    pk_local.data(), sk_local.data(), seed_ptr, seed_len);
                break;
            case SchemeId::MLDSA_44:
                rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_deterministic(
                    pk_local.data(), sk_local.data(), seed_ptr, seed_len);
                break;
            case SchemeId::MLDSA_65:
                rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_deterministic(
                    pk_local.data(), sk_local.data(), seed_ptr, seed_len);
                break;
            case SchemeId::MLDSA_87:
                rc = PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair_deterministic(
                    pk_local.data(), sk_local.data(), seed_ptr, seed_len);
                break;
            default:
                rc = -1;
                break;
            }
        }

        memory_cleanse(seed48.data(), seed48.size());
        memory_cleanse(seed32.data(), seed32.size());
        memory_cleanse(block.data(), block.size());

        if (rc == 0) break;
    }
    if (rc != 0) {
        memory_cleanse(sk_local.data(), sk_local.size());
        return false;
    }

    pk_out = std::move(pk_local);
    sk_out = std::move(sk_local);
    return true;
}

bool KeyGenFromSeedBytes(uint32_t pqhd_version,
                         SchemeId scheme_id,
                         std::span<const uint8_t> key_material,
                         std::vector<uint8_t>& pk_out,
                         SecureKeyBytes& sk_out)
{
    pk_out.clear();
    WipeAndResetSecret(sk_out);
    if (key_material.size() != 64) {
        return false;
    }
    return KeyGenFromSeed(pqhd_version,
                          scheme_id,
                          std::span<const uint8_t, 64>(key_material.data(), 64),
                          pk_out,
                          sk_out);
}

bool KeyGenFromLeafMaterial(uint32_t pqhd_version,
                            const pqhd::LeafMaterialV1& leaf_material,
                            std::vector<uint8_t>& pk_out,
                            SecureKeyBytes& sk_out)
{
    return KeyGenFromSeed(pqhd_version,
                          leaf_material.scheme_id,
                          leaf_material.stream_key.Span(),
                          pk_out,
                          sk_out);
}

} // namespace pq
