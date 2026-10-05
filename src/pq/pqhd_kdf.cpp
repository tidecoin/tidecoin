#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>

#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <crypto/sha256.h>

#include <support/cleanse.h>

#include <algorithm>
#include <cstring>

namespace pqhd {
namespace {

constexpr const char* PQHD_MASTER_KEY = "Tidecoin PQHD seed";
constexpr const char* PQHD_HKDF_SALT = "Tidecoin PQHD hkdf v1";
constexpr const char* PQHD_STREAM_INFO = "Tidecoin PQHD stream key v1";
constexpr const char* PQHD_RNG_PREFIX = "Tidecoin PQHD rng v1";
constexpr const char* PQHD_SEEDID_TAG = "Tidecoin PQHD seedid v1";

KeygenStreamKey64 HmacSha512(std::span<const uint8_t> key, std::span<const uint8_t> msg)
{
    KeygenStreamKey64 out;
    CHMAC_SHA512(key.data(), key.size()).Write(msg.data(), msg.size()).Finalize(out.data());
    return out;
}

std::array<uint8_t, 4> Ser32BE(uint32_t v)
{
    std::array<uint8_t, 4> out{};
    WriteBE32(out.data(), v);
    return out;
}

} // namespace

SeedID32 ComputeSeedID32(std::span<const uint8_t, 32> master_seed)
{
    SeedID32 out{};
    CSHA256 hasher;
    const ScopedMemoryCleanse cleanse_hasher{&hasher, sizeof(hasher)};
    hasher
        .Write(reinterpret_cast<const uint8_t*>(PQHD_SEEDID_TAG), std::strlen(PQHD_SEEDID_TAG))
        .Write(master_seed.data(), master_seed.size())
        .Finalize(out.data());
    return out;
}

uint256 SeedID32ToUint256(std::span<const uint8_t, 32> seedid_be)
{
    std::array<unsigned char, 32> seedid_le{};
    std::reverse_copy(seedid_be.begin(), seedid_be.end(), seedid_le.begin());
    return uint256{std::span<const unsigned char>(seedid_le)};
}

SeedID32 SeedID32FromUint256(const uint256& seed_id)
{
    SeedID32 seedid_be{};
    std::reverse_copy(seed_id.begin(), seed_id.end(), seedid_be.begin());
    return seedid_be;
}

uint256 ComputeSeedID32AsUint256(std::span<const uint8_t, 32> master_seed)
{
    return SeedID32ToUint256(ComputeSeedID32(master_seed));
}

Node MakeMasterNode(std::span<const uint8_t, 32> master_seed)
{
    const std::span<const uint8_t> key{reinterpret_cast<const uint8_t*>(PQHD_MASTER_KEY),
                                       std::strlen(PQHD_MASTER_KEY)};
    auto I = HmacSha512(key, master_seed);

    Node out{};
    std::copy_n(I.begin(), 32, out.node_secret.begin());
    std::copy_n(I.begin() + 32, 32, out.chain_code.begin());
    memory_cleanse(I.data(), I.size());
    return out;
}

std::optional<Node> DeriveChild(const Node& parent, uint32_t index_hardened)
{
    // PQHD v1 is hardened-only.
    if ((index_hardened & 0x80000000U) == 0) return std::nullopt;

    std::array<uint8_t, 1 + 32 + 4> data{};
    const ScopedMemoryCleanse cleanse_data{data.data(), data.size()};
    data[0] = 0x00;
    std::copy(parent.node_secret.begin(), parent.node_secret.end(), data.begin() + 1);
    const auto ser = Ser32BE(index_hardened);
    std::copy(ser.begin(), ser.end(), data.begin() + 1 + parent.node_secret.size());

    auto I = HmacSha512(parent.chain_code, data);
    memory_cleanse(data.data(), data.size());

    Node out{};
    std::copy_n(I.begin(), 32, out.node_secret.begin());
    std::copy_n(I.begin() + 32, 32, out.chain_code.begin());
    memory_cleanse(I.data(), I.size());
    return out;
}

std::optional<Node> DerivePath(const Node& master, std::span<const uint32_t> path_hardened)
{
    Node node = master;
    for (const uint32_t i : path_hardened) {
        auto child = DeriveChild(node, i);
        if (!child) return std::nullopt;
        node = std::move(*child);
    }
    return node;
}

bool ValidateV1LeafPath(std::span<const uint32_t> path_hardened)
{
    constexpr uint32_t HARDENED = 0x80000000U;
    constexpr size_t V1_PATH_LEN = 6;

    if (path_hardened.size() != V1_PATH_LEN) return false;
    for (const uint32_t elem : path_hardened) {
        if ((elem & HARDENED) == 0) return false;
    }
    if (path_hardened[0] != (HARDENED | pqhd::PURPOSE)) return false;
    if (path_hardened[1] != (HARDENED | pqhd::COIN_TYPE)) return false;

    const uint32_t scheme_u32 = path_hardened[2] & ~HARDENED;
    if (scheme_u32 > 0xFFU) return false;
    if (pq::SchemeFromId(static_cast<pq::SchemeId>(scheme_u32)) == nullptr) return false;

    const uint32_t change_u32 = path_hardened[4] & ~HARDENED;
    if (change_u32 > 1U) return false;

    return true;
}

std::optional<LeafMaterialV1> DeriveLeafMaterialV1(std::span<const uint8_t, 32> node_secret_leaf,
                                                   std::span<const uint32_t> path_hardened)
{
    if (!ValidateV1LeafPath(path_hardened)) return std::nullopt;
    const auto scheme_id = static_cast<pq::SchemeId>(path_hardened[2] & 0x7FFFFFFFU);

    const std::span<const uint8_t> salt{reinterpret_cast<const uint8_t*>(PQHD_HKDF_SALT),
                                        std::strlen(PQHD_HKDF_SALT)};
    auto prk_full = HmacSha512(salt, node_secret_leaf);

    const auto ser_scheme = Ser32BE(static_cast<uint32_t>(scheme_id));
    CHMAC_SHA512 hmac(prk_full.data(), prk_full.size());
    hmac.Write(reinterpret_cast<const uint8_t*>(PQHD_STREAM_INFO), std::strlen(PQHD_STREAM_INFO));
    hmac.Write(ser_scheme.data(), ser_scheme.size());
    for (const uint32_t elem : path_hardened) {
        const auto ser = Ser32BE(elem);
        hmac.Write(ser.data(), ser.size());
    }
    const uint8_t ctr = 0x01;
    hmac.Write(&ctr, 1);
    LeafMaterialV1 out{scheme_id, {}};
    hmac.Finalize(out.stream_key.data());
    memory_cleanse(prk_full.data(), prk_full.size());

    return out;
}

std::optional<KeygenStreamKey64> DeriveKeygenStreamKey(std::span<const uint8_t, 32> node_secret_leaf,
                                                       std::span<const uint32_t> path_hardened)
{
    auto material = DeriveLeafMaterialV1(node_secret_leaf, path_hardened);
    if (!material) return std::nullopt;
    return std::move(material->stream_key);
}

KeygenStreamBlock64 DeriveKeygenStreamBlock(std::span<const uint8_t, 64> stream_key, uint32_t ctr)
{
    const auto ser = Ser32BE(ctr);

    KeygenStreamBlock64 out{};
    CHMAC_SHA512(stream_key.data(), stream_key.size())
        .Write(reinterpret_cast<const uint8_t*>(PQHD_RNG_PREFIX), std::strlen(PQHD_RNG_PREFIX))
        .Write(ser.data(), ser.size())
        .Finalize(out.data());
    return out;
}

} // namespace pqhd
