#include <consensus/params.h>
#include <pq/pq_api.h>
#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>

#include <pubkey.h>
#include <script/descriptor.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace {

template <size_t N>
std::array<uint8_t, N> ParseHexArray(const std::string_view hex)
{
    const auto v = ParseHex<uint8_t>(hex);
    BOOST_REQUIRE_EQUAL(v.size(), N);
    std::array<uint8_t, N> out{};
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

constexpr uint32_t HARDENED = 0x80000000U;

struct DerivedPubkey
{
    const pq::SchemeInfo* scheme{nullptr};
    std::vector<uint8_t> prefixed_pubkey;
};

DerivedPubkey DerivePrefixedPubkeyV1(pq::SchemeId scheme_id, std::span<const uint32_t, 6> path_hardened)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    const auto leaf = pqhd::DerivePath(master, path_hardened);
    BOOST_REQUIRE(leaf);
    const auto material = pqhd::DeriveLeafMaterialV1(std::span<const uint8_t, 32>(leaf->node_secret), path_hardened);
    BOOST_REQUIRE(material);
    BOOST_REQUIRE(material->scheme_id == scheme_id);

    std::vector<uint8_t> pk;
    pq::SecureKeyBytes sk;
    BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1, scheme_id, material->stream_key.Span(), pk, sk));

    const pq::SchemeInfo* scheme = pq::SchemeFromId(scheme_id);
    BOOST_REQUIRE(scheme);
    BOOST_REQUIRE_EQUAL(pk.size(), scheme->pubkey_bytes);

    std::vector<uint8_t> prefixed_pubkey;
    prefixed_pubkey.resize(pk.size() + 1);
    prefixed_pubkey[0] = scheme->prefix;
    std::copy(pk.begin(), pk.end(), prefixed_pubkey.begin() + 1);

    return {scheme, std::move(prefixed_pubkey)};
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_pubkey_container_tests)

BOOST_AUTO_TEST_CASE(cpubkey_accepts_all_current_pq_schemes)
{
    struct SchemeVector {
        pq::SchemeId scheme_id;
        std::array<uint32_t, 6> path;
    };

    const std::array<SchemeVector, 5> vectors{{
        {pq::SchemeId::FALCON_512,  {HARDENED | pqhd::PURPOSE_GENERIC, HARDENED | pqhd::COIN_TYPE_MAIN, HARDENED | 7U,  HARDENED | 0U, HARDENED | 0U, HARDENED | 0U}},
        {pq::SchemeId::FALCON_1024, {HARDENED | pqhd::PURPOSE_GENERIC, HARDENED | pqhd::COIN_TYPE_MAIN, HARDENED | 8U,  HARDENED | 0U, HARDENED | 0U, HARDENED | 0U}},
        {pq::SchemeId::MLDSA_44,   {HARDENED | pqhd::PURPOSE_GENERIC, HARDENED | pqhd::COIN_TYPE_MAIN, HARDENED | 9U,  HARDENED | 0U, HARDENED | 0U, HARDENED | 0U}},
        {pq::SchemeId::MLDSA_65,   {HARDENED | pqhd::PURPOSE_GENERIC, HARDENED | pqhd::COIN_TYPE_MAIN, HARDENED | 10U, HARDENED | 2U, HARDENED | 1U, HARDENED | 5U}},
        {pq::SchemeId::MLDSA_87,   {HARDENED | pqhd::PURPOSE_GENERIC, HARDENED | pqhd::COIN_TYPE_MAIN, HARDENED | 11U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U}},
    }};

    for (const auto& vec : vectors) {
        const auto derived = DerivePrefixedPubkeyV1(vec.scheme_id, std::span<const uint32_t, 6>(vec.path));
        BOOST_REQUIRE(derived.scheme);
        BOOST_REQUIRE_EQUAL(derived.prefixed_pubkey.size(), derived.scheme->pubkey_bytes + 1);
        BOOST_REQUIRE_EQUAL(derived.prefixed_pubkey[0], derived.scheme->prefix);

        CPubKey pk(derived.prefixed_pubkey);
        BOOST_REQUIRE_MESSAGE(pk.IsValid(), derived.scheme->name);
        BOOST_CHECK(pk.IsValidNonHybrid());
        BOOST_CHECK_EQUAL(pk.size(), derived.prefixed_pubkey.size());
        BOOST_CHECK_EQUAL(pk[0], derived.scheme->prefix);
        BOOST_CHECK(CPubKey::ValidSize(std::vector<unsigned char>(derived.prefixed_pubkey.begin(), derived.prefixed_pubkey.end())));

        // Descriptor parsing should accept explicit PQ pubkeys (hex) via existing `pk()` wrapper.
        FlatSigningProvider provider;
        std::string error;
        const std::string desc_str = "pk(" + HexStr(derived.prefixed_pubkey) + ")";
        auto descs = Parse(desc_str, provider, error);
        BOOST_CHECK_MESSAGE(!descs.empty(), error);
    }
}

BOOST_AUTO_TEST_CASE(cpubkey_rejects_hybrid_07_len_33)
{
    // Hybrid legacy pubkeys use prefix 0x06/0x07, but 0x07 is reserved for Falcon-512 in Tidecoin.
    std::vector<uint8_t> hybrid_like(33);
    hybrid_like[0] = 0x07;
    CPubKey pk(hybrid_like);
    BOOST_CHECK(!pk.IsValid());
}

BOOST_AUTO_TEST_CASE(pq_scheme_auxpow_gate)
{
    Consensus::Params params;
    params.nAuxpowStartHeight = 100;

    BOOST_CHECK(pq::IsSchemeAllowedAtHeight(pq::SchemeId::FALCON_512, params, 0));
    BOOST_CHECK(!pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, 0));
    BOOST_CHECK(pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, 100));
}

BOOST_AUTO_TEST_SUITE_END()
