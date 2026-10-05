#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>

#include <crypto/hex_base.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <string_view>
#include <vector>

namespace {

template <size_t N>
std::array<uint8_t, N> ParseHexArray(std::string_view hex)
{
    const auto v = ParseHex<uint8_t>(hex);
    BOOST_REQUIRE_EQUAL(v.size(), N);
    std::array<uint8_t, N> out{};
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(pqhd_kdf_tests)

BOOST_AUTO_TEST_CASE(secret_lifetime_and_moves)
{
    static_assert(!std::is_copy_constructible_v<pqhd::KeygenStreamBlock64>);
    static_assert(std::is_nothrow_move_constructible_v<pqhd::Node>);
    std::array<unsigned char, 32> bytes;
    bytes.fill(0x42);
    try {
        const ScopedMemoryCleanse guard{bytes.data(), bytes.size()};
        throw std::runtime_error("exception exit");
    } catch (const std::runtime_error&) {}
    BOOST_CHECK(std::ranges::all_of(bytes, [](auto b) { return b == 0; }));
    pqhd::Node original;
    original.node_secret.fill(0x42);
    original.chain_code.fill(0x24);
    pqhd::Node copy = original;
    pqhd::Node moved = std::move(original);
    BOOST_CHECK(std::ranges::all_of(original.node_secret, [](auto b) { return b == 0; }));
    BOOST_CHECK(std::ranges::all_of(original.chain_code, [](auto b) { return b == 0; }));
    BOOST_CHECK(copy.node_secret == moved.node_secret);
    BOOST_CHECK(copy.chain_code == moved.chain_code);
    original = std::move(moved);
    BOOST_CHECK(original.node_secret == copy.node_secret);
    BOOST_CHECK(std::ranges::all_of(moved.node_secret, [](auto b) { return b == 0; }));
    original.Clear();
    BOOST_CHECK(std::ranges::all_of(original.chain_code, [](auto b) { return b == 0; }));
    BOOST_CHECK_EQUAL(copy.node_secret[0], 0x42);
    pqhd::KeygenStreamKey64 key;
    std::ranges::fill(key.MutableSpan(), 0x99);
    auto block = pqhd::DeriveKeygenStreamBlock(key.Span(), 0);
    const auto expected = HexStr(block.Span());
    auto moved_block = std::move(block);
    BOOST_CHECK_EQUAL(HexStr(moved_block.Span()), expected);
    BOOST_CHECK(std::ranges::all_of(block.Span(), [](auto b) { return b == 0; }));
}

BOOST_AUTO_TEST_CASE(vectors_master_seed_0)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    const auto seedid = pqhd::ComputeSeedID32(std::span<const uint8_t, 32>(master_seed));
    BOOST_CHECK_EQUAL(HexStr(std::span<const uint8_t, 32>(seedid)),
                      "13f45473287a2920f659a303dfc449ab5bf97cba2e23024c61439348ae0eb602");

    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));
    BOOST_CHECK_EQUAL(HexStr(std::span<const uint8_t, 32>(master.node_secret)),
                      "9f46d25ef75d6dd7e5af0e0e88351e80792962fbc8fe936f8685db6aa42edc96");
    BOOST_CHECK_EQUAL(HexStr(std::span<const uint8_t, 32>(master.chain_code)),
                      "7238ac4acb263a6caa7728529d899aebd8fdafdd9f232664bb6894cb79b143b8");
}

BOOST_AUTO_TEST_CASE(seedid_uint256_conversion_is_canonical_and_roundtrips)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto seedid_be = pqhd::ComputeSeedID32(std::span<const uint8_t, 32>(master_seed));
    const auto seed_id_u256 = pqhd::SeedID32ToUint256(seedid_be);

    // Canonical SeedID32 hex and uint256 text representation must match exactly.
    BOOST_CHECK_EQUAL(seed_id_u256.ToString(), HexStr(std::span<const uint8_t, 32>(seedid_be)));

    const auto roundtrip_seedid_be = pqhd::SeedID32FromUint256(seed_id_u256);
    BOOST_CHECK(seedid_be == roundtrip_seedid_be);

    const auto computed_u256 = pqhd::ComputeSeedID32AsUint256(std::span<const uint8_t, 32>(master_seed));
    BOOST_CHECK(seed_id_u256 == computed_u256);
}

BOOST_AUTO_TEST_CASE(vectors_leaf_falcon512_receive_0)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    constexpr uint32_t HARDENED = 0x80000000U;
    const std::array<uint32_t, 6> path{
        HARDENED | pqhd::PURPOSE, // purpose'
        HARDENED | pqhd::COIN_TYPE,  // coin_type'
        HARDENED | 7U,     // scheme' (Falcon-512)
        HARDENED | 0U,     // account'
        HARDENED | 0U,     // change' (receive)
        HARDENED | 0U,     // index'
    };

    const auto leaf = pqhd::DerivePath(master, path);
    BOOST_REQUIRE(leaf);
    BOOST_CHECK_EQUAL(HexStr(std::span<const uint8_t, 32>(leaf->node_secret)),
                      "6a314c506be113c29cdfde990b32494205789711f93e8b435bc42d11177ed6a9");
    BOOST_CHECK_EQUAL(HexStr(std::span<const uint8_t, 32>(leaf->chain_code)),
                      "6333f60d7b7636d6bb0d76adeec9392461f511f4d29877b48fe0738d4aed8418");

    const auto stream_key =
        pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                    std::span<const uint32_t>(path));
    BOOST_REQUIRE(stream_key);
    BOOST_CHECK_EQUAL(
        HexStr(stream_key->Span()),
        "1d28d7fc52b10ad564be42667eea7830ffddcd9beb7666966c9e7fd1f0c6769d"
        "90da93994e186053b4fe6655e9b79aa19306b0994af09d6b77ae141f88cac2e8");

    const auto block0 = pqhd::DeriveKeygenStreamBlock(stream_key->Span(), /*ctr=*/0);
    BOOST_CHECK_EQUAL(
        HexStr(std::span<const uint8_t, 64>(block0)),
        "a826fbc6d97bb72b34628430561b572aca14b6281caeb4fd9fa6b9295f1d711f"
        "4bbcd9f1d3697afda50b9889216634edc8a4ea7b18126cdc0d754b853474ebd2");

    const auto block1 = pqhd::DeriveKeygenStreamBlock(stream_key->Span(), /*ctr=*/1);
    BOOST_CHECK_EQUAL(
        HexStr(std::span<const uint8_t, 64>(block1)),
        "979d62443c10984b5b05af367181c33bb39541b9a1841896858c4df39c5c2347"
        "e7a452264c58eb756c9bc869106cdf76b8e4615b950cd1608b5052049a220719");
}

BOOST_AUTO_TEST_CASE(vectors_leaf_mldsa65_change_5)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    constexpr uint32_t HARDENED = 0x80000000U;
    const std::array<uint32_t, 6> path{
        HARDENED | pqhd::PURPOSE, // purpose'
        HARDENED | pqhd::COIN_TYPE,  // coin_type'
        HARDENED | 10U,    // scheme' (ML-DSA-65)
        HARDENED | 2U,     // account'
        HARDENED | 1U,     // change' (change)
        HARDENED | 5U,     // index'
    };

    const auto leaf = pqhd::DerivePath(master, path);
    BOOST_REQUIRE(leaf);
    BOOST_CHECK_EQUAL(HexStr(std::span<const uint8_t, 32>(leaf->node_secret)),
                      "632ed8f96d5addcf359e80ce43977034b666ab468c0023f9143ae1bea78341df");
    BOOST_CHECK_EQUAL(HexStr(std::span<const uint8_t, 32>(leaf->chain_code)),
                      "58f87112c1632aac4da7dfaea6f8f377733fff977fdf4b6b473d55109c9d1da6");

    const auto stream_key =
        pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                    std::span<const uint32_t>(path));
    BOOST_REQUIRE(stream_key);
    BOOST_CHECK_EQUAL(
        HexStr(stream_key->Span()),
        "d84fe3ee51ac4f613ba55b2357c5ab18bf2397709844fdba2a3ee1a3b8041130"
        "4bb08b20e73508a958e7fc08c1005f75770542d951979a365b869742a953774b");

    const auto block0 = pqhd::DeriveKeygenStreamBlock(stream_key->Span(), /*ctr=*/0);
    BOOST_CHECK_EQUAL(
        HexStr(std::span<const uint8_t, 64>(block0)),
        "980181e20ecf0e7cba979df337b300b35299d52ad75fae9b4154c43b72315263"
        "0daeab708aac355f660677f142052cd68b35a9f9d6fdba772fe62e63279cd0eb");
}

BOOST_AUTO_TEST_CASE(rejects_non_hardened_inputs)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    // A non-hardened element must fail derivation (no silent all-zero nodes).
    const std::array<uint32_t, 1> path_not_hardened{pqhd::PURPOSE};
    BOOST_CHECK(!pqhd::DerivePath(master, path_not_hardened));

    // Keygen stream key derivation must also reject non-hardened paths.
    constexpr uint32_t HARDENED = 0x80000000U;
    const std::array<uint32_t, 6> path_good_stream{
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | 7U,
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 0U,
    };
    const auto leaf = pqhd::DerivePath(master, path_good_stream);
    BOOST_REQUIRE(leaf);
    auto path_bad_stream = path_good_stream;
    path_bad_stream[4] = 0U; // not hardened
    BOOST_CHECK(!pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                             std::span<const uint32_t>(path_bad_stream)));
}

BOOST_AUTO_TEST_CASE(validate_v1_leaf_path_rejects_wrong_shape)
{
    constexpr uint32_t HARDENED = 0x80000000U;
    const std::array<uint32_t, 6> good{
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | 7U,
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 0U,
    };
    BOOST_CHECK(pqhd::ValidateV1LeafPath(good));

    const std::array<uint32_t, 5> bad_len{
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | 7U,
        HARDENED | 0U,
        HARDENED | 0U,
    };
    BOOST_CHECK(!pqhd::ValidateV1LeafPath(bad_len));

    auto bad_purpose = good;
    bad_purpose[0] = HARDENED | (pqhd::PURPOSE + 1U);
    BOOST_CHECK(!pqhd::ValidateV1LeafPath(bad_purpose));

    auto bad_coin = good;
    bad_coin[1] = HARDENED | (pqhd::COIN_TYPE + 1U);
    BOOST_CHECK(!pqhd::ValidateV1LeafPath(bad_coin));

    auto bad_change = good;
    bad_change[4] = HARDENED | 2U;
    BOOST_CHECK(!pqhd::ValidateV1LeafPath(bad_change));
}

BOOST_AUTO_TEST_CASE(rejects_scheme_element_out_of_range)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    constexpr uint32_t HARDENED = 0x80000000U;
    // Scheme id must fit into one byte (SchemeId/prefix space). Reject anything larger.
    const std::array<uint32_t, 6> path{
        HARDENED | pqhd::PURPOSE, // purpose'
        HARDENED | pqhd::COIN_TYPE,  // coin_type'
        HARDENED | 0x1FFU, // scheme' (out of range)
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 0U,
    };
    const auto leaf = pqhd::DerivePath(master, path);
    BOOST_REQUIRE(leaf);
    BOOST_CHECK(!pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                             std::span<const uint32_t>(path)));
}

BOOST_AUTO_TEST_CASE(rejects_unknown_scheme)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    constexpr uint32_t HARDENED = 0x80000000U;
    // Any scheme id that is not recognized by the build must be rejected at the KDF layer.
    const std::array<uint32_t, 6> path{
        HARDENED | pqhd::PURPOSE, // purpose'
        HARDENED | pqhd::COIN_TYPE,  // coin_type'
        HARDENED | 0x01U, // scheme' (unknown but within 1-byte range)
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 0U,
    };
    const auto leaf = pqhd::DerivePath(master, path);
    BOOST_REQUIRE(leaf);
    BOOST_CHECK(!pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                             std::span<const uint32_t>(path)));
}

BOOST_AUTO_TEST_CASE(rejects_change_domain_outside_receive_or_change)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    constexpr uint32_t HARDENED = 0x80000000U;
    const std::array<uint32_t, 6> path{
        HARDENED | pqhd::PURPOSE, // purpose'
        HARDENED | pqhd::COIN_TYPE,  // coin_type'
        HARDENED | 7U,     // scheme' (Falcon-512)
        HARDENED | 0U,     // account'
        HARDENED | 2U,     // invalid change'
        HARDENED | 0U,     // index'
    };
    const auto leaf = pqhd::DerivePath(master, path);
    BOOST_REQUIRE(leaf);
    BOOST_CHECK(!pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                             std::span<const uint32_t>(path)));
}

BOOST_AUTO_TEST_SUITE_END()
