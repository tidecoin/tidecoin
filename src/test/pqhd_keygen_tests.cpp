#include <pq/pq_api.h>
#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>

#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <span>
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

std::string Sha256Hex(std::span<const uint8_t> data)
{
    std::array<uint8_t, 32> out{};
    CSHA256().Write(data.data(), data.size()).Finalize(out.data());
    return HexStr(std::span<const uint8_t, 32>(out));
}

constexpr uint32_t HARDENED = 0x80000000U;

bool DirectFalconDeterministicKeypair(pq::SchemeId scheme_id,
                                      std::span<const uint8_t> seed,
                                      std::vector<uint8_t>& pk_out,
                                      pq::SecureKeyBytes& sk_out)
{
    const pq::SchemeInfo* info = pq::SchemeFromId(scheme_id);
    if (!info) return false;
    pk_out.assign(info->pubkey_bytes, 0);
    sk_out.assign(info->seckey_bytes, 0);
    int rc = -1;
    switch (scheme_id) {
    case pq::SchemeId::FALCON_512:
        rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(
            pk_out.data(), sk_out.data(), seed.data(), seed.size());
        break;
    case pq::SchemeId::FALCON_1024:
        rc = PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair_deterministic(
            pk_out.data(), sk_out.data(), seed.data(), seed.size());
        break;
    default:
        return false;
    }
    return rc == 0;
}

} // namespace

BOOST_AUTO_TEST_SUITE(pqhd_keygen_tests)

BOOST_AUTO_TEST_CASE(rejects_unsupported_version)
{
    const std::array<uint8_t, 64> key_material{};
    std::vector<uint8_t> pk{1, 2, 3};
    pq::SecureKeyBytes sk{4, 5, 6};
    BOOST_CHECK(!pq::KeyGenFromSeed(/*pqhd_version=*/0, pq::SchemeId::FALCON_512, std::span<const uint8_t, 64>(key_material), pk, sk));
    BOOST_CHECK(pk.empty());
    BOOST_CHECK(sk.empty());
}

BOOST_AUTO_TEST_CASE(rejects_wrong_key_material_length)
{
    const std::array<uint8_t, 63> key_material{};
    std::vector<uint8_t> pk{1, 2, 3};
    pq::SecureKeyBytes sk{4, 5, 6};
    BOOST_CHECK(!pq::KeyGenFromSeedBytes(/*pqhd_version=*/1, pq::SchemeId::FALCON_512, key_material, pk, sk));
    BOOST_CHECK(pk.empty());
    BOOST_CHECK(sk.empty());
}

BOOST_AUTO_TEST_CASE(v1_vectors_master_seed_0_all_schemes_hashes)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    auto run = [&](pq::SchemeId scheme_id,
                   std::array<uint32_t, 6> path,
                   std::string_view expected_pk_sha256,
                   std::string_view expected_sk_sha256) {
        const auto leaf = pqhd::DerivePath(master, path);
        BOOST_REQUIRE(leaf);
        const auto stream_key = pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                                            std::span<const uint32_t>(path));
        BOOST_REQUIRE(stream_key);
        std::vector<uint8_t> pk;
        pq::SecureKeyBytes sk;
        BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1, scheme_id, stream_key->Span(), pk, sk));
        BOOST_CHECK_EQUAL(Sha256Hex(pk), expected_pk_sha256);
        BOOST_CHECK_EQUAL(Sha256Hex(sk), expected_sk_sha256);
    };

    // purpose' and coin_type' are centralized in `src/pq/pqhd_params.h` (see `doc/design/pqhd.md`).
    run(pq::SchemeId::FALCON_512,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 7U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U},
        "cb72ac890ce605a32850b885abcd4e83a3e30bcc68f08eaacc342bfdd30ebba5",
        "935f9316ecc62adb2b2c5ce7b2b948d848d1884528a79c3162a2e25989e84f35");

    run(pq::SchemeId::FALCON_1024,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 8U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U},
        "ec638e05cfb547b3315bcd798002e512869782382cbc290561df9435fe2ba7f1",
        "dcbc3734ce83292c3efede196ac38bbc9b6f92f153974507b86b379415a1d42c");

    run(pq::SchemeId::MLDSA_44,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 9U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U},
        "e507351f4903882e597367309d0f1a25053200b39c93ed5288cb8b9821ff749b",
        "3364238c559c07268cde4e7b4bb8f54c46e944804a93abaada81a0645bca26e7");

    run(pq::SchemeId::MLDSA_65,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 10U, HARDENED | 2U, HARDENED | 1U, HARDENED | 5U},
        "3ef25f8229327412340beac8b81af09482e5f7b15f040e919c38cd913045fbbd",
        "f7cac55ef3f5c164e4e17a801ebd7b2cc24aabf236443761427b28c8f2e4d10e");

    run(pq::SchemeId::MLDSA_87,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 11U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U},
        "1288715e0d9a64a30ab5066536b5a7a50af1a882e193ec67433a675da7b36237",
        "7b5d56dd11ae1afd25e51b27f014492742b2ca2ebca324efdb0cdcee6a40cf98");
}

BOOST_AUTO_TEST_CASE(v1_branch_domain_separation_receive_vs_change)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    const auto derive_keypair = [&](const std::array<uint32_t, 6>& path) {
        const auto leaf = pqhd::DerivePath(master, path);
        BOOST_REQUIRE(leaf);
        const auto stream_key = pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                                            std::span<const uint32_t>(path));
        BOOST_REQUIRE(stream_key);
        std::vector<uint8_t> pk;
        pq::SecureKeyBytes sk;
        BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1, pq::SchemeId::FALCON_512, stream_key->Span(), pk, sk));
        return std::pair<std::string, std::string>{Sha256Hex(pk), Sha256Hex(sk)};
    };

    const std::array<uint32_t, 6> receive_path{
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | static_cast<uint32_t>(static_cast<uint8_t>(pq::SchemeId::FALCON_512)),
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 7U,
    };
    auto change_path = receive_path;
    change_path[4] = HARDENED | 1U;

    const auto [receive_pk_sha, receive_sk_sha] = derive_keypair(receive_path);
    const auto [change_pk_sha, change_sk_sha] = derive_keypair(change_path);

    // Branches must be domain-separated: same scheme/account/index but different change branch.
    BOOST_CHECK(receive_pk_sha != change_pk_sha);
    BOOST_CHECK(receive_sk_sha != change_sk_sha);

    // Deterministic regeneration within each branch.
    BOOST_CHECK_EQUAL(receive_pk_sha, derive_keypair(receive_path).first);
    BOOST_CHECK_EQUAL(receive_sk_sha, derive_keypair(receive_path).second);
    BOOST_CHECK_EQUAL(change_pk_sha, derive_keypair(change_path).first);
    BOOST_CHECK_EQUAL(change_sk_sha, derive_keypair(change_path).second);
}

BOOST_AUTO_TEST_CASE(deterministic_keypair_rejects_wrong_seed_length)
{
    {
        std::array<uint8_t, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 47> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                   seed.data(), seed.size()),
                          -1);
    }
    {
        std::array<uint8_t, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 49> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                    seed.data(), seed.size()),
                          -1);
    }
    {
        std::array<uint8_t, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 31> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                 seed.data(), seed.size()),
                          -1);
    }
    {
        std::array<uint8_t, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 33> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                  seed.data(), seed.size()),
                          -1);
    }
    {
        std::array<uint8_t, PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 33> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                  seed.data(), seed.size()),
                          -1);
    }
}

BOOST_AUTO_TEST_CASE(deterministic_keygen_retry_uses_next_stream_block)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    const std::array<std::pair<pq::SchemeId, std::array<uint32_t, 6>>, 2> cases{{
        {pq::SchemeId::FALCON_512, {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 7U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U}},
        {pq::SchemeId::FALCON_1024, {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 8U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U}},
    }};

    for (const auto& [scheme_id, path] : cases) {
        const auto leaf = pqhd::DerivePath(master, path);
        BOOST_REQUIRE(leaf);
        const auto stream_key = pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                                            std::span<const uint32_t>(path));
        BOOST_REQUIRE(stream_key);

        const auto block0 = pqhd::DeriveKeygenStreamBlock(stream_key->Span(), /*ctr=*/0);
        const auto block1 = pqhd::DeriveKeygenStreamBlock(stream_key->Span(), /*ctr=*/1);

        std::vector<uint8_t> expected_pk0;
        pq::SecureKeyBytes expected_sk0;
        std::vector<uint8_t> expected_pk1;
        pq::SecureKeyBytes expected_sk1;
        BOOST_REQUIRE(DirectFalconDeterministicKeypair(scheme_id,
                                                       std::span<const uint8_t>(block0.data(), 48),
                                                       expected_pk0,
                                                       expected_sk0));
        BOOST_REQUIRE(DirectFalconDeterministicKeypair(scheme_id,
                                                       std::span<const uint8_t>(block1.data(), 48),
                                                       expected_pk1,
                                                       expected_sk1));

        std::vector<uint8_t> pk;
        pq::SecureKeyBytes sk;
        BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1, scheme_id, stream_key->Span(), pk, sk));
        BOOST_CHECK(pk == expected_pk0);
        BOOST_CHECK(std::equal(sk.begin(), sk.end(), expected_sk0.begin(), expected_sk0.end()));

        pq::SetDeterministicKeyGenTestFailCount(1);
        std::vector<uint8_t> retry_pk;
        pq::SecureKeyBytes retry_sk;
        BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1, scheme_id, stream_key->Span(), retry_pk, retry_sk));
        BOOST_CHECK_EQUAL(pq::GetDeterministicKeyGenTestFailCount(), 0);
        BOOST_CHECK(retry_pk == expected_pk1);
        BOOST_CHECK(std::equal(retry_sk.begin(), retry_sk.end(), expected_sk1.begin(), expected_sk1.end()));
        pq::SetDeterministicKeyGenTestFailCount(0);
    }
}

BOOST_AUTO_TEST_CASE(deterministic_keygen_retry_exhausts_failures)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));
    const std::array<uint32_t, 6> path{
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | 7U,
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 0U,
    };

    const auto leaf = pqhd::DerivePath(master, path);
    BOOST_REQUIRE(leaf);
    const auto stream_key = pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                                        std::span<const uint32_t>(path));
    BOOST_REQUIRE(stream_key);

    pq::SetDeterministicKeyGenTestFailCount(static_cast<int>(pq::kDeterministicKeyGenMaxAttempts));
    std::vector<uint8_t> pk;
    pq::SecureKeyBytes sk;
    BOOST_CHECK(!pq::KeyGenFromSeed(/*pqhd_version=*/1, pq::SchemeId::FALCON_512, stream_key->Span(), pk, sk));
    BOOST_CHECK(pk.empty());
    BOOST_CHECK(sk.empty());
    BOOST_CHECK_EQUAL(pq::GetDeterministicKeyGenTestFailCount(), 0);
    pq::SetDeterministicKeyGenTestFailCount(0);
}

BOOST_AUTO_TEST_SUITE_END()
