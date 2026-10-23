#include <key.h>
#include <pq/pq_api.h>
#include <pq/randombytes.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

BOOST_AUTO_TEST_SUITE(pq_random_key_tests)

BOOST_AUTO_TEST_CASE(generate_keypair_smoke_all_schemes)
{
    const std::array<pq::SchemeId, 5> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_87,
    };

    for (const auto scheme_id : schemes) {
        const pq::SchemeInfo* info = pq::SchemeFromId(scheme_id);
        BOOST_REQUIRE(info);

        std::vector<unsigned char> pk(info->pubkey_bytes);
        std::vector<unsigned char> sk(info->seckey_bytes);
        BOOST_CHECK(pq::GenerateKeyPair(*info, pk, sk));

        // Spot-check that the keys look well-formed for this scheme.
        BOOST_CHECK(pq::IsSecretKeyEncodingValid(*info, sk));
        BOOST_CHECK_EQUAL(pk.size(), info->pubkey_bytes);
        BOOST_CHECK_EQUAL(sk.size(), info->seckey_bytes);
    }
}

BOOST_AUTO_TEST_CASE(generate_random_key_smoke)
{
    // Ensure we can generate a non-empty private key and access its pubkey
    // without triggering assertions used by wallet create paths.
    CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    BOOST_REQUIRE_MESSAGE(key.IsValid(), "GenerateRandomKey(pq::SchemeId::FALCON_512) produced an invalid key");

    const CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK(key.VerifyPubKey(pubkey));
}

BOOST_AUTO_TEST_CASE(falcon_strict_sign_retry)
{
    constexpr std::array<pq::SchemeId, 2> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
    };

    std::array<unsigned char, 32> msg{};
    for (const auto scheme_id : schemes) {
        const pq::SchemeInfo* info = pq::SchemeFromId(scheme_id);
        BOOST_REQUIRE(info);

        std::vector<unsigned char> pk(info->pubkey_bytes);
        std::vector<unsigned char> sk(info->seckey_bytes);
        BOOST_REQUIRE(pq::GenerateKeyPair(*info, pk, sk));

        pq::SetFalconSignTestFailCount(1);
        std::vector<unsigned char> sig;
        BOOST_CHECK(pq::Sign(*info,
                             std::span<const unsigned char>(msg),
                             std::span<const unsigned char>(sk),
                             sig,
                             /*legacy_mode=*/false));
        BOOST_CHECK_EQUAL(pq::GetFalconSignTestFailCount(), 0);
        BOOST_CHECK(!sig.empty());
    }
}

BOOST_AUTO_TEST_CASE(falcon_strict_sign_exhausts_failures)
{
    const pq::SchemeInfo* info = pq::SchemeFromId(pq::SchemeId::FALCON_512);
    BOOST_REQUIRE(info);

    std::vector<unsigned char> pk(info->pubkey_bytes);
    std::vector<unsigned char> sk(info->seckey_bytes);
    BOOST_REQUIRE(pq::GenerateKeyPair(*info, pk, sk));

    std::array<unsigned char, 32> msg{};
    pq::SetFalconSignTestFailCount(static_cast<int>(pq::kFalconSignMaxAttempts));
    std::vector<unsigned char> sig;
    BOOST_CHECK(!pq::Sign(*info,
                          std::span<const unsigned char>(msg),
                          std::span<const unsigned char>(sk),
                          sig,
                          /*legacy_mode=*/false));
}

BOOST_AUTO_TEST_CASE(falcon_sign_retries_until_within_bound)
{
    // Production signing bounds Falcon at the padded sizes, which compressed
    // signatures rarely exceed. A bound near the median size makes about half
    // of all attempts too long, so each call below exercises the retry.
    struct Case {
        const pq::SchemeInfo* info;
        bool legacy;
        size_t max_sig_len;
    };
    for (const Case& c : {Case{&pq::kFalcon512Info, true, 655}, Case{&pq::kFalcon512Info, false, 655},
                          Case{&pq::kFalcon1024Info, false, 1271}}) {
        BOOST_TEST_CONTEXT(c.info->name << "/legacy=" << c.legacy) {
            std::vector<unsigned char> pk(c.info->pubkey_bytes);
            std::vector<unsigned char> sk(c.info->seckey_bytes);
            BOOST_REQUIRE(pq::GenerateKeyPair(*c.info, pk, sk));
            for (const size_t msg_size : {32U, 64U}) {
                const std::vector<unsigned char> msg(msg_size, 0x42);
                for (int i = 0; i < 8; ++i) {
                    std::vector<unsigned char> sig;
                    BOOST_REQUIRE(pq::SignFalcon(*c.info, msg, sk, sig, c.legacy, c.max_sig_len));
                    BOOST_CHECK_LE(sig.size(), c.max_sig_len);
                    BOOST_CHECK(msg_size == 32 ? pq::Verify(*c.info, msg, sig, pk, c.legacy)
                                               : pq::Verify64(*c.info, msg, sig, pk, c.legacy));
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(falcon_exact_compressed_encoding)
{
    for (const auto* info : {&pq::kFalcon512Info, &pq::kFalcon1024Info}) {
        std::vector<unsigned char> pk(info->pubkey_bytes);
        std::vector<unsigned char> sk(info->seckey_bytes);
        BOOST_REQUIRE(pq::GenerateKeyPair(*info, pk, sk));

        for (const size_t msg_size : {32U, 64U}) {
            BOOST_TEST_CONTEXT(info->name << "/message_bytes=" << msg_size) {
                const std::vector<unsigned char> msg(msg_size, 0x42);
                const auto verify = [&](const std::vector<unsigned char>& sig, bool legacy = false) {
                    return msg_size == 32 ? pq::Verify(*info, msg, sig, pk, legacy)
                                          : pq::Verify64(*info, msg, sig, pk, legacy);
                };
                std::vector<unsigned char> sig;
                // Obtain a signature for which the former padded-length exception applies.
                for (int attempt = 0; attempt < 100; ++attempt) {
                    BOOST_REQUIRE(msg_size == 32 ? pq::Sign(*info, msg, sk, sig, /*legacy_mode=*/false)
                                                 : pq::Sign64(*info, msg, sk, sig, /*legacy_mode=*/false));
                    if (sig.size() < info->sig_bytes_sign_max) break;
                }
                BOOST_REQUIRE_LT(sig.size(), info->sig_bytes_sign_max);
                BOOST_CHECK(verify(sig));

                auto padded = sig;
                padded.resize(info->sig_bytes_sign_max, 0);
                BOOST_CHECK(!verify(padded));
                if (info->id == pq::SchemeId::FALCON_512) {
                    BOOST_CHECK(verify(sig, /*legacy=*/true));
                    BOOST_CHECK(!verify(padded, /*legacy=*/true));
                }
                padded.back() = 1;
                BOOST_CHECK(!verify(padded));
                auto appended = sig;
                appended.push_back(0);
                BOOST_CHECK(!verify(appended));
                auto truncated = sig;
                truncated.pop_back();
                BOOST_CHECK(!verify(truncated));
                BOOST_CHECK(verify(sig));
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
