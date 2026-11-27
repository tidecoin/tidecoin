#include <key.h>
#include <pq/cleanse.h>
#include <pq/pq_api.h>
#include <pq/randombytes.h>
#include <test/util/falcon.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

BOOST_AUTO_TEST_SUITE(pq_random_key_tests)

BOOST_AUTO_TEST_CASE(workspace_cleanse_bounds)
{
    pq_cleanse(nullptr, 0);
    constexpr std::array<size_t, 20> lengths{
        0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129,
        255, 256, 257, 1024, 8192, 73728,
    };
    for (const size_t length : lengths) {
        for (const size_t offset : {0, 1, 7, 15, 63}) {
            BOOST_TEST_CONTEXT("length=" << length << ", offset=" << offset) {
                std::vector<unsigned char> buffer(offset + length + 16, 0xa5);
                pq_cleanse(buffer.data() + offset, length);
                const std::span<const unsigned char> bytes{buffer};
                BOOST_CHECK(std::ranges::all_of(bytes.first(offset), [](auto b) { return b == 0xa5; }));
                BOOST_CHECK(std::ranges::all_of(bytes.subspan(offset, length), [](auto b) { return b == 0; }));
                BOOST_CHECK(std::ranges::all_of(bytes.subspan(offset + length), [](auto b) { return b == 0xa5; }));
            }
        }
    }
}

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
    constexpr std::array<pq::SchemeId, 2> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
    };

    const std::array<unsigned char, 32> msg{};
    for (const auto scheme_id : schemes) {
        const pq::SchemeInfo* info = pq::SchemeFromId(scheme_id);
        BOOST_REQUIRE(info);

        std::vector<unsigned char> pk(info->pubkey_bytes);
        std::vector<unsigned char> sk(info->seckey_bytes);
        BOOST_REQUIRE(pq::GenerateKeyPair(*info, pk, sk));

        pq::SetFalconSignTestFailCount(static_cast<int>(pq::kFalconSignMaxAttempts));
        std::vector<unsigned char> sig;
        BOOST_CHECK(!pq::Sign(*info,
                              std::span<const unsigned char>(msg),
                              std::span<const unsigned char>(sk),
                              sig,
                              /*legacy_mode=*/false));
        BOOST_CHECK_EQUAL(pq::GetFalconSignTestFailCount(), 0);
        pq::SetFalconSignTestFailCount(0);
    }
}

BOOST_AUTO_TEST_CASE(falcon_strict_sign_retry_at_last_attempt)
{
    constexpr std::array<pq::SchemeId, 2> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
    };

    const std::array<unsigned char, 32> msg{};
    for (const auto scheme_id : schemes) {
        const pq::SchemeInfo* info = pq::SchemeFromId(scheme_id);
        BOOST_REQUIRE(info);

        std::vector<unsigned char> pk(info->pubkey_bytes);
        std::vector<unsigned char> sk(info->seckey_bytes);
        BOOST_REQUIRE(pq::GenerateKeyPair(*info, pk, sk));

        // The final allowed attempt must still be available after forced failures.
        pq::SetFalconSignTestFailCount(static_cast<int>(pq::kFalconSignMaxAttempts - 1));
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(pq::Sign(*info, msg, sk, sig, /*legacy_mode=*/false));
        BOOST_CHECK_EQUAL(pq::GetFalconSignTestFailCount(), 0);
        BOOST_REQUIRE(!sig.empty());
        BOOST_CHECK(pq::Verify(*info, msg, sig, pk, /*legacy_mode=*/false));

        auto modified_msg = msg;
        modified_msg[0] ^= 0x01;
        BOOST_CHECK(!pq::Verify(*info, modified_msg, sig, pk, /*legacy_mode=*/false));
    }
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

BOOST_AUTO_TEST_CASE(falcon_legacy_encodings)
{
    // Public vector checked with unmodified Tidecoin 0.18.3 at
    // 7b525367e9ea1b614aa380a52394f0e3d3878aa9; no private key is needed.
    // SHA256 of the detached signature: d0b42fdce08f0ce60272567009ce10500fd0d8daad0aac725963153f0978aff8.
    const auto pk = ParseHex(
        "0916a65538af1f6d61590eab0c6cac76bc64e41cd1c28aa5fc20d203ee06ac1edb916a71910d2f7bde409793762138bcee4b1986b6c9db0a"
        "832c161ff0ddc597634cdf68db227d22528c84cda281660c1e958a53f99f08af37d522db72ee5486db9a8c5092af041b51ec031c9e98098e"
        "0eafba49bb21404baece006853a220b509a8a0045b914b10967077218c2d7e899a678a8b7b42426a9ae72abf9e131012268f12b19f935192"
        "c67805857a9b8af8048ec124148fbf3259ddc8f56f52860034f858c20b53c4cda276e4a2282634b619563899085c941c64c0908ec381d700"
        "8660a55e02a2578789c60ed3bc68f99bf17e26599a973edd5c81048fd05f96b39019a7400a55778337e210127288374547dd3e0281595e08"
        "b653aec002dd03806ee6a199a911628b726d63fcaaef48a10f232f9b19b4e207f4970d74b778c0450c8544200d8a9895c2276a985b470fa4"
        "dc4091383701e124498a12008c61b75076f6911f1ecd21566c36c489c632251d30a6c317254d5ed05c6bc528b5d9350b96ca9fb8eec4cb07"
        "dea12d5a892213e91c557a6875171f6d6614399bc79b896e1c90ae09835f9187f55a8aa617694af5088222791e4a501a896ebcc9fd05606e"
        "53b89db04943e47292c896211ae99b362871f4bae0676f991b47c9d88d1988de2660ab119f110c10d48fd58bbeb66b2f6d419e502ba02a9a"
        "0b13e541bb150aa3962a87a90a44d2b494b5a08a2c891a703c37f82607b980f136265f5178c657f2cde641b0ee35e28a1cbe3c0e6aa8fbda"
        "d47725ad83961c84b6e124c012e6c50aca2dea9ae55476e5eb12e854c5977028fae898816e12f7fa2bd3558ce28f25d80b8c6a4922636226"
        "dc917e4b24b45cc947610d42dee53d4056bba71be7f40d5429135f53ff78a13e6bd16a2caf681c224aaadb5d2184e7a50ee2b34122e95b9e"
        "3a876e2ee4f544c7285e5e6358e4324a5651dae2168c857c0f3aa661c8070eb2246b6f3e2c69f3d9148a5b74141cfa181ddda356b0b4e7d8"
        "f686bc0bc436954eb86a10076a1b933f1940f258827750e941689dcb858fe59898b965dd98f0ac96190e8d2aac9f1b686cad1ef8d0b32241"
        "77580e71bb3890e7623eab56d442126762ac85b4930e7dee03b245c62f3599e5a654e0f88e16429ac2ed543e8df5a4a01b5572a5f968e9ca"
        "8f5e7a1e10135ed2492e3933364eb5288c0f450f18ba5745f87977e41a4b96a6b10b02ca6e755e79a5a5f018fcd6d25118668badb8a6729b"
        "80");
    const auto msg = ParseHex(
        "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da");
    const auto original = ParseHex(
        "39209f5e3b3bc9d5baa7ee2ce8b3496f641ee0463376b4792cac9d2c2a8765c1f70d12586436a5665282e6e079c89255bf620f1cacde319a"
        "bd926aab71512d4c7f09a0aec42d6ffb893393995d73e6dbb1d7290a751ee8d1653186bed552c8a5b7fd32d233ad7241beff34b78c9a227f"
        "b0347174f77bffcaca9121743333ee692657da6967759855a26f6412e5362a064b3cf53546d66b1e7063ae1bb91761d0469471b5d63a4d4d"
        "f5a2290cb49dcc42b3138b8d1dd9c0114a1f19cf20a61f4ee42b6cbd0dedd934ae2085d3fa68bced04f658ac9f0fbb878877adee861deec9"
        "551894ff1d29dbb6082a0fe77fb9ac7d07c3669e38cdceda857de774dd8615ad73a1e8d167336e16bb60f3b3cef6e07da208fc0632fcf070"
        "52a9991b659a442ad170a65def7437f68b108abafeabe65139d97f9552ff0ee2ec3fb241134249b267db44a548d954aac3f9452c5e156f13"
        "ca41f0632e2224ead3df9fcb7c7cfc5e69a1404a74b325c135128a19dcc039389356cad2a290980f09e9b65133ccbc0bcf14cea78d16344a"
        "e278874e61f947ee4a137334a46310242fb6cd968cab2b7d4252d7aaa2f34231a6251e974ff03d932fe5d81cae7b3dfa8935fee78bf2c892"
        "296f635308489198e3a75efe659cca2dd78e6ba1f05abb0449ce17d553ba78764cb903ccdcb1d223fcd557798806ecb462da26fe0eae6938"
        "f154031ca6114b5ecf648bdd1356b7224351bf03c26198d7d9192cb74d1433e6b4aac2fbe8c712b45dc4423f531a542b458646332833bf85"
        "e0378eec7d2ea9eb1c542193c642d2dd393aea4bddc77f39805dc831f1328b29278bb6109dfa2c4430ffacfe71f62212fcdbf32441d9a913"
        "5beb8fb05c8e54df177f6fb9fd942cd750600c14fb26c27ecaa22708e71484418582206811864fa0");
    BOOST_REQUIRE_EQUAL(pk.size(), 897U);
    BOOST_REQUIRE_EQUAL(msg.size(), 32U);
    BOOST_REQUIRE_EQUAL(original.size(), 656U);
    const auto parsed = test::ParseFalcon512(original);
    BOOST_REQUIRE(parsed);
    BOOST_REQUIRE_EQUAL(parsed->zero_sign_bits.size(), 2U);
    BOOST_REQUIRE_EQUAL(parsed->unused_bits, 5U);
    for (unsigned signs = 0; signs < 4; ++signs) {
        for (unsigned tail = 0; tail < 32; ++tail) {
            auto sig = original;
            for (unsigned i = 0; i < 2; ++i) {
                if (signs & (1U << i)) test::SetFalconBit(sig, parsed->zero_sign_bits[i]);
            }
            sig.back() |= tail;
            const bool canonical{signs == 0 && tail == 0};
            const auto decoded = test::ParseFalcon512(sig);
            BOOST_REQUIRE(decoded);
            BOOST_CHECK(decoded->coefficients == parsed->coefficients);
            BOOST_CHECK(pq::Verify(pq::kFalcon512Info, msg, sig, pk, true));
            BOOST_CHECK_EQUAL(pq::Verify(pq::kFalcon512Info, msg, sig, pk, false), canonical);
            BOOST_CHECK_EQUAL(pq::IsNonCanonicalLegacyFalcon512(sig), !canonical);
        }
    }
    // Compare the classifier with the independent bit parser for every body
    // bit change. This also runs under the instrumented unit-test build.
    for (size_t bit = 41 * 8; bit < original.size() * 8; ++bit) {
        auto sig = original;
        sig[bit / 8] ^= 1U << (7 - bit % 8);
        const auto decoded = test::ParseFalcon512(sig);
        bool alternate{false};
        if (decoded) {
            alternate = (sig.back() & ((1U << decoded->unused_bits) - 1)) != 0;
            for (const auto pos : decoded->zero_sign_bits) {
                alternate |= (sig[pos / 8] & (1U << (7 - pos % 8))) != 0;
            }
        }
        BOOST_CHECK_EQUAL(pq::IsNonCanonicalLegacyFalcon512(sig), alternate);
    }
    // Incomplete or extra bytes are not alternate *complete* encodings.
    for (size_t length = 0; length < original.size(); ++length) {
        BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(std::span{original}.first(length)));
    }
    auto alternate = original;
    test::SetFalconBit(alternate, parsed->zero_sign_bits[0]);
    alternate.back() |= 1;
    for (const auto& base : {original, alternate}) {
        for (const unsigned char suffix : {0, 1, 255}) {
            auto sig = base;
            sig.push_back(suffix);
            BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(sig));
            BOOST_CHECK(!pq::Verify(pq::kFalcon512Info, msg, sig, pk, true));
            BOOST_CHECK(!pq::Verify(pq::kFalcon512Info, msg, sig, pk, false));
        }
        auto padded = base;
        padded.resize(666, 0);
        BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(padded));
        BOOST_CHECK(!pq::Verify(pq::kFalcon512Info, msg, padded, pk, true));
        for (const unsigned char header : {0, 0x38, 0x3a, 0xff}) {
            auto sig = base;
            sig[0] = header;
            BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(sig));
        }
    }
    // Classification does not check the nonce, message, key or norm.
    alternate[1] ^= 1;
    BOOST_CHECK(pq::IsNonCanonicalLegacyFalcon512(alternate));
    BOOST_CHECK(!pq::Verify(pq::kFalcon512Info, msg, alternate, pk, true));
    const std::vector<unsigned char> large(65536, 0x39);
    BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(large));
    // A complete canonical encoding need not be a valid mathematical signature.
    for (const int16_t value : {0, 2047}) {
        std::array<int16_t, 512> coefficients;
        coefficients.fill(value);
        const auto sig = test::EncodeFalcon512(coefficients);
        BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(sig));
        BOOST_CHECK(!pq::Verify(pq::kFalcon512Info, msg, sig, pk, true));
        BOOST_CHECK(!pq::Verify(pq::kFalcon512Info, msg, sig, pk, false));
    }
}

BOOST_AUTO_TEST_CASE(falcon_encoding_boundaries)
{
    std::array<int16_t, 512> coefficients{};
    // The all-zero body is byte aligned; adding unary bits covers every
    // remaining final-byte alignment without relying on randomized signing.
    for (unsigned extra_bits = 0; extra_bits < 8; ++extra_bits) {
        coefficients[0] = 128 * extra_bits;
        auto sig = test::EncodeFalcon512(coefficients);
        const auto parsed = test::ParseFalcon512(sig);
        BOOST_REQUIRE(parsed);
        BOOST_CHECK(parsed->coefficients == coefficients);
        BOOST_CHECK_EQUAL(parsed->unused_bits, (8 - extra_bits) % 8);
        BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(sig));
        auto negative_zero = sig;
        test::SetFalconBit(negative_zero, parsed->zero_sign_bits.back());
        BOOST_CHECK(pq::IsNonCanonicalLegacyFalcon512(negative_zero));
        if (parsed->unused_bits) {
            sig.back() |= (1U << parsed->unused_bits) - 1;
            BOOST_CHECK(pq::IsNonCanonicalLegacyFalcon512(sig));
        }
    }
    for (const int16_t magnitude : {-2047, 2047}) {
        coefficients.fill(magnitude);
        const auto sig = test::EncodeFalcon512(coefficients);
        const auto parsed = test::ParseFalcon512(sig);
        BOOST_REQUIRE(parsed);
        BOOST_CHECK(parsed->coefficients == coefficients);
        BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(sig));
    }
    coefficients.fill(0);
    coefficients[0] = 2048;
    auto invalid = test::EncodeFalcon512(coefficients);
    BOOST_CHECK(!test::ParseFalcon512(invalid));
    BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(invalid));
    // An unterminated unary coefficient, including its truncations.
    invalid.resize(44);
    std::fill(invalid.begin() + 41, invalid.end(), 0);
    for (size_t length = 41; length <= invalid.size(); ++length) {
        BOOST_CHECK(!pq::IsNonCanonicalLegacyFalcon512(std::span{invalid}.first(length)));
    }
}

BOOST_AUTO_TEST_SUITE_END()
