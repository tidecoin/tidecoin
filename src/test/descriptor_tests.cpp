// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <pq/pq_scheme.h>
#include <key.h>
#include <key_io.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <string>
#include <vector>

namespace {

/** Compare two descriptors. If only one of them has a checksum, the checksum is ignored. */
bool EqualDescriptor(std::string a, std::string b)
{
    const bool a_check{a.size() > 9 && a[a.size() - 9] == '#'};
    const bool b_check{b.size() > 9 && b[b.size() - 9] == '#'};
    if (a_check != b_check) {
        if (a_check) a = a.substr(0, a.size() - 9);
        if (b_check) b = b.substr(0, b.size() - 9);
    }
    return a == b;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(descriptor_pqhd_key_expression_parsing)
{
    FlatSigningProvider out;
    std::string error;

    const std::string seedid{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};

    const std::string ranged{"wpkh(pqhd(" + seedid + ")/10007h/6868h/7h/0h/0h/*h)"};
    auto parsed_ranged = Parse(ranged, out, error);
    BOOST_REQUIRE_MESSAGE(!parsed_ranged.empty(), error);
    BOOST_CHECK_MESSAGE(EqualDescriptor(ranged, parsed_ranged.at(0)->ToString()), parsed_ranged.at(0)->ToString());
    BOOST_CHECK(parsed_ranged.at(0)->IsRange());
    BOOST_CHECK(out.keys.empty());
    const auto ranged_prefix = parsed_ranged.at(0)->GetPQHDSchemePrefix();
    BOOST_REQUIRE(ranged_prefix.has_value());
    BOOST_CHECK_EQUAL(*ranged_prefix, static_cast<uint8_t>(pq::SchemeId::FALCON_512));

    const std::string fixed{"wpkh(pqhd(" + seedid + ")/10007h/6868h/7h/0h/0h/0h)"};
    out = FlatSigningProvider{};
    auto parsed_fixed = Parse(fixed, out, error);
    BOOST_REQUIRE_MESSAGE(!parsed_fixed.empty(), error);
    BOOST_CHECK_MESSAGE(EqualDescriptor(fixed, parsed_fixed.at(0)->ToString()), parsed_fixed.at(0)->ToString());
    BOOST_CHECK(!parsed_fixed.at(0)->IsRange());
    BOOST_CHECK(out.keys.empty());
    const auto fixed_prefix = parsed_fixed.at(0)->GetPQHDSchemePrefix();
    BOOST_REQUIRE(fixed_prefix.has_value());
    BOOST_CHECK_EQUAL(*fixed_prefix, static_cast<uint8_t>(pq::SchemeId::FALCON_512));

    const auto must_fail = [&](const std::string& s, const std::string& needle) {
        out = FlatSigningProvider{};
        error.clear();
        auto parsed = Parse(s, out, error);
        BOOST_CHECK(parsed.empty());
        BOOST_CHECK_MESSAGE(!error.empty(), "expected parse error");
        const bool has_expected = error.find(needle) != std::string::npos;
        const bool has_fallback = error.find("Key path value") != std::string::npos;
        BOOST_CHECK_MESSAGE(has_expected || has_fallback, error);
    };

    must_fail("wpkh(pqhd(" + seedid + ")/10007/6868h/7h/0h/0h/*h)", "hardened-only");
    must_fail("wpkh(pqhd(" + seedid + ")/10007h/6868h/7h/0h/0h/*)", "*h");
    must_fail("wpkh(pqhd(" + seedid + ")/10008h/6868h/7h/0h/0h/*h)", "purpose");
    must_fail("wpkh(pqhd(" + seedid + ")/10007h/6868h/6h/0h/0h/*h)", "not recognized");
    must_fail("wpkh(pqhd(" + seedid.substr(0, 10) + ")/10007h/6868h/7h/0h/0h/*h)", "pqhd() seed id");
}

BOOST_AUTO_TEST_CASE(descriptor_wsh512_parsing)
{
    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    const CPubKey pubkey = key.GetPubKey();

    FlatSigningProvider out;
    std::string error;
    const std::string desc_str = "wsh512(pk(" + HexStr(pubkey) + "))";
    auto descs = Parse(desc_str, out, error);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), error);
    BOOST_CHECK_MESSAGE(EqualDescriptor(desc_str, descs.at(0)->ToString()), descs.at(0)->ToString());
    BOOST_CHECK(!descs.at(0)->IsRange());
    BOOST_REQUIRE(descs.at(0)->GetOutputType().has_value());
    BOOST_CHECK_EQUAL(*descs.at(0)->GetOutputType(), OutputType::BECH32PQ);
}

BOOST_AUTO_TEST_CASE(descriptor_explicit_pq_pubkey_matrix)
{
    FlatSigningProvider out;
    std::string error;

    auto parse_ok = [&](const std::string& desc, bool expect_same_public_string = true) {
        out = FlatSigningProvider{};
        error.clear();
        auto parsed = Parse(desc, out, error);
        BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
        if (expect_same_public_string) {
            BOOST_CHECK_MESSAGE(EqualDescriptor(desc, parsed.at(0)->ToString()), parsed.at(0)->ToString());
        }
        std::vector<CScript> scripts;
        FlatSigningProvider scripts_out;
        DescriptorCache cache;
        BOOST_REQUIRE(parsed.at(0)->Expand(0, out, scripts, scripts_out, &cache));
        BOOST_REQUIRE(!scripts.empty());
        if (parsed.at(0)->IsSingleType()) {
            BOOST_REQUIRE(parsed.at(0)->ScriptSize().has_value());
            BOOST_CHECK_EQUAL(*parsed.at(0)->ScriptSize(), scripts.back().size());
        }
        return parsed;
    };

    auto parse_fail = [&](const std::string& desc, const std::string& needle) {
        out = FlatSigningProvider{};
        error.clear();
        auto parsed = Parse(desc, out, error);
        BOOST_CHECK(parsed.empty());
        BOOST_CHECK_MESSAGE(!error.empty(), "expected parse error");
        BOOST_CHECK_MESSAGE(error.find(needle) != std::string::npos, error);
    };

    struct SchemeCase {
        pq::SchemeId id;
    };
    const std::array<SchemeCase, 5> schemes{{
        {pq::SchemeId::FALCON_512},
        {pq::SchemeId::FALCON_1024},
        {pq::SchemeId::MLDSA_44},
        {pq::SchemeId::MLDSA_65},
        {pq::SchemeId::MLDSA_87},
    }};

    std::vector<CPubKey> pubkeys;
    pubkeys.reserve(schemes.size());
    for (const auto& scheme : schemes) {
        CKey key;
        key.MakeNewKey(scheme.id);
        const CPubKey pubkey = key.GetPubKey();
        BOOST_REQUIRE(pubkey.IsFullyValid());
        pubkeys.push_back(pubkey);
        const std::string hex = HexStr(pubkey);

        // Explicit PQ raw-hex key expressions should parse across wrappers.
        parse_ok("pk(" + hex + ")");
        parse_ok("pk(" + EncodeSecret(key) + ")", /*expect_same_public_string=*/false);
        parse_ok("pkh(" + hex + ")");
        parse_ok("wpkh(" + hex + ")");
        parse_ok("sh(wpkh(" + hex + "))");
        parse_ok("combo(" + hex + ")");
        parse_ok("wsh(pk(" + hex + "))");
        parse_ok("wsh512(pk(" + hex + "))");
        parse_ok("multi(1," + hex + ")");
        parse_ok("sortedmulti(1," + hex + ")");
        parse_ok("wsh(multi(1," + hex + "))");
    }

    // Mixed-scheme multisig is permitted but has no unambiguous single scheme prefix.
    const std::string mixed = "wsh(multi(1," + HexStr(pubkeys.at(0)) + "," + HexStr(pubkeys.at(2)) + "))";
    auto parsed_mixed = parse_ok(mixed);
    BOOST_CHECK(!parsed_mixed.at(0)->GetPQHDSchemePrefix().has_value());

    // Explicit legacy compressed pubkeys are not accepted in PQ-only descriptor parsing.
    parse_fail("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", "is invalid");
    // BIP32/xpub/xprv expressions are not part of Tidecoin PQ descriptor surface.
    parse_fail("wpkh(xpub661MyMwAqRbcF9QxvA3GvH7Tn2Y4m4v5hJ4Qqg1j9n7S7g7J8q9r3kQ3mLZ2kJ1w4Vw1Y8r6mQ6W2j3s5E5n7jL9pQ2aB6v2mN2QhM8mY8/0/*)", "not valid");
}

BOOST_AUTO_TEST_SUITE_END()
