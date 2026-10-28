// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <hash.h>
#include <pq/pq_api.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/vector.h>

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_key_sign_verify_roundtrip)
{
    CKey key1 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CKey key2 = GenerateRandomKey(pq::SchemeId::FALCON_512);

    BOOST_CHECK(key1.IsValid());
    BOOST_CHECK(key2.IsValid());

    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();

    BOOST_CHECK(key1.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
    BOOST_CHECK(key2.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey1));

    const uint256 hashMsg = Hash("tidecoin pq key test");
    std::vector<unsigned char> sig1;
    std::vector<unsigned char> sig2;

    BOOST_CHECK(key1.Sign(hashMsg, sig1));
    BOOST_CHECK(key2.Sign(hashMsg, sig2));
    BOOST_CHECK(pubkey1.Verify(hashMsg, sig1));
    BOOST_CHECK(!pubkey1.Verify(hashMsg, sig2));
    BOOST_CHECK(pubkey2.Verify(hashMsg, sig2));
    BOOST_CHECK(!pubkey2.Verify(hashMsg, sig1));
}

BOOST_AUTO_TEST_CASE(pq_pubkey_serialize_roundtrip)
{
    CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());

    DataStream stream{};
    stream << pubkey;
    CPubKey pubkey2;
    stream >> pubkey2;
    BOOST_CHECK(pubkey == pubkey2);
}

BOOST_AUTO_TEST_CASE(pq_pubkey_invalid_length)
{
    const unsigned char prefix = pq::kFalcon512Info.prefix;
    std::vector<unsigned char> wrong_len{prefix, 0x00};
    CPubKey bad_pk(wrong_len);
    BOOST_CHECK(!bad_pk.IsValid());
}

BOOST_AUTO_TEST_CASE(pq_pubkey_full_encoding)
{
    for (const auto* scheme : pq::kKnownSchemes) {
        const CPubKey generated = GenerateRandomKey(scheme->id).GetPubKey();
        BOOST_REQUIRE(generated.IsValid());
        BOOST_CHECK(generated.IsFullyValid());
        BOOST_CHECK(pq::IsValidPubKey(generated));
        DataStream stream;
        stream << generated;
        CPubKey restored;
        stream >> restored;
        BOOST_CHECK(restored == generated);
        BOOST_CHECK(restored.IsFullyValid());

        const auto bytes = ToByteVector(generated);
        for (const size_t length : {size_t{0}, size_t{1}, size_t{2}, bytes.size() - 1, bytes.size() + 1}) {
            auto truncated = bytes;
            truncated.resize(length);
            BOOST_CHECK(!pq::IsValidPubKey(truncated));
            BOOST_CHECK(!CPubKey(truncated).IsValid());
            BOOST_CHECK(!CPubKey(truncated).IsFullyValid());
        }
        auto unknown = bytes;
        unknown[0] = 0xff;
        BOOST_CHECK(!pq::IsValidPubKey(unknown));
        BOOST_CHECK(!CPubKey(unknown).IsFullyValid());

        if (scheme->id != pq::SchemeId::FALCON_512 && scheme->id != pq::SchemeId::FALCON_1024) {
            // ML-DSA's seed and packed 10-bit values have no excluded patterns.
            for (const unsigned char fill : {0x00, 0xff, 0x55}) {
                std::vector<unsigned char> packed(bytes.size(), fill);
                packed[0] = scheme->prefix;
                BOOST_CHECK(CPubKey(packed).IsFullyValid());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(falcon_pubkey_encoding_boundaries)
{
    for (const auto* scheme : {&pq::kFalcon512Info, &pq::kFalcon1024Info}) {
        const unsigned logn = scheme->id == pq::SchemeId::FALCON_512 ? 9 : 10;
        std::vector<unsigned char> zero(scheme->pubkey_bytes + 1, 0);
        zero[0] = scheme->prefix;
        zero[1] = logn;
        // Encoding validation is not proof of possession of a private key.
        BOOST_REQUIRE(CPubKey(zero).IsFullyValid());
        for (const unsigned char header : {0, 9, 10, 255}) {
            if (header == logn) continue;
            auto bad = zero;
            bad[1] = header;
            BOOST_CHECK(CPubKey(bad).IsValid());
            BOOST_CHECK(!CPubKey(bad).IsFullyValid());
        }
        auto swapped = zero;
        swapped[0] = scheme->id == pq::SchemeId::FALCON_512 ? pq::kFalcon1024Info.prefix : pq::kFalcon512Info.prefix;
        BOOST_CHECK(!pq::IsValidPubKey(swapped));

        // Check every packed position, including coefficients crossing bytes.
        for (size_t index = 0; index < (size_t{1} << logn); ++index) {
            for (const unsigned value : {12288U, 12289U, 16383U}) {
                auto packed = zero;
                for (unsigned bit = 0; bit < 14; ++bit) {
                    const size_t offset = 16 + 14 * index + bit;
                    packed.at(offset / 8) |= ((value >> (13 - bit)) & 1U) << (7 - offset % 8);
                }
                const CPubKey pubkey(packed);
                BOOST_CHECK(pubkey.IsValid());
                BOOST_CHECK_EQUAL(pubkey.IsFullyValid(), value < 12289);
                BOOST_CHECK_EQUAL(pq::IsValidPubKey(packed), value < 12289);
                DataStream stream;
                stream << pubkey;
                CPubKey restored;
                stream >> restored;
                BOOST_CHECK(restored == pubkey);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(multisig_optional_malformed_pubkey)
{
    const CKey first = GenerateRandomKey(pq::SchemeId::FALCON_512);
    const CKey second = GenerateRandomKey(pq::SchemeId::FALCON_512);
    for (const auto* scheme : {&pq::kFalcon512Info, &pq::kFalcon1024Info}) {
        for (const bool bad_header : {false, true}) {
            std::vector<unsigned char> malformed(scheme->pubkey_bytes + 1, 0);
            malformed[0] = scheme->prefix;
            malformed[1] = bad_header ? 0 : scheme->id == pq::SchemeId::FALCON_512 ? 9 : 10;
            if (!bad_header) {
                malformed[2] = 0xc0;
                malformed[3] = 0x04; // First 14-bit coefficient is 12289.
            }
            BOOST_REQUIRE(CPubKey(malformed).IsValid());
            BOOST_REQUIRE(!CPubKey(malformed).IsFullyValid());
            for (const bool strict : {false, true}) {
                for (const bool required : {false, true}) {
                    // CHECKMULTISIG visits the last key first, so the malformed
                    // optional key is actually examined before matching the others.
                    const CScript script = CScript{} << (required ? OP_3 : OP_2)
                        << ToByteVector(first.GetPubKey()) << ToByteVector(second.GetPubKey())
                        << malformed << OP_3 << OP_CHECKMULTISIG;
                    CMutableTransaction tx;
                    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
                    tx.vout.emplace_back(1, CScript{} << OP_TRUE);
                    const uint256 hash = SignatureHash(script, tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
                    std::vector<unsigned char> sig1, sig2;
                    BOOST_REQUIRE(first.Sign(hash, sig1));
                    BOOST_REQUIRE(second.Sign(hash, sig2));
                    sig1.push_back(SIGHASH_ALL);
                    sig2.push_back(SIGHASH_ALL);
                    CScript input = CScript{} << OP_0 << sig1 << sig2;
                    if (required) input << OP_0;
                    ScriptError error;
                    const unsigned flags = strict ? SCRIPT_VERIFY_PQ_STRICT : SCRIPT_VERIFY_NONE;
                    const MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL, !strict);
                    BOOST_CHECK_EQUAL(VerifyScript(input, script, nullptr, flags, checker, &error), !required);
                    BOOST_CHECK(error == (required ? SCRIPT_ERR_EVAL_FALSE : SCRIPT_ERR_OK));
                }
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
