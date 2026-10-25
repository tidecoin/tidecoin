// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324_pq.h>
#include <chainparams.h>
#include <pq/pq_api.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <array>
#include <cstddef>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

struct BIP324PQTest : BasicTestingSetup {
    BIP324PQTest() : BasicTestingSetup{} { SelectParams(ChainType::MAIN); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(bip324_pq_tests, BIP324PQTest)

BOOST_AUTO_TEST_CASE(kem_key_lifetime)
{
    pq::MLKEM512Keypair keys;
    BOOST_CHECK(!keys.IsInitialized());
    BOOST_REQUIRE(keys.Generate());
    const auto public_key = keys.PublicKey();
    const auto secret_key = keys.SecretKey();
    const std::vector<uint8_t> saved_pk(public_key.begin(), public_key.end());
    const std::vector<uint8_t> saved_sk(secret_key.begin(), secret_key.end());
    BOOST_CHECK(std::ranges::any_of(secret_key, [](uint8_t b) { return b != 0; }));
    keys.Clear();
    BOOST_CHECK(!keys.IsInitialized());
    BOOST_CHECK(std::ranges::all_of(public_key, [](uint8_t b) { return b == 0; }));
    BOOST_CHECK(std::ranges::all_of(secret_key, [](uint8_t b) { return b == 0; }));
    keys.Clear(); // Idempotent, including destruction after explicit cleanup.
    BOOST_REQUIRE(keys.Set(saved_pk, saved_sk));
    BOOST_CHECK(keys.IsInitialized());

    std::array<uint8_t, pq::MLKEM512_CIPHERTEXT_BYTES> ct{};
    std::array<uint8_t, pq::MLKEM512_SHARED_SECRET_BYTES> ss{}, recovered{}, coins{};
    BOOST_REQUIRE(pq::MLKEM512Encaps(keys.PublicKey(), ct, ss));
    BOOST_REQUIRE(pq::MLKEM512Decaps(ct, keys.SecretKey(), recovered));
    BOOST_CHECK(ss == recovered);
    BOOST_REQUIRE(pq::MLKEM512EncapsDeterministic(keys.PublicKey(), coins, ct, ss));
    BOOST_REQUIRE(pq::MLKEM512Decaps(ct, keys.SecretKey(), recovered));
    BOOST_CHECK(ss == recovered);
    ct[0] ^= 1;
    // Ciphertext rejection remains implicit: success with a different shared secret.
    BOOST_REQUIRE(pq::MLKEM512Decaps(ct, keys.SecretKey(), recovered));
    BOOST_CHECK(ss != recovered);

    keys.Clear();
    std::array<uint8_t, pq::MLKEM512_KEYPAIR_COINS_BYTES> seed{};
    BOOST_REQUIRE(keys.GenerateDeterministic(seed));
    BOOST_CHECK(keys.IsInitialized());
    BOOST_REQUIRE(pq::MLKEM512Encaps(keys.PublicKey(), ct, ss));
    BOOST_REQUIRE(pq::MLKEM512Decaps(ct, keys.SecretKey(), recovered));
    BOOST_CHECK(ss == recovered);
}

BOOST_AUTO_TEST_CASE(kem_encapsulation_key_validation)
{
    std::array<uint8_t, pq::MLKEM512_PUBLICKEY_BYTES> pk{};
    std::array<uint8_t, pq::MLKEM512_SHARED_SECRET_BYTES> coins{}, ss{};
    std::array<uint8_t, pq::MLKEM512_CIPHERTEXT_BYTES> ct{};
    const auto check = [&](std::span<const uint8_t> key, bool valid) {
        ct.fill(0xa5);
        ss.fill(0x5a);
        const auto previous_ct = ct;
        const auto previous_ss = ss;
        BOOST_CHECK_EQUAL(pq::MLKEM512Encaps(key, ct, ss), valid);
        if (!valid) {
            BOOST_CHECK(ct == previous_ct);
            BOOST_CHECK(ss == previous_ss);
        }
        BOOST_CHECK_EQUAL(pq::MLKEM512EncapsDeterministic(key, coins, ct, ss), valid);
        if (!valid) {
            BOOST_CHECK(ct == previous_ct);
            BOOST_CHECK(ss == previous_ss);
        }
    };
    const auto set_coefficient = [&](size_t index, uint16_t value) {
        const size_t offset = (index / 2) * 3;
        if (index % 2 == 0) {
            pk[offset] = value & 0xff;
            pk[offset + 1] = (pk[offset + 1] & 0xf0) | (value >> 8);
        } else {
            pk[offset + 1] = (pk[offset + 1] & 0x0f) | ((value & 0xf) << 4);
            pk[offset + 2] = value >> 4;
        }
    };

    check(pk, true); // Canonical encoding need not prove the key was generated.
    for (size_t index = 0; index < 512; ++index) {
        for (uint16_t value : {3328, 3329, 4095}) {
            set_coefficient(index, value);
            check(pk, value < 3329);
        }
        set_coefficient(index, 0);
    }
    // Every out-of-range encoding, in each half of a packed pair.
    for (uint16_t value = 3329; value < 4096; ++value) {
        for (size_t index : {0, 1}) {
            set_coefficient(index, value);
            check(pk, false);
            set_coefficient(index, 0);
        }
    }
    std::fill(pk.end() - 32, pk.end(), 0xff); // Public seed has no modulus restriction.
    check(pk, true);
    check(std::span{pk}.first(pk.size() - 1), false);
    std::vector<uint8_t> oversized(pk.size() + 1);
    check(oversized, false);
}

BOOST_AUTO_TEST_CASE(cipher_roundtrip)
{
    std::array<std::byte, 32> shared_secret{};
    for (size_t i = 0; i < shared_secret.size(); ++i) {
        shared_secret[i] = std::byte{static_cast<unsigned char>(i)};
    }

    BIP324PQCipher initiator;
    BIP324PQCipher responder;
    initiator.InitializeFromSharedSecret(shared_secret, true);
    responder.InitializeFromSharedSecret(shared_secret, false);

    BOOST_CHECK(initiator);
    BOOST_CHECK(responder);
    BOOST_CHECK(std::ranges::equal(initiator.GetSessionID(), responder.GetSessionID()));
    BOOST_CHECK(std::ranges::equal(initiator.GetSendGarbageTerminator(), responder.GetReceiveGarbageTerminator()));
    BOOST_CHECK(std::ranges::equal(initiator.GetReceiveGarbageTerminator(), responder.GetSendGarbageTerminator()));

    const auto aad = ParseHex<std::byte>("a1b2c3");
    const auto msg = ParseHex<std::byte>("deadbeef");

    std::vector<std::byte> ciphertext(msg.size() + BIP324PQCipher::EXPANSION);
    initiator.Encrypt(msg, aad, false, ciphertext);

    uint32_t len = responder.DecryptLength(std::span{ciphertext}.first(BIP324PQCipher::LENGTH_LEN));
    BOOST_CHECK_EQUAL(len, msg.size());

    std::vector<std::byte> decoded(len);
    bool ignore{false};
    BOOST_CHECK(responder.Decrypt(std::span{ciphertext}.subspan(BIP324PQCipher::LENGTH_LEN), aad, ignore, decoded));
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded.begin(), decoded.end(), msg.begin(), msg.end());
    BOOST_CHECK(!ignore);
}

BOOST_AUTO_TEST_SUITE_END()
