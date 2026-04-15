// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/key_io_invalid.json.h>
#include <test/data/key_io_valid.json.h>

#include <base58.h>
#include <bech32.h>
#include <coins.h>
#include <consensus/amount.h>
#include <key.h>
#include <key_io.h>
#include <pq/pq_api.h>
#include <pq/pq_scheme.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

BOOST_FIXTURE_TEST_SUITE(key_io_tests, BasicTestingSetup)

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(key_io_valid_parse)
{
    UniValue tests = read_json(json_tests::key_io_valid);
    CKey privkey;
    CTxDestination destination;
    SelectParams(ChainType::MAIN);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) { // Allow for extra stuff (useful for comments)
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        const std::vector<std::byte> exp_payload{ParseHex<std::byte>(test[1].get_str())};
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        bool try_case_flip = metadata.find_value("tryCaseFlip").isNull() ? false : metadata.find_value("tryCaseFlip").get_bool();
        if (isPrivkey) {
            // Skip legacy private key vectors; PQ WIF coverage is handled separately.
            continue;
        } else {
            // Must be valid public key
            destination = DecodeDestination(exp_base58string);
            CScript script = GetScriptForDestination(destination);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination), "!IsValid:" + strTest);
            BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));

            // Try flipped case version
            for (char& c : exp_base58string) {
                if (c >= 'a' && c <= 'z') {
                    c = (c - 'a') + 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c = (c - 'A') + 'a';
                }
            }
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination) == try_case_flip, "!IsValid case flipped:" + strTest);
            if (IsValidDestination(destination)) {
                script = GetScriptForDestination(destination);
                BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));
            }

            // Public key must be invalid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(key_io_valid_gen)
{
    UniValue tests = read_json(json_tests::key_io_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        if (isPrivkey) {
            // Skip legacy private key vectors; PQ WIF coverage is handled separately.
            continue;
        } else {
            CTxDestination dest;
            CScript exp_script(exp_payload.begin(), exp_payload.end());
            BOOST_CHECK(ExtractDestination(exp_script, dest));
            std::string address = EncodeDestination(dest);

            BOOST_CHECK_EQUAL(address, exp_base58string);
        }
    }

    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(key_io_pq_privkey_roundtrip)
{
    SelectParams(ChainType::MAIN);

    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    BOOST_REQUIRE(key.IsValid());

    const std::string encoded = EncodeSecret(key);
    CKey decoded = DecodeSecret(encoded);
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(key == decoded);

    // WIF strings must not parse as destinations.
    BOOST_CHECK(!IsValidDestination(DecodeDestination(encoded)));
}

BOOST_AUTO_TEST_CASE(key_io_pq_privkey_roundtrip_large)
{
    SelectParams(ChainType::MAIN);

    CKey key;
    key.MakeNewKey(pq::SchemeId::MLDSA_87);
    BOOST_REQUIRE(key.IsValid());

    const std::string encoded = EncodeSecret(key);
    BOOST_TEST_MESSAGE("ML-DSA-87 WIF length=" << encoded.size());

    CKey decoded = DecodeSecret(encoded);
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(key == decoded);
}

BOOST_AUTO_TEST_CASE(key_io_pq_privkey_roundtrip_all_schemes)
{
    SelectParams(ChainType::MAIN);

    const std::array<pq::SchemeId, 5> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_87,
    };

    for (const auto scheme : schemes) {
        CKey key;
        key.MakeNewKey(scheme);
        BOOST_REQUIRE_MESSAGE(key.IsValid(), "key invalid for scheme " << static_cast<int>(scheme));

        const std::string encoded = EncodeSecret(key);
        CKey decoded = DecodeSecret(encoded);
        BOOST_REQUIRE_MESSAGE(decoded.IsValid(), "decode failed for scheme " << static_cast<int>(scheme));
        BOOST_CHECK_MESSAGE(key == decoded, "roundtrip mismatch for scheme " << static_cast<int>(scheme));
    }
}

BOOST_AUTO_TEST_CASE(key_io_pq_legacy_wif_roundtrip)
{
    SelectParams(ChainType::MAIN);

    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    BOOST_REQUIRE(key.IsValid());

    const std::string legacy = EncodeSecretLegacy(key);
    BOOST_REQUIRE(!legacy.empty());

    CKey decoded = DecodeSecret(legacy);
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(key == decoded);

    // Legacy WIF for non-Falcon schemes should be rejected.
    CKey mldsa;
    mldsa.MakeNewKey(pq::SchemeId::MLDSA_44);
    BOOST_REQUIRE(mldsa.IsValid());
    const CPubKey pubkey = mldsa.GetPubKey();
    const pq::SchemeInfo* scheme = pq::SchemeFromPrefix(pubkey[0]);
    BOOST_REQUIRE(scheme != nullptr);

    CPrivKey priv = mldsa.GetPrivKey();
    std::span<const unsigned char> raw = priv;
    if (raw.size() == scheme->seckey_bytes + 1 && raw[0] == scheme->prefix) {
        raw = raw.subspan(1);
    }
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), raw.begin(), raw.end());
    data.push_back(1);
    data.insert(data.end(), pubkey.begin(), pubkey.end());
    const std::string legacy_bad = EncodeBase58Check(data);

    CKey decoded_bad = DecodeSecret(legacy_bad);
    BOOST_CHECK(!decoded_bad.IsValid());
}

BOOST_AUTO_TEST_CASE(key_io_txcreatesignv1_p2pkh_legacy_wif_verifies)
{
    // Minimal reproduction of the failing `tidecoin-tx` util vector txcreatesignv1:
    // P2PKH prevout (BASE sighash), Falcon-512 legacy signing enabled, must pass VerifyScript.
    SelectParams(ChainType::MAIN);

    // From test/functional/data/util/tidecoin-util-test.json ("txcreatesignv1").
    static const std::string kWif =
        "6ddD664vfvjyAquu3uNwVWehzSCoywRyjqo1EA9xdA2iQH8bBNYi7VNEPkqx7rm5b2pqUsDtu9YdwQ4rkHs2Xq5XzpLywUsYS7LeiZyBXmmmZ47q1zxB6b2N14PKvXfywgajjpxv7WFRAqtWDXi6uy5NVwsLn2KdJQybjQpMzX9772M1gCoc3EgBvwfin8c7aeeBdSWShh9gh5pbGTrcU2LeQPoWP4yTRhZ2sCxNuaJWaMPbjyhEf5QFBpXmLCtQQiGjSghttdLayrhBr3hw3ydGk4rwTTgv8MX68rZvnEEV3xibEG3ud8Rq7jGfumk4FaAEUdfiRdHZEZdBx4wDYaQurihxcm6EMCApZ9v1B68NNh4whtQLuHfsqod5ye8K9TPHWS19MtFT96dtdMuSB5CwvhL8Fa6TTjwPAGBYpU5xynym9bdMrZRMsUhTzAyoGmFD1sp94jUE46iwdfp7FFrboyPLV5zLiDfToKmM1J2343quyuzrTewmA6wdqUZbKAmhtL28pbDAoy6jMwk2TM1cggcFmSR3uSXcgDVnV7J9mTBmpvXDaN8xxG18JcSWSbewFVnHLCddvhPn2ZutGPpMRtDkMc3vWt5s9iD3gTUyWC9kjZsjc65Gd6t3JChSKDpUC5BGA5pdHBwo2P5j87DkZqcrUjpeMX25zgPMdt9ZWeRs6SUqJtTGMj4Hk1syNbovpm4Eqha66n8vTvVnwHrxvn85ds4ZcFpxv1FukG7TQ6iStJLBcmwcUSFtyvBFmbK9qu8ToXNGoPnqVCR8V6XveLPCfDELjHoCMCLnp4eQa3AwJpg9Pg9qVQjvcoHqD44JuZ86CAjLcyAmm9QnFcs3JX7JyLKCnBzj3DfjWr2SNgrhjiGnMBrykjEVX6vis6vDL9cJ56jTuxWDovhwzBr5VbkoBArh6MS6z1SPv6Xvv8Sj7ej3nRHZ31Gh5estzKzdUKSU2vQxmtd4Q6KqjjBSf6xLU1K1S9mAtqn3CzKMMDKeLFtTu1oFwHTGDqaCDmAKXWJX1o2xzmTdWCd3UHB9wobBjtjWUcNxvw4ig7BHW89JgsbfzRneyktwdk1cYWU52AHTdFUSnchYwQBPEqyJ5bD7zWo5AbVNMPrebEnt2Sb29CS2XYBwsD88hU6ka2BHmNmTGedEHJmhHzkrJkyWqFAkSZBsH5yq6x6ttYrDH8zXX7i98FzV2ZKnKuyy6NcgwpC8rYaMYPSie14DzoPfGUJc6BytBV69mZDsoJ2UUoVH94uiBkZUPTFfDcyCoDxBACCPxdCnJokerkAvDmFzujELyf2rK9nEoQeVdh9QJdYTTLAgJdzMyREHHYWyseWWti9n2gadocnRwiUMSqEt683KHiMW4Bn8AWBDSFQfXZYvVBcuEL4jvBSXMVJt4Z6cD11gqmCM9BgEGy2CoNLELVmRDRq3RMN22G2jX5U353eqikvgumub2sGRuErt3vbDuEELbmJAzLrVrXjfmbeU5ev5ZhMpBP7CiyRy7sk2DViDYDrZ9W5J8hPDRDVy7SV85bF1MHz1GjXjMjCMSSBYwvPTT9gd7Rmmc1MfVo26t6iS4YVdVeoCBGdvLdCUWd6Z8UZPmkpPASnVN3yj9m119DRyXsZUsqyeNF2vEDTVSNfjfofLGqfFmKtHDEkECW94huFapxokwmSvgi15sYiEKXBXknHnctaEiahSh7ha9qJ6UqhEnd7aJxzG1JbUerZbZMF4dxLEumd66ixzbgAWSBHoC1";
    static constexpr std::string_view kPrevTxid =
        "4d49a71ec9da436f71ec4ee231d04f292a29cd316f598bb7068feccabdc59485";
    static constexpr uint32_t kPrevVout{0};
    static constexpr std::string_view kPrevScriptPubKeyHex =
        "76a9145a2f1784c55a322ffe4cc3ca9fea8dfb44cdea1188ac";
    static constexpr std::string_view kOutAddr =
        "ERNkirDf3jsER2ykJevf8USM2rj8Xi3GCF";
    static constexpr CAmount kOutAmount{COIN / 1000}; // 0.001

    const CKey key = DecodeSecret(kWif);
    BOOST_REQUIRE_MESSAGE(key.IsValid(), "DecodeSecret(WIF) failed");
    const CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE_MESSAGE(pubkey.IsValidNonHybrid(), "decoded pubkey invalid");

    // Sanity: pubkey derived from the decoded secret must match the prevout PKH.
    const std::vector<unsigned char> prev_script_bytes = ParseHex(kPrevScriptPubKeyHex);
    const CScript prev_script(prev_script_bytes.begin(), prev_script_bytes.end());
    CTxDestination prev_dest;
    BOOST_REQUIRE(ExtractDestination(prev_script, prev_dest));
    const auto* pkh = std::get_if<PKHash>(&prev_dest);
    BOOST_REQUIRE(pkh != nullptr);
    BOOST_CHECK(ToKeyID(*pkh) == pubkey.GetID());

    // Stronger invariant: recompute pubkey from secret bytes, ensure it matches the stored pubkey.
    {
        const CPrivKey priv = key.GetPrivKey();
        const pq::SchemeInfo* scheme = nullptr;
        std::span<const unsigned char> raw_sk;
        BOOST_REQUIRE_MESSAGE(pq::DecodeSecretKey(std::span<const unsigned char>{priv.data(), priv.size()}, scheme, raw_sk, /*allow_legacy=*/false),
                              "pq::DecodeSecretKey failed");
        BOOST_REQUIRE(scheme != nullptr);

        std::vector<unsigned char> recomputed_pk(scheme->pubkey_bytes);
        BOOST_REQUIRE_MESSAGE(pq::ComputePublicKeyFromSecret(*scheme, raw_sk, recomputed_pk), "ComputePublicKeyFromSecret failed");

        pq::SchemeId pk_id{};
        std::span<const unsigned char> raw_pk;
        const std::vector<unsigned char> pub_bytes(pubkey.begin(), pubkey.end());
        BOOST_REQUIRE_MESSAGE(pq::DecodePubKey(std::span<const unsigned char>{pub_bytes.data(), pub_bytes.size()}, pk_id, raw_pk),
                              "pq::DecodePubKey failed");
        BOOST_CHECK(pk_id == scheme->id);
        BOOST_REQUIRE(raw_pk.size() == recomputed_pk.size());
        BOOST_CHECK(std::equal(raw_pk.begin(), raw_pk.end(), recomputed_pk.begin()));
    }

    // Build a tx matching the vector (P2PKH spend, BASE sighash).
    const Txid txid = Txid::FromHex(kPrevTxid).value();
    const COutPoint prevout{txid, kPrevVout};

    const CTxDestination out_dest = DecodeDestination(std::string(kOutAddr));
    BOOST_REQUIRE_MESSAGE(IsValidDestination(out_dest), "output address failed DecodeDestination");
    const CScript out_script = GetScriptForDestination(out_dest);

    CMutableTransaction mtx;
    mtx.version = 1;
    mtx.vin.emplace_back(prevout);
    mtx.vout.emplace_back(kOutAmount, out_script);
    const uint256 sighash = SignatureHash(prev_script, mtx, 0, SIGHASH_ALL, /*amount=*/0, SigVersion::BASE);

    std::vector<unsigned char> sig_raw;
    BOOST_REQUIRE_MESSAGE(key.Sign(sighash, sig_raw, /*grind=*/false, /*test_case=*/0, /*legacy_mode=*/true),
                          "CKey::Sign failed");
    BOOST_REQUIRE_MESSAGE(pubkey.Verify(sighash, sig_raw, /*legacy_mode=*/true),
                          "pubkey.Verify failed for freshly-created signature");

    std::vector<unsigned char> sig(sig_raw);
    sig.push_back(SIGHASH_ALL);
    mtx.vin[0].scriptSig = CScript() << sig << ToByteVector(pubkey);

    const CTransaction ctx{mtx};
    const PrecomputedTransactionData txdata(ctx);

    ScriptError serror{SCRIPT_ERR_OK};
    const bool allow_legacy = true;
    const bool ok = VerifyScript(ctx.vin[0].scriptSig, prev_script, &ctx.vin[0].scriptWitness,
                                 STANDARD_SCRIPT_VERIFY_FLAGS,
                                 TransactionSignatureChecker(&ctx, 0, /*amountIn=*/0, txdata, MissingDataBehavior::FAIL, allow_legacy),
                                 &serror);
    BOOST_CHECK_MESSAGE(ok, strprintf("VerifyScript failed: %s", ScriptErrorString(serror)));
}

BOOST_AUTO_TEST_CASE(key_io_txcreatesignv1_p2pkh_toolpath_verifies)
{
    // Reproduce the tidecoin-tx signing path (FillableSigningProvider + ProduceSignature).
    SelectParams(ChainType::MAIN);

    static const std::string kWif =
        "6ddD664vfvjyAquu3uNwVWehzSCoywRyjqo1EA9xdA2iQH8bBNYi7VNEPkqx7rm5b2pqUsDtu9YdwQ4rkHs2Xq5XzpLywUsYS7LeiZyBXmmmZ47q1zxB6b2N14PKvXfywgajjpxv7WFRAqtWDXi6uy5NVwsLn2KdJQybjQpMzX9772M1gCoc3EgBvwfin8c7aeeBdSWShh9gh5pbGTrcU2LeQPoWP4yTRhZ2sCxNuaJWaMPbjyhEf5QFBpXmLCtQQiGjSghttdLayrhBr3hw3ydGk4rwTTgv8MX68rZvnEEV3xibEG3ud8Rq7jGfumk4FaAEUdfiRdHZEZdBx4wDYaQurihxcm6EMCApZ9v1B68NNh4whtQLuHfsqod5ye8K9TPHWS19MtFT96dtdMuSB5CwvhL8Fa6TTjwPAGBYpU5xynym9bdMrZRMsUhTzAyoGmFD1sp94jUE46iwdfp7FFrboyPLV5zLiDfToKmM1J2343quyuzrTewmA6wdqUZbKAmhtL28pbDAoy6jMwk2TM1cggcFmSR3uSXcgDVnV7J9mTBmpvXDaN8xxG18JcSWSbewFVnHLCddvhPn2ZutGPpMRtDkMc3vWt5s9iD3gTUyWC9kjZsjc65Gd6t3JChSKDpUC5BGA5pdHBwo2P5j87DkZqcrUjpeMX25zgPMdt9ZWeRs6SUqJtTGMj4Hk1syNbovpm4Eqha66n8vTvVnwHrxvn85ds4ZcFpxv1FukG7TQ6iStJLBcmwcUSFtyvBFmbK9qu8ToXNGoPnqVCR8V6XveLPCfDELjHoCMCLnp4eQa3AwJpg9Pg9qVQjvcoHqD44JuZ86CAjLcyAmm9QnFcs3JX7JyLKCnBzj3DfjWr2SNgrhjiGnMBrykjEVX6vis6vDL9cJ56jTuxWDovhwzBr5VbkoBArh6MS6z1SPv6Xvv8Sj7ej3nRHZ31Gh5estzKzdUKSU2vQxmtd4Q6KqjjBSf6xLU1K1S9mAtqn3CzKMMDKeLFtTu1oFwHTGDqaCDmAKXWJX1o2xzmTdWCd3UHB9wobBjtjWUcNxvw4ig7BHW89JgsbfzRneyktwdk1cYWU52AHTdFUSnchYwQBPEqyJ5bD7zWo5AbVNMPrebEnt2Sb29CS2XYBwsD88hU6ka2BHmNmTGedEHJmhHzkrJkyWqFAkSZBsH5yq6x6ttYrDH8zXX7i98FzV2ZKnKuyy6NcgwpC8rYaMYPSie14DzoPfGUJc6BytBV69mZDsoJ2UUoVH94uiBkZUPTFfDcyCoDxBACCPxdCnJokerkAvDmFzujELyf2rK9nEoQeVdh9QJdYTTLAgJdzMyREHHYWyseWWti9n2gadocnRwiUMSqEt683KHiMW4Bn8AWBDSFQfXZYvVBcuEL4jvBSXMVJt4Z6cD11gqmCM9BgEGy2CoNLELVmRDRq3RMN22G2jX5U353eqikvgumub2sGRuErt3vbDuEELbmJAzLrVrXjfmbeU5ev5ZhMpBP7CiyRy7sk2DViDYDrZ9W5J8hPDRDVy7SV85bF1MHz1GjXjMjCMSSBYwvPTT9gd7Rmmc1MfVo26t6iS4YVdVeoCBGdvLdCUWd6Z8UZPmkpPASnVN3yj9m119DRyXsZUsqyeNF2vEDTVSNfjfofLGqfFmKtHDEkECW94huFapxokwmSvgi15sYiEKXBXknHnctaEiahSh7ha9qJ6UqhEnd7aJxzG1JbUerZbZMF4dxLEumd66ixzbgAWSBHoC1";
    static constexpr std::string_view kPrevTxid =
        "4d49a71ec9da436f71ec4ee231d04f292a29cd316f598bb7068feccabdc59485";
    static constexpr uint32_t kPrevVout{0};
    static constexpr std::string_view kPrevScriptPubKeyHex =
        "76a9145a2f1784c55a322ffe4cc3ca9fea8dfb44cdea1188ac";
    static constexpr std::string_view kOutAddr =
        "ERNkirDf3jsER2ykJevf8USM2rj8Xi3GCF";
    static constexpr CAmount kOutAmount{COIN / 1000}; // 0.001

    const CKey key = DecodeSecret(kWif);
    BOOST_REQUIRE_MESSAGE(key.IsValid(), "DecodeSecret(WIF) failed");

    FillableSigningProvider keystore;
    keystore.AddKey(key);

    const std::vector<unsigned char> prev_script_bytes = ParseHex(kPrevScriptPubKeyHex);
    const CScript prev_script(prev_script_bytes.begin(), prev_script_bytes.end());
    const Txid txid = Txid::FromHex(kPrevTxid).value();
    const COutPoint prevout{txid, kPrevVout};

    const CTxDestination out_dest = DecodeDestination(std::string(kOutAddr));
    BOOST_REQUIRE_MESSAGE(IsValidDestination(out_dest), "output address failed DecodeDestination");
    const CScript out_script = GetScriptForDestination(out_dest);

    CMutableTransaction mtx;
    mtx.version = 1;
    mtx.vin.emplace_back(prevout);
    mtx.vout.emplace_back(kOutAmount, out_script);

    // Mimic tidecoin-tx view: missing amount defaults to MAX_MONEY.
    Coin coin;
    coin.out.scriptPubKey = prev_script;
    coin.out.nValue = MAX_MONEY;
    coin.nHeight = 1;

    SignatureData sigdata = DataFromTransaction(mtx, 0, coin.out);
    const bool signed_ok = ProduceSignature(keystore, MutableTransactionSignatureCreator(mtx, 0, coin.out.nValue, SIGHASH_ALL), prev_script, sigdata);
    BOOST_REQUIRE_MESSAGE(signed_ok, "ProduceSignature failed");
    BOOST_REQUIRE_MESSAGE(sigdata.complete, "sigdata incomplete");
    UpdateInput(mtx.vin[0], sigdata);

    const CTransaction ctx{mtx};
    const PrecomputedTransactionData txdata(ctx);
    ScriptError serror{SCRIPT_ERR_OK};
    const bool ok = VerifyScript(ctx.vin[0].scriptSig, prev_script, &ctx.vin[0].scriptWitness,
                                 STANDARD_SCRIPT_VERIFY_FLAGS,
                                 TransactionSignatureChecker(&ctx, 0, coin.out.nValue, txdata, MissingDataBehavior::FAIL, /*allow_legacy=*/true),
                                 &serror);
    BOOST_CHECK_MESSAGE(ok, strprintf("VerifyScript failed: %s", ScriptErrorString(serror)));
}


// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(key_io_invalid)
{
    UniValue tests = read_json(json_tests::key_io_invalid); // Negative testcases
    CKey privkey;
    CTxDestination destination;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        for (const auto& chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
            SelectParams(chain);
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid pubkey in mainnet:" + strTest);
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid privkey in mainnet:" + strTest);
        }
    }
}

BOOST_AUTO_TEST_CASE(key_io_bech32pq_v1)
{
    SelectParams(ChainType::MAIN);
    const auto& params = Params();

    CScript witness_script;
    witness_script << OP_TRUE;
    const WitnessV1ScriptHash512 wit_hash{witness_script};

    const std::string addr = EncodeDestination(wit_hash);
    BOOST_CHECK(addr.rfind(params.Bech32PQHRP(), 0) == 0);

    std::string error;
    auto decoded = DecodeDestination(addr, error);
    BOOST_TEST_MESSAGE("bech32pq addr=" << addr << " error=" << error);
    BOOST_CHECK(error.empty());
    BOOST_REQUIRE(std::holds_alternative<WitnessV1ScriptHash512>(decoded));
    BOOST_CHECK(std::get<WitnessV1ScriptHash512>(decoded) == wit_hash);

    // PQ HRP must not accept v0 witness programs.
    std::vector<unsigned char> program20(20, 0x42);
    std::vector<unsigned char> data_v0{0};
    ConvertBits<8, 5, true>([&](unsigned char c) { data_v0.push_back(c); }, program20.begin(), program20.end());
    const std::string pq_v0 = bech32::Encode(bech32::Encoding::BECH32M, params.Bech32PQHRP(), data_v0);
    decoded = DecodeDestination(pq_v0, error);
    BOOST_CHECK(!IsValidDestination(decoded));

    // Legacy HRP must not accept v1 witness programs.
    std::vector<unsigned char> program64(64, 0x11);
    std::vector<unsigned char> data_v1{1};
    ConvertBits<8, 5, true>([&](unsigned char c) { data_v1.push_back(c); }, program64.begin(), program64.end());
    const std::string legacy_v1 = bech32::Encode(bech32::Encoding::BECH32M, params.Bech32HRP(), data_v1);
    decoded = DecodeDestination(legacy_v1, error);
    BOOST_CHECK(!IsValidDestination(decoded));
}

BOOST_AUTO_TEST_CASE(key_io_bech32_checksum_errors)
{
    SelectParams(ChainType::MAIN);
    const auto& params = Params();

    auto corrupt_last = [](std::string s) {
        const char replacement = (s.back() == 'q') ? 'p' : 'q';
        s.back() = replacement;
        return s;
    };

    // Legacy v0 bech32 checksum error
    WitnessV0KeyHash keyhash;
    std::fill(keyhash.begin(), keyhash.end(), 0x11);
    const std::string legacy_addr = EncodeDestination(keyhash);
    std::string error;
    auto decoded = DecodeDestination(corrupt_last(legacy_addr), error);
    BOOST_CHECK(!IsValidDestination(decoded));
    BOOST_CHECK_EQUAL(error, "Invalid Bech32 checksum");

    // PQ v1 bech32m checksum error
    std::vector<unsigned char> program64(64, 0x22);
    std::vector<unsigned char> data_v1{1};
    ConvertBits<8, 5, true>([&](unsigned char c) { data_v1.push_back(c); }, program64.begin(), program64.end());
    const std::string pq_addr = bech32::Encode(bech32::Encoding::BECH32M, params.Bech32PQHRP(), data_v1);
    decoded = DecodeDestination(corrupt_last(pq_addr), error);
    BOOST_CHECK(!IsValidDestination(decoded));
    BOOST_CHECK_EQUAL(error, "Invalid Bech32m checksum");
}

BOOST_AUTO_TEST_SUITE_END()
