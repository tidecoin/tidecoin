// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <addresstype.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace util::hex_literals;

BOOST_FIXTURE_TEST_SUITE(script_standard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dest_default_is_no_dest)
{
    CTxDestination dest;
    BOOST_CHECK(!IsValidDestination(dest));
}

BOOST_AUTO_TEST_CASE(script_standard_Solver_success)
{
    CKey keys[3];
    CPubKey pubkeys[3];
    for (int i = 0; i < 3; i++) {
        keys[i].MakeNewKey(pq::SchemeId::FALCON_512);
        pubkeys[i] = keys[i].GetPubKey();
    }

    CScript s;
    std::vector<std::vector<unsigned char> > solutions;

    // TxoutType::PUBKEY
    s.clear();
    s << ToByteVector(pubkeys[0]) << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::PUBKEY);
    BOOST_CHECK_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == ToByteVector(pubkeys[0]));

    // TxoutType::PUBKEYHASH
    s.clear();
    s << OP_DUP << OP_HASH160 << ToByteVector(pubkeys[0].GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::PUBKEYHASH);
    BOOST_CHECK_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == ToByteVector(pubkeys[0].GetID()));

    // TxoutType::SCRIPTHASH
    CScript redeemScript(s); // initialize with leftover P2PKH script
    s.clear();
    s << OP_HASH160 << ToByteVector(CScriptID(redeemScript)) << OP_EQUAL;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::SCRIPTHASH);
    BOOST_CHECK_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == ToByteVector(CScriptID(redeemScript)));

    // TxoutType::MULTISIG
    s.clear();
    s << OP_1 <<
        ToByteVector(pubkeys[0]) <<
        ToByteVector(pubkeys[1]) <<
        OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::MULTISIG);
    BOOST_CHECK_EQUAL(solutions.size(), 4U);
    BOOST_CHECK(solutions[0] == std::vector<unsigned char>({1}));
    BOOST_CHECK(solutions[1] == ToByteVector(pubkeys[0]));
    BOOST_CHECK(solutions[2] == ToByteVector(pubkeys[1]));
    BOOST_CHECK(solutions[3] == std::vector<unsigned char>({2}));

    s.clear();
    s << OP_2 <<
        ToByteVector(pubkeys[0]) <<
        ToByteVector(pubkeys[1]) <<
        ToByteVector(pubkeys[2]) <<
        OP_3 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::MULTISIG);
    BOOST_CHECK_EQUAL(solutions.size(), 5U);
    BOOST_CHECK(solutions[0] == std::vector<unsigned char>({2}));
    BOOST_CHECK(solutions[1] == ToByteVector(pubkeys[0]));
    BOOST_CHECK(solutions[2] == ToByteVector(pubkeys[1]));
    BOOST_CHECK(solutions[3] == ToByteVector(pubkeys[2]));
    BOOST_CHECK(solutions[4] == std::vector<unsigned char>({3}));

    // TxoutType::NULL_DATA
    s.clear();
    s << OP_RETURN <<
        std::vector<unsigned char>({0}) <<
        std::vector<unsigned char>({75}) <<
        std::vector<unsigned char>({255});
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NULL_DATA);
    BOOST_CHECK_EQUAL(solutions.size(), 0U);

    // TxoutType::WITNESS_V0_KEYHASH
    s.clear();
    s << OP_0 << ToByteVector(pubkeys[0].GetID());
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::WITNESS_V0_KEYHASH);
    BOOST_CHECK_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == ToByteVector(pubkeys[0].GetID()));

    // TxoutType::WITNESS_V0_SCRIPTHASH
    uint256 scriptHash;
    CSHA256().Write(redeemScript.data(), redeemScript.size())
        .Finalize(scriptHash.begin());

    s.clear();
    s << OP_0 << ToByteVector(scriptHash);
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::WITNESS_V0_SCRIPTHASH);
    BOOST_CHECK_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == ToByteVector(scriptHash));

    // TxoutType::WITNESS_V1_SCRIPTHASH_512
    CScript witnessScript512;
    witnessScript512 << ToByteVector(pubkeys[0]) << OP_CHECKSIG;
    WitnessV1ScriptHash512 scriptHash512(witnessScript512);
    s.clear();
    s << OP_1 << ToByteVector(scriptHash512);
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::WITNESS_V1_SCRIPTHASH_512);
    BOOST_CHECK_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == ToByteVector(scriptHash512));

    // TxoutType::NONSTANDARD
    s.clear();
    s << OP_9 << OP_ADD << OP_11 << OP_EQUAL;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);
}

BOOST_AUTO_TEST_CASE(script_standard_Solver_failure)
{
    CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CPubKey pubkey = key.GetPubKey();

    CScript s;
    std::vector<std::vector<unsigned char> > solutions;

    // TxoutType::PUBKEY with incorrectly sized pubkey
    s.clear();
    s << std::vector<unsigned char>(30, 0x01) << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::PUBKEYHASH with incorrectly sized key hash
    s.clear();
    s << OP_DUP << OP_HASH160 << ToByteVector(pubkey) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::SCRIPTHASH with incorrectly sized script hash
    s.clear();
    s << OP_HASH160 << std::vector<unsigned char>(21, 0x01) << OP_EQUAL;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::MULTISIG 0/2
    s.clear();
    s << OP_0 << ToByteVector(pubkey) << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::MULTISIG 2/1
    s.clear();
    s << OP_2 << ToByteVector(pubkey) << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::MULTISIG n = 2 with 1 pubkey
    s.clear();
    s << OP_1 << ToByteVector(pubkey) << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::MULTISIG n = 1 with 0 pubkeys
    s.clear();
    s << OP_1 << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::NULL_DATA with other opcodes
    s.clear();
    s << OP_RETURN << std::vector<unsigned char>({75}) << OP_ADD;
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::WITNESS_V0_{KEY,SCRIPT}HASH with incorrect program size (-> consensus-invalid, i.e. non-standard)
    s.clear();
    s << OP_0 << std::vector<unsigned char>(19, 0x01);
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

    // TxoutType::WITNESS_V1_SCRIPTHASH_512 with incorrect program size
    s.clear();
    s << OP_1 << std::vector<unsigned char>(63, 0x01);
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::NONSTANDARD);

}

BOOST_AUTO_TEST_CASE(script_standard_ExtractDestination)
{
    CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CPubKey pubkey = key.GetPubKey();

    CScript s;
    CTxDestination address;

    // TxoutType::PUBKEY
    s.clear();
    s << ToByteVector(pubkey) << OP_CHECKSIG;
    BOOST_CHECK(!ExtractDestination(s, address));
    BOOST_CHECK(std::get<PubKeyDestination>(address) == PubKeyDestination(pubkey));

    // TxoutType::PUBKEYHASH
    s.clear();
    s << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK(ExtractDestination(s, address));
    BOOST_CHECK(std::get<PKHash>(address) == PKHash(pubkey));

    // TxoutType::SCRIPTHASH
    CScript redeemScript(s); // initialize with leftover P2PKH script
    s.clear();
    s << OP_HASH160 << ToByteVector(CScriptID(redeemScript)) << OP_EQUAL;
    BOOST_CHECK(ExtractDestination(s, address));
    BOOST_CHECK(std::get<ScriptHash>(address) == ScriptHash(redeemScript));

    // TxoutType::MULTISIG
    s.clear();
    s << OP_1 << ToByteVector(pubkey) << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK(!ExtractDestination(s, address));

    // TxoutType::NULL_DATA
    s.clear();
    s << OP_RETURN << std::vector<unsigned char>({75});
    BOOST_CHECK(!ExtractDestination(s, address));

    // TxoutType::WITNESS_V0_KEYHASH
    s.clear();
    s << OP_0 << ToByteVector(pubkey.GetID());
    BOOST_CHECK(ExtractDestination(s, address));
    WitnessV0KeyHash keyhash;
    CHash160().Write(pubkey).Finalize(keyhash);
    BOOST_CHECK(std::get<WitnessV0KeyHash>(address) == keyhash);

    // TxoutType::WITNESS_V0_SCRIPTHASH
    s.clear();
    WitnessV0ScriptHash scripthash;
    CSHA256().Write(redeemScript.data(), redeemScript.size()).Finalize(scripthash.begin());
    s << OP_0 << ToByteVector(scripthash);
    BOOST_CHECK(ExtractDestination(s, address));
    BOOST_CHECK(std::get<WitnessV0ScriptHash>(address) == scripthash);

    // TxoutType::WITNESS_V1_SCRIPTHASH_512
    CScript witnessScript512;
    witnessScript512 << ToByteVector(pubkey) << OP_CHECKSIG;
    WitnessV1ScriptHash512 scripthash512(witnessScript512);
    s.clear();
    s << OP_1 << ToByteVector(scripthash512);
    BOOST_CHECK(ExtractDestination(s, address));
    BOOST_CHECK(std::get<WitnessV1ScriptHash512>(address) == scripthash512);

}

BOOST_AUTO_TEST_CASE(script_standard_GetScriptFor_)
{
    CKey keys[3];
    CPubKey pubkeys[3];
    for (int i = 0; i < 3; i++) {
        keys[i].MakeNewKey(pq::SchemeId::FALCON_512);
        pubkeys[i] = keys[i].GetPubKey();
    }

    CScript expected, result;

    // PKHash
    expected.clear();
    expected << OP_DUP << OP_HASH160 << ToByteVector(pubkeys[0].GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    result = GetScriptForDestination(PKHash(pubkeys[0]));
    BOOST_CHECK(result == expected);

    // CScriptID
    CScript redeemScript(result);
    expected.clear();
    expected << OP_HASH160 << ToByteVector(CScriptID(redeemScript)) << OP_EQUAL;
    result = GetScriptForDestination(ScriptHash(redeemScript));
    BOOST_CHECK(result == expected);

    // CNoDestination
    expected.clear();
    result = GetScriptForDestination(CNoDestination());
    BOOST_CHECK(result == expected);

    // GetScriptForRawPubKey
    expected.clear();
    expected << ToByteVector(pubkeys[0]) << OP_CHECKSIG;
    result = GetScriptForRawPubKey(pubkeys[0]);
    BOOST_CHECK(result == expected);

    // GetScriptForMultisig
    expected.clear();
    expected << OP_2 <<
        ToByteVector(pubkeys[0]) <<
        ToByteVector(pubkeys[1]) <<
        ToByteVector(pubkeys[2]) <<
        OP_3 << OP_CHECKMULTISIG;
    result = GetScriptForMultisig(2, std::vector<CPubKey>(pubkeys, pubkeys + 3));
    BOOST_CHECK(result == expected);

    // WitnessV0KeyHash
    expected.clear();
    expected << OP_0 << ToByteVector(pubkeys[0].GetID());
    result = GetScriptForDestination(WitnessV0KeyHash(Hash160(ToByteVector(pubkeys[0]))));
    BOOST_CHECK(result == expected);
    result = GetScriptForDestination(WitnessV0KeyHash(pubkeys[0].GetID()));
    BOOST_CHECK(result == expected);

    // WitnessV0ScriptHash (multisig)
    CScript witnessScript;
    witnessScript << OP_1 << ToByteVector(pubkeys[0]) << OP_1 << OP_CHECKMULTISIG;

    uint256 scriptHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size())
        .Finalize(scriptHash.begin());

    expected.clear();
    expected << OP_0 << ToByteVector(scriptHash);
    result = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
    BOOST_CHECK(result == expected);

    // WitnessV1ScriptHash512 (single-sig script)
    CScript witnessScript512;
    witnessScript512 << ToByteVector(pubkeys[0]) << OP_CHECKSIG;
    WitnessV1ScriptHash512 hash512(witnessScript512);
    expected.clear();
    expected << OP_1 << ToByteVector(hash512);
    result = GetScriptForDestination(hash512);
    BOOST_CHECK(result == expected);

}

BOOST_AUTO_TEST_CASE(script_standard_IsStandard_v1_scripthash_512)
{
    CScript witnessScript;
    witnessScript << OP_TRUE;
    const WitnessV1ScriptHash512 hash512(witnessScript);
    const CScript spk = GetScriptForDestination(hash512);

    TxoutType which_type;
    BOOST_CHECK(IsStandard(spk, which_type));
    BOOST_CHECK_EQUAL(which_type, TxoutType::WITNESS_V1_SCRIPTHASH_512);

    CScript invalid;
    invalid << OP_1 << std::vector<unsigned char>(63, 0x01);
    BOOST_CHECK(!IsStandard(invalid, which_type));
}

BOOST_AUTO_TEST_CASE(single_key_witness_v1_destination)
{
    for (const auto scheme : {pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_1024,
                              pq::SchemeId::MLDSA_44, pq::SchemeId::MLDSA_65,
                              pq::SchemeId::MLDSA_87}) {
        CKey key, other;
        key.MakeNewKey(scheme);
        other.MakeNewKey(scheme);
        const CPubKey pubkey{key.GetPubKey()};
        const CPubKey other_pubkey{other.GetPubKey()};
        const CScript script{GetScriptForRawPubKey(pubkey)};
        const WitnessV1ScriptHash512 dest{script};
        const CScriptID script_id{RIPEMD160(dest)};
        FlatSigningProvider provider;
        // A private key alone does not establish which script the address uses.
        provider.keys.emplace(pubkey.GetID(), key);
        BOOST_CHECK(GetKeyForDestination(provider, dest).IsNull());
        provider.scripts.emplace(script_id, script);
        BOOST_CHECK(GetKeyForDestination(provider, dest) == pubkey.GetID());
        // Resolution depends on the committed script, not provider key count or order.
        provider.keys.emplace(other_pubkey.GetID(), other);
        BOOST_CHECK(GetKeyForDestination(provider, dest) == pubkey.GetID());
        provider.keys.clear();
        BOOST_CHECK(GetKeyForDestination(provider, dest) == pubkey.GetID());

        provider.scripts[script_id] = GetScriptForRawPubKey(other_pubkey);
        BOOST_CHECK(GetKeyForDestination(provider, dest).IsNull());
        provider.scripts[script_id] = script;

        CScript arbitrary{script};
        arbitrary << OP_DROP << OP_TRUE;
        for (const auto& unsupported : {
                 GetScriptForMultisig(1, {pubkey}),
                 GetScriptForMultisig(1, {pubkey, other_pubkey}),
                 GetScriptForDestination(PKHash{pubkey}), arbitrary}) {
            const WitnessV1ScriptHash512 unsupported_dest{unsupported};
            provider.scripts[CScriptID{RIPEMD160(unsupported_dest)}] = unsupported;
            provider.keys.emplace(pubkey.GetID(), key);
            BOOST_CHECK(GetKeyForDestination(provider, unsupported_dest).IsNull());
        }

        // Wrapping does not turn native-only v1 into a supported export address.
        const CScript wrapped{GetScriptForDestination(dest)};
        provider.scripts[CScriptID{wrapped}] = wrapped;
        BOOST_CHECK(GetKeyForDestination(provider, ScriptHash{wrapped}).IsNull());
        BOOST_CHECK(GetKeyForDestination(provider, PKHash{pubkey}) == pubkey.GetID());
        BOOST_CHECK(GetKeyForDestination(provider, WitnessV0KeyHash{pubkey}) == pubkey.GetID());
        const CScript v0{GetScriptForDestination(WitnessV0KeyHash{pubkey})};
        provider.scripts[CScriptID{v0}] = v0;
        BOOST_CHECK(GetKeyForDestination(provider, ScriptHash{v0}) == pubkey.GetID());
    }
}

BOOST_AUTO_TEST_SUITE_END()
