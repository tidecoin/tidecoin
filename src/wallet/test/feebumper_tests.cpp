// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <pq/pq_scheme.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <wallet/feebumper.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
namespace feebumper {
BOOST_FIXTURE_TEST_SUITE(feebumper_tests, BasicTestingSetup)

namespace {
constexpr unsigned int FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_WITNESS_V1_512};

enum class Form { P2PKH, P2SH_P2WPKH, P2WPKH, P2WSH_MULTI, P2WSH512 };

CPubKey MakePubKey(const pq::SchemeInfo& scheme, uint8_t fill)
{
    std::vector<uint8_t> bytes(scheme.pubkey_bytes + 1, fill);
    bytes[0] = scheme.prefix;
    return CPubKey{bytes};
}

//! Signatures (with sighash byte) of the given sizes, one per key.
std::vector<std::vector<uint8_t>> Sigs(const std::vector<size_t>& sizes)
{
    std::vector<std::vector<uint8_t>> sigs;
    for (size_t size : sizes) sigs.emplace_back(size, 0x01);
    return sigs;
}

std::pair<CTxIn, CScript> MakeInput(Form form, const std::vector<CPubKey>& keys, const std::vector<std::vector<uint8_t>>& sigs)
{
    const CPubKey& key{keys.at(0)};
    const std::vector<uint8_t> key_bytes(key.begin(), key.end());
    CTxIn input{Txid{}, 0};
    switch (form) {
    case Form::P2PKH:
        input.scriptSig = CScript{} << sigs.at(0) << key_bytes;
        return {input, GetScriptForDestination(PKHash{key})};
    case Form::P2SH_P2WPKH: {
        const CScript redeem{GetScriptForDestination(WitnessV0KeyHash{key})};
        input.scriptSig = CScript{} << std::vector<uint8_t>(redeem.begin(), redeem.end());
        input.scriptWitness.stack = {sigs.at(0), key_bytes};
        return {input, GetScriptForDestination(ScriptHash{redeem})};
    }
    case Form::P2WPKH:
        input.scriptWitness.stack = {sigs.at(0), key_bytes};
        return {input, GetScriptForDestination(WitnessV0KeyHash{key})};
    case Form::P2WSH_MULTI: {
        const CScript script{GetScriptForMultisig(keys.size(), keys)};
        input.scriptWitness.stack = {{}};
        for (const auto& sig : sigs) input.scriptWitness.stack.push_back(sig);
        input.scriptWitness.stack.emplace_back(script.begin(), script.end());
        return {input, GetScriptForDestination(WitnessV0ScriptHash{script})};
    }
    case Form::P2WSH512: {
        const CScript script{CScript{} << key_bytes << OP_CHECKSIG};
        input.scriptWitness.stack = {sigs.at(0), std::vector<uint8_t>(script.begin(), script.end())};
        return {input, GetScriptForDestination(WitnessV1ScriptHash512{script})};
    }
    }
    assert(false);
}

int64_t MaxWeight(const CTxIn& input, const CScript& prevout_script)
{
    SignatureWeights weights;
    SignatureWeightChecker size_checker(weights, DUMMY_CHECKER);
    BOOST_REQUIRE(VerifyScript(input.scriptSig, prevout_script, &input.scriptWitness, FLAGS, size_checker));
    return GetTransactionInputWeight(input) + weights.GetWeightDiffToMax();
}
} // namespace

BOOST_AUTO_TEST_CASE(external_max_weight_test)
{
    for (const auto* scheme : pq::kKnownSchemes) {
        const size_t max_sig{scheme->sig_bytes_max + 1};
        // Falcon signatures vary in size; ML-DSA signatures always have the maximum size.
        const size_t sig{scheme->sig_bytes_max == scheme->sig_bytes_sign_max ? max_sig : max_sig - 50};
        for (Form form : {Form::P2PKH, Form::P2SH_P2WPKH, Form::P2WPKH, Form::P2WSH512}) {
            const std::vector keys{MakePubKey(*scheme, 0x11)};
            const auto [input, prevout_script]{MakeInput(form, keys, Sigs({sig}))};
            const auto [max_input, max_prevout_script]{MakeInput(form, keys, Sigs({max_sig}))};
            BOOST_CHECK_EQUAL(MaxWeight(input, prevout_script), GetTransactionInputWeight(max_input));
            BOOST_CHECK_EQUAL(MaxWeight(max_input, max_prevout_script), GetTransactionInputWeight(max_input));
        }
    }

    // Each signature of a multisig is padded to its own scheme's maximum.
    const std::vector keys{MakePubKey(pq::kFalcon512Info, 0x11), MakePubKey(pq::kFalcon1024Info, 0x22), MakePubKey(pq::kMLDSA44Info, 0x33)};
    const auto [input, prevout_script]{MakeInput(Form::P2WSH_MULTI, keys, Sigs({600, 1200, pq::kMLDSA44Info.sig_bytes_max + 1}))};
    const auto [max_input, max_prevout_script]{MakeInput(Form::P2WSH_MULTI, keys, Sigs({pq::kFalcon512Info.sig_bytes_max + 1, pq::kFalcon1024Info.sig_bytes_max + 1, pq::kMLDSA44Info.sig_bytes_max + 1}))};
    BOOST_CHECK_EQUAL(MaxWeight(input, prevout_script), GetTransactionInputWeight(max_input));

    // A signature above the scheme maximum is counted at its own size.
    const std::vector falcon_key{MakePubKey(pq::kFalcon512Info, 0x11)};
    const auto [oversized, oversized_prevout_script]{MakeInput(Form::P2WPKH, falcon_key, Sigs({pq::kFalcon512Info.sig_bytes_max + 10}))};
    BOOST_CHECK_EQUAL(MaxWeight(oversized, oversized_prevout_script), GetTransactionInputWeight(oversized));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace feebumper
} // namespace wallet
