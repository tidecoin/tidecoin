// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/script_tests_pq.json.h>
#include <test/data/tx_invalid_pq.json.h>
#include <test/data/tx_valid_pq.json.h>
#include <test/util/setup_common.h>

#include <checkqueue.h>
#include <clientversion.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction_identifier.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/transaction_utils.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>

#include <functional>
#include <fstream>
#include <map>
#include <string>
#include <cstdlib>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace util::hex_literals;
using util::SplitString;

typedef std::vector<unsigned char> valtype;

static CFeeRate g_dust{DUST_RELAY_TX_FEE};
static bool g_bare_multi{DEFAULT_PERMIT_BAREMULTISIG};

static std::map<std::string, unsigned int> mapFlagNames = {
    {std::string("P2SH"), (unsigned int)SCRIPT_VERIFY_P2SH},
    {std::string("SIGPUSHONLY"), (unsigned int)SCRIPT_VERIFY_SIGPUSHONLY},
    {std::string("MINIMALDATA"), (unsigned int)SCRIPT_VERIFY_MINIMALDATA},
    {std::string("NULLDUMMY"), (unsigned int)SCRIPT_VERIFY_NULLDUMMY},
    {std::string("DISCOURAGE_UPGRADABLE_NOPS"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
    {std::string("CLEANSTACK"), (unsigned int)SCRIPT_VERIFY_CLEANSTACK},
    {std::string("MINIMALIF"), (unsigned int)SCRIPT_VERIFY_MINIMALIF},
    {std::string("NULLFAIL"), (unsigned int)SCRIPT_VERIFY_NULLFAIL},
    {std::string("CHECKLOCKTIMEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
    {std::string("CHECKSEQUENCEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
    {std::string("WITNESS"), (unsigned int)SCRIPT_VERIFY_WITNESS},
    {std::string("SHA512"), (unsigned int)SCRIPT_VERIFY_SHA512},
    {std::string("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM},
    {std::string("WITNESS_V1_512"), (unsigned int)SCRIPT_VERIFY_WITNESS_V1_512},
    {std::string("CONST_SCRIPTCODE"), (unsigned int)SCRIPT_VERIFY_CONST_SCRIPTCODE},
    {std::string("PQ_STRICT"), (unsigned int)SCRIPT_VERIFY_PQ_STRICT},
};

unsigned int ParseScriptFlags(std::string strFlags)
{
    unsigned int flags = SCRIPT_VERIFY_NONE;
    if (strFlags.empty() || strFlags == "NONE") return flags;

    std::vector<std::string> words = SplitString(strFlags, ',');
    for (const std::string& word : words)
    {
        if (!mapFlagNames.count(word))
            BOOST_ERROR("Bad test: unknown verification flag '" << word << "'");
        flags |= mapFlagNames[word];
    }
    return flags;
}

// Check that all flags in STANDARD_SCRIPT_VERIFY_FLAGS are present in mapFlagNames.
bool CheckMapFlagNames()
{
    unsigned int standard_flags_missing{STANDARD_SCRIPT_VERIFY_FLAGS};
    for (const auto& pair : mapFlagNames) {
        standard_flags_missing &= ~(pair.second);
    }
    return standard_flags_missing == 0;
}

std::string FormatScriptFlags(unsigned int flags)
{
    if (flags == SCRIPT_VERIFY_NONE) {
        return "";
    }
    std::string ret;
    std::map<std::string, unsigned int>::const_iterator it = mapFlagNames.begin();
    while (it != mapFlagNames.end()) {
        if (flags & it->second) {
            ret += it->first + ",";
        }
        it++;
    }
    return ret.substr(0, ret.size() - 1);
}

/*
* Check that the input scripts of a transaction are valid/invalid as expected.
*/
bool CheckTxScripts(const CTransaction& tx, const std::map<COutPoint, CScript>& map_prevout_scriptPubKeys,
    const std::map<COutPoint, int64_t>& map_prevout_values, unsigned int flags,
    const PrecomputedTransactionData& txdata, const std::string& strTest, bool expect_valid)
{
    bool tx_valid = true;
    ScriptError err = expect_valid ? SCRIPT_ERR_UNKNOWN_ERROR : SCRIPT_ERR_OK;
    for (unsigned int i = 0; i < tx.vin.size() && tx_valid; ++i) {
        const CTxIn input = tx.vin[i];
        const CAmount amount = map_prevout_values.count(input.prevout) ? map_prevout_values.at(input.prevout) : 0;
        try {
            const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
            tx_valid = VerifyScript(input.scriptSig, map_prevout_scriptPubKeys.at(input.prevout),
                &input.scriptWitness, flags, TransactionSignatureChecker(&tx, i, amount, txdata, MissingDataBehavior::ASSERT_FAIL, allow_legacy), &err);
        } catch (...) {
            BOOST_ERROR("Bad test: " << strTest);
            return true; // The test format is bad and an error is thrown. Return true to silence further error.
        }
        if (expect_valid) {
            BOOST_CHECK_MESSAGE(tx_valid, strTest);
            BOOST_CHECK_MESSAGE((err == SCRIPT_ERR_OK), ScriptErrorString(err));
            err = SCRIPT_ERR_UNKNOWN_ERROR;
        }
    }
    if (!expect_valid) {
        BOOST_CHECK_MESSAGE(!tx_valid, strTest);
        BOOST_CHECK_MESSAGE((err != SCRIPT_ERR_OK), ScriptErrorString(err));
    }
    return (tx_valid == expect_valid);
}

/*
 * Trim or fill flags to make the combination valid:
 * WITNESS must be used with P2SH
 * CLEANSTACK must be used WITNESS and P2SH
 */

unsigned int TrimFlags(unsigned int flags)
{
    // WITNESS requires P2SH
    if (!(flags & SCRIPT_VERIFY_P2SH)) flags &= ~(unsigned int)SCRIPT_VERIFY_WITNESS;

    // CLEANSTACK requires WITNESS (and transitively CLEANSTACK requires P2SH)
    if (!(flags & SCRIPT_VERIFY_WITNESS)) flags &= ~(unsigned int)SCRIPT_VERIFY_CLEANSTACK;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

unsigned int FillFlags(unsigned int flags)
{
    // CLEANSTACK implies WITNESS
    if (flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_WITNESS;

    // WITNESS implies P2SH (and transitively CLEANSTACK implies P2SH)
    if (flags & SCRIPT_VERIFY_WITNESS) flags |= SCRIPT_VERIFY_P2SH;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

// Exclude each possible script verify flag from flags. Returns a set of these flag combinations
// that are valid and without duplicates. For example: if flags=1111 and the 4 possible flags are
// 0001, 0010, 0100, and 1000, this should return the set {0111, 1011, 1101, 1110}.
// Assumes that mapFlagNames contains all script verify flags.
std::set<unsigned int> ExcludeIndividualFlags(unsigned int flags)
{
    std::set<unsigned int> flags_combos;
    for (const auto& pair : mapFlagNames) {
        const unsigned int flags_excluding_one = TrimFlags(flags & ~(pair.second));
        if (flags != flags_excluding_one) {
            flags_combos.insert(flags_excluding_one);
        }
    }
    return flags_combos;
}

struct ParsedScriptVector
{
    CScriptWitness witness;
    CAmount amount{0};
    CScript scriptSig;
    CScript scriptPubKey;
    unsigned int flags{SCRIPT_VERIFY_NONE};
    std::string expected_error;
    std::string comment;
};

static bool ParseScriptVector(const UniValue& test, ParsedScriptVector& out, const std::string& fallback_comment)
{
    if (!test.isArray()) return false;
    unsigned int pos{0};
    if (test.size() > 0 && test[pos].isArray()) {
        const UniValue& wit = test[pos].get_array();
        if (wit.size() == 0) return false;
        unsigned int i = 0;
        for (; i + 1 < wit.size(); ++i) {
            const auto witness_value{TryParseHex<unsigned char>(wit[i].get_str())};
            if (!witness_value.has_value()) return false;
            out.witness.stack.push_back(witness_value.value());
        }
        out.amount = AmountFromValue(wit[i]);
        ++pos;
    }
    if (test.size() < pos + 4 || !test[pos].isStr() || !test[pos + 1].isStr() || !test[pos + 2].isStr() || !test[pos + 3].isStr()) {
        return false;
    }
    out.scriptSig = ParseScript(test[pos++].get_str());
    out.scriptPubKey = ParseScript(test[pos++].get_str());
    out.flags = FillFlags(ParseScriptFlags(test[pos++].get_str()));
    out.expected_error = test[pos++].get_str();
    out.comment = (test.size() > pos && test[pos].isStr()) ? test[pos].get_str() : fallback_comment;
    return true;
}

static bool ParseTxVectorInputs(const UniValue& inputs, std::map<COutPoint, CScript>& scripts, std::map<COutPoint, int64_t>& values)
{
    if (!inputs.isArray()) return false;
    for (unsigned int inp_idx = 0; inp_idx < inputs.size(); ++inp_idx) {
        const UniValue& input = inputs[inp_idx];
        if (!input.isArray()) return false;
        const UniValue& vinput = input.get_array();
        if (vinput.size() < 3 || vinput.size() > 4 || !vinput[0].isStr() || !vinput[1].isNum() || !vinput[2].isStr()) {
            return false;
        }
        const auto txid{Txid::FromHex(vinput[0].get_str())};
        if (!txid.has_value()) return false;
        COutPoint outpoint{txid.value(), uint32_t(vinput[1].getInt<int>())};
        scripts.emplace(outpoint, ParseScript(vinput[2].get_str()));
        if (vinput.size() >= 4) values.emplace(outpoint, vinput[3].getInt<int64_t>());
    }
    return true;
}

static void WriteTxFixture(const UniValue& entries, const char* output_path)
{
    std::ofstream out{output_path, std::ios::out | std::ios::trunc};
    out << entries.write(4) << '\n';
}

static bool GeneratePQTxFixtures(const char* valid_output_path, const char* invalid_output_path)
{
    UniValue script_tests = read_json(json_tests::script_tests_pq);
    UniValue valid_entries(UniValue::VARR);
    UniValue invalid_entries(UniValue::VARR);

    for (unsigned int idx = 0; idx < script_tests.size(); ++idx) {
        const UniValue& test = script_tests[idx];
        if (!test.isArray()) continue;

        ParsedScriptVector parsed;
        if (!ParseScriptVector(test, parsed, strprintf("script_tests_pq[%u]", idx))) {
            BOOST_ERROR("Bad script_tests_pq vector at index " << idx);
            return false;
        }

        const CTransaction tx_credit{BuildCreditingTransaction(parsed.scriptPubKey, parsed.amount)};
        CMutableTransaction tx_spend = BuildSpendingTransaction(parsed.scriptSig, parsed.witness, tx_credit);
        const CTransaction tx{tx_spend};
        const COutPoint prevout{tx.vin[0].prevout};

        std::map<COutPoint, CScript> prev_scripts;
        std::map<COutPoint, int64_t> prev_values;
        prev_scripts.emplace(prevout, parsed.scriptPubKey);
        prev_values.emplace(prevout, parsed.amount);

        PrecomputedTransactionData txdata(tx);
        const bool expect_valid{parsed.expected_error == "OK"};
        if (!CheckTxScripts(tx, prev_scripts, prev_values, parsed.flags, txdata, parsed.comment, expect_valid)) {
            BOOST_ERROR("Generated PQ tx fixture failed self-check: " << parsed.comment);
            return false;
        }

        UniValue input(UniValue::VARR);
        input.push_back(prevout.hash.GetHex());
        input.push_back(int64_t(prevout.n));
        input.push_back(FormatScript(parsed.scriptPubKey));
        input.push_back(parsed.amount);

        UniValue inputs(UniValue::VARR);
        inputs.push_back(std::move(input));

        UniValue entry(UniValue::VARR);
        entry.push_back(std::move(inputs));
        entry.push_back(EncodeHexTx(tx));
        entry.push_back(FormatScriptFlags(parsed.flags));
        entry.push_back(parsed.comment);

        if (expect_valid) {
            valid_entries.push_back(std::move(entry));
        } else {
            invalid_entries.push_back(std::move(entry));
        }
    }

    WriteTxFixture(valid_entries, valid_output_path);
    WriteTxFixture(invalid_entries, invalid_output_path);
    return true;
}

BOOST_FIXTURE_TEST_SUITE(transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tx_valid)
{
    BOOST_CHECK_MESSAGE(CheckMapFlagNames(), "mapFlagNames is missing a script verification flag");

    const char* const env_valid_output{std::getenv("TIDE_TX_VALID_GEN_OUTPUT")};
    const char* const env_invalid_output{std::getenv("TIDE_TX_INVALID_GEN_OUTPUT")};
    const bool regenerate{(env_valid_output != nullptr && env_valid_output[0] != '\0') ||
                          (env_invalid_output != nullptr && env_invalid_output[0] != '\0')};
    if (regenerate) {
        const char* const valid_output{(env_valid_output != nullptr && env_valid_output[0] != '\0') ? env_valid_output : "tx_valid_pq.json.gen"};
        const char* const invalid_output{(env_invalid_output != nullptr && env_invalid_output[0] != '\0') ? env_invalid_output : "tx_invalid_pq.json.gen"};
        BOOST_CHECK_MESSAGE(GeneratePQTxFixtures(valid_output, invalid_output), "Failed to generate PQ transaction fixtures");
        return;
    }

    // Read tests from test/data/tx_valid_pq.json
    UniValue tests = read_json(json_tests::tx_valid_pq);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        if (test.isStr()) continue;
        std::string strTest = test.write();
        if (!test.isArray() || test.size() < 3 || !test[0].isArray() || !test[1].isStr() || !test[2].isStr()) {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }

        std::map<COutPoint, CScript> prev_scripts;
        std::map<COutPoint, int64_t> prev_values;
        if (!ParseTxVectorInputs(test[0].get_array(), prev_scripts, prev_values)) {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }

        DataStream stream(ParseHex(test[1].get_str()));
        CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

        TxValidationState state;
        BOOST_CHECK_MESSAGE(CheckTransaction(tx, state), strTest);
        BOOST_CHECK(state.IsValid());

        const unsigned int verify_flags = FillFlags(ParseScriptFlags(test[2].get_str()));
        PrecomputedTransactionData txdata(tx);
        BOOST_CHECK_MESSAGE(CheckTxScripts(tx, prev_scripts, prev_values, verify_flags, txdata, strTest, /*expect_valid=*/true),
                            "Tx unexpectedly failed: " << strTest);
    }
}

BOOST_AUTO_TEST_CASE(tx_invalid)
{
    // Read tests from test/data/tx_invalid_pq.json
    UniValue tests = read_json(json_tests::tx_invalid_pq);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        if (test.isStr()) continue;
        std::string strTest = test.write();
        if (!test.isArray() || test.size() < 3 || !test[0].isArray() || !test[1].isStr() || !test[2].isStr()) {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }

        std::map<COutPoint, CScript> prev_scripts;
        std::map<COutPoint, int64_t> prev_values;
        if (!ParseTxVectorInputs(test[0].get_array(), prev_scripts, prev_values)) {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }

        DataStream stream(ParseHex(test[1].get_str()));
        CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

        TxValidationState state;
        if (!CheckTransaction(tx, state) || state.IsInvalid()) {
            BOOST_CHECK_MESSAGE(test[2].get_str() == "BADTX", strTest);
            continue;
        }

        const unsigned int verify_flags = FillFlags(ParseScriptFlags(test[2].get_str()));
        PrecomputedTransactionData txdata(tx);
        BOOST_CHECK_MESSAGE(CheckTxScripts(tx, prev_scripts, prev_values, verify_flags, txdata, strTest, /*expect_valid=*/false),
                            "Tx unexpectedly passed: " << strTest);
    }
}

BOOST_AUTO_TEST_CASE(tx_no_inputs)
{
    CMutableTransaction empty;

    TxValidationState state;
    BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(empty), state), "Transaction with no inputs should be invalid.");
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-vin-empty");
}

BOOST_AUTO_TEST_CASE(tx_oversized)
{
    auto createTransaction =[](size_t payloadSize) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vout.emplace_back(1, CScript() << OP_RETURN << std::vector<unsigned char>(payloadSize));
        return CTransaction(tx);
    };
    const auto maxTransactionSize = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR;
    const auto oversizedTransactionBaseSize = ::GetSerializeSize(TX_NO_WITNESS(createTransaction(maxTransactionSize))) - maxTransactionSize;

    auto maxPayloadSize = maxTransactionSize - oversizedTransactionBaseSize;
    {
        TxValidationState state;
        CheckTransaction(createTransaction(maxPayloadSize), state);
        BOOST_CHECK(state.GetRejectReason() != "bad-txns-oversize");
    }

    maxPayloadSize += 1;
    {
        TxValidationState state;
        BOOST_CHECK_MESSAGE(!CheckTransaction(createTransaction(maxPayloadSize), state), "Oversized transaction should be invalid");
        BOOST_CHECK(state.GetRejectReason() == "bad-txns-oversize");
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests)
{
    // Random real transaction (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65, 0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8, 0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77, 0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f, 0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2, 0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e, 0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4, 0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2, 0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a, 0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34, 0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97, 0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b, 0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f, 0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef, 0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39, 0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93, 0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43, 0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<unsigned char> vch(ch, ch + sizeof(ch) -1);
    DataStream stream(vch);
    CMutableTransaction tx;
    stream >> TX_WITH_WITNESS(tx);
    TxValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(CTransaction(tx), state) && state.IsValid(), "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(tx), state) || !state.IsValid(), "Transaction with duplicate txins should be invalid.");
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins, {11*CENT, 50*CENT, 21*CENT, 22*CENT});

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(CTransaction(t1), coins));
}

static void CreateCreditAndSpend(const FillableSigningProvider& keystore, const CScript& outscript, CTransactionRef& output, CMutableTransaction& input, bool success = true)
{
    CMutableTransaction outputm;
    outputm.version = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = outscript;
    DataStream ssout;
    ssout << TX_WITH_WITNESS(outputm);
    ssout >> TX_WITH_WITNESS(output);
    assert(output->vin.size() == 1);
    assert(output->vin[0] == outputm.vin[0]);
    assert(output->vout.size() == 1);
    assert(output->vout[0] == outputm.vout[0]);

    CMutableTransaction inputm;
    inputm.version = 1;
    inputm.vin.resize(1);
    inputm.vin[0].prevout.hash = output->GetHash();
    inputm.vin[0].prevout.n = 0;
    inputm.vout.resize(1);
    inputm.vout[0].nValue = 1;
    inputm.vout[0].scriptPubKey = CScript();
    SignatureData empty;
    bool ret = SignSignature(keystore, *output, inputm, 0, SIGHASH_ALL, empty);
    assert(ret == success);
    DataStream ssin;
    ssin << TX_WITH_WITNESS(inputm);
    ssin >> TX_WITH_WITNESS(input);
    assert(input.vin.size() == 1);
    assert(input.vin[0] == inputm.vin[0]);
    assert(input.vout.size() == 1);
    assert(input.vout[0] == inputm.vout[0]);
    assert(input.vin[0].scriptWitness.stack == inputm.vin[0].scriptWitness.stack);
}

static void CheckWithFlag(const CTransactionRef& output, const CMutableTransaction& input, uint32_t flags, bool success)
{
    ScriptError error;
    CTransaction inputi(input);
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output->vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output->vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, allow_legacy), &error);
    assert(ret == success);
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

static void ReplaceRedeemScript(CScript& script, const CScript& redeemScript)
{
    std::vector<valtype> stack;
    EvalScript(stack, script, 0, BaseSignatureChecker(), SigVersion::BASE);
    assert(stack.size() > 0);
    stack.back() = std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());
    script = PushAll(stack);
}

BOOST_AUTO_TEST_CASE(test_big_witness_transaction)
{
    CMutableTransaction mtx;
    mtx.version = 1;

    CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKeyPubKey(key, key.GetPubKey()));
    CKeyID hash = key.GetPubKey().GetID();
    CScript scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(hash.begin(), hash.end());

    std::vector<int> sigHashes;
    sigHashes.push_back(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_NONE);
    sigHashes.push_back(SIGHASH_SINGLE);
    sigHashes.push_back(SIGHASH_ALL);

    // create a big transaction of 4500 inputs signed by the same key
    for(uint32_t ij = 0; ij < 4500; ij++) {
        uint32_t i = mtx.vin.size();
        COutPoint outpoint(Txid::FromHex("0000000000000000000000000000000000000000000000000000000000000100").value(), i);

        mtx.vin.resize(mtx.vin.size() + 1);
        mtx.vin[i].prevout = outpoint;
        mtx.vin[i].scriptSig = CScript();

        mtx.vout.resize(mtx.vout.size() + 1);
        mtx.vout[i].nValue = 1000;
        mtx.vout[i].scriptPubKey = CScript() << OP_1;
    }

    // sign all inputs
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        SignatureData empty;
        bool hashSigned = SignSignature(keystore, scriptPubKey, mtx, i, 1000, sigHashes.at(i % sigHashes.size()), empty);
        assert(hashSigned);
    }

    DataStream ssout;
    ssout << TX_WITH_WITNESS(mtx);
    CTransaction tx(deserialize, TX_WITH_WITNESS, ssout);

    // check all inputs concurrently, with the cache
    PrecomputedTransactionData txdata(tx);
    CCheckQueue<CScriptCheck> scriptcheckqueue(/*batch_size=*/128, /*worker_threads_num=*/20);
    CCheckQueueControl<CScriptCheck> control(scriptcheckqueue);

    std::vector<Coin> coins;
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        Coin coin;
        coin.nHeight = 1;
        coin.fCoinBase = false;
        coin.out.nValue = 1000;
        coin.out.scriptPubKey = scriptPubKey;
        coins.emplace_back(std::move(coin));
    }

    SignatureCache signature_cache{DEFAULT_SIGNATURE_CACHE_BYTES};

    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        std::vector<CScriptCheck> vChecks;
        vChecks.emplace_back(coins[tx.vin[i].prevout.n].out, tx, signature_cache, i, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false, &txdata);
        control.Add(std::move(vChecks));
    }

    bool controlCheck = !control.Complete().has_value();
    assert(controlCheck);
}

SignatureData CombineSignatures(const CMutableTransaction& input1, const CMutableTransaction& input2, const CTransactionRef tx)
{
    SignatureData sigdata;
    sigdata = DataFromTransaction(input1, 0, tx->vout[0]);
    sigdata.MergeSignatureData(DataFromTransaction(input2, 0, tx->vout[0]));
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(input1, 0, tx->vout[0].nValue, SIGHASH_ALL), tx->vout[0].scriptPubKey, sigdata);
    return sigdata;
}

BOOST_AUTO_TEST_CASE(test_witness)
{
    FillableSigningProvider keystore, keystore2;
    CKey key1 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CKey key2 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CKey key3 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();
    CPubKey pubkey3 = key3.GetPubKey();
    BOOST_CHECK(keystore.AddKeyPubKey(key1, pubkey1));
    BOOST_CHECK(keystore.AddKeyPubKey(key2, pubkey2));
    CScript scriptPubkey1, scriptPubkey2, scriptMulti;
    scriptPubkey1 << ToByteVector(pubkey1) << OP_CHECKSIG;
    scriptPubkey2 << ToByteVector(pubkey2) << OP_CHECKSIG;
    std::vector<CPubKey> oneandthree;
    oneandthree.push_back(pubkey1);
    oneandthree.push_back(pubkey3);
    scriptMulti = GetScriptForMultisig(2, oneandthree);
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2));
    BOOST_CHECK(keystore.AddCScript(scriptMulti));
    CScript destination_script_1, destination_script_2, destination_script_multi;
    destination_script_1 = GetScriptForDestination(WitnessV0KeyHash(pubkey1));
    destination_script_2 = GetScriptForDestination(WitnessV0KeyHash(pubkey2));
    destination_script_multi = GetScriptForDestination(WitnessV0ScriptHash(scriptMulti));
    BOOST_CHECK(keystore.AddCScript(destination_script_1));
    BOOST_CHECK(keystore.AddCScript(destination_script_2));
    BOOST_CHECK(keystore.AddCScript(destination_script_multi));
    BOOST_CHECK(keystore2.AddCScript(scriptMulti));
    BOOST_CHECK(keystore2.AddCScript(destination_script_multi));
    BOOST_CHECK(keystore2.AddKeyPubKey(key3, pubkey3));

    CTransactionRef output1, output2;
    CMutableTransaction input1, input2;

    // Normal pay-to-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-pubkey.
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey1)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey2)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Witness pay-to-pubkey (v0).
    CreateCreditAndSpend(keystore, destination_script_1, output1, input1);
    CreateCreditAndSpend(keystore, destination_script_2, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH witness pay-to-pubkey (v0).
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_1)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_2)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, destination_script_1);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal 2-of-2 multisig
    CreateCreditAndSpend(keystore, scriptMulti, output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, false);
    CreateCreditAndSpend(keystore2, scriptMulti, output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH 2-of-2 multisig
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptMulti)), output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, false);
    CreateCreditAndSpend(keystore2, GetScriptForDestination(ScriptHash(scriptMulti)), output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // Witness 2-of-2 multisig
    CreateCreditAndSpend(keystore, destination_script_multi, output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    CreateCreditAndSpend(keystore2, destination_script_multi, output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH witness 2-of-2 multisig
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_multi)), output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    CreateCreditAndSpend(keystore2, GetScriptForDestination(ScriptHash(destination_script_multi)), output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
}

BOOST_AUTO_TEST_CASE(test_witness_v0_v1_mix)
{
    const CScript witness_script_v0 = CScript() << OP_TRUE;
    const CScript witness_script_v1 = CScript() << OP_TRUE;

    const CScript script_pub_key_v0 = GetScriptForDestination(WitnessV0ScriptHash(witness_script_v0));
    const CScript script_pub_key_v1 = GetScriptForDestination(WitnessV1ScriptHash512(witness_script_v1));

    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    tx.vout[0].scriptPubKey = CScript();

    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[1].prevout.hash = Txid::FromUint256(uint256::FromUserHex("2").value());
    tx.vin[1].prevout.n = 1;

    tx.vin[0].scriptWitness.stack.emplace_back(witness_script_v0.begin(), witness_script_v0.end());
    tx.vin[1].scriptWitness.stack.emplace_back(witness_script_v1.begin(), witness_script_v1.end());

    const CTransaction tx_const(tx);
    const unsigned int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_V1_512 | SCRIPT_VERIFY_SHA512;
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(CScript(), script_pub_key_v0, &tx_const.vin[0].scriptWitness, flags,
                             TransactionSignatureChecker(&tx_const, 0, 1, MissingDataBehavior::ASSERT_FAIL, allow_legacy), &err));
    err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(CScript(), script_pub_key_v1, &tx_const.vin[1].scriptWitness, flags,
                             TransactionSignatureChecker(&tx_const, 1, 1, MissingDataBehavior::ASSERT_FAIL, allow_legacy), &err));
}

BOOST_AUTO_TEST_CASE(test_IsStandard)
{
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins, {11*CENT, 50*CENT, 21*CENT, 22*CENT});

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t.vin[0].prevout.n = 1;
    t.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90*CENT;
    CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

    constexpr auto CheckIsStandard = [](const auto& t, const unsigned int max_op_return_relay = MAX_OP_RETURN_RELAY) {
        std::string reason;
        BOOST_CHECK(IsStandardTx(CTransaction{t}, max_op_return_relay, g_bare_multi, g_dust, reason));
        BOOST_CHECK(reason.empty());
    };
    constexpr auto CheckIsNotStandard = [](const auto& t, const std::string& reason_in, const unsigned int max_op_return_relay = MAX_OP_RETURN_RELAY) {
        std::string reason;
        BOOST_CHECK(!IsStandardTx(CTransaction{t}, max_op_return_relay, g_bare_multi, g_dust, reason));
        BOOST_CHECK_EQUAL(reason_in, reason);
    };

    CheckIsStandard(t);

    // Check dust with default relay fee (PQ-aware threshold for selected script type).
    CAmount nDustThreshold = GetDustThreshold(t.vout[0], g_dust);

    // Add dust outputs up to allowed maximum, still standard!
    for (size_t i{0}; i < MAX_DUST_OUTPUTS_PER_TX; ++i) {
        t.vout.emplace_back(0, t.vout[0].scriptPubKey);
        CheckIsStandard(t);
    }

    // dust:
    t.vout[0].nValue = nDustThreshold - 1;
    CheckIsNotStandard(t, "dust");
    // not dust:
    t.vout[0].nValue = nDustThreshold;
    CheckIsStandard(t);

    // Disallowed version
    t.version = std::numeric_limits<uint32_t>::max();
    CheckIsNotStandard(t, "version");

    t.version = 0;
    CheckIsNotStandard(t, "version");

    t.version = TX_MAX_STANDARD_VERSION + 1;
    CheckIsNotStandard(t, "version");

    // Allowed version
    t.version = 1;
    CheckIsStandard(t);

    t.version = 2;
    CheckIsStandard(t);

    // Check dust with odd relay fee to verify rounding.
    g_dust = CFeeRate(3702);
    nDustThreshold = GetDustThreshold(t.vout[0], g_dust);
    // dust:
    t.vout[0].nValue = nDustThreshold - 1;
    CheckIsNotStandard(t, "dust");
    // not dust:
    t.vout[0].nValue = nDustThreshold;
    CheckIsStandard(t);
    g_dust = CFeeRate{DUST_RELAY_TX_FEE};

    t.vout[0].scriptPubKey = CScript() << OP_1;
    CheckIsNotStandard(t, "scriptpubkey");

    // Custom 83-byte TxoutType::NULL_DATA (standard with max_op_return_relay of 83)
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    BOOST_CHECK_EQUAL(83, t.vout[0].scriptPubKey.size());
    CheckIsStandard(t, /*max_op_return_relay=*/83);

    // Non-standard if max_op_return_relay datacarrier arg is one less
    CheckIsNotStandard(t, "datacarrier", /*max_op_return_relay=*/82);

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ""_hex;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "00"_hex << "01"_hex;
    CheckIsStandard(t);
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED << -1 << 0 << "01"_hex << 2 << 3 << 4 << 5 << 6 << 7 << 8 << 9 << 10 << 11 << 12 << 13 << 14 << 15 << 16;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << 0 << "01"_hex << 2 << "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex;
    CheckIsStandard(t);

    // ...so long as it only contains PUSHDATA's
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    CheckIsNotStandard(t, "scriptpubkey");

    // TxoutType::NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    CheckIsStandard(t);

    // Multiple TxoutType::NULL_DATA are permitted
    t.vout.resize(2);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[0].nValue = 0;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].nValue = 0;
    CheckIsStandard(t);

    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    CheckIsStandard(t);

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    CheckIsStandard(t);

    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    const auto datacarrier_size = t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size();
    CheckIsStandard(t); // Default max relay should never trigger
    CheckIsStandard(t, /*max_op_return_relay=*/datacarrier_size);
    CheckIsNotStandard(t, "datacarrier", /*max_op_return_relay=*/datacarrier_size-1);

    // Check large scriptSig (non-standard if size is > MAX_STANDARD_SCRIPTSIG_SIZE)
    t.vout.resize(1);
    t.vout[0].nValue = MAX_MONEY;
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    BOOST_REQUIRE(MAX_STANDARD_SCRIPTSIG_SIZE > 3);
    const auto push_len = static_cast<size_t>(MAX_STANDARD_SCRIPTSIG_SIZE) - 3;
    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(push_len, 0);
    BOOST_CHECK_EQUAL(t.vin[0].scriptSig.size(), MAX_STANDARD_SCRIPTSIG_SIZE);
    CheckIsStandard(t);

    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(push_len + 1, 0);
    BOOST_CHECK(t.vin[0].scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE);
    CheckIsNotStandard(t, "scriptsig-size");

    // Check scriptSig format (non-standard if there are any other ops than just PUSHs)
    t.vin[0].scriptSig = CScript()
        << OP_TRUE << OP_0 << OP_1NEGATE << OP_16 // OP_n (single byte pushes: n = 1, 0, -1, 16)
        << std::vector<unsigned char>(75, 0)      // OP_PUSHx [...x bytes...]
        << std::vector<unsigned char>(235, 0)     // OP_PUSHDATA1 x [...x bytes...]
        << std::vector<unsigned char>(1234, 0)    // OP_PUSHDATA2 x [...x bytes...]
        << OP_9;
    CheckIsStandard(t);

    const std::vector<unsigned char> non_push_ops = { // arbitrary set of non-push operations
        OP_NOP, OP_VERIFY, OP_IF, OP_ROT, OP_3DUP, OP_SIZE, OP_EQUAL, OP_ADD, OP_SUB,
        OP_HASH256, OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKLOCKTIMEVERIFY };

    CScript::const_iterator pc = t.vin[0].scriptSig.begin();
    while (pc < t.vin[0].scriptSig.end()) {
        opcodetype opcode;
        CScript::const_iterator prev_pc = pc;
        t.vin[0].scriptSig.GetOp(pc, opcode); // advance to next op
        // for the sake of simplicity, we only replace single-byte push operations
        if (opcode >= 1 && opcode <= OP_PUSHDATA4)
            continue;

        int index = prev_pc - t.vin[0].scriptSig.begin();
        unsigned char orig_op = *prev_pc; // save op
        // replace current push-op with each non-push-op
        for (auto op : non_push_ops) {
            t.vin[0].scriptSig[index] = op;
            CheckIsNotStandard(t, "scriptsig-not-pushonly");
        }
        t.vin[0].scriptSig[index] = orig_op; // restore op
        CheckIsStandard(t);
    }

    // Check tx-size (non-standard if transaction weight is > MAX_STANDARD_TX_WEIGHT)
    t.vin.clear();
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(19, 0);

    t.vin.resize(1);
    const auto weight_one = GetTransactionWeight(CTransaction(t));
    t.vin.resize(2);
    const auto weight_two = GetTransactionWeight(CTransaction(t));
    const auto input_weight = weight_two - weight_one;
    const auto base_weight = weight_one - input_weight;
    const auto max_inputs = (MAX_STANDARD_TX_WEIGHT - base_weight) / input_weight;
    BOOST_REQUIRE(max_inputs > 0);
    t.vin.resize(max_inputs);
    const auto standard_weight = GetTransactionWeight(CTransaction(t));
    BOOST_CHECK(standard_weight <= MAX_STANDARD_TX_WEIGHT);
    CheckIsStandard(t);

    const auto slack = MAX_STANDARD_TX_WEIGHT - standard_weight;
    const auto extra_bytes = (slack / WITNESS_SCALE_FACTOR) + 1;
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(19 + extra_bytes, 0);
    BOOST_CHECK(GetTransactionWeight(CTransaction(t)) > MAX_STANDARD_TX_WEIGHT);
    CheckIsNotStandard(t, "tx-size");

    // Check bare multisig (standard if policy flag g_bare_multi is set)
    g_bare_multi = true;
    t.vout[0].scriptPubKey = GetScriptForMultisig(1, {key.GetPubKey()}); // simple 1-of-1
    t.vin.resize(1);
    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(65, 0);
    CheckIsStandard(t);

    g_bare_multi = false;
    CheckIsNotStandard(t, "bare-multisig");
    g_bare_multi = DEFAULT_PERMIT_BAREMULTISIG;

    // Add dust outputs up to allowed maximum (use non-bare script to avoid policy interference)
    t.vout.clear();
    t.vout.emplace_back(0, GetScriptForDestination(PKHash(key.GetPubKey())));
    t.vout.insert(t.vout.end(), MAX_DUST_OUTPUTS_PER_TX, {0, t.vout[0].scriptPubKey});

    // Check P2PK outputs dust threshold for PQ pubkeys.
    const CScript p2pk_script = GetScriptForRawPubKey(key.GetPubKey());
    t.vout[0].scriptPubKey = p2pk_script;
    t.vout[0].nValue = GetDustThreshold(t.vout[0], g_dust);
    CheckIsStandard(t);
    t.vout[0].nValue--;
    CheckIsNotStandard(t, "dust");

    // Check P2PKH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
    t.vout[0].nValue = GetDustThreshold(t.vout[0], g_dust);
    CheckIsStandard(t);
    t.vout[0].nValue--;
    CheckIsNotStandard(t, "dust");

    // Check P2SH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUAL;
    t.vout[0].nValue = GetDustThreshold(t.vout[0], g_dust);
    CheckIsStandard(t);
    t.vout[0].nValue--;
    CheckIsNotStandard(t, "dust");

    // Check P2WPKH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(20, 0);
    t.vout[0].nValue = GetDustThreshold(t.vout[0], g_dust);
    CheckIsStandard(t);
    t.vout[0].nValue--;
    CheckIsNotStandard(t, "dust");

    // Check P2WSH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(32, 0);
    t.vout[0].nValue = GetDustThreshold(t.vout[0], g_dust);
    CheckIsStandard(t);
    t.vout[0].nValue--;
    CheckIsNotStandard(t, "dust");

    // Check witness-v1_512 outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(64, 0);
    t.vout[0].nValue = GetDustThreshold(t.vout[0], g_dust);
    CheckIsStandard(t);
    t.vout[0].nValue--;
    CheckIsNotStandard(t, "dust");

}

BOOST_AUTO_TEST_CASE(max_standard_legacy_sigops)
{
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);

    // Create a pathological P2SH script padded with as many sigops as is standard.
    CScript max_sigops_redeem_script{CScript() << std::vector<unsigned char>{} << key.GetPubKey()};
    for (unsigned i{0}; i < MAX_P2SH_SIGOPS - 1; ++i) max_sigops_redeem_script << OP_2DUP << OP_CHECKSIG << OP_DROP;
    max_sigops_redeem_script << OP_CHECKSIG << OP_NOT;
    const CScript max_sigops_p2sh{GetScriptForDestination(ScriptHash(max_sigops_redeem_script))};

    // Create a transaction fanning out as many such P2SH outputs as is standard to spend in a
    // single transaction, and a transaction spending them.
    CMutableTransaction tx_create, tx_max_sigops;
    const unsigned p2sh_inputs_count{MAX_TX_LEGACY_SIGOPS / MAX_P2SH_SIGOPS};
    tx_create.vout.reserve(p2sh_inputs_count);
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_create.vout.emplace_back(424242 + i, max_sigops_p2sh);
    }
    auto prev_txid{tx_create.GetHash()};
    tx_max_sigops.vin.reserve(p2sh_inputs_count);
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i, CScript() << ToByteVector(max_sigops_redeem_script));
    }

    // p2sh_inputs_count is truncated to 166 (from 166.6666..)
    BOOST_CHECK_LT(p2sh_inputs_count * MAX_P2SH_SIGOPS, MAX_TX_LEGACY_SIGOPS);
    AddCoins(coins, CTransaction(tx_create), 0, false);

    // 2490 sigops is below the limit.
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(CTransaction(tx_max_sigops), coins), 2490);
    BOOST_CHECK(::AreInputsStandard(CTransaction(tx_max_sigops), coins));

    // Adding one more input will bump this to 2505, hitting the limit.
    tx_create.vout.emplace_back(424242, max_sigops_p2sh);
    prev_txid = tx_create.GetHash();
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_max_sigops.vin[i] = CTxIn(COutPoint(prev_txid, i), CScript() << ToByteVector(max_sigops_redeem_script));
    }
    tx_max_sigops.vin.emplace_back(prev_txid, p2sh_inputs_count, CScript() << ToByteVector(max_sigops_redeem_script));
    AddCoins(coins, CTransaction(tx_create), 0, false);
    BOOST_CHECK_GT((p2sh_inputs_count + 1) * MAX_P2SH_SIGOPS, MAX_TX_LEGACY_SIGOPS);
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(CTransaction(tx_max_sigops), coins), 2505);
    BOOST_CHECK(!::AreInputsStandard(CTransaction(tx_max_sigops), coins));

    // Now, check the limit can be reached with regular P2PK outputs too. Use a separate
    // preparation transaction, to demonstrate spending coins from a single tx is irrelevant.
    CMutableTransaction tx_create_p2pk;
    const auto p2pk_script{CScript() << key.GetPubKey() << OP_CHECKSIG};
    unsigned p2pk_inputs_count{10}; // From 2490 to 2500.
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_create_p2pk.vout.emplace_back(212121 + i, p2pk_script);
    }
    prev_txid = tx_create_p2pk.GetHash();
    tx_max_sigops.vin.resize(p2sh_inputs_count); // Drop the extra input.
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }
    AddCoins(coins, CTransaction(tx_create_p2pk), 0, false);

    // The transaction now contains exactly 2500 sigops, the check should pass.
    BOOST_CHECK_EQUAL(p2sh_inputs_count * MAX_P2SH_SIGOPS + p2pk_inputs_count * 1, MAX_TX_LEGACY_SIGOPS);
    BOOST_CHECK(::AreInputsStandard(CTransaction(tx_max_sigops), coins));

    // Now, add some Segwit inputs. We add one for each Segwit v0 output type. The limit
    // is exclusively on non-witness sigops and therefore those should not be counted.
    CMutableTransaction tx_create_segwit;
    const auto witness_script{CScript() << key.GetPubKey() << OP_CHECKSIG};
    tx_create_segwit.vout.emplace_back(121212, GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey())));
    tx_create_segwit.vout.emplace_back(131313, GetScriptForDestination(WitnessV0ScriptHash(witness_script)));
    prev_txid = tx_create_segwit.GetHash();
    for (unsigned i{0}; i < tx_create_segwit.vout.size(); ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }

    // The transaction now still contains exactly 2500 sigops, the check should pass.
    AddCoins(coins, CTransaction(tx_create_segwit), 0, false);
    BOOST_REQUIRE(::AreInputsStandard(CTransaction(tx_max_sigops), coins));

    // Add one more P2PK input. We'll reach the limit.
    tx_create_p2pk.vout.emplace_back(212121, p2pk_script);
    prev_txid = tx_create_p2pk.GetHash();
    tx_max_sigops.vin.resize(p2sh_inputs_count);
    ++p2pk_inputs_count;
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }
    AddCoins(coins, CTransaction(tx_create_p2pk), 0, false);
    BOOST_CHECK_GT(p2sh_inputs_count * MAX_P2SH_SIGOPS + p2pk_inputs_count * 1, MAX_TX_LEGACY_SIGOPS);
    BOOST_CHECK(!::AreInputsStandard(CTransaction(tx_max_sigops), coins));
}

/** Sanity check the return value of SpendsNonAnchorWitnessProg for various output types. */
BOOST_AUTO_TEST_CASE(spends_witness_prog)
{
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    const CPubKey pubkey{key.GetPubKey()};
    CMutableTransaction tx_create{}, tx_spend{};
    tx_create.vout.emplace_back(0, CScript{});
    tx_spend.vin.emplace_back(Txid{}, 0);
    std::vector<std::vector<uint8_t>> sol_dummy;

    // CNoDestination, PubKeyDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessV1ScriptHash512.
    static_assert(std::variant_size_v<CTxDestination> == 7);

    // Go through all defined output types and sanity check SpendsNonAnchorWitnessProg.

    // P2PK
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(PubKeyDestination{pubkey});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::PUBKEY);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2PKH
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(PKHash{pubkey});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::PUBKEYHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH
    auto redeem_script{CScript{} << OP_1 << OP_CHECKSIG};
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash{redeem_script});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << OP_0 << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();

    // native P2WSH
    const auto witness_script{CScript{} << OP_12 << OP_HASH160 << OP_DUP << OP_EQUAL};
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash{witness_script});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::WITNESS_V0_SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH-wrapped P2WSH
    redeem_script = tx_create.vout[0].scriptPubKey;
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(redeem_script));
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // native P2WPKH
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(WitnessV0KeyHash{pubkey});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::WITNESS_V0_KEYHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH-wrapped P2WPKH
    redeem_script = tx_create.vout[0].scriptPubKey;
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(redeem_script));
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

}

BOOST_AUTO_TEST_SUITE_END()
