// Copyright (c) 2019-2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tidecoin-build-config.h> // IWYU pragma: keep
#include <common/run_command.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#ifdef ENABLE_EXTERNAL_SIGNER
#include <external_signer.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/policy.h>
#include <psbt.h>
#include <script/sign.h>
#include <script/solver.h>
#include <key.h>
#include <util/strencodings.h>
#include <fstream>
#include <test/util/run_command.h>
#include <util/subprocess.h>
#endif

#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(system_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(command_arguments)
{
    const auto check = [](const std::string& command, const std::vector<std::string>& expected) {
        const auto actual{ParseCommandArguments(command)};
        BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
    };
    check("", {});
    check(" \t\r\n", {});
    check("signer   --device\tusb", {"signer", "--device", "usb"});
    check(R"("/path with spaces/signer" 'argument with spaces' "")", {"/path with spaces/signer", "argument with spaces", ""});
    check(R"(signer pre"middle space"post 'double"quote' "single'quote")", {"signer", "premiddle spacepost", "double\"quote", "single'quote"});
    check(R"(C:\tools\signer.exe 'C:\Program Files\signer.exe' 'C:\directory\' '\\server\share\signer.exe')",
          {R"(C:\tools\signer.exe)", R"(C:\Program Files\signer.exe)", R"(C:\directory\)", R"(\\server\share\signer.exe)"});
    check(R"("C:\Program Files\signer.exe" "C:\directory\\" "a\"b" "\\\\server\share")",
          {R"(C:\Program Files\signer.exe)", R"(C:\directory\)", "a\"b", R"(\\server\share)"});
    check("signer $HOME $(command) ; * ~", {"signer", "$HOME", "$(command)", ";", "*", "~"});
    for (const std::string command : {"'unterminated", "signer \"unterminated", "\"\" arg", "''"}) {
        BOOST_CHECK_THROW(ParseCommandArguments(command), std::invalid_argument);
    }
    BOOST_CHECK_THROW(ParseCommandArguments(std::string{"signer\0arg", 10}), std::invalid_argument);
}

#ifdef ENABLE_EXTERNAL_SIGNER
BOOST_AUTO_TEST_CASE(run_command)
{
    const auto executable{fs::PathToString(test::CopyMockProcess(m_args.GetDataDirBase() / "process space"))};
    BOOST_CHECK(RunCommandParseJSON({}).isNull());
    BOOST_CHECK_THROW(RunCommandParseJSON({""}), std::invalid_argument);
    BOOST_CHECK_THROW(RunCommandParseJSON({executable, std::string{"x\0y", 3}}), std::invalid_argument);

    const std::vector<std::string> values{"a b", "", "quote\"and'apostrophe", R"(C:\path\)", "unicode-\xc3\xa9", "$(echo unwanted);*"};
    auto command{std::vector<std::string>{executable, "echo"}};
    command.insert(command.end(), values.begin(), values.end());
    const auto result{RunCommandParseJSON(command)};
    const auto& actual{result.find_value("args")};
    BOOST_REQUIRE_EQUAL(actual.size(), values.size());
    for (size_t i = 0; i < values.size(); ++i) BOOST_CHECK_EQUAL(actual[i].get_str(), values[i]);

    std::string configured{test::QuoteCommandArgument(executable) + " echo"};
    for (const auto& value : values) configured += " " + test::QuoteCommandArgument(value);
    BOOST_CHECK_EQUAL(RunCommandParseJSON(ParseCommandArguments(configured)).write(), result.write());
    BOOST_CHECK_EXCEPTION(RunCommandParseJSON({executable, "fail"}), std::runtime_error, HasReason("returned 7: mock failure"));
    BOOST_CHECK_EXCEPTION(RunCommandParseJSON({executable, "invalid-json"}), std::runtime_error, HasReason("Unable to parse JSON: {"));
    BOOST_CHECK(RunCommandParseJSON({executable, "stdin"}, "{\"success\":true}")["success"].get_bool());
#ifdef WIN32
    const std::string expected{"CreateProcess failed: "};
#else
    const std::string expected{"execve failed: "};
#endif
    BOOST_CHECK_EXCEPTION(RunCommandParseJSON({executable + ".missing"}), subprocess::CalledProcessError, HasReason(expected));
}

BOOST_AUTO_TEST_CASE(signer_argument_boundaries)
{
    const auto executable{fs::PathToString(test::CopyMockProcess(m_args.GetDataDirBase() / "signer space"))};
    ExternalSigner signer{{executable, "echo"}, "chain value", "finger print", "mock"};
    const auto result{signer.GetDescriptors(3)};
    const std::vector<std::string> expected{"--fingerprint", "finger print", "--chain", "chain value", "getdescriptors", "--account", "3"};
    const auto& actual{result["args"]};
    BOOST_REQUIRE_EQUAL(actual.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) BOOST_CHECK_EQUAL(actual[i].get_str(), expected[i]);
    const std::string descriptor{"descriptor with spaces, quotes '\" and $(literal)"};
    const auto display{signer.DisplayAddress(descriptor)};
    BOOST_REQUIRE_EQUAL(display["args"].size(), 7U);
    BOOST_CHECK_EQUAL(display["args"][6].get_str(), descriptor);
}
BOOST_AUTO_TEST_CASE(signer_response_preserves_request)
{
    const CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    provider.pubkeys.emplace(key.GetPubKey().GetID(), key.GetPubKey());
    CMutableTransaction tx;
    tx.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
    tx.vout.emplace_back(COIN - 1000, CScript{} << OP_TRUE);
    PartiallySignedTransaction original{tx};
    original.inputs[0].witness_utxo = CTxOut(COIN, GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey())));
    original.inputs[0].unknown[{0xaa}] = {1};
    original.outputs[0].unknown[{0xab}] = {2};
    original.unknown[{0xac}] = {3};
    const auto bytes = [](const auto& value) { DataStream s; s << value; return HexStr(s); };
    const auto sign = [&](int sighash, bool finalize) {
        auto result = original;
        const auto data = PrecomputePSBTData(result);
        BOOST_REQUIRE(SignPSBTInput(provider, result, 0, &data, sighash, nullptr, finalize) == common::PSBTError::OK);
        return result;
    };
    const auto signed_psbt = sign(SIGHASH_ALL, true);
    const auto reject = [&](const auto& returned) {
        auto request = original;
        const auto before = bytes(request);
        std::string error;
        BOOST_CHECK(!ExternalSigner::MergeSignatures(request, returned, error, STANDARD_SCRIPT_VERIFY_FLAGS));
        BOOST_CHECK(!error.empty());
        BOOST_CHECK_EQUAL(bytes(request), before);
    };
    auto changed = signed_psbt;
    changed.tx->vout[0].nValue--;
    reject(changed);
    changed = signed_psbt;
    changed.inputs[0].witness_utxo.nValue++;
    reject(changed);
    changed = signed_psbt;
    changed.outputs[0].unknown[{0xab}] = {4};
    reject(changed);
    changed = signed_psbt;
    changed.inputs[0].sighash_type = SIGHASH_NONE; // Hidden by finalization when serialized.
    reject(changed);
    changed = signed_psbt;
    changed.inputs[0].final_script_witness.stack[0][10] ^= 1;
    reject(changed);
    changed = sign(SIGHASH_NONE, true);
    changed.inputs[0].sighash_type.reset();
    reject(changed); // A valid signature still cannot change the requested sighash.

    auto omitted = signed_psbt;
    omitted.unknown.clear();
    omitted.inputs[0].unknown.clear();
    omitted.outputs[0].unknown.clear();
    auto request = original;
    std::string error;
    BOOST_REQUIRE(ExternalSigner::MergeSignatures(request, sign(SIGHASH_ALL, false), error, STANDARD_SCRIPT_VERIFY_FLAGS));
    BOOST_CHECK(!PSBTInputSigned(request.inputs[0]));
    BOOST_CHECK(!request.inputs[0].partial_sigs.empty());
    BOOST_CHECK(FinalizePSBT(request));
    request = original;
    BOOST_REQUIRE(ExternalSigner::MergeSignatures(request, omitted, error, STANDARD_SCRIPT_VERIFY_FLAGS));
    BOOST_CHECK(request.unknown == original.unknown);
    BOOST_CHECK(request.inputs[0].unknown == original.inputs[0].unknown);
    BOOST_CHECK(request.outputs[0].unknown == original.outputs[0].unknown);
    const auto data = PrecomputePSBTData(request);
    BOOST_CHECK(PSBTInputSignedAndVerified(request, 0, &data));

    // Existing verified finals may have a different sighash with no remaining
    // sighash metadata. Signing another input must preserve those finals.
    auto prior = sign(SIGHASH_NONE, true);
    prior.inputs[0].sighash_type.reset();
    auto same = prior;
    BOOST_REQUIRE(ExternalSigner::MergeSignatures(prior, same, error, STANDARD_SCRIPT_VERIFY_FLAGS));

    // A hash-type policy checker must not change CHECKSIG's truth value: that
    // could turn a consensus-invalid CHECKSIG NOT script into an accepted one.
    auto negated = original;
    const CScript witness_script = CScript{} << ToByteVector(key.GetPubKey()) << OP_CHECKSIG << OP_NOT;
    negated.inputs[0].witness_script = witness_script;
    negated.inputs[0].witness_utxo.scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
    auto negated_reply = negated;
    const auto negated_data = PrecomputePSBTData(negated);
    MutableTransactionSignatureCreator creator{*negated.tx, 0, COIN, &negated_data, SIGHASH_NONE, true};
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(creator.CreateSig(provider, signature, key.GetPubKey().GetID(), witness_script, SigVersion::WITNESS_V0));
    negated_reply.inputs[0].final_script_witness.stack = {signature, {witness_script.begin(), witness_script.end()}};
    BOOST_CHECK(!PSBTInputSignedAndVerified(negated_reply, 0, &negated_data));
    const auto negated_before = bytes(negated);
    BOOST_CHECK(!ExternalSigner::MergeSignatures(negated, negated_reply, error, STANDARD_SCRIPT_VERIFY_FLAGS));
    BOOST_CHECK_EQUAL(bytes(negated), negated_before);

    // Exercise the actual subprocess boundary and rejection preservation too.
    const auto executable = test::CopyMockProcess(m_args.GetDataDirBase() / "PSBT signer");
    const auto path = m_args.GetDataDirBase() / fs::PathFromString("signer r\xc3\xa9ponses \xe6\x96\x87.json");
    ExternalSigner signer{{fs::PathToString(executable), "signer", fs::PathToString(path)}, "regtest", "mock", "mock"};
    for (bool valid : {false, true}) {
        auto response = signed_psbt;
        if (!valid) response.tx->nLockTime++;
        DataStream stream;
        stream << response;
        UniValue result{UniValue::VOBJ}, responses{UniValue::VOBJ};
        result.pushKV("psbt", EncodeBase64(stream));
        responses.pushKV("signtx", result);
        { std::ofstream file{path}; file << responses.write(); BOOST_REQUIRE(file.good()); }
        request = original;
        BOOST_CHECK_EQUAL(signer.SignTransaction(request, error, STANDARD_SCRIPT_VERIFY_FLAGS), valid);
        if (!valid) BOOST_CHECK_EQUAL(bytes(request), bytes(original));
        else BOOST_CHECK(PSBTInputSignedAndVerified(request, 0, &data));
    }
}

#else
BOOST_AUTO_TEST_CASE(run_command_disabled)
{
    BOOST_CHECK_EXCEPTION(RunCommandParseJSON({"unused"}), std::runtime_error,
                          HasReason("Compiled without external signing support"));
}
#endif // ENABLE_EXTERNAL_SIGNER

BOOST_AUTO_TEST_SUITE_END()
