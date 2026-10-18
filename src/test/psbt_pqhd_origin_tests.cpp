#include <pq/pq_scheme.h>
#include <pq/pqhd_params.h>

#include <key.h>
#include <coins.h>
#include <common/messages.h>
#include <node/psbt.h>
#include <policy/policy.h>
#include <psbt.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <util/vector.h>
#include <util/translation.h>

#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#ifndef WIN32
#include <csignal>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include <set>
#include <span>
#include <vector>

namespace {

constexpr uint32_t HARDENED = 0x80000000U;

CPubKey MakeDummyTidePubKey(pq::SchemeId scheme_id)
{
    const pq::SchemeInfo* scheme = pq::SchemeFromId(scheme_id);
    BOOST_REQUIRE(scheme);

    std::vector<unsigned char> bytes(scheme->pubkey_bytes + 1);
    bytes[0] = scheme->prefix;
    for (size_t i = 1; i < bytes.size(); ++i) bytes[i] = 0x42;
    return CPubKey{bytes};
}

std::vector<uint32_t> MakePQHDPathForScheme(pq::SchemeId scheme_id)
{
    return {
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | static_cast<uint32_t>(static_cast<uint8_t>(scheme_id)),
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 0U,
    };
}

PartiallySignedTransaction MakeMinimalPSBT()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
    mtx.vout.emplace_back(1, CScript{});
    return PartiallySignedTransaction{mtx};
}

} // namespace

BOOST_AUTO_TEST_SUITE(psbt_pqhd_origin_tests)

BOOST_AUTO_TEST_CASE(psbt_missing_witness_script_commitment)
{
    const CScript script{CScript{} << OP_TRUE};
    for (int version : {0, 1}) {
        const auto commitment = version == 0 ? ToByteVector(WitnessV0ScriptHash{script}) : ToByteVector(WitnessV1ScriptHash512{script});
        const CScript program{CScript{} << CScript::EncodeOP_N(version) << commitment};
        for (bool wrapped : {false, true}) {
            auto psbt = MakeMinimalPSBT();
            psbt.inputs[0].witness_utxo = CTxOut{1000, wrapped ? GetScriptForDestination(ScriptHash{program}) : program};
            if (wrapped) psbt.inputs[0].redeem_script = program;
            for (const CScript& supplied : {CScript{}, CScript{} << OP_FALSE}) {
                psbt.inputs[0].witness_script = supplied;
                const auto analysis = node::AnalyzePSBT(psbt, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_WITNESS_V1_512);
                BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
                BOOST_CHECK(analysis.inputs[0].missing_witness_script == commitment);
                BOOST_CHECK(analysis.next == PSBTRole::UPDATER);
                BOOST_CHECK(!analysis.estimated_vsize);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(psbt_witness_v1_analysis_size, BasicTestingSetup)
{
    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    const auto pubkey = key.GetPubKey();
    FlatSigningProvider provider;
    provider.keys.emplace(pubkey.GetID(), key);
    const CScript script{CScript{} << ToByteVector(pubkey) << OP_CHECKSIG};
    constexpr unsigned flags{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512};
    auto psbt = MakeMinimalPSBT();
    psbt.inputs[0].witness_utxo = CTxOut{1000, GetScriptForDestination(WitnessV1ScriptHash512{script})};
    psbt.inputs[0].witness_script = script;
    const auto unsigned_analysis = node::AnalyzePSBT(psbt, flags);
    BOOST_CHECK(unsigned_analysis.next == PSBTRole::SIGNER);
    BOOST_CHECK(unsigned_analysis.estimated_vsize);
    BOOST_CHECK(unsigned_analysis.estimated_feerate);

    const auto data = PrecomputePSBTData(psbt);
    BOOST_REQUIRE(SignPSBTInput(provider, psbt, 0, &data, SIGHASH_ALL, nullptr, false, flags) == PSBTError::OK);
    const auto ready_analysis = node::AnalyzePSBT(psbt, flags);
    BOOST_CHECK(ready_analysis.next == PSBTRole::FINALIZER);
    BOOST_REQUIRE(ready_analysis.estimated_vsize);
    BOOST_CHECK(!PSBTInputSigned(psbt.inputs[0])); // Analysis finalizes only its copy.

    BOOST_REQUIRE(FinalizePSBT(psbt, flags));
    const auto final_analysis = node::AnalyzePSBT(psbt, flags);
    BOOST_CHECK(final_analysis.next == PSBTRole::EXTRACTOR);
    BOOST_CHECK(final_analysis.estimated_vsize == ready_analysis.estimated_vsize);
    BOOST_CHECK(final_analysis.estimated_feerate == ready_analysis.estimated_feerate);
    BOOST_REQUIRE(final_analysis.fee);
    BOOST_CHECK_EQUAL(*final_analysis.fee, 999);

    // Invalid final fields must not be accepted by the dummy signature checker.
    psbt.inputs[0].final_script_witness.stack[0][0] ^= 1;
    const auto invalid_analysis = node::AnalyzePSBT(psbt, flags);
    BOOST_CHECK(invalid_analysis.next == PSBTRole::UPDATER);
    BOOST_CHECK(!invalid_analysis.estimated_vsize);
    BOOST_CHECK(!invalid_analysis.estimated_feerate);
}

BOOST_AUTO_TEST_CASE(invalid_final_fields_do_not_imply_completion)
{
    CMutableTransaction previous;
    previous.vout.emplace_back(1000, CScript{} << OP_FALSE);
    auto psbt = MakeMinimalPSBT();
    psbt.tx->vin[0].prevout = COutPoint(previous.GetHash(), 0);
    psbt.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
    psbt.inputs[0].final_script_sig = CScript{} << OP_TRUE;
    const auto data = PrecomputePSBTData(psbt);
    BOOST_CHECK(PSBTInputSigned(psbt.inputs[0]));
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, &data, 0));
    BOOST_CHECK(SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbt, 0, &data, std::nullopt, nullptr, true, 0) == common::PSBTError::INCOMPLETE);
    BOOST_CHECK(!FinalizePSBT(psbt, 0));
    CMutableTransaction extracted;
    BOOST_CHECK(!FinalizeAndExtractPSBT(psbt, extracted, 0));
}

BOOST_AUTO_TEST_CASE(psbt_previous_output_consistency)
{
    CMutableTransaction previous;
    previous.vout.emplace_back(1000, CScript{} << OP_TRUE);
    auto full = MakeMinimalPSBT();
    full.tx->vin[0].prevout = COutPoint(previous.GetHash(), 0);
    full.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
    auto output = full;
    output.inputs[0].non_witness_utxo.reset();
    output.inputs[0].witness_utxo = previous.vout[0];
    for (bool change_script : {false, true}) {
        auto changed = output;
        if (change_script) changed.inputs[0].witness_utxo.scriptPubKey << OP_FALSE;
        else ++changed.inputs[0].witness_utxo.nValue;
        auto merged = full;
        BOOST_CHECK(!merged.Merge(changed));
        BOOST_CHECK(merged.inputs[0].witness_utxo.IsNull());
        merged = changed;
        BOOST_CHECK(!merged.Merge(full));
        BOOST_CHECK(!merged.inputs[0].non_witness_utxo);
        changed.inputs[0].non_witness_utxo = full.inputs[0].non_witness_utxo;
        CTxOut utxo;
        BOOST_CHECK(!changed.GetInputUTXO(utxo, 0));
        BOOST_CHECK(!PSBTInputSignedAndVerified(changed, 0, nullptr, 0));
        BOOST_CHECK(SignPSBTInput(DUMMY_SIGNING_PROVIDER, changed, 0, nullptr, std::nullopt) == common::PSBTError::UTXO_MISMATCH);
    }
    BOOST_CHECK(full.Merge(output));
    BOOST_CHECK(full.inputs[0].IsUTXOConsistent(full.tx->vin[0].prevout));
}

BOOST_AUTO_TEST_CASE(psbt_previous_transaction_removal)
{
    const auto make_psbt = [](int version, size_t program_size) {
        CMutableTransaction previous;
        previous.vout.emplace_back(1000, CScript{} << CScript::EncodeOP_N(version) << std::vector<unsigned char>(program_size, 1));
        auto psbt = MakeMinimalPSBT();
        psbt.tx->vin[0].prevout = COutPoint(previous.GetHash(), 0);
        psbt.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
        psbt.inputs[0].witness_utxo = previous.vout[0];
        return psbt;
    };
    constexpr unsigned flags{SCRIPT_VERIFY_WITNESS_V1_512};
    auto psbt = make_psbt(1, 64);
    RemoveUnnecessaryTransactions(psbt, 0);
    BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
    RemoveUnnecessaryTransactions(psbt, flags);
    BOOST_CHECK(!psbt.inputs[0].non_witness_utxo);
    for (int version : {0, 1, 2}) {
        psbt = make_psbt(version, 32);
        RemoveUnnecessaryTransactions(psbt, flags);
        BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
    }
    for (int mode : std::array<int, 3>{SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL | SIGHASH_ANYONECANPAY}) {
        psbt = make_psbt(1, 64);
        psbt.inputs[0].sighash_type = mode;
        RemoveUnnecessaryTransactions(psbt, flags);
        BOOST_CHECK(bool(psbt.inputs[0].non_witness_utxo) == bool(mode & SIGHASH_ANYONECANPAY));
    }
    psbt = make_psbt(1, 64);
    psbt.inputs[0].partial_sigs.emplace(CKeyID{}, SigPair{CPubKey{}, {SIGHASH_ALL | SIGHASH_ANYONECANPAY}});
    RemoveUnnecessaryTransactions(psbt, flags);
    BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
    psbt = make_psbt(1, 64);
    psbt.inputs[0].final_script_witness.stack = {{1}};
    RemoveUnnecessaryTransactions(psbt, flags);
    BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
    psbt = make_psbt(1, 64);
    ++psbt.inputs[0].witness_utxo.nValue;
    RemoveUnnecessaryTransactions(psbt, flags);
    BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
    psbt = make_psbt(1, 64);
    auto v0 = make_psbt(0, 32);
    psbt.tx->vin.push_back(v0.tx->vin[0]);
    psbt.inputs.push_back(v0.inputs[0]);
    RemoveUnnecessaryTransactions(psbt, flags);
    BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
    BOOST_CHECK(psbt.inputs[1].non_witness_utxo);
}

BOOST_AUTO_TEST_CASE(psbt_verified_input_bounds)
{
    auto psbt = MakeMinimalPSBT();
    // A valid index without UTXO data is incomplete, not an assertion failure.
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr, 0));
#ifndef WIN32
    // Keep fatal assertion cases in children, without producing core dumps.
    for (const bool empty : {false, true}) {
        if (empty) psbt.inputs.clear();
        const pid_t pid = fork();
        BOOST_REQUIRE(pid >= 0);
        if (pid == 0) {
            std::signal(SIGABRT, SIG_DFL); // Do not inherit Boost.Test's signal handler.
            const rlimit limit{0, 0};
            setrlimit(RLIMIT_CORE, &limit);
            PSBTInputSignedAndVerified(psbt, psbt.inputs.size(), nullptr, 0);
            _exit(0);
        }
        int status{0};
        BOOST_REQUIRE_EQUAL(waitpid(pid, &status, 0), pid);
        BOOST_REQUIRE(WIFSIGNALED(status));
        BOOST_CHECK_EQUAL(WTERMSIG(status), SIGABRT);
    }
#endif
}

BOOST_AUTO_TEST_CASE(pqhd_origin_conflicts_reject_before_merge)
{
    const auto key = MakeDummyTidePubKey(pq::SchemeId::FALCON_512);
    const auto path = MakePQHDPathForScheme(pq::SchemeId::FALCON_512);
    auto left = MakeMinimalPSBT();
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(left.outputs[0].m_proprietary, PSBT_OUT_PROPRIETARY, key, uint256::ONE, path));
    BOOST_CHECK(psbt::tidecoin::AddPQHDOrigin(left.outputs[0].m_proprietary, PSBT_OUT_PROPRIETARY, key, uint256::ONE, path));
    BOOST_CHECK(!psbt::tidecoin::AddPQHDOrigin(left.outputs[0].m_proprietary, PSBT_OUT_PROPRIETARY, key, uint256{}, path));
    auto right = MakeMinimalPSBT();
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(right.outputs[0].m_proprietary, PSBT_OUT_PROPRIETARY, key, uint256{}, path));
    right.inputs[0].witness_utxo = CTxOut(1, CScript{} << OP_TRUE);
    DataStream original;
    original << left;
    BOOST_CHECK(!left.Merge(right));
    DataStream after;
    after << left;
    BOOST_CHECK(std::ranges::equal(original, after));
    auto combined = left;
    BOOST_CHECK(!CombinePSBTs(combined, {left, right}));
    DataStream unchanged;
    unchanged << combined;
    BOOST_CHECK(std::ranges::equal(original, unchanged));
    auto same = left;
    BOOST_CHECK(left.Merge(same));
    auto malformed = MakeMinimalPSBT();
    auto entry = *same.outputs[0].m_proprietary.begin();
    entry.value.clear();
    malformed.outputs[0].m_proprietary.insert(entry);
    BOOST_CHECK(!left.Merge(malformed));
    BOOST_CHECK(!CombinePSBTs(combined, {malformed}));
}

BOOST_AUTO_TEST_CASE(pqhd_origin_roundtrip_input_and_output)
{
    auto psbtx = MakeMinimalPSBT();

    const auto pubkey_in = MakeDummyTidePubKey(pq::SchemeId::FALCON_512);
    const auto pubkey_out = MakeDummyTidePubKey(pq::SchemeId::MLDSA_65);
    const uint256 seed_id = uint256::ONE;

    const auto path_in = MakePQHDPathForScheme(pq::SchemeId::FALCON_512);
    const auto path_out = MakePQHDPathForScheme(pq::SchemeId::MLDSA_65);

    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbtx.inputs.at(0).m_proprietary, PSBT_IN_PROPRIETARY, pubkey_in, seed_id, path_in));
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbtx.outputs.at(0).m_proprietary, PSBT_OUT_PROPRIETARY, pubkey_out, seed_id, path_out));

    DataStream ds;
    ds << psbtx;

    PartiallySignedTransaction decoded;
    ds >> decoded;

    BOOST_CHECK(ds.empty());
    BOOST_CHECK_EQUAL(decoded.inputs.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.outputs.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.inputs.at(0).m_proprietary.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.outputs.at(0).m_proprietary.size(), 1U);

    const auto origin_in = psbt::tidecoin::DecodePQHDOrigin(*decoded.inputs.at(0).m_proprietary.begin());
    BOOST_REQUIRE(origin_in);
    BOOST_CHECK(origin_in->pubkey == pubkey_in);
    BOOST_CHECK(origin_in->seed_id == seed_id);
    BOOST_CHECK(origin_in->path_hardened == path_in);

    const auto origin_out = psbt::tidecoin::DecodePQHDOrigin(*decoded.outputs.at(0).m_proprietary.begin());
    BOOST_REQUIRE(origin_out);
    BOOST_CHECK(origin_out->pubkey == pubkey_out);
    BOOST_CHECK(origin_out->seed_id == seed_id);
    BOOST_CHECK(origin_out->path_hardened == path_out);
}

BOOST_AUTO_TEST_CASE(pqhd_origin_decode_rejects_wrong_identifier_or_subtype)
{
    PSBTProprietary entry;
    entry.identifier.assign({'n','o','t','t','i','d','e'});
    entry.subtype = psbt::tidecoin::SUBTYPE_PQHD_ORIGIN;
    entry.key = psbt::tidecoin::MakeProprietaryKey(PSBT_IN_PROPRIETARY,
                                                   std::span<const unsigned char>(entry.identifier.data(), entry.identifier.size()),
                                                   entry.subtype,
                                                   std::span<const unsigned char>());
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, std::span<const uint32_t>());
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    entry.identifier.assign(psbt::tidecoin::PROPRIETARY_IDENTIFIER.begin(), psbt::tidecoin::PROPRIETARY_IDENTIFIER.end());
    entry.subtype = psbt::tidecoin::SUBTYPE_PQHD_ORIGIN + 1;
    entry.key = psbt::tidecoin::MakeProprietaryKey(PSBT_IN_PROPRIETARY,
                                                   std::span<const unsigned char>(entry.identifier.data(), entry.identifier.size()),
                                                   entry.subtype,
                                                   std::span<const unsigned char>());
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, std::span<const uint32_t>());
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));
}

BOOST_AUTO_TEST_CASE(pqhd_origin_decode_rejects_malformed_values)
{
    const auto pubkey = MakeDummyTidePubKey(pq::SchemeId::FALCON_512);
    PSBTProprietary entry;
    entry.identifier.assign(psbt::tidecoin::PROPRIETARY_IDENTIFIER.begin(), psbt::tidecoin::PROPRIETARY_IDENTIFIER.end());
    entry.subtype = psbt::tidecoin::SUBTYPE_PQHD_ORIGIN;
    entry.key = psbt::tidecoin::MakeProprietaryKey(PSBT_IN_PROPRIETARY,
                                                   std::span<const unsigned char>(entry.identifier.data(), entry.identifier.size()),
                                                   entry.subtype,
                                                   std::span<const unsigned char>(pubkey.data(), pubkey.size()));

    // Too short to contain SeedID32.
    entry.value = {0x01, 0x02, 0x03};
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    // Non-hardened path elements should be rejected.
    const std::vector<uint32_t> non_hardened_path{0U, 1U, 2U};
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, non_hardened_path);
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    // Legacy short paths (3 elements) are rejected; PQHD v1 requires 6 elements.
    const std::vector<uint32_t> short_path{
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | static_cast<uint32_t>(static_cast<uint8_t>(pq::SchemeId::FALCON_512)),
    };
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, short_path);
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    // Wrong purpose should be rejected.
    auto bad_purpose_path = MakePQHDPathForScheme(pq::SchemeId::FALCON_512);
    bad_purpose_path[0] = HARDENED | (pqhd::PURPOSE + 1U);
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, bad_purpose_path);
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    // Wrong coin type should be rejected.
    auto bad_coin_path = MakePQHDPathForScheme(pq::SchemeId::FALCON_512);
    bad_coin_path[1] = HARDENED | (pqhd::COIN_TYPE + 1U);
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, bad_coin_path);
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    // change must be 0 or 1.
    auto bad_change_path = MakePQHDPathForScheme(pq::SchemeId::FALCON_512);
    bad_change_path[4] = HARDENED | 2U;
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, bad_change_path);
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    // Hardened path, but scheme mismatch between path[2] and pubkey prefix.
    const std::vector<uint32_t> mismatch_scheme_path{
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | 0x0AU, // ML-DSA-65
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 0U,
    };
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, mismatch_scheme_path);
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));
}

BOOST_AUTO_TEST_CASE(combine_psbt_preserves_proprietary_records)
{
    auto psbt_a = MakeMinimalPSBT();
    auto psbt_b = MakeMinimalPSBT();

    const uint256 seed_id_a = uint256::ONE;
    const uint256 seed_id_b{uint8_t{2}};

    const auto in_pubkey_a = MakeDummyTidePubKey(pq::SchemeId::FALCON_512);
    const auto in_pubkey_b = MakeDummyTidePubKey(pq::SchemeId::MLDSA_65);
    const auto out_pubkey_a = MakeDummyTidePubKey(pq::SchemeId::FALCON_1024);
    const auto out_pubkey_b = MakeDummyTidePubKey(pq::SchemeId::MLDSA_87);
    const auto in_path_a = MakePQHDPathForScheme(pq::SchemeId::FALCON_512);
    const auto in_path_b = MakePQHDPathForScheme(pq::SchemeId::MLDSA_65);
    const auto out_path_a = MakePQHDPathForScheme(pq::SchemeId::FALCON_1024);
    const auto out_path_b = MakePQHDPathForScheme(pq::SchemeId::MLDSA_87);

    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbt_a.inputs.at(0).m_proprietary, PSBT_IN_PROPRIETARY, in_pubkey_a, seed_id_a, in_path_a));
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbt_b.inputs.at(0).m_proprietary, PSBT_IN_PROPRIETARY, in_pubkey_b, seed_id_b, in_path_b));
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbt_a.outputs.at(0).m_proprietary, PSBT_OUT_PROPRIETARY, out_pubkey_a, seed_id_a, out_path_a));
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbt_b.outputs.at(0).m_proprietary, PSBT_OUT_PROPRIETARY, out_pubkey_b, seed_id_b, out_path_b));

    PSBTProprietary global_a;
    global_a.identifier.assign(psbt::tidecoin::PROPRIETARY_IDENTIFIER.begin(), psbt::tidecoin::PROPRIETARY_IDENTIFIER.end());
    global_a.subtype = 0xAA;
    const std::vector<unsigned char> global_a_keydata{0x01};
    global_a.key = psbt::tidecoin::MakeProprietaryKey(PSBT_GLOBAL_PROPRIETARY,
                                                      std::span<const unsigned char>(global_a.identifier.data(), global_a.identifier.size()),
                                                      global_a.subtype,
                                                      std::span<const unsigned char>(global_a_keydata.data(), global_a_keydata.size()));
    global_a.value = {0xA1};
    psbt_a.m_proprietary.insert(global_a);

    PSBTProprietary global_b;
    global_b.identifier.assign(psbt::tidecoin::PROPRIETARY_IDENTIFIER.begin(), psbt::tidecoin::PROPRIETARY_IDENTIFIER.end());
    global_b.subtype = 0xAB;
    const std::vector<unsigned char> global_b_keydata{0x02};
    global_b.key = psbt::tidecoin::MakeProprietaryKey(PSBT_GLOBAL_PROPRIETARY,
                                                      std::span<const unsigned char>(global_b.identifier.data(), global_b.identifier.size()),
                                                      global_b.subtype,
                                                      std::span<const unsigned char>(global_b_keydata.data(), global_b_keydata.size()));
    global_b.value = {0xB2};
    psbt_b.m_proprietary.insert(global_b);

    PartiallySignedTransaction combined;
    BOOST_REQUIRE(CombinePSBTs(combined, {psbt_a, psbt_b}));
    BOOST_CHECK_EQUAL(combined.m_proprietary.size(), 2U);
    BOOST_CHECK_EQUAL(combined.inputs.at(0).m_proprietary.size(), 2U);
    BOOST_CHECK_EQUAL(combined.outputs.at(0).m_proprietary.size(), 2U);

    std::set<uint256> input_seed_ids;
    for (const auto& entry : combined.inputs.at(0).m_proprietary) {
        const auto origin = psbt::tidecoin::DecodePQHDOrigin(entry);
        BOOST_REQUIRE(origin);
        input_seed_ids.insert(origin->seed_id);
    }
    BOOST_CHECK(input_seed_ids.contains(seed_id_a));
    BOOST_CHECK(input_seed_ids.contains(seed_id_b));

    std::set<uint256> output_seed_ids;
    for (const auto& entry : combined.outputs.at(0).m_proprietary) {
        const auto origin = psbt::tidecoin::DecodePQHDOrigin(entry);
        BOOST_REQUIRE(origin);
        output_seed_ids.insert(origin->seed_id);
    }
    BOOST_CHECK(output_seed_ids.contains(seed_id_a));
    BOOST_CHECK(output_seed_ids.contains(seed_id_b));
}

BOOST_AUTO_TEST_CASE(combine_psbt_deduplicates_identical_proprietary_records)
{
    auto psbt_a = MakeMinimalPSBT();
    auto psbt_b = MakeMinimalPSBT();

    const uint256 seed_id = uint256::ONE;
    const auto in_pubkey = MakeDummyTidePubKey(pq::SchemeId::FALCON_512);
    const auto out_pubkey = MakeDummyTidePubKey(pq::SchemeId::FALCON_1024);
    const auto in_path = MakePQHDPathForScheme(pq::SchemeId::FALCON_512);
    const auto out_path = MakePQHDPathForScheme(pq::SchemeId::FALCON_1024);

    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbt_a.inputs.at(0).m_proprietary, PSBT_IN_PROPRIETARY, in_pubkey, seed_id, in_path));
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbt_b.inputs.at(0).m_proprietary, PSBT_IN_PROPRIETARY, in_pubkey, seed_id, in_path));
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbt_a.outputs.at(0).m_proprietary, PSBT_OUT_PROPRIETARY, out_pubkey, seed_id, out_path));
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbt_b.outputs.at(0).m_proprietary, PSBT_OUT_PROPRIETARY, out_pubkey, seed_id, out_path));

    PSBTProprietary global_prop;
    global_prop.identifier.assign(psbt::tidecoin::PROPRIETARY_IDENTIFIER.begin(), psbt::tidecoin::PROPRIETARY_IDENTIFIER.end());
    global_prop.subtype = 0xAA;
    const std::vector<unsigned char> keydata{0x01};
    global_prop.key = psbt::tidecoin::MakeProprietaryKey(PSBT_GLOBAL_PROPRIETARY,
                                                         std::span<const unsigned char>(global_prop.identifier.data(), global_prop.identifier.size()),
                                                         global_prop.subtype,
                                                         std::span<const unsigned char>(keydata.data(), keydata.size()));
    global_prop.value = {0xA1};
    psbt_a.m_proprietary.insert(global_prop);
    psbt_b.m_proprietary.insert(global_prop);

    PartiallySignedTransaction combined;
    BOOST_REQUIRE(CombinePSBTs(combined, {psbt_a, psbt_b}));
    BOOST_CHECK_EQUAL(combined.m_proprietary.size(), 1U);
    BOOST_CHECK_EQUAL(combined.inputs.at(0).m_proprietary.size(), 1U);
    BOOST_CHECK_EQUAL(combined.outputs.at(0).m_proprietary.size(), 1U);
}

BOOST_FIXTURE_TEST_CASE(psbt_modes_and_cleanup, BasicTestingSetup)
{
    constexpr unsigned flags{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512 | SCRIPT_VERIFY_SHA512};
    for (auto scheme : {pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_1024, pq::SchemeId::MLDSA_44, pq::SchemeId::MLDSA_65, pq::SchemeId::MLDSA_87}) {
        CKey key;
        key.MakeNewKey(scheme);
        const auto pubkey = key.GetPubKey();
        FlatSigningProvider provider;
        provider.keys.emplace(pubkey.GetID(), key);
        const CScript script{CScript{} << ToByteVector(pubkey) << OP_CHECKSIG};
        for (bool wrapped : {false, true}) {
            const CScript program = GetScriptForDestination(WitnessV1ScriptHash512(script));
            CMutableTransaction previous;
            previous.vout.emplace_back(1000, wrapped ? GetScriptForDestination(ScriptHash(program)) : program);
            auto original = MakeMinimalPSBT();
            original.tx->vin[0].prevout = COutPoint(previous.GetHash(), 0);
            original.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
            original.inputs[0].witness_utxo = previous.vout[0];
            original.inputs[0].witness_script = script;
            if (wrapped) original.inputs[0].redeem_script = program;
            auto compact = original;
            RemoveUnnecessaryTransactions(compact, flags);
            BOOST_CHECK(!compact.inputs[0].non_witness_utxo);
            BOOST_CHECK(!compact.inputs[0].sighash_type);
            const auto compact_data = PrecomputePSBTData(compact);
            auto constrained = compact;
            constrained.inputs[0].sighash_type = SIGHASH_ALL;
            BOOST_CHECK(SignPSBTInput(provider, constrained, 0, &compact_data, 0x81, nullptr, false, flags) == PSBTError::SIGHASH_MISMATCH);
            BOOST_REQUIRE(SignPSBTInput(provider, compact, 0, &compact_data, 0x81, nullptr, false, flags) == PSBTError::OK);
            BOOST_CHECK(compact.inputs[0].sighash_type == 0x81);
            for (int mode : {1, 2, 3, 0x81, 0x82, 0x83}) {
                auto psbt = original;
                psbt.inputs[0].sighash_type = mode;
                const auto data = PrecomputePSBTData(psbt);
                auto analysis = node::AnalyzePSBT(psbt, flags);
                BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
                BOOST_CHECK(analysis.estimated_vsize);
                BOOST_CHECK(analysis.estimated_feerate);
                BOOST_CHECK(std::set<CKeyID>(analysis.inputs[0].missing_sigs.begin(), analysis.inputs[0].missing_sigs.end()).size() == 1U);
                BOOST_CHECK(analysis.fee == 999);
                auto unchanged = psbt;
                if (mode != SIGHASH_ALL) {
                    BOOST_CHECK(SignPSBTInput(provider, unchanged, 0, &data, std::nullopt, nullptr, false, flags) == PSBTError::SIGHASH_MISMATCH);
                    BOOST_CHECK(unchanged.inputs[0].partial_sigs.empty());
                }
                BOOST_REQUIRE(SignPSBTInput(provider, psbt, 0, &data, mode, nullptr, false, flags) == PSBTError::OK);
                BOOST_REQUIRE_EQUAL(psbt.inputs[0].partial_sigs.size(), 1U);
                BOOST_CHECK_EQUAL(psbt.inputs[0].partial_sigs.begin()->second.second.back(), mode);
                analysis = node::AnalyzePSBT(psbt, flags);
                BOOST_CHECK(analysis.next == PSBTRole::FINALIZER);
                BOOST_CHECK(analysis.estimated_vsize);
                auto unfinished = psbt;
                RemoveUnnecessaryTransactions(unfinished, flags);
                BOOST_CHECK(bool(unfinished.inputs[0].non_witness_utxo) == bool(mode & SIGHASH_ANYONECANPAY));
                BOOST_REQUIRE(FinalizePSBT(psbt, flags));
                psbt.inputs[0].sighash_type.reset();
                const auto witness = psbt.inputs[0].final_script_witness.stack;
                const auto script_sig = psbt.inputs[0].final_script_sig;
                analysis = node::AnalyzePSBT(psbt, flags);
                BOOST_CHECK(analysis.next == PSBTRole::EXTRACTOR);
                // The only UTXO record must be replaced atomically before removal.
                psbt.inputs[0].witness_utxo.SetNull();
                auto corrupt = psbt;
                corrupt.inputs[0].final_script_witness.stack[0][1] ^= 1;
                RemoveUnnecessaryTransactions(corrupt, flags);
                BOOST_CHECK(corrupt.inputs[0].non_witness_utxo);
                auto conflict = psbt;
                conflict.inputs[0].sighash_type = mode == 1 ? 2 : 1;
                RemoveUnnecessaryTransactions(conflict, flags);
                BOOST_CHECK(conflict.inputs[0].non_witness_utxo);
                if (wrapped) {
                    for (bool extra_push : {false, true}) {
                        auto malformed = psbt;
                        auto& script_sig = malformed.inputs[0].final_script_sig;
                        if (extra_push) script_sig << OP_0;
                        else script_sig.insert(script_sig.begin(), OP_PUSHDATA1);
                        RemoveUnnecessaryTransactions(malformed, flags);
                        BOOST_CHECK(malformed.inputs[0].non_witness_utxo);
                    }
                    auto missing_script = original;
                    missing_script.inputs[0].witness_script.clear();
                    RemoveUnnecessaryTransactions(missing_script, flags);
                    BOOST_CHECK(missing_script.inputs[0].non_witness_utxo);
                }
                RemoveUnnecessaryTransactions(psbt, flags);
                BOOST_CHECK(bool(psbt.inputs[0].non_witness_utxo) == bool(mode & SIGHASH_ANYONECANPAY));
                BOOST_CHECK(psbt.inputs[0].final_script_witness.stack == witness);
                BOOST_CHECK(psbt.inputs[0].final_script_sig == script_sig);
                BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &data, flags));
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(psbt_signing_refusals_and_declarations, BasicTestingSetup)
{
    constexpr unsigned flags{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512};
    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    const auto pubkey = key.GetPubKey();
    FlatSigningProvider provider;
    provider.keys.emplace(pubkey.GetID(), key);
    provider.pubkeys.emplace(pubkey.GetID(), pubkey);
    const CScript script{CScript{} << ToByteVector(pubkey) << OP_CHECKSIG};
    for (int kind : {0, 1, 2, 3}) {
        CMutableTransaction previous;
        const CScript output = kind == 0 ? script : kind == 1 ? GetScriptForDestination(ScriptHash(script)) :
            kind == 2 ? GetScriptForDestination(WitnessV0ScriptHash(script)) : GetScriptForDestination(WitnessV1ScriptHash512(script));
        previous.vout.emplace_back(1000, output);
        auto base = MakeMinimalPSBT();
        base.tx->vin[0].prevout = COutPoint(previous.GetHash(), 0);
        base.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
        if (kind == 1) base.inputs[0].redeem_script = script;
        if (kind >= 2) base.inputs[0].witness_script = script;
        for (int mode : {3, 0x83, 0x23, 0x43, 0x63, 0xa3}) {
            auto psbt = base;
            psbt.tx->vout.clear();
            psbt.outputs.clear();
            psbt.inputs[0].sighash_type = mode;
            const auto data = PrecomputePSBTData(psbt);
            MutableTransactionSignatureCreator creator(*psbt.tx, 0, -1, &data, mode, false);
            creator.SetAmountAvailability(false, false);
            SignatureData produced;
            if (kind == 1) produced.redeem_script = script;
            if (kind >= 2) produced.witness_script = script;
            BOOST_CHECK(!ProduceSignature(provider, creator, output, produced, flags));
            BOOST_CHECK(creator.Error() == PSBTError::SINGLE_WITHOUT_OUTPUT);
            BOOST_CHECK(produced.missing_sigs.empty());
            BOOST_CHECK(produced.signatures.empty());
            SignatureData missing;
            BOOST_CHECK(SignPSBTInput(provider, psbt, 0, &data, mode, &missing, false, flags) == PSBTError::SINGLE_WITHOUT_OUTPUT);
            BOOST_CHECK(psbt.inputs[0].partial_sigs.empty());
            BOOST_CHECK(missing.missing_sigs.empty());
            const auto analysis = node::AnalyzePSBT(psbt, flags);
            BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
            BOOST_CHECK(analysis.inputs[0].issue == PSBTError::SINGLE_WITHOUT_OUTPUT);
            BOOST_CHECK(analysis.next == PSBTRole::CREATOR);
            BOOST_CHECK(analysis.error.empty());
            BOOST_CHECK(analysis.fee == 1000);
            BOOST_CHECK(!analysis.estimated_vsize);
        }
        for (int mode : {0, -1, 0x101, 4, 7, 0x22, 0x41, 0x43}) {
            auto psbt = base;
            psbt.inputs[0].sighash_type = mode;
            const auto data = PrecomputePSBTData(psbt);
            BOOST_CHECK(SignPSBTInput(provider, psbt, 0, &data, mode, nullptr, false, flags) == PSBTError::SIGHASH_UNSUPPORTED);
            BOOST_CHECK(psbt.inputs[0].partial_sigs.empty());
            const auto analysis = node::AnalyzePSBT(psbt, flags);
            BOOST_CHECK(analysis.inputs[0].issue == PSBTError::SIGHASH_UNSUPPORTED);
            BOOST_CHECK(analysis.fee == 999);
            BOOST_CHECK(!analysis.estimated_vsize);
            if (kind < 3 && mode >= 0 && mode <= 255) {
                // Existing valid legacy/v0 finals keep their consensus meaning,
                // even when their byte cannot be requested for new signing.
                std::vector<unsigned char> signature;
                const auto version = kind == 2 ? SigVersion::WITNESS_V0 : SigVersion::BASE;
                BOOST_REQUIRE(key.Sign(SignatureHash(script, *psbt.tx, 0, mode, 1000, version, &data), signature, false, 0, false));
                signature.push_back(mode);
                if (kind == 2) psbt.inputs[0].final_script_witness.stack = {signature, ToByteVector(script)};
                else {
                    psbt.inputs[0].final_script_sig = CScript{} << signature;
                    if (kind == 1) psbt.inputs[0].final_script_sig << ToByteVector(script);
                }
                BOOST_REQUIRE(PSBTInputSignedAndVerified(psbt, 0, &data, flags));
                BOOST_CHECK(FinalizePSBT(psbt, flags));
                BOOST_CHECK(node::AnalyzePSBT(psbt, flags).next == PSBTRole::EXTRACTOR);
            }
        }
        auto partial = base;
        const auto data = PrecomputePSBTData(partial);
        BOOST_REQUIRE(SignPSBTInput(provider, partial, 0, &data, SIGHASH_NONE, nullptr, false, flags) == PSBTError::OK);
        partial.inputs[0].sighash_type = SIGHASH_ALL;
        BOOST_CHECK(!FinalizePSBT(partial, flags));
        BOOST_CHECK(node::AnalyzePSBT(partial, flags).inputs[0].issue == PSBTError::SIGHASH_MISMATCH);
        partial.inputs[0].sighash_type.reset();
        BOOST_CHECK(!FinalizePSBT(partial, flags));
        BOOST_CHECK(DeclarePSBTSighash(partial, SIGHASH_ALL) == PSBTError::SIGHASH_MISMATCH);
        BOOST_REQUIRE(DeclarePSBTSighash(partial, SIGHASH_NONE) == PSBTError::OK);
        BOOST_CHECK(FinalizePSBT(partial, flags));
    }
    auto left = MakeMinimalPSBT();
    auto right = left;
    right.inputs[0].sighash_type = SIGHASH_NONE;
    BOOST_REQUIRE(left.Merge(right));
    BOOST_CHECK(left.inputs[0].sighash_type == SIGHASH_NONE);
    right.inputs[0].sighash_type = SIGHASH_SINGLE;
    BOOST_CHECK(!left.Merge(right));
    BOOST_CHECK(left.inputs[0].sighash_type == SIGHASH_NONE);
    auto public_psbt = MakeMinimalPSBT(); // Declaration does not require a UTXO or key.
    BOOST_CHECK(DeclarePSBTSighash(public_psbt, SIGHASH_ALL) == PSBTError::OK);
    BOOST_CHECK(public_psbt.inputs[0].sighash_type == SIGHASH_ALL);
}

BOOST_FIXTURE_TEST_CASE(raw_signing_amount_presence, BasicTestingSetup)
{
    constexpr unsigned flags{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512};
    for (auto scheme : {pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_1024, pq::SchemeId::MLDSA_44, pq::SchemeId::MLDSA_65, pq::SchemeId::MLDSA_87}) {
        CKey key;
        key.MakeNewKey(scheme);
        const auto pubkey = key.GetPubKey();
        const CScript script = CScript{} << ToByteVector(pubkey) << OP_CHECKSIG;
        const CScript v1 = GetScriptForDestination(WitnessV1ScriptHash512{script});
        FlatSigningProvider provider;
        provider.keys.emplace(pubkey.GetID(), key);
        provider.pubkeys.emplace(pubkey.GetID(), pubkey);
        provider.scripts.emplace(CScriptID(script), script);
        provider.scripts.emplace(CScriptID(v1), v1);
        provider.scripts.emplace(CScriptID{RIPEMD160(WitnessV1ScriptHash512{script})}, script);
        const CScript foreign_script = CScript{} << OP_FALSE;
        const CScript foreign_v1 = GetScriptForDestination(WitnessV1ScriptHash512{foreign_script});
        provider.scripts.emplace(CScriptID(foreign_script), foreign_script);
        provider.scripts.emplace(CScriptID(foreign_v1), foreign_v1);
        provider.scripts.emplace(CScriptID{RIPEMD160(WitnessV1ScriptHash512{foreign_script})}, foreign_script);
        for (int kind : {0, 1, 2}) {
            const CScript own = kind == 0 ? GetScriptForDestination(WitnessV0ScriptHash{script}) : kind == 1 ? v1 : GetScriptForDestination(ScriptHash{v1});
            for (const CScript& foreign : {GetScriptForDestination(PKHash{}), foreign_script, GetScriptForDestination(WitnessV0ScriptHash{foreign_script}), foreign_v1, GetScriptForDestination(ScriptHash{foreign_v1})}) {
                CMutableTransaction base;
                base.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
                base.vin.emplace_back(Txid::FromUint256(uint256::ONE), 1);
                base.vout.assign(2, CTxOut{0, CScript{} << OP_TRUE});
                std::map<COutPoint, Coin> coins;
                coins.emplace(base.vin[0].prevout, Coin{CTxOut{1, own}, 1, false});
                coins.emplace(base.vin[1].prevout, Coin{CTxOut{0, foreign}, 1, false});
                for (int mode : {1, 2, 3, 0x81, 0x82, 0x83}) {
                    auto tx = base;
                    std::map<int, bilingual_str> errors;
                    const std::set<COutPoint> missing_foreign{base.vin[1].prevout};
                    SignTransaction(tx, &provider, coins, mode, errors, flags, &missing_foreign);
                    if (kind != 0 && !(mode & SIGHASH_ANYONECANPAY)) {
                        BOOST_CHECK(tx.vin[0].scriptWitness.IsNull());
                        BOOST_CHECK_EQUAL(errors.at(0).original, common::PSBTErrorString(PSBTError::MISSING_SPENT_AMOUNTS).original);
                    } else {
                        BOOST_CHECK(!tx.vin[0].scriptWitness.IsNull());
                        BOOST_CHECK(!errors.contains(0));
                    }
                    // A later keyless manager preserves the precise refusal.
                    FlatSigningProvider keyless = provider;
                    keyless.keys.clear();
                    const auto first_errors = errors;
                    SignTransaction(tx, &keyless, coins, mode, errors, flags, &missing_foreign);
                    if (first_errors.contains(0)) BOOST_CHECK_EQUAL(errors.at(0).original, first_errors.at(0).original);

                    tx = base;
                    errors.clear();
                    const std::set<COutPoint> missing_own{base.vin[0].prevout};
                    SignTransaction(tx, &provider, coins, mode, errors, flags, &missing_own);
                    BOOST_CHECK_EQUAL(errors.at(0).original, "Missing amount");
                    BOOST_CHECK(tx.vin[0].scriptWitness.IsNull());
                    SignTransaction(tx, &keyless, coins, mode, errors, flags, &missing_own);
                    BOOST_CHECK_EQUAL(errors.at(0).original, "Missing amount");
                }
                for (CAmount amount : {CAmount{0}, CAmount{1}, MAX_MONEY - 1, MAX_MONEY}) {
                    coins.at(base.vin[0].prevout).out.nValue = amount;
                    auto tx = base;
                    std::map<int, bilingual_str> errors;
                    SignTransaction(tx, &provider, coins, SIGHASH_ALL, errors, flags);
                    BOOST_CHECK(!errors.contains(0));
                    PrecomputedTransactionData data;
                    data.Init(tx, {coins.at(base.vin[0].prevout).out, coins.at(base.vin[1].prevout).out}, true);
                    BOOST_CHECK(VerifyScript(tx.vin[0].scriptSig, own, &tx.vin[0].scriptWitness, flags, MutableTransactionSignatureChecker{&tx, 0, amount, data, MissingDataBehavior::FAIL, false}));
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(single_without_output_predicate)
{
    for (int mode : {3, 0x23, 0x43, 0x63, 0x83, 0xa3}) {
        BOOST_CHECK(SingleWithoutOutput(mode, 1, 1));
        BOOST_CHECK(!SingleWithoutOutput(mode, 0, 1));
    }
    for (int mode : {7, 0x13}) BOOST_CHECK(!SingleWithoutOutput(mode, 1, 1));
}

BOOST_FIXTURE_TEST_CASE(psbt_cleanup_observes_execution_atomically, BasicTestingSetup)
{
    constexpr unsigned flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512};
    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    const auto pub = ToByteVector(key.GetPubKey());
    const auto make = [&](const CScript& script) {
        CMutableTransaction previous;
        previous.vout.emplace_back(1000, GetScriptForDestination(WitnessV1ScriptHash512(script)));
        auto psbt = MakeMinimalPSBT();
        psbt.tx->vin[0].prevout = COutPoint(previous.GetHash(), 0);
        psbt.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
        psbt.inputs[0].witness_utxo = previous.vout[0];
        psbt.inputs[0].witness_script = script;
        return psbt;
    };
    // Successful execution with no successful signature retains every record.
    for (const CScript& script : {CScript{} << OP_TRUE, CScript{} << pub << OP_CHECKSIG << OP_NOT, CScript{} << pub << OP_CHECKSIG << OP_DROP << OP_TRUE}) {
        for (bool empty : {false, true}) {
            auto psbt = make(script);
            const auto data = PrecomputePSBTData(psbt);
            if (script.size() > 1) psbt.inputs[0].final_script_witness.stack.push_back(empty ? std::vector<unsigned char>{} : std::vector<unsigned char>{1});
            psbt.inputs[0].final_script_witness.stack.push_back(ToByteVector(script));
            BOOST_REQUIRE(PSBTInputSignedAndVerified(psbt, 0, &data, flags));
            DataStream before;
            before << psbt;
            RemoveUnnecessaryTransactions(psbt, flags);
            DataStream after;
            after << psbt;
            BOOST_CHECK(before.str() == after.str());
            BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &data, flags));
        }
    }
    {
        const CScript dropped_script = CScript{} << pub << OP_CHECKSIG << OP_DROP << OP_TRUE;
        auto dropped = make(dropped_script);
        const auto data = PrecomputePSBTData(dropped);
        uint512 digest;
        BOOST_REQUIRE(SignatureHash512(digest, dropped_script, *dropped.tx, 0, SIGHASH_ALL, 1000, &data));
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign512(digest, sig, false));
        sig.push_back(SIGHASH_ALL);
        dropped.inputs[0].final_script_witness.stack = {sig, ToByteVector(dropped_script)};
        BOOST_REQUIRE(PSBTInputSignedAndVerified(dropped, 0, &data, flags));
        const auto witness = dropped.inputs[0].final_script_witness.stack;
        RemoveUnnecessaryTransactions(dropped, flags);
        BOOST_CHECK(!dropped.inputs[0].non_witness_utxo);
        BOOST_CHECK(dropped.inputs[0].final_script_witness.stack == witness);
        BOOST_CHECK(PSBTInputSignedAndVerified(dropped, 0, &data, flags));
    }
    // Unexecuted signature-shaped data does not count as an executed mode.
    const CScript script{CScript{} << OP_0 << OP_IF << std::vector<unsigned char>{1, 0x81} << OP_DROP << OP_ENDIF << pub << OP_CHECKSIG};
    auto psbt = make(script);
    auto data = PrecomputePSBTData(psbt);
    uint512 hash;
    BOOST_REQUIRE(SignatureHash512(hash, script, *psbt.tx, 0, SIGHASH_ALL, 1000, &data));
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign512(hash, signature, false));
    signature.push_back(SIGHASH_ALL);
    psbt.inputs[0].final_script_witness.stack = {signature, ToByteVector(script)};
    BOOST_REQUIRE(PSBTInputSignedAndVerified(psbt, 0, &data, flags));
    auto eligible = psbt;
    RemoveUnnecessaryTransactions(eligible, flags);
    BOOST_CHECK(!eligible.inputs[0].non_witness_utxo);
    BOOST_CHECK(PSBTInputSignedAndVerified(eligible, 0, &data, flags));
    // Differing eligible modes and an unsuccessful intermediate key pairing
    // still qualify when real multisig execution verifies both signatures.
    CKey middle, last;
    middle.MakeNewKey(pq::SchemeId::FALCON_512);
    last.MakeNewKey(pq::SchemeId::FALCON_512);
    const CScript multisig = CScript{} << OP_2 << pub << ToByteVector(middle.GetPubKey()) << ToByteVector(last.GetPubKey()) << OP_3 << OP_CHECKMULTISIG;
    for (int second_mode : std::array<int, 3>{SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL | SIGHASH_ANYONECANPAY}) {
        auto multi = make(multisig);
        const auto multi_data = PrecomputePSBTData(multi);
        std::vector<unsigned char> first_sig, last_sig;
        BOOST_REQUIRE(SignatureHash512(hash, multisig, *multi.tx, 0, SIGHASH_ALL, 1000, &multi_data));
        BOOST_REQUIRE(key.Sign512(hash, first_sig, false));
        first_sig.push_back(SIGHASH_ALL);
        BOOST_REQUIRE(SignatureHash512(hash, multisig, *multi.tx, 0, second_mode, 1000, &multi_data));
        BOOST_REQUIRE(last.Sign512(hash, last_sig, false));
        last_sig.push_back(second_mode);
        multi.inputs[0].final_script_witness.stack = {{}, first_sig, last_sig, ToByteVector(multisig)};
        BOOST_REQUIRE(PSBTInputSignedAndVerified(multi, 0, &multi_data, flags));
        RemoveUnnecessaryTransactions(multi, flags);
        BOOST_CHECK(bool(multi.inputs[0].non_witness_utxo) == bool(second_mode & SIGHASH_ANYONECANPAY));
        BOOST_CHECK(PSBTInputSignedAndVerified(multi, 0, &multi_data, flags));
    }
    for (int excluded : {-1, 0, 1, 2, 3}) {
        auto mixed = psbt;
        // Combine a verified final with an unfinished input. One excluded
        // input must retain all records; the eligible control removes both.
        auto extra = make(CScript{} << OP_TRUE);
        mixed.tx->vin.push_back(extra.tx->vin[0]);
        mixed.inputs.push_back(extra.inputs[0]);
        const auto mixed_data = PrecomputePSBTData(mixed);
        BOOST_REQUIRE(SignatureHash512(hash, script, *mixed.tx, 0, SIGHASH_ALL, 1000, &mixed_data));
        BOOST_REQUIRE(key.Sign512(hash, signature, false));
        signature.push_back(SIGHASH_ALL);
        mixed.inputs[0].final_script_witness.stack[0] = signature;
        BOOST_REQUIRE(PSBTInputSignedAndVerified(mixed, 0, &mixed_data, flags));
        if (excluded == 0) mixed.inputs[1].sighash_type = 0x81;
        if (excluded == 1) mixed.inputs[1].witness_utxo.nValue++;
        if (excluded == 2) mixed.inputs[1].witness_utxo.SetNull();
        if (excluded == 3) mixed.inputs[1].partial_sigs.emplace(CKeyID{}, SigPair{CPubKey{}, {}});
        RemoveUnnecessaryTransactions(mixed, flags);
        BOOST_CHECK(bool(mixed.inputs[0].non_witness_utxo) == (excluded >= 0));
        BOOST_CHECK(bool(mixed.inputs[1].non_witness_utxo) == (excluded >= 0));
    }
    // A valid SINGLE partial made under legacy rules is not newly finalized.
    CMutableTransaction previous;
    const CScript legacy{CScript{} << pub << OP_CHECKSIG};
    previous.vout.emplace_back(1000, legacy);
    auto single = MakeMinimalPSBT();
    single.tx->vout.clear();
    single.outputs.clear();
    single.tx->vin[0].prevout = COutPoint(previous.GetHash(), 0);
    single.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
    BOOST_REQUIRE(key.Sign(uint256::ONE, signature, false, 0, false));
    signature.push_back(SIGHASH_SINGLE);
    single.inputs[0].sighash_type = SIGHASH_SINGLE;
    single.inputs[0].partial_sigs.emplace(key.GetPubKey().GetID(), SigPair{key.GetPubKey(), signature});
    BOOST_CHECK(!FinalizePSBT(single, flags));
    BOOST_CHECK(node::AnalyzePSBT(single, flags).inputs[0].issue == PSBTError::SINGLE_WITHOUT_OUTPUT);
    single.inputs[0].final_script_sig = CScript{} << signature;
    single.inputs[0].partial_sigs.clear();
    data = PrecomputePSBTData(single);
    for (unsigned verify_flags : {flags, flags & ~(SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512)}) {
        BOOST_CHECK(PSBTInputSignedAndVerified(single, 0, &data, verify_flags));
    }
    const auto analysis = node::AnalyzePSBT(single, flags);
    BOOST_CHECK(analysis.inputs[0].is_final);
    BOOST_CHECK(analysis.inputs[0].issue == PSBTError::SINGLE_WITHOUT_OUTPUT);
}

BOOST_FIXTURE_TEST_CASE(psbt_legacy_v0_state_modes_and_maximum, BasicTestingSetup)
{
    constexpr unsigned flags{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512};
    for (auto scheme : {pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_1024, pq::SchemeId::MLDSA_44, pq::SchemeId::MLDSA_65, pq::SchemeId::MLDSA_87}) {
        CKey first, second;
        first.MakeNewKey(scheme);
        second.MakeNewKey(scheme);
        FlatSigningProvider provider, other;
        provider.keys.emplace(first.GetPubKey().GetID(), first);
        other.keys.emplace(second.GetPubKey().GetID(), second);
        const CScript script = CScript{} << OP_2 << ToByteVector(first.GetPubKey()) << ToByteVector(second.GetPubKey()) << OP_2 << OP_CHECKMULTISIG;
        for (int version : {0, 1, 2}) {
            CMutableTransaction previous;
            previous.vout.emplace_back(MAX_MONEY, version == 0 ? script : version == 1 ? GetScriptForDestination(WitnessV0ScriptHash(script)) : GetScriptForDestination(WitnessV1ScriptHash512(script)));
            auto base = MakeMinimalPSBT();
            base.tx->vin[0].prevout = COutPoint(previous.GetHash(), 0);
            base.tx->vout[0].nValue = MAX_MONEY - 1;
            base.inputs[0].non_witness_utxo = MakeTransactionRef(previous);
            if (version) base.inputs[0].witness_script = script;
            const auto data = PrecomputePSBTData(base);
            for (int mode : {1, 2, 3, 0x81, 0x82, 0x83}) {
                auto psbt = base;
                psbt.inputs[0].sighash_type = mode;
                auto analysis = node::AnalyzePSBT(psbt, flags);
                BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
                BOOST_CHECK_EQUAL(analysis.inputs[0].missing_sigs.size(), 2U);
                BOOST_CHECK(analysis.fee == 1);
                BOOST_CHECK(analysis.estimated_vsize && analysis.estimated_feerate);
                BOOST_CHECK(SignPSBTInput(provider, psbt, 0, &data, mode, nullptr, false, flags) == PSBTError::INCOMPLETE);
                analysis = node::AnalyzePSBT(psbt, flags);
                BOOST_CHECK(analysis.next == PSBTRole::SIGNER);
                BOOST_CHECK(std::set<CKeyID>(analysis.inputs[0].missing_sigs.begin(), analysis.inputs[0].missing_sigs.end()).size() == 1U);
                if (mode == SIGHASH_ALL) {
                    for (int unsupported : {0, -1, 0x101, 4, 0x22, 0x41, 0x43}) {
                        auto refused = psbt;
                        refused.inputs[0].sighash_type = unsupported;
                        const auto signatures = refused.inputs[0].partial_sigs;
                        BOOST_CHECK(SignPSBTInput(other, refused, 0, &data, unsupported, nullptr, false, flags) == PSBTError::SIGHASH_UNSUPPORTED);
                        BOOST_CHECK(refused.inputs[0].partial_sigs == signatures);
                        BOOST_CHECK(!PSBTInputSigned(refused.inputs[0]));
                    }
                }
                BOOST_REQUIRE(SignPSBTInput(other, psbt, 0, &data, mode, nullptr, false, flags) == PSBTError::OK);
                BOOST_CHECK(node::AnalyzePSBT(psbt, flags).next == PSBTRole::FINALIZER);
                BOOST_REQUIRE(FinalizePSBT(psbt, flags));
                BOOST_CHECK(node::AnalyzePSBT(psbt, flags).next == PSBTRole::EXTRACTOR);
                BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &data, flags));
                if (mode == SIGHASH_ALL) {
                    for (int unused : {0, -1, 0x101, 4, 0x22, 0x41, 0x43}) {
                        auto final = psbt;
                        final.inputs[0].sighash_type = unused;
                        BOOST_CHECK(FinalizePSBT(final, flags));
                        BOOST_CHECK(node::AnalyzePSBT(final, flags).next == PSBTRole::EXTRACTOR);
                    }
                }
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(psbt_cleanup_metadata_and_wrappers, BasicTestingSetup)
{
    constexpr unsigned flags{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512};
    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    const CScript script = CScript{} << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
    const CScript program = GetScriptForDestination(WitnessV1ScriptHash512(script));
    CMutableTransaction previous;
    previous.vout = {CTxOut(1000, program), CTxOut(1000, GetScriptForDestination(ScriptHash(program)))};
    CMutableTransaction tx;
    tx.vin.emplace_back(previous.GetHash(), 0);
    tx.vin.emplace_back(previous.GetHash(), 1);
    tx.vout.assign(2, CTxOut(999, CScript{} << OP_TRUE));
    PartiallySignedTransaction base(tx);
    for (int i = 0; i < 2; ++i) {
        base.inputs[i].non_witness_utxo = MakeTransactionRef(previous);
        base.inputs[i].witness_utxo = previous.vout[i];
        base.inputs[i].witness_script = script;
        base.inputs[i].unknown[{0xaa}] = {1, 2, 3};
    }
    base.inputs[1].redeem_script = program;
    base.inputs[0].sighash_type = SIGHASH_NONE;
    base.inputs[1].sighash_type = SIGHASH_SINGLE;
    const auto bytes = [](const auto& value) { DataStream stream; stream << value; return std::vector<std::byte>(stream.begin(), stream.end()); };
    for (const auto& excluded_script : {script, GetScriptForDestination(WitnessV0ScriptHash(script)), CScript{} << OP_2 << std::vector<unsigned char>(32, 1)}) {
        auto mixed = base;
        CMutableTransaction different = previous;
        different.vout[1].scriptPubKey = excluded_script;
        mixed.inputs[1].non_witness_utxo = MakeTransactionRef(different);
        mixed.inputs[1].witness_utxo = different.vout[1];
        mixed.inputs[1].redeem_script.clear();
        mixed.inputs[1].witness_script.clear();
        mixed.tx->vin[1].prevout.hash = different.GetHash();
        const auto data = PrecomputePSBTData(mixed);
        BOOST_REQUIRE(SignPSBTInput(provider, mixed, 0, &data, SIGHASH_NONE, nullptr, true, flags) == PSBTError::OK);
        BOOST_REQUIRE(PSBTInputSignedAndVerified(mixed, 0, &data, flags));
        const auto before = bytes(mixed);
        RemoveUnnecessaryTransactions(mixed, flags);
        BOOST_CHECK(bytes(mixed) == before);
    }
    {
        auto unknown = base;
        CMutableTransaction different = previous;
        different.vout[1].scriptPubKey = CScript{} << OP_2 << std::vector<unsigned char>(32, 1);
        unknown.inputs[1] = PSBTInput{};
        unknown.inputs[1].non_witness_utxo = MakeTransactionRef(different);
        unknown.inputs[1].witness_utxo = different.vout[1];
        unknown.inputs[1].final_script_witness.stack = {{OP_TRUE}};
        unknown.tx->vin[1].prevout.hash = different.GetHash();
        const auto data = PrecomputePSBTData(unknown);
        const unsigned unknown_flags = flags & ~SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
        BOOST_REQUIRE(SignPSBTInput(provider, unknown, 0, &data, SIGHASH_NONE, nullptr, true, unknown_flags) == PSBTError::OK);
        BOOST_REQUIRE(PSBTInputSignedAndVerified(unknown, 0, &data, unknown_flags));
        BOOST_REQUIRE(PSBTInputSignedAndVerified(unknown, 1, &data, unknown_flags));
        const auto before = bytes(unknown);
        RemoveUnnecessaryTransactions(unknown, unknown_flags);
        BOOST_CHECK(bytes(unknown) == before);
    }
    for (bool finalized : {false, true}) {
        auto eligible = base;
        if (finalized) {
            const auto data = PrecomputePSBTData(eligible);
            BOOST_REQUIRE(SignPSBTInput(provider, eligible, 0, &data, SIGHASH_NONE, nullptr, true, flags) == PSBTError::OK);
            BOOST_REQUIRE(SignPSBTInput(provider, eligible, 1, &data, SIGHASH_SINGLE, nullptr, true, flags) == PSBTError::OK);
        }
        for (int excluded = 0; excluded < 12; ++excluded) {
            auto test = eligible;
            unsigned test_flags = flags;
            if (excluded < 3) test.inputs[1].sighash_type = std::array<int, 3>{0, 4, 0x101}[excluded];
            if (excluded == 3) test.inputs[1].witness_utxo.nValue++;
            if (excluded == 4) test.inputs[1].sighash_type = 0x81;
            if (excluded == 5) {
                if (finalized) test.inputs[1].final_script_witness.stack.back() = {OP_FALSE};
                else test.inputs[1].witness_script = CScript{} << OP_FALSE;
            }
            if (excluded == 6) {
                const auto wrong_program = GetScriptForDestination(WitnessV0ScriptHash(script));
                if (finalized) test.inputs[1].final_script_sig = CScript{} << ToByteVector(wrong_program);
                else test.inputs[1].redeem_script = wrong_program;
            }
            if (excluded == 7) {
                test.inputs[1].redeem_script.clear();
                if (finalized) test.inputs[1].final_script_sig.clear();
            }
            if (excluded == 8) test_flags &= ~SCRIPT_VERIFY_WITNESS_V1_512;
            if (excluded == 9 || excluded == 10) {
                CMutableTransaction wrong = previous;
                wrong.vout[1].scriptPubKey = excluded == 9 ? GetScriptForDestination(ScriptHash(CScript{} << OP_TRUE)) : GetScriptForDestination(WitnessV0ScriptHash(program));
                test.inputs[1].non_witness_utxo = MakeTransactionRef(wrong);
                test.inputs[1].witness_utxo = wrong.vout[1];
                test.tx->vin[1].prevout.hash = wrong.GetHash();
                if (finalized) {
                    // The changed outpoint is committed by input 0 as well.
                    // Restore its valid final before testing input 1's wrapper.
                    test.inputs[0] = base.inputs[0];
                    const auto data = PrecomputePSBTData(test);
                    BOOST_REQUIRE(SignPSBTInput(provider, test, 0, &data, SIGHASH_NONE, nullptr, true, flags) == PSBTError::OK);
                    BOOST_REQUIRE(PSBTInputSignedAndVerified(test, 0, &data, flags));
                    const MutableTransactionSignatureChecker checker{&*test.tx, 1, wrong.vout[1].nValue, data, MissingDataBehavior::FAIL, false};
                    ScriptError error{SCRIPT_ERR_OK};
                    BOOST_REQUIRE(!VerifyScript(test.inputs[1].final_script_sig, wrong.vout[1].scriptPubKey, &test.inputs[1].final_script_witness, flags, checker, &error));
                    BOOST_CHECK_EQUAL(error, excluded == 9 ? SCRIPT_ERR_EVAL_FALSE : SCRIPT_ERR_WITNESS_MALLEATED);
                }
            }
            if (excluded == 11) {
                test.inputs[1].witness_utxo.SetNull();
                test.inputs[1].non_witness_utxo.reset();
            }
            const auto before = bytes(test);
            RemoveUnnecessaryTransactions(test, test_flags);
            BOOST_CHECK(bytes(test) == before);
        }
        RemoveUnnecessaryTransactions(eligible, flags);
        BOOST_CHECK(!eligible.inputs[0].non_witness_utxo && !eligible.inputs[1].non_witness_utxo);
    }
}

BOOST_AUTO_TEST_SUITE_END()
