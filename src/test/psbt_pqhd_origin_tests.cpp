#include <pq/pq_scheme.h>
#include <pq/pqhd_params.h>

#include <psbt.h>

#include <uint256.h>

#include <boost/test/unit_test.hpp>

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

BOOST_AUTO_TEST_SUITE_END()
