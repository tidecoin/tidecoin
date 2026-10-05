// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <tidecoin-build-config.h> // IWYU pragma: keep

#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <wallet/walletdb.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/sqlite.h>
#ifdef ENABLE_EXTERNAL_SIGNER
#include <test/util/run_command.h>
#endif
#include <key.h>
#include <pq/pqhd_kdf.h>
#include <pq/pq_scheme.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <fstream>

namespace wallet {

BOOST_AUTO_TEST_SUITE(walletload_tests)

class DummyDescriptor final : public Descriptor {
private:
    std::string desc;
public:
    explicit DummyDescriptor(const std::string& descriptor) : desc(descriptor) {};
    ~DummyDescriptor() = default;

    std::string ToString(bool compat_format) const override { return desc; }
    std::optional<OutputType> GetOutputType() const override { return OutputType::UNKNOWN; }

    bool IsRange() const override { return false; }
    bool IsSolvable() const override { return false; }
    bool IsSingleType() const override { return true; }
    bool ToPrivateString(const SigningProvider& provider, std::string& out) const override { return false; }
    bool ToNormalizedString(const SigningProvider& provider, std::string& out, const DescriptorCache* cache = nullptr) const override { return false; }
    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const override { return false; };
    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const override { return false; }
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override {}
    std::optional<int64_t> ScriptSize() const override { return {}; }
    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }
    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }
    void GetPubKeys(std::set<CPubKey>& pubkeys) const override {}
    std::optional<uint8_t> GetPQHDSchemePrefix() const override { return std::nullopt; }
    std::optional<PQHDKeyPathInfo> GetPQHDKeyPathInfo() const override { return std::nullopt; }
    std::set<uint256> GetPQHDSeedIDs() const override { return {}; }
    std::map<uint32_t, PQHDKeyPathInfo> GetPQHDKeyPaths() const override { return {}; }
};

BOOST_FIXTURE_TEST_CASE(wallet_load_unknown_descriptor, TestingSetup)
{
    auto database{CreateMockableWalletDatabase()};
    {
        WalletBatch batch(*database);
        BOOST_REQUIRE(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS));
        // Use a valid checksum so parsing fails on the unknown function, not
        // on an unrelated missing or incorrect checksum.
        const std::string unknown_desc{"unknown(00)"};
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(unknown_desc + "#" + GetDescriptorChecksum(unknown_desc)), 0, 0, 0, 0);
        BOOST_REQUIRE(batch.WriteDescriptor(uint256::ZERO, wallet_descriptor));
        // Preserve UNKNOWN_DESCRIPTOR even when an active binding references
        // the unrecognized descriptor, which cannot create a manager.
        BOOST_REQUIRE(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::UNKNOWN), uint256::ZERO, false));
    }

    CWallet wallet(m_node.chain.get(), "", std::move(database));
    ASSERT_DEBUG_LOG("is not a valid descriptor function");
    BOOST_CHECK_EQUAL(wallet.LoadWallet(), DBErrors::UNKNOWN_DESCRIPTOR);
    BOOST_CHECK(wallet.GetAllScriptPubKeyMans().empty());
}

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptor_id_mismatch, TestingSetup)
{
    // Construct a real, parseable Tidecoin descriptor; a dummy descriptor with
    // stale syntax/checksum could fail before the ID check we intend to test.
    const CKey key{GenerateRandomKey(pq::SchemeId::FALCON_512)};
    FlatSigningProvider provider;
    std::string error;
    auto descriptors{Parse("wpkh(" + HexStr(key.GetPubKey()) + ")", provider, error, /*require_checksum=*/false)};
    BOOST_REQUIRE_EQUAL(descriptors.size(), 1U);
    const WalletDescriptor descriptor{std::move(descriptors.front()), 0, 0, 1, 0};
    uint256 wrong_id{descriptor.id};
    wrong_id.begin()[0] ^= 1;
    BOOST_REQUIRE(wrong_id != descriptor.id);

    // Only the database key differs. The correct-ID control must load, so a
    // generic parsing/corruption error cannot satisfy the rejection test.
    for (const bool correct_id : {false, true}) {
        auto database{CreateMockableWalletDatabase()};
        {
            WalletBatch batch(*database);
            BOOST_REQUIRE(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS));
            BOOST_REQUIRE(batch.WriteDescriptor(correct_id ? descriptor.id : wrong_id, descriptor));
        }
        CWallet wallet(m_node.chain.get(), "", std::move(database));
        if (correct_id) {
            BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
            BOOST_CHECK_EQUAL(wallet.GetAllScriptPubKeyMans().size(), 1U);
            const auto* manager{wallet.GetScriptPubKeyMan(descriptor.id)};
            BOOST_REQUIRE(manager);
            BOOST_CHECK(manager->GetID() == descriptor.id);
        } else {
            ASSERT_DEBUG_LOG("The descriptor ID calculated by the wallet differs from the one in DB");
            BOOST_CHECK_EQUAL(wallet.LoadWallet(), DBErrors::CORRUPT);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_load_legacy_keys, TestingSetup)
{
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    WalletBatch batch(*database);

    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    const CPubKey pubkey = key.GetPubKey();
    const CPrivKey privkey = key.GetPrivKey();
    CKeyMetadata meta;
    meta.nCreateTime = 1;

    BOOST_CHECK(batch.WriteKey(pubkey, privkey, meta));

    const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::LOAD_OK);
    LegacyDataSPKM* legacy = wallet->GetLegacyDataSPKM();
    BOOST_REQUIRE(legacy != nullptr);
    BOOST_CHECK(legacy->HaveKey(pubkey.GetID()));
}

BOOST_FIXTURE_TEST_CASE(wallet_load_rejects_plaintext_pqhd_seed_in_encrypted_wallet, TestingSetup)
{
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        WalletBatch batch(*database);
        BOOST_CHECK(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS));

        CMasterKey master_key;
        BOOST_CHECK(batch.WriteMasterKey(/*nID=*/1, master_key));

        PQHDSeed seed;
        seed.nCreateTime = 1;
        seed.seed.assign(32, 0x11);
        BOOST_CHECK(batch.WritePQHDSeed(uint256::ONE, seed));
    }

    const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::CORRUPT);
}

BOOST_FIXTURE_TEST_CASE(wallet_load_rejects_crypted_pqhd_seed_in_unencrypted_wallet, TestingSetup)
{
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        WalletBatch batch(*database);
        BOOST_CHECK(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS));

        PQHDCryptedSeed seed;
        seed.nCreateTime = 1;
        seed.crypted_seed.assign(64, 0x22);
        BOOST_CHECK(batch.WriteCryptedPQHDSeed(uint256::ONE, seed));
    }

    const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::CORRUPT);
}

BOOST_FIXTURE_TEST_CASE(wallet_load_rejects_pqhd_seed_id_mismatch, TestingSetup)
{
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        WalletBatch batch(*database);
        BOOST_CHECK(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS));

        PQHDSeed seed;
        seed.nCreateTime = 1;
        seed.seed.assign(32, 0x11);
        BOOST_CHECK(batch.WritePQHDSeed(uint256::ONE, seed));
    }

    const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::CORRUPT);
}

BOOST_FIXTURE_TEST_CASE(wallet_load_rejects_pqhd_policy_seed_mismatch, TestingSetup)
{
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        WalletBatch batch(*database);
        BOOST_CHECK(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS));

        PQHDPolicy policy;
        policy.default_receive_scheme = static_cast<uint8_t>(pq::SchemeId::FALCON_512);
        policy.default_change_scheme = static_cast<uint8_t>(pq::SchemeId::FALCON_512);
        policy.default_seed_id = uint256::ONE;
        policy.default_change_seed_id = uint256::ONE;
        BOOST_CHECK(batch.WritePQHDPolicy(policy));
    }

    const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::CORRUPT);
}

// Reconciliation rollback and recovery are tested against real SQLite databases
// in wallet_persistence_tests.

#ifdef ENABLE_EXTERNAL_SIGNER
BOOST_FIXTURE_TEST_CASE(wallet_external_signer_imports_all_output_types, TestingSetup)
{
    const auto executable{test::CopyMockProcess(m_args.GetDataDirBase() / "signer with spaces")};
    const auto responses_path{m_args.GetDataDirBase() / fs::PathFromString("signer r\xc3\xa9ponses \xe6\x96\x87.json")};
    UniValue descriptors{UniValue::VOBJ};
    for (const auto* branch : {"receive", "internal"}) {
        const CKey key{GenerateRandomKey(pq::SchemeId::FALCON_512)};
        const std::string pubkey{HexStr(key.GetPubKey())};
        UniValue values{UniValue::VARR};
        // combo() is one descriptor with no single output type, not a list of
        // active descriptors. Each side needs distinct, explicit descriptors.
        values.push_back("pkh(" + pubkey + ")");
        values.push_back("sh(wpkh(" + pubkey + "))");
        values.push_back("wpkh(" + pubkey + ")");
        descriptors.pushKV(branch, values);
    }
    UniValue signer{UniValue::VOBJ};
    signer.pushKV("fingerprint", "00000001");
    signer.pushKV("model", "mock");
    UniValue signers{UniValue::VARR};
    signers.push_back(signer);
    UniValue responses{UniValue::VOBJ};
    responses.pushKV("enumerate", signers);
    responses.pushKV("getdescriptors", descriptors);
    {
        std::ofstream file{responses_path};
        BOOST_REQUIRE(file.good());
        file << responses.write();
        BOOST_REQUIRE(file.good());
    }
    const std::string command{test::QuoteCommandArgument(fs::PathToString(executable)) + " signer " +
                              test::QuoteCommandArgument(fs::PathToString(responses_path))};
    // BasicTestingSetup owns and resets the argument managers at teardown.
    m_args.ForceSetArg("-signer", command);
    gArgs.ForceSetArg("-signer", command);
    const auto path{m_args.GetDataDirBase() / "signer-wallet"};
    auto open_wallet = [&] {
        auto wallet{std::make_unique<CWallet>(m_node.chain.get(), "", std::make_unique<SQLiteDatabase>(path, path / "wallet.dat", DatabaseOptions{}))};
        wallet->m_keypool_size = 1;
        BOOST_REQUIRE(wallet->LoadWallet() == DBErrors::LOAD_OK);
        return wallet;
    };
    auto wallet{open_wallet()};
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_EXTERNAL_SIGNER);
        wallet->SetupDescriptorScriptPubKeyMans();
    }
    const CKey additional_key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse("wpkh(" + HexStr(additional_key.GetPubKey()) + ")", provider, error, false);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    WalletDescriptor additional{std::move(parsed[0]), 1, 0, 1, 0};
    {
        LOCK(wallet->cs_wallet);
        auto imported = wallet->AddWalletDescriptor(additional, provider, "", false);
        BOOST_REQUIRE(imported);
        BOOST_CHECK(dynamic_cast<ExternalSignerScriptPubKeyMan*>(&imported->get()));
    }
    std::map<std::pair<OutputType, bool>, uint256> ids;
    for (int pass = 0; pass < 2; ++pass) {
        BOOST_CHECK_EQUAL(wallet->GetAllScriptPubKeyMans().size(), 7U);
        BOOST_CHECK(dynamic_cast<ExternalSignerScriptPubKeyMan*>(wallet->GetDescriptorScriptPubKeyMan(additional)));
        for (const auto type : {OutputType::LEGACY, OutputType::P2SH_SEGWIT, OutputType::BECH32}) {
            auto* receive = wallet->GetScriptPubKeyMan(type, false);
            auto* change = wallet->GetScriptPubKeyMan(type, true);
            BOOST_REQUIRE(receive);
            BOOST_REQUIRE(change);
            BOOST_CHECK(receive->GetID() != change->GetID());
            for (bool internal : {false, true}) {
                const auto id{wallet->GetScriptPubKeyMan(type, internal)->GetID()};
                if (pass == 0) ids[{type, internal}] = id;
                else BOOST_CHECK(id == ids.at({type, internal}));
            }
        }
        if (pass == 0) {
            wallet.reset();
            wallet = open_wallet();
        }
    }
}

#endif

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
