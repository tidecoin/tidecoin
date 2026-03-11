// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <pq/pq_scheme.h>
#include <pq/pqhd_params.h>
#include <test/util/test_controls.h>
#include <wallet/test/wallet_test_fixture.h>
#include <script/solver.h>
#include <util/result.h>
#include <util/string.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/crypter.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/test/util.h>
#include <support/cleanse.h>

#include <boost/test/unit_test.hpp>

#include <array>

namespace wallet {
struct WalletFlagTxnTestAccess
{
    static void SetWalletFlagWithDB(CWallet& wallet, WalletBatch& batch, uint64_t flags)
    {
        wallet.SetWalletFlagWithDB(batch, flags);
    }

    static void UnsetBlankWalletFlag(CWallet& wallet, WalletBatch& batch)
    {
        wallet.UnsetBlankWalletFlag(batch);
    }
};

BOOST_FIXTURE_TEST_SUITE(scriptpubkeyman_tests, WalletTestingSetup)

class TxnPolicyFailBatch final : public DatabaseBatch
{
public:
    TxnPolicyFailBatch(MockableData& records, bool fail_pqhd_policy_write, bool fail_active_spk_write, bool fail_commit)
        : m_records(records), m_fail_pqhd_policy_write(fail_pqhd_policy_write), m_fail_active_spk_write(fail_active_spk_write), m_fail_commit(fail_commit)
    {
    }

    void Close() override {}

    std::unique_ptr<DatabaseCursor> GetNewCursor() override
    {
        return std::make_unique<MockableCursor>(ActiveRecords(), true);
    }

    std::unique_ptr<DatabaseCursor> GetNewPrefixCursor(std::span<const std::byte> prefix) override
    {
        return std::make_unique<MockableCursor>(ActiveRecords(), true, prefix);
    }

    bool TxnBegin() override
    {
        if (m_txn_active) return false;
        m_txn_records = m_records;
        m_txn_active = true;
        return true;
    }

    bool TxnCommit() override
    {
        if (!m_txn_active) return false;
        if (m_fail_commit) {
            return false;
        }
        m_records = std::move(m_txn_records);
        m_txn_records.clear();
        m_txn_active = false;
        return true;
    }

    bool TxnAbort() override
    {
        if (!m_txn_active) return false;
        m_txn_records.clear();
        m_txn_active = false;
        return true;
    }

    bool HasActiveTxn() override { return m_txn_active; }

    bool ContainsDBKey(const std::string& db_key) const
    {
        for (const auto& [raw_key, _] : m_records) {
            DataStream key_stream{raw_key};
            std::string key_name;
            try {
                key_stream >> key_name;
            } catch (const std::exception&) {
                continue;
            }
            if (key_name == db_key) {
                return true;
            }
        }
        return false;
    }

    size_t CountDBKeys(const std::string& db_key) const
    {
        size_t count{0};
        for (const auto& [raw_key, _] : m_records) {
            DataStream key_stream{raw_key};
            std::string key_name;
            try {
                key_stream >> key_name;
            } catch (const std::exception&) {
                continue;
            }
            if (key_name == db_key) {
                ++count;
            }
        }
        return count;
    }

private:
    const MockableData& ActiveRecords() const
    {
        return m_txn_active ? m_txn_records : m_records;
    }

    MockableData& MutableActiveRecords()
    {
        return m_txn_active ? m_txn_records : m_records;
    }

    bool IsPolicyKey(DataStream& key) const
    {
        DataStream copy{key};
        std::string key_name;
        try {
            copy >> key_name;
        } catch (const std::exception&) {
            return false;
        }
        return key_name == DBKeys::PQHD_POLICY;
    }

    bool IsActiveSpkKey(DataStream& key) const
    {
        DataStream copy{key};
        std::string key_name;
        try {
            copy >> key_name;
        } catch (const std::exception&) {
            return false;
        }
        return key_name == DBKeys::ACTIVEEXTERNALSPK || key_name == DBKeys::ACTIVEINTERNALSPK;
    }

    bool ReadKey(DataStream&& key, DataStream& value) override
    {
        SerializeData key_data{key.begin(), key.end()};
        const auto& records = ActiveRecords();
        const auto it = records.find(key_data);
        if (it == records.end()) {
            return false;
        }
        value.clear();
        value.write(it->second);
        return true;
    }

    bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite) override
    {
        if (m_fail_pqhd_policy_write && IsPolicyKey(key)) {
            return false;
        }
        if (m_fail_active_spk_write && IsActiveSpkKey(key)) {
            return false;
        }
        SerializeData key_data{key.begin(), key.end()};
        SerializeData value_data{value.begin(), value.end()};
        auto& records = MutableActiveRecords();
        auto [it, inserted] = records.emplace(key_data, value_data);
        if (!inserted && overwrite) {
            it->second = value_data;
            inserted = true;
        }
        return inserted;
    }

    bool EraseKey(DataStream&& key) override
    {
        SerializeData key_data{key.begin(), key.end()};
        auto& records = MutableActiveRecords();
        records.erase(key_data);
        return true;
    }

    bool HasKey(DataStream&& key) override
    {
        SerializeData key_data{key.begin(), key.end()};
        const auto& records = ActiveRecords();
        return records.count(key_data) > 0;
    }

    bool ErasePrefix(std::span<const std::byte> prefix) override
    {
        auto& records = MutableActiveRecords();
        auto it = records.begin();
        while (it != records.end()) {
            auto& key = it->first;
            if (key.size() < prefix.size() || std::search(key.begin(), key.end(), prefix.begin(), prefix.end()) != key.begin()) {
                ++it;
                continue;
            }
            it = records.erase(it);
        }
        return true;
    }

    MockableData& m_records;
    MockableData m_txn_records;
    bool m_txn_active{false};
    bool m_fail_pqhd_policy_write{false};
    bool m_fail_active_spk_write{false};
    bool m_fail_commit{false};
};

class TxnPolicyFailDatabase final : public WalletDatabase
{
public:
    explicit TxnPolicyFailDatabase(bool fail_pqhd_policy_write,
                                   bool fail_active_spk_write = false,
                                   bool fail_commit = false)
        : m_fail_pqhd_policy_write(fail_pqhd_policy_write), m_fail_active_spk_write(fail_active_spk_write), m_fail_commit(fail_commit) {}

    void Open() override {}
    bool Rewrite() override { return true; }
    bool Backup(const std::string&) const override { return true; }
    void Close() override {}
    std::string Filename() override { return "txn-policy-fail"; }
    std::vector<fs::path> Files() override { return {}; }
    std::string Format() override { return "mock"; }
    std::unique_ptr<DatabaseBatch> MakeBatch() override
    {
        return std::make_unique<TxnPolicyFailBatch>(m_records, m_fail_pqhd_policy_write, m_fail_active_spk_write, m_fail_commit);
    }

    bool ContainsDBKey(const std::string& db_key)
    {
        TxnPolicyFailBatch batch(m_records, /*fail_pqhd_policy_write=*/false, /*fail_active_spk_write=*/false, /*fail_commit=*/false);
        return batch.ContainsDBKey(db_key);
    }

    size_t CountDBKeys(const std::string& db_key)
    {
        TxnPolicyFailBatch batch(m_records, /*fail_pqhd_policy_write=*/false, /*fail_active_spk_write=*/false, /*fail_commit=*/false);
        return batch.CountDBKeys(db_key);
    }

    void SetFailPQHDPolicyWrite(bool fail)
    {
        m_fail_pqhd_policy_write = fail;
    }

    void SetFailActiveSPKWrite(bool fail)
    {
        m_fail_active_spk_write = fail;
    }

    void SetFailCommit(bool fail)
    {
        m_fail_commit = fail;
    }

private:
    MockableData m_records;
    bool m_fail_pqhd_policy_write{false};
    bool m_fail_active_spk_write{false};
    bool m_fail_commit{false};
};

BOOST_AUTO_TEST_CASE(DescriptorScriptPubKeyManTests)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet keystore(chain.get(), "", CreateMockableWalletDatabase());
    auto key_scriptpath = GenerateRandomKey(pq::SchemeId::FALCON_512);

    // Verify that a SigningProvider for a pubkey is only returned if its corresponding private key is available
    auto key_internal = GenerateRandomKey(pq::SchemeId::FALCON_512);
    std::string desc_str = "wpkh(" + EncodeSecret(key_internal) + ")";
    auto spk_man1 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man1 != nullptr);
    auto signprov_keypath_spendable = spk_man1->GetSigningProvider(key_internal.GetPubKey());
    BOOST_CHECK(signprov_keypath_spendable != nullptr);

    desc_str = "wpkh(" + HexStr(key_scriptpath.GetPubKey()) + ")";
    auto spk_man2 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man2 != nullptr);
    auto signprov_keypath_pubonly = spk_man2->GetSigningProvider(key_scriptpath.GetPubKey());
    BOOST_CHECK(signprov_keypath_pubonly == nullptr);
}

BOOST_AUTO_TEST_CASE(PQHDSchemeGatePreAuxpow)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    uint256 seed_id;
    {
        LOCK(wallet.cs_wallet);
        auto policy = wallet.GetPQHDPolicy();
        BOOST_REQUIRE(policy);
        seed_id = policy->default_seed_id;
    }

    const std::string desc_str = strprintf("wpkh(pqhd(%s)/%uh/%uh/9h/0h/0h/*h)",
                                           seed_id.ToString(), pqhd::PURPOSE, pqhd::COIN_TYPE);
    auto spk_man = CreateDescriptor(wallet, desc_str, true);
    BOOST_REQUIRE(spk_man != nullptr);

    auto res = spk_man->GetNewDestination(OutputType::BECH32);
    const Consensus::Params& params = Params().GetConsensus();
    const int target_height = wallet.GetTargetHeightForOutputs();
    const bool allowed = pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, target_height);
    if (allowed) {
        BOOST_CHECK(res.has_value());
    } else {
        BOOST_CHECK(!res);
    }
}

BOOST_AUTO_TEST_CASE(PQHDInternalDescriptorUsesDefaultScheme)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    auto spk_man = wallet.GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true);
    BOOST_REQUIRE(spk_man);
    auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    BOOST_REQUIRE(desc_spk_man);

    LOCK(desc_spk_man->cs_desc_man);
    const std::optional<uint8_t> scheme_prefix = desc_spk_man->GetWalletDescriptor().descriptor->GetPQHDSchemePrefix();
    BOOST_REQUIRE(scheme_prefix);
    BOOST_CHECK_EQUAL(*scheme_prefix, static_cast<uint8_t>(pq::SchemeId::FALCON_512));
}

BOOST_AUTO_TEST_CASE(PQHDSeedRemovalBlockedForMixedDescriptorPaths)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    uint256 default_seed_id;
    uint256 imported_seed_id;
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();

        const auto policy = wallet.GetPQHDPolicy();
        BOOST_REQUIRE(policy);
        default_seed_id = policy->default_seed_id;

        std::array<unsigned char, 32> imported_seed_material{};
        imported_seed_material.fill(0x42);
        auto import_result = wallet.ImportPQHDSeed(imported_seed_material);
        BOOST_REQUIRE(import_result);
        imported_seed_id = import_result->seed_id;
    }

    const uint8_t falcon512 = static_cast<uint8_t>(pq::SchemeId::FALCON_512);
    const std::string desc_str = strprintf(
        "wsh(sortedmulti(2,"
        "pqhd(%s)/%uh/%uh/%uh/0h/0h/*h,"
        "pqhd(%s)/%uh/%uh/%uh/0h/1h/*h))",
        default_seed_id.ToString(), pqhd::PURPOSE, pqhd::COIN_TYPE, falcon512,
        imported_seed_id.ToString(), pqhd::PURPOSE, pqhd::COIN_TYPE, falcon512);
    auto* spk_man = CreateDescriptor(wallet, desc_str, true);
    BOOST_REQUIRE(spk_man != nullptr);

    LOCK(wallet.cs_wallet);
    auto remove_result = wallet.RemovePQHDSeed(imported_seed_id);
    BOOST_CHECK(!remove_result);
    BOOST_CHECK(util::ErrorString(remove_result).original.find("Cannot remove PQHD seed referenced by wallet descriptors") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(PQHDSeedImportRollsBackOnPolicyWriteFailure)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/true);
    CWallet wallet(chain.get(), "", std::move(database));

    std::array<unsigned char, 32> seed_material{};
    seed_material.fill(0x5a);

    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    const auto import_res = wallet.ImportPQHDSeed(seed_material);
    BOOST_REQUIRE(!import_res);
    BOOST_CHECK(util::ErrorString(import_res).original.find("Failed to write default PQHD policy") != std::string::npos);

    BOOST_CHECK(wallet.ListPQHDSeeds().empty());
    BOOST_CHECK(!wallet.GetPQHDPolicy().has_value());

    auto& db = dynamic_cast<TxnPolicyFailDatabase&>(wallet.GetDatabase());
    BOOST_CHECK(!db.ContainsDBKey(DBKeys::PQHD_SEED));
    BOOST_CHECK(!db.ContainsDBKey(DBKeys::PQHD_CRYPTED_SEED));
    BOOST_CHECK(!db.ContainsDBKey(DBKeys::PQHD_POLICY));
}

BOOST_AUTO_TEST_CASE(PQHDPolicyUpdatesRollbackWhenDescriptorReconciliationFails)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    const auto original_policy = wallet.GetPQHDPolicy();
    BOOST_REQUIRE(original_policy);

    auto read_db_policy = [&wallet]() -> std::optional<PQHDPolicy> {
        auto db_batch = wallet.GetDatabase().MakeBatch();
        if (!db_batch) return std::nullopt;
        PQHDPolicy policy;
        if (!db_batch->Read(DBKeys::PQHD_POLICY, policy)) return std::nullopt;
        return policy;
    };

    const auto original_db_policy = read_db_policy();
    BOOST_REQUIRE(original_db_policy);

    const SecureString passphrase{"passphrase"};
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase));

    std::array<unsigned char, 32> imported_seed_material{};
    imported_seed_material.fill(0x24);
    const auto import_result = wallet.ImportPQHDSeed(imported_seed_material);
    BOOST_REQUIRE(import_result);
    const uint256 imported_seed_id = import_result->seed_id;

    BOOST_REQUIRE(wallet.Lock());
    BOOST_REQUIRE(wallet.IsLocked());

    const auto set_seed_result = wallet.SetPQHDSeedDefaults(imported_seed_id, imported_seed_id);
    BOOST_REQUIRE(!set_seed_result);
    BOOST_CHECK(util::ErrorString(set_seed_result).original.find("Missing PQHD descriptor") != std::string::npos);

    const auto after_seed_policy = wallet.GetPQHDPolicy();
    BOOST_REQUIRE(after_seed_policy);
    BOOST_CHECK(after_seed_policy->default_seed_id == original_policy->default_seed_id);
    BOOST_CHECK(after_seed_policy->default_change_seed_id == original_policy->default_change_seed_id);

    const auto db_after_seed_policy = read_db_policy();
    BOOST_REQUIRE(db_after_seed_policy);
    BOOST_CHECK(db_after_seed_policy->default_seed_id == original_db_policy->default_seed_id);
    BOOST_CHECK(db_after_seed_policy->default_change_seed_id == original_db_policy->default_change_seed_id);

    const int target_height = wallet.GetTargetHeightForOutputs();
    const Consensus::Params& params = Params().GetConsensus();
    const bool can_test_scheme_switch =
        pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, target_height) &&
        pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_65, params, target_height);
    if (!can_test_scheme_switch) return;

    const auto set_policy_result = wallet.SetPQHDPolicy(static_cast<uint8_t>(pq::SchemeId::MLDSA_44),
                                                        static_cast<uint8_t>(pq::SchemeId::MLDSA_65));
    BOOST_REQUIRE(!set_policy_result);
    BOOST_CHECK(util::ErrorString(set_policy_result).original.find("Missing PQHD descriptor") != std::string::npos);

    const auto after_scheme_policy = wallet.GetPQHDPolicy();
    BOOST_REQUIRE(after_scheme_policy);
    BOOST_CHECK_EQUAL(after_scheme_policy->default_receive_scheme, original_policy->default_receive_scheme);
    BOOST_CHECK_EQUAL(after_scheme_policy->default_change_scheme, original_policy->default_change_scheme);

    const auto db_after_scheme_policy = read_db_policy();
    BOOST_REQUIRE(db_after_scheme_policy);
    BOOST_CHECK_EQUAL(db_after_scheme_policy->default_receive_scheme, original_db_policy->default_receive_scheme);
    BOOST_CHECK_EQUAL(db_after_scheme_policy->default_change_scheme, original_db_policy->default_change_scheme);
}

BOOST_AUTO_TEST_CASE(PQHDPolicyUpdateWriteFailureDoesNotCreateDescriptors)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false);
    auto* db_ptr = database.get();
    CWallet wallet(chain.get(), "", std::move(database));
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    const int target_height = wallet.GetTargetHeightForOutputs();
    const Consensus::Params& params = Params().GetConsensus();
    const bool can_test_scheme_switch =
        pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, target_height) &&
        pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_65, params, target_height);
    if (!can_test_scheme_switch) return;

    const size_t spkm_count_before = wallet.GetAllScriptPubKeyMans().size();
    db_ptr->SetFailPQHDPolicyWrite(true);

    const auto set_policy_result = wallet.SetPQHDPolicy(static_cast<uint8_t>(pq::SchemeId::MLDSA_44),
                                                        static_cast<uint8_t>(pq::SchemeId::MLDSA_65));
    BOOST_REQUIRE(!set_policy_result);
    BOOST_CHECK(util::ErrorString(set_policy_result).original.find("Failed to write PQHD policy") != std::string::npos);
    BOOST_CHECK_EQUAL(wallet.GetAllScriptPubKeyMans().size(), spkm_count_before);
}

BOOST_AUTO_TEST_CASE(PQHDPolicyUpdateAbortRemovesCreatedDescriptors)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false,
                                                             /*fail_active_spk_write=*/false);
    auto* db_ptr = database.get();
    CWallet wallet(chain.get(), "", std::move(database));
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    const auto original_policy = wallet.GetPQHDPolicy();
    BOOST_REQUIRE(original_policy);

    const int target_height = wallet.GetTargetHeightForOutputs();
    const Consensus::Params& params = Params().GetConsensus();
    const bool can_test_scheme_switch =
        pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, target_height) &&
        pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_65, params, target_height);
    if (!can_test_scheme_switch) return;

    const size_t spkm_count_before = wallet.GetAllScriptPubKeyMans().size();
    db_ptr->SetFailActiveSPKWrite(true);

    const auto set_policy_result = wallet.SetPQHDPolicy(static_cast<uint8_t>(pq::SchemeId::MLDSA_44),
                                                        static_cast<uint8_t>(pq::SchemeId::MLDSA_65));
    BOOST_REQUIRE(!set_policy_result);
    BOOST_CHECK(util::ErrorString(set_policy_result).original.find("writing active ScriptPubKeyMan id failed") != std::string::npos);
    BOOST_CHECK_EQUAL(wallet.GetAllScriptPubKeyMans().size(), spkm_count_before);

    const auto restored_policy = wallet.GetPQHDPolicy();
    BOOST_REQUIRE(restored_policy);
    BOOST_CHECK(restored_policy->default_seed_id == original_policy->default_seed_id);
    BOOST_CHECK(restored_policy->default_change_seed_id == original_policy->default_change_seed_id);
    BOOST_CHECK_EQUAL(restored_policy->default_receive_scheme, original_policy->default_receive_scheme);
    BOOST_CHECK_EQUAL(restored_policy->default_change_scheme, original_policy->default_change_scheme);
}

BOOST_AUTO_TEST_CASE(PQHDDescriptorSetupAbortPreservesBlankWalletFlag)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false,
                                                             /*fail_active_spk_write=*/true);
    CWallet wallet(chain.get(), "", std::move(database));
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));

    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK_THROW(wallet.SetupDescriptorScriptPubKeyMans(), std::runtime_error);
        BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    }

    auto db_batch = wallet.GetDatabase().MakeBatch();
    uint64_t flags{0};
    BOOST_REQUIRE(db_batch->Read(DBKeys::FLAGS, flags));
    BOOST_CHECK((flags & WALLET_FLAG_BLANK_WALLET) != 0);
}

BOOST_AUTO_TEST_CASE(WalletFlagTransactionalUpdatesComposeAndRollback)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());

    // Commit path: set descriptors+blank, then unset blank in the same txn.
    {
        WalletBatch batch(wallet.GetDatabase());
        BOOST_REQUIRE(batch.TxnBegin());
        WalletFlagTxnTestAccess::SetWalletFlagWithDB(wallet, batch, WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
        WalletFlagTxnTestAccess::UnsetBlankWalletFlag(wallet, batch);
        BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
        BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
        BOOST_REQUIRE(batch.TxnCommit());
    }
    BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    {
        auto db_batch = wallet.GetDatabase().MakeBatch();
        uint64_t flags{0};
        BOOST_REQUIRE(db_batch->Read(DBKeys::FLAGS, flags));
        BOOST_CHECK((flags & WALLET_FLAG_DESCRIPTORS) != 0);
        BOOST_CHECK((flags & WALLET_FLAG_BLANK_WALLET) == 0);
    }

    // Abort path: same sequence should roll back to pre-txn flags.
    {
        WalletBatch batch(wallet.GetDatabase());
        BOOST_REQUIRE(batch.TxnBegin());
        WalletFlagTxnTestAccess::SetWalletFlagWithDB(wallet, batch, WALLET_FLAG_BLANK_WALLET);
        WalletFlagTxnTestAccess::UnsetBlankWalletFlag(wallet, batch);
        BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
        BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
        BOOST_REQUIRE(batch.TxnAbort());
    }
    BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
}

BOOST_AUTO_TEST_CASE(RunWithinTxnCommitFailureAbortsAndRestoresWalletFlags)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false,
                                                             /*fail_active_spk_write=*/false,
                                                             /*fail_commit=*/true);
    auto* db_ptr = database.get();
    CWallet wallet(chain.get(), "", std::move(database));

    LOCK(wallet.cs_wallet);
    BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    const bool ok = RunWithinTxn(wallet.GetDatabase(), /*process_desc=*/"wallet flag rollback on commit failure",
                                 [&](WalletBatch& batch) {
                                     WalletFlagTxnTestAccess::SetWalletFlagWithDB(wallet, batch, WALLET_FLAG_DESCRIPTORS);
                                     BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
                                     return true;
                                 });
    BOOST_CHECK(!ok);

    // Abort listeners must run after commit failure and restore in-memory flags.
    BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    // DB txn must also be rolled back.
    BOOST_CHECK(!db_ptr->ContainsDBKey(DBKeys::FLAGS));
}

BOOST_AUTO_TEST_CASE(RunWithinTxnExceptionAbortsAndRestoresWalletFlags)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false,
                                                             /*fail_active_spk_write=*/false,
                                                             /*fail_commit=*/false);
    auto* db_ptr = database.get();
    CWallet wallet(chain.get(), "", std::move(database));

    LOCK(wallet.cs_wallet);
    BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    BOOST_CHECK_THROW(
        RunWithinTxn(wallet.GetDatabase(), /*process_desc=*/"wallet flag rollback on exception",
                     [&](WalletBatch& batch) -> bool {
                         WalletFlagTxnTestAccess::SetWalletFlagWithDB(wallet, batch, WALLET_FLAG_DESCRIPTORS);
                         BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
                         throw std::runtime_error("intentional test exception");
                         return true;
                     }),
        std::runtime_error);

    // Abort listeners must run after exception and restore in-memory flags.
    BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    // DB txn must be rolled back.
    BOOST_CHECK(!db_ptr->ContainsDBKey(DBKeys::FLAGS));
}

BOOST_AUTO_TEST_CASE(PQHDOnDemandDescriptorCreationCommitFailureRollsBack)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false,
                                                             /*fail_active_spk_write=*/false,
                                                             /*fail_commit=*/false);
    auto* db_ptr = database.get();
    CWallet wallet(chain.get(), "", std::move(database));
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    const int target_height = wallet.GetTargetHeightForOutputs();
    const Consensus::Params& params = Params().GetConsensus();
    if (!pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, target_height)) return;

    const size_t spkm_count_before = wallet.GetAllScriptPubKeyMans().size();
    const size_t descriptor_records_before = db_ptr->CountDBKeys(DBKeys::WALLETDESCRIPTOR);
    db_ptr->SetFailCommit(true);

    BOOST_CHECK_THROW(wallet.GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false, static_cast<uint8_t>(pq::SchemeId::MLDSA_44)),
                      std::runtime_error);
    BOOST_CHECK_EQUAL(wallet.GetAllScriptPubKeyMans().size(), spkm_count_before);
    BOOST_CHECK_EQUAL(db_ptr->CountDBKeys(DBKeys::WALLETDESCRIPTOR), descriptor_records_before);

    // Recovery check: with commit failures disabled, descriptor creation succeeds.
    db_ptr->SetFailCommit(false);
    auto* created = wallet.GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false, static_cast<uint8_t>(pq::SchemeId::MLDSA_44));
    BOOST_REQUIRE(created != nullptr);
    BOOST_CHECK(wallet.GetAllScriptPubKeyMans().size() > spkm_count_before);
    BOOST_CHECK(db_ptr->CountDBKeys(DBKeys::WALLETDESCRIPTOR) > descriptor_records_before);
}

BOOST_AUTO_TEST_CASE(PQHDOnDemandDescriptorCreationPreAuxpowDoesNotThrow)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    const int target_height = wallet.GetTargetHeightForOutputs();
    const Consensus::Params& params = Params().GetConsensus();
    if (target_height >= params.nAuxpowStartHeight) return;

    BOOST_CHECK_NO_THROW(wallet.GetScriptPubKeyMan(OutputType::BECH32PQ, /*internal=*/false, static_cast<uint8_t>(pq::SchemeId::FALCON_512)));
    BOOST_CHECK(!wallet.GetScriptPubKeyMan(OutputType::BECH32PQ, /*internal=*/false, static_cast<uint8_t>(pq::SchemeId::FALCON_512)));

    auto new_dest = wallet.GetNewDestination(OutputType::BECH32PQ, "");
    BOOST_CHECK(!new_dest);
    BOOST_CHECK(util::ErrorString(new_dest).original.find("Output type bech32pq is not allowed before auxpow activation") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(PQHDCryptedSeedDecryptRejectsSeedIdMismatch)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    const SecureString passphrase{"passphrase"};
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase));

    std::array<unsigned char, 32> tampered_seed_bytes{};
    tampered_seed_bytes.fill(0x6d);
    const uint256 expected_seed_id = pqhd::ComputeSeedID32AsUint256(std::span<const uint8_t, 32>(
        reinterpret_cast<const uint8_t*>(tampered_seed_bytes.data()), tampered_seed_bytes.size()));

    uint256 fake_seed_id = expected_seed_id;
    fake_seed_id.begin()[0] ^= 0x01;
    if (wallet.HavePQHDSeed(fake_seed_id)) {
        fake_seed_id.begin()[1] ^= 0x01;
    }
    BOOST_REQUIRE(fake_seed_id != expected_seed_id);
    BOOST_REQUIRE(!wallet.HavePQHDSeed(fake_seed_id));

    CKeyingMaterial tampered_seed{tampered_seed_bytes.begin(), tampered_seed_bytes.end()};
    std::vector<unsigned char> crypted_seed;
    BOOST_REQUIRE(wallet.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
        return EncryptSecret(encryption_key, tampered_seed, fake_seed_id, crypted_seed);
    }));
    memory_cleanse(tampered_seed.data(), tampered_seed.size());
    tampered_seed.clear();

    PQHDCryptedSeed tampered_record;
    tampered_record.nCreateTime = 1;
    tampered_record.crypted_seed = std::move(crypted_seed);
    BOOST_REQUIRE(wallet.LoadPQHDCryptedSeed(fake_seed_id, std::move(tampered_record)));

    // Decryption can succeed, but mismatched seed_id integrity check must reject the record.
    BOOST_CHECK(!wallet.GetPQHDSeed(fake_seed_id).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
