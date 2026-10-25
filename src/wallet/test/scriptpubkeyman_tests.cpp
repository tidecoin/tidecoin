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
#include <map>
#include <set>
#include <utility>
#include <vector>

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

struct ActivePQWalletTestingSetup : WalletTestingSetup {
    ActivePQWalletTestingSetup() : WalletTestingSetup(ChainType::REGTEST) {}
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
    auto signprov_keypath_spendable = spk_man1->GetSigningProvider(key_internal.GetPubKey(), /*include_private=*/true);
    BOOST_CHECK(signprov_keypath_spendable != nullptr);

    desc_str = "wpkh(" + HexStr(key_scriptpath.GetPubKey()) + ")";
    auto spk_man2 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man2 != nullptr);
    auto signprov_keypath_pubonly = spk_man2->GetSigningProvider(key_scriptpath.GetPubKey(), /*include_private=*/true);
    BOOST_CHECK(signprov_keypath_pubonly == nullptr);
    const auto public_provider = spk_man2->GetSigningProvider(key_scriptpath.GetPubKey(), /*include_private=*/false);
    BOOST_REQUIRE(public_provider);
    BOOST_CHECK(public_provider->keys.empty());
    BOOST_CHECK(public_provider->pubkeys.contains(key_scriptpath.GetPubKey().GetID()));
}

BOOST_AUTO_TEST_CASE(PQHDSchemeGatePreAuxpow)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    wallet.m_keypool_size = 1; // This case tests state transitions, not pool capacity.
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
                                           seed_id.ToString(), pqhd::PURPOSE_WPKH, Params().PQHDCoinType());
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

BOOST_AUTO_TEST_CASE(PQHDWitnessV1IssuanceGatedPreAuxpow)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    wallet.m_keypool_size = 1; // This case tests issuance gating, not pool capacity.
    uint256 seed_id;
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
        seed_id = Assert(wallet.GetPQHDPolicy())->default_seed_id;
    }
    BOOST_REQUIRE(wallet.GetTargetHeightForOutputs() < Params().GetConsensus().nAuxpowStartHeight);

    // Native v1 issuance is gated; P2SH-wrapped v0 remains available.
    const auto key = [&](uint32_t purpose) {
        return strprintf("pqhd(%s)/%uh/%uh/7h/0h/0h/*h", seed_id.ToString(), purpose, Params().PQHDCoinType());
    };
    auto* native_v1 = CreateDescriptor(wallet, "wsh512(pk(" + key(pqhd::PURPOSE_WSH512) + "))", true);
    BOOST_REQUIRE(native_v1);
    const auto v1_res = native_v1->GetNewDestination(OutputType::BECH32PQ);
    BOOST_REQUIRE(!v1_res);
    BOOST_CHECK(util::ErrorString(v1_res).original.find("PQ v1 outputs not allowed") != std::string::npos);

    auto* wrapped_v0 = CreateDescriptor(wallet, "sh(wpkh(" + key(pqhd::PURPOSE_GENERIC) + "))", true);
    BOOST_REQUIRE(wrapped_v0);
    BOOST_CHECK(wrapped_v0->GetNewDestination(OutputType::P2SH_SEGWIT));
}

// Keep these expectations independent of PQHDPurposeForOutputType and pqhd_params.h.
static constexpr std::array<std::pair<OutputType, uint32_t>, 4> DEFAULT_PQHD_PURPOSES{{
    {OutputType::LEGACY, 10044},
    {OutputType::P2SH_SEGWIT, 10049},
    {OutputType::BECH32, 10084},
    {OutputType::BECH32PQ, 10087},
}};

BOOST_FIXTURE_TEST_CASE(PQHDDefaultDescriptorsUseFamilyPaths, ActivePQWalletTestingSetup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    wallet.m_keypool_size = 1; // Index 0 of each family is enough.
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    BOOST_REQUIRE_GE(wallet.GetTargetHeightForOutputs(), Params().GetConsensus().nAuxpowStartHeight);
    const auto policy = wallet.GetPQHDPolicy();
    BOOST_REQUIRE(policy);
    BOOST_CHECK(policy->default_seed_id == policy->default_change_seed_id);
    std::map<std::pair<OutputType, bool>, uint256> manager_ids;
    std::set<CPubKey> pubkeys;
    for (const auto& [type, purpose] : DEFAULT_PQHD_PURPOSES) {
        for (const bool internal : {false, true}) {
            auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet.GetScriptPubKeyMan(type, internal));
            BOOST_REQUIRE(manager);
            LOCK(manager->cs_desc_man);
            const auto info = manager->GetWalletDescriptor().descriptor->GetPQHDKeyPathInfo();
            BOOST_REQUIRE(info);
            const std::vector<uint32_t> expected_path{
                0x80000000U | purpose, 0x80000001U, 0x80000007U, 0x80000000U, 0x80000000U | uint32_t{internal}};
            BOOST_CHECK_EQUAL_COLLECTIONS(info->path.begin(), info->path.end(), expected_path.begin(), expected_path.end());
            BOOST_CHECK(info->is_range);
            BOOST_CHECK(info->seed_id == policy->default_seed_id);
            manager_ids.emplace(std::make_pair(type, internal), manager->GetID());
            const auto provider = manager->GetSigningProviderForIndex(0);
            BOOST_REQUIRE(provider);
            BOOST_REQUIRE_EQUAL(provider->pubkeys.size(), 1U);
            BOOST_CHECK(pubkeys.insert(provider->pubkeys.begin()->second).second);
        }
    }

    // Reapplying policy must find the existing family paths even without active
    // bindings, rather than create duplicates or select another family's manager.
    for (const auto& [slot, id] : manager_ids) {
        wallet.DeactivateScriptPubKeyMan(id, slot.first, slot.second);
    }
    const auto manager_count = wallet.GetAllScriptPubKeyMans().size();
    BOOST_REQUIRE(wallet.SetPQHDPolicy(/*receive_scheme=*/7, /*change_scheme=*/7));
    BOOST_CHECK_EQUAL(wallet.GetAllScriptPubKeyMans().size(), manager_count);
    for (const auto& [slot, id] : manager_ids) {
        const auto [type, internal] = slot;
        auto* manager = wallet.GetScriptPubKeyMan(type, internal);
        BOOST_REQUIRE(manager);
        BOOST_CHECK(manager->GetID() == id);
        const auto dest = internal ? wallet.GetNewChangeDestination(type) : wallet.GetNewDestination(type, "");
        BOOST_REQUIRE(dest);
        BOOST_CHECK(manager->IsMine(GetScriptForDestination(*dest)));
    }
}

// No chainstate is installed by BasicTestingSetup, so switching Params here does
// not invalidate a live chain's reference to its parameters.
BOOST_FIXTURE_TEST_CASE(PQHDDefaultDescriptorsUseNetworkCoinTypes, BasicTestingSetup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    struct SeedProvider final : SigningProvider {
        const std::array<uint8_t, 32> seed{};
        uint256 ID() const { return pqhd::ComputeSeedID32AsUint256(seed); }
        std::optional<pqhd::SecureSeed32> GetPQHDSeed(const uint256& id) const override
        {
            if (id != ID()) return std::nullopt;
            std::optional<pqhd::SecureSeed32> result{std::in_place};
            if (!result->Set(seed)) return std::nullopt;
            return result;
        }
    } seed_provider;
    const std::array<std::pair<ChainType, uint32_t>, 3> networks{{
        {ChainType::MAIN, 6868}, {ChainType::TESTNET, 1}, {ChainType::REGTEST, 1},
    }};
    std::map<ChainType, std::vector<CPubKey>> network_pubkeys;
    for (const auto& [network, coin_type] : networks) {
        SelectParams(network);
        BOOST_CHECK_EQUAL(Params().PQHDCoinType(), coin_type);
        // Exercise v1 generation for every network without changing its actual
        // activation settings (mainnet still has activation disabled).
        auto consensus = Params().GetConsensus();
        consensus.nAuxpowStartHeight = 0;
        std::set<CPubKey> family_pubkeys;
        for (const auto& [type, purpose] : DEFAULT_PQHD_PURPOSES) {
            for (const bool internal : {false, true}) {
                const auto descriptor = GeneratePQHDWalletDescriptor(seed_provider.ID(), /*scheme_prefix=*/7,
                    type, internal, consensus, /*target_height=*/0);
                const auto info = descriptor.descriptor->GetPQHDKeyPathInfo();
                BOOST_REQUIRE(info);
                const std::vector<uint32_t> expected_path{
                    0x80000000U | purpose, 0x80000000U | coin_type, 0x80000007U, 0x80000000U, 0x80000000U | uint32_t{internal}};
                BOOST_CHECK_EQUAL_COLLECTIONS(info->path.begin(), info->path.end(), expected_path.begin(), expected_path.end());
                BOOST_CHECK(info->is_range);
                BOOST_CHECK(info->seed_id == seed_provider.ID());
                BOOST_CHECK(descriptor.descriptor->GetOutputType() == type);
                std::vector<CScript> scripts;
                FlatSigningProvider expanded;
                BOOST_REQUIRE(descriptor.descriptor->Expand(/*pos=*/0, seed_provider, scripts, expanded));
                BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
                BOOST_REQUIRE_EQUAL(expanded.pubkeys.size(), 1U);
                const auto& pubkey = expanded.pubkeys.begin()->second;
                BOOST_CHECK(family_pubkeys.insert(pubkey).second);
                network_pubkeys[network].push_back(pubkey);
            }
        }
    }
    // Testnet and regtest deliberately share a domain. Mainnet must share no
    // index-0 key with either, even across output families or receive/change.
    BOOST_CHECK(network_pubkeys.at(ChainType::TESTNET) == network_pubkeys.at(ChainType::REGTEST));
    for (const auto& main_pubkey : network_pubkeys.at(ChainType::MAIN)) {
        for (const auto& test_pubkey : network_pubkeys.at(ChainType::TESTNET)) {
            BOOST_CHECK(main_pubkey != test_pubkey);
        }
    }
}

BOOST_AUTO_TEST_CASE(PQHDDefaultKeypoolAndInternalScheme)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    // Keep one real default-size prefill regression while the state-transition
    // fixtures use small pools. Check every active receive/change manager.
    BOOST_CHECK_EQUAL(wallet.m_keypool_size, DEFAULT_KEYPOOL_SIZE);
    BOOST_REQUIRE(!wallet.GetAllScriptPubKeyMans().empty());
    for (auto* manager : wallet.GetAllScriptPubKeyMans()) {
        BOOST_CHECK_EQUAL(manager->GetKeyPoolSize(), DEFAULT_KEYPOOL_SIZE);
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
    wallet.m_keypool_size = 1; // This case tests state transitions, not pool capacity.
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
        default_seed_id.ToString(), pqhd::PURPOSE_GENERIC, Params().PQHDCoinType(), falcon512,
        imported_seed_id.ToString(), pqhd::PURPOSE_GENERIC, Params().PQHDCoinType(), falcon512);
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

BOOST_FIXTURE_TEST_CASE(PQHDPolicyUpdatesRollbackWhenDescriptorReconciliationFails, ActivePQWalletTestingSetup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    wallet.m_keypool_size = 1;
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    auto read_db_policy = [&wallet]() -> std::optional<PQHDPolicy> {
        auto db_batch = wallet.GetDatabase().MakeBatch();
        if (!db_batch) return std::nullopt;
        PQHDPolicy policy;
        if (!db_batch->Read(DBKeys::PQHD_POLICY, policy)) return std::nullopt;
        return policy;
    };

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

    // Encryption rotates the default seed. Snapshot the state being rolled back
    // immediately before the failing policy update, after that successful rotation.
    const auto original_policy = wallet.GetPQHDPolicy();
    BOOST_REQUIRE(original_policy);
    const auto original_db_policy = read_db_policy();
    BOOST_REQUIRE(original_db_policy);

    const auto set_seed_result = wallet.SetPQHDSeedDefaults(imported_seed_id, imported_seed_id);
    BOOST_REQUIRE(!set_seed_result);
    BOOST_CHECK(set_seed_result.error_code == PQHDErrorCode::UnlockNeeded);
    BOOST_CHECK(util::ErrorString(set_seed_result).original.find("Wallet must be unlocked to create PQHD descriptors") != std::string::npos);

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
    BOOST_REQUIRE(can_test_scheme_switch);

    const auto set_policy_result = wallet.SetPQHDPolicy(static_cast<uint8_t>(pq::SchemeId::MLDSA_44),
                                                        static_cast<uint8_t>(pq::SchemeId::MLDSA_65));
    BOOST_REQUIRE(!set_policy_result);
    BOOST_CHECK(util::ErrorString(set_policy_result).original.find("Wallet must be unlocked to create PQHD descriptors") != std::string::npos);
    BOOST_CHECK(set_policy_result.error_code == PQHDErrorCode::UnlockNeeded);
    const auto invalid_policy = wallet.SetPQHDPolicy(0xff, std::nullopt);
    BOOST_REQUIRE(!invalid_policy);
    BOOST_CHECK(invalid_policy.error_code == PQHDErrorCode::Generic);

    const auto after_scheme_policy = wallet.GetPQHDPolicy();
    BOOST_REQUIRE(after_scheme_policy);
    BOOST_CHECK_EQUAL(after_scheme_policy->default_receive_scheme, original_policy->default_receive_scheme);
    BOOST_CHECK_EQUAL(after_scheme_policy->default_change_scheme, original_policy->default_change_scheme);

    const auto db_after_scheme_policy = read_db_policy();
    BOOST_REQUIRE(db_after_scheme_policy);
    BOOST_CHECK_EQUAL(db_after_scheme_policy->default_receive_scheme, original_db_policy->default_receive_scheme);
    BOOST_CHECK_EQUAL(db_after_scheme_policy->default_change_scheme, original_db_policy->default_change_scheme);
}

BOOST_FIXTURE_TEST_CASE(PQHDPolicyUpdateWriteFailureDoesNotCreateDescriptors, ActivePQWalletTestingSetup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false);
    auto* db_ptr = database.get();
    CWallet wallet(chain.get(), "", std::move(database));
    wallet.m_keypool_size = 1; // This case tests state transitions, not pool capacity.
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    const int target_height = wallet.GetTargetHeightForOutputs();
    const Consensus::Params& params = Params().GetConsensus();
    const bool can_test_scheme_switch =
        pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, target_height) &&
        pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_65, params, target_height);
    BOOST_REQUIRE(can_test_scheme_switch);

    const size_t spkm_count_before = wallet.GetAllScriptPubKeyMans().size();
    db_ptr->SetFailPQHDPolicyWrite(true);

    const auto set_policy_result = wallet.SetPQHDPolicy(static_cast<uint8_t>(pq::SchemeId::MLDSA_44),
                                                        static_cast<uint8_t>(pq::SchemeId::MLDSA_65));
    BOOST_REQUIRE(!set_policy_result);
    BOOST_CHECK(util::ErrorString(set_policy_result).original.find("Failed to write PQHD policy") != std::string::npos);
    BOOST_CHECK_EQUAL(wallet.GetAllScriptPubKeyMans().size(), spkm_count_before);
}

BOOST_FIXTURE_TEST_CASE(PQHDPolicyUpdateAbortRemovesCreatedDescriptors, ActivePQWalletTestingSetup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false,
                                                             /*fail_active_spk_write=*/false);
    auto* db_ptr = database.get();
    CWallet wallet(chain.get(), "", std::move(database));
    wallet.m_keypool_size = 1; // This case tests state transitions, not pool capacity.
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
    BOOST_REQUIRE(can_test_scheme_switch);

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
    wallet.m_keypool_size = 1; // This case tests state transitions, not pool capacity.
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

BOOST_FIXTURE_TEST_CASE(PQHDOnDemandDescriptorCreationCommitFailureRollsBack, ActivePQWalletTestingSetup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    auto database = std::make_unique<TxnPolicyFailDatabase>(/*fail_pqhd_policy_write=*/false,
                                                             /*fail_active_spk_write=*/false,
                                                             /*fail_commit=*/false);
    auto* db_ptr = database.get();
    CWallet wallet(chain.get(), "", std::move(database));
    wallet.m_keypool_size = 1; // This case tests state transitions, not pool capacity.
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    const int target_height = wallet.GetTargetHeightForOutputs();
    const Consensus::Params& params = Params().GetConsensus();
    BOOST_REQUIRE(pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, target_height));

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
    wallet.m_keypool_size = 1; // This case tests state transitions, not pool capacity.
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
    wallet.m_keypool_size = 1; // This case tests state transitions, not pool capacity.
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
    const bool loaded_tampered_record{wallet.LoadPQHDCryptedSeed(fake_seed_id, std::move(tampered_record))};
    BOOST_REQUIRE(loaded_tampered_record);

    // Decryption can succeed, but mismatched seed_id integrity check must reject the record.
    BOOST_CHECK(!wallet.GetPQHDSeed(fake_seed_id).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
