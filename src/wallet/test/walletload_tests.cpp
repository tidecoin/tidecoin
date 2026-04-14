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
#include <key.h>
#include <pq/pqhd_kdf.h>
#include <pq/pq_scheme.h>

#include <boost/test/unit_test.hpp>

#include <fstream>

namespace wallet {

BOOST_AUTO_TEST_SUITE(walletload_tests)

class LoadTxnFailBatch final : public DatabaseBatch
{
public:
    LoadTxnFailBatch(MockableData& records, bool fail_active_spk_write)
        : m_records(records), m_fail_active_spk_write(fail_active_spk_write)
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

private:
    const MockableData& ActiveRecords() const
    {
        return m_txn_active ? m_txn_records : m_records;
    }

    MockableData& MutableActiveRecords()
    {
        return m_txn_active ? m_txn_records : m_records;
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
    bool m_fail_active_spk_write{false};
};

class LoadTxnFailDatabase final : public WalletDatabase
{
public:
    explicit LoadTxnFailDatabase(bool fail_active_spk_write) : m_fail_active_spk_write(fail_active_spk_write) {}

    void Open() override {}
    bool Rewrite() override { return true; }
    bool Backup(const std::string&) const override { return true; }
    void Close() override {}
    std::string Filename() override { return "load-txn-fail"; }
    std::vector<fs::path> Files() override { return {}; }
    std::string Format() override { return "mock"; }
    std::unique_ptr<DatabaseBatch> MakeBatch() override
    {
        return std::make_unique<LoadTxnFailBatch>(m_records, m_fail_active_spk_write);
    }

    bool ContainsDBKey(const std::string& db_key)
    {
        for (const auto& [raw_key, _] : m_records) {
            DataStream key_stream{raw_key};
            std::string key_name;
            try {
                key_stream >> key_name;
            } catch (const std::exception&) {
                continue;
            }
            if (key_name == db_key) return true;
        }
        return false;
    }

private:
    MockableData m_records;
    bool m_fail_active_spk_write{false};
};

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
};

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptors, TestingSetup)
{
    if (CKey::SIZE != 32) return;
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        // Write unknown active descriptor
        WalletBatch batch(*database);
        std::string unknown_desc = "unknown(00)";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(unknown_desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256(), wallet_descriptor));
        BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::UNKNOWN), uint256(), false));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::UNKNOWN_DESCRIPTOR);
    }

    // Test 2
    // Now write a valid descriptor with an invalid ID.
    // As the software produces another ID for the descriptor, the loading process must be aborted.
    database = CreateMockableWalletDatabase();

    // Verify the error
    bool found = false;
    DebugLogHelper logHelper("The descriptor ID calculated by the wallet differs from the one in DB", [&](const std::string* s) {
        found = true;
        return false;
    });

    {
        // Write valid descriptor with invalid ID
        WalletBatch batch(*database);
        std::string desc = "wpkh(pqhd(08dbf2b54de8894fcd63ae0b6626e80180833984ac10cd947308d19455ffcdf4)/10007h/6868h/7h/0h/0h/*h)#mwsjdcmr";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256::ONE, wallet_descriptor));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::CORRUPT);
        BOOST_CHECK(found); // The error must be logged
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

BOOST_FIXTURE_TEST_CASE(wallet_load_pqhd_reconciliation_is_atomic, TestingSetup)
{
    auto database = std::make_unique<LoadTxnFailDatabase>(/*fail_active_spk_write=*/true);
    auto* db_ptr = database.get();
    {
        WalletBatch batch(*database);
        BOOST_CHECK(batch.WriteWalletFlags(WALLET_FLAG_DESCRIPTORS));

        std::array<unsigned char, 32> seed_bytes{};
        seed_bytes.fill(0x44);
        const uint256 seed_id = pqhd::ComputeSeedID32AsUint256(std::span<const uint8_t, 32>(
            reinterpret_cast<const uint8_t*>(seed_bytes.data()), seed_bytes.size()));

        PQHDSeed seed;
        seed.nCreateTime = 1;
        seed.seed.assign(seed_bytes.begin(), seed_bytes.end());
        BOOST_CHECK(batch.WritePQHDSeed(seed_id, seed));

        PQHDPolicy policy;
        policy.default_receive_scheme = static_cast<uint8_t>(pq::SchemeId::FALCON_512);
        policy.default_change_scheme = static_cast<uint8_t>(pq::SchemeId::FALCON_512);
        policy.default_seed_id = seed_id;
        policy.default_change_seed_id = seed_id;
        BOOST_CHECK(batch.WritePQHDPolicy(policy));
    }

    const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    const int64_t birth_time_before = wallet->GetBirthTime();
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::CORRUPT);
    BOOST_CHECK_EQUAL(wallet->GetBirthTime(), birth_time_before);

    // Reconciliation attempted descriptor creation but must not persist partial state on failure.
    BOOST_CHECK(!db_ptr->ContainsDBKey(DBKeys::WALLETDESCRIPTOR));
    BOOST_CHECK(!db_ptr->ContainsDBKey(DBKeys::ACTIVEEXTERNALSPK));
    BOOST_CHECK(!db_ptr->ContainsDBKey(DBKeys::ACTIVEINTERNALSPK));
}

#ifdef ENABLE_EXTERNAL_SIGNER
BOOST_FIXTURE_TEST_CASE(wallet_external_signer_imports_all_parsed_descriptors, TestingSetup)
{
    const CKey key{GenerateRandomKey(pq::SchemeId::FALCON_512)};
    const std::string pubkey_hex{HexStr(key.GetPubKey())};

    const fs::path signer_script{m_args.GetDataDirBase() / "mock_ext_signer_combo.sh"};
    {
        std::ofstream script{signer_script};
        BOOST_REQUIRE(script.good());
        script << "#!/usr/bin/env bash\n";
        script << "set -euo pipefail\n";
        script << "if [[ \"$*\" == *\"enumerate\"* ]]; then\n";
        script << "  echo '[{\"fingerprint\":\"00000001\",\"model\":\"mock\"}]'\n";
        script << "  exit 0\n";
        script << "fi\n";
        script << "if [[ \"$*\" == *\"getdescriptors\"* ]]; then\n";
        script << "  echo '{\"receive\":[\"combo(" << pubkey_hex << ")\"],\"internal\":[\"combo(" << pubkey_hex << ")\"]}'\n";
        script << "  exit 0\n";
        script << "fi\n";
        script << "echo '{\"error\":\"unsupported\"}'\n";
        script << "exit 1\n";
    }
    fs::permissions(
        signer_script,
        fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec,
        fs::perm_options::replace);

    m_args.ForceSetArg("-signer", fs::PathToString(signer_script));
    gArgs.ForceSetArg("-signer", fs::PathToString(signer_script));

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    wallet.SetWalletFlag(WALLET_FLAG_EXTERNAL_SIGNER);

    {
        LOCK(wallet.cs_wallet);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    BOOST_CHECK(wallet.GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/false));
    BOOST_CHECK(wallet.GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/false));
    BOOST_CHECK(wallet.GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
    BOOST_CHECK(wallet.GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/true));
    BOOST_CHECK(wallet.GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/true));
    BOOST_CHECK(wallet.GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
}
#endif

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
