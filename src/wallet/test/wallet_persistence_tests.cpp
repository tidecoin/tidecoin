// Copyright (c) 2026-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tidecoin-build-config.h> // IWYU pragma: keep

#include <crypto/common.h>
#include <hash.h>
#include <key_io.h>
#include <kernel/chain.h>
#include <node/blockstorage.h>
#include <pq/pqhd_kdf.h>
#include <pq/pq_scheme.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <scheduler.h>
#include <script/descriptor.h>
#include <test/util/setup_common.h>
#include <test/util/mining.h>
#include <util/chaintype.h>
#include <util/fs_helpers.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/context.h>
#include <wallet/crypter.h>
#ifdef ENABLE_EXTERNAL_SIGNER
#include <external_signer.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#endif
#include <wallet/migrate.h>
#include <wallet/sqlite.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <fstream>
#include <functional>
#include <future>
#include <limits>
#include <map>
#include <set>

#ifndef WIN32
#include <csignal>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace wallet {
RPCHelpMan importdescriptors();
RPCHelpMan walletpassphrase();
RPCHelpMan walletlock();
// Inspect transaction state without adding runtime fault hooks to the wallet.
struct WalletReconciliationTestAccess {
    static bool Attach(const std::shared_ptr<CWallet>& wallet, interfaces::Chain& chain, bilingual_str& error)
    {
        std::vector<bilingual_str> warnings;
        return CWallet::AttachChain(wallet, chain, false, error, warnings);
    }
    static void Detach(CWallet& wallet) { wallet.m_chain_notifications_handler.reset(); }

    struct State {
        uint64_t flags;
        int64_t birth;
        size_t managers, active, scripts, flag_snapshots;
        uint256 digest;
        bool operator==(const State&) const = default;
    };

    static State Snapshot(CWallet& wallet)
    {
        LOCK(wallet.cs_wallet);
        DataStream data;
        data << wallet.m_wallet_flags.load() << wallet.GetBirthTime();
        for (const auto& [id, manager] : wallet.m_spk_managers) {
            data << id;
            const auto* desc = dynamic_cast<DescriptorScriptPubKeyMan*>(manager.get());
            BOOST_REQUIRE(desc);
            LOCK(desc->cs_desc_man);
            const auto record{desc->GetWalletDescriptor()};
            // Normalize unordered caches before comparing snapshots.
            std::map<uint32_t, std::map<uint32_t, CPubKey>> derived;
            for (const auto& [index, pubkeys] : record.cache.GetCachedDerivedPubKeys()) {
                derived[index] = {pubkeys.begin(), pubkeys.end()};
            }
            data << record << derived << desc->m_map_script_pub_keys << desc->m_map_pubkeys << desc->m_max_cached_index << static_cast<uint8_t>(desc->m_cache_state);
            std::set<CKeyID> stored_keys;
            for (const auto& [id, key] : desc->m_map_keys) stored_keys.insert(id);
            data << stored_keys << desc->m_map_crypted_keys;
            data << uint64_t{desc->m_mutation_batches.size()};
            data << uint64_t{desc->m_map_signing_providers.size()};
            for (const auto& [index, provider] : desc->m_map_signing_providers) {
                data << index << provider.pubkeys << uint64_t{provider.scripts.size()};
                for (const auto& [script_id, script] : provider.scripts) data << script_id.ToString() << script;
                std::set<CKeyID> key_ids;
                for (const auto& [key_id, key] : provider.keys) key_ids.insert(key_id);
                data << key_ids;
            }
        }
        size_t active{0};
        for (bool internal : {false, true}) {
            for (auto type : OUTPUT_TYPES) {
                if (auto* manager = wallet.GetScriptPubKeyMan(type, internal)) {
                    data << internal << static_cast<uint8_t>(type) << manager->GetID();
                    ++active;
                }
            }
        }
        std::map<CScript, std::vector<uint256>> cache;
        for (const auto& [script, managers] : wallet.m_cached_spks) {
            for (auto* manager : managers) cache[script].push_back(manager->GetID());
            std::sort(cache[script].begin(), cache[script].end());
        }
        data << cache;
        if (wallet.m_pqhd_policy) data << *wallet.m_pqhd_policy;
        for (const auto& [id, seed] : wallet.m_pqhd_seeds) data << id << seed.create_time << seed.encrypted;
        return {wallet.m_wallet_flags.load(), wallet.GetBirthTime(), wallet.m_spk_managers.size(), active,
                cache.size(), wallet.m_wallet_flags_txn_snapshot.size(), Hash(data)};
    }

    // Temporarily withhold seed material after the load-time validity checks, so
    // expansion really returns false. Seed records and seed-presence checks stay
    // intact. Swap back before checking rollback; never write this fault to disk.
    static void SwapSeeds(CWallet& wallet, std::map<uint256, CKeyingMaterial>& seeds)
    {
        LOCK(wallet.cs_wallet);
        for (auto& [id, seed] : wallet.m_pqhd_seeds) seed.seed.swap(seeds[id]);
    }
};

namespace {
MockableData ReadRecords(WalletDatabase& database);

// Faults are confined to this test adapter. All successful operations go to a
// real SQLite database, which is closed and reopened to check durable state.
struct Failure {
    std::string operation;
    std::string record{};
    bool hit{false};
    size_t skip{0};
    bool persistent{false};
    bool Reject(std::string_view op, std::string_view type = {}) {
        if ((!hit || persistent) && operation == op && record == type) {
            if (skip > 0) { --skip; return false; }
            hit = true;
            return true;
        }
        return false;
    }
};
struct RawRecord {
    DataStream& data;
    template <typename Stream> void Serialize(Stream& s) const { s.write(std::span<const std::byte>{data.data(), data.size()}); }
    void Unserialize(DataStream& s) { data = std::move(s); }
};
class FailingBatch final : public DatabaseBatch {
    std::unique_ptr<DatabaseBatch> m_inner;
    Failure& m_failure;
    const std::function<void()>& m_before_begin;
    const std::function<void(std::string_view)>& m_after_write;
    static std::string Type(const DataStream& key) {
        DataStream copy{std::span<const std::byte>{key.data(), key.size()}};
        std::string type;
        copy >> type;
        return type;
    }
    bool ReadKey(DataStream&& key, DataStream& value) override {
        RawRecord output{value};
        return m_inner->Read(RawRecord{key}, output);
    }
    bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite) override {
        const auto type{Type(key)};
        if (m_failure.Reject("write", type) || !m_inner->Write(RawRecord{key}, RawRecord{value}, overwrite)) return false;
        if (m_after_write) m_after_write(type);
        return true;
    }
    bool EraseKey(DataStream&& key) override { return !m_failure.Reject("erase", Type(key)) && m_inner->Erase(RawRecord{key}); }
    bool HasKey(DataStream&& key) override { return m_inner->Exists(RawRecord{key}); }
public:
    FailingBatch(std::unique_ptr<DatabaseBatch> inner, Failure& failure,
                 const std::function<void()>& before_begin, const std::function<void(std::string_view)>& after_write)
        : m_inner(std::move(inner)), m_failure(failure), m_before_begin(before_begin), m_after_write(after_write) {}
    void Close() override { m_inner->Close(); }
    bool ErasePrefix(std::span<const std::byte> prefix) override { return m_inner->ErasePrefix(prefix); }
    std::unique_ptr<DatabaseCursor> GetNewCursor() override { return m_inner->GetNewCursor(); }
    std::unique_ptr<DatabaseCursor> GetNewPrefixCursor(std::span<const std::byte> prefix) override { return m_inner->GetNewPrefixCursor(prefix); }
    bool TxnBegin() override {
        if (m_before_begin) m_before_begin();
        return !m_failure.Reject("begin") && m_inner->TxnBegin();
    }
    bool TxnCommit() override { return !m_failure.Reject("commit") && m_inner->TxnCommit(); }
    bool TxnAbort() override { return !m_failure.Reject("abort") && m_inner->TxnAbort(); }
    bool HasActiveTxn() override { return m_inner->HasActiveTxn(); }
};
class FailingDatabase final : public SQLiteDatabase {
public:
    Failure failure;
    std::function<void()> before_begin;
    std::function<void(std::string_view)> after_write;
    explicit FailingDatabase(const fs::path& path) : SQLiteDatabase(path, path / "wallet.dat", DatabaseOptions{}) {}
    std::unique_ptr<DatabaseBatch> MakeBatch() override { return std::make_unique<FailingBatch>(SQLiteDatabase::MakeBatch(), failure, before_begin, after_write); }
};
struct PersistenceSetup : BasicTestingSetup {
    PersistenceSetup() : BasicTestingSetup(ChainType::REGTEST) {}
    std::unique_ptr<CWallet> Open(const fs::path& path) {
        auto wallet{std::make_unique<CWallet>(m_node.chain.get(), "", std::make_unique<FailingDatabase>(path))};
        wallet->m_keypool_size = 1;
        BOOST_REQUIRE(wallet->LoadWallet() == DBErrors::LOAD_OK);
        return wallet;
    }
    static Failure& Fault(CWallet& wallet) { return dynamic_cast<FailingDatabase&>(wallet.GetDatabase()).failure; }
    static DescriptorScriptPubKeyMan& Import(CWallet& wallet, const CKey& key) {
        LOCK(wallet.cs_wallet);
        FlatSigningProvider provider;
        std::string error;
        auto descriptors{Parse("pk(" + EncodeSecret(key) + ")", provider, error, false)};
        BOOST_REQUIRE_EQUAL(descriptors.size(), 1U);
        WalletDescriptor desc{std::move(descriptors[0]), 1, 0, 1, 0};
        auto result{wallet.AddWalletDescriptor(desc, provider, "", false)};
        BOOST_REQUIRE(result);
        return result->get();
    }
    static void CheckKey(CWallet& wallet, const CPubKey& pubkey) {
        const auto key{wallet.GetKey(pubkey.GetID())};
        BOOST_REQUIRE(key);
        std::vector<unsigned char> signature;
        BOOST_REQUIRE(key->Sign(uint256::ONE, signature));
        BOOST_CHECK(pubkey.Verify(uint256::ONE, signature));
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_persistence_tests, PersistenceSetup)

BOOST_AUTO_TEST_CASE(unlock_rpc_failure_restores_lock_and_timeout)
{
    const SecureString pass{"unlock failure test"};
    const CKey key{GenerateRandomKey(pq::SchemeId::FALCON_512)};
    unsigned int index{0};
    for (bool initially_locked : {true, false}) {
        for (const Failure& point : std::vector<Failure>{{"begin"}, {"write", "walletdescriptorpubkeycache"},
                 {"write", DBKeys::WALLETDESCRIPTOR}, {"commit"}}) {
            BOOST_TEST_CONTEXT(initially_locked << " " << point.operation << " " << point.record) {
                const auto path{m_args.GetDataDirBase() / fs::PathFromString(strprintf("unlock-rpc-%u", index++))};
                std::shared_ptr<CWallet> wallet{Open(path)};
                WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
                WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
                Import(*wallet, key);
                BOOST_REQUIRE(wallet->EncryptWallet(pass));

                CScheduler scheduler;
                WalletContext context;
                context.args = &m_args;
                context.chain = m_node.chain.get();
                context.scheduler = &scheduler;
                AddWallet(context, wallet);
                JSONRPCRequest request;
                request.context = &context;
                BOOST_REQUIRE(request.params.read("[\"unlock failure test\", 600]"));
                if (!initially_locked) walletpassphrase().HandleRequest(request);
                const int64_t previous_timeout{WITH_LOCK(wallet->cs_wallet, return wallet->nRelockTime)};
                // Consume the cached key so the next unlock really writes new
                // cache entries, including when the wallet started unlocked.
                BOOST_REQUIRE(wallet->GetNewDestination(OutputType::BECH32, ""));
                const auto records{ReadRecords(wallet->GetDatabase())};
                Fault(*wallet) = point;
                BOOST_REQUIRE(request.params.read("[\"unlock failure test\", 1200]"));
                bool failed{false};
                try { walletpassphrase().HandleRequest(request); }
                catch (const UniValue& error) {
                    failed = true;
                    BOOST_CHECK_EQUAL(error["code"].getInt<int>(), -4);
                } catch (const std::runtime_error&) { failed = true; }
                BOOST_CHECK(failed);
                BOOST_CHECK(Fault(*wallet).hit);
                BOOST_CHECK_EQUAL(wallet->IsLocked(), initially_locked);
                BOOST_CHECK_EQUAL(WITH_LOCK(wallet->cs_wallet, return wallet->nRelockTime), previous_timeout);
                BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
                BOOST_CHECK(!wallet->GetDatabase().MakeBatch()->HasActiveTxn());
                if (initially_locked) {
                    BOOST_CHECK(!wallet->GetKey(key.GetPubKey().GetID()));
                } else {
                    CheckKey(*wallet, key.GetPubKey());
                }
                std::chrono::steady_clock::time_point first, last;
                BOOST_CHECK_EQUAL(scheduler.getQueueInfo(first, last), initially_locked ? 0U : 1U);
                // Run the original callback without waiting for the real timeout.
                scheduler.MockForward(std::chrono::seconds{1200});
                scheduler.StopWhenDrained();
                scheduler.serviceQueue();
                BOOST_CHECK(wallet->IsLocked());
                BOOST_CHECK_EQUAL(WITH_LOCK(wallet->cs_wallet, return wallet->nRelockTime), 0);
                RemoveWallet(context, wallet, std::nullopt);
                wallet.reset();

                // Failed refills must also preserve a usable encrypted wallet on disk.
                wallet = Open(path);
                CScheduler recovered_scheduler;
                context.scheduler = &recovered_scheduler;
                AddWallet(context, wallet);
                BOOST_REQUIRE(request.params.read("[\"unlock failure test\", 0]"));
                walletpassphrase().HandleRequest(request);
                CheckKey(*wallet, key.GetPubKey());
                recovered_scheduler.StopWhenDrained();
                recovered_scheduler.serviceQueue();
                BOOST_CHECK(wallet->IsLocked());
                BOOST_CHECK_EQUAL(WITH_LOCK(wallet->cs_wallet, return wallet->nRelockTime), 0);
                RemoveWallet(context, wallet, std::nullopt);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(unlock_rpc_failure_with_concurrent_relock)
{
    std::shared_ptr<CWallet> wallet{Open(m_args.GetDataDirBase() / "concurrent-unlock")};
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"test passphrase"}));
    CScheduler scheduler;
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = &scheduler;
    AddWallet(context, wallet);
    JSONRPCRequest request;
    request.context = &context;
    BOOST_REQUIRE(request.params.read("[\"test passphrase\", 600]"));
    walletpassphrase().HandleRequest(request);

    std::promise<void> entered, release;
    auto entered_future{entered.get_future()};
    auto gate{release.get_future()};
    auto& db{dynamic_cast<FailingDatabase&>(wallet->GetDatabase())};
    db.failure = {"begin"};
    db.before_begin = [&] {
        entered.set_value();
        gate.wait();
    };
    auto unlock{std::async(std::launch::async, [&] {
        try { walletpassphrase().HandleRequest(request); }
        catch (const UniValue& e) { return e["code"].getInt<int>() == -4; }
        return false;
    })};
    const bool waiting{entered_future.wait_for(std::chrono::seconds{5}) == std::future_status::ready};
    if (!waiting) {
        release.set_value();
        unlock.wait();
        BOOST_FAIL("unlock did not reach the refill transaction");
    }
    scheduler.MockForward(std::chrono::seconds{1200});
    scheduler.StopWhenDrained();
    auto timer{std::async(std::launch::async, [&] { scheduler.serviceQueue(); })};
    auto lock{std::async(std::launch::async, [&] {
        JSONRPCRequest lock_request;
        lock_request.context = &context;
        BOOST_REQUIRE(lock_request.params.read("[]"));
        walletlock().HandleRequest(lock_request);
    })};
    // Both relock paths must wait for the in-progress unlock to unwind.
    const bool timer_waited{timer.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout};
    const bool lock_waited{lock.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout};
    release.set_value();
    BOOST_CHECK(unlock.get());
    timer.get();
    lock.get();
    db.before_begin = {};
    BOOST_CHECK(timer_waited);
    BOOST_CHECK(lock_waited);
    BOOST_CHECK(db.failure.hit);
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK_EQUAL(WITH_LOCK(wallet->cs_wallet, return wallet->nRelockTime), 0);
    RemoveWallet(context, wallet, std::nullopt);
}

BOOST_FIXTURE_TEST_CASE(rescan_abort_survives_preparation, TestingSetup)
{
    auto wallet{std::make_shared<CWallet>(m_node.chain.get(), "early-abort", std::make_unique<FailingDatabase>(m_args.GetDataDirBase() / "early-abort"))};
    BOOST_REQUIRE(wallet->LoadWallet() == DBErrors::LOAD_OK);
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    const auto genesis{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Genesis()->GetBlockHash())};
    WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(0, genesis));
    BOOST_CHECK(!wallet->AbortRescan());
    {
        WalletRescanReserver reserver{*wallet};
        BOOST_REQUIRE(reserver.reserve(/*with_passphrase=*/true));
        BOOST_CHECK(wallet->IsScanningWithPassphrase());
        BOOST_CHECK(wallet->AbortRescan());
        BOOST_CHECK(!wallet->AbortRescan());
        WalletRescanReserver competing{*wallet};
        BOOST_CHECK(!competing.reserve());
        BOOST_CHECK(wallet->IsAbortingRescan());
        BOOST_CHECK(wallet->ScanForWalletTransactions(genesis, 0, {}, reserver, true, false).status == CWallet::ScanResult::USER_ABORT);
        BOOST_CHECK(!wallet->RescanFromTime(0, reserver, true));
    }
    BOOST_CHECK(!wallet->IsScanning());
    BOOST_CHECK(!wallet->IsScanningWithPassphrase());
    BOOST_CHECK(!wallet->AbortRescan());
    {
        WalletRescanReserver next{*wallet};
        BOOST_REQUIRE(next.reserve());
        BOOST_CHECK(!wallet->IsAbortingRescan());
        BOOST_CHECK(wallet->ScanForWalletTransactions(genesis, 0, {}, next, true, false).status == CWallet::ScanResult::SUCCESS);
    }

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);
    JSONRPCRequest request;
    request.context = &context;
    FlatSigningProvider provider;
    std::string error;
    auto desc{Parse("pk(" + HexStr(GenerateRandomKey(pq::SchemeId::FALCON_512).GetPubKey()) + ")", provider, error, false)};
    UniValue item{UniValue::VOBJ};
    item.pushKV("desc", desc.at(0)->ToString());
    item.pushKV("timestamp", 0);
    UniValue items{UniValue::VARR};
    items.push_back(item);
    request.params = UniValue{UniValue::VARR};
    request.params.push_back(items);
    bool aborted{false};
    auto& db{dynamic_cast<FailingDatabase&>(wallet->GetDatabase())};
    db.after_write = [&](std::string_view type) {
        // Cancel deterministically during descriptor persistence, before scanning.
        if (!aborted && type == DBKeys::WALLETDESCRIPTOR) aborted = wallet->AbortRescan();
    };
    BOOST_CHECK_EXCEPTION(importdescriptors().HandleRequest(request), UniValue, [](const UniValue& e) {
        return e["code"].getInt<int>() == -1 && e["message"].get_str() == "Rescan aborted by user.";
    });
    db.after_write = {};
    BOOST_CHECK(aborted);
    BOOST_CHECK(!wallet->IsScanning());
    // Abort stops the scan, not the descriptor transaction that already committed.
    BOOST_CHECK_EQUAL(wallet->GetAllScriptPubKeyMans().size(), 1U);
    const auto result{importdescriptors().HandleRequest(request)};
    BOOST_CHECK_MESSAGE(result[0]["success"].get_bool(), result.write());
    RemoveWallet(context, wallet, std::nullopt);
}

BOOST_AUTO_TEST_CASE(encryption_failures_survive_reopen)
{
    const SecureString pass{"old passphrase"};
    const CKey key{GenerateRandomKey(pq::SchemeId::FALCON_512)};
    unsigned int index{0};
    for (const Failure& point : std::vector<Failure>{{"begin"}, {"write", DBKeys::MASTER_KEY},
             {"write", DBKeys::WALLETDESCRIPTORCKEY}, {"erase", DBKeys::WALLETDESCRIPTORKEY},
             {"write", DBKeys::PQHD_CRYPTED_SEED}, {"erase", DBKeys::PQHD_SEED}, {"commit"}}) {
        BOOST_TEST_CONTEXT(point.operation << " " << point.record) {
            const auto path{m_args.GetDataDirBase() / fs::PathFromString(strprintf("encryption-%u", index++))};
            auto wallet{Open(path)};
            uint256 seed_id;
            {
                LOCK(wallet->cs_wallet);
                wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
                wallet->SetupDescriptorScriptPubKeyMans();
                seed_id = wallet->GetPQHDPolicy()->default_seed_id;
            }
            Import(*wallet, key);
            const auto seed{wallet->GetPQHDSeed(seed_id)};
            BOOST_REQUIRE(seed);
            Fault(*wallet) = point;
            BOOST_CHECK(!wallet->EncryptWallet(pass));
            BOOST_CHECK(Fault(*wallet).hit);
            BOOST_CHECK(!wallet->IsCrypted());
            BOOST_CHECK(!wallet->IsLocked());
            BOOST_CHECK(wallet->GetPQHDSeed(seed_id));
            CheckKey(*wallet, key.GetPubKey());
            BOOST_CHECK(!dynamic_cast<SQLiteDatabase&>(wallet->GetDatabase()).HasActiveTxn());
            wallet.reset();
            wallet = Open(path);
            BOOST_CHECK(!wallet->IsCrypted());
            CheckKey(*wallet, key.GetPubKey());
            const auto reopened_seed{wallet->GetPQHDSeed(seed_id)};
            BOOST_REQUIRE(reopened_seed);
            BOOST_CHECK(std::ranges::equal(seed->Span(), reopened_seed->Span()));
            // Consume more than the one-entry pool so recovery also exercises PQHD derivation.
            for (int i = 0; i < 2; ++i) BOOST_REQUIRE(wallet->GetNewDestination(OutputType::BECH32, ""));
            BOOST_REQUIRE(wallet->EncryptWallet(pass));
            BOOST_CHECK(wallet->IsLocked());
            BOOST_CHECK(!wallet->GetPQHDSeed(seed_id));
            wallet.reset();
            wallet = Open(path);
            BOOST_CHECK(wallet->IsLocked());
            BOOST_REQUIRE(wallet->Unlock(pass));
            CheckKey(*wallet, key.GetPubKey());
            const auto encrypted_seed{wallet->GetPQHDSeed(seed_id)};
            BOOST_REQUIRE(encrypted_seed);
            BOOST_CHECK(std::ranges::equal(seed->Span(), encrypted_seed->Span()));
        }
    }
}

BOOST_AUTO_TEST_CASE(passphrase_failures_preserve_lock_and_disk_state)
{
    const SecureString old_pass{"old passphrase"}, new_pass{"new passphrase"};
    unsigned int index{0};
    for (bool locked : {false, true}) {
        for (const Failure& point : std::vector<Failure>{{"begin"}, {"write", DBKeys::MASTER_KEY}, {"commit"}}) {
            const auto path{m_args.GetDataDirBase() / fs::PathFromString(strprintf("passphrase-%u", index++))};
            auto wallet{Open(path)};
            {
                LOCK(wallet->cs_wallet);
                wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
                wallet->SetupDescriptorScriptPubKeyMans();
            }
            BOOST_REQUIRE(wallet->EncryptWallet(old_pass));
            if (!locked) BOOST_REQUIRE(wallet->Unlock(old_pass));
            BOOST_CHECK(!wallet->ChangeWalletPassphrase(SecureString{"wrong"}, new_pass));
            BOOST_CHECK_EQUAL(wallet->IsLocked(), locked);
            Fault(*wallet) = point;
            BOOST_CHECK(!wallet->ChangeWalletPassphrase(old_pass, new_pass));
            BOOST_CHECK(Fault(*wallet).hit);
            BOOST_CHECK_EQUAL(wallet->IsLocked(), locked);
            wallet.reset();
            wallet = Open(path);
            BOOST_CHECK(!wallet->Unlock(new_pass));
            BOOST_REQUIRE(wallet->Unlock(old_pass));
            BOOST_REQUIRE(wallet->ChangeWalletPassphrase(old_pass, new_pass));
            wallet.reset();
            wallet = Open(path);
            BOOST_CHECK(!wallet->Unlock(old_pass));
            BOOST_REQUIRE(wallet->Unlock(new_pass));
        }
    }
}

// A deliberately constructed master-key record exercises successful outer
// decryption without a valid wallet key. No probabilistic password search or
// production fault hook is needed.
static CMasterKey CandidateMasterKey(const SecureString& pass, size_t size)
{
    CMasterKey record;
    record.vchSalt.assign(WALLET_CRYPTO_SALT_SIZE, 0x31);
    CCrypter crypter;
    BOOST_REQUIRE(crypter.SetKeyFromPassphrase(pass, record.vchSalt, record.nDeriveIterations, record.nDerivationMethod));
    BOOST_REQUIRE(crypter.Encrypt(CKeyingMaterial(size, 0x42), record.vchCryptedKey));
    return record;
}

BOOST_AUTO_TEST_CASE(pqhd_unlock_authenticates_master_key_before_passphrase_change)
{
    const SecureString real_pass{"real passphrase"}, false_pass{"invalid candidate"}, new_pass{"replacement"};
    for (bool mixed_keys : {false, true}) {
        const auto path{m_args.GetDataDirBase() / (mixed_keys ? "auth-mixed" : "auth-seeds")};
        auto wallet{Open(path)};
        {
            LOCK(wallet->cs_wallet);
            wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet->SetupDescriptorScriptPubKeyMans();
        }
        const CKey imported_key{GenerateRandomKey(pq::SchemeId::FALCON_512)};
        if (mixed_keys) Import(*wallet, imported_key);
        BOOST_REQUIRE(wallet->EncryptWallet(real_pass));
        BOOST_REQUIRE(wallet->Unlock(real_pass));
        std::map<uint256, CKeyingMaterial> expected_seeds;
        {
            LOCK(wallet->cs_wallet);
            for (const auto& info : wallet->ListPQHDSeeds()) {
                auto seed{wallet->GetPQHDSeed(info.seed_id)};
                BOOST_REQUIRE(seed);
                expected_seeds.emplace(info.seed_id, CKeyingMaterial(seed->Span().begin(), seed->Span().end()));
            }
        }
        BOOST_REQUIRE_GE(expected_seeds.size(), 2U);
        wallet->Lock();
        for (size_t candidate_size : {47U, 32U}) {
            const auto record{CandidateMasterKey(false_pass, candidate_size)};
            {
                LOCK(wallet->cs_wallet);
                BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteMasterKey(100, record));
                wallet->mapMasterKeys[100] = record;
            }
            for (bool locked : {true, false}) {
                if (!locked) BOOST_REQUIRE(wallet->Unlock(real_pass));
                const auto before{ReadRecords(wallet->GetDatabase())};
                BOOST_CHECK(!wallet->Unlock(false_pass));
                BOOST_CHECK_EQUAL(wallet->IsLocked(), locked);
                BOOST_CHECK(!wallet->ChangeWalletPassphrase(false_pass, new_pass));
                BOOST_CHECK_EQUAL(wallet->IsLocked(), locked);
                BOOST_CHECK(before == ReadRecords(wallet->GetDatabase()));
                wallet.reset();
                wallet = Open(path);
                BOOST_CHECK(!wallet->Unlock(false_pass));
                BOOST_REQUIRE(wallet->Unlock(real_pass));
                for (const auto& [id, expected] : expected_seeds) {
                    auto seed{wallet->GetPQHDSeed(id)};
                    BOOST_REQUIRE(seed);
                    BOOST_CHECK_EQUAL_COLLECTIONS(seed->Span().begin(), seed->Span().end(), expected.begin(), expected.end());
                }
                if (mixed_keys) CheckKey(*wallet, imported_key.GetPubKey());
                wallet->Lock();
            }
        }
        BOOST_REQUIRE(wallet->ChangeWalletPassphrase(real_pass, new_pass));
        wallet.reset();
        wallet = Open(path);
        BOOST_CHECK(!wallet->Unlock(real_pass));
        BOOST_REQUIRE(wallet->Unlock(new_pass));
        for (const auto& [id, expected] : expected_seeds) {
            auto seed{wallet->GetPQHDSeed(id)};
            BOOST_REQUIRE(seed);
            BOOST_CHECK_EQUAL_COLLECTIONS(seed->Span().begin(), seed->Span().end(), expected.begin(), expected.end());
        }
        if (mixed_keys) CheckKey(*wallet, imported_key.GetPubKey());
    }
}

BOOST_AUTO_TEST_CASE(pqhd_unlock_checks_every_encrypted_seed)
{
    const SecureString pass{"real passphrase"};
    const auto path{m_args.GetDataDirBase() / "auth-corrupt-seed"};
    auto wallet{Open(path)};
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetupDescriptorScriptPubKeyMans();
    }
    BOOST_REQUIRE(wallet->EncryptWallet(pass));
    CKeyingMaterial master;
    uint256 id;
    {
        LOCK(wallet->cs_wallet);
        const auto& record{wallet->mapMasterKeys.begin()->second};
        CCrypter crypter;
        BOOST_REQUIRE(crypter.SetKeyFromPassphrase(pass, record.vchSalt, record.nDeriveIterations, record.nDerivationMethod));
        BOOST_REQUIRE(crypter.Decrypt(record.vchCryptedKey, master));
        const auto seeds{wallet->ListPQHDSeeds()};
        BOOST_REQUIRE_GE(seeds.size(), 2U);
        // Leave the first seed valid: checking just one seed is insufficient.
        id = seeds.back().seed_id;
    }
    PQHDCryptedSeed original;
    BOOST_REQUIRE(wallet->GetDatabase().MakeBatch()->Read(std::make_pair(DBKeys::PQHD_CRYPTED_SEED, id), original));
    for (size_t seed_size : {31U, 32U, 33U}) {
        PQHDCryptedSeed damaged{original};
        // Valid encryption of invalid seed material tests both length and ID
        // validation independently of ciphertext padding errors.
        BOOST_REQUIRE(EncryptSecret(master, CKeyingMaterial(seed_size, 0x63), id, damaged.crypted_seed));
        BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteCryptedPQHDSeed(id, damaged));
        if (damaged.crypted_seed.size() != 48) {
            const auto records = ReadRecords(wallet->GetDatabase());
            wallet.reset();
            wallet = std::make_unique<CWallet>(m_node.chain.get(), "", std::make_unique<FailingDatabase>(path));
            BOOST_CHECK(wallet->LoadWallet() == DBErrors::CORRUPT);
            BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
            BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteCryptedPQHDSeed(id, original));
            wallet.reset();
            wallet = Open(path);
            BOOST_REQUIRE(wallet->Unlock(pass));
            wallet->Lock();
            continue;
        }
        wallet.reset();
        wallet = Open(path);
        const auto before{ReadRecords(wallet->GetDatabase())};
        BOOST_CHECK(!wallet->Unlock(pass));
        BOOST_CHECK(wallet->IsLocked());
        BOOST_CHECK(!wallet->ChangeWalletPassphrase(pass, SecureString{"replacement"}));
        BOOST_CHECK(before == ReadRecords(wallet->GetDatabase()));
        BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteCryptedPQHDSeed(id, original));
        wallet.reset();
        wallet = Open(path);
        BOOST_REQUIRE(wallet->Unlock(pass));
        BOOST_REQUIRE(wallet->GetPQHDSeed(id));
        wallet->Lock();
    }
}

BOOST_AUTO_TEST_CASE(empty_encrypted_wallet_rejects_wrong_length_master_key)
{
    const SecureString pass{"empty wallet"}, false_pass{"invalid candidate"}, new_pass{"replacement"};
    const auto path{m_args.GetDataDirBase() / "auth-empty"};
    auto wallet{Open(path)};
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
    }
    BOOST_REQUIRE(wallet->EncryptWallet(pass));
    const auto record{CandidateMasterKey(false_pass, 47)};
    BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteMasterKey(100, record));
    WITH_LOCK(wallet->cs_wallet, wallet->mapMasterKeys[100] = record);
    const auto before{ReadRecords(wallet->GetDatabase())};
    BOOST_CHECK(!wallet->Unlock(false_pass));
    BOOST_CHECK(!wallet->ChangeWalletPassphrase(false_pass, new_pass));
    BOOST_CHECK(before == ReadRecords(wallet->GetDatabase()));
    BOOST_REQUIRE(wallet->ChangeWalletPassphrase(pass, new_pass));
    wallet.reset();
    wallet = Open(path);
    BOOST_REQUIRE(wallet->Unlock(new_pass));
    // The existing empty-wallet format has no encrypted secret to verify.
    // Keep it usable and authenticate against seeds once they are imported.
    std::array<unsigned char, 32> bytes{};
    bytes.fill(0x24);
    uint256 seed_id;
    {
        LOCK(wallet->cs_wallet);
        const auto imported{wallet->ImportPQHDSeed(bytes)};
        BOOST_REQUIRE(imported);
        seed_id = imported->seed_id;
        BOOST_REQUIRE(wallet->SetPQHDSeedDefaults(seed_id, seed_id));
    }
    wallet.reset();
    wallet = Open(path);
    BOOST_REQUIRE(wallet->Unlock(new_pass));
    BOOST_REQUIRE(wallet->GetPQHDSeed(seed_id));
}

BOOST_AUTO_TEST_CASE(pqhd_private_seed_restrictions_preserve_state)
{
    size_t index{0};
    for (uint64_t flags : std::array<uint64_t, 3>{WALLET_FLAG_DISABLE_PRIVATE_KEYS, WALLET_FLAG_EXTERNAL_SIGNER,
                           WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_EXTERNAL_SIGNER}) {
        const auto path{m_args.GetDataDirBase() / fs::PathFromString(strprintf("seed-restricted-%u", index++))};
        auto wallet{Open(path)};
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET | flags);
        std::array<unsigned char, 32> bytes{};
        bytes.fill(0x53);
        const auto id{pqhd::ComputeSeedID32AsUint256(bytes)};
        const auto records{ReadRecords(wallet->GetDatabase())};
        const auto state{WalletReconciliationTestAccess::Snapshot(*wallet)};
        BOOST_CHECK(!wallet->ImportPQHDSeed(bytes));
        PQHDSeed seed;
        seed.seed.assign(bytes.begin(), bytes.end());
        BOOST_CHECK(!wallet->LoadPQHDSeed(id, std::move(seed)));
        PQHDCryptedSeed encrypted;
        encrypted.crypted_seed.assign(48, 0x42);
        BOOST_CHECK(!wallet->LoadPQHDCryptedSeed(id, std::move(encrypted)));
        BOOST_CHECK(!wallet->SetPQHDSeedDefaults(id, id));
        BOOST_CHECK(!wallet->SetPQHDPolicy(7, 7));
        WalletBatch batch(wallet->GetDatabase());
        BOOST_CHECK_THROW(wallet->SetupOwnDescriptorScriptPubKeyMans(batch), std::runtime_error);
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    }
}

BOOST_AUTO_TEST_CASE(pqhd_restricted_seed_records_fail_load_without_rewrite)
{
    for (bool encrypted : {false, true}) {
        const auto path{m_args.GetDataDirBase() / (encrypted ? "restricted-crypted" : "restricted-plain")};
        auto wallet{Open(path)};
        {
            LOCK(wallet->cs_wallet);
            wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet->SetupDescriptorScriptPubKeyMans();
        }
        if (encrypted) BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"pass"}));
        const auto flags{WalletReconciliationTestAccess::Snapshot(*wallet).flags};
        BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteWalletFlags(flags | WALLET_FLAG_DISABLE_PRIVATE_KEYS));
        const auto records{ReadRecords(wallet->GetDatabase())};
        wallet.reset();
        wallet = std::make_unique<CWallet>(m_node.chain.get(), "", std::make_unique<FailingDatabase>(path));
        BOOST_CHECK(wallet->LoadWallet() == DBErrors::CORRUPT);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        // Repair only the intentionally invalid flag; seed records survive.
        BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteWalletFlags(flags));
        wallet.reset();
        wallet = Open(path);
        if (encrypted) BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
        LOCK(wallet->cs_wallet);
        for (const auto& seed : wallet->ListPQHDSeeds()) BOOST_REQUIRE(wallet->GetPQHDSeed(seed.seed_id));
    }
}

BOOST_AUTO_TEST_CASE(pqhd_consumption_survives_locked_topup_and_write_failure)
{
    for (bool internal : {false, true}) {
        const auto path{m_args.GetDataDirBase() / (internal ? "consume-change" : "consume-receive")};
        auto wallet{Open(path)};
        {
            LOCK(wallet->cs_wallet);
            wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet->SetupDescriptorScriptPubKeyMans();
        }
        BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"pass"}));
        auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, internal));
        BOOST_REQUIRE(manager);
        const auto scripts{manager->GetScriptPubKeys()};
        BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
        const auto script{*scripts.begin()};
        const auto records{ReadRecords(wallet->GetDatabase())};
        Fault(*wallet) = {"write", DBKeys::WALLETDESCRIPTOR};
        BOOST_CHECK_THROW(manager->MarkUnusedAddresses(script), std::runtime_error);
        BOOST_CHECK(Fault(*wallet).hit);
        BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 1);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(wallet->IsWalletRecoveryRequired());
        BOOST_CHECK(!wallet->CanGetAddresses(false));
        BOOST_CHECK(!wallet->CanGetAddresses(true));
        BOOST_CHECK(!manager->GetNewDestination(OutputType::BECH32));
        manager->ReturnDestination(0, internal, CNoDestination{});
        BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 1);
        Fault(*wallet) = {};
        // Retrying the same consumption must persist the already-advanced index.
        manager->MarkUnusedAddresses(script);
        // A successful retry of one output does not establish that the rest of
        // its transaction/block was processed. Recovery remains latched.
        BOOST_CHECK(wallet->IsWalletRecoveryRequired());
        wallet.reset();
        wallet = Open(path);
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, internal));
        BOOST_REQUIRE(manager);
        BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 1);
        BOOST_CHECK(!manager->GetNewDestination(OutputType::BECH32));
        BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
        const auto next{manager->GetNewDestination(OutputType::BECH32)};
        BOOST_REQUIRE(next);
        BOOST_CHECK(GetScriptForDestination(*next) != script);
    }
}

BOOST_FIXTURE_TEST_CASE(pqhd_failed_observation_preserves_replay_checkpoint, RegTestingSetup)
{
    SetMockTime(Params().GenesisBlock().nTime);
    for (bool internal : {false, true}) {
        for (const auto& [record, historical] : std::vector<std::pair<std::string, bool>>{
                 {DBKeys::WALLETDESCRIPTOR, false}, {DBKeys::TX, false}, {DBKeys::WALLETDESCRIPTOR, true}}) {
            // Explicit history requests must survive reload even when the
            // descriptor birthday is later than the failed observation.
            SetMockTime(Params().GenesisBlock().nTime + (historical ? 86400 : 0));
            const auto path{m_args.GetDataDirBase() / fs::PathFromString(strprintf("replay-%d-%s-%d", internal, record, historical))};
            auto open = [&] {
                auto wallet{std::make_shared<CWallet>(m_node.chain.get(), "replay", std::make_unique<FailingDatabase>(path))};
                wallet->m_keypool_size = 2;
                BOOST_REQUIRE(wallet->LoadWallet() == DBErrors::LOAD_OK);
                return wallet;
            };
            auto wallet{open()};
            {
                LOCK(wallet->cs_wallet);
                wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
                wallet->SetupDescriptorScriptPubKeyMans();
                const auto* tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())};
                wallet->SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash());
            }
            BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"pass"}));
            auto* manager{dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, internal))};
            BOOST_REQUIRE(manager);
            std::vector<CScript> scripts;
            FlatSigningProvider provider;
            BOOST_REQUIRE(WITH_LOCK(manager->cs_desc_man, return manager->ExpandPublicFromCache(1, scripts, provider)));
            BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
            const auto used_script{scripts.front()};
            CBlockLocator before;
            BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).ReadBestBlock(before));
            auto check_checkpoint = [&] {
                CBlockLocator after;
                BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).ReadBestBlock(after));
                BOOST_CHECK(before.vHave == after.vHave);
            };

            node::BlockAssembler::Options options;
            options.coinbase_output_script = used_script;
            auto block{PrepareBlock(m_node, options)};
            BOOST_REQUIRE(!MineBlock(m_node, block).IsNull());
            const auto* tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())};
            auto& failure{PersistenceSetup::Fault(*wallet)};
            failure = {"write", record};
            if (historical) {
                // A user-requested historical scan may begin behind an already
                // saved tip; it must first durably rewind its replay checkpoint.
                WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash()));
                WalletRescanReserver reserver{*wallet};
                BOOST_REQUIRE(reserver.reserve());
                failure = {"write", DBKeys::BESTBLOCK_NOMERKLE};
                BOOST_CHECK_THROW(wallet->ScanForWalletTransactions(tip->GetBlockHash(), tip->nHeight, {}, reserver, true, false), std::runtime_error);
                BOOST_REQUIRE(failure.hit);
                BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 0);
                BOOST_CHECK(WITH_LOCK(wallet->cs_wallet, return !wallet->GetWalletTx(block->vtx.front()->GetHash())));
                BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
                // No observation was made before the failed rewind. Once the
                // rewind can be persisted, exercise the consumption failure.
                failure = {"write", record};
                BOOST_CHECK_THROW(wallet->ScanForWalletTransactions(tip->GetBlockHash(), tip->nHeight, {}, reserver, true, false), std::runtime_error);
            } else {
                BOOST_CHECK_THROW(wallet->blockConnected(ChainstateRole::NORMAL, kernel::MakeBlockInfo(tip, block.get())), std::runtime_error);
            }
            BOOST_REQUIRE(failure.hit);
            BOOST_CHECK(wallet->IsWalletRecoveryRequired());
            BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
            BOOST_CHECK(!wallet->GetNewChangeDestination(OutputType::BECH32));
            check_checkpoint();

            // Even after storage recovers, a later block, explicit checkpoint,
            // or backup/unload must not skip the unsuccessfully processed block.
            failure = {};
            options.coinbase_output_script = CScript() << OP_TRUE;
            auto later{PrepareBlock(m_node, options)};
            BOOST_REQUIRE(!MineBlock(m_node, later).IsNull());
            const auto* later_tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())};
            wallet->blockConnected(ChainstateRole::NORMAL, kernel::MakeBlockInfo(later_tip, later.get()));
            WITH_LOCK(wallet->cs_wallet, wallet->WriteBestBlock());
            BOOST_REQUIRE(wallet->BackupWallet(fs::PathToString(path / "backup.dat")));
            check_checkpoint();
            wallet.reset(); // No retry of the failed observation before reopen.

            wallet = open();
            // A failure during startup replay must also preserve the old
            // checkpoint despite AttachChain's in-memory tip initialization.
            PersistenceSetup::Fault(*wallet) = {"write", DBKeys::WALLETDESCRIPTOR};
            bilingual_str error;
            BOOST_CHECK_THROW(WalletReconciliationTestAccess::Attach(wallet, *m_node.chain, error), std::runtime_error);
            BOOST_CHECK(PersistenceSetup::Fault(*wallet).hit);
            WITH_LOCK(wallet->cs_wallet, wallet->WriteBestBlock());
            check_checkpoint();
            WalletReconciliationTestAccess::Detach(*wallet);
            wallet.reset();

            // Missing history must fail loading without replacing the replay
            // checkpoint with the observed tip. Restore only this test's flags.
            wallet = open();
            auto* missing{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain()[tip->nHeight])};
            const auto status{WITH_LOCK(cs_main, return missing->nStatus)};
            const bool was_pruned{WITH_LOCK(cs_main, return m_node.chainman->m_blockman.m_have_pruned)};
            {
                LOCK(cs_main);
                missing->nStatus &= ~BLOCK_HAVE_DATA;
                m_node.chainman->m_blockman.m_have_pruned = true;
            }
            bool attached{true};
            BOOST_CHECK_NO_THROW(attached = WalletReconciliationTestAccess::Attach(wallet, *m_node.chain, error));
            {
                LOCK(cs_main);
                missing->nStatus = status;
                m_node.chainman->m_blockman.m_have_pruned = was_pruned;
            }
            BOOST_CHECK(!attached);
            BOOST_CHECK(error.original.find("Prune:") != std::string::npos);
            WITH_LOCK(wallet->cs_wallet, wallet->WriteBestBlock());
            check_checkpoint();
            BOOST_CHECK_EQUAL(wallet.use_count(), 1);
            WalletReconciliationTestAccess::Detach(*wallet);
            wallet.reset();

            wallet = open();
            BOOST_REQUIRE(WalletReconciliationTestAccess::Attach(wallet, *m_node.chain, error));
            WalletReconciliationTestAccess::Detach(*wallet);
            BOOST_CHECK(!wallet->IsWalletRecoveryRequired());
            manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, internal));
            BOOST_REQUIRE(manager);
            BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 2);
            BOOST_REQUIRE(WITH_LOCK(wallet->cs_wallet, return wallet->GetWalletTx(block->vtx.front()->GetHash()) != nullptr));
            CBlockLocator recovered;
            BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).ReadBestBlock(recovered));
            BOOST_CHECK_EQUAL(recovered.vHave.front(), later->GetHash());
            BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
            const auto destination{manager->GetNewDestination(OutputType::BECH32)};
            BOOST_REQUIRE(destination);
            BOOST_CHECK(GetScriptForDestination(*destination) != used_script);

            // Recovery retains the actual signing capability for the received output.
            CMutableTransaction spend;
            spend.vin.emplace_back(COutPoint{block->vtx.front()->GetHash(), 0});
            spend.vout.emplace_back(block->vtx.front()->vout[0].nValue - 1000, GetScriptForDestination(*destination));
            std::map<COutPoint, Coin> coins;
            coins.emplace(spend.vin[0].prevout, Coin{block->vtx.front()->vout[0], tip->nHeight, true});
            std::map<int, bilingual_str> errors;
            BOOST_CHECK(wallet->SignTransaction(spend, coins, SIGHASH_ALL, errors));
            BOOST_CHECK(errors.empty());
        }
    }
}

BOOST_AUTO_TEST_CASE(pqhd_allocation_and_return_check_descriptor_writes)
{
    const auto path{m_args.GetDataDirBase() / "reservation-writes"};
    auto wallet{Open(path)};
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetupDescriptorScriptPubKeyMans();
    }
    BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"pass"}));
    auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
    BOOST_REQUIRE(manager);
    const auto records{ReadRecords(wallet->GetDatabase())};
    manager->ReturnDestination(-1, false, CNoDestination{});
    manager->ReturnDestination(int64_t{1} << 32, false, CNoDestination{});
    BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 0);
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    // Skip the successful no-growth TopUp write and fail the reservation write.
    Fault(*wallet) = {"write", DBKeys::WALLETDESCRIPTOR, false, 1};
    BOOST_CHECK(!manager->GetNewDestination(OutputType::BECH32));
    BOOST_CHECK(Fault(*wallet).hit);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 0);
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    Fault(*wallet) = {};
    const auto reserved{manager->GetNewDestination(OutputType::BECH32)};
    BOOST_REQUIRE(reserved);
    const auto reserved_records{ReadRecords(wallet->GetDatabase())};
    Fault(*wallet) = {"write", DBKeys::WALLETDESCRIPTOR};
    BOOST_CHECK_NO_THROW(manager->ReturnDestination(0, false, *reserved));
    BOOST_CHECK(Fault(*wallet).hit);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 1);
    BOOST_CHECK(reserved_records == ReadRecords(wallet->GetDatabase()));
    wallet.reset();
    wallet = Open(path);
    manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
    BOOST_REQUIRE(manager);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().next_index), 1);
    BOOST_CHECK(!manager->GetNewDestination(OutputType::BECH32));
}

BOOST_AUTO_TEST_CASE(pqhd_topup_failure_restores_complete_state)
{
    size_t scenario{0};
    for (const Failure& fault : {Failure{"begin"}, Failure{"write", "walletdescriptorpubkeycache", false, 1},
                                Failure{"write", DBKeys::WALLETDESCRIPTOR}, Failure{"commit"}}) {
        const auto path = m_args.GetDataDirBase() / fs::PathFromString(strprintf("topup-%u", scenario++));
        auto wallet = Open(path);
        WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
        WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
        auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_REQUIRE(manager->GetSigningProviderForScript(*manager->GetScriptPubKeys().begin()));
        const auto records = ReadRecords(wallet->GetDatabase());
        const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
        Fault(*wallet) = fault;
        bool success{false};
        // Match wallet entry points: seed derivation takes cs_wallet before cs_desc_man.
        try { LOCK(wallet->cs_wallet); success = manager->TopUp(4); } catch (const std::runtime_error&) {}
        BOOST_CHECK(!success);
        BOOST_CHECK(Fault(*wallet).hit);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
        wallet.reset();
        wallet = Open(path);
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_CHECK_EQUAL(manager->GetEndRange(), 1);
        BOOST_REQUIRE(WITH_LOCK(wallet->cs_wallet, return manager->TopUp(4)));
        BOOST_CHECK_EQUAL(manager->GetEndRange(), 4);
        wallet.reset();
        wallet = Open(path);
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_CHECK_EQUAL(manager->GetEndRange(), 4);
    }
}

BOOST_AUTO_TEST_CASE(pqhd_wallet_refill_is_atomic_across_managers)
{
    const auto path = m_args.GetDataDirBase() / "wallet-refill";
    auto wallet = Open(path);
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
    const auto records = ReadRecords(wallet->GetDatabase());
    // A prior manager has completed its two new cache writes when this fails.
    Fault(*wallet) = {"write", "walletdescriptorpubkeycache", false, 3};
    BOOST_CHECK_THROW(wallet->TopUpKeyPool(3), std::runtime_error);
    BOOST_CHECK(Fault(*wallet).hit);
    BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    wallet.reset();
    wallet = Open(path);
    for (auto* manager : wallet->GetActiveScriptPubKeyMans()) {
        BOOST_CHECK_EQUAL(dynamic_cast<DescriptorScriptPubKeyMan*>(manager)->GetEndRange(), 1);
    }
    BOOST_REQUIRE(wallet->TopUpKeyPool(3));
    wallet.reset();
    wallet = Open(path);
    for (auto* manager : wallet->GetActiveScriptPubKeyMans()) {
        BOOST_CHECK_EQUAL(dynamic_cast<DescriptorScriptPubKeyMan*>(manager)->GetEndRange(), 3);
    }
}

BOOST_AUTO_TEST_CASE(pqhd_abandoned_transaction_rolls_back)
{
    auto wallet = Open(m_args.GetDataDirBase() / "abandoned-topup");
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetupDescriptorScriptPubKeyMans();
    auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
    BOOST_REQUIRE(manager);
    const auto records = ReadRecords(wallet->GetDatabase());
    const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
    for (bool transient_failure : {false, true}) {
        auto descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
        descriptor.range_end = 3;
        if (transient_failure) Fault(*wallet) = {"abort"};
        BOOST_CHECK(!RunWithinTxn(wallet->GetDatabase(), "abort import", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_REQUIRE(wallet->AddWalletDescriptor(descriptor, {}, "", false, &batch));
            return false;
        }));
        if (transient_failure) BOOST_CHECK(Fault(*wallet).hit);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
    }
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(pqhd_persistent_abort_failure_stops_before_reuse)
{
    const auto path = m_args.GetDataDirBase() / "abort-fail-stop";
    auto wallet = Open(path);
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    const auto records = ReadRecords(wallet->GetDatabase());
    wallet.reset();
    const pid_t pid = fork();
    BOOST_REQUIRE(pid >= 0);
    if (pid == 0) {
        std::signal(SIGABRT, SIG_DFL); // Do not inherit the Boost.Test signal handler.
        const rlimit no_core{0, 0};
        setrlimit(RLIMIT_CORE, &no_core);
        auto child = Open(path);
        LOCK(child->cs_wallet);
        auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(child->GetScriptPubKeyMan(OutputType::BECH32, false));
        if (!manager) _exit(2);
        auto descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
        descriptor.range_end = 3;
        Fault(*child) = {"abort", "", false, 0, true};
        RunWithinTxn(child->GetDatabase(), "abort failure", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(child->cs_wallet) {
            if (!child->AddWalletDescriptor(descriptor, {}, "", false, &batch)) _exit(3);
            return false;
        });
        _exit(4);
    }
    int status{0};
    BOOST_REQUIRE_EQUAL(waitpid(pid, &status, 0), pid);
    BOOST_REQUIRE(WIFSIGNALED(status));
    BOOST_CHECK_EQUAL(WTERMSIG(status), SIGABRT);
    wallet = Open(path);
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
    BOOST_REQUIRE(manager);
    BOOST_REQUIRE(WITH_LOCK(wallet->cs_wallet, return manager->TopUp(3)));
}
#endif

BOOST_AUTO_TEST_CASE(pqhd_topup_derivation_failure_aborts_partial_progress)
{
    auto wallet = Open(m_args.GetDataDirBase() / "topup-derivation-failure");
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
    BOOST_REQUIRE(manager);
    const auto records = ReadRecords(wallet->GetDatabase());
    const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
    std::map<uint256, CKeyingMaterial> seeds;
    bool withheld{false};
    auto& db = dynamic_cast<FailingDatabase&>(wallet->GetDatabase());
    db.after_write = [&](std::string_view type) {
        if (!withheld && type == "walletdescriptorpubkeycache") {
            WalletReconciliationTestAccess::SwapSeeds(*wallet, seeds);
            withheld = true;
        }
    };
    BOOST_CHECK(WITH_LOCK(wallet->cs_wallet, return !manager->TopUp(4)));
    BOOST_REQUIRE(withheld);
    WalletReconciliationTestAccess::SwapSeeds(*wallet, seeds);
    db.after_write = {};
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
    BOOST_REQUIRE(WITH_LOCK(wallet->cs_wallet, return manager->TopUp(4)));
    BOOST_CHECK_EQUAL(manager->GetEndRange(), 4);
}

BOOST_AUTO_TEST_CASE(descriptor_import_failure_is_atomic)
{
    size_t scenario{0};
    for (const Failure& fault : {Failure{"begin"}, Failure{"write", DBKeys::WALLETDESCRIPTORKEY},
                                Failure{"write", DBKeys::WALLETDESCRIPTOR}, Failure{"write", DBKeys::NAME},
                                Failure{"write", DBKeys::PURPOSE}, Failure{"commit"}}) {
        const auto path = m_args.GetDataDirBase() / fs::PathFromString(strprintf("import-%u", scenario++));
        auto wallet = Open(path);
        WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET));
        const auto key = GenerateRandomKey(pq::SchemeId::FALCON_512);
        FlatSigningProvider provider;
        std::string error;
        auto parsed = Parse("wpkh(" + EncodeSecret(key) + ")", provider, error, false);
        BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
        WalletDescriptor descriptor(std::move(parsed[0]), 123, 0, 1, 0);
        const auto records = ReadRecords(wallet->GetDatabase());
        const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
        Fault(*wallet) = fault;
        bool success{false};
        try { LOCK(wallet->cs_wallet); success = wallet->AddWalletDescriptor(descriptor, provider, "imported", false).has_value(); }
        catch (const std::runtime_error&) {}
        BOOST_CHECK(!success);
        BOOST_CHECK(Fault(*wallet).hit);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
        wallet.reset();
        wallet = Open(path);
        BOOST_CHECK(wallet->GetAllScriptPubKeyMans().empty());
        WITH_LOCK(wallet->cs_wallet, BOOST_REQUIRE(wallet->AddWalletDescriptor(descriptor, provider, "imported", false)));
        wallet.reset();
        wallet = Open(path);
        CheckKey(*wallet, key.GetPubKey());
    }
}

BOOST_AUTO_TEST_CASE(pqhd_descriptor_update_failure_restores_cache_and_bindings)
{
    size_t scenario{0};
    for (const Failure& fault : {Failure{"write", "walletdescriptorpubkeycache", false, 1},
                                Failure{"write", DBKeys::ACTIVEINTERNALSPK}, Failure{"commit"}}) {
        const auto path = m_args.GetDataDirBase() / fs::PathFromString(strprintf("update-atomic-%u", scenario++));
        auto wallet = Open(path);
        WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
        WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
        auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_REQUIRE(manager->GetSigningProviderForScript(*manager->GetScriptPubKeys().begin()));
        const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
        const auto records = ReadRecords(wallet->GetDatabase());
        WalletDescriptor descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
        descriptor.range_end = 4;
        descriptor.creation_time = 1;
        int notifications{0};
        auto addresses_changed = manager->NotifyCanGetAddressesChanged.connect([&] { ++notifications; });
        auto birth_changed = manager->NotifyFirstKeyTimeChanged.connect([&](const ScriptPubKeyMan*, int64_t) { ++notifications; });
        Fault(*wallet) = fault;
        bool success{false};
        try {
            LOCK(wallet->cs_wallet);
            success = RunWithinTxn(wallet->GetDatabase(), "test descriptor update", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
                if (!wallet->AddWalletDescriptor(descriptor, {}, "", false, &batch)) return false;
                wallet->AddActiveScriptPubKeyMan(manager->GetID(), OutputType::BECH32, true, &batch);
                return true;
            });
        } catch (const std::runtime_error&) {}
        BOOST_CHECK(!success);
        BOOST_CHECK_EQUAL(notifications, 0);
        BOOST_CHECK(Fault(*wallet).hit);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
        wallet.reset();
        wallet = Open(path);
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_CHECK_EQUAL(manager->GetEndRange(), 1);
        descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
        descriptor.range_end = 4;
        WITH_LOCK(wallet->cs_wallet, BOOST_REQUIRE(wallet->AddWalletDescriptor(descriptor, {}, "", false)));
        BOOST_CHECK_EQUAL(manager->GetEndRange(), 4);
        wallet.reset();
        wallet = Open(path);
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_CHECK_EQUAL(manager->GetEndRange(), 4);
    }
}

BOOST_AUTO_TEST_CASE(pqhd_descriptor_update_notifications_follow_commit)
{
    for (const bool commit : {false, true}) {
        const auto path = m_args.GetDataDirBase() / (commit ? "update-notify-commit" : "update-notify-abort");
        auto wallet = Open(path);
        {
            LOCK(wallet->cs_wallet);
            wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet->SetupDescriptorScriptPubKeyMans();
        }
        auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        auto descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
        const int64_t original_time = descriptor.creation_time;
        BOOST_REQUIRE_GT(original_time, 2);
        std::vector<int64_t> notifications;
        auto connection = manager->NotifyFirstKeyTimeChanged.connect([&](const ScriptPubKeyMan* source, int64_t time) {
            BOOST_CHECK(source == manager);
            notifications.push_back(time);
        });
        {
            LOCK(wallet->cs_wallet);
            WalletBatch batch{wallet->GetDatabase()};
            BOOST_REQUIRE(batch.TxnBegin());
            // Each committed update must publish its own timestamp, even when
            // another update changes the descriptor before the batch commits.
            for (const int64_t time : {original_time - 1, original_time - 2}) {
                descriptor.creation_time = time;
                BOOST_REQUIRE(wallet->AddWalletDescriptor(descriptor, {}, "", false, &batch));
                BOOST_CHECK(notifications.empty());
            }
            if (commit) {
                BOOST_REQUIRE(batch.TxnCommit());
                const std::vector<int64_t> expected{original_time - 1, original_time - 2};
                BOOST_CHECK(notifications == expected);
            } else {
                Fault(*wallet) = {"commit"};
                BOOST_CHECK(!batch.TxnCommit());
                BOOST_CHECK(Fault(*wallet).hit);
                BOOST_CHECK(notifications.empty());
                BOOST_REQUIRE(batch.TxnAbort());
                BOOST_CHECK(notifications.empty());
                Fault(*wallet) = {};
            }
        }
        connection.disconnect();
        const int64_t expected_time = commit ? original_time - 2 : original_time;
        BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().creation_time), expected_time);
        wallet.reset();
        wallet = Open(path);
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_CHECK_EQUAL(WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor().creation_time), expected_time);
    }
}

BOOST_AUTO_TEST_CASE(pqhd_import_capabilities_and_failures)
{
    const auto path = m_args.GetDataDirBase() / "import-capabilities";
    auto wallet = Open(path);
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    std::array<unsigned char, 32> seed{};
    uint256 seed_id;
    {
        LOCK(wallet->cs_wallet);
        const auto imported = wallet->ImportPQHDSeed(seed);
        BOOST_REQUIRE(imported);
        seed_id = imported->seed_id;
    }
    BOOST_CHECK(wallet->HavePQHDSeed(seed_id));
    BOOST_CHECK(!wallet->HavePQHDSeed(uint256::ONE));
    const auto key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    const auto parse = [&](const std::string& expression) {
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(expression, keys, error, false);
        BOOST_REQUIRE_MESSAGE(parsed.size() == 1, error);
        return WalletDescriptor(std::move(parsed[0]), 1, 5, 5, 5);
    };
    const auto ref = [&](const uint256& id) {
        return "pqhd(" + id.GetHex() + ")/10007h/6868h/7h/42h/0h/*h";
    };
    auto public_desc = parse("wpkh(" + HexStr(key.GetPubKey()) + ")");
    DescriptorScriptPubKeyMan public_manager(*wallet, public_desc, 1);
    BOOST_CHECK(!public_manager.HavePrivateKeys()); // Unrelated wallet seed is irrelevant.
    auto missing_desc = parse("wpkh(" + ref(uint256::ONE) + ")");
    DescriptorScriptPubKeyMan missing_manager(*wallet, missing_desc, 1);
    BOOST_CHECK(!missing_manager.HavePrivateKeys());
    BOOST_CHECK(!missing_manager.CanGetAddresses());
    auto mixed_desc = parse("wsh(multi(2," + ref(seed_id) + "," + ref(uint256::ONE) + "))");
    DescriptorScriptPubKeyMan mixed_manager(*wallet, mixed_desc, 1);
    BOOST_CHECK(mixed_manager.HavePrivateKeys()); // Some private material, not full derivation.
    BOOST_CHECK(!mixed_manager.CanGetAddresses());
    auto descriptor = parse("wpkh(" + ref(seed_id) + ")");
    descriptor.range_end = 8;
    const auto records = ReadRecords(wallet->GetDatabase());
    const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
    for (const Failure& fault : {Failure{"write", "walletdescriptorpubkeycache", false, 1}, Failure{"commit"}}) {
        Fault(*wallet) = fault;
        bool success{false};
        try { LOCK(wallet->cs_wallet); success = wallet->AddWalletDescriptor(descriptor, {}, "", false).has_value(); }
        catch (const std::runtime_error&) {}
        BOOST_CHECK(!success);
        BOOST_CHECK(Fault(*wallet).hit);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
        wallet.reset();
        wallet = Open(path);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(wallet->HavePQHDSeed(seed_id));
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
    }
    DescriptorScriptPubKeyMan* imported;
    {
        LOCK(wallet->cs_wallet);
        auto result = wallet->AddWalletDescriptor(descriptor, {}, "", false);
        BOOST_REQUIRE(result);
        imported = &result->get();
    }
    BOOST_CHECK_EQUAL(imported->GetEndRange(), 8);
    BOOST_CHECK_EQUAL(imported->GetScriptPubKeys().size(), 3U);
    BOOST_CHECK(imported->HavePrivateKeys());
    FlatSigningProvider expanded;
    std::vector<CScript> scripts;
    const auto saved = WITH_LOCK(imported->cs_desc_man, return imported->GetWalletDescriptor());
    BOOST_REQUIRE(saved.descriptor->ExpandFromCache(5, saved.cache, scripts, expanded));
    BOOST_REQUIRE(!expanded.pubkeys.empty());
    auto provider = imported->GetSolvingProvider(scripts.at(0));
    BOOST_REQUIRE(provider);
    for (const auto& [id, pubkey] : expanded.pubkeys) {
        BOOST_CHECK(!provider->HaveKey(id)); // Public solving does not imply signing.
        auto private_provider = imported->GetSigningProvider(pubkey, /*include_private=*/true);
        BOOST_REQUIRE(private_provider);
        BOOST_CHECK(private_provider->HaveKey(id));
    }
    BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"pass"}));
    BOOST_CHECK(imported->HavePrivateKeys()); // Ownership survives locking.
    BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
    BOOST_REQUIRE(wallet->Lock());
    WITH_LOCK(wallet->cs_wallet, BOOST_REQUIRE(wallet->AddWalletDescriptor(descriptor, {}, "", false)));
    const auto locked_state = WalletReconciliationTestAccess::Snapshot(*wallet);
    const auto locked_records = ReadRecords(wallet->GetDatabase());
    descriptor.range_end = 9;
    WITH_LOCK(wallet->cs_wallet, BOOST_CHECK(!wallet->AddWalletDescriptor(descriptor, {}, "", false)));
    BOOST_CHECK(locked_state == WalletReconciliationTestAccess::Snapshot(*wallet));
    BOOST_CHECK(locked_records == ReadRecords(wallet->GetDatabase()));
    wallet.reset();
    wallet = Open(path);
    BOOST_CHECK(wallet->HavePQHDSeed(seed_id));
    BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
    WITH_LOCK(wallet->cs_wallet, BOOST_REQUIRE(wallet->AddWalletDescriptor(descriptor, {}, "", false)));
    wallet.reset();
    wallet = Open(path);
    BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
    auto* reloaded = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(descriptor.id));
    BOOST_REQUIRE(reloaded);
    BOOST_CHECK_EQUAL(reloaded->GetEndRange(), 9);
}

BOOST_AUTO_TEST_CASE(pqhd_active_import_survives_reload_and_policy_rollback)
{
    const auto path = m_args.GetDataDirBase() / "active-import";
    auto wallet = Open(path);
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    const auto seed_id = WITH_LOCK(wallet->cs_wallet, return wallet->GetPQHDPolicy()->default_seed_id);
    FlatSigningProvider keys;
    std::string error;
    auto parsed = Parse("wpkh(pqhd(" + seed_id.GetHex() + ")/10007h/6868h/7h/42h/0h/*h)", keys, error, false);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    WalletDescriptor descriptor(std::move(parsed[0]), 1, 5, 7, 5);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(RunWithinTxn(wallet->GetDatabase(), "active import test", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            auto result = wallet->AddWalletDescriptor(descriptor, {}, "", false, &batch);
            if (!result) return false;
            wallet->AddActiveScriptPubKeyMan(result->get().GetID(), OutputType::BECH32, false, &batch);
            return true;
        }));
    }
    const auto records = ReadRecords(wallet->GetDatabase());
    wallet.reset();
    wallet = Open(path);
    BOOST_CHECK_EQUAL(wallet->GetScriptPubKeyMan(OutputType::BECH32, false)->GetID(), descriptor.id);
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
    for (const Failure& fault : {Failure{"write", DBKeys::ACTIVEEXTERNALSPK}, Failure{"commit"}}) {
        Fault(*wallet) = fault;
        WITH_LOCK(wallet->cs_wallet, BOOST_CHECK(!wallet->SetPQHDPolicy(7, 7)));
        BOOST_REQUIRE(Fault(*wallet).hit);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
        wallet.reset();
        wallet = Open(path);
        BOOST_CHECK_EQUAL(wallet->GetScriptPubKeyMan(OutputType::BECH32, false)->GetID(), descriptor.id);
    }
    WITH_LOCK(wallet->cs_wallet, BOOST_REQUIRE(wallet->SetPQHDPolicy(7, 7)));
    BOOST_CHECK(wallet->GetScriptPubKeyMan(OutputType::BECH32, false)->GetID() != descriptor.id);
    wallet.reset();
    wallet = Open(path);
    BOOST_CHECK(wallet->GetScriptPubKeyMan(OutputType::BECH32, false)->GetID() != descriptor.id);
    // Preserving active bindings must not trust a mismatched stored output type.
    const auto legacy_id = wallet->GetScriptPubKeyMan(OutputType::LEGACY, false)->GetID();
    BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::LEGACY), descriptor.id, false));
    const auto corrupted = ReadRecords(wallet->GetDatabase());
    wallet.reset();
    wallet = std::make_unique<CWallet>(m_node.chain.get(), "", std::make_unique<FailingDatabase>(path));
    wallet->m_keypool_size = 1;
    BOOST_CHECK(wallet->LoadWallet() == DBErrors::CORRUPT);
    BOOST_CHECK(corrupted == ReadRecords(wallet->GetDatabase()));
    BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::LEGACY), legacy_id, false));
    wallet.reset();
    wallet = Open(path);
    BOOST_CHECK_EQUAL(wallet->GetScriptPubKeyMan(OutputType::LEGACY, false)->GetID(), legacy_id);
}

BOOST_AUTO_TEST_CASE(pqhd_reimport_preserves_recovery_progress)
{
    const auto path = m_args.GetDataDirBase() / "recovery-progress";
    auto wallet = Open(path);
    uint256 id;
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
        const auto seed = wallet->ImportPQHDSeed(std::array<unsigned char, 32>{});
        BOOST_REQUIRE(seed);
        auto descriptor = GeneratePQHDWalletDescriptor(seed->seed_id, 7, OutputType::BECH32, false, Params().GetConsensus(), 0);
        descriptor.range_start = 5;
        descriptor.range_end = descriptor.next_index = 7;
        descriptor.creation_time = 123;
        auto imported = wallet->AddWalletDescriptor(descriptor, {}, "", false);
        BOOST_REQUIRE(imported);
        id = descriptor.id;
        descriptor.range_end = 9;
        descriptor.next_index = 5;
        descriptor.creation_time = 999;
        BOOST_REQUIRE(wallet->AddWalletDescriptor(descriptor, {}, "", false));
        const auto saved = WITH_LOCK(imported->get().cs_desc_man, return imported->get().GetWalletDescriptor());
        BOOST_CHECK_EQUAL(saved.next_index, 7);
        BOOST_CHECK_EQUAL(saved.creation_time, 123);
        const auto records = ReadRecords(wallet->GetDatabase());
        const auto state = WalletReconciliationTestAccess::Snapshot(*wallet);
        descriptor.next_index = 9;
        descriptor.creation_time = 1;
        Fault(*wallet) = {"commit"};
        BOOST_CHECK(!wallet->AddWalletDescriptor(descriptor, {}, "", false));
        BOOST_CHECK(Fault(*wallet).hit);
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_CHECK(state == WalletReconciliationTestAccess::Snapshot(*wallet));
    }
    wallet.reset();
    wallet = Open(path);
    {
        LOCK(wallet->cs_wallet);
        auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(id));
        BOOST_REQUIRE(manager);
        auto descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
        BOOST_CHECK_EQUAL(descriptor.next_index, 7);
        BOOST_CHECK_EQUAL(descriptor.creation_time, 123);
        descriptor.creation_time = 1;
        descriptor.next_index = 9;
        BOOST_REQUIRE(wallet->AddWalletDescriptor(descriptor, {}, "", false));
    }
    wallet.reset();
    wallet = Open(path);
    auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(id));
    BOOST_REQUIRE(manager);
    const auto saved = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
    BOOST_CHECK_EQUAL(saved.next_index, 9);
    BOOST_CHECK_EQUAL(saved.creation_time, 1);
}

BOOST_AUTO_TEST_CASE(pqhd_nonzero_range_and_terminal_exhaustion)
{
    const auto path = m_args.GetDataDirBase() / "terminal-range";
    auto wallet = Open(path);
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET));
    std::array<unsigned char, 32> seed{};
    uint256 descriptor_id;
    {
        LOCK(wallet->cs_wallet);
        const auto imported = wallet->ImportPQHDSeed(seed);
        BOOST_REQUIRE(imported);
        auto descriptor = GeneratePQHDWalletDescriptor(imported->seed_id, 7, OutputType::BECH32, false, Params().GetConsensus(), 0);
        constexpr int32_t END = std::numeric_limits<int32_t>::max();
        descriptor.range_start = descriptor.next_index = END - 2;
        descriptor.range_end = END - 1;
        const auto result = wallet->AddWalletDescriptor(descriptor, {}, "", false);
        BOOST_REQUIRE(result);
        auto& manager = result->get();
        BOOST_CHECK_EQUAL(manager.GetEndRange(), END - 1);
        BOOST_REQUIRE(manager.TopUp(2));
        BOOST_CHECK_EQUAL(manager.GetEndRange(), END);
        BOOST_CHECK(!manager.TopUp(std::numeric_limits<unsigned int>::max()));
        const auto first = manager.GetNewDestination(OutputType::BECH32);
        const auto second = manager.GetNewDestination(OutputType::BECH32);
        BOOST_REQUIRE(first);
        BOOST_REQUIRE(second);
        BOOST_CHECK(*first != *second);
        BOOST_CHECK(!manager.GetNewDestination(OutputType::BECH32));
        descriptor_id = descriptor.id;
        auto record = WITH_LOCK(manager.cs_desc_man, return manager.GetWalletDescriptor());
        BOOST_CHECK(record.HasValidRange());
        record.next_index = -1;
        BOOST_CHECK(!record.HasValidRange());
        record.next_index = END;
        record.range_start = -1;
        BOOST_CHECK(!record.HasValidRange());
    }
    wallet.reset();
    wallet = Open(path);
    auto* reloaded = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(descriptor_id));
    BOOST_REQUIRE(reloaded);
    BOOST_CHECK_EQUAL(reloaded->GetEndRange(), std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!reloaded->GetNewDestination(OutputType::BECH32));
}

BOOST_AUTO_TEST_CASE(pqhd_cache_seed_mismatch_rejected_without_rewrite)
{
    for (bool encrypted : {false, true}) {
        const auto path = m_args.GetDataDirBase() / (encrypted ? "cache-encrypted" : "cache-plain");
        auto wallet = Open(path);
        WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
        WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
        if (encrypted) BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"pass"}));
        if (encrypted) BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
        auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_REQUIRE(WITH_LOCK(wallet->cs_wallet, return manager->TopUp(2)));
        const auto descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
        CPubKey zero, one;
        BOOST_REQUIRE(descriptor.cache.GetCachedDerivedPubKey(0, 0, zero));
        BOOST_REQUIRE(descriptor.cache.GetCachedDerivedPubKey(0, 1, one));
        DescriptorCache swapped;
        swapped.CacheDerivedPubKey(0, 0, one);
        swapped.CacheDerivedPubKey(0, 1, zero);
        BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteDescriptorCacheItems(manager->GetID(), swapped));
        const auto records = ReadRecords(wallet->GetDatabase());
        wallet.reset();
        wallet = std::make_unique<CWallet>(m_node.chain.get(), "", std::make_unique<FailingDatabase>(path));
        wallet->m_keypool_size = 1;
        if (encrypted) {
            BOOST_REQUIRE(wallet->LoadWallet() == DBErrors::LOAD_OK);
            manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
            BOOST_REQUIRE(manager);
            BOOST_CHECK(!manager->IsCacheVerified());
            BOOST_CHECK(manager->IsCacheUsable());
            auto public_provider = manager->GetSigningProvider(zero, /*include_private=*/false);
            BOOST_REQUIRE(public_provider);
            BOOST_CHECK(public_provider->keys.empty());
            BOOST_CHECK(public_provider->pubkeys.contains(zero.GetID()));
            BOOST_CHECK(!manager->GetSigningProvider(zero, /*include_private=*/true));
            BOOST_CHECK(!wallet->Unlock(SecureString{"wrong"}));
            BOOST_CHECK(manager->IsCacheUsable());
            // A mismatch discovered during a transaction must remain rejected
            // after rollback, even if its snapshot had an unchecked cache.
            {
                WalletBatch batch{wallet->GetDatabase()};
                BOOST_REQUIRE(batch.TxnBegin());
                auto update = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
                BOOST_REQUIRE(manager->UpdateWalletDescriptor(update, &batch));
                BOOST_CHECK_THROW(wallet->Unlock(SecureString{"pass"}), std::runtime_error);
                BOOST_REQUIRE(batch.TxnAbort());
            }
            BOOST_CHECK(wallet->IsLocked());
            BOOST_CHECK(!manager->IsCacheUsable());
            BOOST_CHECK(!manager->CanGetAddresses());
            BOOST_CHECK(!manager->GetNewDestination(OutputType::BECH32));
            BOOST_CHECK(WITH_LOCK(wallet->cs_wallet, return !manager->TopUp()));
            BOOST_CHECK(!manager->GetSigningProvider(zero, /*include_private=*/false));
            FlatSigningProvider provider;
            std::vector<CScript> scripts;
            BOOST_CHECK(!WITH_LOCK(manager->cs_desc_man, return manager->ExpandPublicFromCache(0, scripts, provider)));
            BOOST_CHECK_THROW(wallet->Unlock(SecureString{"pass"}), std::runtime_error);
        } else {
            BOOST_CHECK(wallet->LoadWallet() == DBErrors::CORRUPT);
        }
        BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
        BOOST_REQUIRE(WalletBatch(wallet->GetDatabase()).WriteDescriptorCacheItems(descriptor.id, descriptor.cache));
        wallet.reset();
        wallet = Open(path);
        if (encrypted) BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_REQUIRE(manager->GetNewDestination(OutputType::BECH32));
    }
}

BOOST_AUTO_TEST_CASE(pqhd_locked_reload_issues_cached_addresses_durably)
{
    const auto path = m_args.GetDataDirBase() / "cache-locked-issuance";
    auto wallet = Open(path);
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"pass"}));
    BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
    auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
    BOOST_REQUIRE(manager);
    BOOST_REQUIRE(WITH_LOCK(wallet->cs_wallet, return manager->TopUp(2)));
    const auto descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
    std::vector<CTxDestination> expected;
    for (int i = 0; i < 2; ++i) {
        FlatSigningProvider provider;
        std::vector<CScript> scripts;
        BOOST_REQUIRE(descriptor.descriptor->ExpandFromCache(i, descriptor.cache, scripts, provider));
        CTxDestination dest;
        BOOST_REQUIRE(ExtractDestination(scripts.at(0), dest));
        expected.push_back(dest);
    }
    for (int i = 0; i < 2; ++i) {
        wallet.reset();
        wallet = Open(path);
        BOOST_CHECK(wallet->IsLocked());
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
        BOOST_REQUIRE(manager);
        BOOST_CHECK(!manager->IsCacheVerified());
        // Failed reservation must not consume a key, even before verification.
        Fault(*wallet) = {"write", DBKeys::WALLETDESCRIPTOR, false, 1};
        BOOST_CHECK(!manager->GetNewDestination(OutputType::BECH32));
        Fault(*wallet) = {};
        const auto issued = manager->GetNewDestination(OutputType::BECH32);
        BOOST_REQUIRE(issued);
        BOOST_CHECK(*issued == expected.at(i));
        BOOST_CHECK(!manager->IsCacheVerified());
    }
    wallet.reset();
    wallet = Open(path);
    manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
    BOOST_REQUIRE(manager);
    BOOST_CHECK(!manager->GetNewDestination(OutputType::BECH32));
    BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
    BOOST_CHECK(manager->IsCacheVerified());
    BOOST_REQUIRE(WITH_LOCK(wallet->cs_wallet, return manager->TopUp(1)));
    BOOST_REQUIRE(wallet->Lock());
    const auto issued = manager->GetNewDestination(OutputType::BECH32);
    BOOST_REQUIRE(issued);
    BOOST_CHECK(*issued != expected[0] && *issued != expected[1]);
}

BOOST_AUTO_TEST_CASE(pqhd_cache_structure_rejects_invalid_entries)
{
    auto wallet = Open(m_args.GetDataDirBase() / "cache-structure");
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, false));
    BOOST_REQUIRE(manager);
    auto descriptor = WITH_LOCK(manager->cs_desc_man, return manager->GetWalletDescriptor());
    CPubKey pubkey;
    BOOST_REQUIRE(descriptor.cache.GetCachedDerivedPubKey(0, 0, pubkey));
    const CPubKey wrong_scheme = GenerateRandomKey(pq::SchemeId::MLDSA_44).GetPubKey();
    DescriptorCache missing, extra, expression, wrong;
    extra = descriptor.cache;
    extra.CacheDerivedPubKey(0, 1, pubkey);
    expression.CacheDerivedPubKey(1, 0, pubkey);
    wrong.CacheDerivedPubKey(0, 0, wrong_scheme);
    for (const auto& bad : {missing, extra, expression, wrong}) {
        DescriptorScriptPubKeyMan isolated(*wallet, descriptor, 1);
        BOOST_CHECK_THROW(isolated.SetCache(bad), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(pqhd_record_versions_and_ranges)
{
    const auto check_version = [](auto record) {
        for (int version : {0, 2, std::numeric_limits<int>::max()}) {
            record.nVersion = version;
            DataStream bytes;
            bytes << record;
            decltype(record) decoded;
            BOOST_CHECK_THROW(bytes >> decoded, std::ios_base::failure);
        }
    };
    check_version(PQHDSeed{});
    check_version(PQHDCryptedSeed{});
    check_version(PQHDPolicy{});
    const auto key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse("wpkh(" + HexStr(key.GetPubKey()) + ")", provider, error, false);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    for (const auto bounds : {std::array<int32_t, 3>{-1, 1, 0}, {0, -1, 0}, {0, 1, -1}, {0, 1, 2}, {0, 2, 0}}) {
        auto copy = Parse(parsed[0]->ToString(), provider, error, true);
        WalletDescriptor invalid(std::move(copy[0]), 0, bounds[0], bounds[1], bounds[2]);
        DataStream bytes;
        bytes << invalid;
        WalletDescriptor decoded;
        BOOST_CHECK_THROW(bytes >> decoded, std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(descriptor_insert_and_erase_failures)
{
    const auto path{m_args.GetDataDirBase() / "descriptor-keys"};
    auto wallet{Open(path)};
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    const CKey original{GenerateRandomKey(pq::SchemeId::FALCON_512)};
    auto* manager{&Import(*wallet, original)};
    const auto manager_id{manager->GetID()};
    // A failed plaintext insertion must not suppress the retry as a duplicate.
    CKey plaintext{GenerateRandomKey(pq::SchemeId::FALCON_512)};
    Fault(*wallet) = {"write", DBKeys::WALLETDESCRIPTORKEY};
    BOOST_CHECK_THROW(manager->AddDescriptorKey(plaintext, plaintext.GetPubKey()), std::runtime_error);
    BOOST_CHECK(!manager->GetKey(plaintext.GetPubKey().GetID()));
    manager->AddDescriptorKey(plaintext, plaintext.GetPubKey());
    BOOST_CHECK(manager->GetKey(plaintext.GetPubKey().GetID()));
    BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"pass"}));
    BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
    std::vector<CPubKey> inserted_keys;
    for (const Failure& point : std::vector<Failure>{{"begin"}, {"write", DBKeys::WALLETDESCRIPTORCKEY}, {"erase", DBKeys::WALLETDESCRIPTORKEY}, {"commit"}}) {
        CKey key{GenerateRandomKey(pq::SchemeId::FALCON_512)};
        Fault(*wallet) = point;
        BOOST_CHECK_THROW(manager->AddDescriptorKey(key, key.GetPubKey()), std::runtime_error);
        BOOST_CHECK(Fault(*wallet).hit);
        BOOST_CHECK(!manager->GetKey(key.GetPubKey().GetID()));
        wallet.reset();
        wallet = Open(path);
        BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
        manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(manager_id));
        BOOST_REQUIRE(manager);
        BOOST_CHECK(!manager->GetKey(key.GetPubKey().GetID()));
        CheckKey(*wallet, original.GetPubKey());
        manager->AddDescriptorKey(key, key.GetPubKey());
        CheckKey(*wallet, key.GetPubKey());
        inserted_keys.push_back(key.GetPubKey());
    }
    wallet.reset();
    wallet = Open(path);
    BOOST_REQUIRE(wallet->Unlock(SecureString{"pass"}));
    CheckKey(*wallet, original.GetPubKey());
    CheckKey(*wallet, plaintext.GetPubKey());
    for (const auto& pubkey : inserted_keys) CheckKey(*wallet, pubkey);
}

#ifdef __linux__
BOOST_AUTO_TEST_CASE(restore_partial_copy_cleanup)
{
    WalletContext context;
    context.args = &m_args;
    const auto backup{m_args.GetDataDirBase() / "large-backup"};
    {
        std::ofstream file{backup, std::ios::binary};
        file << std::string(8192, 'x');
        BOOST_REQUIRE(file.good());
    }
    struct FileSizeLimit {
        struct rlimit previous;
        using Handler = void (*)(int);
        Handler handler;
        FileSizeLimit() {
            BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_FSIZE, &previous), 0);
            handler = std::signal(SIGXFSZ, SIG_IGN);
            BOOST_REQUIRE(handler != SIG_ERR);
            struct rlimit limited{previous};
            limited.rlim_cur = 1024;
            if (setrlimit(RLIMIT_FSIZE, &limited) != 0) {
                std::signal(SIGXFSZ, handler);
                BOOST_FAIL("Cannot set file-size limit");
            }
        }
        ~FileSizeLimit() {
            setrlimit(RLIMIT_FSIZE, &previous);
            std::signal(SIGXFSZ, handler);
        }
    };
    // Verify that the operating system really leaves a partial file on this copy error.
    const auto partial{m_args.GetDataDirBase() / "partial-control"};
    std::error_code copy_error;
    {
        FileSizeLimit limit;
        try {
            fs::copy_file(backup, partial, fs::copy_options::none);
        } catch (const fs::filesystem_error& e) {
            copy_error = e.code();
        }
    }
    BOOST_REQUIRE(copy_error);
    BOOST_REQUIRE(fs::exists(partial));
    BOOST_CHECK_GT(fs::file_size(partial), 0U);
    BOOST_CHECK_LT(fs::file_size(partial), fs::file_size(backup));

    for (const bool existing : {false, true}) {
        const auto destination{m_args.GetDataDirBase() / (existing ? "existing-destination" : "new-destination")};
        if (existing) {
            fs::create_directories(destination);
            std::ofstream{destination / "keep"} << "keep";
        }
        DatabaseStatus status;
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        {
            FileSizeLimit limit;
            RestoreWallet(context, backup, fs::PathToString(destination), std::nullopt, status, error, warnings, /*load_after_restore=*/false);
        }
        BOOST_CHECK(status == DatabaseStatus::FAILED_LOAD);
        BOOST_CHECK(!error.empty());
        BOOST_CHECK(!fs::exists(destination / "wallet.dat"));
        BOOST_CHECK_EQUAL(fs::exists(destination), existing);
        if (existing) BOOST_CHECK_EQUAL(fs::file_size(destination / "keep"), 4U);
    }
    BOOST_CHECK_EQUAL(fs::file_size(backup), 8192U);
}
#endif

BOOST_AUTO_TEST_CASE(kdf_integer_calibration_boundaries)
{
    using namespace std::chrono_literals;
    BOOST_CHECK(!CalibrateDeriveIterations(0, 100ms));
    BOOST_CHECK(!CalibrateDeriveIterations(25000, 0ns));
    BOOST_CHECK(!CalibrateDeriveIterations(25000, -1ns));
    BOOST_CHECK(!CalibrateDeriveIterations(25000, 1ns));
    BOOST_CHECK(!CalibrateDeriveIterations(1, std::chrono::nanoseconds::max()));
    BOOST_CHECK_EQUAL(*CalibrateDeriveIterations(25000, 50ms), 50000U);
    BOOST_CHECK_EQUAL(*CalibrateDeriveIterations(std::numeric_limits<unsigned int>::max(), 100ms), std::numeric_limits<unsigned int>::max());
    BOOST_CHECK(!CalibrateDeriveIterations(std::numeric_limits<unsigned int>::max(), 99ms));
}

BOOST_AUTO_TEST_CASE(pq_checksum_compatibility)
{
    auto wallet{Open(m_args.GetDataDirBase() / "pq-compatibility")};
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    std::vector<CPubKey> pubkeys;
    for (const auto scheme : {pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_1024, pq::SchemeId::MLDSA_44, pq::SchemeId::MLDSA_65, pq::SchemeId::MLDSA_87}) {
        const CKey key{GenerateRandomKey(scheme)};
        const auto pub{key.GetPubKey()};
        const auto priv{key.GetPrivKey()};
        // Use secure storage for the old concatenated checksum representation.
        CKeyingMaterial old_bytes{pub.begin(), pub.end()};
        old_bytes.insert(old_bytes.end(), priv.begin(), priv.end());
        BOOST_CHECK(Hash(old_bytes) == Hash(pub, priv));
        Import(*wallet, key);
        pubkeys.push_back(pub);
    }
    BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"old"}));
    wallet.reset();
    wallet = Open(m_args.GetDataDirBase() / "pq-compatibility");
    BOOST_REQUIRE(wallet->Unlock(SecureString{"old"}));
    for (const auto& pub : pubkeys) CheckKey(*wallet, pub);
    BOOST_REQUIRE(wallet->ChangeWalletPassphrase(SecureString{"old"}, SecureString{"new"}));
    wallet.reset();
    wallet = Open(m_args.GetDataDirBase() / "pq-compatibility");
    BOOST_CHECK(!wallet->Unlock(SecureString{"old"}));
    BOOST_REQUIRE(wallet->Unlock(SecureString{"new"}));
    for (const auto& pub : pubkeys) CheckKey(*wallet, pub);
}

// Minimal BDB v9 fixtures. Every page is initialized with a reset LSN.
static std::vector<unsigned char> BDBFixture(bool overflow = false)
{
    const uint32_t count{overflow ? 6U : 4U};
    std::vector<unsigned char> bytes(count * 512);
    auto put32 = [&](size_t offset, uint32_t value) { WriteLE32(bytes.data() + offset, value); };
    auto put16 = [&](size_t offset, uint16_t value) { WriteLE16(bytes.data() + offset, value); };
    for (uint32_t page = 0; page < count; ++page) {
        put32(page * 512 + 4, 1);
        put32(page * 512 + 8, page);
    }
    for (uint32_t page : {0U, 2U}) {
        const size_t base{page * 512};
        put32(base + 12, 0x53162);
        put32(base + 16, 9);
        put32(base + 20, 512);
        bytes[base + 25] = 9;
        put32(base + 32, count - 1);
        put32(base + 48, 0x20);
        put32(base + 88, page == 0 ? 1 : 3);
    }
    auto record = [&](uint32_t page, uint16_t offset, std::string_view data) {
        const size_t base{page * 512 + offset};
        put16(base, data.size());
        bytes[base + 2] = 1;
        std::copy(data.begin(), data.end(), bytes.begin() + base + 3);
    };
    for (uint32_t page : {1U, 3U}) {
        const size_t base{page * 512};
        put16(base + 20, 2);
        bytes[base + 24] = 1;
        bytes[base + 25] = 5;
        put16(base + 26, 500);
        put16(base + 28, 480);
    }
    record(1, 500, "main");
    record(1, 480, std::string_view{"\0\0\0\2", 4});
    record(3, 500, "key");
    record(3, 480, "value");
    if (overflow) {
        const size_t rec{3 * 512 + 480};
        put16(rec, 0);
        bytes[rec + 2] = 3;
        put32(rec + 4, 4);
        put32(rec + 8, 8);
        for (uint32_t page : {4U, 5U}) {
            const size_t base{page * 512};
            bytes[base + 25] = 7;
            put16(base + 22, 4);
            put32(base + 16, page == 4 ? 5 : 0);
            std::fill_n(bytes.begin() + base + 26, 4, page == 4 ? 'a' : 'b');
        }
    }
    return bytes;
}

BOOST_AUTO_TEST_CASE(recordless_legacy_wallet_load_fails_cleanly)
{
    auto bytes{BDBFixture()};
    // The subdatabase exists, but its leaf contains no wallet records.
    WriteLE16(bytes.data() + 3 * 512 + 20, 0);
    const auto path{m_args.GetDataDirBase() / "recordless-bdb.dat"};
    {
        AutoFile file{fsbridge::fopen(path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        file.write(std::as_bytes(std::span{bytes}));
    }
    WalletContext context;
    context.args = &m_args;
    for (int attempt = 0; attempt < 2; ++attempt) {
        auto database{std::make_unique<BerkeleyRODatabase>(path)};
        BOOST_REQUIRE(database->m_records.empty());
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        auto wallet{CWallet::Create(context, "recordless", std::move(database), 0, error, warnings)};
        BOOST_CHECK(!wallet);
        BOOST_CHECK(error.original.find("Wallet is empty and does not have the blank wallet flag set.") != std::string::npos);
        AutoFile file{fsbridge::fopen(path, "rb")};
        BOOST_REQUIRE(!file.IsNull());
        std::vector<unsigned char> after(bytes.size());
        file.read(std::as_writable_bytes(std::span{after}));
        BOOST_CHECK(after == bytes);
    }
}

BOOST_AUTO_TEST_CASE(bdb_structure_and_overflow_bounds)
{
    const auto path{m_args.GetDataDirBase() / "synthetic-bdb.dat"};
    auto write = [&](const std::vector<unsigned char>& bytes) {
        AutoFile file{fsbridge::fopen(path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        file.write(std::as_bytes(std::span{bytes}));
    };
    for (bool overflow : {false, true}) {
        auto bytes{BDBFixture(overflow)};
        write(bytes);
        BerkeleyRODatabase db{path};
        BOOST_REQUIRE_EQUAL(db.m_records.size(), 1U);
        BOOST_CHECK_EQUAL(db.m_records.begin()->second.size(), overflow ? 8U : 5U);
    }
    auto reject = [&](std::vector<unsigned char> bytes, std::string_view message) {
        write(bytes);
        BOOST_CHECK_EXCEPTION(BerkeleyRODatabase{path}, std::runtime_error, [&](const auto& e) {
            return std::string_view{e.what()}.find(message) != std::string_view::npos;
        });
    };
    auto bytes{BDBFixture()};
    WriteLE32(bytes.data() + 3 * 512, 1);
    reject(bytes, "LSNs are not reset");
    bytes = BDBFixture();
    bytes[3 * 512 + 24] = 2;
    reject(bytes, "Leaf page is not at level 1");
    bytes = BDBFixture(true);
    WriteLE32(bytes.data() + 3 * 512 + 488, std::numeric_limits<uint32_t>::max());
    reject(bytes, "impossible length");
    bytes = BDBFixture(true);
    WriteLE32(bytes.data() + 4 * 512 + 16, 0);
    reject(bytes, "shorter than stated size");
    bytes = BDBFixture(true);
    WriteLE32(bytes.data() + 3 * 512 + 488, 3);
    reject(bytes, "larger than stated size");
    bytes = BDBFixture(true);
    WriteLE16(bytes.data() + 4 * 512 + 22, 0);
    WriteLE32(bytes.data() + 4 * 512 + 16, 4);
    reject(bytes, "repeated overflow page");
    bytes = BDBFixture(true);
    WriteLE32(bytes.data() + 4 * 512 + 16, 6);
    reject(bytes, "Invalid or repeated overflow page");
    // An internal root pointing back to itself must terminate.
    bytes = BDBFixture();
    bytes[3 * 512 + 24] = 2;
    bytes[3 * 512 + 25] = 3;
    WriteLE16(bytes.data() + 3 * 512 + 20, 1);
    WriteLE16(bytes.data() + 3 * 512 + 26, 480);
    WriteLE16(bytes.data() + 3 * 512 + 480, 0);
    WriteLE32(bytes.data() + 3 * 512 + 484, 3);
    reject(bytes, "repeated BTree page");
    // Root level 3 with a level-1 leaf is an inconsistent tree.
    bytes[3 * 512 + 24] = 3;
    WriteLE32(bytes.data() + 3 * 512 + 484, 1);
    reject(bytes, "unexpected level");
}

BOOST_FIXTURE_TEST_CASE(pqhd_recovery_scan_failures, TestChain100Setup)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = std::make_shared<CWallet>(m_node.chain.get(), "recovery", CreateMockableWalletDatabase());
    wallet->m_keypool_size = 1;
    BOOST_REQUIRE(wallet->LoadWallet() == DBErrors::LOAD_OK);
    uint256 seed_id;
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
        const auto seed = wallet->ImportPQHDSeed(std::array<unsigned char, 32>{});
        BOOST_REQUIRE(seed);
        seed_id = seed->seed_id;
    }
    FlatSigningProvider keys;
    std::string error;
    auto parsed = Parse("wpkh(pqhd(" + seed_id.GetHex() + ")/10007h/6868h/7h/42h/1h/*h)", keys, error, false);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    const std::string desc = parsed[0]->ToString();
    // Construct the historical payment independently of the restoring wallet.
    CWallet source(m_node.chain.get(), "source", CreateMockableWalletDatabase());
    source.m_keypool_size = 1;
    BOOST_REQUIRE(source.LoadWallet() == DBErrors::LOAD_OK);
    CScript script;
    {
        LOCK(source.cs_wallet);
        source.SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
        BOOST_REQUIRE(source.ImportPQHDSeed(std::array<unsigned char, 32>{}));
        WalletDescriptor descriptor(std::move(parsed[0]), 1, 8, 9, 9);
        auto imported = source.AddWalletDescriptor(descriptor, {}, "", true);
        BOOST_REQUIRE(imported);
        script = *imported->get().GetScriptPubKeys().begin();
    }
    CreateAndProcessBlock({}, script);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash()));
    AddWallet(context, wallet);
    JSONRPCRequest request;
    request.context = &context;
    request.URI = "/wallet/recovery";
    UniValue item(UniValue::VOBJ);
    item.pushKV("desc", desc);
    item.pushKV("timestamp", 0);
    UniValue range(UniValue::VARR);
    range.push_back(8);
    range.push_back(9);
    item.pushKV("range", range);
    item.pushKV("next_index", 9);
    item.pushKV("internal", true);
    UniValue items(UniValue::VARR);
    items.push_back(item);
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(items);

    // Deterministic cancellation at genesis, partway through the scan, and on
    // shutdown. Registration is durable, but none may report scan success.
    for (int scenario : {0, 1, 2}) {
        bool stopped{false};
        auto connection = wallet->ShowProgress.connect([&](const std::string&, int progress) {
            if (!stopped && scenario != 1 && progress == 0) {
                stopped = true;
                if (scenario == 2) {
                    BOOST_CHECK(m_interrupt());
                } else {
                    wallet->AbortRescan();
                }
            }
        });
        auto transaction_connection = wallet->NotifyTransactionChanged.connect([&](const Txid&, ChangeType) {
            if (!stopped && scenario == 1) {
                stopped = true;
                wallet->AbortRescan();
            }
        });
        std::optional<UniValue> failure;
        UniValue outcome;
        try { outcome = importdescriptors().HandleRequest(request); }
        catch (const UniValue& e) { failure = e; }
        connection.disconnect();
        transaction_connection.disconnect();
        if (scenario == 2) BOOST_CHECK(m_interrupt.reset());
        BOOST_REQUIRE_MESSAGE(stopped, strprintf("scenario %d: %s", scenario, failure ? failure->write() : outcome.write()));
        BOOST_REQUIRE(failure);
        BOOST_CHECK_EQUAL((*failure)["code"].getInt<int>(), -1);
        BOOST_CHECK_EQUAL((*failure)["message"].get_str(), scenario == 2 ? "Rescan interrupted by shutdown." : "Rescan aborted by user.");
        BOOST_CHECK(!wallet->IsScanning());
        BOOST_CHECK_EQUAL(wallet->GetAllScriptPubKeyMans().size(), 1U);
        BOOST_CHECK_EQUAL(WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.size()), scenario == 0 ? 0U : 1U);
    }
    auto result = importdescriptors().HandleRequest(request);
    BOOST_CHECK_MESSAGE(result[0]["success"].get_bool(), result.write());
    BOOST_CHECK_EQUAL(WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.size()), 1U);
    const auto recovered_txid = WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.begin()->first);
    BOOST_CHECK(WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.begin()->second.tx->vout[0].scriptPubKey == script));

    // Missing historical block data must not be reported as successful recovery,
    // even if a previous scan has already populated some transactions.
    const int file = WITH_LOCK(cs_main, return tip->GetBlockPos().nFile);
    WITH_LOCK(cs_main, m_node.chainman->m_blockman.PruneOneBlockFile(file));
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file});
    result = importdescriptors().HandleRequest(request);
    BOOST_CHECK(!result[0]["success"].get_bool());
    BOOST_CHECK(result[0]["error"]["message"].get_str().find("Rescan failed") != std::string::npos);
    BOOST_CHECK_EQUAL(wallet->GetAllScriptPubKeyMans().size(), 1U);
    BOOST_CHECK(WITH_LOCK(wallet->cs_wallet, return wallet->mapWallet.contains(recovered_txid)));
    RemoveWallet(context, wallet, std::nullopt);
}

BOOST_FIXTURE_TEST_CASE(import_reserves_before_chain_sync, TestingSetup)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet{std::make_shared<CWallet>(m_node.chain.get(), "rescan-order", CreateMockableWalletDatabase())};
    BOOST_REQUIRE(wallet->LoadWallet() == DBErrors::LOAD_OK);
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    AddWallet(context, wallet);
    JSONRPCRequest request;
    request.context = &context;
    request.URI = "/wallet/rescan-order";
    BOOST_REQUIRE(request.params.read("[[]]"));
    {
        WalletRescanReserver existing{*wallet};
        BOOST_REQUIRE(existing.reserve());
        std::promise<void> release;
        auto gate{release.get_future()};
        m_node.validation_signals->CallFunctionInValidationInterfaceQueue([&] { gate.wait(); });
        auto result{std::async(std::launch::async, [&] {
            try { importdescriptors().HandleRequest(request); }
            catch (const UniValue& error) {
                return error["code"].getInt<int>() == -4 && error["message"].get_str() == "Wallet is currently rescanning. Abort existing rescan or wait.";
            }
            return false;
        })};
        const bool ready{result.wait_for(std::chrono::seconds{2}) == std::future_status::ready};
        // Always release the queue before assertions, including on old faulty code.
        release.set_value();
        BOOST_CHECK(ready);
        BOOST_CHECK(result.get());
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
    }
    // A real descriptor import succeeds once the other scan releases its reservation.
    FlatSigningProvider provider;
    std::string error;
    auto desc{Parse("pk(" + HexStr(GenerateRandomKey(pq::SchemeId::FALCON_512).GetPubKey()) + ")", provider, error, false)};
    UniValue item{UniValue::VOBJ};
    item.pushKV("desc", desc.at(0)->ToString());
    item.pushKV("timestamp", "now");
    UniValue items{UniValue::VARR};
    items.push_back(item);
    request.params = UniValue{UniValue::VARR};
    request.params.push_back(items);
    {
        // Hold the notification queue while this import owns its reservation.
        // An accepted abort must survive the synchronization wait as well.
        std::promise<void> release;
        auto gate{release.get_future()};
        m_node.validation_signals->CallFunctionInValidationInterfaceQueue([&] { gate.wait(); });
        auto result{std::async(std::launch::async, [&] {
            try { importdescriptors().HandleRequest(request); }
            catch (const UniValue& error) {
                return error["code"].getInt<int>() == -1 && error["message"].get_str() == "Rescan aborted by user.";
            }
            return false;
        })};
        for (int i{0}; i < 2000 && !wallet->IsScanning(); ++i) UninterruptibleSleep(std::chrono::milliseconds{1});
        const bool reserved{wallet->IsScanning()};
        const bool waiting{result.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout};
        const bool aborted{wallet->AbortRescan()};
        WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(0, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash())));
        release.set_value();
        BOOST_CHECK(reserved);
        BOOST_CHECK(waiting);
        BOOST_CHECK(aborted);
        BOOST_CHECK(result.get());
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK(!wallet->IsScanning());
        BOOST_CHECK(wallet->GetAllScriptPubKeyMans().empty());
    }
    WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(0, WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash())));
    const auto result{importdescriptors().HandleRequest(request)};
    BOOST_CHECK_MESSAGE(result[0]["success"].get_bool(), result.write());
    RemoveWallet(context, wallet, std::nullopt);
}

BOOST_AUTO_TEST_SUITE_END()
namespace {
using ReconciliationState = WalletReconciliationTestAccess::State;

MockableData ReadRecords(WalletDatabase& database)
{
    auto batch{database.MakeBatch()};
    auto cursor{batch->GetNewCursor()};
    MockableData records;
    DataStream key, value;
    DatabaseCursor::Status status;
    while ((status = cursor->Next(key, value)) == DatabaseCursor::Status::MORE) {
        records.emplace(SerializeData{key.begin(), key.end()}, SerializeData{value.begin(), value.end()});
        key.clear();
        value.clear();
    }
    BOOST_REQUIRE(status == DatabaseCursor::Status::DONE);
    return records;
}

struct ReconciliationSetup : PersistenceSetup {
    static FailingDatabase& Database(CWallet& wallet) { return dynamic_cast<FailingDatabase&>(wallet.GetDatabase()); }

    void Prepare(const fs::path& path, bool existing, int64_t birth = 1,
                 pq::SchemeId scheme = pq::SchemeId::FALCON_512)
    {
        auto wallet{Open(path)};
        {
            LOCK(wallet->cs_wallet);
            wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | (existing ? uint64_t{0} : uint64_t{WALLET_FLAG_BLANK_WALLET}));
            if (existing) wallet->SetupDescriptorScriptPubKeyMans();
        }
        std::array<uint8_t, 32> bytes{};
        bytes.fill(0x44);
        const auto id{pqhd::ComputeSeedID32AsUint256(bytes)};
        PQHDSeed seed;
        seed.nCreateTime = birth;
        seed.seed.assign(bytes.begin(), bytes.end());
        PQHDPolicy policy;
        policy.default_seed_id = id;
        policy.default_change_seed_id = id;
        policy.default_receive_scheme = static_cast<uint8_t>(scheme);
        policy.default_change_scheme = policy.default_receive_scheme;
        // Preserve one active binding and the existing descriptors, but remove
        // other bindings so load must fill them from the newly persisted policy.
        // Existing active imports now survive reconciliation by design.
        WalletBatch batch{wallet->GetDatabase()};
        BOOST_REQUIRE(batch.WritePQHDSeed(id, seed));
        BOOST_REQUIRE(batch.WritePQHDPolicy(policy));
        if (existing) {
            for (bool internal : {false, true}) {
                for (const auto type : OUTPUT_TYPES) {
                    if (!internal && type == OutputType::BECH32) continue;
                    BOOST_REQUIRE(batch.EraseActiveScriptPubKeyMan(static_cast<uint8_t>(type), internal));
                }
            }
        }
    }

    std::unique_ptr<CWallet> Unloaded(const fs::path& path)
    {
        auto wallet{std::make_unique<CWallet>(m_node.chain.get(), "", std::make_unique<FailingDatabase>(path))};
        wallet->m_keypool_size = 1;
        return wallet;
    }

    void CheckRecovered(const fs::path& path)
    {
        auto wallet{Open(path)};
        // Exhaust the initial pool on both branches and verify PQ signing too.
        for (bool internal : {false, true}) {
            for (int i = 0; i < 3; ++i) {
                auto destination{internal ? wallet->GetNewChangeDestination(OutputType::BECH32)
                                          : wallet->GetNewDestination(OutputType::BECH32, "")};
                BOOST_REQUIRE(destination);
                LOCK(wallet->cs_wallet);
                BOOST_CHECK(wallet->IsMine(*destination));
                auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::BECH32, internal));
                BOOST_REQUIRE(manager);
                auto provider{manager->GetSigningProviderForScript(GetScriptForDestination(*destination), true)};
                BOOST_REQUIRE(provider);
                BOOST_REQUIRE(!provider->keys.empty());
                for (const auto& [id, key] : provider->keys) {
                    std::vector<unsigned char> signature;
                    BOOST_REQUIRE(key.Sign(uint256::ONE, signature));
                    BOOST_CHECK(key.GetPubKey().Verify(uint256::ONE, signature));
                }
            }
        }
        const auto state{WalletReconciliationTestAccess::Snapshot(*wallet)};
        BOOST_CHECK_GT(state.managers, 0U);
        BOOST_CHECK_GT(state.active, 0U);
        BOOST_CHECK_GT(state.scripts, 0U);
        BOOST_CHECK_EQUAL(state.flag_snapshots, 0U);
        BOOST_CHECK_EQUAL(state.birth, 1);
    }

    void CheckFailedLoad(CWallet& wallet, const ReconciliationState& baseline, const MockableData& records)
    {
        BOOST_CHECK(baseline == WalletReconciliationTestAccess::Snapshot(wallet));
        BOOST_CHECK_EQUAL(WalletReconciliationTestAccess::Snapshot(wallet).flag_snapshots, 0U);
        BOOST_CHECK(records == ReadRecords(wallet.GetDatabase()));
        BOOST_CHECK(!Database(wallet).HasActiveTxn());
    }

    void CheckReopened(const fs::path& path, const MockableData& records)
    {
        {
            FailingDatabase reopened{path};
            BOOST_CHECK(records == ReadRecords(reopened));
        }
        CheckRecovered(path);
        CheckRecovered(path);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_reconciliation_tests, ReconciliationSetup)

BOOST_AUTO_TEST_CASE(wallet_load_pqhd_reconciliation_is_atomic)
{
    size_t index{0};
    for (bool existing : {false, true}) {
        for (const Failure& point : std::vector<Failure>{
                 {"begin"}, {"write", DBKeys::WALLETDESCRIPTOR}, {"write", DBKeys::WALLETDESCRIPTOR, false, 1},
                 {"write", "walletdescriptorpubkeycache"}, {"write", "walletdescriptorpubkeycache", false, 1},
                 {"write", DBKeys::FLAGS}, {"write", DBKeys::FLAGS, false, 1},
                 {"write", DBKeys::ACTIVEEXTERNALSPK}, {"write", DBKeys::ACTIVEEXTERNALSPK, false, 1},
                 {"write", DBKeys::ACTIVEINTERNALSPK}, {"commit"}}) {
            BOOST_TEST_CONTEXT(point.operation << " " << point.record << " skip=" << point.skip << " existing=" << existing) {
                const auto path{m_args.GetDataDirBase() / fs::PathFromString("reconcile-" + std::to_string(index++))};
                Prepare(path, existing);
                auto wallet{Unloaded(path)};
                const auto records{ReadRecords(wallet->GetDatabase())};
                std::optional<ReconciliationState> baseline;
                Fault(*wallet) = point;
                // Capture after persisted records load, before reconciliation.
                Database(*wallet).before_begin = [&] { baseline = WalletReconciliationTestAccess::Snapshot(*wallet); };
                BOOST_CHECK(wallet->LoadWallet() == DBErrors::CORRUPT);
                Database(*wallet).before_begin = {};
                BOOST_REQUIRE(baseline);
                BOOST_REQUIRE(Fault(*wallet).hit);
                BOOST_CHECK_EQUAL(baseline->birth, 1);
                BOOST_CHECK_EQUAL(baseline->managers > 0, existing);
                CheckFailedLoad(*wallet, *baseline, records);
                wallet.reset();
                CheckReopened(path, records);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(reconciliation_birth_time_commit_boundary)
{
    struct ResetTime {
        const std::chrono::seconds previous{GetMockTime()};
        ~ResetTime() { SetMockTime(previous); }
    } reset;
    SetMockTime(1);
    size_t index{0};
    for (const Failure& point : std::vector<Failure>{{"write", DBKeys::ACTIVEINTERNALSPK}, {"commit"}, {}}) {
        const auto path{m_args.GetDataDirBase() / fs::PathFromString("birth-" + std::to_string(index++))};
        Prepare(path, false, 100);
        auto wallet{Unloaded(path)};
        const auto records{ReadRecords(wallet->GetDatabase())};
        std::optional<ReconciliationState> baseline;
        Fault(*wallet) = point;
        Database(*wallet).before_begin = [&] { baseline = WalletReconciliationTestAccess::Snapshot(*wallet); };
        const auto result{wallet->LoadWallet()};
        Database(*wallet).before_begin = {};
        BOOST_REQUIRE(baseline);
        BOOST_CHECK_EQUAL(baseline->birth, 100);
        if (point.operation.empty()) {
            BOOST_CHECK(result == DBErrors::LOAD_OK);
            BOOST_CHECK_EQUAL(wallet->GetBirthTime(), 1);
        } else {
            BOOST_REQUIRE(Fault(*wallet).hit);
            BOOST_CHECK(result == DBErrors::CORRUPT);
            CheckFailedLoad(*wallet, *baseline, records);
        }
        wallet.reset();
        if (point.operation.empty()) {
            CheckRecovered(path);
            CheckRecovered(path);
        } else {
            CheckReopened(path, records);
        }
    }
}

BOOST_AUTO_TEST_CASE(descriptor_setup_propagates_expansion_failure)
{
    const auto path{m_args.GetDataDirBase() / "setup-false"};
    auto wallet{Open(path)};
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET));
    const auto records{ReadRecords(wallet->GetDatabase())};
    // Structurally valid descriptor; its seed is unavailable for expansion.
    auto descriptor{GeneratePQHDWalletDescriptor(uint256::ONE, static_cast<uint8_t>(pq::SchemeId::FALCON_512),
                                                OutputType::BECH32, false, Params().GetConsensus(), 0)};
    {
        DescriptorScriptPubKeyMan manager{*wallet, 1};
        WalletBatch batch{wallet->GetDatabase()};
        BOOST_REQUIRE(batch.TxnBegin());
        BOOST_CHECK(!manager.SetupDescriptor(batch, std::move(descriptor)));
        BOOST_CHECK_EQUAL(manager.GetKeyPoolSize(), 0U);
        BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
        BOOST_REQUIRE(batch.TxnAbort());
    }
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    wallet.reset();
    wallet = Open(path);
    BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    BOOST_REQUIRE(wallet->GetNewDestination(OutputType::BECH32, ""));
}

BOOST_AUTO_TEST_CASE(own_descriptor_setup_propagates_expansion_failure)
{
    const auto path{m_args.GetDataDirBase() / "own-setup-false"};
    auto wallet{Open(path)};
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET));
    const auto records{ReadRecords(wallet->GetDatabase())};
    Failure fault{"seed", DBKeys::WALLETDESCRIPTOR};
    std::map<uint256, CKeyingMaterial> seeds;
    Database(*wallet).after_write = [&](std::string_view type) {
        if (fault.Reject("seed", type)) WalletReconciliationTestAccess::SwapSeeds(*wallet, seeds);
    };
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_THROW(wallet->SetupDescriptorScriptPubKeyMans(), std::runtime_error);
    }
    Database(*wallet).after_write = {};
    if (fault.hit) WalletReconciliationTestAccess::SwapSeeds(*wallet, seeds);
    BOOST_REQUIRE(fault.hit);
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    BOOST_CHECK(!Database(*wallet).HasActiveTxn());
    wallet.reset();
    wallet = Open(path);
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    WITH_LOCK(wallet->cs_wallet, wallet->SetupDescriptorScriptPubKeyMans());
    BOOST_REQUIRE(wallet->GetNewDestination(OutputType::BECH32, ""));
}

#ifdef ENABLE_EXTERNAL_SIGNER
BOOST_AUTO_TEST_CASE(external_descriptor_setup_propagates_expansion_failure)
{
    const auto path{m_args.GetDataDirBase() / "external-setup-false"};
    auto wallet{Open(path)};
    WITH_LOCK(wallet->cs_wallet, wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET |
                                                     WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_EXTERNAL_SIGNER));
    const auto records{ReadRecords(wallet->GetDatabase())};
    auto descriptor{GeneratePQHDWalletDescriptor(uint256::ONE, static_cast<uint8_t>(pq::SchemeId::FALCON_512),
                                                OutputType::BECH32, false, Params().GetConsensus(), 0)};
    {
        ExternalSignerScriptPubKeyMan manager{*wallet, 1};
        WalletBatch batch{wallet->GetDatabase()};
        BOOST_REQUIRE(batch.TxnBegin());
        FlatSigningProvider provider;
        std::string error;
        auto parsed{Parse(descriptor.descriptor->ToString(), provider, error, false)};
        BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
        BOOST_CHECK(!manager.SetupDescriptor(batch, std::move(parsed.front())));
        BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
        BOOST_REQUIRE(batch.TxnAbort());
    }
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
    wallet.reset();
    wallet = Open(path);
    BOOST_CHECK(records == ReadRecords(wallet->GetDatabase()));
}
#endif

BOOST_AUTO_TEST_CASE(reconciliation_expansion_failure_survives_reopen)
{
    size_t index{0};
    for (bool existing : {false, true}) {
        for (const auto scheme : {pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_1024,
                                 pq::SchemeId::MLDSA_44, pq::SchemeId::MLDSA_65, pq::SchemeId::MLDSA_87}) {
            // Fail before the first expansion, midway through one manager's
            // top-up, and after another manager has finished setup.
            for (const Failure& trigger : std::vector<Failure>{{"seed", DBKeys::WALLETDESCRIPTOR},
                     {"seed", "walletdescriptorpubkeycache"}, {"seed", DBKeys::WALLETDESCRIPTOR, false, 2}}) {
                BOOST_TEST_CONTEXT("scheme=" << int(scheme) << " existing=" << existing << " trigger=" << trigger.record << " skip=" << trigger.skip) {
                    const auto path{m_args.GetDataDirBase() / fs::PathFromString("expand-" + std::to_string(index++))};
                    Prepare(path, existing, 1, scheme);
                    auto wallet{Unloaded(path)};
                    wallet->m_keypool_size = 2;
                    const auto records{ReadRecords(wallet->GetDatabase())};
                    std::optional<ReconciliationState> baseline;
                    Database(*wallet).before_begin = [&] { baseline = WalletReconciliationTestAccess::Snapshot(*wallet); };
                    auto fault{trigger};
                    std::map<uint256, CKeyingMaterial> seeds;
                    Database(*wallet).after_write = [&](std::string_view type) {
                        if (fault.Reject("seed", type)) WalletReconciliationTestAccess::SwapSeeds(*wallet, seeds);
                    };
                    const auto result{wallet->LoadWallet()};
                    Database(*wallet).before_begin = {};
                    Database(*wallet).after_write = {};
                    // Remove only the deliberate test fault before comparing state.
                    if (fault.hit) WalletReconciliationTestAccess::SwapSeeds(*wallet, seeds);
                    BOOST_REQUIRE(fault.hit);
                    BOOST_REQUIRE(baseline);
                    const auto policy{WITH_LOCK(wallet->cs_wallet, return wallet->GetPQHDPolicy())};
                    BOOST_REQUIRE(policy);
                    BOOST_CHECK_EQUAL(policy->default_receive_scheme, static_cast<uint8_t>(scheme));
                    BOOST_CHECK(result == DBErrors::CORRUPT);
                    CheckFailedLoad(*wallet, *baseline, records);
                    wallet.reset();
                    CheckReopened(path, records);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
