// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/coinstats.h>
#include <node/blockstorage.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <test/util/setup_common.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <txdb.h>
#include <validation.h>
#include <validationinterface.h>

#include <leveldb/env.h>

#include <atomic>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(chainstate_write_tests)

namespace {
// Inject a real LevelDB I/O status at a WAL append, including a failure after
// the record header has been appended. Other files and normal operations use
// the actual filesystem environment.
class FailingWalEnv : public leveldb::EnvWrapper {
    class File : public leveldb::WritableFile {
        std::unique_ptr<leveldb::WritableFile> m_file;
        FailingWalEnv& m_env;
    public:
        File(leveldb::WritableFile* file, FailingWalEnv& env) : m_file{file}, m_env{env} {}
        leveldb::Status Append(const leveldb::Slice& data) override
        {
            ++m_env.total_appends;
            const size_t limit{m_env.fail_at.load()};
            if (limit && ++m_env.appends >= limit) {
                m_env.failed = true;
                return leveldb::Status::IOError("injected chainstate WAL append failure");
            }
            return m_file->Append(data);
        }
        leveldb::Status Close() override { return m_file->Close(); }
        leveldb::Status Flush() override { return m_file->Flush(); }
        leveldb::Status Sync() override { return m_file->Sync(); }
        std::string GetName() const override { return m_file->GetName(); }
    };
public:
    std::atomic<size_t> fail_at{0}, appends{0}, total_appends{0};
    std::atomic<bool> failed{false};
    FailingWalEnv() : EnvWrapper{leveldb::Env::Default()} {}
    void Arm(size_t append) { appends = 0; failed = false; fail_at = append; }
    leveldb::Status NewWritableFile(const std::string& name, leveldb::WritableFile** file) override
    {
        auto status = target()->NewWritableFile(name, file);
        if (status.ok() && name.ends_with(".log")) *file = new File{*file, *this};
        return status;
    }
    leveldb::Status NewAppendableFile(const std::string& name, leveldb::WritableFile** file) override
    {
        auto status = target()->NewAppendableFile(name, file);
        if (status.ok() && name.ends_with(".log")) *file = new File{*file, *this};
        return status;
    }
};

struct RecoverySetup : TestChain100Setup {
    FailingWalEnv env;
    RecoverySetup() : TestChain100Setup{ChainType::REGTEST, {.coins_db_in_memory = false, .block_tree_db_in_memory = false, .setup_net = false}} {}
    ~RecoverySetup()
    {
        // Environment must outlive the database and any validation callbacks.
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.chainman.reset();
    }
    void Reopen()
    {
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        auto options = m_node.chainman->m_options;
        const node::BlockManager::Options block_options{
            .chainparams = options.chainparams,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = options.notifications,
            .block_tree_db_params = {.path = m_args.GetDataDirNet() / "blocks" / "index", .cache_bytes = m_kernel_cache_sizes.block_tree_db},
        };
        m_node.chainman.reset();
        BOOST_REQUIRE(m_interrupt.reset());
        m_node.exit_status = EXIT_SUCCESS;
        options.coins_db.env = &env;
        options.coins_view.batch_write_bytes = 1;
        m_node.chainman = std::make_unique<ChainstateManager>(m_interrupt, options, block_options);
        LoadVerifyActivateChainstate();
    }
};

struct FlushObserver final : CValidationInterface {
    std::atomic<size_t> notifications{0};
    void ChainStateFlushed(ChainstateRole, const CBlockLocator&) override { ++notifications; }
};
} // namespace

BOOST_AUTO_TEST_CASE(chainstate_wal_failure_recovery)
{
    // Each coin produces one partial database batch. LevelDB appends a record
    // header and payload separately. Cover the first header, a torn first
    // record, an intermediate batch, and the final completion batch.
    for (size_t fail_at : {1U, 2U, 3U, 7U}) {
        RecoverySetup setup;
        BOOST_REQUIRE(setup.m_node.chainman->ActiveChainstate().ForceFlushStateToDisk());
        setup.Reopen();
        auto& chainstate = setup.m_node.chainman->ActiveChainstate();
        const auto old_tip = WITH_LOCK(cs_main, return chainstate.CoinsDB().GetBestBlock());
        CCoinsViewDB reference{{.path = "reference", .cache_bytes = 1 << 20, .memory_only = true}, {}};
        CCoinsViewCache reference_cache{&reference};
        {
            LOCK(cs_main);
            auto cursor = chainstate.CoinsDB().Cursor();
            for (; cursor->Valid(); cursor->Next()) {
                COutPoint out;
                Coin coin;
                BOOST_REQUIRE(cursor->GetKey(out) && cursor->GetValue(coin));
                reference_cache.AddCoin(out, std::move(coin), false);
            }
        }
        for (int i{0}; i < 3; ++i) {
            const auto block = setup.CreateAndProcessBlock({}, CScript{} << OP_TRUE);
            AddCoins(reference_cache, *block.vtx[0], 101 + i);
        }
        const auto expected_tip = WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash());
        reference_cache.SetBestBlock(expected_tip);
        BOOST_REQUIRE(reference_cache.Flush());
        const auto expected = kernel::ComputeUTXOStats(kernel::CoinStatsHashType::MUHASH, &reference, chainstate.m_blockman);
        BOOST_REQUIRE(expected);

        // Force a non-erasing Sync, so retrying a failed flush would lose
        // already-cleaned entries and could falsely complete the transition.
        BlockValidationState state;
        BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::PERIODIC));
        setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        const auto observer = std::make_shared<FlushObserver>();
        setup.m_node.validation_signals->RegisterSharedValidationInterface(observer);
        SetMockTime(GetTime<std::chrono::minutes>() + 71min);
        setup.env.Arm(fail_at);
        BOOST_CHECK(!chainstate.FlushStateToDisk(state, FlushStateMode::PERIODIC));
        BOOST_REQUIRE(setup.env.failed);
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(bool(setup.m_interrupt));
        BOOST_CHECK_EQUAL(setup.m_node.exit_status.load(), EXIT_FAILURE);
        const auto appends = setup.env.total_appends.load();
        const auto heads = WITH_LOCK(cs_main, return chainstate.CoinsDB().GetHeadBlocks());
        const auto best_block = WITH_LOCK(cs_main, return chainstate.CoinsDB().GetBestBlock());
        if (fail_at <= 2) {
            BOOST_CHECK(heads.empty());
            BOOST_CHECK(best_block == old_tip);
        } else {
            BOOST_CHECK(heads == (std::vector<uint256>{expected_tip, old_tip}));
            BOOST_CHECK(best_block.IsNull());
        }
        setup.env.fail_at = 0;
        BOOST_CHECK(!chainstate.ForceFlushStateToDisk());
        BOOST_CHECK_EQUAL(setup.env.total_appends.load(), appends);
        BOOST_CHECK(WITH_LOCK(cs_main, return chainstate.CoinsDB().GetHeadBlocks()) == heads);
        BlockValidationState activate_state;
        BOOST_CHECK(!chainstate.ActivateBestChain(activate_state));
        setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(observer->notifications.load(), 0U);

        // Reopen all chainstate objects. Normal startup replays the unfinished
        // transition or reconnects blocks not represented in the old UTXO tip.
        setup.Reopen();
        auto& recovered = setup.m_node.chainman->ActiveChainstate();
        BOOST_REQUIRE(recovered.ForceFlushStateToDisk());
        const auto actual = kernel::ComputeUTXOStats(kernel::CoinStatsHashType::MUHASH, WITH_LOCK(cs_main, return &recovered.CoinsDB()), recovered.m_blockman);
        BOOST_REQUIRE(actual);
        BOOST_CHECK(actual->hashBlock == expected->hashBlock);
        BOOST_CHECK_EQUAL(actual->nHeight, expected->nHeight);
        BOOST_CHECK(actual->hashSerialized == expected->hashSerialized);
        BOOST_CHECK(actual->total_amount == expected->total_amount);
        BOOST_CHECK_EQUAL(actual->nTransactionOutputs, expected->nTransactionOutputs);
        BOOST_CHECK(WITH_LOCK(cs_main, return recovered.CoinsDB().GetHeadBlocks().empty()));
    }
}

BOOST_AUTO_TEST_CASE(chainstate_blockfile_failure_stops_flush)
{
    for (const auto prefix : {"blk", "rev"}) {
        RecoverySetup setup;
        auto& chainstate = setup.m_node.chainman->ActiveChainstate();
        BOOST_REQUIRE(chainstate.ForceFlushStateToDisk());
        const auto old_tip = WITH_LOCK(cs_main, return chainstate.CoinsDB().GetBestBlock());
        const auto block = setup.CreateAndProcessBlock({}, CScript{} << OP_TRUE);
        setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        const auto observer = std::make_shared<FlushObserver>();
        setup.m_node.validation_signals->RegisterSharedValidationInterface(observer);
        const auto path = setup.m_args.GetBlocksDirPath() / fs::PathFromString(std::string{prefix} + "00000.dat");
        const auto backup = fs::PathFromString(fs::PathToString(path) + ".saved");
        fs::rename(path, backup);
        fs::create_directory(path); // Forces a real open error, even when run as root.
        const bool flushed = chainstate.ForceFlushStateToDisk();
        fs::remove(path);
        fs::rename(backup, path);
        BOOST_CHECK(!flushed);
        BOOST_CHECK(bool(setup.m_interrupt));
        BOOST_CHECK(WITH_LOCK(cs_main, return chainstate.CoinsDB().GetBestBlock()) == old_tip);

        setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(observer->notifications.load(), 0U);
        BOOST_CHECK(!chainstate.ForceFlushStateToDisk());
        BOOST_CHECK(WITH_LOCK(cs_main, return chainstate.CoinsDB().GetBestBlock()) == old_tip);

        JSONRPCRequest request;
        request.context = &setup.m_node;
        request.strMethod = "gettxoutsetinfo";
        request.params = UniValue{UniValue::VARR};
        if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
        BOOST_CHECK_EXCEPTION(tableRPC.execute(request), UniValue, [](const UniValue& error) {
            return error["code"].isNum() && error["code"].getValStr() == std::to_string(RPC_DATABASE_ERROR);
        });
        setup.Reopen();
        BOOST_CHECK(setup.m_node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), true, true, nullptr));
        auto& recovered = setup.m_node.chainman->ActiveChainstate();
        BOOST_REQUIRE(recovered.ForceFlushStateToDisk());
        BOOST_CHECK(WITH_LOCK(cs_main, return recovered.CoinsDB().GetBestBlock()) == block.GetHash());
    }
}

BOOST_FIXTURE_TEST_CASE(chainstate_write_interval, TestingSetup)
{
    struct TestSubscriber final : CValidationInterface {
        bool m_did_flush{false};
        void ChainStateFlushed(ChainstateRole, const CBlockLocator&) override
        {
            m_did_flush = true;
        }
    };

    const auto sub{std::make_shared<TestSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);
    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state_dummy{};

    // The first periodic flush sets m_next_write and does not flush
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!sub->m_did_flush);

    // The periodic flush interval is between 50 and 70 minutes (inclusive)
    SetMockTime(GetTime<std::chrono::minutes>() + 49min);
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!sub->m_did_flush);

    SetMockTime(GetTime<std::chrono::minutes>() + 70min);
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(sub->m_did_flush);
}

BOOST_FIXTURE_TEST_CASE(chainstate_compaction_scheduling, RegTestingSetup)
{
    auto& chainman = *Assert(m_node.chainman);
    auto& chainstate = chainman.ActiveChainstate();
    std::atomic<size_t> starts{0};
    DebugLogHelper logs{"Starting chainstate compaction", [&starts](const std::string* line) {
        if (line) ++starts;
        return false;
    }};
    BOOST_REQUIRE(chainman.IsInitialBlockDownload());
    SeedRandomStateForTest(SeedRand::ZEROS);
    for (int i{0}; i < 1024; ++i) BOOST_REQUIRE(chainstate.ForceFlushStateToDisk());
    BOOST_CHECK_EQUAL(starts.load(), 0U);

    // Make the genesis-only regtest chain current, without changing consensus
    // parameters or introducing a production test switch for compaction.
    SetMockTime(chainman.GetParams().GenesisBlock().GetBlockTime());
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
    BlockValidationState state;
    for (int i{0}; i < 1024; ++i) BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::NONE));
    BOOST_CHECK_EQUAL(starts.load(), 0U);

    // Fixed test randomness exercises the real 1-in-320 scheduler. The bound
    // prevents an absent trigger from hanging the test.
    SeedRandomStateForTest(SeedRand::ZEROS);
    for (int i{0}; i < 4096 && starts.load() == 0; ++i) BOOST_REQUIRE(chainstate.ForceFlushStateToDisk());
    const bool scheduled{starts.load() > 0};
    WITH_LOCK(::cs_main, return chainstate.CoinsDB().CompactFullAsync()).get();
    BOOST_CHECK(scheduled);

    // The interrupt flag suppresses maintenance even after a successful flush.
    const auto before = starts.load();
    BOOST_REQUIRE(m_interrupt());
    SeedRandomStateForTest(SeedRand::ZEROS);
    for (int i{0}; i < 1024; ++i) BOOST_CHECK(chainstate.ForceFlushStateToDisk());
    BOOST_CHECK_EQUAL(starts.load(), before);
    BOOST_REQUIRE(m_interrupt.reset());
}

BOOST_AUTO_TEST_SUITE_END()
