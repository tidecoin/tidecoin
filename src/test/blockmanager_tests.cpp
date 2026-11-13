// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <compat/compat.h>
#include <kernel/notifications_interface.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <util/chaintype.h>
#include <util/readwritefile.h>
#include <validation.h>
#include <validationinterface.h>

#ifdef WIN32
#include <io.h>
#include <winioctl.h>
#endif

#include <algorithm>
#include <array>
#include <limits>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

using node::STORAGE_HEADER_BYTES;
using node::BlockManager;
using node::KernelNotifications;
using node::MAX_BLOCKFILE_SIZE;

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(xor_key_metadata)
{
    const auto directory = m_args.GetDataDirNet() / "xor-metadata";
    fs::create_directories(directory);
    const auto key_path = directory / "xor.dat";
    const auto temporary = directory / ".xor.dat.tmp";
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    BlockManager::Options opts{
        .chainparams = Params(),
        .blocks_dir = directory,
        .notifications = notifications,
        .block_tree_db_params = DBParams{.path = directory / "index", .cache_bytes = 1 << 20, .memory_only = true},
    };
    const auto initialize = [&] { BlockManager blockman{*Assert(m_node.shutdown_signal), opts}; };
    // Interrupted first initialization must not change the choice of obfuscation.
    BOOST_REQUIRE(WriteBinaryFile(temporary, "partial"));
    initialize();
    const auto key = ReadBinaryFileBounded(key_path, 8);
    BOOST_REQUIRE(key.status == FileReadStatus::OK);
    BOOST_REQUIRE_EQUAL(key.data.size(), 8U);
    BOOST_CHECK(key.data != std::string(8, '\0'));
    BOOST_CHECK(!fs::exists(temporary));
    initialize();
    BOOST_CHECK_EQUAL(ReadBinaryFileBounded(key_path, 8).data, key.data);

    for (const auto size : {0, 1, 7, 9}) {
        const std::string damaged(size, 'x');
        BOOST_REQUIRE(WriteBinaryFile(key_path, damaged));
        BOOST_CHECK_EXCEPTION(initialize(), std::runtime_error, [&](const std::runtime_error& e) {
            return std::string{e.what()}.find(fs::PathToString(key_path)) != std::string::npos;
        });
        BOOST_CHECK_EQUAL(ReadBinaryFile(key_path).second, damaged);
    }
    BOOST_REQUIRE(WriteBinaryFile(key_path, key.data));
    opts.use_xor = false;
    BOOST_CHECK_THROW(initialize(), std::runtime_error);
    BOOST_CHECK_EQUAL(ReadBinaryFileBounded(key_path, 8).data, key.data);

    // Keep compatibility with existing unobfuscated directories without a key.
    opts.use_xor = true;
    fs::remove(key_path);
    BOOST_REQUIRE(WriteBinaryFile(directory / "blk00000.dat", "existing data"));
    initialize();
    BOOST_CHECK_EQUAL(ReadBinaryFileBounded(key_path, 8).data, std::string(8, '\0'));
    BOOST_CHECK_EQUAL(ReadBinaryFile(directory / "blk00000.dat").second, "existing data");
}

BOOST_AUTO_TEST_CASE(database_format_version)
{
    const DBParams params{.path = m_args.GetDataDirNet() / "format-index", .cache_bytes = 1 << 20};
    {
        node::BlockTreeDB db{params};
        BOOST_CHECK(db.CheckGenesisBlock(Params().GetConsensus().hashGenesisBlock));
        BOOST_CHECK(!db.ReadDatabaseFormatVersion());
        BOOST_REQUIRE(db.WriteDatabaseFormatVersion());
        BOOST_CHECK_EQUAL(*db.ReadDatabaseFormatVersion(), node::BlockTreeDB::DATABASE_FORMAT_VERSION);
        BOOST_REQUIRE(db.WriteReindexing(true));
    }
    {
        node::BlockTreeDB db{params};
        BOOST_CHECK_EQUAL(*db.ReadDatabaseFormatVersion(), node::BlockTreeDB::DATABASE_FORMAT_VERSION);
        bool reindex{false};
        db.ReadReindexing(reindex);
        BOOST_CHECK(reindex);
        BOOST_REQUIRE(db.WriteReindexing(false));
        // Format and rebuild progress are independent records.
        BOOST_CHECK_EQUAL(*db.ReadDatabaseFormatVersion(), node::BlockTreeDB::DATABASE_FORMAT_VERSION);
        BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint32_t{999}));
        BOOST_CHECK_EQUAL(*db.ReadDatabaseFormatVersion(), 999U);
        // Reject both truncated and extended encodings of the version.
        BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint8_t{1}));
        BOOST_CHECK_THROW(db.ReadDatabaseFormatVersion(), node::BlockTreeDB::InvalidFormatVersion);
        BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint64_t{1}));
        BOOST_CHECK_THROW(db.ReadDatabaseFormatVersion(), node::BlockTreeDB::InvalidFormatVersion);
        BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'b'}, uint256{123}), uint8_t{0}));
        BOOST_CHECK(!db.CheckGenesisBlock(Params().GetConsensus().hashGenesisBlock));
        BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'b'}, Params().GetConsensus().hashGenesisBlock), uint8_t{0}));
        BOOST_CHECK(db.CheckGenesisBlock(Params().GetConsensus().hashGenesisBlock));
    }
}

BOOST_AUTO_TEST_CASE(last_block_file_record)
{
    node::BlockTreeDB db{{.path = "", .cache_bytes = 1 << 20, .memory_only = true}};
    constexpr uint8_t key{'l'};
    int file_num{123};
    BOOST_CHECK(!db.ReadLastBlockFile(file_num));
    BOOST_CHECK_EQUAL(file_num, 123);
    for (const int valid : {0, 42, node::MAX_BLOCKFILE_ENTRIES - 1}) {
        BOOST_REQUIRE(db.Write(key, valid));
        BOOST_REQUIRE(db.ReadLastBlockFile(file_num));
        BOOST_CHECK_EQUAL(file_num, valid);
    }
    const auto check_malformed = [&] {
        file_num = 123;
        BOOST_CHECK_THROW(db.ReadLastBlockFile(file_num), node::BlockTreeDB::InvalidLastBlockFile);
        BOOST_CHECK_EQUAL(file_num, 123);
    };
    BOOST_REQUIRE(db.Write(key, std::array<uint8_t, 0>{}));
    check_malformed();
    BOOST_REQUIRE(db.Write(key, uint8_t{0}));
    check_malformed();
    BOOST_REQUIRE(db.Write(key, std::array<uint8_t, 3>{}));
    check_malformed();
    BOOST_REQUIRE(db.Write(key, std::array<uint8_t, 5>{}));
    check_malformed();
    for (const int invalid : {-1, -2, std::numeric_limits<int>::min()}) {
        BOOST_REQUIRE(db.Write(key, invalid));
        check_malformed();
    }
    for (const int excessive : {node::MAX_BLOCKFILE_ENTRIES, 500'000'000, std::numeric_limits<int>::max()}) {
        BOOST_REQUIRE(db.Write(key, excessive));
        BOOST_CHECK_THROW(db.ReadLastBlockFile(file_num), node::BlockFileLimitError);
        BOOST_CHECK_EQUAL(file_num, 123);
    }

    // Exercise the forward scan's boundary without allocating a million entries.
    CBlockFileInfo info;
    BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'f'}, node::MAX_BLOCKFILE_ENTRIES - 1), info));
    BOOST_CHECK(db.ReadBlockFileInfo(node::MAX_BLOCKFILE_ENTRIES - 1, info));
    BOOST_CHECK(!db.ReadBlockFileInfo(node::MAX_BLOCKFILE_ENTRIES, info));
    BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'f'}, node::MAX_BLOCKFILE_ENTRIES), info));
    BOOST_CHECK_THROW(db.ReadBlockFileInfo(node::MAX_BLOCKFILE_ENTRIES, info), node::BlockFileLimitError);
    // A malformed boundary record is not mistaken for the end of the scan.
    BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'f'}, node::MAX_BLOCKFILE_ENTRIES), uint8_t{0}));
    BOOST_CHECK_THROW(db.ReadBlockFileInfo(node::MAX_BLOCKFILE_ENTRIES, info), node::BlockFileLimitError);
}

BOOST_AUTO_TEST_CASE(last_block_file_loading)
{
    kernel::Notifications notifications;
    const BlockManager::Options opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{.path = "", .cache_bytes = 1 << 20, .memory_only = true},
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};
    auto& db = *blockman.m_block_tree_db;
    LOCK(cs_main);
    BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
    BOOST_CHECK_THROW(blockman.GetBlockFileInfo(1), std::out_of_range);

    CBlockFileInfo info;
    info.nSize = 42;
    const CBlockFileInfo pruned;
    BOOST_REQUIRE(db.WriteBatchSync({{0, &info}, {1, &pruned}, {2, &info}}, 2, {}));
    BOOST_REQUIRE(db.Erase(uint8_t{'l'}));
    BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
    BOOST_CHECK_THROW(blockman.GetBlockFileInfo(3), std::out_of_range);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(1)->nSize, 0U);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(2)->nSize, 42U);
    BOOST_REQUIRE(blockman.WriteBlockIndexDB());
    int recovered_file{-1};
    BOOST_REQUIRE(db.ReadLastBlockFile(recovered_file));
    BOOST_CHECK_EQUAL(recovered_file, 2);
    // Retain forward scanning after an explicitly stored, older last-file value.
    BOOST_REQUIRE(db.Write(uint8_t{'l'}, 0));
    BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
    BOOST_CHECK_THROW(blockman.GetBlockFileInfo(3), std::out_of_range);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(2)->nSize, 42U);
    // Also retain the historical allowance for holes before an explicit last file.
    BOOST_REQUIRE(db.Erase(std::make_pair(uint8_t{'f'}, 1)));
    BOOST_REQUIRE(db.Write(uint8_t{'l'}, 2));
    BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
    BOOST_CHECK_THROW(blockman.GetBlockFileInfo(3), std::out_of_range);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(2)->nSize, 42U);

    BOOST_REQUIRE(db.Write(uint8_t{'l'}, -1));
    BOOST_CHECK_THROW(blockman.LoadBlockIndexDB(std::nullopt), node::BlockTreeDB::InvalidLastBlockFile);
    BOOST_CHECK_THROW(blockman.GetBlockFileInfo(3), std::out_of_range);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(2)->nSize, 42U);
    for (const int excessive : {node::MAX_BLOCKFILE_ENTRIES, std::numeric_limits<int>::max()}) {
        BOOST_REQUIRE(db.Write(uint8_t{'l'}, excessive));
        BOOST_CHECK_THROW(blockman.LoadBlockIndexDB(std::nullopt), node::BlockFileLimitError);
        BOOST_CHECK_THROW(blockman.GetBlockFileInfo(3), std::out_of_range);
        BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(2)->nSize, 42U);
    }

    // The existing file-presence check alone would accept this file. Its index
    // must still have a corresponding slot, for block and undo users alike.
    BOOST_REQUIRE(db.Write(uint8_t{'l'}, 0));
    BOOST_REQUIRE(db.Erase(std::make_pair(uint8_t{'f'}, 2)));
    BOOST_REQUIRE(!blockman.OpenBlockFile({1, 0}, false).IsNull());
    CBlockIndex index{Params().GenesisBlock()};
    const uint256 hash{Params().GenesisBlock().GetHash()};
    index.phashBlock = &hash;
    index.nFile = 1;
    for (const auto status : {BLOCK_HAVE_DATA, BLOCK_HAVE_UNDO}) {
        index.nStatus = status;
        BOOST_REQUIRE(db.WriteBatchSync({}, 0, {&index}));
        BOOST_CHECK(!blockman.LoadBlockIndexDB(std::nullopt));
    }
}

BOOST_AUTO_TEST_CASE(last_block_file_load_errors)
{
    kernel::Notifications notifications;
    const ChainstateManager::Options chain_opts{
        .chainparams = Params(),
        .datadir = m_args.GetDataDirNet(),
        .notifications = notifications,
    };
    const BlockManager::Options block_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{.path = "", .cache_bytes = 1 << 20, .memory_only = true},
    };
    for (const int file_num : {-1, node::MAX_BLOCKFILE_ENTRIES, 0x41414141}) {
        ChainstateManager chainman{*Assert(m_node.shutdown_signal), chain_opts, block_opts};
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->WriteDatabaseFormatVersion());
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Write(uint8_t{'l'}, file_num));
        node::ChainstateLoadOptions load_opts;
        load_opts.coins_db_in_memory = true;
        const auto [status, error] = node::LoadChainstate(chainman, kernel::CacheSizes{1 << 20}, load_opts);
        BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE);
        BOOST_CHECK(error.original.find(strprintf("%d", file_num)) != std::string::npos);
        if (file_num >= node::MAX_BLOCKFILE_ENTRIES) {
            BOOST_CHECK(error.original.find("Invalid or unsupported block file number") != std::string::npos);
            BOOST_CHECK(error.original.find("full rebuild with -reindex may repair it") != std::string::npos);
            BOOST_CHECK(error.original.find("Rebuilding does not increase the supported limit") != std::string::npos);
        }
        BOOST_CHECK_THROW(chainman.m_blockman.GetBlockFileInfo(0), std::out_of_range);
        int stored;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(uint8_t{'l'}, stored));
        BOOST_CHECK_EQUAL(stored, file_num);
    }
}

BOOST_FIXTURE_TEST_CASE(last_block_file_reindex_recovery, TestChain100Setup)
{
    // Use a separate copy so a failed load/rebuild cannot affect the fixture.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    auto& original = *m_node.chainman;
    const auto datadir = m_args.GetDataDirNet() / "last-file-reindex";
    const auto blocks_dir = datadir / "blocks";
    fs::create_directories(blocks_dir);
    kernel::Notifications notifications;
    const ChainstateManager::Options chain_opts{
        .chainparams = Params(),
        .datadir = datadir,
        .notifications = notifications,
    };
    BlockManager::Options block_opts{
        .chainparams = Params(),
        .blocks_dir = blocks_dir,
        .notifications = notifications,
        .block_tree_db_params = DBParams{.path = blocks_dir / "index", .cache_bytes = 1 << 20},
    };
    constexpr int damaged_file_num{0x41414141};
    uint256 expected_tip;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(original.ActiveChainstate().ForceFlushStateToDisk());
        expected_tip = original.ActiveTip()->GetBlockHash();
        BOOST_REQUIRE_EQUAL(original.ActiveTip()->nFile, 0);
        BOOST_REQUIRE(fs::copy_file(original.m_blockman.GetBlockPosFilename({0, 0}), blocks_dir / "blk00000.dat", fs::copy_options::none));
        BOOST_REQUIRE(fs::copy_file(m_args.GetBlocksDirPath() / "xor.dat", blocks_dir / "xor.dat", fs::copy_options::none));
        std::vector<const CBlockIndex*> records;
        for (const auto* index : original.m_blockman.GetAllBlockIndices()) records.push_back(index);
        node::BlockTreeDB db{block_opts.block_tree_db_params};
        BOOST_REQUIRE(db.WriteDatabaseFormatVersion());
        BOOST_REQUIRE(db.WriteBatchSync({{0, original.m_blockman.GetBlockFileInfo(0)}}, damaged_file_num, records));
    }
    const auto original_blocks = ReadBinaryFile(blocks_dir / "blk00000.dat");
    BOOST_REQUIRE(original_blocks.first);

    // Normal startup and -reindex-chainstate must preserve the damaged record
    // and offer full rebuilding. Only -reindex replaces the block index.
    for (int attempt{0}; attempt < 4; ++attempt) {
        block_opts.block_tree_db_params.wipe_data = attempt == 2;
        ChainstateManager chainman{*Assert(m_node.shutdown_signal), chain_opts, block_opts};
        node::ChainstateLoadOptions load_opts;
        load_opts.wipe_chainstate_db = attempt == 1 || attempt == 2;
        const auto [status, error] = node::LoadChainstate(chainman, kernel::CacheSizes{8 << 20}, load_opts);
        if (attempt < 2) {
            BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE);
            BOOST_CHECK(error.original.find("full rebuild with -reindex may repair it") != std::string::npos);
            int stored;
            BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(uint8_t{'l'}, stored));
            BOOST_CHECK_EQUAL(stored, damaged_file_num);
            const auto unchanged_blocks = ReadBinaryFile(blocks_dir / "blk00000.dat");
            BOOST_REQUIRE(unchanged_blocks.first);
            BOOST_CHECK(unchanged_blocks.second == original_blocks.second);
            continue;
        }
        BOOST_REQUIRE_MESSAGE(status == node::ChainstateLoadStatus::SUCCESS, error.original);
        if (attempt == 2) {
            bool reindexing{false};
            chainman.m_blockman.m_block_tree_db->ReadReindexing(reindexing);
            BOOST_REQUIRE(reindexing);
            node::ImportBlocks(chainman, {});
            chainman.m_blockman.m_block_tree_db->ReadReindexing(reindexing);
            BOOST_CHECK(!reindexing);
        }
        const auto [verify_status, verify_error] = node::VerifyLoadedChainstate(chainman, load_opts);
        BOOST_CHECK_MESSAGE(verify_status == node::ChainstateLoadStatus::SUCCESS, verify_error.original);
        LOCK(cs_main);
        BOOST_REQUIRE(chainman.ActiveTip());
        BOOST_CHECK_EQUAL(chainman.ActiveHeight(), 100);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == expected_tip);
        BOOST_REQUIRE(chainman.ActiveChainstate().ForceFlushStateToDisk());
        int last_file{-1};
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->ReadLastBlockFile(last_file));
        BOOST_CHECK_EQUAL(last_file, 0);
        chainman.ActiveChainstate().ResetCoinsViews();
    }
}

BOOST_AUTO_TEST_CASE(block_file_limit_preserves_cursors)
{
    struct Notifications : kernel::Notifications {
        std::vector<std::string> errors;
        void fatalError(const bilingual_str& message) override { errors.push_back(message.original); }
    } notifications;
    const BlockManager::Options opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{.path = "", .cache_bytes = 1 << 20, .memory_only = true},
    };
    LOCK(cs_main);
    const auto& block = Params().GenesisBlock();
    const auto check_last_file = [](BlockManager& blockman) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        BOOST_REQUIRE(blockman.WriteBlockIndexDB());
        int last_file{-1};
        BOOST_REQUIRE(blockman.m_block_tree_db->ReadLastBlockFile(last_file));
        BOOST_CHECK_EQUAL(last_file, node::MAX_BLOCKFILE_ENTRIES - 1);
        BOOST_CHECK_THROW(blockman.GetBlockFileInfo(node::MAX_BLOCKFILE_ENTRIES), std::out_of_range);
    };
    {
        BlockManager blockman{*Assert(m_node.shutdown_signal), opts};
        blockman.m_snapshot_height = 1;
        // Seed two cursors through the production reindex path, without creating
        // a million database records or block files. The array uses about 48 MiB.
        blockman.UpdateBlockInfo(block, 0, {0, 0});
        blockman.UpdateBlockInfo(block, 1, {node::MAX_BLOCKFILE_ENTRIES - 1, 0});
        blockman.GetBlockFileInfo(0)->nSize = MAX_BLOCKFILE_SIZE;
        BOOST_CHECK(blockman.WriteBlock(block, 0).IsNull());
        BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(0)->nSize, MAX_BLOCKFILE_SIZE);
        check_last_file(blockman);
        // The rejected rollover must leave NORMAL pointing to file zero.
        blockman.GetBlockFileInfo(0)->nSize = 0;
        BOOST_CHECK_EQUAL(blockman.WriteBlock(block, 0).nFile, 0);
    }
    {
        BlockManager blockman{*Assert(m_node.shutdown_signal), opts};
        blockman.UpdateBlockInfo(block, 0, {node::MAX_BLOCKFILE_ENTRIES - 1, 0});
        blockman.m_snapshot_height = 1;
        // Starting snapshot storage must not publish an unsupported cursor.
        BOOST_CHECK(blockman.WriteBlock(block, 1).IsNull());
        check_last_file(blockman);
    }
    {
        BlockManager blockman{*Assert(m_node.shutdown_signal), opts};
        // Model a caller violating the reindex boundary. Allocation must still
        // reject an unsupported current cursor before modifying it or the file.
        blockman.UpdateBlockInfo(block, 0, {node::MAX_BLOCKFILE_ENTRIES, 0});
        const auto size_before = blockman.GetBlockFileInfo(node::MAX_BLOCKFILE_ENTRIES)->nSize;
        BOOST_CHECK(blockman.WriteBlock(block, 0).IsNull());
        BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(node::MAX_BLOCKFILE_ENTRIES)->nSize, size_before);
    }
    BOOST_REQUIRE_EQUAL(notifications.errors.size(), 3U);
    for (const auto& error : notifications.errors) {
        BOOST_CHECK(error.find("1048576") != std::string::npos);
    }
    BOOST_CHECK(!fs::exists(m_args.GetBlocksDirPath() / "blk1048576.dat"));
}

BOOST_AUTO_TEST_CASE(reindex_preserves_unsupported_database_format)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const DBParams params{.path = m_args.GetDataDirNet() / "format-index", .cache_bytes = 1 << 20};
    auto reindex_params = params;
    reindex_params.wipe_data = true;
    const BlockManager::Options opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = reindex_params,
    };
    for (const auto width : {1, 4, 8}) {
        {
            node::BlockTreeDB db{params};
            if (width == 1) BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint8_t{1}));
            if (width == 4) BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint32_t{999}));
            if (width == 8) BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint64_t{1}));
            BOOST_REQUIRE(db.WriteFlag("preserve", true));
        }
        BOOST_CHECK_EXCEPTION((BlockManager{*Assert(m_node.shutdown_signal), opts}), std::runtime_error,
            [width](const std::runtime_error& e) {
                return std::string{e.what()}.starts_with(width == 4 ? "Unsupported database format version" : "Invalid database format version");
            });
        node::BlockTreeDB db{params};
        bool preserved{false};
        BOOST_REQUIRE(db.ReadFlag("preserve", preserved));
        BOOST_CHECK(preserved);
        if (width == 4) {
            BOOST_CHECK_EQUAL(*db.ReadDatabaseFormatVersion(), 999U);
        } else {
            BOOST_CHECK_THROW(db.ReadDatabaseFormatVersion(), node::BlockTreeDB::InvalidFormatVersion);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(unlinked_blocks_unique_pairs, TestingSetup)
{
    LOCK(cs_main);
    auto& blockman = m_node.chainman->m_blockman;
    CBlockIndex parent, other_parent, first, sibling, other_child;
    first.pprev = sibling.pprev = &parent;
    other_child.pprev = &other_parent;
    for (auto* block : {&first, &sibling, &other_child}) block->nStatus |= BLOCK_HAVE_DATA;

    for (int repeat{0}; repeat < 3; ++repeat) {
        for (auto* block : {&first, &sibling, &other_child, &first}) blockman.AddUnlinkedBlock(block);
        BOOST_CHECK_EQUAL(blockman.m_blocks_unlinked.size(), 3U);
        BOOST_CHECK_EQUAL(blockman.m_blocks_unlinked.count(&parent), 2U);
        BOOST_CHECK_EQUAL(blockman.m_blocks_unlinked.count(&other_parent), 1U);
    }
    const auto [begin, end] = blockman.m_blocks_unlinked.equal_range(&parent);
    BOOST_CHECK_EQUAL(std::count_if(begin, end, [&](const auto& entry) { return entry.second == &first; }), 1);
    BOOST_CHECK_EQUAL(std::count_if(begin, end, [&](const auto& entry) { return entry.second == &sibling; }), 1);
    blockman.m_blocks_unlinked.clear();
}

BOOST_FIXTURE_TEST_CASE(unlinked_blocks_reload_skips_pruned_data, TestChain100Setup)
{
    // Finish notifications from fixture mining before rewriting their block indexes.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    LOCK(cs_main);
    auto& chainman = *m_node.chainman;
    auto& blockman = chainman.m_blockman;
    auto* missing = chainman.ActiveChain()[98];
    auto* pruned = chainman.ActiveChain()[99];
    auto* available = chainman.ActiveChain()[100];

    // Model an unreceived ancestor, followed by a previously received but
    // pruned block and a descendant whose data is still available.
    missing->nStatus = BLOCK_VALID_TREE;
    missing->nTx = 0;
    missing->m_chain_tx_count = 0;
    missing->nSequenceId = 0;
    missing->nDataPos = missing->nUndoPos = 0;
    pruned->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
    pruned->nDataPos = pruned->nUndoPos = 0;
    BOOST_REQUIRE(blockman.WriteBlockIndexDB());
    BOOST_REQUIRE(blockman.m_block_tree_db->WriteBatchSync({}, available->nFile, {missing, pruned}));
    BOOST_REQUIRE(blockman.m_block_tree_db->WriteFlag("prunedblockfiles", true));

    for (int repeat{0}; repeat < 2; ++repeat) {
        BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
        BOOST_CHECK(!pruned->HaveNumChainTxs());
        BOOST_CHECK(!available->HaveNumChainTxs());
        BOOST_REQUIRE_EQUAL(blockman.m_blocks_unlinked.size(), 1U);
        BOOST_CHECK(blockman.m_blocks_unlinked.begin()->first == pruned);
        BOOST_CHECK(blockman.m_blocks_unlinked.begin()->second == available);
    }
}

BOOST_FIXTURE_TEST_CASE(legacy_invalidity_roundtrip, TestChain100Setup)
{
    LOCK(cs_main);
    const auto& chain = m_node.chainman->ActiveChain();
    const auto* child = chain.Tip();
    const auto* parent = child->pprev;

    // Serialize a legacy failure with valid ancestors, as can remain after
    // reconsidering a sibling. An invalid ancestor must not mask a broken
    // conversion by supplying the parent's failure flag through propagation.
    CDiskBlockIndex legacy_parent{parent};
    legacy_parent.nStatus |= BLOCK_FAILED_CHILD;
    std::vector<const CBlockIndex*> records;
    for (int height{0}; height <= chain.Height(); ++height) {
        BOOST_REQUIRE_EQUAL(chain[height]->nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD), 0U);
        records.push_back(height == parent->nHeight ? &legacy_parent : chain[height]);
    }

    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "legacy-invalidity-index",
            .cache_bytes = 1 << 20,
            .memory_only = false,
        },
    };
    {
        node::BlockTreeDB db{blockman_opts.block_tree_db_params};
        BOOST_REQUIRE(db.WriteBatchSync({}, child->nFile, records));
    }

    // Open a fresh database and block manager each time. The second load must
    // read already-normalized records, without needing to repair them again.
    for (int reopen{0}; reopen < 2; ++reopen) {
        BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
        if (reopen == 1) {
            // Inspect persisted records before normalization can repair them.
            // This proves the first load scheduled both changed entries for
            // WriteBlockIndexDB, without exposing its private dirty set.
            node::BlockMap persisted;
            BOOST_REQUIRE(blockman.m_block_tree_db->LoadBlockIndexGuts(
                Params().GetConsensus(),
                [&persisted](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> CBlockIndex* {
                    if (hash.IsNull()) return nullptr;
                    auto [it, inserted] = persisted.try_emplace(hash);
                    it->second.phashBlock = &it->first;
                    return &it->second;
                },
                *Assert(m_node.shutdown_signal)));
            for (int height{0}; height <= chain.Height(); ++height) {
                const auto* original = chain[height];
                const auto it = persisted.find(original->GetBlockHash());
                BOOST_REQUIRE(it != persisted.end());
                const uint32_t expected_status{original->nStatus | (height >= parent->nHeight ? BLOCK_FAILED_VALID : 0U)};
                BOOST_CHECK_EQUAL(it->second.nStatus, expected_status);
            }
        }
        BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
        for (int height{0}; height <= chain.Height(); ++height) {
            const auto* original = chain[height];
            auto* loaded = blockman.LookupBlockIndex(original->GetBlockHash());
            BOOST_REQUIRE(loaded);
            const uint32_t expected_status{original->nStatus | (height >= parent->nHeight ? BLOCK_FAILED_VALID : 0U)};
            // Compare the complete status so validity, data, undo and witness
            // flags must survive conversion, persistence and reloading.
            BOOST_CHECK_EQUAL(loaded->nStatus, expected_status);
        }
        BOOST_REQUIRE(blockman.WriteBlockIndexDB());
    }
}

BOOST_AUTO_TEST_CASE(blockmanager_find_block_pos)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
    // simulate adding a genesis block normally
    BOOST_CHECK_EQUAL(blockman.WriteBlock(params->GenesisBlock(), 0).nPos, STORAGE_HEADER_BYTES);
    // simulate what happens during reindex
    // simulate a well-formed genesis block being found at offset 8 in the blk00000.dat file
    // the block is found at offset 8 because there is an 8 byte serialization header
    // consisting of 4 magic bytes + 4 length bytes before each block in a well-formed blk file.
    const FlatFilePos pos{0, STORAGE_HEADER_BYTES};
    blockman.UpdateBlockInfo(params->GenesisBlock(), 0, pos);
    // now simulate what happens after reindex for the first new block processed
    // the actual block contents don't matter, just that it's a block.
    // verify that the write position is at offset 0x12d.
    // this is a check to make sure that https://github.com/bitcoin/bitcoin/issues/21379 does not recur
    // 8 bytes (for serialization header) + 285 (for serialized genesis block) = 293
    // add another 8 bytes for the second block's serialization header and we get 293 + 8 = 301
    FlatFilePos actual{blockman.WriteBlock(params->GenesisBlock(), 1)};
    BOOST_CHECK_EQUAL(actual.nPos, STORAGE_HEADER_BYTES + ::GetSerializeSize(TX_WITH_WITNESS(params->GenesisBlock())) + STORAGE_HEADER_BYTES);
}

BOOST_FIXTURE_TEST_CASE(blockmanager_scan_unlink_already_pruned_files, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    const auto& chainman = Assert(m_node.chainman);
    auto& blockman = chainman->m_blockman;
    const CBlockIndex* old_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    WITH_LOCK(chainman->GetMutex(), blockman.GetBlockFileInfo(old_tip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    // Prune the older block file, but don't unlink it
    int file_number;
    {
        LOCK(chainman->GetMutex());
        file_number = old_tip->GetBlockPos().nFile;
        blockman.PruneOneBlockFile(file_number);
    }

    const FlatFilePos pos(file_number, 0);

    // Check that the file is not unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // if m_have_pruned is not yet set
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!blockman.OpenBlockFile(pos, true).IsNull());

    // Check that the file is unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // once m_have_pruned is set
    blockman.m_have_pruned = true;
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(blockman.OpenBlockFile(pos, true).IsNull());

    // Check that calling with already pruned files doesn't cause an error
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());

    // Check that the new tip file has not been removed
    const CBlockIndex* new_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    BOOST_CHECK_NE(old_tip, new_tip);
    const int new_file_number{WITH_LOCK(chainman->GetMutex(), return new_tip->GetBlockPos().nFile)};
    const FlatFilePos new_pos(new_file_number, 0);
    BOOST_CHECK(!blockman.OpenBlockFile(new_pos, true).IsNull());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_availability, TestChain100Setup)
{
    // The goal of the function is to return the first not pruned block in the range [upper_block, lower_block].
    LOCK(::cs_main);
    auto& chainman = m_node.chainman;
    auto& blockman = chainman->m_blockman;
    const CBlockIndex& tip = *chainman->ActiveTip();

    // Function to prune all blocks from 'last_pruned_block' down to the genesis block
    const auto& func_prune_blocks = [&](CBlockIndex* last_pruned_block)
    {
        LOCK(::cs_main);
        CBlockIndex* it = last_pruned_block;
        while (it != nullptr && it->nStatus & BLOCK_HAVE_DATA) {
            it->nStatus &= ~BLOCK_HAVE_DATA;
            it = it->pprev;
        }
    };

    // 1) Return genesis block when all blocks are available
    BOOST_CHECK_EQUAL(blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), chainman->ActiveChain()[0]);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *chainman->ActiveChain()[0]));

    // 2) Check lower_block when all blocks are available
    CBlockIndex* lower_block = chainman->ActiveChain()[tip.nHeight / 2];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *lower_block));

    // Prune half of the blocks
    int height_to_prune = tip.nHeight / 2;
    CBlockIndex* first_available_block = chainman->ActiveChain()[height_to_prune + 1];
    CBlockIndex* last_pruned_block = first_available_block->pprev;
    func_prune_blocks(last_pruned_block);

    // 3) The last block not pruned is in-between upper-block and the genesis block
    BOOST_CHECK_EQUAL(blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), first_available_block);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block));
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *last_pruned_block));
}

BOOST_FIXTURE_TEST_CASE(block_header_prefix_read, TestingSetup)
{
    LOCK(cs_main);
    auto& chainman = *m_node.chainman;
    auto& blockman = chainman.m_blockman;
    CBlockHeader header;
    header.SetBaseVersion(2, Params().GetConsensus().nAuxpowChainId);
    header.SetAuxpowVersion(true);
    header.auxpow = std::make_shared<CAuxPow>();
    // A multi-buffer proof. Its work is intentionally not checked during a disk read.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig.resize(9000);
    DataStream proof;
    proof << TX_WITH_WITNESS(MakeTransactionRef(tx)) << uint256{} << std::vector<uint256>{}
          << int32_t{0} << std::vector<uint256>{} << int32_t{0} << CBlockHeader{};
    proof >> *header.auxpow;
    const auto hash = header.GetHash();
    CBlockIndex index{header};
    index.phashBlock = &hash;
    index.nStatus |= BLOCK_HAVE_DATA;
    index.nTx = 1;
    DataStream encoded;
    encoded << header;
    const std::vector<std::byte> bytes{encoded.begin(), encoded.end()};
    const auto expect_error = [&](HeaderReadError expected) {
        const auto result = index.GetBlockHeader(chainman);
        BOOST_REQUIRE(std::holds_alternative<HeaderReadError>(result));
        BOOST_CHECK(std::get<HeaderReadError>(result) == expected);
    };
    // Exercise the existing XOR file API and positions above 32 bits without allocating a large file.
    for (const uint64_t start : {uint64_t{0}, uint64_t{1} << 32}) {
        index.nFile = start == 0 ? 77 : 78;
        index.nDataPos = start + STORAGE_HEADER_BYTES;
#ifdef WIN32
        if (start != 0) {
            auto file = blockman.OpenBlockFile({index.nFile, 0}, false);
            FILE* raw_file = file.release();
            BOOST_REQUIRE(raw_file != nullptr);
            AutoFile owner{raw_file};
            DWORD returned{0};
            const bool sparse = DeviceIoControl(reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(raw_file))),
                                                FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr) != 0;
            BOOST_REQUIRE_EQUAL(owner.fclose(), 0);
            if (!sparse) {
                BOOST_TEST_MESSAGE("Skipping wide header position: filesystem does not support sparse files");
                continue;
            }
        }
#endif
        const auto write = [&](uint32_t record_size, size_t actual_size, bool good_magic = true) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            auto file = blockman.OpenBlockFile({index.nFile, start}, /*fReadOnly=*/false);
            BOOST_REQUIRE(!file.IsNull());
            auto magic = Params().MessageStart();
            if (!good_magic) magic[0] ^= 1;
            file << magic << record_size;
            file.write(std::span{bytes}.first(actual_size));
            BOOST_REQUIRE(file.Commit());
            BOOST_REQUIRE(file.Truncate(start + STORAGE_HEADER_BYTES + actual_size));
            BOOST_REQUIRE_EQUAL(file.fclose(), 0);
        };
        // Only the header exists at EOF, despite a large declared record. Old whole-block reads fail.
        write(MAX_BLOCK_SERIALIZED_SIZE, bytes.size());
        auto result = index.GetBlockHeader(chainman);
        BOOST_REQUIRE(std::holds_alternative<CBlockHeader>(result));
        DataStream read;
        read << std::get<CBlockHeader>(result);
        BOOST_CHECK(std::ranges::equal(read, bytes));
        // Complete bytes exist after the claimed record boundary: they must not be consumed.
        write(bytes.size() - 1, bytes.size());
        expect_error(HeaderReadError::READ_ERROR);
        write(bytes.size(), bytes.size() - 1);
        expect_error(HeaderReadError::READ_ERROR);
        write(79, bytes.size());
        expect_error(HeaderReadError::READ_ERROR);
        write(MAX_SIZE + 1, bytes.size());
        expect_error(HeaderReadError::READ_ERROR);
        write(bytes.size(), bytes.size(), false);
        expect_error(HeaderReadError::READ_ERROR);
        write(bytes.size(), bytes.size());
        index.phashBlock = &uint256::ONE;
        expect_error(HeaderReadError::READ_ERROR);
        index.phashBlock = &hash;
    }
    index.nFile = 77;
    index.nDataPos = STORAGE_HEADER_BYTES;
    // A record can be large enough while its header exceeds the necessary header bound.
    tx.vin[0].scriptSig.resize(MAX_BLOCK_HEADER_SIZE);
    DataStream large_proof;
    large_proof << TX_WITH_WITNESS(MakeTransactionRef(tx)) << uint256{} << std::vector<uint256>{}
                << int32_t{0} << std::vector<uint256>{} << int32_t{0} << CBlockHeader{};
    large_proof >> *header.auxpow;
    BOOST_CHECK(IsOversizedAuxPowHeader(header));
    {
        auto file = blockman.OpenBlockFile({index.nFile, index.nDataPos - STORAGE_HEADER_BYTES}, false);
        file << Params().MessageStart() << uint32_t(GetSerializeSize(header)) << header;
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
    expect_error(HeaderReadError::READ_ERROR);
    // Equality is permitted by the necessary bound; complete block validity is separate.
    tx.vin[0].scriptSig.resize(2 * MAX_BLOCK_HEADER_SIZE - GetSerializeSize(header));
    DataStream exact_proof;
    exact_proof << TX_WITH_WITNESS(MakeTransactionRef(tx)) << uint256{} << std::vector<uint256>{}
                << int32_t{0} << std::vector<uint256>{} << int32_t{0} << CBlockHeader{};
    exact_proof >> *header.auxpow;
    BOOST_CHECK_EQUAL(GetSerializeSize(header), MAX_BLOCK_HEADER_SIZE);
    BOOST_CHECK(!IsOversizedAuxPowHeader(header));
    {
        auto file = blockman.OpenBlockFile({index.nFile, index.nDataPos - STORAGE_HEADER_BYTES}, false);
        file << Params().MessageStart() << uint32_t(GetSerializeSize(header)) << header;
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
    BOOST_CHECK(std::holds_alternative<CBlockHeader>(index.GetBlockHeader(chainman)));
    index.nStatus &= ~BLOCK_HAVE_DATA;
    index.nTx = 0;
    expect_error(HeaderReadError::NOT_DOWNLOADED);
    blockman.m_have_pruned = true;
    index.nTx = 1;
    expect_error(HeaderReadError::PRUNED);
    // Ordinary header metadata remains reconstructible without stored block data.
    index.nVersion = 1;
    BOOST_CHECK(std::holds_alternative<CBlockHeader>(index.GetBlockHeader(chainman)));
}

BOOST_FIXTURE_TEST_CASE(blockmanager_readblock_hash_mismatch, TestingSetup)
{
    CBlockIndex index;
    {
        LOCK(cs_main);
        const auto tip{m_node.chainman->ActiveTip()};
        index.nStatus = tip->nStatus;
        index.nDataPos = tip->nDataPos;
        index.phashBlock = &uint256::ONE; // mismatched block hash
    }

    ASSERT_DEBUG_LOG("GetHash() doesn't match index");
    CBlock block;
    BOOST_CHECK(!m_node.chainman->m_blockman.ReadBlock(block, index));
}

BOOST_AUTO_TEST_CASE(blockmanager_flush_block_file)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    // Test blocks with no transactions, not even a coinbase
    CBlock block1;
    block1.nVersion = 1;
    CBlock block2;
    block2.nVersion = 2;
    CBlock block3;
    block3.nVersion = 3;

    // They are 80 bytes header + 1 byte 0x00 for vtx length
    constexpr int TEST_BLOCK_SIZE{81};

    // Blockstore is empty
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), 0);

    // Write the first block to a new location.
    FlatFilePos pos1{blockman.WriteBlock(block1, /*nHeight=*/1)};

    // Write second block
    FlatFilePos pos2{blockman.WriteBlock(block2, /*nHeight=*/2)};

    // Two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + STORAGE_HEADER_BYTES) * 2);

    // First two blocks are written as expected
    // Errors are expected because block data is junk, thrown AFTER successful read
    CBlock read_block;
    BOOST_CHECK_EQUAL(read_block.nVersion, 0);
    {
        ASSERT_DEBUG_LOG("Errors in block header");
        BOOST_CHECK(!blockman.ReadBlock(read_block, pos1, {}));
        BOOST_CHECK_EQUAL(read_block.nVersion, 1);
    }
    {
        ASSERT_DEBUG_LOG("Errors in block header");
        BOOST_CHECK(!blockman.ReadBlock(read_block, pos2, {}));
        BOOST_CHECK_EQUAL(read_block.nVersion, 2);
    }

    // During reindex, the flat file block storage will not be written to.
    // UpdateBlockInfo will, however, update the blockfile metadata.
    // Verify this behavior by attempting (and failing) to write block 3 data
    // to block 2 location.
    CBlockFileInfo* block_data = blockman.GetBlockFileInfo(0);
    BOOST_CHECK_EQUAL(block_data->nBlocks, 2);
    blockman.UpdateBlockInfo(block3, /*nHeight=*/3, /*pos=*/pos2);
    // Metadata is updated...
    BOOST_CHECK_EQUAL(block_data->nBlocks, 3);
    // ...but there are still only two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + STORAGE_HEADER_BYTES) * 2);

    // Block 2 was not overwritten:
    BOOST_CHECK(!blockman.ReadBlock(read_block, pos2, {}));
    BOOST_CHECK_EQUAL(read_block.nVersion, 2);
}

BOOST_FIXTURE_TEST_CASE(prune_lock_update_and_delete, TestingSetup)
{
    LOCK(::cs_main);
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};

    // Create a prune lock
    blockman.UpdatePruneLock("test_lock", node::PruneLockInfo{.height_first = 100});

    // Update it to a new height
    blockman.UpdatePruneLock("test_lock", node::PruneLockInfo{.height_first = 200});

    // Delete existing prune lock
    BOOST_CHECK(blockman.DeletePruneLock("test_lock"));

    // Verify deletion worked by trying to delete the same lock again
    BOOST_CHECK(!blockman.DeletePruneLock("test_lock"));

    // Deleting a non-existent lock returns false
    BOOST_CHECK(!blockman.DeletePruneLock("nonexistent"));
}

BOOST_AUTO_TEST_SUITE_END()
