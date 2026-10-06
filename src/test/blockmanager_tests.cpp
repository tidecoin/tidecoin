// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <util/chaintype.h>
#include <validation.h>

#include <algorithm>
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

BOOST_AUTO_TEST_SUITE_END()
