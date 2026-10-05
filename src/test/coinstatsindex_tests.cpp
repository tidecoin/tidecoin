// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <index/coinstatsindex.h>
#include <interfaces/chain.h>
#include <kernel/coinstats.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <txdb.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(coinstatsindex_tests)

BOOST_FIXTURE_TEST_CASE(coinstats_cursor_snapshot, TestChain100Setup)
{
    using kernel::CoinStatsHashType;
    // Model a tip change between a separate GetBestBlock() read and Cursor().
    // The cursor must be created under cs_main, and its block is authoritative.
    class SnapshotView : public CCoinsViewBacked {
        const uint256 m_old_tip;
    public:
        SnapshotView(CCoinsView* view, const uint256& old_tip) : CCoinsViewBacked{view}, m_old_tip{old_tip} {}
        uint256 GetBestBlock() const override { return m_old_tip; }
        std::unique_ptr<CCoinsViewCursor> Cursor() const override EXCLUSIVE_LOCKS_REQUIRED(cs_main)
        {
            AssertLockHeld(cs_main);
            return base->Cursor();
        }
    };

    auto& chainstate = m_node.chainman->ActiveChainstate();
    const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    for (const auto hash_type : {CoinStatsHashType::NONE, CoinStatsHashType::MUHASH, CoinStatsHashType::HASH_SERIALIZED}) {
        chainstate.ForceFlushStateToDisk();
        const auto expected = kernel::ComputeUTXOStats(hash_type, WITH_LOCK(cs_main, return &chainstate.CoinsDB()), chainstate.m_blockman);
        BOOST_REQUIRE(expected);
        const auto old_tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->pprev->GetBlockHash());
        SnapshotView view{WITH_LOCK(cs_main, return &chainstate.CoinsDB()), old_tip};
        bool advanced{false};
        const auto stats = kernel::ComputeUTXOStats(hash_type, &view, chainstate.m_blockman, [&] {
            // Once iteration starts, a subsequent flush must not change either
            // the cursor's contents or the metadata describing those contents.
            AssertLockNotHeld(cs_main);
            if (advanced) return;
            advanced = true;
            CreateAndProcessBlock({}, script_pub_key);
            chainstate.ForceFlushStateToDisk();
        });
        BOOST_REQUIRE(advanced);
        BOOST_REQUIRE(stats);
        BOOST_CHECK_EQUAL(stats->nHeight, expected->nHeight);
        BOOST_CHECK(stats->hashBlock == expected->hashBlock);
        BOOST_CHECK(stats->hashSerialized == expected->hashSerialized);
        BOOST_CHECK(stats->total_amount == expected->total_amount);
        BOOST_CHECK_EQUAL(stats->nTransactions, expected->nTransactions);
        BOOST_CHECK_EQUAL(stats->nTransactionOutputs, expected->nTransactionOutputs);
        BOOST_CHECK_EQUAL(stats->nBogoSize, expected->nBogoSize);
        BOOST_CHECK_EQUAL(stats->coins_count, expected->coins_count);
        BOOST_CHECK(WITH_LOCK(cs_main, return chainstate.CoinsDB().GetBestBlock()) != stats->hashBlock);
    }
}

BOOST_FIXTURE_TEST_CASE(coinstatsindex_initial_sync, TestChain100Setup)
{
    CoinStatsIndex coin_stats_index{interfaces::MakeChain(m_node), 1 << 20, true};
    BOOST_REQUIRE(coin_stats_index.Init());

    const CBlockIndex* block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->ActiveChain().Tip();
    }

    // CoinStatsIndex should not be found before it is started.
    BOOST_CHECK(!coin_stats_index.LookUpStats(*block_index));

    // BlockUntilSyncedToCurrentChain should return false before CoinStatsIndex
    // is started.
    BOOST_CHECK(!coin_stats_index.BlockUntilSyncedToCurrentChain());

    coin_stats_index.Sync();

    // Check that CoinStatsIndex works for genesis block.
    const CBlockIndex* genesis_block_index;
    {
        LOCK(cs_main);
        genesis_block_index = m_node.chainman->ActiveChain().Genesis();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(*genesis_block_index));

    // Check that CoinStatsIndex updates with new blocks.
    BOOST_CHECK(coin_stats_index.LookUpStats(*block_index));

    const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    std::vector<CMutableTransaction> noTxns;
    CreateAndProcessBlock(noTxns, script_pub_key);

    // Let the CoinStatsIndex to catch up again.
    BOOST_CHECK(coin_stats_index.BlockUntilSyncedToCurrentChain());

    const CBlockIndex* new_block_index;
    {
        LOCK(cs_main);
        new_block_index = m_node.chainman->ActiveChain().Tip();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(*new_block_index));

    BOOST_CHECK(block_index != new_block_index);

    // It is not safe to stop and destroy the index until it finishes handling
    // the last BlockConnected notification. The BlockUntilSyncedToCurrentChain()
    // call above is sufficient to ensure this, but the
    // SyncWithValidationInterfaceQueue() call below is also needed to ensure
    // TSAN always sees the test thread waiting for the notification thread, and
    // avoid potential false positive reports.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // Shutdown sequence (c.f. Shutdown() in init.cpp)
    coin_stats_index.Stop();
}

// Test shutdown between BlockConnected and ChainStateFlushed notifications,
// make sure index is not corrupted and is able to reload.
BOOST_FIXTURE_TEST_CASE(coinstatsindex_unclean_shutdown, TestChain100Setup)
{
    Chainstate& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    const CChainParams& params = Params();
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        index.Sync();
        std::shared_ptr<const CBlock> new_block;
        CBlockIndex* new_block_index = nullptr;
        {
            const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
            const CBlock block = this->CreateBlock({}, script_pub_key, chainstate);

            new_block = std::make_shared<CBlock>(block);

            LOCK(cs_main);
            BlockValidationState state;
            BOOST_CHECK(CheckBlock(block, state, params.GetConsensus()));
            BOOST_CHECK(m_node.chainman->AcceptBlock(new_block, state, &new_block_index, true, nullptr, nullptr, true));
            CCoinsViewCache view(&chainstate.CoinsTip());
            BOOST_CHECK(chainstate.ConnectBlock(block, state, new_block_index, view));
        }
        // Send block connected notification, then stop the index without
        // sending a chainstate flushed notification. Prior to #24138, this
        // would cause the index to be corrupted and fail to reload.
        ValidationInterfaceTest::BlockConnected(ChainstateRole::NORMAL, index, new_block, new_block_index);
        index.Stop();
    }

    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        // Make sure the index can be loaded.
        BOOST_REQUIRE(index.StartBackgroundSync());
        index.Stop();
    }
}

BOOST_AUTO_TEST_SUITE_END()
