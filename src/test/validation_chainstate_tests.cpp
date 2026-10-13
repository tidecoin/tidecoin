// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <consensus/validation.h>
#include <node/chainstate.h>
#include <node/kernel_notifications.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/coins.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_chainstate_tests, ChainTestingSetup)

BOOST_AUTO_TEST_CASE(recreate_memory_databases_with_existing_block_files)
{
    for (int i{0}; i < 3; ++i) {
        LoadVerifyActivateChainstate();
        {
            LOCK(cs_main);
            auto& chainman = *m_node.chainman;
            BOOST_CHECK_EQUAL(chainman.ActiveChain().Height(), 0);
            BOOST_CHECK_EQUAL(*chainman.m_blockman.m_block_tree_db->ReadDatabaseFormatVersion(), node::BlockTreeDB::DATABASE_FORMAT_VERSION);
            BOOST_CHECK(fs::exists(chainman.m_blockman.GetBlockPosFilename(FlatFilePos{0, 0})));
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.chainman.reset();
        m_make_chainman();
    }
}

BOOST_AUTO_TEST_CASE(database_format_checked_before_chainstate_rebuild)
{
    auto& chainman = *m_node.chainman;
    auto& db = WITH_LOCK(cs_main, return *chainman.m_blockman.m_block_tree_db);
    node::ChainstateLoadOptions options;
    options.coins_db_in_memory = true;
    options.wipe_chainstate_db = true;
    const auto check_status = [&](node::ChainstateLoadStatus expected) {
        const auto [status, error] = node::LoadChainstate(chainman, m_kernel_cache_sizes, options);
        BOOST_CHECK(status == expected);
        BOOST_CHECK(WITH_LOCK(cs_main, return chainman.GetAll().empty()));
    };

    // An unversioned index, even with an in-progress reindex, must not be
    // certified by deleting chainstate alone.
    BOOST_REQUIRE(db.WriteReindexing(true));
    check_status(node::ChainstateLoadStatus::FAILURE_REINDEX);
    BOOST_CHECK(!db.ReadDatabaseFormatVersion());
    BOOST_REQUIRE(db.WriteFlag("prunedblockfiles", true));
    check_status(node::ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB);
    BOOST_REQUIRE(db.WriteFlag("prunedblockfiles", false));

    BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint32_t{999}));
    check_status(node::ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB);
    BOOST_CHECK_EQUAL(*db.ReadDatabaseFormatVersion(), 999U);
    BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint8_t{1}));
    check_status(node::ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB);
}

//! Test resizing coins-related Chainstate caches during runtime.
//!
BOOST_AUTO_TEST_CASE(validation_chainstate_resize_caches)
{
    ChainstateManager& manager = *Assert(m_node.chainman);
    CTxMemPool& mempool = *Assert(m_node.mempool);
    Chainstate& c1 = WITH_LOCK(cs_main, return manager.InitializeChainstate(&mempool));
    c1.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);
    WITH_LOCK(::cs_main, c1.InitCoinsCache(1 << 23));
    BOOST_REQUIRE(c1.LoadGenesisBlock()); // Need at least one block loaded to be able to flush caches

    // Add a coin to the in-memory cache, upsize once, then downsize.
    {
        LOCK(::cs_main);
        const auto outpoint = AddTestCoin(m_rng, c1.CoinsTip());

        // Set a meaningless bestblock value in the coinsview cache - otherwise we won't
        // flush during ResizecoinsCaches() and will subsequently hit an assertion.
        c1.CoinsTip().SetBestBlock(m_rng.rand256());

        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 24,  // upsizing the coinsview cache
            1 << 22  // downsizing the coinsdb cache
        );

        // View should still have the coin cached, since we haven't destructed the cache on upsize.
        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 22,  // downsizing the coinsview cache
            1 << 23  // upsizing the coinsdb cache
        );

        // The view cache should be empty since we had to destruct to downsize.
        BOOST_CHECK(!c1.CoinsTip().HaveCoinInCache(outpoint));
    }
}

//! Test UpdateTip behavior for both active and background chainstates.
//!
//! When run on the background chainstate, UpdateTip should do a subset
//! of what it does for the active chainstate.
BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto get_notify_tip{[&]() {
        LOCK(m_node.notifications->m_tip_block_mutex);
        BOOST_REQUIRE(m_node.notifications->TipBlock());
        return *m_node.notifications->TipBlock();
    }};
    uint256 curr_tip = get_notify_tip();

    // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
    // be found.
    mineBlocks(10);

    // After adding some blocks to the tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);

    // Grab block 1 from disk; we'll add it to the background chain later.
    std::shared_ptr<CBlock> pblockone = std::make_shared<CBlock>();
    {
        LOCK(::cs_main);
        chainman.m_blockman.ReadBlock(*pblockone, *chainman.ActiveChain()[1]);
    }

    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/ true));

    // Ensure our active chain is the snapshot chainstate.
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.IsSnapshotActive()));

    curr_tip = get_notify_tip();

    // Mine a new block on top of the activated snapshot chainstate.
    mineBlocks(1);  // Defined in TestChain100Setup.

    // After adding some blocks to the snapshot tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);

    curr_tip = get_notify_tip();

    BOOST_CHECK_EQUAL(chainman.GetAll().size(), 2);

    Chainstate& background_cs{*Assert([&]() -> Chainstate* {
        for (Chainstate* cs : chainman.GetAll()) {
            if (cs != &chainman.ActiveChainstate()) {
                return cs;
            }
        }
        return nullptr;
    }())};

    // Append the first block to the background chain.
    BlockValidationState state;
    CBlockIndex* pindex = nullptr;
    const CChainParams& chainparams = Params();
    bool newblock = false;

    // TODO: much of this is inlined from ProcessNewBlock(); just reuse PNB()
    // once it is changed to support multiple chainstates.
    {
        LOCK(::cs_main);
        bool checked = CheckBlock(*pblockone, state, chainparams.GetConsensus());
        BOOST_CHECK(checked);
        bool accepted = chainman.AcceptBlock(
            pblockone, state, &pindex, true, nullptr, &newblock, true);
        BOOST_CHECK(accepted);
    }

    // UpdateTip is called here
    bool block_added = background_cs.ActivateBestChain(state, pblockone);

    // Ensure tip is as expected
    BOOST_CHECK_EQUAL(background_cs.m_chain.Tip()->GetBlockHash(), pblockone->GetHash());

    // get_notify_tip() should be unchanged after adding a block to the background
    // validation chain.
    BOOST_CHECK(block_added);
    BOOST_CHECK_EQUAL(curr_tip, get_notify_tip());
}

BOOST_AUTO_TEST_SUITE_END()
