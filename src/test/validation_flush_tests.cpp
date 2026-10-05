// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sync.h>
#include <test/util/coins.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(validation_flush_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(large_coins_cache_threshold_boundaries)
{
    constexpr int64_t max{std::numeric_limits<int64_t>::max()};
    // An independent form of floor(90% * total) is total - ceil(total / 10).
    const auto check = [](int64_t total) {
        const int64_t expected{std::max(total - total / 10 - (total % 10 != 0), total - int64_t(10_MiB))};
        BOOST_CHECK_EQUAL(LargeCoinsCacheThreshold(total), expected);
    };
    for (int64_t total{0}; total < 40; ++total) check(total);
    for (const int64_t total : {int64_t(100_MiB) - 1, int64_t(100_MiB), int64_t(100_MiB) + 1,
                               max / 9 - 1, max / 9, max / 9 + 1, int64_t{1} << 60, max - 1, max}) {
        check(total);
    }
}

BOOST_AUTO_TEST_CASE(large_coins_cache_budget)
{
    LOCK(cs_main);
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    // A tiny actual cache with a huge budget must stay OK. These calls only
    // calculate thresholds; they do not resize or allocate the requested cache.
    if constexpr (sizeof(size_t) == 8) {
        for (const size_t budget : {static_cast<size_t>(uint64_t{1} << 60), static_cast<size_t>(std::numeric_limits<int64_t>::max())}) {
            BOOST_CHECK_EQUAL(chainstate.GetCoinsCacheSizeState(budget, 0), CoinsCacheSizeState::OK);
        }
    }
    BOOST_CHECK_EQUAL(chainstate.GetCoinsCacheSizeState(4_MiB, 0), CoinsCacheSizeState::OK);
    BOOST_CHECK_EQUAL(chainstate.GetCoinsCacheSizeState(0, 0), CoinsCacheSizeState::CRITICAL);
}

//! Verify that Chainstate::GetCoinsCacheSizeState() switches from OK→LARGE→CRITICAL
//! at the expected utilization thresholds, first with *no* mempool head-room,
//! then with additional mempool head-room.
BOOST_AUTO_TEST_CASE(getcoinscachesizestate)
{
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};

    LOCK(::cs_main);
    CCoinsViewCache& view{chainstate.CoinsTip()};

    // Sanity: an empty cache should be ≲ 1 chunk (~ 256 KiB).
    BOOST_CHECK_LT(view.DynamicMemoryUsage() / (256 * 1024.0), 1.1);

    constexpr size_t MAX_COINS_BYTES{8_MiB};
    constexpr size_t MAX_MEMPOOL_BYTES{4_MiB};
    constexpr size_t MAX_ATTEMPTS{50'000};

    // Run the same growth-path twice: first with 0 head-room, then with extra head-room
    for (size_t max_mempool_size_bytes : {size_t{0}, MAX_MEMPOOL_BYTES}) {
        const int64_t full_cap{int64_t(MAX_COINS_BYTES + max_mempool_size_bytes)};
        const int64_t large_cap{LargeCoinsCacheThreshold(full_cap)};

        // OK → LARGE
        auto state{chainstate.GetCoinsCacheSizeState(MAX_COINS_BYTES, max_mempool_size_bytes)};
        for (size_t i{0}; i < MAX_ATTEMPTS && int64_t(view.DynamicMemoryUsage()) <= large_cap; ++i) {
            BOOST_CHECK_EQUAL(state, CoinsCacheSizeState::OK);
            AddTestCoin(m_rng, view);
            state = chainstate.GetCoinsCacheSizeState(MAX_COINS_BYTES, max_mempool_size_bytes);
        }

        // LARGE → CRITICAL
        for (size_t i{0}; i < MAX_ATTEMPTS && int64_t(view.DynamicMemoryUsage()) <= full_cap; ++i) {
            BOOST_CHECK_EQUAL(state, CoinsCacheSizeState::LARGE);
            AddTestCoin(m_rng, view);
            state = chainstate.GetCoinsCacheSizeState(MAX_COINS_BYTES, max_mempool_size_bytes);
        }
        BOOST_CHECK_EQUAL(state, CoinsCacheSizeState::CRITICAL);
    }

    // Default thresholds (no explicit limits) permit many more coins.
    for (int i{0}; i < 1'000; ++i) {
        AddTestCoin(m_rng, view);
        BOOST_CHECK_EQUAL(chainstate.GetCoinsCacheSizeState(), CoinsCacheSizeState::OK);
    }

    // CRITICAL → OK via Flush
    BOOST_CHECK_EQUAL(chainstate.GetCoinsCacheSizeState(MAX_COINS_BYTES, /*max_mempool_size_bytes=*/0), CoinsCacheSizeState::CRITICAL);
    view.SetBestBlock(m_rng.rand256());
    BOOST_REQUIRE(view.Flush());
    BOOST_CHECK_EQUAL(chainstate.GetCoinsCacheSizeState(MAX_COINS_BYTES, /*max_mempool_size_bytes=*/0), CoinsCacheSizeState::OK);
}

BOOST_AUTO_TEST_SUITE_END()
