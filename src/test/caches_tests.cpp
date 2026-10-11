#include <chainparams.h>
#include <common/args.h>
#include <kernel/mempool_options.h>
#include <node/caches.h>
#include <node/mempool_args.h>
#include <util/byte_units.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

using namespace node;

BOOST_AUTO_TEST_SUITE(caches_tests)

BOOST_AUTO_TEST_CASE(default_cache_allocation)
{
    ArgsManager args;
    const auto no_indexes{CalculateCacheSizes(args)};
    BOOST_CHECK_EQUAL(no_indexes.index.tx_index, 0U);
    BOOST_CHECK_EQUAL(no_indexes.index.filter_index, 0U);
    BOOST_CHECK_EQUAL(no_indexes.kernel.block_tree_db, 2_MiB);
    BOOST_CHECK_EQUAL(no_indexes.kernel.coins_db, 8_MiB);
    BOOST_CHECK_EQUAL(no_indexes.kernel.coins, 440_MiB);

    args.ForceSetArg("-txindex", "1");
    const auto indexed{CalculateCacheSizes(args, /*n_indexes=*/1)};
    // Preserve Tidecoin's allocation: one eighth for txindex, then one eighth
    // of the remainder for filters. These byte counts also fit a 32-bit target.
    BOOST_CHECK_EQUAL(indexed.index.tx_index, 58'982'400U);
    BOOST_CHECK_EQUAL(indexed.index.filter_index, 51'609'600U);
    BOOST_CHECK_EQUAL(indexed.kernel.block_tree_db, 2_MiB);
    BOOST_CHECK_EQUAL(indexed.kernel.coins_db, 8_MiB);
    BOOST_CHECK_EQUAL(indexed.kernel.coins, 350'781'440U);
}

BOOST_AUTO_TEST_CASE(cache_allocation_boundaries)
{
    constexpr size_t max_cache{sizeof(void*) == 4 ? 1024_MiB : std::numeric_limits<size_t>::max()};
    const struct {
        std::optional<int64_t> option;
        size_t expected;
    } cases[]{
        {std::nullopt, 450_MiB},
        {std::numeric_limits<int64_t>::min(), 4_MiB},
        {-1, 4_MiB},
        {0, 4_MiB},
        {3, 4_MiB},
        {4, 4_MiB},
        {450, 450_MiB},
        {1024, 1024_MiB},
        {1025, sizeof(void*) == 4 ? 1024_MiB : 1025_MiB},
        // The MiB conversion saturates before the platform limit is applied.
        {int64_t{1} << 44, max_cache},
        {std::numeric_limits<int64_t>::max(), max_cache},
    };
    for (const auto& test : cases) {
        for (const bool txindex : {false, true}) {
            for (const size_t indexes : {size_t{0}, size_t{1}, size_t{2}, size_t{3}, std::numeric_limits<size_t>::max()}) {
                BOOST_TEST_CONTEXT("dbcache=" << (test.option ? util::ToString(*test.option) : "default")
                                   << " txindex=" << txindex << " indexes=" << indexes) {
                    ArgsManager args;
                    if (test.option) args.ForceSetArg("-dbcache", util::ToString(*test.option));
                    args.ForceSetArg("-txindex", txindex ? "1" : "0");
                    const auto sizes{CalculateCacheSizes(args, indexes)};
                    size_t remaining{test.expected};
                    BOOST_CHECK_LE(sizes.index.tx_index, 1024_MiB);
                    if (!txindex) BOOST_CHECK_EQUAL(sizes.index.tx_index, 0U);
                    BOOST_REQUIRE_LE(sizes.index.tx_index, remaining);
                    remaining -= sizes.index.tx_index;
                    if (indexes == 0) {
                        BOOST_CHECK_EQUAL(sizes.index.filter_index, 0U);
                    } else {
                        // Check before multiplying, including when indexes is SIZE_MAX.
                        BOOST_REQUIRE_LE(sizes.index.filter_index, std::min(remaining, 1024_MiB) / indexes);
                        remaining -= sizes.index.filter_index * indexes;
                    }
                    BOOST_CHECK_LE(sizes.kernel.block_tree_db, 2_MiB);
                    BOOST_REQUIRE_LE(sizes.kernel.block_tree_db, remaining);
                    remaining -= sizes.kernel.block_tree_db;
                    BOOST_CHECK_LE(sizes.kernel.coins_db, 8_MiB);
                    BOOST_REQUIRE_LE(sizes.kernel.coins_db, remaining);
                    remaining -= sizes.kernel.coins_db;
                    BOOST_CHECK_EQUAL(sizes.kernel.coins, remaining);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(kernel_cache_allocation_boundaries)
{
    for (const size_t total : {size_t{0}, size_t{1}, size_t{7}, size_t{8}, 4_MiB, 450_MiB, 1024_MiB, std::numeric_limits<size_t>::max()}) {
        const kernel::CacheSizes sizes{total};
        size_t remaining{total};
        BOOST_REQUIRE_LE(sizes.block_tree_db, remaining);
        BOOST_CHECK_LE(sizes.block_tree_db, 2_MiB);
        remaining -= sizes.block_tree_db;
        BOOST_REQUIRE_LE(sizes.coins_db, remaining);
        BOOST_CHECK_LE(sizes.coins_db, 8_MiB);
        remaining -= sizes.coins_db;
        BOOST_CHECK_EQUAL(sizes.coins, remaining);
    }
}

BOOST_AUTO_TEST_CASE(cache_option_bounds)
{
    ArgsManager args;
    BOOST_CHECK(CheckCacheOptions(args, /*max_mempool_bytes=*/0));
    BOOST_CHECK(!CheckCacheOptions(args, /*max_mempool_bytes=*/-1));
    constexpr int64_t max{std::numeric_limits<int64_t>::max()};
    constexpr int64_t max_dbcache_mib{max >> 20};
    for (const int64_t dbcache : {std::numeric_limits<int64_t>::min(), int64_t{-1}, int64_t{0}, int64_t{450}, max_dbcache_mib}) {
        args.ForceSetArg("-dbcache", util::ToString(dbcache));
        for (const bool txindex : {false, true}) {
            args.ForceSetArg("-txindex", txindex ? "1" : "0");
            for (const size_t indexes : {size_t{0}, size_t{1}, size_t{3}}) {
                const auto coins{CalculateCacheSizes(args, indexes).kernel.coins};
                const int64_t headroom{max - static_cast<int64_t>(coins)};
                BOOST_CHECK(CheckCacheOptions(args, headroom, indexes));
                BOOST_CHECK(!CheckCacheOptions(args, headroom + 1, indexes));
            }
        }
    }
    for (const int64_t dbcache : {max_dbcache_mib + 1, max}) {
        args.ForceSetArg("-dbcache", util::ToString(dbcache));
        const auto result{CheckCacheOptions(args, /*max_mempool_bytes=*/0)};
        // Oversized options retain the existing 1 GiB clamp on 32-bit systems.
        BOOST_CHECK_EQUAL(result.has_value(), sizeof(void*) == 4);
    }
}

BOOST_AUTO_TEST_CASE(mempool_option_byte_conversion)
{
    ArgsManager args;
    const auto chainparams{CreateChainParams(args, ChainType::REGTEST)};
    constexpr int64_t max_mb{std::numeric_limits<int64_t>::max() / 1'000'000};
    for (const int64_t mb : {std::numeric_limits<int64_t>::min(), int64_t{-1}, int64_t{0}, int64_t{9}, int64_t{500}, int64_t{501}, max_mb, max_mb + 1, std::numeric_limits<int64_t>::max()}) {
        kernel::MemPoolOptions options;
        args.ForceSetArg("-maxmempool", util::ToString(mb));
        const auto result{ApplyArgsManOptions(args, *chainparams, options)};
        const bool valid{mb >= 0 && mb <= (sizeof(void*) == 4 ? 500 : max_mb)};
        BOOST_CHECK_EQUAL(result.has_value(), valid);
        if (valid) BOOST_CHECK_EQUAL(options.max_size_bytes, mb * 1'000'000);
    }
}

BOOST_AUTO_TEST_CASE(mempool_default_and_inherited_options)
{
    ArgsManager args;
    const auto chainparams{CreateChainParams(args, ChainType::REGTEST)};
    kernel::MemPoolOptions options;
    const int64_t expected_bytes{sizeof(void*) == 4 ? 500'000'000 : 1'024'000'000};
    BOOST_CHECK_EQUAL(options.max_size_bytes, expected_bytes);
    BOOST_REQUIRE(ApplyArgsManOptions(args, *chainparams, options));
    BOOST_CHECK_EQUAL(options.max_size_bytes, expected_bytes);

    // A caller-provided budget must obey the limit even without an argument.
    options.max_size_bytes = 500'000'000;
    BOOST_CHECK(ApplyArgsManOptions(args, *chainparams, options));
    options.max_size_bytes = 500'000'001;
    BOOST_CHECK_EQUAL(ApplyArgsManOptions(args, *chainparams, options).has_value(), sizeof(void*) != 4);

    // An explicit valid setting replaces an oversized inherited budget.
    args.ForceSetArg("-maxmempool", "500");
    BOOST_REQUIRE(ApplyArgsManOptions(args, *chainparams, options));
    BOOST_CHECK_EQUAL(options.max_size_bytes, 500'000'000);
}

BOOST_AUTO_TEST_CASE(oversized_dbcache_warning)
{
    // Division must precede multiplication even at the largest representable RAM size.
    constexpr size_t max_ram{std::numeric_limits<size_t>::max()};
    constexpr size_t max_ram_cap{(max_ram / 100) * 75};
    BOOST_CHECK(!ShouldWarnOversizedDbCache(max_ram_cap, max_ram));
    BOOST_CHECK(ShouldWarnOversizedDbCache(max_ram_cap + 1, max_ram));

    // memory restricted setup - cap is DEFAULT_DB_CACHE (450 MiB)
    BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/4_MiB, /*total_ram=*/1024_MiB));    // Under cap
    BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/512_MiB, /*total_ram=*/1024_MiB));  // At cap
    BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/1500_MiB, /*total_ram=*/1024_MiB)); // Over cap

    // 2 GiB RAM - cap is 75%
    BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/1500_MiB, /*total_ram=*/2048_MiB)); // Under cap
    BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/1600_MiB, /*total_ram=*/2048_MiB)); // Over cap

    if constexpr (SIZE_MAX == UINT64_MAX) {
        // 4 GiB RAM - cap is 75%
        BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/2500_MiB, /*total_ram=*/4096_MiB)); // Under cap
        BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/3500_MiB, /*total_ram=*/4096_MiB)); // Over cap

        // 8 GiB RAM - cap is 75%
        BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/6000_MiB, /*total_ram=*/8192_MiB)); // Under cap
        BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/7000_MiB, /*total_ram=*/8192_MiB)); // Over cap

        // 16 GiB RAM - cap is 75%
        BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/10'000_MiB, /*total_ram=*/16384_MiB)); // Under cap
        BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/15'000_MiB, /*total_ram=*/16384_MiB)); // Over cap

        // 32 GiB RAM - cap is 75%
        BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/20'000_MiB, /*total_ram=*/32768_MiB)); // Under cap
        BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/30'000_MiB, /*total_ram=*/32768_MiB)); // Over cap
    }
}

BOOST_AUTO_TEST_SUITE_END()
