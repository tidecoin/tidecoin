// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <banman.h>
#include <chainparams.h>
#include <netbase.h>
#include <streams.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <util/readwritefile.h>


#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(banman_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(file)
{
    SetMockTime(777s);
    const fs::path banlist_path{m_args.GetDataDirBase() / "banlist_test"};
    {
        const std::string entries_write{
            "{ \"banned_nets\": ["
            "  { \"version\": 1, \"ban_created\": 0, \"banned_until\": 778, \"address\": \"aaaaaaaaa\" },"
            "  { \"version\": 2, \"ban_created\": 0, \"banned_until\": 778, \"address\": \"bbbbbbbbb\" },"
            "  { \"version\": 1, \"ban_created\": 0, \"banned_until\": 778, \"address\": \"1.0.0.0/8\" }"
            "] }",
        };
        BOOST_REQUIRE(WriteBinaryFile(banlist_path + ".json", entries_write));
        {
            // The invalid entries will be dropped, but the valid one remains
            ASSERT_DEBUG_LOG("Dropping entry with unparseable address or subnet (aaaaaaaaa) from ban list");
            ASSERT_DEBUG_LOG("Dropping entry with unknown version (2) from ban list");
            BanMan banman{banlist_path, /*client_interface=*/nullptr, /*default_ban_time=*/0};
            banmap_t entries_read;
            banman.GetBanned(entries_read);
            BOOST_CHECK_EQUAL(entries_read.size(), 1);
        }
    }
}

BOOST_AUTO_TEST_CASE(expiry_limits)
{
    constexpr int64_t now{1'700'000'000};
    constexpr int64_t max_time{std::numeric_limits<int64_t>::max()};
    SetMockTime(std::chrono::seconds{now});
    const CSubNet subnet{LookupSubNet("203.0.113.0/24")};
    const fs::path banlist_path{m_args.GetDataDirBase() / "banlist_limits"};

    const auto check_expiry = [&](BanMan& banman, int64_t offset, bool absolute, int64_t expected) {
        banman.ClearBanned();
        banman.Ban(subnet, offset, absolute);
        banmap_t entries;
        banman.GetBanned(entries);
        BOOST_REQUIRE_EQUAL(entries.size(), 1);
        BOOST_CHECK_EQUAL(entries.at(subnet).nCreateTime, now);
        BOOST_CHECK_EQUAL(entries.at(subnet).nBanUntil, expected);
        BOOST_CHECK(banman.IsBanned(subnet));
    };

    {
        BanMan banman{banlist_path, /*client_interface=*/nullptr, /*default_ban_time=*/1234};
        check_expiry(banman, 60, false, now + 60);
        check_expiry(banman, 0, false, now + 1234);
        check_expiry(banman, -1, false, now + 1234);
        check_expiry(banman, max_time - now, false, max_time);
        check_expiry(banman, max_time - now + 1, false, max_time);
        check_expiry(banman, max_time, false, max_time);
        check_expiry(banman, max_time, true, max_time);
    }

    // The maximum timestamp must also survive persistence. A configured default
    // bypasses RPC duration checks, so it uses the same saturation backstop.
    BanMan banman{banlist_path, /*client_interface=*/nullptr, /*default_ban_time=*/max_time};
    banmap_t entries;
    banman.GetBanned(entries);
    BOOST_REQUIRE_EQUAL(entries.size(), 1);
    BOOST_CHECK_EQUAL(entries.at(subnet).nBanUntil, max_time);
    check_expiry(banman, 0, false, max_time);
    check_expiry(banman, -1, false, max_time);
}

BOOST_AUTO_TEST_SUITE_END()
