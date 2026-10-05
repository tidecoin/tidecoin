// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/request.h>
#include <test/util/setup_common.h>
#include <test/util/test_controls.h>
#include <univalue.h>
#include <wallet/rpc/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>

namespace wallet {
static std::string TestWalletName(const std::string& endpoint, std::optional<std::string> parameter = std::nullopt)
{
    JSONRPCRequest req;
    req.URI = endpoint;
    return EnsureUniqueWalletName(req, parameter ? &*parameter : nullptr);
}

BOOST_FIXTURE_TEST_SUITE(wallet_rpc_tests, BasicTestingSetup)

BOOST_FIXTURE_TEST_CASE(descriptor_expansion_reservation, WalletTestingSetup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    BOOST_CHECK(!m_wallet.IsDescriptorExpansionRunning());
    BOOST_CHECK(!m_wallet.AbortDescriptorExpansion());
    {
        WalletDescriptorExpansionReserver first{m_wallet};
        BOOST_REQUIRE(first.reserve());
        {
            WalletDescriptorExpansionReserver second{m_wallet};
            BOOST_CHECK(!second.reserve());
        }
        BOOST_CHECK(m_wallet.IsDescriptorExpansionRunning());
        BOOST_CHECK(m_wallet.AbortDescriptorExpansion());
        BOOST_CHECK(m_wallet.IsDescriptorExpansionAborted());
        BOOST_CHECK(!first.complete());
        BOOST_CHECK(m_wallet.IsDescriptorExpansionRunning());
    }
    BOOST_CHECK(!m_wallet.IsDescriptorExpansionRunning());
    {
        WalletDescriptorExpansionReserver next{m_wallet};
        BOOST_REQUIRE(next.reserve());
        BOOST_CHECK(!m_wallet.IsDescriptorExpansionAborted());
        BOOST_CHECK(next.complete());
        BOOST_CHECK(!m_wallet.AbortDescriptorExpansion());
        WalletDescriptorExpansionReserver other{m_wallet};
        BOOST_CHECK(other.reserve());
    }
    BOOST_CHECK(!m_wallet.IsDescriptorExpansionRunning());
    // Model an encrypted, already-locked wallet without creating any keypool.
    // Direct Lock() is also used by the GUI and must cancel an active expansion.
    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.mapMasterKeys.emplace(0, CMasterKey{});
    }
    {
        WalletDescriptorExpansionReserver direct_lock{m_wallet};
        BOOST_REQUIRE(direct_lock.reserve());
        BOOST_CHECK(m_wallet.Lock());
        BOOST_CHECK(m_wallet.IsDescriptorExpansionAborted());
        BOOST_CHECK(!direct_lock.complete());
    }
    BOOST_CHECK(!m_wallet.IsDescriptorExpansionRunning());
    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.mapMasterKeys.clear();
    }
}

BOOST_AUTO_TEST_CASE(ensure_unique_wallet_name)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    // EnsureUniqueWalletName should only return if exactly one unique wallet name is provided
    BOOST_CHECK_EQUAL(TestWalletName("/wallet/foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/wallet/foo", "foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/", "foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/bar", "foo"), "foo");

    BOOST_CHECK_THROW(TestWalletName("/"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/foo"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foo", "bar"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foo", "foobar"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foobar", "foo"), UniValue);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
