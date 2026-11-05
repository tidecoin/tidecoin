// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <test/util/setup_common.h>
#include <test/util/test_controls.h>
#include <univalue.h>
#include <wallet/context.h>
#include <wallet/rpc/util.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <optional>
#include <string>

namespace wallet {
RPCHelpMan getauxblock();

static std::string TestWalletName(const std::string& endpoint, std::optional<std::string> parameter = std::nullopt)
{
    JSONRPCRequest req;
    req.URI = endpoint;
    return EnsureUniqueWalletName(req, parameter ? &*parameter : nullptr);
}

BOOST_FIXTURE_TEST_SUITE(wallet_rpc_tests, BasicTestingSetup)

BOOST_FIXTURE_TEST_CASE(mining_payout_unload_lifetime, WalletTestingSetup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    m_args.ForceSetArg("-keypool", "2");

    JSONRPCRequest request;
    request.context = &context;
    request.strMethod = "getauxblock";
    request.params = UniValue{UniValue::VARR};
    // Mainnet's unconnected fixture refuses mining after selecting the payout.
    // This also exercises reservation cleanup after an unsuccessful work request.
    const auto request_work = [&] {
        BOOST_CHECK_EXCEPTION(getauxblock().HandleRequest(request), UniValue, [](const UniValue& error) {
            return error["code"].getInt<int>() == RPC_CLIENT_NOT_CONNECTED;
        });
    };

    for (int i = 0; i < 3; ++i) {
        auto wallet = TestLoadWallet(CreateMockableWalletDatabase(), context, WALLET_FLAG_DESCRIPTORS);
        BOOST_REQUIRE(AddWallet(context, wallet));
        BOOST_CHECK(wallet->NotifyUnload.empty());
        request_work();
        BOOST_CHECK_EQUAL(wallet->NotifyUnload.num_slots(), 1U);
        request_work();
        BOOST_CHECK_EQUAL(wallet->NotifyUnload.num_slots(), 1U);

        const std::weak_ptr<CWallet> weak_wallet{wallet};
        BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
        BOOST_CHECK(wallet->NotifyUnload.empty());
        TestUnloadWallet(std::move(wallet));
        BOOST_CHECK(weak_wallet.expired());
    }
}

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
