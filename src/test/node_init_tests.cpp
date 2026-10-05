// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init.h>
#include <interfaces/init.h>
#include <interfaces/mining.h>

#include <future>
#include <rpc/server.h>
#include <util/signalinterrupt.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

using node::NodeContext;

//! Like BasicTestingSetup, but using regtest network instead of mainnet.
struct InitTestSetup : BasicTestingSetup {
    InitTestSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

BOOST_FIXTURE_TEST_SUITE(node_init_tests, InitTestSetup)

//! Custom implementation of interfaces::Init for testing.
class TestInit : public interfaces::Init
{
public:
    TestInit(NodeContext& node) : m_node(node)
    {
        InitContext(m_node);
        m_node.init = this;
    }
    std::unique_ptr<interfaces::Chain> makeChain() override { return interfaces::MakeChain(m_node); }
    std::unique_ptr<interfaces::WalletLoader> makeWalletLoader(interfaces::Chain& chain) override
    {
        return MakeWalletLoader(chain, *Assert(m_node.args));
    }
    NodeContext& m_node;
};

BOOST_AUTO_TEST_CASE(init_test)
{
    // Clear state set by BasicTestingSetup that AppInitMain assumes is unset.
    LogInstance().DisconnectTestLogger();
    m_node.args->SetConfigFilePath({});

    // Prevent the test from trying to listen on ports 8332 and 8333.
    m_node.args->ForceSetArg("-server", "0");
    m_node.args->ForceSetArg("-listen", "0");

    // Run through initialization and shutdown code.
    TestInit init{m_node};
    BOOST_CHECK(AppInitInterfaces(m_node));
    BOOST_CHECK(AppInitMain(m_node));
    Interrupt(m_node);
    BOOST_CHECK(!interfaces::MakeMining(m_node));
    Shutdown(m_node);
}

BOOST_AUTO_TEST_CASE(mining_wait_released_on_early_init_failure)
{
    // AppInit may fail before notifications or chainman exists and without a
    // shutdown signal. Interrupt must still release a waiting external client.
    NodeContext early;
    util::SignalInterrupt interrupt;
    early.args = m_node.args;
    early.shutdown_signal = &interrupt;
    auto pending = std::async(std::launch::async, [&] { return interfaces::MakeMining(early); });
    const auto before = pending.wait_for(std::chrono::milliseconds{20});
    Interrupt(early);
    const auto after = pending.wait_for(std::chrono::seconds{5});
    auto result = pending.get();
    BOOST_CHECK(before == std::future_status::timeout);
    BOOST_CHECK(after == std::future_status::ready);
    BOOST_CHECK(!result);
}

BOOST_AUTO_TEST_SUITE_END()
