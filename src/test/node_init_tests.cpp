// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init.h>
#include <interfaces/init.h>
#include <interfaces/mining.h>
#include <node/blockstorage.h>
#include <node/interface_ui.h>
#include <rpc/server.h>
#include <util/signalinterrupt.h>
#include <validation.h>

#include <future>

#include <boost/signals2/connection.hpp>
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
        m_node.init = this;
    }
    ~TestInit() override
    {
        Interrupt(m_node);
        Shutdown(m_node);
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
    std::string config_error;
    BOOST_REQUIRE(m_node.args->ReadConfigFiles(config_error));

    // Prevent the test from trying to listen on ports 8332 and 8333.
    m_node.args->ForceSetArg("-server", "0");
    m_node.args->ForceSetArg("-listen", "0");

    // Run through initialization and shutdown code.
    InitContext(m_node);
    TestInit init{m_node};
    BOOST_CHECK(AppInitInterfaces(m_node));
    BOOST_CHECK(AppInitMain(m_node));
    Interrupt(m_node);
    BOOST_CHECK(!interfaces::MakeMining(m_node));
}

static void TestReindexRetry(NodeContext& node, bool automatic, bool request_shutdown)
{
    // BasicTestingSetup supplies a fresh interrupt for each test. InitContext's
    // process-wide signal is intentionally initialized only by init_test.
    LogInstance().DisconnectTestLogger();
    std::string config_error;
    BOOST_REQUIRE(node.args->ReadConfigFiles(config_error));
    node.args->ForceSetArg("-server", "0");
    node.args->ForceSetArg("-listen", "0");
    node.args->ForceSetArg("-connect", "0");
    node.args->ForceSetArg("-listenonion", "0");

    TestInit init{node};
    BOOST_REQUIRE(AppInitInterfaces(node));
    {
        node::BlockTreeDB db{{.path = node.args->GetBlocksDirPath() / "index", .cache_bytes = 1 << 20}};
        BOOST_REQUIRE(db.WriteFlag("reindex_retry_sentinel", true));
        if (!automatic) {
            // A current-format index with invalid last-file metadata offers
            // the interactive rebuild instead of the automatic format upgrade.
            BOOST_REQUIRE(db.WriteDatabaseFormatVersion());
            BOOST_REQUIRE(db.WriteBatchSync({}, -1, {}));
        }
    }

    int retry_messages{0};
    int retry_questions{0};
    const boost::signals2::scoped_connection message{uiInterface.InitMessage_connect([&](const std::string& text) {
        if (!text.starts_with("Database storage format upgrade:")) return;
        ++retry_messages;
        if (request_shutdown) BOOST_CHECK((*node.shutdown_signal)());
    })};
    const boost::signals2::scoped_connection question{uiInterface.ThreadSafeQuestion_connect(
        [&](const bilingual_str&, const std::string&, const std::string&, unsigned int) {
            ++retry_questions;
            if (request_shutdown) BOOST_CHECK((*node.shutdown_signal)());
            return true;
        })};

    // Both callbacks run after retry eligibility was checked, before a retry
    // can clear the shutdown signal or recreate the block-index database.
    BOOST_CHECK_EQUAL(AppInitMain(node), !request_shutdown);
    BOOST_CHECK_EQUAL(retry_messages, automatic ? 1 : 0);
    BOOST_CHECK_EQUAL(retry_questions, automatic ? 0 : 1);
    BOOST_CHECK_EQUAL(ShutdownRequested(node), request_shutdown);
    BOOST_REQUIRE(node.chainman);
    {
        LOCK(cs_main);
        auto& db = *node.chainman->m_blockman.m_block_tree_db;
        bool sentinel{false};
        BOOST_CHECK_EQUAL(db.ReadFlag("reindex_retry_sentinel", sentinel), request_shutdown);
        BOOST_CHECK_EQUAL(sentinel, request_shutdown);
        if (request_shutdown) {
            bool reindexing{false};
            db.ReadReindexing(reindexing);
            BOOST_CHECK(!reindexing);
            BOOST_CHECK(!node.chainman->m_blockman.BlockIndexWasWiped());
        } else {
            BOOST_CHECK(node.chainman->m_blockman.BlockIndexWasWiped());
            BOOST_REQUIRE(node.chainman->ActiveTip());
            BOOST_CHECK_EQUAL(node.chainman->ActiveTip()->GetBlockHash(), node.chainman->GetConsensus().hashGenesisBlock);
        }
    }
}

BOOST_AUTO_TEST_CASE(automatic_reindex_shutdown)
{
    TestReindexRetry(m_node, /*automatic=*/true, /*request_shutdown=*/true);
}

BOOST_AUTO_TEST_CASE(interactive_reindex_shutdown)
{
    TestReindexRetry(m_node, /*automatic=*/false, /*request_shutdown=*/true);
}

BOOST_AUTO_TEST_CASE(automatic_reindex_retry)
{
    TestReindexRetry(m_node, /*automatic=*/true, /*request_shutdown=*/false);
}

BOOST_AUTO_TEST_CASE(interactive_reindex_retry)
{
    TestReindexRetry(m_node, /*automatic=*/false, /*request_shutdown=*/false);
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
