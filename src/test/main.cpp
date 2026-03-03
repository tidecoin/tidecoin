// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * See https://www.boost.org/doc/libs/1_78_0/libs/test/doc/html/boost_test/adv_scenarios/single_header_customizations/multiple_translation_units.html
 */
#define BOOST_TEST_MODULE Tidecoin Core Test Suite

#include <boost/test/included/unit_test.hpp>

#include <test/util/setup_common.h>

#include <cstdlib>
#include <functional>
#include <iostream>
#include <unordered_set>

/** Redirect debug log to unit_test.log files */
const std::function<void(const std::string&)> G_TEST_LOG_FUN = [](const std::string& s) {
    static const bool should_log{std::any_of(
        &boost::unit_test::framework::master_test_suite().argv[1],
        &boost::unit_test::framework::master_test_suite().argv[boost::unit_test::framework::master_test_suite().argc],
        [](const char* arg) {
            return std::string{"DEBUG_LOG_OUT"} == arg;
        })};
    if (!should_log) return;
    std::cout << s;
};

/**
 * Retrieve the command line arguments from boost.
 * Allows usage like:
 * `test_tidecoin --run_test="net_tests/cnode_listen_port" -- -checkaddrman=1 -printtoconsole=1`
 * which would return `["-checkaddrman=1", "-printtoconsole=1"]`.
 */
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    std::vector<const char*> args;
    for (int i = 1; i < boost::unit_test::framework::master_test_suite().argc; ++i) {
        args.push_back(boost::unit_test::framework::master_test_suite().argv[i]);
    }
    return args;
};

/**
 * Retrieve the boost unit test name.
 */
const std::function<std::string()> G_TEST_GET_FULL_NAME = []() {
    return boost::unit_test::framework::current_test_case().full_name();
};

namespace {

bool EnvVarEnabled(const char* name)
{
    const char* env = std::getenv(name);
    return env && env[0] && env[0] != '0';
}

bool WalletTestsEnabled()
{
    return EnvVarEnabled("TIDECOIN_RUN_WALLET_TESTS");
}

void DisableTestSuitesByName(const std::unordered_set<std::string>& suite_names)
{
    using namespace boost::unit_test;

    struct Visitor final : test_tree_visitor {
        const std::unordered_set<std::string>& names;
        explicit Visitor(const std::unordered_set<std::string>& n) : names(n) {}

        bool test_suite_start(test_suite const& ts) override
        {
            // Disabling a suite disables the entire subtree, so no need to walk
            // its children.
            if (names.count(ts.p_name)) {
                // This runs after Boost has applied run filters; flip the run
                // status to disabled so the suite (and subtree) is skipped.
                const_cast<test_suite&>(ts).p_run_status.set(test_unit::RS_DISABLED);
                return false;
            }
            return true;
        }
    };

    Visitor visitor{suite_names};
    traverse_test_tree(framework::master_test_suite(), visitor);
}

struct WalletTestsDisabler final {
    void setup()
    {
        if (WalletTestsEnabled()) return;

        // Wallet tests are very expensive in PQ builds due to key generation.
        // Hide them from default unit test runs; run explicitly with:
        //   TIDECOIN_RUN_WALLET_TESTS=1 ./build/bin/test_tidecoin --run_test=...
        static const std::unordered_set<std::string> kWalletSuites{
            "coinselection_tests",
            "coinselector_tests",
            "db_tests",
            "feebumper_tests",
            "group_outputs_tests",
            "init_tests",
            "ismine_tests",
            "psbt_wallet_tests",
            "scriptpubkeyman_tests",
            "spend_tests",
            "wallet_crypto_tests",
            "wallet_rpc_tests",
            "wallet_tests",
            "wallet_transaction_tests",
            "walletdb_tests",
            "walletload_tests",
        };
        DisableTestSuitesByName(kWalletSuites);
    }
    void teardown() {}
};

} // namespace

BOOST_TEST_GLOBAL_FIXTURE(WalletTestsDisabler);
