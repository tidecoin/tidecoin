// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/consensus.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <memory>
#include <vector>

using node::BlockAssembler;

static void AssembleBlock(benchmark::Bench& bench)
{
    auto test_setup = MakeNoLogFileContext<TestChain100Setup>();
    BlockAssembler::Options options;
    options.coinbase_output_script = P2WSH_OP_TRUE;

    // Build a 200-block chain so the first 101 coinbase outputs are mature and spendable.
    constexpr size_t NUM_BLOCKS{200};
    test_setup->mineBlocks(COINBASE_MATURITY);
    constexpr size_t NUM_MATURE_COINBASES{NUM_BLOCKS - COINBASE_MATURITY + 1};
    for (size_t b{0}; b < NUM_MATURE_COINBASES; ++b) {
        test_setup->CreateValidMempoolTransaction(
            /*input_transaction=*/test_setup->m_coinbase_txns.at(b),
            /*input_vout=*/0,
            /*input_height=*/static_cast<int>(b + 1),
            /*input_signing_key=*/test_setup->coinbaseKey,
            /*output_destination=*/P2WSH_OP_TRUE,
            /*output_amount=*/CAmount{1 * COIN},
            /*submit=*/true,
            /*normalize_falcon_sigs=*/true);
    }

    bench.run([&] {
        PrepareBlock(test_setup->m_node, options);
    });
}
static void BlockAssemblerAddPackageTxns(benchmark::Bench& bench)
{
    FastRandomContext det_rand{true};
    auto testing_setup{MakeNoLogFileContext<TestChain100Setup>()};
    testing_setup->PopulateMempool(det_rand, /*num_transactions=*/1000, /*submit=*/true);
    BlockAssembler::Options assembler_options;
    assembler_options.test_block_validity = false;
    assembler_options.coinbase_output_script = P2WSH_OP_TRUE;

    bench.run([&] {
        PrepareBlock(testing_setup->m_node, assembler_options);
    });
}

BENCHMARK(AssembleBlock, benchmark::PriorityLevel::HIGH);
BENCHMARK(BlockAssemblerAddPackageTxns, benchmark::PriorityLevel::LOW);
