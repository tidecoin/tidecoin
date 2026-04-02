// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <node/miner.h>
#include <pow.h>
#include <random.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <thread>

using node::BlockAssembler;

namespace validation_block_tests {
struct MinerTestingSetup : public RegTestingSetup {
    std::shared_ptr<CBlock> Block(const uint256& prev_hash);
    std::shared_ptr<const CBlock> GoodBlock(const uint256& prev_hash);
    std::shared_ptr<const CBlock> BadBlock(const uint256& prev_hash);
    std::shared_ptr<CBlock> FinalizeBlock(std::shared_ptr<CBlock> pblock);
    void BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks);
};

struct ScopedConsensusMutation {
    Consensus::Params& params;
    const Consensus::Params original;

    explicit ScopedConsensusMutation(Consensus::Params& params_in)
        : params{params_in}, original{params_in} {}

    ~ScopedConsensusMutation()
    {
        params = original;
    }
};
} // namespace validation_block_tests

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, MinerTestingSetup)

struct TestSubscriber final : public CValidationInterface {
    uint256 m_expected_tip;

    explicit TestSubscriber(uint256 tip) : m_expected_tip(tip) {}

    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, pindexNew->GetBlockHash());
    }

    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->hashPrevBlock);
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->pprev->GetBlockHash());

        m_expected_tip = block->GetHash();
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->GetHash());
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->GetBlockHash());

        m_expected_tip = block->hashPrevBlock;
    }
};

std::shared_ptr<CBlock> MinerTestingSetup::Block(const uint256& prev_hash)
{
    static int i = 0;
    static uint64_t time = Params().GenesisBlock().nTime;

    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << i++ << OP_TRUE;
    auto ptemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    auto pblock = std::make_shared<CBlock>(ptemplate->block);
    pblock->hashPrevBlock = prev_hash;
    pblock->nTime = ++time;

    // Make the coinbase transaction with two outputs:
    // One zero-value one that has a unique pubkey to make sure that blocks at the same height can have a different hash
    // Another one that has the coinbase reward in a P2WSH with OP_TRUE as witness program to make it easy to spend
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vout.resize(2);
    txCoinbase.vout[1].scriptPubKey = P2WSH_OP_TRUE;
    const int prev_height{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(prev_hash)->nHeight)};
    const int assembled_height{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height() + 1)};
    const CAmount assembled_subsidy{GetBlockSubsidy(assembled_height, Params().GetConsensus())};
    const CAmount fee_delta{txCoinbase.vout[0].nValue - assembled_subsidy};
    txCoinbase.vout[1].nValue = GetBlockSubsidy(prev_height + 1, Params().GetConsensus()) + fee_delta;
    txCoinbase.vout[0].nValue = 0;
    txCoinbase.vin[0].scriptWitness.SetNull();
    // Always pad with OP_0 at the end to avoid bad-cb-length error
    txCoinbase.vin[0].scriptSig = CScript{} << prev_height + 1 << OP_0;
    txCoinbase.nLockTime = static_cast<uint32_t>(prev_height);
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    return pblock;
}

std::shared_ptr<CBlock> MinerTestingSetup::FinalizeBlock(std::shared_ptr<CBlock> pblock)
{
    const CBlockIndex* prev_block{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(pblock->hashPrevBlock))};
    m_node.chainman->GenerateCoinbaseCommitment(*pblock, prev_block);

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    const int height{prev_block ? prev_block->nHeight + 1 : 0};
    if (prev_block) {
        // Ensure difficulty matches the actual prev block, not the active chain tip.
        pblock->nBits = GetNextWorkRequired(prev_block, pblock.get(), Params().GetConsensus());
    }
    while (!CheckProofOfWork(*pblock, Params().GetConsensus(), height)) {
        ++(pblock->nNonce);
    }

    // submit block header, so that miner can get the block height from the
    // global state and the node has the topology of the chain
    BlockValidationState ignored;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{pblock->GetBlockHeader()}}, true, ignored));

    return pblock;
}

// construct a valid block
std::shared_ptr<const CBlock> MinerTestingSetup::GoodBlock(const uint256& prev_hash)
{
    return FinalizeBlock(Block(prev_hash));
}

// construct an invalid block (but with a valid header)
std::shared_ptr<const CBlock> MinerTestingSetup::BadBlock(const uint256& prev_hash)
{
    auto pblock = Block(prev_hash);

    CMutableTransaction coinbase_spend;
    coinbase_spend.vin.emplace_back(COutPoint(pblock->vtx[0]->GetHash(), 0), CScript(), 0);
    coinbase_spend.vout.push_back(pblock->vtx[0]->vout[0]);

    CTransactionRef tx = MakeTransactionRef(coinbase_spend);
    pblock->vtx.push_back(tx);

    auto ret = FinalizeBlock(pblock);
    return ret;
}

// NOLINTNEXTLINE(misc-no-recursion)
void MinerTestingSetup::BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks)
{
    if (height <= 0 || blocks.size() >= max_size) return;

    bool gen_invalid = m_rng.randrange(100U) < invalid_rate;
    bool gen_fork = m_rng.randrange(100U) < branch_rate;

    const std::shared_ptr<const CBlock> pblock = gen_invalid ? BadBlock(root) : GoodBlock(root);
    blocks.push_back(pblock);
    if (!gen_invalid) {
        BuildChain(pblock->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }

    if (gen_fork) {
        blocks.push_back(GoodBlock(root));
        BuildChain(blocks.back()->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }
}

BOOST_AUTO_TEST_CASE(processnewblock_signals_ordering)
{
    // build a large-ish chain that's likely to have some forks
    std::vector<std::shared_ptr<const CBlock>> blocks;
    while (blocks.size() < 50) {
        blocks.clear();
        BuildChain(Params().GenesisBlock().GetHash(), 100, 15, 10, 500, blocks);
    }

    bool ignored;
    // Connect the genesis block and drain any outstanding events
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // subscribe to events (this subscriber will validate event ordering)
    const CBlockIndex* initial_tip = nullptr;
    {
        LOCK(cs_main);
        initial_tip = m_node.chainman->ActiveChain().Tip();
    }
    auto sub = std::make_shared<TestSubscriber>(initial_tip->GetBlockHash());
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    // create a bunch of threads that repeatedly process a block generated above at random
    // this will create parallelism and randomness inside validation - the ValidationInterface
    // will subscribe to events generated during block validation and assert on ordering invariance
    std::vector<std::thread> threads;
    threads.reserve(10);
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&]() {
            bool ignored;
            FastRandomContext insecure;
            for (int i = 0; i < 1000; i++) {
                const auto& block = blocks[insecure.randrange(blocks.size() - 1)];
                Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
            }

            // to make sure that eventually we process the full chain - do it here
            for (const auto& block : blocks) {
                if (block->vtx.size() == 1) {
                    bool processed = Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
                    assert(processed);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    m_node.validation_signals->UnregisterSharedValidationInterface(sub);

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(sub->m_expected_tip, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(processnewblockheaders_prechecked_still_runs_contextual_checks)
{
    const auto good_block = GoodBlock(Params().GenesisBlock().GetHash());
    const CBlockHeader good_header = good_block->GetBlockHeader();

    const CBlockIndex* prev_index{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(good_header.hashPrevBlock))};
    BOOST_REQUIRE(prev_index);
    const int height{prev_index->nHeight + 1};

    BOOST_CHECK(Assert(m_node.chainman)->HasValidHeadersProofOfWork({{good_header}}, height));
    BlockValidationState state;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeadersPrechecked({{good_header}}, state));

    CBlockHeader bad_header{good_header};
    bad_header.nTime = prev_index->GetMedianTimePast();
    bad_header.nNonce = 0;
    while (!CheckProofOfWork(bad_header, Params().GetConsensus(), height)) {
        ++bad_header.nNonce;
    }

    BOOST_CHECK(Assert(m_node.chainman)->HasValidHeadersProofOfWork({{bad_header}}, height));

    BlockValidationState bad_state;
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlockHeadersPrechecked({{bad_header}}, bad_state));
    BOOST_CHECK(bad_state.IsInvalid());
    BOOST_CHECK_EQUAL(bad_state.GetRejectReason(), "time-too-old");
}

BOOST_AUTO_TEST_CASE(processnewblockheaders_prechecked_enforces_pow_activation_boundary)
{
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    ScopedConsensusMutation consensus_guard{consensus};

    consensus.nAuxpowStartHeight = 5;
    consensus.nPowTargetSpacing = 1;
    consensus.nPowTargetTimespan = 4;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.enforce_BIP94 = false;
    consensus.fPowNoRetargeting = false;
    consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
    consensus.nPowAveragingWindow = 2;
    consensus.nPowMaxAdjustUp = 16;
    consensus.nPowMaxAdjustDown = 32;

    auto legacy_consensus = consensus;
    legacy_consensus.nAuxpowStartHeight = Consensus::AUXPOW_DISABLED;

    std::array<int64_t, 5> times{};
    unsigned int post_auxpow_nbits{0};
    unsigned int legacy_nbits{0};
    bool found_boundary_case{false};

    const int64_t genesis_time = Params().GenesisBlock().nTime;
    const unsigned int genesis_nbits = Params().GenesisBlock().nBits;

    for (int64_t t1 = genesis_time + 1; t1 <= genesis_time + 3 && !found_boundary_case; ++t1) {
        for (int64_t t2 = t1 + 1; t2 <= genesis_time + 6 && !found_boundary_case; ++t2) {
            for (int64_t t3 = t2 + 1; t3 <= genesis_time + 9 && !found_boundary_case; ++t3) {
                for (int64_t t4 = t3 + 1; t4 <= genesis_time + 12 && !found_boundary_case; ++t4) {
                    std::array<CBlockIndex, 5> indices{};
                    indices[0].nHeight = 0;
                    indices[0].nTime = genesis_time;
                    indices[0].nBits = genesis_nbits;
                    indices[0].pprev = nullptr;
                    const std::array<int64_t, 5> candidate_times{
                        genesis_time, t1, t2, t3, t4,
                    };

                    for (int height = 1; height <= 4; ++height) {
                        CBlockHeader candidate_header;
                        candidate_header.nTime = candidate_times[height];
                        indices[height].nHeight = height;
                        indices[height].nTime = candidate_times[height];
                        indices[height].nBits = GetNextWorkRequired(&indices[height - 1], &candidate_header, consensus);
                        indices[height].pprev = &indices[height - 1];
                        indices[height].BuildSkip();
                    }

                    CBlockHeader activation_header;
                    activation_header.nTime = t4 + 1;
                    const unsigned int candidate_post_auxpow_nbits = GetNextWorkRequired(&indices[4], &activation_header, consensus);
                    const unsigned int candidate_legacy_nbits = GetNextWorkRequired(&indices[4], &activation_header, legacy_consensus);
                    if (candidate_post_auxpow_nbits != candidate_legacy_nbits) {
                        times = candidate_times;
                        post_auxpow_nbits = candidate_post_auxpow_nbits;
                        legacy_nbits = candidate_legacy_nbits;
                        found_boundary_case = true;
                    }
                }
            }
        }
    }

    BOOST_REQUIRE(found_boundary_case);

    auto make_block = [&](const uint256& prev_hash, const CBlockIndex* expected_prev, int64_t ntime, unsigned int nbits) {
        auto pblock = Block(prev_hash);
        pblock->nTime = ntime;
        m_node.chainman->GenerateCoinbaseCommitment(*pblock, expected_prev);
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        pblock->nBits = nbits;
        pblock->nNonce = 0;
        while (!CheckProofOfWork(*pblock, consensus, expected_prev->nHeight + 1)) {
            ++pblock->nNonce;
        }
        return pblock;
    };

    bool ignored{false};
    uint256 tip_hash{Params().GenesisBlock().GetHash()};
    for (int height = 1; height < consensus.nAuxpowStartHeight; ++height) {
        const CBlockIndex* current_prev{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(tip_hash))};
        BOOST_REQUIRE(current_prev);
        auto block = make_block(tip_hash, current_prev, times[height], GetNextWorkRequired(current_prev, nullptr, consensus));
        BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored));
        tip_hash = block->GetHash();
    }

    const CBlockIndex* prev_index{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(tip_hash))};
    BOOST_REQUIRE(prev_index);
    BOOST_REQUIRE_EQUAL(prev_index->nHeight + 1, consensus.nAuxpowStartHeight);

    auto post_auxpow_block = make_block(tip_hash, prev_index, times[4] + 1, post_auxpow_nbits);
    const CBlockHeader good_header{post_auxpow_block->GetBlockHeader()};
    BOOST_CHECK(Assert(m_node.chainman)->HasValidHeadersProofOfWork({{good_header}}, consensus.nAuxpowStartHeight));

    BlockValidationState good_state;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeadersPrechecked({{good_header}}, good_state));
    BOOST_CHECK(good_state.IsValid());

    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(post_auxpow_block, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored));

    auto legacy_block = make_block(tip_hash, prev_index, times[4] + 1, legacy_nbits);
    const CBlockHeader bad_header{legacy_block->GetBlockHeader()};
    BOOST_CHECK(Assert(m_node.chainman)->HasValidHeadersProofOfWork({{bad_header}}, consensus.nAuxpowStartHeight));

    BlockValidationState bad_state;
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlockHeadersPrechecked({{bad_header}}, bad_state));
    BOOST_CHECK(bad_state.IsInvalid());
    BOOST_CHECK_EQUAL(bad_state.GetRejectReason(), "bad-diffbits");
}

/**
 * Test that mempool updates happen atomically with reorgs.
 *
 * This prevents RPC clients, among others, from retrieving immediately-out-of-date mempool data
 * during large reorgs.
 *
 * The test verifies this by creating a chain of `num_txs` blocks, matures their coinbases, and then
 * submits txns spending from their coinbase to the mempool. A fork chain is then processed,
 * invalidating the txns and evicting them from the mempool.
 *
 * We verify that the mempool updates atomically by polling it continuously
 * from another thread during the reorg and checking that its size only changes
 * once. The size changing exactly once indicates that the polling thread's
 * view of the mempool is either consistent with the chain state before reorg,
 * or consistent with the chain state after the reorg, and not just consistent
 * with some intermediate state during the reorg.
 */
BOOST_AUTO_TEST_CASE(mempool_locks_reorg)
{
    bool ignored;
    auto ProcessBlock = [&](std::shared_ptr<const CBlock> block) -> bool {
        return Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&ignored);
    };

    // Process all mined blocks
    BOOST_REQUIRE(ProcessBlock(std::make_shared<CBlock>(Params().GenesisBlock())));
    auto last_mined = GoodBlock(Params().GenesisBlock().GetHash());
    BOOST_REQUIRE(ProcessBlock(last_mined));

    // Run the test multiple times
    for (int test_runs = 3; test_runs > 0; --test_runs) {
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // Later on split from here
        const uint256 split_hash{last_mined->hashPrevBlock};

        // Create a bunch of transactions to spend the miner rewards of the
        // most recent blocks
        std::vector<CTransactionRef> txs;
        for (int num_txs = 22; num_txs > 0; --num_txs) {
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint{last_mined->vtx[0]->GetHash(), 1}, CScript{});
            mtx.vin[0].scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
            mtx.vout.push_back(last_mined->vtx[0]->vout[1]);
            mtx.vout[0].nValue -= 1000;
            txs.push_back(MakeTransactionRef(mtx));

            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mature the inputs of the txs
        for (int j = COINBASE_MATURITY; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mine a reorg (and hold it back) before adding the txs to the mempool
        const uint256 tip_init{last_mined->GetHash()};

        std::vector<std::shared_ptr<const CBlock>> reorg;
        last_mined = GoodBlock(split_hash);
        reorg.push_back(last_mined);
        for (size_t j = COINBASE_MATURITY + txs.size() + 1; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            reorg.push_back(last_mined);
        }

        // Add the txs to the tx pool
        {
            LOCK(cs_main);
            for (const auto& tx : txs) {
                const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx);
                BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
            }
        }

        // Check that all txs are in the pool
        {
            BOOST_CHECK_EQUAL(m_node.mempool->size(), txs.size());
        }

        // Run a thread that simulates an RPC caller that is polling while
        // validation is doing a reorg
        std::thread rpc_thread{[&]() {
            // This thread is checking that the mempool either contains all of
            // the transactions invalidated by the reorg, or none of them, and
            // not some intermediate amount.
            while (true) {
                LOCK(m_node.mempool->cs);
                if (m_node.mempool->size() == 0) {
                    // We are done with the reorg
                    break;
                }
                // Internally, we might be in the middle of the reorg, but
                // externally the reorg to the most-proof-of-work chain should
                // be atomic. So the caller assumes that the returned mempool
                // is consistent. That is, it has all txs that were there
                // before the reorg.
                assert(m_node.mempool->size() == txs.size());
                continue;
            }
            LOCK(cs_main);
            // We are done with the reorg, so the tip must have changed
            assert(tip_init != m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }};

        // Submit the reorg in this thread to invalidate and remove the txs from the tx pool
        for (const auto& b : reorg) {
            ProcessBlock(b);
        }
        // Check that the reorg was eventually successful
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // We can join the other thread, which returns when the reorg was successful
        rpc_thread.join();
    }
}

BOOST_AUTO_TEST_CASE(witness_commitment_index)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    CScript pubKey;
    pubKey << 1 << OP_TRUE;
    BlockAssembler::Options options;
    options.coinbase_output_script = pubKey;
    auto ptemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    CBlock pblock = ptemplate->block;

    CTxOut witness;
    witness.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
    witness.scriptPubKey[0] = OP_RETURN;
    witness.scriptPubKey[1] = 0x24;
    witness.scriptPubKey[2] = 0xaa;
    witness.scriptPubKey[3] = 0x21;
    witness.scriptPubKey[4] = 0xa9;
    witness.scriptPubKey[5] = 0xed;

    // A witness larger than the minimum size is still valid
    CTxOut min_plus_one = witness;
    min_plus_one.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT + 1);

    CTxOut invalid = witness;
    invalid.scriptPubKey[0] = OP_VERIFY;

    CMutableTransaction txCoinbase(*pblock.vtx[0]);
    txCoinbase.vout.resize(4);
    txCoinbase.vout[0] = witness;
    txCoinbase.vout[1] = witness;
    txCoinbase.vout[2] = min_plus_one;
    txCoinbase.vout[3] = invalid;
    pblock.vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    BOOST_CHECK_EQUAL(GetWitnessCommitmentIndex(pblock), 2);
}
BOOST_AUTO_TEST_SUITE_END()
