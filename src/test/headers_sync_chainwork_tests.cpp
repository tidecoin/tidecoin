// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <array>
#include <optional>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Initialize a nonce without grinding expensive PQ PoW. */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits);

    /** Exercise a difficulty transition in both passes without relying on commitments. */
    void CheckRetargetBothPhases(const Consensus::Params& params, int next_height,
            uint32_t old_bits, uint32_t new_bits, bool expected, size_t history_size,
            uint32_t time_delta = 60, std::optional<uint32_t> valid_bits = std::nullopt);
};

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    starting_header.nNonce = 0;
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

void HeadersGeneratorSetup::CheckRetargetBothPhases(const Consensus::Params& params, int next_height,
        uint32_t old_bits, uint32_t new_bits, bool expected, size_t history_size,
        uint32_t time_delta, std::optional<uint32_t> valid_bits)
{
    BOOST_REQUIRE(history_size > 0 && history_size <= static_cast<size_t>(next_height));
    std::vector<CBlockIndex> history(history_size);
    std::vector<uint256> hashes(history_size);
    for (size_t i = 0; i < history_size; ++i) {
        CBlockHeader header;
        header.nVersion = 4;
        header.nTime = 1'600'000'000 + 60 * static_cast<uint32_t>(i);
        header.nBits = old_bits;
        if (i > 0) header.hashPrevBlock = hashes[i - 1];
        hashes[i] = header.GetHash();
        history[i].nVersion = header.nVersion;
        history[i].nTime = header.nTime;
        history[i].nBits = header.nBits;
        history[i].phashBlock = &hashes[i];
        history[i].nHeight = next_height - static_cast<int>(history_size) + static_cast<int>(i);
        if (i > 0) history[i].pprev = &history[i - 1];
    }
    const CBlockIndex* start = &history.back();
    CBlockHeader candidate = start->GetBlockHeader();
    candidate.hashPrevBlock = start->GetBlockHash();
    candidate.nTime += time_delta;
    candidate.nBits = new_bits;

    // PoW is checked by the caller, not HeadersSyncState. A threshold of one
    // lets either candidate reach it, avoiding randomized commitment checks
    // when changing the redownloaded header to isolate the retarget check.
    for (bool redownload : {false, true}) {
        BOOST_TEST_CONTEXT("height=" << next_height << " history=" << history_size << " redownload=" << redownload) {
            HeadersSyncState sync{0, params, start, arith_uint256{1}};
            if (redownload) {
                CBlockHeader valid = candidate;
                valid.nBits = expected ? new_bits : valid_bits.value_or(old_bits);
                BOOST_REQUIRE(sync.ProcessNextHeaders({valid}, true).success);
                BOOST_REQUIRE(sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
            }
            const auto result = sync.ProcessNextHeaders({candidate}, true);
            BOOST_CHECK_EQUAL(result.success, expected);
            if (!expected) {
                BOOST_CHECK(!result.request_more);
                BOOST_CHECK(result.pow_validated_headers.empty());
                BOOST_CHECK(sync.GetState() == HeadersSyncState::State::FINAL);
            } else if (redownload) {
                BOOST_REQUIRE_EQUAL(result.pow_validated_headers.size(), 1U);
                BOOST_CHECK(result.pow_validated_headers.front().GetHash() == candidate.GetHash());
            } else {
                BOOST_CHECK(sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
            }
        }
    }
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

BOOST_AUTO_TEST_CASE(compressed_header_preserves_fields_without_proof)
{
    CBlockHeader header;
    header.nVersion = 4;
    header.SetAuxpowVersion(true);
    header.nTime = 123;
    header.nBits = 0x207fffff;
    header.nNonce = 7;
    header.hashMerkleRoot = uint256{0x11};
    header.auxpow = std::make_shared<CAuxPow>();

    CompressedHeader compressed{header};
    const uint256 prev{0xaa};
    CBlockHeader full = compressed.GetFullHeader(prev);

    BOOST_CHECK(full.IsAuxpow());
    BOOST_CHECK(!full.auxpow);
    BOOST_CHECK_EQUAL(full.nNonce, header.nNonce);
    BOOST_CHECK(full.hashMerkleRoot == header.hashMerkleRoot);
    BOOST_CHECK(full.hashPrevBlock == prev);
}

BOOST_AUTO_TEST_CASE(sync_tracks_height_without_retaining_proofs)
{
    const auto* start = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    std::vector<CBlockHeader> headers;
    GenerateHeaders(headers, 1, start->GetBlockHash(), 4, start->nTime, uint256{1}, start->nBits);
    headers[0].SetAuxpowVersion(true);
    headers[0].auxpow = std::make_shared<CAuxPow>();
    std::weak_ptr<CAuxPow> proof = headers[0].auxpow;
    const auto work = start->nChainWork + GetBlockProof(CBlockIndex(headers[0]));
    HeadersSyncState sync{0, Params().GetConsensus(), start, work};
    BOOST_REQUIRE(sync.GetNextHeight(start->GetBlockHash()));
    BOOST_CHECK_EQUAL(*sync.GetNextHeight(start->GetBlockHash()), 1);
    BOOST_CHECK(!sync.GetNextHeight(uint256{123}));

    // This unit exercises bookkeeping; the caller performs proof checks.
    auto first = sync.ProcessNextHeaders(headers, true);
    BOOST_REQUIRE(first.success);
    BOOST_CHECK(!first.checked_start_height);
    BOOST_CHECK(sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
    headers[0].auxpow.reset();
    BOOST_CHECK(proof.expired()); // The first-pass reference must be gone too.
    BOOST_REQUIRE(sync.GetNextHeight(start->GetBlockHash()));
    BOOST_CHECK_EQUAL(*sync.GetNextHeight(start->GetBlockHash()), 1);
    BOOST_CHECK(!sync.GetNextHeight(headers[0].GetHash()));

    headers[0].auxpow = std::make_shared<CAuxPow>();
    proof = headers[0].auxpow;
    auto second = sync.ProcessNextHeaders(headers, true);
    BOOST_REQUIRE(second.success);
    BOOST_REQUIRE(second.checked_start_height);
    BOOST_CHECK_EQUAL(*second.checked_start_height, 1);
    BOOST_REQUIRE_EQUAL(second.pow_validated_headers.size(), 1U);
    BOOST_CHECK(second.pow_validated_headers[0].GetHash() == headers[0].GetHash());
    BOOST_CHECK(!second.pow_validated_headers[0].auxpow);
    headers[0].auxpow.reset();
    BOOST_CHECK(proof.expired());
    BOOST_CHECK(sync.GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(!sync.GetNextHeight(start->GetBlockHash()));
}

// In this test, we construct two sets of headers from genesis, one with
// sufficient chain work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    // Use enough headers to cross multiple commitment points with the default
    // commitment period, while avoiding PQ PoW grinding in this test.
    const int target_blocks = 15000;

    // Generate headers for the first chain.
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    const arith_uint256 per_block_proof = GetBlockProof(CBlockIndex(Params().GenesisBlock()));
    arith_uint256 chain_work = chain_start->nChainWork;
    for (int i = 0; i < target_blocks - 1; ++i) {
        chain_work += per_block_proof;
    }
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the chain work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(headers_sync_window_retarget_post_auxpow)
{
    // Use a local consensus copy to force post-auxpow per-block retarget rules.
    Consensus::Params params = Params().GetConsensus();
    params.nAuxpowStartHeight = 0;
    params.nPowAveragingWindow = 4;
    params.nPowMaxAdjustUp = 16;
    params.nPowMaxAdjustDown = 32;
    params.fPowAllowMinDifficultyBlocks = false;
    params.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));

    // Set a very high required work so we remain in PRESYNC for this test.
    arith_uint256 chain_work = ~arith_uint256{0};

    HeadersSyncState hss(0, params, chain_start, chain_work);

    std::vector<CBlockHeader> headers;
    // Constant nBits at powLimit should be rejected once window-aware retarget activates.
    GenerateHeaders(headers, 5, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    auto result = hss.ProcessNextHeaders(headers, true);
    BOOST_CHECK(!result.success);
}

BOOST_AUTO_TEST_CASE(headers_sync_legacy_retarget)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE_EQUAL(params.nAuxpowStartHeight, Consensus::AUXPOW_DISABLED);
    BOOST_REQUIRE_EQUAL(params.DifficultyAdjustmentInterval(), 7200);
    BOOST_REQUIRE(!params.fPowAllowMinDifficultyBlocks);
    // Stay below the legacy overflow range for the bounded retarget cases.
    arith_uint256 target = UintToArith256(params.powLimit) >> 32;
    const uint32_t old_bits = target.GetCompact();
    target.SetCompact(old_bits);

    for (int activation : {Consensus::AUXPOW_DISABLED, 15000}) {
        params.nAuxpowStartHeight = activation;
        for (size_t history : {1U, 30U}) {
            // Legacy screening must not wait for an averaging window.
            CheckRetargetBothPhases(params, 7201, old_bits, old_bits, true, history);
            CheckRetargetBothPhases(params, 7201, old_bits, arith_uint256{target * 2}.GetCompact(), false, history);
            CheckRetargetBothPhases(params, 7201, old_bits, arith_uint256{target / 2}.GetCompact(), false, history);
            for (int height : {7200, 14400}) {
                for (const auto& permitted : std::array<arith_uint256, 5>{target / 4, target / 2, target, target * 2, target * 4}) {
                    CheckRetargetBothPhases(params, height, old_bits, permitted.GetCompact(), true, history);
                }
                CheckRetargetBothPhases(params, height, old_bits, arith_uint256{target * 8}.GetCompact(), false, history);
                CheckRetargetBothPhases(params, height, old_bits, arith_uint256{target / 8}.GetCompact(), false, history);
            }
        }
        CheckRetargetBothPhases(params, 1, old_bits, arith_uint256{target * 2}.GetCompact(), false, 1);

        // Preserve the historical arithmetic exception: the legacy retarget
        // can wrap, so the preliminary check deliberately permits these cases.
        CBlockIndex previous;
        previous.nHeight = 7199;
        previous.nTime = 1'600'000'000;
        previous.nBits = UintToArith256(params.powLimit).GetCompact();
        const uint32_t wrapped_bits = CalculateNextWorkRequired(&previous,
                previous.GetBlockTime() - params.nPowTargetTimespan * 10, params);
        BOOST_REQUIRE_NE(wrapped_bits, previous.nBits);
        CheckRetargetBothPhases(params, 7200, previous.nBits, wrapped_bits, true, 30);

        // Testnet/regtest's broad min-difficulty exception remains unchanged.
        params.fPowAllowMinDifficultyBlocks = true;
        CheckRetargetBothPhases(params, 7201, old_bits, arith_uint256{target * 8}.GetCompact(), true, 1);
        CheckRetargetBothPhases(params, 7200, old_bits, arith_uint256{target / 8}.GetCompact(), true, 30);
        params.fPowAllowMinDifficultyBlocks = false;
    }
    params.nAuxpowStartHeight = Consensus::AUXPOW_DISABLED;
    CheckRetargetBothPhases(params, Consensus::AUXPOW_DISABLED - 1,
            old_bits, arith_uint256{target * 2}.GetCompact(), false, 30);
}

BOOST_AUTO_TEST_CASE(headers_sync_retarget_activation_window)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.nAuxpowStartHeight = 1000;
    BOOST_REQUIRE_EQUAL(params.nPowAveragingWindow, 17);
    arith_uint256 target = UintToArith256(params.powLimit) >> 32;
    const uint32_t old_bits = target.GetCompact();
    target.SetCompact(old_bits);
    const uint32_t changed_bits = arith_uint256{target * 8}.GetCompact();

    CheckRetargetBothPhases(params, 999, old_bits, changed_bits, false, 30);
    for (int height : {1000, 1001, 1017}) {
        CheckRetargetBothPhases(params, height, old_bits, changed_bits, true, 30);
    }
    CheckRetargetBothPhases(params, 1018, old_bits, old_bits, true, 30);
    CheckRetargetBothPhases(params, 1018, old_bits, changed_bits, false, 30);
    // The existing post-activation warmup for insufficient history still applies.
    CheckRetargetBothPhases(params, 1018, old_bits, changed_bits, true, 1);

    params.nPowAllowMinDifficultyBlocksAfterHeight = 1000;
    const uint32_t powlimit_bits = UintToArith256(params.powLimit).GetCompact();
    CheckRetargetBothPhases(params, 1018, old_bits, powlimit_bits, true, 30, 361);
    CheckRetargetBothPhases(params, 1018, old_bits, old_bits, false, 30, 361, powlimit_bits);
    CheckRetargetBothPhases(params, 1018, old_bits, old_bits, true, 30, 360);
}

BOOST_AUTO_TEST_SUITE_END()
