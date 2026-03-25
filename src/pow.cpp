// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <algorithm>
#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

namespace {
arith_uint256 ScaleTargetLegacyOverflow(arith_uint256 target, int64_t actual_timespan, int64_t target_timespan, const arith_uint256& pow_limit)
{
    const bool shift = target.bits() > pow_limit.bits() - 1;
    if (shift) {
        target >>= 1;
    }
    target *= actual_timespan;
    target /= target_timespan;
    if (shift) {
        target <<= 1;
    }
    return target;
}
} // namespace

unsigned int CalculateNextWorkRequiredOld(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params);
unsigned int GetNextWorkRequiredOld(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params);
unsigned int CalculateNextWorkRequiredNew(arith_uint256 bnAvg, int64_t nLastBlockTime, int64_t nFirstBlockTime, const Consensus::Params& params);
unsigned int GetNextWorkRequiredNew(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    if (pindexLast->nHeight <= params.nNewPowDiffHeight) {
        return GetNextWorkRequiredOld(pindexLast, pblock, params);
    }
    return GetNextWorkRequiredNew(pindexLast, pblock, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    if (pindexLast->nHeight <= params.nNewPowDiffHeight) {
        return CalculateNextWorkRequiredOld(pindexLast, nFirstBlockTime, params);
    }

    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    // Find the first block in the averaging interval.
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot{0};
    for (int i = 0; pindexFirst && i < params.nPowAveragingWindow; ++i) {
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
    }

    if (!pindexFirst) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    arith_uint256 bnAvg{bnTot / params.nPowAveragingWindow};

    return CalculateNextWorkRequiredNew(bnAvg, pindexLast->GetMedianTimePast(), pindexFirst->GetMedianTimePast(), params);
}

unsigned int GetNextWorkRequiredOld(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Tidecoin: go back the full period unless this is the first retarget after genesis.
    int blockstogoback = params.DifficultyAdjustmentInterval() - 1;
    if ((pindexLast->nHeight + 1) != params.DifficultyAdjustmentInterval()) {
        blockstogoback = params.DifficultyAdjustmentInterval();
    }

    int nHeightFirst = pindexLast->nHeight - blockstogoback;
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequiredOld(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int GetNextWorkRequiredNew(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == nullptr) {
        return nProofOfWorkLimit;
    }

    // Regtest
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    if (params.nPowAllowMinDifficultyBlocksAfterHeight != std::nullopt &&
        static_cast<uint32_t>(pindexLast->nHeight) >= params.nPowAllowMinDifficultyBlocksAfterHeight.value()) {
        if (pblock && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.PoWTargetSpacing().count() * 6) {
            return nProofOfWorkLimit;
        }
    }

    // Find the first block in the averaging interval
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot{0};
    for (int i = 0; pindexFirst && i < params.nPowAveragingWindow; i++) {
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
    }

    if (pindexFirst == nullptr) {
        return nProofOfWorkLimit;
    }

    arith_uint256 bnAvg{bnTot / params.nPowAveragingWindow};

    return CalculateNextWorkRequiredNew(bnAvg,
        pindexLast->GetMedianTimePast(), pindexFirst->GetMedianTimePast(), params);
}

unsigned int CalculateNextWorkRequiredNew(arith_uint256 bnAvg,
    int64_t nLastBlockTime,
    int64_t nFirstBlockTime,
    const Consensus::Params& params)
{
    const int64_t averagingWindowTimespan = params.AveragingWindowTimespan();
    const int64_t minActualTimespan = params.MinActualTimespan();
    const int64_t maxActualTimespan = params.MaxActualTimespan();

    // Use medians to prevent time-warp attacks.
    int64_t nActualTimespan = nLastBlockTime - nFirstBlockTime;
    nActualTimespan = averagingWindowTimespan + (nActualTimespan - averagingWindowTimespan) / 4;

    if (nActualTimespan < minActualTimespan) {
        nActualTimespan = minActualTimespan;
    }
    if (nActualTimespan > maxActualTimespan) {
        nActualTimespan = maxActualTimespan;
    }

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew{bnAvg};
    bnNew /= averagingWindowTimespan;
    bnNew *= nActualTimespan;

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequiredOld(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew = ScaleTargetLegacyOverflow(bnNew, nActualTimespan, params.nPowTargetTimespan, bnPowLimit);

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    // Allow everything when min-difficulty is allowed (regtest/test modes).
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height <= params.nNewPowDiffHeight) {
        if (height % params.DifficultyAdjustmentInterval() == 0) {
            int64_t smallest_timespan = params.nPowTargetTimespan/4;
            int64_t largest_timespan = params.nPowTargetTimespan*4;

            const arith_uint256 pow_limit = UintToArith256(params.powLimit);
            arith_uint256 observed_new_target;
            observed_new_target.SetCompact(new_nbits);

            // Calculate the largest difficulty value possible:
            arith_uint256 largest_difficulty_target;
            largest_difficulty_target.SetCompact(old_nbits);
            largest_difficulty_target = ScaleTargetLegacyOverflow(largest_difficulty_target, largest_timespan, params.nPowTargetTimespan, pow_limit);

            if (largest_difficulty_target > pow_limit) {
                largest_difficulty_target = pow_limit;
            }

            // Round and then compare this new calculated value to what is
            // observed.
            arith_uint256 maximum_new_target;
            maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
            if (maximum_new_target < observed_new_target) return false;

            // Calculate the smallest difficulty value possible:
            arith_uint256 smallest_difficulty_target;
            smallest_difficulty_target.SetCompact(old_nbits);
            smallest_difficulty_target = ScaleTargetLegacyOverflow(smallest_difficulty_target, smallest_timespan, params.nPowTargetTimespan, pow_limit);

            if (smallest_difficulty_target > pow_limit) {
                smallest_difficulty_target = pow_limit;
            }

            // Round and then compare this new calculated value to what is
            // observed.
            arith_uint256 minimum_new_target;
            minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
            if (minimum_new_target > observed_new_target) return false;
        } else if (old_nbits != new_nbits) {
            return false;
        }
        return true;
    }

    // Post-activation (per-block retargeting) bounds.
    const arith_uint256 pow_limit = UintToArith256(params.powLimit);

    arith_uint256 old_target;
    old_target.SetCompact(old_nbits);

    arith_uint256 observed_new_target;
    observed_new_target.SetCompact(new_nbits);

    const int64_t up_pct = std::max<int64_t>(0, params.nPowMaxAdjustUp);
    const int64_t down_pct = std::max<int64_t>(0, params.nPowMaxAdjustDown);

    const int64_t up_num_sq = (100LL - up_pct) * (100LL - up_pct);
    const int64_t down_num_sq = (100LL + down_pct) * (100LL + down_pct);

    arith_uint256 largest_difficulty_target = old_target;
    largest_difficulty_target *= down_num_sq;
    largest_difficulty_target /= 10000LL;
    if (largest_difficulty_target > pow_limit) largest_difficulty_target = pow_limit;

    arith_uint256 smallest_difficulty_target = old_target;
    smallest_difficulty_target *= up_num_sq;
    smallest_difficulty_target /= 10000LL;

    arith_uint256 maximum_new_target;
    maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
    maximum_new_target += 2;

    arith_uint256 minimum_new_target;
    minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
    if (minimum_new_target > 1) {
        minimum_new_target -= 2;
    } else if (minimum_new_target > 0) {
        minimum_new_target -= 1;
    }

    if (observed_new_target < minimum_new_target) return false;
    if (observed_new_target > maximum_new_target) return false;

    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

bool UseScryptPoW(const Consensus::Params& params, int height)
{
    return height >= params.nAuxpowStartHeight;
}

uint256 GetPoWHashForHeight(const CBlockHeader& block, const Consensus::Params& params, int height)
{
    return UseScryptPoW(params, height) ? block.GetScryptPoWHash() : block.GetPoWHash();
}

bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params, int height)
{
    return CheckProofOfWork(GetPoWHashForHeight(block, params, height), block.nBits, params);
}

bool CheckProofOfWorkAny(const CBlockHeader& block, const Consensus::Params& params)
{
    if (CheckProofOfWork(block.GetPoWHash(), block.nBits, params)) {
        return true;
    }
    return CheckProofOfWork(block.GetScryptPoWHash(), block.nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
