// Copyright (c) 2024-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <rpc/auxpow_miner.h>
#include <rpc/protocol.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

namespace auxpow_tests {
class AuxpowMinerForTest
{
public:
    static CBlock Current(AuxpowMiner& miner, ChainstateManager& chainman,
                          const CTxMemPool& mempool, const CScript& payout)
    {
        LOCK(miner.cs);
        uint256 target;
        return *miner.getCurrentBlock(chainman, mempool, payout, target);
    }

    static CBlock Saved(AuxpowMiner& miner, const uint256& hash)
    {
        LOCK(miner.cs);
        return *miner.lookupSavedBlock(hash.GetHex());
    }
};

class CAuxPowForTest
{
public:
    static uint256 CheckBranch(uint256 hash, const std::vector<uint256>& merkle_branch, int index)
    {
        return CAuxPow::CheckMerkleBranch(hash, merkle_branch, index);
    }

    static std::vector<uint256>& MerkleBranch(CAuxPow& auxpow)
    {
        return auxpow.vMerkleBranch;
    }

    static std::vector<uint256>& ChainMerkleBranch(CAuxPow& auxpow)
    {
        return auxpow.vChainMerkleBranch;
    }

    static int& ChainIndex(CAuxPow& auxpow)
    {
        return auxpow.nChainIndex;
    }

    static CPureBlockHeader& Parent(CAuxPow& auxpow)
    {
        return auxpow.parentBlock;
    }

    static void SetParent(CAuxPow& auxpow, const CBlockHeader& header)
    {
        CPureBlockHeader& parent = auxpow.parentBlock;
        parent.nVersion = header.nVersion;
        parent.hashPrevBlock = header.hashPrevBlock;
        parent.hashMerkleRoot = header.hashMerkleRoot;
        parent.nTime = header.nTime;
        parent.nBits = header.nBits;
        parent.nNonce = header.nNonce;
    }
};
} // namespace auxpow_tests

namespace {
CBlockHeader MakeTestHeader(const Consensus::Params& params)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetNull();
    header.nTime = 1;
    header.nBits = UintToArith256(params.powLimit).GetCompact();
    header.nNonce = 1;
    return header;
}

class CAuxpowBuilder
{
public:
    CBlock parent_block;
    std::vector<uint256> chain_merkle_branch;
    int chain_index{-1};

    CAuxpowBuilder(int base_version, int chain_id)
    {
        parent_block.SetBaseVersion(base_version, chain_id);
    }

    void SetCoinbase(const CScript& script)
    {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout.SetNull();
        mtx.vin[0].scriptSig = script;

        parent_block.vtx.clear();
        parent_block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
        parent_block.hashMerkleRoot = BlockMerkleRoot(parent_block);
    }

    std::vector<unsigned char> BuildChainMerkleRoot(const uint256& aux_hash, unsigned height, int index)
    {
        chain_index = index;
        chain_merkle_branch.clear();
        for (unsigned i = 0; i < height; ++i) {
            chain_merkle_branch.push_back(ArithToUint256(arith_uint256(i + 1)));
        }

        uint256 root = auxpow_tests::CAuxPowForTest::CheckBranch(aux_hash, chain_merkle_branch, index);
        std::vector<unsigned char> result(root.begin(), root.end());
        std::reverse(result.begin(), result.end());
        return result;
    }

    CAuxPow Get(const CTransactionRef& tx) const
    {
        CAuxPow auxpow{CTransactionRef{tx}};
        auxpow_tests::CAuxPowForTest::MerkleBranch(auxpow) = TransactionMerklePath(parent_block, 0);
        auxpow_tests::CAuxPowForTest::ChainMerkleBranch(auxpow) = chain_merkle_branch;
        auxpow_tests::CAuxPowForTest::ChainIndex(auxpow) = chain_index;
        auxpow_tests::CAuxPowForTest::SetParent(auxpow, parent_block);
        return auxpow;
    }

    std::unique_ptr<CAuxPow> GetUnique() const
    {
        return std::make_unique<CAuxPow>(Get(parent_block.vtx[0]));
    }

    static std::vector<unsigned char> BuildCoinbaseData(bool include_header, const std::vector<unsigned char>& aux_root,
                                                        unsigned height, int nonce)
    {
        std::vector<unsigned char> result;

        if (include_header) {
            result.insert(result.end(), pchMergedMiningHeader,
                          pchMergedMiningHeader + sizeof(pchMergedMiningHeader));
        }
        result.insert(result.end(), aux_root.begin(), aux_root.end());

        int size = (1 << height);
        for (int i = 0; i < 4; ++i) {
            result.push_back(size & 0xff);
            size >>= 8;
        }
        for (int i = 0; i < 4; ++i) {
            result.push_back(nonce & 0xff);
            nonce >>= 8;
        }
        return result;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(auxpow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(auxpow_missing_header_rejected)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.fStrictChainId = false;

    CBlockHeader header = MakeTestHeader(params);
    header.SetAuxpowVersion(true);
    header.auxpow = CAuxPow::createAuxPow(header);

    BOOST_CHECK(!header.auxpow->check(header.GetHash(), params.nAuxpowChainId, params));
}

BOOST_AUTO_TEST_CASE(auxpow_parent_chainid_rejected)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.fStrictChainId = true;

    CBlockHeader header = MakeTestHeader(params);
    header.SetAuxpowVersion(true);
    header.auxpow = CAuxPow::createAuxPow(header);

    CPureBlockHeader& parent = auxpow_tests::CAuxPowForTest::Parent(*header.auxpow);
    parent.SetNull();
    parent.SetBaseVersion(2, params.nAuxpowChainId);
    parent.SetAuxpowVersion(true);

    BOOST_CHECK(!header.auxpow->check(header.GetHash(), params.nAuxpowChainId, params));
}

BOOST_AUTO_TEST_CASE(auxpow_parent_pow_checked_in_headers)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.fStrictChainId = false;
    params.nAuxpowStartHeight = 1;

    CBlockHeader header = MakeTestHeader(params);
    header.SetBaseVersion(2, params.nAuxpowChainId);
    header.SetAuxpowVersion(true);

    const unsigned merkle_height = 1;
    const int nonce = 7;
    const uint256 aux_hash = header.GetHash();
    CAuxpowBuilder builder(/*base_version=*/2, /*chain_id=*/0);
    const int index = CAuxPow::getExpectedIndex(nonce, params.nAuxpowChainId, merkle_height);
    const std::vector<unsigned char> aux_root = builder.BuildChainMerkleRoot(aux_hash, merkle_height, index);
    const std::vector<unsigned char> data = CAuxpowBuilder::BuildCoinbaseData(true, aux_root, merkle_height, nonce);
    builder.SetCoinbase(CScript() << OP_2 << data);
    header.auxpow = builder.GetUnique();

    BOOST_CHECK(header.auxpow->check(aux_hash, params.nAuxpowChainId, params));

    const arith_uint256 parent_hash = UintToArith256(header.auxpow->getParentBlockHash());
    arith_uint256 target = parent_hash;
    if (target > 0) {
        target -= 1;
    }
    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    if (target > pow_limit) {
        target = pow_limit;
    }
    header.nBits = target.GetCompact();

    BOOST_CHECK(!HasValidProofOfWork({header}, params, params.nAuxpowStartHeight));
}

BOOST_FIXTURE_TEST_CASE(auxpow_blockheader_reads_auxpow, TestingSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    auto& blockman = chainman.m_blockman;
    const Consensus::Params& params = Params().GetConsensus();

    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock.SetNull();
    block.nTime = 2;
    block.nBits = UintToArith256(params.powLimit).GetCompact();
    block.nNonce = 3;
    block.SetBaseVersion(2, params.nAuxpowChainId);
    block.SetAuxpowVersion(true);

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << OP_0;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    block.auxpow = CAuxPow::createAuxPow(block);

    const FlatFilePos pos = blockman.WriteBlock(block, /*nHeight=*/1);
    blockman.UpdateBlockInfo(block, /*nHeight=*/1, pos);

    auto block_hash = std::make_unique<uint256>(block.GetHash());
    CBlockIndex index{block};
    index.phashBlock = block_hash.get();
    index.nHeight = 1;
    {
        LOCK(cs_main);
        index.nStatus |= BLOCK_HAVE_DATA;
        index.nFile = pos.nFile;
        index.nDataPos = pos.nPos;
    }

    const auto result = index.GetBlockHeader(chainman);
    BOOST_REQUIRE(std::holds_alternative<CBlockHeader>(result));
    const auto& header = std::get<CBlockHeader>(result);
    BOOST_CHECK(header.IsAuxpow());
    BOOST_CHECK(header.auxpow);
    BOOST_CHECK_EQUAL(header.auxpow->getParentBlockHash(), block.auxpow->getParentBlockHash());
}

BOOST_FIXTURE_TEST_CASE(auxpow_template_refresh_and_retention, TestChain100Setup)
{
    using auxpow_tests::AuxpowMinerForTest;
    AuxpowMiner miner;
    auto& chainman = *m_node.chainman;
    auto& mempool = *m_node.mempool;
    const CScript payout_a{CScript() << OP_TRUE};
    const CScript payout_b{CScript() << OP_2};
    const int64_t start{GetTime()};
    const auto current = [&](const CScript& payout) {
        return AuxpowMinerForTest::Current(miner, chainman, mempool, payout).GetHash();
    };

    const auto a0 = current(payout_a);
    SetMockTime(start + 30);
    const auto b0 = current(payout_b);
    BOOST_CHECK(a0 != b0);
    mempool.AddTransactionsUpdated(1);

    // Each payout must wait strictly more than 60 seconds from its own creation.
    SetMockTime(start + 60);
    BOOST_CHECK(current(payout_a) == a0);
    SetMockTime(start + 61);
    const auto a1 = current(payout_a);
    BOOST_CHECK(a1 != a0);
    BOOST_CHECK(current(payout_a) == a1);
    BOOST_CHECK(current(payout_b) == b0);
    SetMockTime(start + 90);
    BOOST_CHECK(current(payout_b) == b0);
    SetMockTime(start + 91);
    const auto b1 = current(payout_b);
    BOOST_CHECK(b1 != b0);
    BOOST_CHECK(current(payout_b) == b1);
    BOOST_CHECK(current(payout_a) == a1);

    // Time alone does not expire current or previously issued work.
    SetMockTime(start + 3600);
    BOOST_CHECK(current(payout_a) == a1);
    BOOST_CHECK(current(payout_b) == b1);
    mempool.AddTransactionsUpdated(1);
    const auto a2 = current(payout_a);
    const auto b2 = current(payout_b);
    BOOST_CHECK(a2 != a1);
    BOOST_CHECK(b2 != b1);
    BOOST_CHECK(current(payout_a) == a2);
    BOOST_CHECK(current(payout_b) == b2);

    // Moving mock time backwards must not look like an elapsed refresh interval.
    mempool.AddTransactionsUpdated(1);
    SetMockTime(start + 3500);
    BOOST_CHECK(current(payout_a) == a2);
    BOOST_CHECK(current(payout_b) == b2);
    for (const auto& hash : {a0, b0, a1, b1, a2, b2}) {
        BOOST_CHECK(AuxpowMinerForTest::Saved(miner, hash).GetHash() == hash);
    }

    SetMockTime(start + 3601);
    const auto block = CreateAndProcessBlock({}, payout_a);
    const auto next_a = AuxpowMinerForTest::Current(miner, chainman, mempool, payout_a);
    const auto next_b = AuxpowMinerForTest::Current(miner, chainman, mempool, payout_b);
    BOOST_CHECK(next_a.hashPrevBlock == block.GetHash());
    BOOST_CHECK(next_b.hashPrevBlock == block.GetHash());
    BOOST_CHECK(current(payout_a) == next_a.GetHash());
    BOOST_CHECK(current(payout_b) == next_b.GetHash());
    for (const auto& hash : {a0, b0, a1, b1, a2, b2}) {
        BOOST_CHECK_EXCEPTION(AuxpowMinerForTest::Saved(miner, hash), UniValue,
            [](const UniValue& error) {
                return error["code"].getInt<int>() == RPC_INVALID_PARAMETER &&
                       error["message"].get_str() == "block hash unknown";
            });
    }
}

BOOST_AUTO_TEST_SUITE_END()
