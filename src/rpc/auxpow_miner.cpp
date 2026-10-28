// Copyright (c) 2018-2020 Daniel Kraft
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/auxpow_miner.h>

#include <arith_uint256.h>
#include <auxpow.h>
#include <chainparams.h>
#include <common/args.h>
#include <net.h>
#include <node/context.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server_util.h>
#include <streams.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <cassert>

namespace {
void AuxMiningCheck(const JSONRPCRequest& request)
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    if (!node.connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED,
                           "Error: Peer-to-peer functionality missing or disabled");
    }

    if (node.connman->GetNodeCount(ConnectionDirection::Both) == 0 &&
        !node.chainman->GetParams().MineBlocksOnDemand()) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Tidecoin is not connected!");
    }

    if (node.chainman->IsInitialBlockDownload() &&
        !node.chainman->GetParams().MineBlocksOnDemand()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Tidecoin is downloading blocks...");
    }

    {
        LOCK(cs_main);
        const auto auxpow_start = node.chainman->GetConsensus().nAuxpowStartHeight;
        if (node.chainman->ActiveChain().Height() + 1 < auxpow_start) {
            throw std::runtime_error("mining auxblock method is not yet available");
        }
    }
}
} // namespace

const CBlock* AuxpowMiner::getCurrentBlock(ChainstateManager& chainman, const CTxMemPool& mempool,
                                           const CScript& script_pub_key, uint256& target)
{
    AssertLockHeld(cs);
    const CBlock* block_cur = nullptr;

    {
        LOCK(cs_main);
        if (pindex_prev != chainman.ActiveTip()) {
            cur_blocks.clear();
            blocks.clear();
            templates.clear();
        }

        const CScriptID script_id(script_pub_key);
        const auto iter = cur_blocks.find(script_id);
        const auto tx_updated = mempool.GetTransactionsUpdated();
        const int64_t now = GetTime();
        if (iter == cur_blocks.end() ||
            (tx_updated != iter->second.tx_updated && now - iter->second.created_at > 60)) {

            node::BlockAssembler::Options assemble_options;
            node::ApplyArgsManOptions(gArgs, assemble_options);
            assemble_options.coinbase_output_script = script_pub_key;

            std::unique_ptr<node::CBlockTemplate> new_block =
                node::BlockAssembler(chainman.ActiveChainstate(), &mempool, assemble_options).CreateNewBlock();
            if (!new_block) {
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "out of memory");
            }

            new_block->block.SetAuxpowVersion(true);
            new_block->block.nVersion &= ~CPureBlockHeader::MASK_AUXPOW_CHAINID_SHIFTED;
            new_block->block.nVersion |= chainman.GetConsensus().nAuxpowChainId << CPureBlockHeader::VERSION_START_BIT;

            block_cur = &new_block->block;
            templates.push_back(std::move(new_block));
            blocks[block_cur->GetHash()] = block_cur;
            cur_blocks.insert_or_assign(script_id, CurrentBlock{block_cur, tx_updated, now});
            pindex_prev = chainman.ActiveTip();
        } else {
            block_cur = iter->second.block;
        }
    }

    CHECK_NONFATAL(block_cur);

    arith_uint256 arith_target;
    bool f_negative, f_overflow;
    arith_target.SetCompact(block_cur->nBits, &f_negative, &f_overflow);
    if (f_negative || f_overflow || arith_target == 0) {
        throw std::runtime_error("invalid difficulty bits in block");
    }
    target = ArithToUint256(arith_target);

    return block_cur;
}

const CBlock* AuxpowMiner::lookupSavedBlock(const std::string& hash_hex) const
{
    AssertLockHeld(cs);

    const auto hash_opt = uint256::FromHex(hash_hex);
    if (!hash_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "block hash invalid");
    }
    const uint256 hash{*hash_opt};

    const auto iter = blocks.find(hash);
    if (iter == blocks.end()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "block hash unknown");
    }

    return iter->second;
}

UniValue AuxpowMiner::createAuxBlock(const JSONRPCRequest& request, const CScript& script_pub_key)
{
    AuxMiningCheck(request);
    LOCK(cs);

    const auto& mempool = EnsureAnyMemPool(request.context);
    auto& chainman = EnsureAnyChainman(request.context);
    uint256 target;
    const CBlock* block = getCurrentBlock(chainman, mempool, script_pub_key, target);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", block->GetHash().GetHex());
    result.pushKV("chainid", block->GetChainId());
    result.pushKV("previousblockhash", block->hashPrevBlock.GetHex());
    result.pushKV("coinbasevalue", static_cast<int64_t>(block->vtx[0]->vout[0].nValue));
    result.pushKV("bits", strprintf("%08x", block->nBits));
    result.pushKV("height", static_cast<int64_t>(pindex_prev->nHeight + 1));
    result.pushKV("_target", HexStr(target));

    return result;
}

bool AuxpowMiner::submitAuxBlock(const JSONRPCRequest& request, const std::string& hash_hex,
                                 const std::string& auxpow_hex) const
{
    AuxMiningCheck(request);
    auto& chainman = EnsureAnyChainman(request.context);

    std::shared_ptr<CBlock> shared_block;
    {
        LOCK(cs);
        const CBlock* block = lookupSavedBlock(hash_hex);
        shared_block = std::make_shared<CBlock>(*block);
    }

    const std::vector<unsigned char> auxpow_bytes = ParseHex(auxpow_hex);
    DataStream ss(auxpow_bytes);
    std::unique_ptr<CAuxPow> pow(new CAuxPow());
    ss >> *pow;

    shared_block->auxpow = std::shared_ptr<CAuxPow>(std::move(pow));
    CHECK_NONFATAL(shared_block->GetHash() == uint256::FromHex(hash_hex).value());

    return chainman.ProcessNewBlock(shared_block, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr);
}

AuxpowMiner& AuxpowMiner::get()
{
    static AuxpowMiner* instance = nullptr;
    static RecursiveMutex lock;

    LOCK(lock);
    if (instance == nullptr) {
        instance = new AuxpowMiner();
    }

    return *instance;
}
