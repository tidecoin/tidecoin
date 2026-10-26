// Copyright (c) 2018-2020 Daniel Kraft
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TIDECOIN_RPC_AUXPOW_MINER_H
#define TIDECOIN_RPC_AUXPOW_MINER_H

#include <node/miner.h>
#include <script/script.h>
#include <sync.h>
#include <txmempool.h>
#include <uint256.h>
#include <univalue.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

class ChainstateManager;
class JSONRPCRequest;

namespace auxpow_tests
{
class AuxpowMinerForTest;
} // namespace auxpow_tests

/**
 * Singleton state for auxpow mining RPCs (create/submit aux blocks).
 */
class AuxpowMiner
{
private:
    struct CurrentBlock {
        const CBlock* block;
        unsigned int tx_updated;
        int64_t created_at;
    };

    mutable RecursiveMutex cs;
    // Retain all issued work until a request observes a new chain tip.
    std::vector<std::unique_ptr<node::CBlockTemplate>> templates;
    std::map<uint256, const CBlock*> blocks;
    std::map<CScriptID, CurrentBlock> cur_blocks;

    const CBlockIndex* pindex_prev{nullptr};

    const CBlock* getCurrentBlock(ChainstateManager& chainman, const CTxMemPool& mempool,
                                  const CScript& script_pub_key, uint256& target) EXCLUSIVE_LOCKS_REQUIRED(cs);
    const CBlock* lookupSavedBlock(const std::string& hash_hex) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    friend class auxpow_tests::AuxpowMinerForTest;

public:
    AuxpowMiner() = default;

    UniValue createAuxBlock(const JSONRPCRequest& request, const CScript& script_pub_key);
    bool submitAuxBlock(const JSONRPCRequest& request, const std::string& hash_hex,
                        const std::string& auxpow_hex) const;

    static AuxpowMiner& get();
};

#endif // TIDECOIN_RPC_AUXPOW_MINER_H
