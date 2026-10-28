// Copyright (c) 2013-2019 The BELLSCOIN Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <node/context.h>
#include <rpc/auxpow_miner.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <sync.h>
#include <wallet/context.h>
#include <wallet/rpc/util.h>
#include <wallet/rpc/wallet.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <map>
#include <set>
#include <string>

namespace wallet {
namespace {

/**
 * Helper class that keeps track of reserved keys that are used for mining
 * coinbases. We also keep track of the block hash(es) that are based on the
 * key, so we can mark it as keep and get a fresh one once a block is submitted.
 */
class ReservedKeysForMining
{
private:
    struct PerWallet
    {
        CScript coinbase_script;
        std::set<uint256> block_hashes;

        explicit PerWallet(const CScript& script)
            : coinbase_script(script)
        {
        }

        PerWallet(PerWallet&&) = default;
    };

    std::map<std::string, PerWallet> data;

public:
    mutable RecursiveMutex cs;
    ReservedKeysForMining() = default;

    CScript GetCoinbaseScript(CWallet* pwallet) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        LOCK(pwallet->cs_wallet);

        const auto it = data.find(pwallet->GetName());
        if (it != data.end()) {
            return it->second.coinbase_script;
        }

        ReserveDestination rdest(pwallet, pwallet->m_default_address_type);
        auto op_dest = rdest.GetReservedDestination(false);
        if (!op_dest) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,
                               "Error: Keypool ran out, please call keypoolrefill first");
        }

        rdest.KeepDestination();
        const CScript script = GetScriptForDestination(*op_dest);
        data.emplace(pwallet->GetName(), PerWallet(script));
        return script;
    }

    void AddBlockHash(const CWallet* pwallet, const std::string& hash_hex) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        const auto it = data.find(pwallet->GetName());
        CHECK_NONFATAL(it != data.end());
        it->second.block_hashes.insert(uint256::FromHex(hash_hex).value());
    }

    void MarkBlockSubmitted(const CWallet* pwallet, const std::string& hash_hex) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        const auto it = data.find(pwallet->GetName());
        if (it == data.end()) {
            return;
        }

        if (it->second.block_hashes.count(uint256::FromHex(hash_hex).value()) > 0) {
            data.erase(it);
        }
    }
};

ReservedKeysForMining g_mining_keys;

} // namespace

RPCHelpMan getauxblock()
{
    return RPCHelpMan{"getauxblock",
                "Creates or submits a merge-mined block.\n"
                "\nWithout arguments, creates a new block and returns information\n"
                "required to merge-mine it. With arguments, submits a solved\n"
                "auxpow for a previously returned block.\n",
                {
                    {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hash of the block to submit"},
                    {"auxpow", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Serialised auxpow found"},
                },
                {
                    RPCResult{"without arguments",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "hash of the created block"},
                            {RPCResult::Type::NUM, "chainid", "chain ID for this block"},
                            {RPCResult::Type::STR_HEX, "previousblockhash", "hash of the previous block"},
                            {RPCResult::Type::NUM, "coinbasevalue", "value of the block's coinbase"},
                            {RPCResult::Type::STR, "bits", "compressed target of the block"},
                            {RPCResult::Type::NUM, "height", "height of the block"},
                            {RPCResult::Type::STR_HEX, "_target", "target in reversed byte order, deprecated"},
                        },
                    },
                    RPCResult{"with arguments",
                        RPCResult::Type::BOOL, "", "whether the submitted block was correct"},
                },
                RPCExamples{
                    HelpExampleCli("getauxblock", "")
                    + HelpExampleCli("getauxblock", "\"hash\" \"serialised auxpow\"")
                    + HelpExampleRpc("getauxblock", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;

    CWallet* const pwallet = wallet.get();
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    LOCK(g_mining_keys.cs);

    WalletContext& wallet_context = EnsureWalletContext(request.context);
    node::NodeContext* node_context = wallet_context.chain ? wallet_context.chain->context() : nullptr;
    if (!node_context) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available");
    }

    JSONRPCRequest node_request = request;
    node_request.context = node_context;

    if (request.params.empty()) {
        const CScript coinbase_script = g_mining_keys.GetCoinbaseScript(pwallet);
        UniValue res = AuxpowMiner::get().createAuxBlock(node_request, coinbase_script);
        g_mining_keys.AddBlockHash(pwallet, res["hash"].get_str());
        return res;
    }

    CHECK_NONFATAL(request.params.size() == 2);
    const std::string& hash = request.params[0].get_str();

    const bool accepted = AuxpowMiner::get().submitAuxBlock(node_request, hash, request.params[1].get_str());
    if (accepted) {
        g_mining_keys.MarkBlockSubmitted(pwallet, hash);
    }

    return accepted;
},
    };
}

} // namespace wallet
