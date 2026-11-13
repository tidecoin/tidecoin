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

#include <boost/signals2/connection.hpp>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>

namespace wallet {
namespace {

/**
 * Track a coinbase destination and its issued work for each loaded wallet.
 * Reserve a fresh destination after a matching submission, and forget the
 * reservation on unload without changing any already-issued block templates.
 */
class ReservedKeysForMining
{
private:
    using WalletRef = std::weak_ptr<CWallet>;

    struct PerWallet
    {
        CScript coinbase_script;
        std::set<uint256> block_hashes;
        boost::signals2::scoped_connection unload_connection;

        explicit PerWallet(const CScript& script)
            : coinbase_script(script)
        {
        }

        PerWallet(PerWallet&&) = default;
    };

    // Compare shared ownership, not wallet names or reusable object addresses.
    // Neither the entries nor their unload callbacks keep a wallet alive.
    std::map<WalletRef, PerWallet, std::owner_less<WalletRef>> data GUARDED_BY(cs);

public:
    mutable RecursiveMutex cs;
    ReservedKeysForMining() = default;

    CScript GetCoinbaseScript(const std::shared_ptr<CWallet>& wallet, WalletContext& context) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        CScript script;
        {
            LOCK(wallet->cs_wallet);

            const auto it = data.find(wallet);
            if (it != data.end()) {
                if (wallet->IsMine(it->second.coinbase_script)) {
                    return it->second.coinbase_script;
                }
                data.erase(it);
            }

            ReserveDestination rdest(wallet.get(), wallet->m_default_address_type);
            auto op_dest = rdest.GetReservedDestination(false);
            if (!op_dest) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,
                                   "Error: Keypool ran out, please call keypoolrefill first");
            }

            rdest.KeepDestination();
            script = GetScriptForDestination(*op_dest);
        }

        // Register before RemoveWallet can remove the wallet and emit NotifyUnload.
        // Do not take wallets_mutex while holding cs_wallet. RemoveWallet emits
        // the signal with neither of those locks held; its callback waits for cs,
        // so an in-flight getauxblock finishes before its reservation is erased.
        LOCK(context.wallets_mutex);
        if (std::find(context.wallets.begin(), context.wallets.end(), wallet) == context.wallets.end()) {
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet was unloaded");
        }
        const WalletRef ref{wallet};
        boost::signals2::scoped_connection unload_connection{wallet->NotifyUnload.connect([this, ref] {
            LOCK(cs);
            data.erase(ref);
        })};
        const auto [it, inserted] = data.try_emplace(ref, script);
        CHECK_NONFATAL(inserted);
        it->second.unload_connection = std::move(unload_connection);
        return script;
    }

    void AddBlockHash(const std::shared_ptr<CWallet>& wallet, const std::string& hash_hex) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        const auto it = data.find(wallet);
        CHECK_NONFATAL(it != data.end());
        it->second.block_hashes.insert(uint256::FromHex(hash_hex).value());
    }

    void MarkBlockSubmitted(const std::shared_ptr<CWallet>& wallet, const std::string& hash_hex) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        const auto it = data.find(wallet);
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
                "required to merge-mine it. With both hash and auxpow, submits a solved\n"
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
    if (!request.params.empty() && (request.params.size() != 2 || request.params[0].isNull() || request.params[1].isNull())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getauxblock requires either no arguments or both hash and auxpow.");
    }
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
        const CScript coinbase_script = g_mining_keys.GetCoinbaseScript(wallet, wallet_context);
        UniValue res = AuxpowMiner::get().createAuxBlock(node_request, coinbase_script);
        g_mining_keys.AddBlockHash(wallet, res["hash"].get_str());
        return res;
    }

    const std::string& hash = request.params[0].get_str();

    const bool accepted = AuxpowMiner::get().submitAuxBlock(node_request, hash, request.params[1].get_str());
    if (accepted) {
        g_mining_keys.MarkBlockSubmitted(wallet, hash);
    }

    return accepted;
},
    };
}

} // namespace wallet
