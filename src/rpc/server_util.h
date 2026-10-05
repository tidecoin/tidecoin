// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_SERVER_UTIL_H
#define BITCOIN_RPC_SERVER_UTIL_H

#include <consensus/params.h>
#include <rpc/util.h>

#include <any>

class AddrMan;
class ArgsManager;
class CBlockIndex;
class CBlockPolicyEstimator;
class CConnman;
class CTxMemPool;
class ChainstateManager;
class PeerManager;
class BanMan;
namespace node {
struct NodeContext;
} // namespace node
namespace interfaces {
class Mining;
class WalletDescriptorExpansion;
} // namespace interfaces

node::NodeContext& EnsureAnyNodeContext(const std::any& context);
CTxMemPool& EnsureMemPool(const node::NodeContext& node);
CTxMemPool& EnsureAnyMemPool(const std::any& context);
BanMan& EnsureBanman(const node::NodeContext& node);
BanMan& EnsureAnyBanman(const std::any& context);
ArgsManager& EnsureArgsman(const node::NodeContext& node);
ArgsManager& EnsureAnyArgsman(const std::any& context);
ChainstateManager& EnsureChainman(const node::NodeContext& node);
ChainstateManager& EnsureAnyChainman(const std::any& context);
CBlockPolicyEstimator& EnsureFeeEstimator(const node::NodeContext& node);
CBlockPolicyEstimator& EnsureAnyFeeEstimator(const std::any& context);
CConnman& EnsureConnman(const node::NodeContext& node);
interfaces::Mining& EnsureMining(const node::NodeContext& node);
PeerManager& EnsurePeerman(const node::NodeContext& node);
AddrMan& EnsureAddrman(const node::NodeContext& node);
AddrMan& EnsureAnyAddrman(const std::any& context);

/** Public expansion for existing node RPCs. Wallet access is lazy and explicit;
 * self-contained descriptors retain their ordinary wallet-independent behavior.
 */
class RPCDescriptorResolver
{
    const JSONRPCRequest& m_request;
    std::function<void()> m_interruption_point;
    std::unique_ptr<interfaces::WalletDescriptorExpansion> m_wallet_expansion;

public:
    explicit RPCDescriptorResolver(const JSONRPCRequest& request, std::function<void()> interruption_point = {});
    ~RPCDescriptorResolver();
    bool Expand(const Descriptor& descriptor, int32_t index, const SigningProvider& provider, std::vector<CScript>& scripts, FlatSigningProvider& out);
    DescriptorExpandFn GetExpander();
    void Finish();
};

/** Return an empty block index on top of the tip, with height, time and nBits set */
void NextEmptyBlockIndex(CBlockIndex& tip, const Consensus::Params& consensusParams, CBlockIndex& next_index);

#endif // BITCOIN_RPC_SERVER_UTIL_H
