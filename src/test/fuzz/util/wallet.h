// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_UTIL_WALLET_H
#define BITCOIN_TEST_FUZZ_UTIL_WALLET_H

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <policy/policy.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

namespace wallet {

/**
 * Wraps a descriptor wallet for fuzzing.
 */
struct FuzzedWallet {
    std::shared_ptr<CWallet> wallet;
    FuzzedWallet(interfaces::Chain& chain, const std::string& name, const std::string& seed_insecure)
    {
        (void)seed_insecure;
        wallet = std::make_shared<CWallet>(&chain, name, CreateMockableWalletDatabase());
        {
            LOCK(wallet->cs_wallet);
            wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            auto height{*Assert(chain.getHeight())};
            wallet->SetLastBlockProcessed(height, chain.getBlockHash(height));
            wallet->m_keypool_size = 1; // Avoid timeout in TopUp()
            wallet->SetupDescriptorScriptPubKeyMans();
        }
        assert(wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    }
    CTxDestination GetDestination(FuzzedDataProvider& fuzzed_data_provider)
    {
        if (fuzzed_data_provider.ConsumeBool()) {
            std::vector<OutputType> output_types;
            {
                LOCK(wallet->cs_wallet);
                for (OutputType type : OUTPUT_TYPES) {
                    if (wallet->GetScriptPubKeyMan(type, /*internal=*/false)) output_types.push_back(type);
                }
            }
            if (output_types.empty()) return CNoDestination{};
            return wallet->GetNewDestination(PickValue(fuzzed_data_provider, output_types), "").value_or(CNoDestination{});
        } else {
            std::vector<OutputType> output_types;
            {
                LOCK(wallet->cs_wallet);
                for (OutputType type : OUTPUT_TYPES) {
                    if (wallet->GetScriptPubKeyMan(type, /*internal=*/true)) output_types.push_back(type);
                }
            }
            if (output_types.empty()) return CNoDestination{};
            return wallet->GetNewChangeDestination(PickValue(fuzzed_data_provider, output_types)).value_or(CNoDestination{});
        }
    }
    CScript GetScriptPubKey(FuzzedDataProvider& fuzzed_data_provider) { return GetScriptForDestination(GetDestination(fuzzed_data_provider)); }
};
}

#endif // BITCOIN_TEST_FUZZ_UTIL_WALLET_H
