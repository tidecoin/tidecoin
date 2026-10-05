// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/rpc/util.h>

#include <common/url.h>
#include <interfaces/wallet.h>
#include <pq/pq_scheme.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <util/any.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/context.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <string_view>
#include <univalue.h>

namespace wallet {
static const std::string WALLET_ENDPOINT_BASE = "/wallet/";
const std::string HELP_REQUIRING_PASSPHRASE{"\nRequires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.\n"};

bool GetAvoidReuseFlag(const CWallet& wallet, const UniValue& param) {
    bool can_avoid_reuse = wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    bool avoid_reuse = param.isNull() ? can_avoid_reuse : param.get_bool();

    if (avoid_reuse && !can_avoid_reuse) {
        throw JSONRPCError(RPC_WALLET_ERROR, "wallet does not have the \"avoid reuse\" feature enabled");
    }

    return avoid_reuse;
}

std::string EnsureUniqueWalletName(const JSONRPCRequest& request, const std::string* wallet_name)
{
    std::string endpoint_wallet;
    if (GetWalletNameFromJSONRPCRequest(request, endpoint_wallet)) {
        // wallet endpoint was used
        if (wallet_name && *wallet_name != endpoint_wallet) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "The RPC endpoint wallet and the wallet name parameter specify different wallets");
        }
        return endpoint_wallet;
    }

    // Not a wallet endpoint; parameter must be provided
    if (!wallet_name) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Either the RPC endpoint wallet or the wallet name parameter must be provided");
    }

    return *wallet_name;
}

bool GetWalletNameFromJSONRPCRequest(const JSONRPCRequest& request, std::string& wallet_name)
{
    if (request.URI.starts_with(WALLET_ENDPOINT_BASE)) {
        // wallet endpoint was used
        wallet_name = UrlDecode(std::string_view{request.URI}.substr(WALLET_ENDPOINT_BASE.size()));
        return true;
    }
    return false;
}

std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    CHECK_NONFATAL(request.mode == JSONRPCRequest::EXECUTE);
    WalletContext& context = EnsureWalletContext(request.context);

    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        std::shared_ptr<CWallet> pwallet = GetWallet(context, wallet_name);
        if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
        return pwallet;
    }

    size_t count{0};
    auto wallet = GetDefaultWallet(context, count);
    if (wallet) return wallet;

    if (count == 0) {
        throw JSONRPCError(
            RPC_WALLET_NOT_FOUND, "No wallet is loaded. Load a wallet using loadwallet or create a new one with createwallet. (Note: A default wallet is no longer automatically created)");
    }
    throw JSONRPCError(RPC_WALLET_NOT_SPECIFIED,
        "Multiple wallets are loaded. Please select which wallet to use by requesting the RPC through the /wallet/<walletname> URI path.");
}

namespace {
class WalletDescriptorExpansionImpl final : public interfaces::WalletDescriptorExpansion
{
    std::shared_ptr<CWallet> m_wallet;
    WalletDescriptorExpansionReserver m_reservation;

    void CheckInterrupted() const
    {
        if (m_wallet->IsDescriptorExpansionAborted() || m_wallet->chain().shutdownRequested()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Descriptor expansion interrupted; no partial result returned");
        }
    }

public:
    explicit WalletDescriptorExpansionImpl(std::shared_ptr<CWallet> wallet)
        : m_wallet(std::move(wallet)), m_reservation(*m_wallet)
    {
        if (!m_reservation.reserve()) throw JSONRPCError(RPC_WALLET_ERROR, "Descriptor expansion already in progress for this wallet");
    }

    void expand(const Descriptor& descriptor, int32_t index, std::vector<CScript>& scripts, FlatSigningProvider& out) override
    {
        CheckInterrupted();
        FlatSigningProvider public_data;
        std::vector<CScript> expanded;
        {
            LOCK(m_wallet->cs_wallet);
            CheckInterrupted();
            // Match canonical public descriptors, never arbitrary paths referring
            // to a wallet seed. Recheck registration while holding the wallet lock.
            const DescriptorScriptPubKeyMan* manager{nullptr};
            const auto public_descriptor = descriptor.ToString();
            for (auto* spkm : m_wallet->GetAllScriptPubKeyMans()) {
                const auto* candidate = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
                if (!candidate) continue;
                LOCK(candidate->cs_desc_man);
                if (candidate->GetPublicDescriptor()->ToString() == public_descriptor) {
                    manager = candidate;
                    break;
                }
            }
            if (!manager) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "PQHD descriptor is not registered in this wallet. Use a public descriptor from listdescriptors.");
            if (!manager->IsCacheUsable()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "PQHD cache does not match wallet seed; wallet may be corrupted");
            }
            bool cached;
            {
                LOCK(manager->cs_desc_man);
                cached = manager->ExpandPublicFromCache(index, expanded, public_data);
            }
            if (!cached) {
                for (const auto& seed_id : descriptor.GetPQHDSeedIDs()) {
                    if (!m_wallet->HavePQHDSeed(seed_id)) throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Index %d is not cached and its PQHD seed is not present in this wallet", index));
                }
                if (m_wallet->IsLocked() || (m_wallet->IsCrypted() && m_wallet->nRelockTime > 0 && m_wallet->nRelockTime <= GetTime())) {
                    throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, strprintf("Index %d is not cached. Unlock this wallet to derive it", index));
                }
                struct SeedProvider final : SigningProvider {
                    const CWallet& wallet;
                    explicit SeedProvider(const CWallet& w) : wallet(w) {}
                    std::optional<pqhd::SecureSeed32> GetPQHDSeed(const uint256& id) const override { return wallet.GetPQHDSeed(id); }
                } provider{*m_wallet};
                // Discard any partial cache expansion before fresh derivation.
                expanded.clear();
                public_data = FlatSigningProvider{};
                if (!descriptor.Expand(index, provider, expanded, public_data)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Public descriptor derivation failed at index %d", index));
                }
            }
        }
        CheckInterrupted();
        CHECK_NONFATAL(public_data.keys.empty());
        scripts = std::move(expanded);
        out.Merge(std::move(public_data));
    }

    void finish() override
    {
        CheckInterrupted();
        if (!m_reservation.complete()) throw JSONRPCError(RPC_MISC_ERROR, "Descriptor expansion interrupted; no partial result returned");
    }
};
} // namespace

std::unique_ptr<interfaces::WalletDescriptorExpansion> MakeWalletDescriptorExpansion(WalletContext& context, const std::string& wallet_name)
{
    auto wallet = GetWallet(context, wallet_name);
    if (!wallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
    return MakeWalletDescriptorExpansion(std::move(wallet));
}

std::unique_ptr<interfaces::WalletDescriptorExpansion> MakeWalletDescriptorExpansion(std::shared_ptr<CWallet> wallet)
{
    return std::make_unique<WalletDescriptorExpansionImpl>(std::move(wallet));
}

void EnsureWalletIsUnlocked(const CWallet& wallet)
{
    if (wallet.IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

WalletContext& EnsureWalletContext(const std::any& context)
{
    auto wallet_context = util::AnyPtr<WalletContext>(context);
    if (!wallet_context) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet context not found");
    }
    return *wallet_context;
}

std::string LabelFromValue(const UniValue& value)
{
    static const std::string empty_string;
    if (value.isNull()) return empty_string;

    const std::string& label{value.get_str()};
    if (label == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, "Invalid label name");
    return label;
}

std::optional<uint8_t> ParsePQSchemePrefix(const UniValue& value)
{
    if (value.isNull()) return std::nullopt;

    std::optional<uint64_t> scheme;
    if (value.isNum()) {
        const auto numeric = value.getInt<int64_t>();
        if (numeric < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scheme id must be between 0 and 255");
        }
        scheme = static_cast<uint64_t>(numeric);
    } else if (value.isStr()) {
        std::string input = value.get_str();
        std::string normalized;
        normalized.reserve(input.size());
        for (char ch : input) {
            if (ch == '-' || ch == '_' || ch == ' ') continue;
            normalized.push_back(ToLower(ch));
        }
        if (auto parsed = ToIntegral<uint64_t>(normalized)) {
            scheme = *parsed;
        } else if (normalized == "falcon512") {
            scheme = static_cast<uint64_t>(pq::SchemeId::FALCON_512);
        } else if (normalized == "falcon1024") {
            scheme = static_cast<uint64_t>(pq::SchemeId::FALCON_1024);
        } else if (normalized == "mldsa44") {
            scheme = static_cast<uint64_t>(pq::SchemeId::MLDSA_44);
        } else if (normalized == "mldsa65") {
            scheme = static_cast<uint64_t>(pq::SchemeId::MLDSA_65);
        } else if (normalized == "mldsa87") {
            scheme = static_cast<uint64_t>(pq::SchemeId::MLDSA_87);
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Scheme id must be a string or number");
    }

    if (!scheme || *scheme > std::numeric_limits<uint8_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scheme id");
    }

    const uint8_t prefix = static_cast<uint8_t>(*scheme);
    if (!pq::SchemeFromPrefix(prefix)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scheme id");
    }

    return prefix;
}

void PushParentDescriptors(const CWallet& wallet, const CScript& script_pubkey, UniValue& entry)
{
    UniValue parent_descs(UniValue::VARR);
    const auto descs{WITH_LOCK(wallet.cs_wallet, return wallet.GetWalletDescriptors(script_pubkey))};
    for (const auto& desc: descs) {
        std::string desc_str;
        FlatSigningProvider dummy_provider;
        if (!CHECK_NONFATAL(desc.descriptor->ToNormalizedString(dummy_provider, desc_str, &desc.cache))) continue;
        parent_descs.push_back(desc_str);
    }
    entry.pushKV("parent_descs", std::move(parent_descs));
}

void HandleWalletError(const std::shared_ptr<CWallet> wallet, DatabaseStatus& status, bilingual_str& error)
{
    if (!wallet) {
        // Map bad format to not found, since bad format is returned when the
        // wallet directory exists, but doesn't contain a data file.
        RPCErrorCode code = RPC_WALLET_ERROR;
        switch (status) {
            case DatabaseStatus::FAILED_NOT_FOUND:
            case DatabaseStatus::FAILED_BAD_FORMAT:
            case DatabaseStatus::FAILED_LEGACY_DISABLED:
                code = RPC_WALLET_NOT_FOUND;
                break;
            case DatabaseStatus::FAILED_ALREADY_LOADED:
                code = RPC_WALLET_ALREADY_LOADED;
                break;
            case DatabaseStatus::FAILED_ALREADY_EXISTS:
                code = RPC_WALLET_ALREADY_EXISTS;
                break;
            case DatabaseStatus::FAILED_INVALID_BACKUP_FILE:
                code = RPC_INVALID_PARAMETER;
                break;
            default: // RPC_WALLET_ERROR is returned for all other cases.
                break;
        }
        throw JSONRPCError(code, error.original);
    }
}

void AppendLastProcessedBlock(UniValue& entry, const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    UniValue lastprocessedblock{UniValue::VOBJ};
    lastprocessedblock.pushKV("hash", wallet.GetLastBlockHash().GetHex());
    lastprocessedblock.pushKV("height", wallet.GetLastBlockHeight());
    entry.pushKV("lastprocessedblock", std::move(lastprocessedblock));
}

} // namespace wallet
