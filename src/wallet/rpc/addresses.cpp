// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tidecoin-build-config.h> // IWYU pragma: keep

#include <core_io.h>
#include <key_io.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/solver.h>
#include <util/string.h>
#include <util/translation.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <univalue.h>

namespace wallet {
static CKey GetSingleKeyFromProvider(const SigningProvider& provider, const CTxDestination& dest)
{
    const CKeyID keyid = GetKeyForDestination(provider, dest);
    if (keyid.IsNull()) {
        // Some descriptor/provider paths don't expose enough script metadata for
        // GetKeyForDestination (e.g. nested script wrappers), but still carry a
        // single concrete private key. Export that deterministic single-key case.
        if (const auto* flat_provider = dynamic_cast<const FlatSigningProvider*>(&provider)) {
            if (flat_provider->keys.size() == 1) {
                return flat_provider->keys.begin()->second;
            }
        }
        return {};
    }
    CKey key;
    if (!provider.GetKey(keyid, key)) {
        return {};
    }
    return key;
}

static std::string WritePQHDPath(const std::vector<uint32_t>& path)
{
    std::string out = "m";
    for (const uint32_t elem : path) {
        out += "/";
        out += util::ToString(elem & 0x7FFFFFFFU);
        if ((elem & 0x80000000U) != 0) {
            out += "h";
        }
    }
    return out;
}

RPCHelpMan dumpprivkey()
{
    return RPCHelpMan{
        "dumpprivkey",
        "Returns the private key corresponding to an address or wallet descriptor.\n"
        "Only per-address child keys are exported (no master seed export).\n",
        {
            {"target", RPCArg::Type::STR, RPCArg::Optional::NO, "The address or descriptor."},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"format", RPCArg::Type::STR, RPCArg::Default{"privonly"}, "Output format: privonly or legacy (Falcon-512 only)."},
                {"index", RPCArg::Type::NUM, RPCArg::Default{0}, "Index for ranged descriptors."},
            }},
        },
        RPCResult{RPCResult::Type::STR, "wif", "The private key encoded in WIF"},
        RPCExamples{
            HelpExampleCli("dumpprivkey", "\"tbc1q...\"") +
            HelpExampleCliNamed("dumpprivkey", {{"target", "\"tbc1q...\""}, {"format", "\"legacy\""}}) +
            HelpExampleCliNamed("dumpprivkey", {{"target", "\"wpkh(pqhd(...)/.../*h)#checksum\""}, {"index", "0"}})
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            EnsureWalletIsUnlocked(*pwallet);

            const UniValue options = request.params.size() > 1 ? request.params[1] : UniValue::VNULL;
            const std::string format = options.isObject() && options.exists("format") ? options["format"].get_str() : "privonly";
            const int64_t index = options.isObject() && options.exists("index") ? options["index"].getInt<int64_t>() : 0;

            if (format != "privonly" && format != "legacy") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "format must be \"privonly\" or \"legacy\"");
            }

            const std::string target = request.params[0].get_str();
            std::string error;
            const CTxDestination dest = DecodeDestination(target, error);
            if (IsValidDestination(dest)) {
                const CScript script = GetScriptForDestination(dest);
                const auto spk_mans = pwallet->GetScriptPubKeyMans(script);
                std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(script);
                CKey key;
                if (provider) {
                    key = GetSingleKeyFromProvider(*provider, dest);
                    if (!key.IsValid()) {
                        // Legacy solving providers intentionally omit private key access.
                        // Resolve via the owning legacy SPKM when destination->keyid is known.
                        const CKeyID keyid = GetKeyForDestination(*provider, dest);
                        if (!keyid.IsNull()) {
                            for (ScriptPubKeyMan* spk_man : spk_mans) {
                                auto* legacy_spk_man = dynamic_cast<LegacyDataSPKM*>(spk_man);
                                if (!legacy_spk_man) continue;
                                if (legacy_spk_man->GetKey(keyid, key) && key.IsValid()) break;
                            }
                        }
                    }
                }
                if (!key.IsValid()) {
                    for (ScriptPubKeyMan* spk_man : spk_mans) {
                        auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
                        if (!desc_spk_man) continue;
                        std::unique_ptr<FlatSigningProvider> desc_provider;
                        {
                            LOCK(desc_spk_man->cs_desc_man);
                            desc_provider = desc_spk_man->GetSigningProviderForScript(script, /*include_private=*/true);
                        }
                        if (!desc_provider) continue;
                        if (desc_provider->keys.size() == 1) {
                            key = desc_provider->keys.begin()->second;
                        } else {
                            key = GetSingleKeyFromProvider(*desc_provider, dest);
                        }
                        if (key.IsValid()) break;
                    }
                }
                if (!key.IsValid()) {
                    if (!provider && spk_mans.empty()) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available (address not found in wallet)");
                    }
                    throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available (watch-only or locked)");
                }
                if (format == "legacy") {
                    const std::string legacy = EncodeSecretLegacy(key);
                    if (legacy.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "legacy format is only supported for Falcon-512");
                    }
                    return legacy;
                }
                return EncodeSecret(key);
            }

            FlatSigningProvider parse_keys;
            auto descs = Parse(target, parse_keys, error, /* require_checksum */ true);
            if (descs.empty()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
            }
            if (descs.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Multipath descriptors are not supported");
            }
            auto& desc = descs.at(0);
            if (desc->IsRange() && index < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "index must be non-negative for ranged descriptors");
            }
            if (!desc->IsRange() && index != 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "index must be 0 for non-ranged descriptors");
            }

            const uint256 desc_id = DescriptorID(*desc);
            auto* spk_man = pwallet->GetScriptPubKeyMan(desc_id);
            auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
            if (!desc_spk_man) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Descriptor not found in wallet");
            }
            std::unique_ptr<FlatSigningProvider> keys;
            {
                LOCK(desc_spk_man->cs_desc_man);
                keys = desc_spk_man->GetSigningProviderForIndex(static_cast<int32_t>(index), /*include_private=*/true);
            }
            if (!keys || keys->keys.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available for descriptor");
            }
            if (keys->keys.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor does not contain a single key");
            }
            const CKey key = keys->keys.begin()->second;
            if (!key.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available for descriptor");
            }
            if (format == "legacy") {
                const std::string legacy = EncodeSecretLegacy(key);
                if (legacy.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "legacy format is only supported for Falcon-512");
                }
                return legacy;
            }
            return EncodeSecret(key);
        },
    };
}

RPCHelpMan getnewaddress()
{
    return RPCHelpMan{
        "getnewaddress",
        "Returns a new Tidecoin address for receiving payments.\n"
                "If 'label' is specified, it is added to the address book \n"
                "so payments received with the address will be associated with 'label'.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "The label name for the address to be linked to. It can also be set to the empty string \"\" to represent the default label. The label does not need to exist, it will be created if there is no label by the given name."},
                    {"address_type", RPCArg::Type::STR, RPCArg::DefaultHint{"set by -addresstype"}, "The address type to use. Options are " + FormatAllOutputTypes() + "."},
                    {"scheme", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional PQ scheme override (name or numeric prefix)."},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The new Tidecoin address"
                },
                RPCExamples{
                    HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    if (!pwallet->CanGetAddresses()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    // Parse the label first so we don't generate a key if there's an error
    const std::string label{LabelFromValue(request.params[0])};

    OutputType output_type = pwallet->m_default_address_type;
    if (!request.params[1].isNull()) {
        std::optional<OutputType> parsed = ParseOutputType(request.params[1].get_str());
        if (!parsed) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[1].get_str()));
        }
        output_type = parsed.value();
    }

    const std::optional<uint8_t> scheme_override = ParsePQSchemePrefix(request.params[2]);
    auto op_dest = pwallet->GetNewDestination(output_type, label, scheme_override);
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
    }

    return EncodeDestination(*op_dest);
},
    };
}

RPCHelpMan getrawchangeaddress()
{
    return RPCHelpMan{
        "getrawchangeaddress",
        "Returns a new Tidecoin address, for receiving change.\n"
                "This is for use with raw transactions, NOT normal use.\n",
                {
                    {"address_type", RPCArg::Type::STR, RPCArg::DefaultHint{"set by -changetype"}, "The address type to use. Options are " + FormatAllOutputTypes() + "."},
                    {"scheme", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional PQ scheme override (name or numeric prefix)."},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The address"
                },
                RPCExamples{
                    HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    if (!pwallet->CanGetAddresses(true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    OutputType output_type = pwallet->m_default_change_type.value_or(pwallet->m_default_address_type);
    if (!request.params[0].isNull()) {
        std::optional<OutputType> parsed = ParseOutputType(request.params[0].get_str());
        if (!parsed) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[0].get_str()));
        }
        output_type = parsed.value();
    }

    const std::optional<uint8_t> scheme_override = ParsePQSchemePrefix(request.params[1]);
    auto op_dest = pwallet->GetNewChangeDestination(output_type, scheme_override);
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
    }
    return EncodeDestination(*op_dest);
},
    };
}


RPCHelpMan setlabel()
{
    return RPCHelpMan{
        "setlabel",
        "Sets the label associated with the given address.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Tidecoin address to be associated with a label."},
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The label to assign to the address."},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("setlabel", "\"" + EXAMPLE_ADDRESS[0] + "\" \"tabby\"")
            + HelpExampleRpc("setlabel", "\"" + EXAMPLE_ADDRESS[0] + "\", \"tabby\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Tidecoin address");
    }

    const std::string label{LabelFromValue(request.params[1])};

    if (pwallet->IsMine(dest)) {
        pwallet->SetAddressBook(dest, label, AddressPurpose::RECEIVE);
    } else {
        pwallet->SetAddressBook(dest, label, AddressPurpose::SEND);
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan listaddressgroupings()
{
    return RPCHelpMan{
        "listaddressgroupings",
        "Lists groups of addresses which have had their common ownership\n"
                "made public by common use as inputs or as the resulting change\n"
                "in past transactions\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::ARR, "", "",
                        {
                            {RPCResult::Type::ARR_FIXED, "", "",
                            {
                                {RPCResult::Type::STR, "address", "The Tidecoin address"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR, "label", /*optional=*/true, "The label"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    std::map<CTxDestination, CAmount> balances = GetAddressBalances(*pwallet);
    for (const std::set<CTxDestination>& grouping : GetAddressGroupings(*pwallet)) {
        UniValue jsonGrouping(UniValue::VARR);
        for (const CTxDestination& address : grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(EncodeDestination(address));
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
                if (address_book_entry) {
                    addressInfo.push_back(address_book_entry->GetLabel());
                }
            }
            jsonGrouping.push_back(std::move(addressInfo));
        }
        jsonGroupings.push_back(std::move(jsonGrouping));
    }
    return jsonGroupings;
},
    };
}

RPCHelpMan keypoolrefill()
{
    return RPCHelpMan{"keypoolrefill",
                "Refills each descriptor keypool in the wallet up to the specified number of new keys.\n"
                "By default, descriptor wallets have 4 active ranged descriptors (" + FormatAllOutputTypes() + "), each with " + util::ToString(DEFAULT_KEYPOOL_SIZE) + " entries.\n" +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"newsize", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%u, or as set by -keypool", DEFAULT_KEYPOOL_SIZE)}, "The new keypool size"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (!request.params[0].isNull()) {
        if (request.params[0].getInt<int>() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].getInt<int>();
    }

    EnsureWalletIsUnlocked(*pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }
    pwallet->RefreshAllTXOs();

    return UniValue::VNULL;
},
    };
}

class DescribeWalletAddressVisitor
{
public:
    const SigningProvider * const provider;

    // NOLINTNEXTLINE(misc-no-recursion)
    void ProcessSubScript(const CScript& subscript, UniValue& obj) const
    {
        // Always present: script type and redeemscript
        std::vector<std::vector<unsigned char>> solutions_data;
        TxoutType which_type = Solver(subscript, solutions_data);
        obj.pushKV("script", GetTxnOutputType(which_type));
        obj.pushKV("hex", HexStr(subscript));

        CTxDestination embedded;
        if (ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            UniValue subobj(UniValue::VOBJ);
            UniValue detail = DescribeAddress(embedded);
            subobj.pushKVs(std::move(detail));
            UniValue wallet_detail = std::visit(*this, embedded);
            subobj.pushKVs(std::move(wallet_detail));
            subobj.pushKV("address", EncodeDestination(embedded));
            subobj.pushKV("scriptPubKey", HexStr(subscript));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.pushKV("pubkey", subobj["pubkey"]);
            obj.pushKV("embedded", std::move(subobj));
        } else if (which_type == TxoutType::MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            obj.pushKV("sigsrequired", solutions_data[0][0]);
            UniValue pubkeys(UniValue::VARR);
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                pubkeys.push_back(HexStr(key));
            }
            obj.pushKV("pubkeys", std::move(pubkeys));
        }
    }

    explicit DescribeWalletAddressVisitor(const SigningProvider* _provider) : provider(_provider) {}

    UniValue operator()(const CNoDestination& dest) const { return UniValue(UniValue::VOBJ); }
    UniValue operator()(const PubKeyDestination& dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const PKHash& pkhash) const
    {
        CKeyID keyID{ToKeyID(pkhash)};
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        if (provider && provider->GetPubKey(keyID, vchPubKey)) {
            obj.pushKV("pubkey", HexStr(vchPubKey));
        }
        return obj;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    UniValue operator()(const ScriptHash& scripthash) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        if (provider && provider->GetCScript(ToScriptID(scripthash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pubkey;
        if (provider && provider->GetPubKey(ToKeyID(id), pubkey)) {
            obj.pushKV("pubkey", HexStr(pubkey));
        }
        return obj;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (provider && provider->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    UniValue operator()(const WitnessV1ScriptHash512& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 64).Finalize(hash.begin());
        if (provider && provider->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

};

static UniValue DescribeWalletAddress(const CWallet& wallet, const CTxDestination& dest)
{
    UniValue ret(UniValue::VOBJ);
    UniValue detail = DescribeAddress(dest);
    CScript script = GetScriptForDestination(dest);
    std::unique_ptr<SigningProvider> provider = nullptr;
    provider = wallet.GetSolvingProvider(script);
    ret.pushKVs(std::move(detail));
    ret.pushKVs(std::visit(DescribeWalletAddressVisitor(provider.get()), dest));
    return ret;
}

RPCHelpMan getaddressinfo()
{
    return RPCHelpMan{
        "getaddressinfo",
        "Return information about the given Tidecoin address.\n"
                "Some of the information will only be present if the address is in the active wallet.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Tidecoin address for which to get information."},
                    {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                        {"include_pqhd_origin", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include PQHD seed/path metadata when available."},
                    }},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The Tidecoin address validated."},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The hex-encoded output script generated by the address."},
                        {RPCResult::Type::BOOL, "ismine", "If the address is yours."},
                        {RPCResult::Type::BOOL, "iswatchonly", "(DEPRECATED) Always false."},
                        {RPCResult::Type::BOOL, "solvable", "If we know how to spend coins sent to this address, ignoring the possible lack of private keys."},
                        {RPCResult::Type::STR, "desc", /*optional=*/true, "A descriptor for spending coins sent to this address (only when solvable)."},
                        {RPCResult::Type::STR, "parent_desc", /*optional=*/true, "The descriptor used to derive this address if this is a descriptor wallet"},
                        {RPCResult::Type::BOOL, "isscript", /*optional=*/true, "If the key is a script."},
                        {RPCResult::Type::BOOL, "ischange", "If the address was used for change output."},
                        {RPCResult::Type::BOOL, "iswitness", "If the address is a witness address."},
                        {RPCResult::Type::NUM, "witness_version", /*optional=*/true, "The version number of the witness program."},
                        {RPCResult::Type::STR_HEX, "witness_program", /*optional=*/true, "The hex value of the witness program."},
                        {RPCResult::Type::STR, "script", /*optional=*/true, "The output script type. Only if isscript is true and the redeemscript is known. Possible\n"
                                                                     "types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash,\n"
                            "witness_v0_scripthash."},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The redeemscript for the p2sh address."},
                        {RPCResult::Type::ARR, "pubkeys", /*optional=*/true, "Array of pubkeys associated with the known redeemscript (only if script is multisig).",
                        {
                            {RPCResult::Type::STR, "pubkey", ""},
                        }},
                        {RPCResult::Type::NUM, "sigsrequired", /*optional=*/true, "The number of signatures required to spend multisig output (only if script is multisig)."},
                        {RPCResult::Type::STR_HEX, "pubkey", /*optional=*/true, "The hex value of the raw public key for single-key addresses (possibly embedded in P2SH or P2WSH)."},
                        {RPCResult::Type::OBJ, "embedded", /*optional=*/true, "Information about the address embedded in P2SH or P2WSH, if relevant and known.",
                        {
                            {RPCResult::Type::ELISION, "", "Includes all getaddressinfo output fields for the embedded address, excluding metadata (timestamp, pqhd_seedid, pqhd_path)\n"
                            "and relation to the wallet (ismine)."},
                        }},
                        {RPCResult::Type::NUM_TIME, "timestamp", /*optional=*/true, "The creation time of the key, if available, expressed in " + UNIX_EPOCH_TIME + "."},
                        {RPCResult::Type::STR_HEX, "pqhd_seedid", /*optional=*/true, "The PQHD SeedID32 for descriptor-derived addresses, when available."},
                        {RPCResult::Type::STR, "pqhd_path", /*optional=*/true, "The PQHD derivation path for descriptor-derived addresses, when available."},
                        {RPCResult::Type::ARR, "labels", "Array of labels associated with the address. Currently limited to one label but returned\n"
                            "as an array to keep the API stable if multiple labels are enabled in the future.",
                        {
                            {RPCResult::Type::STR, "label name", "Label name (defaults to \"\")."},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddressinfo", "\"" + EXAMPLE_ADDRESS[0] + "\"") +
                    HelpExampleCliNamed("getaddressinfo", {{"address", "\"" + EXAMPLE_ADDRESS[0] + "\""}, {"include_pqhd_origin", "false"}}) +
                    HelpExampleRpc("getaddressinfo", "\"" + EXAMPLE_ADDRESS[0] + "\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::string error_msg;
    CTxDestination dest = DecodeDestination(request.params[0].get_str(), error_msg);
    const UniValue options = request.params[1].isObject() ? request.params[1] : UniValue::VOBJ;
    const bool include_pqhd_origin = options.exists("include_pqhd_origin") ? options["include_pqhd_origin"].get_bool() : true;

    // Make sure the destination is valid
    if (!IsValidDestination(dest)) {
        // Set generic error message in case 'DecodeDestination' didn't set it
        if (error_msg.empty()) error_msg = "Invalid address";

        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error_msg);
    }

    UniValue ret(UniValue::VOBJ);

    std::string currentAddress = EncodeDestination(dest);
    ret.pushKV("address", currentAddress);

    CScript scriptPubKey = GetScriptForDestination(dest);
    ret.pushKV("scriptPubKey", HexStr(scriptPubKey));

    std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKey);

    bool mine = pwallet->IsMine(dest);
    ret.pushKV("ismine", mine);

    if (provider) {
        auto inferred = InferDescriptor(scriptPubKey, *provider);
        bool solvable = inferred->IsSolvable();
        ret.pushKV("solvable", solvable);
        if (solvable) {
            ret.pushKV("desc", inferred->ToString());
        }
    } else {
        ret.pushKV("solvable", false);
    }

    const auto& spk_mans = pwallet->GetScriptPubKeyMans(scriptPubKey);
    // In most cases there is only one matching ScriptPubKey manager and we can't resolve ambiguity in a better way
    ScriptPubKeyMan* spk_man{nullptr};
    if (spk_mans.size()) spk_man = *spk_mans.begin();

    DescriptorScriptPubKeyMan* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    if (desc_spk_man) {
        std::string desc_str;
        if (desc_spk_man->GetDescriptorString(desc_str, /*priv=*/false)) {
            ret.pushKV("parent_desc", desc_str);
        }
    }

    ret.pushKV("iswatchonly", false);

    UniValue detail = DescribeWalletAddress(*pwallet, dest);
    ret.pushKVs(std::move(detail));

    ret.pushKV("ischange", ScriptIsChange(*pwallet, scriptPubKey));

    if (spk_man) {
        if (const std::unique_ptr<CKeyMetadata> meta = spk_man->GetMetadata(dest)) {
            ret.pushKV("timestamp", meta->nCreateTime);
            if (include_pqhd_origin && meta->has_pqhd_origin) {
                ret.pushKV("pqhd_seedid", meta->pqhd_seed_id.ToString());
                ret.pushKV("pqhd_path", WritePQHDPath(meta->pqhd_path));
            }
        }
    }

    // Return a `labels` array containing the label associated with the address,
    // equivalent to the `label` field above. Currently only one label can be
    // associated with an address, but we return an array so the API remains
    // stable if we allow multiple labels to be associated with an address in
    // the future.
    UniValue labels(UniValue::VARR);
    const auto* address_book_entry = pwallet->FindAddressBookEntry(dest);
    if (address_book_entry) {
        labels.push_back(address_book_entry->GetLabel());
    }
    ret.pushKV("labels", std::move(labels));

    return ret;
},
    };
}

RPCHelpMan getaddressesbylabel()
{
    return RPCHelpMan{
        "getaddressesbylabel",
        "Returns the list of addresses assigned the specified label.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The label."},
                },
                RPCResult{
                    RPCResult::Type::OBJ_DYN, "", "json object with addresses as keys",
                    {
                        {RPCResult::Type::OBJ, "address", "json object with information about address",
                        {
                            {RPCResult::Type::STR, "purpose", "Purpose of address (\"send\" for sending address, \"receive\" for receiving address)"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddressesbylabel", "\"tabby\"")
            + HelpExampleRpc("getaddressesbylabel", "\"tabby\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    const std::string label{LabelFromValue(request.params[0])};

    // Find all addresses that have the given label
    UniValue ret(UniValue::VOBJ);
    std::set<std::string> addresses;
    pwallet->ForEachAddrBookEntry([&](const CTxDestination& _dest, const std::string& _label, bool _is_change, const std::optional<AddressPurpose>& _purpose) {
        if (_is_change) return;
        if (_label == label) {
            std::string address = EncodeDestination(_dest);
            // CWallet::m_address_book is not expected to contain duplicate
            // address strings, but build a separate set as a precaution just in
            // case it does.
            bool unique = addresses.emplace(address).second;
            CHECK_NONFATAL(unique);
            // UniValue::pushKV checks if the key exists in O(N)
            // and since duplicate addresses are unexpected (checked with
            // std::set in O(log(N))), UniValue::pushKVEnd is used instead,
            // which currently is O(1).
            UniValue value(UniValue::VOBJ);
            value.pushKV("purpose", _purpose ? PurposeToString(*_purpose) : "unknown");
            ret.pushKVEnd(address, std::move(value));
        }
    });

    if (ret.empty()) {
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, std::string("No addresses with label " + label));
    }

    return ret;
},
    };
}

RPCHelpMan listlabels()
{
    return RPCHelpMan{
        "listlabels",
        "Returns the list of all labels, or labels that are assigned to addresses with a specific purpose.\n",
                {
                    {"purpose", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Address purpose to list labels for ('send','receive'). An empty string is the same as not providing this argument."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "label", "Label name"},
                    }
                },
                RPCExamples{
            "\nList all labels\n"
            + HelpExampleCli("listlabels", "") +
            "\nList labels that have receiving addresses\n"
            + HelpExampleCli("listlabels", "receive") +
            "\nList labels that have sending addresses\n"
            + HelpExampleCli("listlabels", "send") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listlabels", "receive")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::optional<AddressPurpose> purpose;
    if (!request.params[0].isNull()) {
        std::string purpose_str = request.params[0].get_str();
        if (!purpose_str.empty()) {
            purpose = PurposeFromString(purpose_str);
            if (!purpose) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid 'purpose' argument, must be a known purpose string, typically 'send', or 'receive'.");
            }
        }
    }

    // Add to a set to sort by label name, then insert into Univalue array
    std::set<std::string> label_set = pwallet->ListAddrBookLabels(purpose);

    UniValue ret(UniValue::VARR);
    for (const std::string& name : label_set) {
        ret.push_back(name);
    }

    return ret;
},
    };
}


#ifdef ENABLE_EXTERNAL_SIGNER
RPCHelpMan walletdisplayaddress()
{
    return RPCHelpMan{
        "walletdisplayaddress",
        "Display address on an external signer for verification.",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Tidecoin address to display"},
        },
        RPCResult{
            RPCResult::Type::OBJ,"","",
            {
                {RPCResult::Type::STR, "address", "The address as confirmed by the signer"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;
            CWallet* const pwallet = wallet.get();

            LOCK(pwallet->cs_wallet);

            CTxDestination dest = DecodeDestination(request.params[0].get_str());

            // Make sure the destination is valid
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }

            util::Result<void> res = pwallet->DisplayAddress(dest);
            if (!res) throw JSONRPCError(RPC_MISC_ERROR, util::ErrorString(res).original);

            UniValue result(UniValue::VOBJ);
            result.pushKV("address", request.params[0].get_str());
            return result;
        }
    };
}
#endif // ENABLE_EXTERNAL_SIGNER
} // namespace wallet
