// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <external_signer.h>
#include <node/types.h>
#include <policy/policy.h>
#include <wallet/external_signer_scriptpubkeyman.h>

#include <iostream>
#include <key_io.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <univalue.h>
#include <utility>
#include <vector>

using common::PSBTError;

namespace wallet {
bool ExternalSignerScriptPubKeyMan::SetupDescriptor(WalletBatch& batch, std::unique_ptr<Descriptor> desc)
{
    LOCK(cs_desc_man);
    assert(m_storage.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    assert(m_storage.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));

    int64_t creation_time = GetTime();

    // Make the descriptor
    WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
    m_wallet_descriptor = w_desc;

    // Store the descriptor
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // TopUp
    if (!TopUpWithDB(batch)) return false;

    m_storage.UnsetBlankWalletFlag(batch);
    return true;
}

 util::Result<ExternalSigner> ExternalSignerScriptPubKeyMan::GetExternalSigner() {
    const std::string command = gArgs.GetArg("-signer", "");
    if (command == "") return util::Error{Untranslated("restart tidecoind with -signer=<cmd>")};
    std::vector<ExternalSigner> signers;
    ExternalSigner::Enumerate(command, signers, Params().GetChainTypeString());
    if (signers.empty()) return util::Error{Untranslated("No external signers found")};
    // TODO: add fingerprint argument instead of failing in case of multiple signers.
    if (signers.size() > 1) return util::Error{Untranslated("More than one external signer found. Please connect only one at a time.")};
    return signers[0];
}

bool ExternalSignerScriptPubKeyMan::MatchesSigner(const ExternalSigner& signer) const
{
    const auto response = signer.GetDescriptors(0);
    if (!response.isObject()) return false;
    bool found{false};
    for (const char* branch : {"receive", "internal"}) {
        const auto& values = response.find_value(branch);
        if (!values.isArray()) return false;
        for (const auto& value : values.getValues()) {
            if (!value.isStr()) return false;
            FlatSigningProvider keys;
            std::string error;
            auto descriptors = Parse(value.get_str(), keys, error, false);
            if (descriptors.empty() || !keys.keys.empty()) return false;
            for (const auto& descriptor : descriptors) {
                if (descriptor->IsRange() || !descriptor->GetPQHDKeyPaths().empty()) return false;
                found |= DescriptorID(*descriptor) == GetID();
            }
        }
    }
    return found;
}

util::Result<void> ExternalSignerScriptPubKeyMan::DisplayAddress(const CTxDestination& dest, const ExternalSigner &signer) const
{
    if (!MatchesSigner(signer)) return util::Error{_("External signer does not provide the enrolled public descriptor")};
    // Display the fully resolved public script, never a seed identifier alone.
    const CScript& scriptPubKey = GetScriptForDestination(dest);
    auto provider = GetSolvingProvider(scriptPubKey);
    if (!provider) return util::Error{_("Address solving data is unavailable")};
    auto descriptor = InferDescriptor(scriptPubKey, *provider);

    const UniValue& result = signer.DisplayAddress(descriptor->ToString());

    const UniValue& error = result.find_value("error");
    if (error.isStr()) return util::Error{strprintf(_("Signer returned error: %s"), error.getValStr())};

    const UniValue& ret_address = result.find_value("address");
    if (!ret_address.isStr()) return util::Error{_("Signer did not echo address")};

    if (ret_address.getValStr() != EncodeDestination(dest)) {
        return util::Error{strprintf(_("Signer echoed unexpected address %s"), ret_address.getValStr())};
    }

    return util::Result<void>();
}

std::optional<PSBTError> ExternalSignerScriptPubKeyMan::CheckPSBTSigningIntent(const PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, int mode, unsigned int flags, std::vector<common::PSBTInputError>* input_errors) const
{
    std::optional<PSBTError> result;
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        if (PSBTInputSignedAndVerified(psbt, i, &txdata, flags)) continue;
        CTxOut utxo;
        if (!psbt.GetInputUTXO(utxo, i) || !GetSolvingProvider(utxo.scriptPubKey)) continue;
        const auto& input = psbt.inputs[i];
        std::optional<PSBTError> error;
        if (!PSBTInputHasSigningUTXO(psbt, i, flags)) error = PSBTError::MISSING_NON_WITNESS_UTXO;
        else if (SingleWithoutOutput(mode, i, psbt.tx->vout.size())) error = PSBTError::SINGLE_WITHOUT_OUTPUT;
        else if (!IsSupportedSighash(mode)) error = PSBTError::SIGHASH_UNSUPPORTED;
        else if (input.sighash_type && *input.sighash_type != mode) error = PSBTError::SIGHASH_MISMATCH;
        else for (const auto& [_, sig] : input.partial_sigs) {
            if (sig.second.empty() || sig.second.back() != mode || sig.second.back() != input.sighash_type.value_or(SIGHASH_ALL)) error = PSBTError::SIGHASH_MISMATCH;
        }
        if (error) {
            if (!result) result = error;
            if (input_errors) input_errors->push_back({i, mode, input.sighash_type, *error});
        }
    }
    return result;
}

// If sign is true, transaction must previously have been filled
std::optional<PSBTError> ExternalSignerScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, std::optional<int> sighash_type, bool sign, int* n_signed, bool finalize, bool include_pqhd_origins, std::optional<unsigned int> script_verify_flags, std::vector<common::PSBTInputError>* input_errors) const
{
    if (!sign) {
        return DescriptorScriptPubKeyMan::FillPSBT(psbt, txdata, sighash_type, false, n_signed, finalize, include_pqhd_origins, script_verify_flags);
    }

    const unsigned int effective_flags = script_verify_flags.value_or(STANDARD_SCRIPT_VERIFY_FLAGS);
    sighash_type = sighash_type.value_or(SIGHASH_ALL);
    if (n_signed) *n_signed = 0;
    if (const auto error = DescriptorScriptPubKeyMan::FillPSBT(psbt, txdata, sighash_type, false, nullptr, false, include_pqhd_origins, effective_flags)) return error;
    if (const auto error = CheckPSBTSigningIntent(psbt, txdata, *sighash_type, effective_flags, input_errors)) return error;

    // Do not contact a signer for unrelated managers or already verified inputs.
    bool needs_signer{false};
    std::vector<bool> targets(psbt.inputs.size());
    std::vector<bool> previously_verified(psbt.inputs.size());
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        previously_verified[i] = PSBTInputSignedAndVerified(psbt, i, &txdata, effective_flags);
        if (previously_verified[i]) continue;
        const auto& input = psbt.inputs[i];
        CScript script;
        if (input.non_witness_utxo) {
            const auto& prevout = psbt.tx->vin[i].prevout;
            if (prevout.hash != input.non_witness_utxo->GetHash() || prevout.n >= input.non_witness_utxo->vout.size()) return PSBTError::MISSING_INPUTS;
            script = input.non_witness_utxo->vout[prevout.n].scriptPubKey;
        } else if (!input.witness_utxo.IsNull()) {
            script = input.witness_utxo.scriptPubKey;
        }
        targets[i] = static_cast<bool>(GetSolvingProvider(script));
        if (targets[i]) {
            const auto refuse = [&](PSBTError error) -> std::optional<PSBTError> {
                if (input_errors) input_errors->push_back({i, *sighash_type, input.sighash_type, error});
                return error;
            };
            if (SingleWithoutOutput(*sighash_type, i, psbt.tx->vout.size())) return refuse(PSBTError::SINGLE_WITHOUT_OUTPUT);
            if (!IsSupportedSighash(*sighash_type)) return refuse(PSBTError::SIGHASH_UNSUPPORTED);
            if (input.sighash_type && input.sighash_type != sighash_type) return refuse(PSBTError::SIGHASH_MISMATCH);
            for (const auto& [_, sig] : input.partial_sigs) {
                if (sig.second.empty() || sig.second.back() != *sighash_type || sig.second.back() != input.sighash_type.value_or(SIGHASH_ALL)) return refuse(PSBTError::SIGHASH_MISMATCH);
            }
        }
        needs_signer |= targets[i];
    }
    if (!needs_signer) return {};

    auto signer{GetExternalSigner()};
    if (!signer) {
        LogWarning("%s", util::ErrorString(signer).original);
        return PSBTError::EXTERNAL_SIGNER_NOT_FOUND;
    }

    if (!MatchesSigner(*signer)) {
        LogWarning("External signer does not provide the enrolled public descriptor");
        return PSBTError::EXTERNAL_SIGNER_FAILED;
    }
    std::string failure_reason;
    if (!signer->SignTransaction(psbt, failure_reason, effective_flags, &targets, sighash_type)) {
        LogWarning("Failed to sign: %s\n", failure_reason);
        return PSBTError::EXTERNAL_SIGNER_FAILED;
    }
    if (finalize) {
        FinalizePSBT(psbt, effective_flags);
    }
    if (n_signed) {
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            if (!previously_verified[i] && PSBTInputSignedAndVerified(psbt, i, &txdata, effective_flags)) ++*n_signed;
        }
    }
    return {};
}
} // namespace wallet
