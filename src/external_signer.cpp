// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <external_signer.h>

#include <chainparams.h>
#include <common/run_command.h>
#include <core_io.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <algorithm>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

ExternalSigner::ExternalSigner(std::vector<std::string> command, const std::string chain, const std::string& fingerprint, const std::string name): m_command(std::move(command)), m_chain(chain), m_fingerprint(fingerprint), m_name(name) {}

std::vector<std::string> ExternalSigner::NetworkArg() const
{
    return {"--chain", m_chain};
}

bool ExternalSigner::Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string chain)
{
    // Call <command> enumerate
    const auto args{ParseCommandArguments(command)};
    if (args.empty()) throw std::invalid_argument("External signer command is empty");
    const UniValue result = RunCommandParseJSON(Cat(args, {"enumerate"}));
    if (!result.isArray()) {
        throw std::runtime_error(strprintf("'%s' received invalid response, expected array of signers", command));
    }
    for (const UniValue& signer : result.getValues()) {
        // Check for error
        const UniValue& error = signer.find_value("error");
        if (!error.isNull()) {
            if (!error.isStr()) {
                throw std::runtime_error(strprintf("'%s' error", command));
            }
            throw std::runtime_error(strprintf("'%s' error: %s", command, error.getValStr()));
        }
        // Check if fingerprint is present
        const UniValue& fingerprint = signer.find_value("fingerprint");
        if (fingerprint.isNull()) {
            throw std::runtime_error(strprintf("'%s' received invalid response, missing signer fingerprint", command));
        }
        const std::string& fingerprintStr{fingerprint.get_str()};
        // Skip duplicate signer
        bool duplicate = false;
        for (const ExternalSigner& signer : signers) {
            if (signer.m_fingerprint.compare(fingerprintStr) == 0) duplicate = true;
        }
        if (duplicate) break;
        std::string name;
        const UniValue& model_field = signer.find_value("model");
        if (model_field.isStr() && model_field.getValStr() != "") {
            name += model_field.getValStr();
        }
        signers.emplace_back(args, chain, fingerprintStr, name);
    }
    return true;
}

UniValue ExternalSigner::DisplayAddress(const std::string& descriptor) const
{
    return RunCommandParseJSON(Cat(Cat(m_command, {"--fingerprint", m_fingerprint}), Cat(NetworkArg(), {"displayaddress", "--desc", descriptor})));
}

UniValue ExternalSigner::GetDescriptors(const int account) const
{
    return RunCommandParseJSON(Cat(Cat(m_command, {"--fingerprint", m_fingerprint}), Cat(NetworkArg(), {"getdescriptors", "--account", strprintf("%d", account)})));
}

bool ExternalSigner::SignTransaction(PartiallySignedTransaction& psbtx, std::string& error, unsigned int script_verify_flags)
{
    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;
    // The wallet checks enrolled public descriptors before selecting this signer.

    const auto command{Cat(Cat(m_command, {"--stdin", "--fingerprint", m_fingerprint}), NetworkArg())};
    const std::string stdinStr = "signtx " + EncodeBase64(ssTx.str());

    const UniValue signer_result = RunCommandParseJSON(command, stdinStr);

    if (signer_result.find_value("error").isStr()) {
        error = signer_result.find_value("error").get_str();
        return false;
    }

    if (!signer_result.find_value("psbt").isStr()) {
        error = "Unexpected result from signer";
        return false;
    }

    PartiallySignedTransaction signer_psbtx;
    std::string signer_psbt_error;
    if (!DecodeBase64PSBT(signer_psbtx, signer_result.find_value("psbt").get_str(), signer_psbt_error)) {
        error = strprintf("TX decode failed %s", signer_psbt_error);
        return false;
    }

    return MergeSignatures(psbtx, signer_psbtx, error, script_verify_flags);
}

namespace {
using PSBTMap = std::map<std::vector<unsigned char>, std::vector<unsigned char>>;

// Normalize away signature fields so even metadata hidden by finalization in
// serialization is checked. Signers may omit metadata; they cannot replace it.
std::vector<PSBTMap> ProtectedMaps(PartiallySignedTransaction psbt)
{
    for (auto& input : psbt.inputs) {
        input.partial_sigs.clear();
        input.final_script_sig.clear();
        input.final_script_witness.SetNull();
    }
    DataStream stream;
    stream << psbt;
    stream.ignore(sizeof(PSBT_MAGIC_BYTES));
    std::vector<PSBTMap> maps(1 + psbt.inputs.size() + psbt.outputs.size());
    for (auto& map : maps) {
        while (true) {
            std::vector<unsigned char> key, value;
            stream >> key;
            if (key.empty()) break;
            stream >> value;
            map.emplace(std::move(key), std::move(value));
        }
    }
    return maps;
}

class RequestedSighashChecker : public DeferringSignatureChecker
{
    const std::optional<int> m_sighash;
    mutable bool m_sighash_mismatch{false};
public:
    RequestedSighashChecker(const BaseSignatureChecker& checker, std::optional<int> sighash)
        : DeferringSignatureChecker(checker), m_sighash(sighash) {}
    bool SighashMatches() const { return !m_sighash_mismatch; }
    bool CheckPostQuantumSignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& key,
                                   const CScript& script, SigVersion version) const override
    {
        // Observe the requested hash type without changing script semantics:
        // forcing CHECKSIG to fail could incorrectly satisfy a negated check.
        if (m_sighash && !sig.empty() && sig.back() != *m_sighash) m_sighash_mismatch = true;
        return m_checker.CheckPostQuantumSignature(sig, key, script, version);
    }
};
} // namespace

bool ExternalSigner::MergeSignatures(PartiallySignedTransaction& psbt, const PartiallySignedTransaction& response,
                                     std::string& error, unsigned int script_verify_flags)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (!psbt.tx || !response.tx || psbt.tx->GetHash() != response.tx->GetHash() ||
        psbt.inputs.size() != psbt.tx->vin.size() || psbt.outputs.size() != psbt.tx->vout.size() ||
        response.inputs.size() != psbt.inputs.size() || response.outputs.size() != psbt.outputs.size()) {
        return fail("Signer changed the unsigned transaction");
    }
    auto expected = psbt;
    for (size_t i = 0; i < expected.inputs.size(); ++i) {
        auto& input = expected.inputs[i];
        if (!input.non_witness_utxo) continue;
        const auto& prevout = expected.tx->vin[i].prevout;
        if (input.non_witness_utxo->GetHash() != prevout.hash || prevout.n >= input.non_witness_utxo->vout.size()) {
            return fail("Invalid requested previous transaction");
        }
        const auto& utxo = input.non_witness_utxo->vout[prevout.n];
        if (!input.witness_utxo.IsNull() && input.witness_utxo != utxo) return fail("Conflicting requested UTXO data");
        // A finalizer may replace a full previous transaction with this exact output.
        input.witness_utxo = utxo;
    }
    const auto expected_maps = ProtectedMaps(expected);
    const auto response_maps = ProtectedMaps(response);
    for (size_t i = 0; i < expected_maps.size(); ++i) {
        for (const auto& [key, value] : response_maps[i]) {
            const auto it = expected_maps[i].find(key);
            if (it == expected_maps[i].end() || it->second != value) return fail("Signer changed protected PSBT metadata");
        }
    }
    auto merged = psbt;
    for (size_t i = 0; i < merged.inputs.size(); ++i) {
        auto& input = merged.inputs[i];
        const auto& returned = response.inputs[i];
        const int sighash = input.sighash_type.value_or(SIGHASH_ALL);
        for (const auto& [key, sig] : returned.partial_sigs) {
            if (sig.second.empty() || sig.second.back() != sighash) return fail("Signer used an unexpected sighash type");
            const auto [it, inserted] = input.partial_sigs.emplace(key, sig);
            if (!inserted && it->second != sig) return fail("Signer changed an existing signature");
        }
        if (!returned.final_script_sig.empty()) {
            if (!input.final_script_sig.empty() && input.final_script_sig != returned.final_script_sig) return fail("Signer changed an existing final script");
            input.final_script_sig = returned.final_script_sig;
        }
        if (!returned.final_script_witness.IsNull()) {
            if (!input.final_script_witness.IsNull() && input.final_script_witness.stack != returned.final_script_witness.stack) return fail("Signer changed an existing final witness");
            input.final_script_witness = returned.final_script_witness;
        }
    }
    const auto txdata = PrecomputePSBTData(merged);
    for (size_t i = 0; i < merged.inputs.size(); ++i) {
        const auto& input = merged.inputs[i];
        if (!PSBTInputSigned(input)) continue;
        const auto& utxo = expected.inputs[i].witness_utxo;
        if (utxo.IsNull()) return fail("Missing UTXO for signer final script");
        const bool allow_legacy = !(script_verify_flags & SCRIPT_VERIFY_PQ_STRICT);
        const MutableTransactionSignatureChecker checker{&*merged.tx, static_cast<unsigned int>(i), utxo.nValue, txdata, MissingDataBehavior::FAIL, allow_legacy};
        // Do not impose this signing request's default on a previously finalized,
        // verified input from another participant whose sighash field was removed.
        const bool already_verified = PSBTInputSignedAndVerified(psbt, i, &txdata, script_verify_flags);
        const RequestedSighashChecker requested{checker, already_verified ? std::nullopt : std::optional{input.sighash_type.value_or(SIGHASH_ALL)}};
        if (!VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, script_verify_flags, requested) || !requested.SighashMatches()) {
            return fail("Signer returned an invalid final script or unexpected sighash type");
        }
    }
    psbt = std::move(merged);
    return true;
}
