// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <algorithm>

#include <common/types.h>
#include <consensus/amount.h>
#include <crypto/sha512.h>
#include <script/solver.h>
#include <node/types.h>
#include <policy/policy.h>
#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>
#include <script/signingprovider.h>
#include <util/check.h>
#include <util/strencodings.h>

using common::PSBTError;

namespace psbt::tidecoin {
std::vector<unsigned char> MakeProprietaryKey(uint8_t map_type,
                                              std::span<const unsigned char> identifier,
                                              uint64_t subtype,
                                              std::span<const unsigned char> keydata)
{
    std::vector<unsigned char> key;
    VectorWriter w{key, /*nPosIn=*/0};
    w << CompactSizeWriter(map_type);
    w << std::vector<unsigned char>(identifier.begin(), identifier.end());
    w << CompactSizeWriter(subtype);
    if (!keydata.empty()) w << keydata;
    return key;
}

std::vector<unsigned char> MakePQHDOriginValue(const uint256& seed_id,
                                               std::span<const uint32_t> path_hardened)
{
    std::vector<unsigned char> value;
    VectorWriter w{value, /*nPosIn=*/0};
    w << seed_id;
    w << CompactSizeWriter(path_hardened.size());
    for (uint32_t elem : path_hardened) {
        w << elem;
    }
    return value;
}

static bool ParseProprietaryKeydata(const PSBTProprietary& entry, std::vector<unsigned char>& out_keydata)
{
    try {
        if (entry.key.size() < 1) return false;
        const auto type8 = entry.key[0];
        if (type8 != PSBT_IN_PROPRIETARY && type8 != PSBT_OUT_PROPRIETARY && type8 != PSBT_GLOBAL_PROPRIETARY) return false;

        const unsigned char* const start = entry.key.data() + 1;
        const size_t total = entry.key.size() - 1;
        SpanReader r{std::span<const unsigned char>(start, total)};
        std::vector<unsigned char> identifier;
        r >> identifier;
        (void)ReadCompactSize(r); // subtype

        const size_t consumed = total - r.size();
        out_keydata.assign(start + consumed, start + total);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::optional<PQHDOrigin> DecodePQHDOrigin(const PSBTProprietary& entry)
{
    if (entry.identifier.size() != PROPRIETARY_IDENTIFIER.size()) return std::nullopt;
    if (!std::equal(entry.identifier.begin(), entry.identifier.end(), PROPRIETARY_IDENTIFIER.begin())) return std::nullopt;
    if (entry.subtype != SUBTYPE_PQHD_ORIGIN) return std::nullopt;

    try {
        std::vector<unsigned char> keydata;
        if (!ParseProprietaryKeydata(entry, keydata)) return std::nullopt;
        CPubKey pubkey{keydata};
        if (!pubkey.IsValidNonHybrid()) return std::nullopt;

        SpanReader v{entry.value};
        uint256 seed_id;
        v >> seed_id;
        const uint64_t path_len = ReadCompactSize(v);
        constexpr uint64_t V1_PATH_LEN = 6;
        constexpr uint32_t HARDENED = 0x80000000U;
        if (path_len != V1_PATH_LEN) return std::nullopt;
        std::vector<uint32_t> path;
        path.reserve(path_len);
        for (uint64_t i = 0; i < path_len; ++i) {
            uint32_t elem;
            v >> elem;
            if ((elem & HARDENED) == 0) return std::nullopt; // hardened-only
            path.push_back(elem);
        }
        if (!v.empty()) return std::nullopt;

        if (!pqhd::ValidateV1LeafPath(path)) return std::nullopt;

        const uint32_t scheme_u32 = path[2] & 0x7FFFFFFFU;
        const auto scheme_u8 = static_cast<uint8_t>(scheme_u32);
        if (pubkey.size() == 0 || pubkey[0] != scheme_u8) return std::nullopt;

        return PQHDOrigin{std::move(pubkey), seed_id, std::move(path)};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool AddPQHDOrigin(std::set<PSBTProprietary>& set,
                   uint8_t map_type,
                   const CPubKey& pubkey,
                   const uint256& seed_id,
                   std::span<const uint32_t> path_hardened)
{
    PSBTProprietary entry;
    entry.identifier.assign(PROPRIETARY_IDENTIFIER.begin(), PROPRIETARY_IDENTIFIER.end());
    entry.subtype = SUBTYPE_PQHD_ORIGIN;

    entry.key = MakeProprietaryKey(map_type, entry.identifier, entry.subtype, std::span{pubkey});
    entry.value = MakePQHDOriginValue(seed_id, path_hardened);

    if (!DecodePQHDOrigin(entry)) return false;
    if (const auto existing = set.find(entry); existing != set.end()) return existing->value == entry.value;
    set.insert(std::move(entry));
    return true;
}
} // namespace psbt::tidecoin

PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx) : tx(tx)
{
    inputs.resize(tx.vin.size());
    outputs.resize(tx.vout.size());
}

bool PartiallySignedTransaction::IsNull() const
{
    return !tx && inputs.empty() && outputs.empty() && unknown.empty();
}

namespace {
bool PQHDOriginsCompatible(const std::set<PSBTProprietary>& left, const std::set<PSBTProprietary>& right)
{
    for (const auto* records : {&left, &right}) {
        for (const auto& entry : *records) {
            if (!std::ranges::equal(entry.identifier, psbt::tidecoin::PROPRIETARY_IDENTIFIER) || entry.subtype != psbt::tidecoin::SUBTYPE_PQHD_ORIGIN) continue;
            if (!psbt::tidecoin::DecodePQHDOrigin(entry)) return false;
            if (const auto other = (records == &left ? right : left).find(entry);
                other != (records == &left ? right : left).end() && other->value != entry.value) return false;
        }
    }
    return true;
}
} // namespace

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    // Prohibited to merge two PSBTs over different transactions
    if (!tx || !psbt.tx || tx->GetHash() != psbt.tx->GetHash() ||
        inputs.size() != psbt.inputs.size() || outputs.size() != psbt.outputs.size()) {
        return false;
    }

    // Check every origin map before publishing any merge, including metadata
    // from a participant whose keys are unknown to the local wallet.
    if (!PQHDOriginsCompatible(m_proprietary, psbt.m_proprietary)) return false;
    for (size_t i = 0; i < inputs.size(); ++i) {
        if (!PQHDOriginsCompatible(inputs[i].m_proprietary, psbt.inputs[i].m_proprietary)) return false;
        const auto& left = inputs[i];
        const auto& right = psbt.inputs[i];
        if (left.sighash_type && right.sighash_type && left.sighash_type != right.sighash_type) return false;
        const auto& prevout = tx->vin[i].prevout;
        if (!left.IsUTXOConsistent(prevout) || !right.IsUTXOConsistent(prevout)) return false;
        if (!left.witness_utxo.IsNull() && !right.witness_utxo.IsNull() && left.witness_utxo != right.witness_utxo) return false;
        PSBTInput combined;
        combined.non_witness_utxo = left.non_witness_utxo ? left.non_witness_utxo : right.non_witness_utxo;
        combined.witness_utxo = left.witness_utxo.IsNull() ? right.witness_utxo : left.witness_utxo;
        if (!combined.IsUTXOConsistent(prevout)) return false;
    }
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (!PQHDOriginsCompatible(outputs[i].m_proprietary, psbt.outputs[i].m_proprietary)) return false;
    }

    for (unsigned int i = 0; i < inputs.size(); ++i) {
        inputs[i].Merge(psbt.inputs[i]);
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        outputs[i].Merge(psbt.outputs[i]);
    }
    m_proprietary.insert(psbt.m_proprietary.begin(), psbt.m_proprietary.end());
    unknown.insert(psbt.unknown.begin(), psbt.unknown.end());

    return true;
}

bool PartiallySignedTransaction::AddInput(const CTxIn& txin, PSBTInput& psbtin)
{
    if (std::find(tx->vin.begin(), tx->vin.end(), txin) != tx->vin.end()) {
        return false;
    }
    tx->vin.push_back(txin);
    psbtin.partial_sigs.clear();
    psbtin.final_script_sig.clear();
    psbtin.final_script_witness.SetNull();
    inputs.push_back(psbtin);
    return true;
}

bool PartiallySignedTransaction::AddOutput(const CTxOut& txout, const PSBTOutput& psbtout)
{
    tx->vout.push_back(txout);
    outputs.push_back(psbtout);
    return true;
}

bool PSBTInput::IsUTXOConsistent(const COutPoint& prevout) const
{
    if (!non_witness_utxo) return true;
    if (non_witness_utxo->GetHash() != prevout.hash || prevout.n >= non_witness_utxo->vout.size()) return false;
    return witness_utxo.IsNull() || witness_utxo == non_witness_utxo->vout[prevout.n];
}

bool PartiallySignedTransaction::GetInputUTXO(CTxOut& utxo, int input_index) const
{
    const PSBTInput& input = inputs[input_index];
    if (!input.IsUTXOConsistent(tx->vin[input_index].prevout)) return false;
    uint32_t prevout_index = tx->vin[input_index].prevout.n;
    if (input.non_witness_utxo) {
        if (prevout_index >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != tx->vin[input_index].prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout_index];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
    } else {
        return false;
    }
    return true;
}

bool PSBTInput::IsNull() const
{
    return !non_witness_utxo && witness_utxo.IsNull() && partial_sigs.empty() && unknown.empty() && redeem_script.empty() && witness_script.empty();
}

void PSBTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (!final_script_witness.IsNull()) {
        sigdata.scriptWitness = final_script_witness;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& [hash, preimage] : ripemd160_preimages) {
        sigdata.ripemd160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sha256_preimages) {
        sigdata.sha256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : hash160_preimages) {
        sigdata.hash160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : hash256_preimages) {
        sigdata.hash256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
}

void PSBTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        redeem_script.clear();
        witness_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }
        if (!sigdata.scriptWitness.IsNull()) {
            final_script_witness = sigdata.scriptWitness;
        }
        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
}

void PSBTInput::Merge(const PSBTInput& input)
{
    if (!sighash_type) sighash_type = input.sighash_type;
    if (!non_witness_utxo && input.non_witness_utxo) non_witness_utxo = input.non_witness_utxo;
    if (witness_utxo.IsNull() && !input.witness_utxo.IsNull()) {
        witness_utxo = input.witness_utxo;
    }

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    ripemd160_preimages.insert(input.ripemd160_preimages.begin(), input.ripemd160_preimages.end());
    sha256_preimages.insert(input.sha256_preimages.begin(), input.sha256_preimages.end());
    hash160_preimages.insert(input.hash160_preimages.begin(), input.hash160_preimages.end());
    hash256_preimages.insert(input.hash256_preimages.begin(), input.hash256_preimages.end());
    m_proprietary.insert(input.m_proprietary.begin(), input.m_proprietary.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (witness_script.empty() && !input.witness_script.empty()) witness_script = input.witness_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
    if (final_script_witness.IsNull() && !input.final_script_witness.IsNull()) final_script_witness = input.final_script_witness;
}

void PSBTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
}

void PSBTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
}

bool PSBTOutput::IsNull() const
{
    return redeem_script.empty() && witness_script.empty() && unknown.empty();
}

void PSBTOutput::Merge(const PSBTOutput& output)
{
    m_proprietary.insert(output.m_proprietary.begin(), output.m_proprietary.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
    if (witness_script.empty() && !output.witness_script.empty()) witness_script = output.witness_script;
}

bool PSBTInputSigned(const PSBTInput& input)
{
    return !input.final_script_sig.empty() || !input.final_script_witness.IsNull();
}

bool PSBTInputHasSigningUTXO(const PartiallySignedTransaction& psbt, size_t index, unsigned int flags)
{
    if (!psbt.tx || index >= psbt.inputs.size() || index >= psbt.tx->vin.size()) return false;
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, index)) return false;
    const auto& input = psbt.inputs[index];
    if (input.non_witness_utxo) return true;
    CScript script = utxo.scriptPubKey;
    if (script.IsPayToScriptHash()) {
        if (GetScriptForDestination(ScriptHash(input.redeem_script)) != script) return false;
        script = input.redeem_script;
    }
    int version;
    std::vector<unsigned char> program;
    if (!script.IsWitnessProgram(version, program)) return false;
    return (version == 0 && (program.size() == 20 || program.size() == 32)) ||
           (version == 1 && program.size() == WITNESS_V1_SCRIPTHASH_512_SIZE && (flags & SCRIPT_VERIFY_WITNESS_V1_512));
}

bool VerifyPSBTPartialSignature(const PartiallySignedTransaction& psbt, size_t index, const SigPair& signature,
                                const PrecomputedTransactionData& txdata, unsigned int flags)
{
    if (signature.second.empty() || !PSBTInputHasSigningUTXO(psbt, index, flags)) return false;
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, index)) return false;
    const auto& input = psbt.inputs[index];
    CScript script = utxo.scriptPubKey;
    if (script.IsPayToScriptHash()) {
        if (GetScriptForDestination(ScriptHash(input.redeem_script)) != script) return false;
        script = input.redeem_script;
    }
    SigVersion sigversion = SigVersion::BASE;
    int version;
    std::vector<unsigned char> program;
    if (script.IsWitnessProgram(version, program)) {
        if (version == 0 && program.size() == 20) {
            uint160 id;
            std::copy(program.begin(), program.end(), id.begin());
            script = GetScriptForDestination(PKHash(id));
            sigversion = SigVersion::WITNESS_V0;
        } else if (version == 0 && program.size() == 32) {
            if (GetScriptForDestination(WitnessV0ScriptHash(input.witness_script)) != script) return false;
            script = input.witness_script;
            sigversion = SigVersion::WITNESS_V0;
        } else if (version == 1 && program.size() == WITNESS_V1_SCRIPTHASH_512_SIZE && (flags & SCRIPT_VERIFY_WITNESS_V1_512)) {
            if (GetScriptForDestination(WitnessV1ScriptHash512(input.witness_script)) != script) return false;
            script = input.witness_script;
            sigversion = SigVersion::WITNESS_V1_512;
        } else {
            return false;
        }
    }
    if (sigversion == SigVersion::WITNESS_V1_512 && !IsSupportedSighash(signature.second.back())) return false;
    const MutableTransactionSignatureChecker checker{&*psbt.tx, static_cast<unsigned int>(index), utxo.nValue, txdata, MissingDataBehavior::FAIL, !(flags & SCRIPT_VERIFY_PQ_STRICT)};
    return checker.CheckPostQuantumSignature(signature.second, std::vector<unsigned char>(signature.first.begin(), signature.first.end()), script, sigversion);
}

bool PSBTInputSignedAndVerified(const PartiallySignedTransaction psbt, unsigned int input_index, const PrecomputedTransactionData* txdata, unsigned int script_verify_flags)
{
    const bool allow_legacy = !(script_verify_flags & SCRIPT_VERIFY_PQ_STRICT);
    CTxOut utxo;
    assert(input_index < psbt.inputs.size());
    const PSBTInput& input = psbt.inputs[input_index];
    if (!input.IsUTXOConsistent(psbt.tx->vin[input_index].prevout)) return false;

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = psbt.tx->vin[input_index].prevout;
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
    } else {
        return false;
    }

    if (txdata) {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, script_verify_flags, MutableTransactionSignatureChecker{&(*psbt.tx), input_index, utxo.nValue, *txdata, MissingDataBehavior::FAIL, allow_legacy});
    }
    return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, script_verify_flags, MutableTransactionSignatureChecker{&(*psbt.tx), input_index, utxo.nValue, MissingDataBehavior::FAIL, allow_legacy});
}

bool PSBTInputSignedAndVerified(const PartiallySignedTransaction psbt, unsigned int input_index, const PrecomputedTransactionData* txdata)
{
    return PSBTInputSignedAndVerified(psbt, input_index, txdata, STANDARD_SCRIPT_VERIFY_FLAGS);
}

size_t CountPSBTUnsignedInputs(const PartiallySignedTransaction& psbt) {
    size_t count = 0;
    for (const auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) {
            count++;
        }
    }

    return count;
}

void UpdatePSBTOutput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index)
{
    CMutableTransaction& tx = *Assert(psbt.tx);
    const CTxOut& out = tx.vout.at(index);
    PSBTOutput& psbt_out = psbt.outputs.at(index);

    // Fill a SignatureData with output info
    SignatureData sigdata;
    psbt_out.FillSignatureData(sigdata);

    // Construct a would-be spend of this output, to update sigdata with.
    // Note that ProduceSignature is used to fill in metadata (not actual signatures),
    // so provider does not need to provide any private keys (it can be a HidingSigningProvider).
    MutableTransactionSignatureCreator creator(tx, /*input_idx=*/0, out.nValue, SIGHASH_ALL);
    ProduceSignature(provider, creator, out.scriptPubKey, sigdata);

    // Put redeem_script, witness_script, key paths, into PSBTOutput.
    psbt_out.FromSignatureData(sigdata);
}

PrecomputedTransactionData PrecomputePSBTData(const PartiallySignedTransaction& psbt)
{
    const CMutableTransaction& tx = *psbt.tx;
    bool have_all_spent_outputs = true;
    std::vector<CTxOut> utxos(tx.vin.size());
    for (size_t idx = 0; idx < tx.vin.size(); ++idx) {
        if (!psbt.GetInputUTXO(utxos[idx], idx)) have_all_spent_outputs = false;
    }
    PrecomputedTransactionData txdata;
    if (have_all_spent_outputs) {
        txdata.Init(tx, std::move(utxos), true);
    } else {
        txdata.Init(tx, {}, true);
    }
    return txdata;
}

PSBTError DeclarePSBTSighash(PartiallySignedTransaction& psbt, int sighash)
{
    if (!IsSupportedSighash(sighash)) return PSBTError::SIGHASH_UNSUPPORTED;
    for (const auto& input : psbt.inputs) {
        if (PSBTInputSigned(input)) continue;
        if (input.sighash_type && *input.sighash_type != sighash) return PSBTError::SIGHASH_MISMATCH;
        for (const auto& [_, sig] : input.partial_sigs) {
            if (sig.second.empty() || sig.second.back() != sighash) return PSBTError::SIGHASH_MISMATCH;
        }
    }
    for (auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) input.sighash_type = sighash;
    }
    return PSBTError::OK;
}

PSBTError SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, const PrecomputedTransactionData* txdata, std::optional<int> sighash, SignatureData* out_sigdata, bool finalize, std::optional<unsigned int> script_verify_flags, PSBTInputIntent intent)
{
    PSBTInput& input = psbt.inputs.at(index);
    const CMutableTransaction& tx = *psbt.tx;
    if (!input.IsUTXOConsistent(tx.vin[index].prevout)) return PSBTError::UTXO_MISMATCH;
    const unsigned int effective_flags = script_verify_flags.value_or(STANDARD_SCRIPT_VERIFY_FLAGS);
    const bool allow_legacy = !(effective_flags & SCRIPT_VERIFY_PQ_STRICT);

    if (PSBTInputSignedAndVerified(psbt, index, txdata, effective_flags)) {
        return PSBTError::OK;
    }

    // Final fields are untrusted until script verification succeeds. In particular,
    // FillSignatureData's presence marker must not turn invalid finals into success.
    if (PSBTInputSigned(input)) return PSBTError::INCOMPLETE;

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    // Get UTXO
    bool require_witness_sig = false;
    CTxOut utxo;

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = tx.vin[index].prevout;
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return PSBTError::MISSING_INPUTS;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return PSBTError::MISSING_INPUTS;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
        // When we're taking our information from a witness UTXO, we can't verify it is actually data from
        // the output being spent. This is safe in case a witness signature is produced (which includes this
        // information directly in the hash), but not for non-witness signatures. Remember that we require
        // a witness signature in this situation.
        require_witness_sig = true;
    } else {
        return PSBTError::MISSING_INPUTS;
    }

    const int requested = intent == PSBTInputIntent::SIGN ? sighash.value_or(SIGHASH_ALL) : input.sighash_type.value_or(SIGHASH_ALL);
    const auto report_missing = [&] {
        if (!out_sigdata) return;
        out_sigdata->missing_pubkeys = sigdata.missing_pubkeys;
        out_sigdata->missing_sigs = sigdata.missing_sigs;
        out_sigdata->missing_redeem_script = sigdata.missing_redeem_script;
        out_sigdata->missing_witness_script = sigdata.missing_witness_script;
    };
    const auto preserve_public_metadata = [&] {
        if (intent != PSBTInputIntent::INSPECT || !txdata) return;
        // Resolve scripts without creating signatures or publishing a final.
        // A preceding signing attempt may already have recorded these keys.
        sigdata.missing_pubkeys.clear();
        sigdata.missing_sigs.clear();
        MutableTransactionSignatureCreator creator(tx, index, utxo.nValue, txdata, requested, allow_legacy);
        ProduceSignature(HidingSigningProvider(&provider, true), creator, utxo.scriptPubKey, sigdata, effective_flags);
        sigdata.complete = false;
        input.FromSignatureData(sigdata);
        if (sigdata.witness) input.witness_utxo = utxo;
        report_missing();
    };
    bool existing_match{true};
    bool declaration_match{true};
    for (const auto& [_, sig] : input.partial_sigs) {
        if (!sig.second.empty() && SingleWithoutOutput(sig.second.back(), index, tx.vout.size())) {
            // Do not newly finalize this partial, including on a foreign input.
            // Inspection explains it; unrelated signing can still proceed.
            preserve_public_metadata();
            return intent == PSBTInputIntent::INSPECT ? PSBTError::SINGLE_WITHOUT_OUTPUT : PSBTError::INCOMPLETE;
        }
        existing_match &= !sig.second.empty() && sig.second.back() == requested;
        declaration_match &= !sig.second.empty() && sig.second.back() == input.sighash_type.value_or(SIGHASH_ALL);
    }

    sigdata.witness = false;
    bool sig_complete;
    bool signed_new{false};
    if (txdata == nullptr) {
        if (SingleWithoutOutput(requested, index, tx.vout.size())) return PSBTError::SINGLE_WITHOUT_OUTPUT;
        if (!IsSupportedSighash(requested)) return PSBTError::SIGHASH_UNSUPPORTED;
        if (!declaration_match) return PSBTError::SIGHASH_MISMATCH;
        sig_complete = ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, utxo.scriptPubKey, sigdata, effective_flags);
    } else {
        MutableTransactionSignatureCreator creator(tx, index, utxo.nValue, txdata, requested, allow_legacy);
        creator.SetPSBTConstraints(input.sighash_type, existing_match && declaration_match);
        sig_complete = ProduceSignature(provider, creator, utxo.scriptPubKey, sigdata, effective_flags);
        if (creator.Error() != PSBTError::OK) {
            if (out_sigdata) *out_sigdata = sigdata;
            return creator.Error();
        }
        signed_new = creator.Signed();
        // Cached signatures do not pass through the creator. Inspection and
        // foreign inputs use their own declarations, never the caller's mode.
        if (!declaration_match && !signed_new) {
            preserve_public_metadata();
            return intent == PSBTInputIntent::INSPECT ? PSBTError::SIGHASH_MISMATCH : PSBTError::INCOMPLETE;
        }
    }

    // Report missing solving data even if no witness could be constructed.
    report_missing();

    // Verify that a witness signature was produced in case one was required.
    if (require_witness_sig && !sigdata.witness) return PSBTError::INCOMPLETE;

    // If we are not finalizing, set sigdata.complete to false to not set the scriptWitness
    if (!finalize && sigdata.complete) sigdata.complete = false;

    input.FromSignatureData(sigdata);
    if (signed_new && requested != SIGHASH_ALL && !PSBTInputSigned(input)) input.sighash_type = requested;

    // If we have a witness signature, put a witness UTXO.
    if (sigdata.witness) {
        input.witness_utxo = utxo;
        // The caller may drop full transactions after checking the signing
        // modes and witness versions of every input.
    }

    return sig_complete ? PSBTError::OK : PSBTError::INCOMPLETE;
}

void RemoveUnnecessaryTransactions(PartiallySignedTransaction& psbt, unsigned int script_verify_flags)
{
    if (!(script_verify_flags & SCRIPT_VERIFY_WITNESS_V1_512)) return;
    if (!psbt.tx || psbt.inputs.size() != psbt.tx->vin.size()) return;
    const auto txdata = PrecomputePSBTData(psbt);
    std::vector<CTxOut> utxos(psbt.inputs.size());
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        const auto& input = psbt.inputs[i];
        auto& utxo = utxos[i];
        if (!psbt.GetInputUTXO(utxo, i) || !MoneyRange(utxo.nValue)) return;
        const bool final = PSBTInputSigned(input);
        // Unfinished inputs must already carry their witness UTXO. Final inputs
        // may have only the verified full record; stage its output before removal.
        if (!final && input.witness_utxo.IsNull()) return;
        CScript program_script = utxo.scriptPubKey;
        if (program_script.IsPayToScriptHash()) {
            CScript redeem = input.redeem_script;
            if (final) {
                auto pc = input.final_script_sig.begin();
                opcodetype opcode;
                std::vector<unsigned char> data;
                if (!input.final_script_sig.GetOp(pc, opcode, data) || pc != input.final_script_sig.end()) return;
                redeem = CScript(data.begin(), data.end());
                if (input.final_script_sig != (CScript() << data)) return;
            }
            if (GetScriptForDestination(ScriptHash(redeem)) != program_script) return;
            program_script = redeem;
            if (!final && input.witness_script.empty()) return;
        }
        int version;
        std::vector<unsigned char> program;
        if (!program_script.IsWitnessProgram(version, program) || version != 1 || program.size() != WITNESS_V1_SCRIPTHASH_512_SIZE) return;
        if (!final && !input.witness_script.empty()) {
            uint512 hash;
            CSHA512().Write(input.witness_script.data(), input.witness_script.size()).Finalize(hash.begin());
            if (!std::equal(program.begin(), program.end(), hash.begin())) return;
        }
        if (final) {
            const MutableTransactionSignatureChecker checker{&*psbt.tx, static_cast<unsigned int>(i), utxo.nValue, txdata, MissingDataBehavior::FAIL, !(script_verify_flags & SCRIPT_VERIFY_PQ_STRICT)};
            const SignatureCheckObserver observer{checker, i, psbt.tx->vout.size()};
            if (!VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, script_verify_flags, observer)) return;
            if (!observer.all_full_commitment || !observer.successful_v1) return;
            if (input.sighash_type && (observer.modes.size() != 1 || !observer.modes.contains(*input.sighash_type))) return;
        } else {
            const int mode = input.sighash_type.value_or(SIGHASH_ALL);
            if (mode != SIGHASH_ALL && mode != SIGHASH_NONE && mode != SIGHASH_SINGLE) return;
            if (SingleWithoutOutput(mode, i, psbt.tx->vout.size())) return;
            for (const auto& [id, signature] : input.partial_sigs) {
                if (signature.second.empty() || signature.second.back() != mode) return;
            }
        }
    }
    // Publish only after every input qualified. Never remove the only UTXO record.
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        psbt.inputs[i].witness_utxo = utxos[i];
        psbt.inputs[i].non_witness_utxo.reset();
    }
}

bool FinalizePSBT(PartiallySignedTransaction& psbtx, std::optional<unsigned int> script_verify_flags)
{
    const unsigned int effective_flags = script_verify_flags.value_or(STANDARD_SCRIPT_VERIFY_FLAGS);
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
    bool complete = true;
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& input = psbtx.inputs.at(i);
        complete &= (SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, input.sighash_type, nullptr, true, effective_flags, PSBTInputIntent::INSPECT) == PSBTError::OK);
    }

    return complete;
}

bool FinalizeAndExtractPSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& result, std::optional<unsigned int> script_verify_flags)
{
    // It's not safe to extract a PSBT that isn't finalized, and there's no easy way to check
    //   whether a PSBT is finalized without finalizing it, so we just do this.
    if (!FinalizePSBT(psbtx, script_verify_flags)) {
        return false;
    }

    result = *psbtx.tx;
    for (unsigned int i = 0; i < result.vin.size(); ++i) {
        result.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
        result.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
    }
    return true;
}

bool CombinePSBTs(PartiallySignedTransaction& out, const std::vector<PartiallySignedTransaction>& psbtxs)
{
    if (psbtxs.empty()) return false;
    auto merged = psbtxs[0];
    if (!merged.Merge(psbtxs[0])) return false;

    // Merge
    for (auto it = std::next(psbtxs.begin()); it != psbtxs.end(); ++it) {
        if (!merged.Merge(*it)) {
            return false;
        }
    }
    out = std::move(merged);
    return true;
}

std::string PSBTRoleName(PSBTRole role) {
    switch (role) {
    case PSBTRole::CREATOR: return "creator";
    case PSBTRole::UPDATER: return "updater";
    case PSBTRole::SIGNER: return "signer";
    case PSBTRole::FINALIZER: return "finalizer";
    case PSBTRole::EXTRACTOR: return "extractor";
        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}

bool DecodeBase64PSBT(PartiallySignedTransaction& psbt, const std::string& base64_tx, std::string& error)
{
    auto tx_data = DecodeBase64(base64_tx);
    if (!tx_data) {
        error = "invalid base64";
        return false;
    }
    return DecodeRawPSBT(psbt, MakeByteSpan(*tx_data), error);
}

bool DecodeRawPSBT(PartiallySignedTransaction& psbt, std::span<const std::byte> tx_data, std::string& error)
{
    DataStream ss_data{tx_data};
    try {
        ss_data >> psbt;
        if (!ss_data.empty()) {
            error = "extra data after PSBT";
            return false;
        }
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    return true;
}

uint32_t PartiallySignedTransaction::GetVersion() const
{
    if (m_version != std::nullopt) {
        return *m_version;
    }
    return 0;
}
