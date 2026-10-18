// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <consensus/amount.h>
#include <common/messages.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/miniscript.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <pq/pq_txsize.h>
#include <uint256.h>
#include <uint512.h>
#include <util/translation.h>
#include <util/vector.h>

#include <algorithm>

typedef std::vector<unsigned char> valtype;

static constexpr bool ALLOW_LEGACY_STANDARD = !(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_PQ_STRICT);

bool SignatureCheckObserver::CheckPostQuantumSignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& key,
                                                       const CScript& script, SigVersion version) const
{
    const bool result = m_checker.CheckPostQuantumSignature(sig, key, script, version);
    if (!sig.empty()) {
        const int mode = sig.back();
        modes.insert(mode);
        successful_signature |= result;
        all_full_commitment &= version == SigVersion::WITNESS_V1_512 && (mode == SIGHASH_ALL || mode == SIGHASH_NONE || mode == SIGHASH_SINGLE);
        successful_v1 |= result && version == SigVersion::WITNESS_V1_512 && IsSupportedSighash(mode);
        single_without_output |= SingleWithoutOutput(mode, m_input, m_outputs);
        legacy_single_without_output |= result && version == SigVersion::BASE && SingleWithoutOutput(mode, m_input, m_outputs);
    }
    return result;
}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, int hash_type)
    : MutableTransactionSignatureCreator(tx, input_idx, amount, nullptr, hash_type, ALLOW_LEGACY_STANDARD)
{
}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, const PrecomputedTransactionData* txdata, int hash_type)
    : MutableTransactionSignatureCreator(tx, input_idx, amount, txdata, hash_type, ALLOW_LEGACY_STANDARD)
{
}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, int hash_type, bool allow_legacy)
    : MutableTransactionSignatureCreator(tx, input_idx, amount, nullptr, hash_type, allow_legacy)
{
}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, const PrecomputedTransactionData* txdata, int hash_type, bool allow_legacy)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type}, amount{amount}, m_allow_legacy{allow_legacy},
      checker{txdata ? MutableTransactionSignatureChecker{&m_txto, nIn, amount, *txdata, MissingDataBehavior::FAIL, allow_legacy} :
                       MutableTransactionSignatureChecker{&m_txto, nIn, amount, MissingDataBehavior::FAIL, allow_legacy}},
      m_txdata(txdata)
{
}

bool MutableTransactionSignatureCreator::CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0 || sigversion == SigVersion::WITNESS_V1_512);

    CKey key;
    if (!provider.GetKey(address, key))
        return false;

    const auto refuse = [&](common::PSBTError error) { m_error = error; return false; };
    // Refuse SINGLE ((nHashType & 0x1f) == SIGHASH_SINGLE, the same test the
    // signature hashes use) when the input has no output at its index. Legacy
    // hashing returns the constant 1 (an unbound, reusable signature); witness
    // v0 still commits to the spent input but uses a zero output hash, so outputs
    // are not committed; witness v1 fails in SignatureHash512. Consensus
    // verification is unchanged.
    if (SingleWithoutOutput(nHashType, nIn, m_txto.vout.size())) return refuse(common::PSBTError::SINGLE_WITHOUT_OUTPUT);
    if (!IsSupportedSighash(nHashType)) return refuse(common::PSBTError::SIGHASH_UNSUPPORTED);
    if ((m_declared_sighash && *m_declared_sighash != nHashType) || !m_existing_signatures_match) return refuse(common::PSBTError::SIGHASH_MISMATCH);
    if (sigversion != SigVersion::BASE && !m_amount_known) {
        return refuse(common::PSBTError::MISSING_AMOUNT);
    }
    if (sigversion == SigVersion::WITNESS_V1_512 && !(nHashType & SIGHASH_ANYONECANPAY) && !m_all_amounts_known) return refuse(common::PSBTError::MISSING_SPENT_AMOUNTS);

    // Signing without known amount does not work in witness scripts.
    if ((sigversion == SigVersion::WITNESS_V0 || sigversion == SigVersion::WITNESS_V1_512) && !MoneyRange(amount)) return false;

    if (nHashType == 0) {
        return false;
    }

    if (sigversion == SigVersion::WITNESS_V1_512) {
        uint512 hash;
        if (!SignatureHash512(hash, scriptCode, m_txto, nIn, nHashType, amount, m_txdata)) return false;
        if (!key.Sign512(hash, vchSig, /*legacy_mode=*/false)) {
            return false;
        }
        vchSig.push_back((unsigned char)nHashType);
        m_signed = true;
        return true;
    }

    uint256 hash = SignatureHash(scriptCode, m_txto, nIn, nHashType, amount, sigversion, m_txdata);
    if (!key.Sign(hash, vchSig, false, 0, m_allow_legacy))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    m_signed = true;
    return true;
}

static bool GetCScript(const SigningProvider& provider, const SignatureData& sigdata, const CScriptID& scriptid, CScript& script)
{
    if (provider.GetCScript(scriptid, script)) {
        return true;
    }
    // Look for scripts in SignatureData
    if (CScriptID(sigdata.redeem_script) == scriptid) {
        script = sigdata.redeem_script;
        return true;
    } else if (CScriptID(sigdata.witness_script) == scriptid) {
        script = sigdata.witness_script;
        return true;
    }
    return false;
}

static bool GetPubKey(const SigningProvider& provider, const SignatureData& sigdata, const CKeyID& address, CPubKey& pubkey)
{
    // Look for pubkey in all partial sigs
    const auto it = sigdata.signatures.find(address);
    if (it != sigdata.signatures.end()) {
        pubkey = it->second.first;
        return true;
    }
    // Look for pubkey in pubkey lists
    // Query the underlying provider
    return provider.GetPubKey(address, pubkey);
}

static bool CreateSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const CPubKey& pubkey, const CScript& scriptcode, SigVersion sigversion)
{
    CKeyID keyid = pubkey.GetID();
    const auto it = sigdata.signatures.find(keyid);
    if (it != sigdata.signatures.end()) {
        sig_out = it->second.second;
        return true;
    }
    if (creator.CreateSig(provider, sig_out, keyid, scriptcode, sigversion)) {
        auto i = sigdata.signatures.emplace(keyid, SigPair(pubkey, sig_out));
        assert(i.second);
        return true;
    }
    // Could not make signature or signature not found, add keyid to missing
    if (creator.Error() == common::PSBTError::OK) sigdata.missing_sigs.push_back(keyid);
    return false;
}

template<typename M, typename K, typename V>
miniscript::Availability MsLookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return miniscript::Availability::YES;
    }
    return miniscript::Availability::NO;
}

/**
 * Context for solving a Miniscript.
 * If enough material (access to keys, hash preimages, ..) is given, produces a valid satisfaction.
 */
template<typename Pk>
struct Satisfier {
    using Key = Pk;

    const SigningProvider& m_provider;
    SignatureData& m_sig_data;
    const BaseSignatureCreator& m_creator;
    const CScript& m_witness_script;
    //! The context of the script we are satisfying (P2WSH only).
    const miniscript::MiniscriptContext m_script_ctx;

    explicit Satisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                       const BaseSignatureCreator& creator LIFETIMEBOUND,
                       const CScript& witscript LIFETIMEBOUND,
                       miniscript::MiniscriptContext script_ctx) : m_provider(provider),
                                                                   m_sig_data(sig_data),
                                                                   m_creator(creator),
                                                                   m_witness_script(witscript),
                                                                   m_script_ctx(script_ctx) {}

    static bool KeyCompare(const Key& a, const Key& b) {
        return a < b;
    }

    //! Get a CPubKey from a key hash.
    template<typename I>
    std::optional<CPubKey> CPubFromPKHBytes(I first, I last) const {
        assert(last - first == 20);
        CPubKey pubkey;
        CKeyID key_id;
        std::copy(first, last, key_id.begin());
        if (GetPubKey(m_provider, m_sig_data, key_id, pubkey)) return pubkey;
        m_sig_data.missing_pubkeys.push_back(key_id);
        return {};
    }

    //! Conversion to raw public key.
    std::vector<unsigned char> ToPKBytes(const Key& key) const { return {key.begin(), key.end()}; }

    //! Time lock satisfactions.
    bool CheckAfter(uint32_t value) const { return m_creator.Checker().CheckLockTime(CScriptNum(value)); }
    bool CheckOlder(uint32_t value) const { return m_creator.Checker().CheckSequence(CScriptNum(value)); }

    //! Hash preimage satisfactions.
    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.sha256_preimages, hash, preimage);
    }
    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.ripemd160_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash256_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash160_preimages, hash, preimage);
    }

    miniscript::MiniscriptContext MsContext() const {
        return m_script_ctx;
    }
};

/** Miniscript satisfier specific to P2WSH context. */
struct WshSatisfier: Satisfier<CPubKey> {
    explicit WshSatisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                          const BaseSignatureCreator& creator LIFETIMEBOUND, const CScript& witscript LIFETIMEBOUND)
                          : Satisfier(provider, sig_data, creator, witscript, miniscript::MiniscriptContext::P2WSH) {}

    //! Conversion from a raw public key.
    template <typename I>
    std::optional<CPubKey> FromPKBytes(I first, I last) const {
        CPubKey pubkey{first, last};
        if (pubkey.IsValid()) return pubkey;
        return {};
    }

    //! Conversion from a raw public key hash.
    template<typename I>
    std::optional<CPubKey> FromPKHBytes(I first, I last) const {
        return Satisfier::CPubFromPKHBytes(first, last);
    }

    //! Satisfy an Post Quantum signature check.
    miniscript::Availability Sign(const CPubKey& key, std::vector<unsigned char>& sig) const {
        if (CreateSig(m_creator, m_sig_data, m_provider, sig, key, m_witness_script, SigVersion::WITNESS_V0)) {
            return miniscript::Availability::YES;
        }
        return miniscript::Availability::NO;
    }
};

struct Wsh512Satisfier: Satisfier<CPubKey> {
    explicit Wsh512Satisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                             const BaseSignatureCreator& creator LIFETIMEBOUND, const CScript& witness_script)
        : Satisfier<CPubKey>(provider, sig_data, creator, witness_script, miniscript::MiniscriptContext::P2WSH) {}

    //! Conversion from a raw public key.
    template<typename I>
    std::optional<CPubKey> FromPKBytes(I first, I last) const {
        CPubKey pubkey{first, last};
        if (pubkey.IsValid()) return pubkey;
        return {};
    }

    //! Conversion from a raw public key hash.
    template<typename I>
    std::optional<CPubKey> FromPKHBytes(I first, I last) const {
        return Satisfier::CPubFromPKHBytes(first, last);
    }

    //! Satisfy an Post Quantum signature check.
    miniscript::Availability Sign(const CPubKey& key, std::vector<unsigned char>& sig) const {
        if (CreateSig(m_creator, m_sig_data, m_provider, sig, key, m_witness_script, SigVersion::WITNESS_V1_512)) {
            return miniscript::Availability::YES;
        }
        return miniscript::Availability::NO;
    }
};

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TxoutType::SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     std::vector<valtype>& ret, TxoutType& whichTypeRet, SigVersion sigversion, SignatureData& sigdata)
{
    CScript scriptRet;
    ret.clear();
    std::vector<unsigned char> sig;

    std::vector<valtype> vSolutions;
    whichTypeRet = Solver(scriptPubKey, vSolutions);

    switch (whichTypeRet) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
        return false;
    case TxoutType::PUBKEY:
        if (!CreateSig(creator, sigdata, provider, sig, CPubKey(vSolutions[0]), scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        return true;
    case TxoutType::PUBKEYHASH: {
        CKeyID keyID = CKeyID(uint160(vSolutions[0]));
        CPubKey pubkey;
        if (!GetPubKey(provider, sigdata, keyID, pubkey)) {
            // Pubkey could not be found, add to missing
            sigdata.missing_pubkeys.push_back(keyID);
            return false;
        }
        if (!CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        ret.push_back(ToByteVector(pubkey));
        return true;
    }
    case TxoutType::SCRIPTHASH: {
        uint160 h160{vSolutions[0]};
        if (GetCScript(provider, sigdata, CScriptID{h160}, scriptRet)) {
            ret.emplace_back(scriptRet.begin(), scriptRet.end());
            return true;
        }
        // Could not find redeemScript, add to missing
        sigdata.missing_redeem_script = h160;
        return false;
    }
    case TxoutType::MULTISIG: {
        size_t required = vSolutions.front()[0];
        ret.emplace_back(); // workaround CHECKMULTISIG bug
        for (size_t i = 1; i < vSolutions.size() - 1; ++i) {
            CPubKey pubkey = CPubKey(vSolutions[i]);
            // We need to always call CreateSig in order to fill sigdata with all
            // possible signatures that we can create. This will allow further PSBT
            // processing to work as it needs all possible signature and pubkey pairs
            if (CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) {
                if (ret.size() < required + 1) {
                    ret.push_back(std::move(sig));
                }
            }
        }
        bool ok = ret.size() == required + 1;
        for (size_t i = 0; i + ret.size() < required + 1; ++i) {
            ret.emplace_back();
        }
        return ok;
    }
    case TxoutType::WITNESS_V0_KEYHASH:
        ret.push_back(vSolutions[0]);
        return true;

    case TxoutType::WITNESS_V0_SCRIPTHASH:
        if (GetCScript(provider, sigdata, CScriptID{RIPEMD160(vSolutions[0])}, scriptRet)) {
            ret.emplace_back(scriptRet.begin(), scriptRet.end());
            return true;
        }
        // Could not find witnessScript, add to missing
        sigdata.missing_witness_script = vSolutions[0];
        return false;
    case TxoutType::WITNESS_V1_SCRIPTHASH_512: {
        // Provider keys differ from CScriptID(script) for witness v1. Check
        // the complete commitment, including for a script supplied by a PSBT.
        const auto matches = [&](const CScript& script) {
            return ToByteVector(WitnessV1ScriptHash512{script}) == vSolutions[0];
        };
        if (!provider.GetCScript(CScriptID{RIPEMD160(vSolutions[0])}, scriptRet) || !matches(scriptRet)) {
            scriptRet = sigdata.witness_script;
        }
        if (!matches(scriptRet)) {
            sigdata.missing_witness_script = vSolutions[0];
            return false;
        }
        ret.emplace_back(scriptRet.begin(), scriptRet.end());
        return true;
    }

    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    return ProduceSignature(provider, creator, fromPubKey, sigdata, STANDARD_SCRIPT_VERIFY_FLAGS);
}

bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata, unsigned int script_verify_flags)
{
    if (sigdata.complete) return true;

    std::vector<valtype> result;
    TxoutType whichType;
    bool solved = SignStep(provider, creator, fromPubKey, result, whichType, SigVersion::BASE, sigdata);
    bool P2SH = false;
    CScript subscript;

    if (solved && whichType == TxoutType::SCRIPTHASH)
    {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        subscript = CScript(result[0].begin(), result[0].end());
        sigdata.redeem_script = subscript;
        solved = solved && SignStep(provider, creator, subscript, result, whichType, SigVersion::BASE, sigdata) && whichType != TxoutType::SCRIPTHASH;
        P2SH = true;
    }

    if (solved && whichType == TxoutType::WITNESS_V0_KEYHASH)
    {
        CScript witnessscript;
        witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
        TxoutType subType;
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata);
        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    else if (solved && whichType == TxoutType::WITNESS_V0_SCRIPTHASH)
    {
        CScript witnessscript(result[0].begin(), result[0].end());
        sigdata.witness_script = witnessscript;

        TxoutType subType{TxoutType::NONSTANDARD};
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata) && subType != TxoutType::SCRIPTHASH && subType != TxoutType::WITNESS_V0_SCRIPTHASH && subType != TxoutType::WITNESS_V0_KEYHASH;

        // If we couldn't find a solution with the legacy satisfier, try satisfying the script using Miniscript.
        // Note we need to check if the result stack is empty before, because it might be used even if the Script
        // isn't fully solved. For instance the CHECKMULTISIG satisfaction in SignStep() pushes partial signatures
        // and the extractor relies on this behaviour to combine witnesses.
        if (!solved && result.empty()) {
            WshSatisfier ms_satisfier{provider, sigdata, creator, witnessscript};
            const auto ms = miniscript::FromScript(witnessscript, ms_satisfier);
            solved = ms && ms->Satisfy(ms_satisfier, result) == miniscript::Availability::YES;
        }
        result.emplace_back(witnessscript.begin(), witnessscript.end());

        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    else if (solved && whichType == TxoutType::WITNESS_V1_SCRIPTHASH_512)
    {
        CScript witnessscript(result[0].begin(), result[0].end());
        sigdata.witness_script = witnessscript;

        TxoutType subType{TxoutType::NONSTANDARD};
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V1_512, sigdata) &&
                          subType != TxoutType::SCRIPTHASH && subType != TxoutType::WITNESS_V0_SCRIPTHASH &&
                          subType != TxoutType::WITNESS_V0_KEYHASH && subType != TxoutType::WITNESS_V1_SCRIPTHASH_512;

        if (!solved && result.empty()) {
            Wsh512Satisfier ms_satisfier{provider, sigdata, creator, witnessscript};
            const auto ms = miniscript::FromScript(witnessscript, ms_satisfier);
            solved = ms && ms->Satisfy(ms_satisfier, result) == miniscript::Availability::YES;
        }
        result.emplace_back(witnessscript.begin(), witnessscript.end());

        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    if (!sigdata.witness) sigdata.scriptWitness.stack.clear();
    if (P2SH) {
        result.emplace_back(subscript.begin(), subscript.end());
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
    sigdata.complete = solved && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, script_verify_flags, creator.Checker());
    return sigdata.complete;
}

namespace {
class SignatureExtractorChecker final : public DeferringSignatureChecker
{
private:
    SignatureData& sigdata;

public:
    SignatureExtractorChecker(SignatureData& sigdata, BaseSignatureChecker& checker) : DeferringSignatureChecker(checker), sigdata(sigdata) {}

    bool CheckPostQuantumSignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        if (m_checker.CheckPostQuantumSignature(scriptSig, vchPubKey, scriptCode, sigversion)) {
            CPubKey pubkey(vchPubKey);
            sigdata.signatures.emplace(pubkey.GetID(), SigPair(pubkey, scriptSig));
            return true;
        }
        return false;
    }
};

struct Stacks
{
    std::vector<valtype> script;
    std::vector<valtype> witness;

    Stacks() = delete;
    Stacks(const Stacks&) = delete;
    explicit Stacks(const SignatureData& data) : witness(data.scriptWitness.stack) {
        EvalScript(script, data.scriptSig, 0, BaseSignatureChecker(), SigVersion::BASE);
    }
};
}

// Extracts signatures and scripts from incomplete scriptSigs. Please do not extend this, use PSBT instead
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout)
{
    return DataFromTransaction(tx, nIn, txout, STANDARD_SCRIPT_VERIFY_FLAGS);
}

SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout, unsigned int script_verify_flags, const PrecomputedTransactionData* txdata)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    data.scriptWitness = tx.vin[nIn].scriptWitness;
    Stacks stack(data);

    // Get signatures
    const bool allow_legacy = !(script_verify_flags & SCRIPT_VERIFY_PQ_STRICT);
    MutableTransactionSignatureChecker tx_checker = txdata ?
        MutableTransactionSignatureChecker{&tx, nIn, txout.nValue, *txdata, MissingDataBehavior::FAIL, allow_legacy} :
        MutableTransactionSignatureChecker{&tx, nIn, txout.nValue, MissingDataBehavior::FAIL, allow_legacy};
    SignatureExtractorChecker extractor_checker(data, tx_checker);
    if (VerifyScript(data.scriptSig, txout.scriptPubKey, &data.scriptWitness, script_verify_flags, extractor_checker)) {
        data.complete = true;
        return data;
    }

    // Get scripts
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType script_type = Solver(txout.scriptPubKey, solutions);
    SigVersion sigversion = SigVersion::BASE;
    CScript next_script = txout.scriptPubKey;

    if (script_type == TxoutType::SCRIPTHASH && !stack.script.empty() && !stack.script.back().empty()) {
        // Get the redeemScript
        CScript redeem_script(stack.script.back().begin(), stack.script.back().end());
        data.redeem_script = redeem_script;
        next_script = std::move(redeem_script);

        // Get redeemScript type
        script_type = Solver(next_script, solutions);
        stack.script.pop_back();
    }
    if (script_type == TxoutType::WITNESS_V0_SCRIPTHASH && !stack.witness.empty() && !stack.witness.back().empty()) {
        // Get the witnessScript
        CScript witness_script(stack.witness.back().begin(), stack.witness.back().end());
        data.witness_script = witness_script;
        next_script = std::move(witness_script);

        // Get witnessScript type
        script_type = Solver(next_script, solutions);
        stack.witness.pop_back();
        stack.script = std::move(stack.witness);
        stack.witness.clear();
        sigversion = SigVersion::WITNESS_V0;
    }
    if (script_type == TxoutType::WITNESS_V1_SCRIPTHASH_512 && !stack.witness.empty() && !stack.witness.back().empty()) {
        // Get the witnessScript for v1-512 spends.
        CScript witness_script(stack.witness.back().begin(), stack.witness.back().end());
        data.witness_script = witness_script;
        next_script = std::move(witness_script);

        // Get witnessScript type.
        script_type = Solver(next_script, solutions);
        stack.witness.pop_back();
        stack.script = std::move(stack.witness);
        stack.witness.clear();
        sigversion = SigVersion::WITNESS_V1_512;
    }
    if (script_type == TxoutType::MULTISIG && !stack.script.empty()) {
        // Build a map of pubkey -> signature by matching sigs to pubkeys:
        assert(solutions.size() > 1);
        unsigned int num_pubkeys = solutions.size()-2;
        unsigned int last_success_key = 0;
        for (const valtype& sig : stack.script) {
            for (unsigned int i = last_success_key; i < num_pubkeys; ++i) {
                const valtype& pubkey = solutions[i+1];
                // We either have a signature for this pubkey, or we have found a signature and it is valid
                if (data.signatures.count(CPubKey(pubkey).GetID()) || extractor_checker.CheckPostQuantumSignature(sig, pubkey, next_script, sigversion)) {
                    last_success_key = i + 1;
                    break;
                }
            }
        }
    }

    return data;
}

void UpdateInput(CTxIn& input, const SignatureData& data)
{
    input.scriptSig = data.scriptSig;
    input.scriptWitness = data.scriptWitness;
}

void SignatureData::MergeSignatureData(SignatureData sigdata)
{
    if (complete) return;
    if (sigdata.complete) {
        *this = std::move(sigdata);
        return;
    }
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    signatures.insert(std::make_move_iterator(sigdata.signatures.begin()), std::make_move_iterator(sigdata.signatures.end()));
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker final : public BaseSignatureChecker
{
public:
    DummySignatureChecker() = default;
    bool CheckPostQuantumSignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override { return sig.size() != 0; }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return true; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return true; }
};
}

const BaseSignatureChecker& DUMMY_CHECKER = DummySignatureChecker();

namespace {
size_t MaxKnownPqSigLenInScript()
{
    const pq::SchemeInfo* const schemes[] = {
        &pq::kFalcon512Info,
        &pq::kFalcon1024Info,
        &pq::kMLDSA44Info,
        &pq::kMLDSA65Info,
        &pq::kMLDSA87Info,
    };
    size_t max_len = 0;
    for (const auto* info : schemes) {
        max_len = std::max(max_len, pq::SigLenMaxInScript(*info));
    }
    return max_len;
}

class DummySignatureCreator final : public BaseSignatureCreator {
private:
    bool m_use_max = false;
public:
    explicit DummySignatureCreator(bool use_max) : m_use_max(use_max) {}
    const BaseSignatureChecker& Checker() const override { return DUMMY_CHECKER; }
    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const override
    {
        (void)scriptCode;
        (void)sigversion;
        size_t sig_len = 0;
        CPubKey pubkey;
        if (provider.GetPubKey(keyid, pubkey) && pubkey.IsValid()) {
            const auto* scheme = pq::SchemeFromPrefix(pubkey[0]);
            if (scheme) {
                sig_len = m_use_max ? pq::SigLenMaxInScript(*scheme) : pq::SigLenFixedInScript(*scheme);
            }
        }
        if (sig_len == 0) {
            sig_len = MaxKnownPqSigLenInScript();
        }
        vchSig.assign(sig_len, '\0');
        if (!vchSig.empty()) vchSig.back() = SIGHASH_ALL;
        return !vchSig.empty();
    }
};

} // namespace

const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR = DummySignatureCreator(/*use_max=*/false);
const BaseSignatureCreator& DUMMY_MAXIMUM_SIGNATURE_CREATOR = DummySignatureCreator(/*use_max=*/true);

bool IsSegWitOutput(const SigningProvider& provider, const CScript& script)
{
    int version;
    valtype program;
    if (script.IsWitnessProgram(version, program)) return true;
    if (script.IsPayToScriptHash()) {
        std::vector<valtype> solutions;
        auto whichtype = Solver(script, solutions);
        if (whichtype == TxoutType::SCRIPTHASH) {
            auto h160 = uint160(solutions[0]);
            CScript subscript;
            if (provider.GetCScript(CScriptID{h160}, subscript)) {
                if (subscript.IsWitnessProgram(version, program)) return true;
            }
        }
    }
    return false;
}

bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, bilingual_str>& input_errors)
{
    return SignTransaction(mtx, keystore, coins, nHashType, input_errors, STANDARD_SCRIPT_VERIFY_FLAGS);
}

bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, bilingual_str>& input_errors, unsigned int script_verify_flags, const std::set<COutPoint>* missing_amounts)
{
    const bool allow_legacy = !(script_verify_flags & SCRIPT_VERIFY_PQ_STRICT);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);

    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs;
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent() || (missing_amounts && missing_amounts->contains(txin.prevout))) {
            txdata.Init(txConst, /*spent_outputs=*/{}, /*force=*/true);
            break;
        } else {
            spent_outputs.emplace_back(coin->second.out.nValue, coin->second.out.scriptPubKey);
        }
    }
    if (spent_outputs.size() == mtx.vin.size()) {
        txdata.Init(txConst, std::move(spent_outputs), true);
    }

    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            input_errors[i] = _("Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coin->second.out.scriptPubKey;
        const bool amount_known = !missing_amounts || !missing_amounts->contains(txin.prevout);
        const CAmount amount = amount_known ? coin->second.out.nValue : -1;
        CTxOut signing_output{amount, prevPubKey};
        SignatureData sigdata = DataFromTransaction(mtx, i, signing_output, script_verify_flags, &txdata);
        MutableTransactionSignatureCreator creator(mtx, i, amount, &txdata, nHashType, allow_legacy);
        creator.SetAmountAvailability(!missing_amounts || !missing_amounts->contains(txin.prevout), txdata.m_spent_outputs_ready);
        ProduceSignature(*keystore, creator, prevPubKey, sigdata, script_verify_flags);
        if (creator.Error() != common::PSBTError::OK) {
            input_errors[i] = common::PSBTErrorString(creator.Error());
            continue;
        }
        // Preserve the original bytes, including foreign inputs and existing
        // signatures. Producing solving data can also produce placeholders.
        if (!SingleWithoutOutput(nHashType, i, mtx.vout.size())) UpdateInput(txin, sigdata);
        // A later manager without the key must not replace an earlier manager's
        // precise signing refusal with a generic incomplete-script diagnostic.
        if (const auto it = input_errors.find(i); it != input_errors.end()) {
            bool signing_refusal{false};
            for (auto error : {common::PSBTError::SINGLE_WITHOUT_OUTPUT, common::PSBTError::MISSING_AMOUNT,
                               common::PSBTError::MISSING_SPENT_AMOUNTS, common::PSBTError::SIGHASH_UNSUPPORTED,
                               common::PSBTError::SIGHASH_MISMATCH}) {
                signing_refusal |= it->second.original == common::PSBTErrorString(error).original;
            }
            if (signing_refusal) continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!sigdata.complete && !VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, script_verify_flags, TransactionSignatureChecker(&txConst, i, amount, txdata, MissingDataBehavior::FAIL, allow_legacy), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                input_errors[i] = Untranslated("Unable to sign input, invalid stack size (possibly missing key)");
            } else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                // Verification failed (possibly due to insufficient signatures).
                input_errors[i] = Untranslated("CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)");
            } else {
                input_errors[i] = Untranslated(ScriptErrorString(serror));
            }
        } else {
            // If this input succeeds, make sure there is no error set for it
            input_errors.erase(i);
        }
    }
    return input_errors.empty();
}
