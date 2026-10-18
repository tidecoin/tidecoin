// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <node/types.h>
#include <outputtype.h>
#include <policy/policy.h>
#include <pq/pqhd_kdf.h>
#include <pq/pq_scheme.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/solver.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>

#include <optional>
#include <set>

using common::PSBTError;

namespace wallet {

namespace {
struct PQHDWalletSigningProvider final : public SigningProvider {
    const WalletStorage& storage;
    const FlatSigningProvider& base;

    explicit PQHDWalletSigningProvider(const WalletStorage& storage_in, const FlatSigningProvider& base_in)
        : storage(storage_in), base(base_in) {}

    bool GetCScript(const CScriptID& scriptid, CScript& script) const override { return base.GetCScript(scriptid, script); }
    bool HaveCScript(const CScriptID& scriptid) const override { return base.scripts.find(scriptid) != base.scripts.end(); }
    bool GetPubKey(const CKeyID& address, CPubKey& pubkey) const override { return base.GetPubKey(address, pubkey); }
    bool GetKey(const CKeyID& address, CKey& key) const override { return base.GetKey(address, key); }
    bool HaveKey(const CKeyID& address) const override { return base.keys.find(address) != base.keys.end(); }
    std::optional<pqhd::SecureSeed32> GetPQHDSeed(const uint256& seed_id) const override { return storage.GetPQHDSeed(seed_id); }
};

} // namespace

typedef std::vector<unsigned char> valtype;

// Legacy wallet IsMine(). Used only in migration
// DO NOT USE ANYTHING IN THIS NAMESPACE OUTSIDE OF MIGRATION
namespace {

/**
 * This is an enum that tracks the execution context of a script, similar to
 * SigVersion in script/interpreter. It is separate however because we want to
 * distinguish between top-level scriptPubKey execution and P2SH redeemScript
 * execution (a distinction that has no impact on consensus rules).
 */
enum class IsMineSigVersion
{
    TOP = 0,        //!< scriptPubKey execution
    P2SH = 1,       //!< P2SH redeemScript
    WITNESS_V0 = 2, //!< P2WSH witness script execution
};

/**
 * This is an internal representation of isminetype + invalidity.
 * Its order is significant, as we return the max of all explored
 * possibilities.
 */
enum class IsMineResult
{
    NO = 0,         //!< Not ours
    WATCH_ONLY = 1, //!< Included in watch-only balance
    SPENDABLE = 2,  //!< Included in all balances
    INVALID = 3,    //!< Not spendable by anyone (P2SH inside P2SH or witness, witness inside witness)
};

bool HaveKeys(const std::vector<valtype>& pubkeys, const LegacyDataSPKM& keystore)
{
    for (const valtype& pubkey : pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (!keystore.HaveKey(keyID)) return false;
    }
    return true;
}

//! Recursively solve script and return spendable/watchonly/invalid status.
//!
//! @param keystore            legacy key and script store
//! @param scriptPubKey        script to solve
//! @param sigversion          script type (top-level / redeemscript / witnessscript)
//! @param recurse_scripthash  whether to recurse into nested p2sh and p2wsh
//!                            scripts or simply treat any script that has been
//!                            stored in the keystore as spendable
// NOLINTNEXTLINE(misc-no-recursion)
IsMineResult LegacyWalletIsMineInnerDONOTUSE(const LegacyDataSPKM& keystore, const CScript& scriptPubKey, IsMineSigVersion sigversion, bool recurse_scripthash=true)
{
    IsMineResult ret = IsMineResult::NO;

    std::vector<valtype> vSolutions;
    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    CKeyID keyID;
    switch (whichType) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
        break;
    case TxoutType::PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::WITNESS_V0_KEYHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WPKH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            // We do not support bare witness outputs unless the P2SH version of it would be
            // acceptable as well. This protects against matching before segwit activates.
            // This also applies to the P2WSH case.
            break;
        }
        ret = std::max(ret, LegacyWalletIsMineInnerDONOTUSE(keystore, GetScriptForDestination(PKHash(uint160(vSolutions[0]))), IsMineSigVersion::WITNESS_V0));
        break;
    }
    case TxoutType::PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::SCRIPTHASH:
    {
        if (sigversion != IsMineSigVersion::TOP) {
            // P2SH inside P2WSH or P2SH is invalid.
            return IsMineResult::INVALID;
        }
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? LegacyWalletIsMineInnerDONOTUSE(keystore, subscript, IsMineSigVersion::P2SH) : IsMineResult::SPENDABLE);
        }
        break;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WSH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            break;
        }
        CScriptID scriptID{RIPEMD160(vSolutions[0])};
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? LegacyWalletIsMineInnerDONOTUSE(keystore, subscript, IsMineSigVersion::WITNESS_V0) : IsMineResult::SPENDABLE);
        }
        break;
    }
    case TxoutType::WITNESS_V1_SCRIPTHASH_512:
        // Legacy wallets do not support v1 witness scripts; descriptor wallets handle this.
        break;

    case TxoutType::MULTISIG:
    {
        // Never treat bare multisig outputs as ours (they can still be made watchonly-though)
        if (sigversion == IsMineSigVersion::TOP) {
            break;
        }

        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        std::vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (HaveKeys(keys, keystore)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    }
    } // no default case, so the compiler can warn about missing cases

    if (ret == IsMineResult::NO && keystore.HaveWatchOnly(scriptPubKey)) {
        ret = std::max(ret, IsMineResult::WATCH_ONLY);
    }
    return ret;
}

} // namespace

bool LegacyDataSPKM::IsMine(const CScript& script) const
{
    switch (LegacyWalletIsMineInnerDONOTUSE(*this, script, IsMineSigVersion::TOP)) {
    case IsMineResult::INVALID:
    case IsMineResult::NO:
        return false;
    case IsMineResult::WATCH_ONLY:
    case IsMineResult::SPENDABLE:
        return true;
    }
    assert(false);
}

bool LegacyDataSPKM::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    {
        LOCK(cs_KeyStore);
        assert(mapKeys.empty());

        bool keyPass = mapCryptedKeys.empty(); // Always pass when there are no encrypted keys
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        WalletBatch batch(m_storage.GetDatabase());
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(master_key, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
            else {
                // Rewrite these encrypted keys with checksums
                batch.WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
            }
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
        }
        if (keyFail || !keyPass)
            return false;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

std::unique_ptr<SigningProvider> LegacyDataSPKM::GetSolvingProvider(const CScript& script) const
{
    return std::make_unique<LegacySigningProvider>(*this);
}

bool LegacyDataSPKM::CanProvide(const CScript& script, SignatureData& sigdata)
{
    IsMineResult ismine = LegacyWalletIsMineInnerDONOTUSE(*this, script, IsMineSigVersion::TOP, /* recurse_scripthash= */ false);
    if (ismine == IsMineResult::SPENDABLE || ismine == IsMineResult::WATCH_ONLY) {
        // If ismine, it means we recognize keys or script ids in the script, or
        // are watching the script itself, and we can at least provide metadata
        // or solving information, even if not able to sign fully.
        return true;
    } else {
        // If, given the stuff in sigdata, we could make a valid signature, then we can provide for this script
        ProduceSignature(*this, DUMMY_SIGNATURE_CREATOR, script, sigdata);
        if (!sigdata.signatures.empty()) {
            // If we could make signatures, make sure we have a private key to actually make a signature
            bool has_privkeys = false;
            for (const auto& key_sig_pair : sigdata.signatures) {
                has_privkeys |= HaveKey(key_sig_pair.first);
            }
            return has_privkeys;
        }
        return false;
    }
}

bool LegacyDataSPKM::LoadKey(const CKey& key, const CPubKey &pubkey)
{
    return AddKeyPubKeyInner(key, pubkey);
}

bool LegacyDataSPKM::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(ScriptHash(redeemScript));
        WalletLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n", __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return FillableSigningProvider::AddCScript(redeemScript);
}

void LegacyDataSPKM::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    mapKeyMetadata[keyID] = meta;
}

void LegacyDataSPKM::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    m_script_metadata[script_id] = meta;
}

bool LegacyDataSPKM::AddKeyPubKeyInner(const CKey& key, const CPubKey& pubkey)
{
    LOCK(cs_KeyStore);
    return FillableSigningProvider::AddKeyPubKey(key, pubkey);
}

bool LegacyDataSPKM::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret, bool checksum_valid)
{
    // Set fDecryptionThoroughlyChecked to false when the checksum is invalid
    if (!checksum_valid) {
        fDecryptionThoroughlyChecked = false;
    }

    return AddCryptedKeyInner(vchPubKey, vchCryptedSecret);
}

bool LegacyDataSPKM::AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    assert(mapKeys.empty());

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

bool LegacyDataSPKM::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool LegacyDataSPKM::LoadWatchOnly(const CScript &dest)
{
    return AddWatchOnlyInMem(dest);
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    std::vector<std::vector<unsigned char>> solutions;
    return Solver(dest, solutions) == TxoutType::PUBKEY &&
        (pubKeyOut = CPubKey(solutions[0])).IsFullyValid();
}

bool LegacyDataSPKM::AddWatchOnlyInMem(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) {
        mapWatchKeys[pubKey.GetID()] = pubKey;
        ImplicitlyLearnRelatedKeyScripts(pubKey);
    }
    return true;
}

bool LegacyDataSPKM::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::HaveKey(address);
    }
    return mapCryptedKeys.count(address) > 0;
}

bool LegacyDataSPKM::GetKey(const CKeyID &address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        return m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            return DecryptKey(encryption_key, vchCryptedSecret, vchPubKey, keyOut);
        });
    }
    return false;
}

bool LegacyDataSPKM::GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const
{
    LOCK(cs_KeyStore);
    WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
    if (it != mapWatchKeys.end()) {
        pubkey_out = it->second;
        return true;
    }
    return false;
}

bool LegacyDataSPKM::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        if (!FillableSigningProvider::GetPubKey(address, vchPubKeyOut)) {
            return GetWatchPubKey(address, vchPubKeyOut);
        }
        return true;
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        vchPubKeyOut = (*mi).second.first;
        return true;
    }
    // Check for watch-only pubkeys
    return GetWatchPubKey(address, vchPubKeyOut);
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetCandidateScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<CScript, SaltedSipHasher> candidate_spks;

    // For every private key in the wallet, there should be a P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH
    const auto& add_pubkey = [&candidate_spks](const CPubKey& pub) -> void {
        candidate_spks.insert(GetScriptForRawPubKey(pub));
        candidate_spks.insert(GetScriptForDestination(PKHash(pub)));

        CScript wpkh = GetScriptForDestination(WitnessV0KeyHash(pub));
        candidate_spks.insert(wpkh);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(wpkh)));
    };
    for (const auto& [_, key] : mapKeys) {
        add_pubkey(key.GetPubKey());
    }
    for (const auto& [_, ckeypair] : mapCryptedKeys) {
        add_pubkey(ckeypair.first);
    }

    // mapScripts contains all redeemScripts and witnessScripts. Therefore each script in it has
    // itself, P2SH, P2WSH, and P2SH-P2WSH as a candidate.
    // Invalid scripts such as P2SH-P2SH and P2WSH-P2SH, among others, will be added as candidates.
    // Callers of this function will need to remove such scripts.
    const auto& add_script = [&candidate_spks](const CScript& script) -> void {
        candidate_spks.insert(script);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(script)));

        CScript wsh = GetScriptForDestination(WitnessV0ScriptHash(script));
        candidate_spks.insert(wsh);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(wsh)));
    };
    for (const auto& [_, script] : mapScripts) {
        add_script(script);
    }

    // Although setWatchOnly should only contain output scripts, we will also include each script's
    // P2SH, P2WSH, and P2SH-P2WSH as a precaution.
    for (const auto& script : setWatchOnly) {
        add_script(script);
    }

    return candidate_spks;
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetScriptPubKeys() const
{
    // Run IsMine() on each candidate output script. Any script that IsMine is an output
    // script to return.
    // This both filters out things that are not watched by the wallet, and things that are invalid.
    std::unordered_set<CScript, SaltedSipHasher> spks;
    for (const CScript& script : GetCandidateScriptPubKeys()) {
        if (IsMine(script)) {
            spks.insert(script);
        }
    }

    return spks;
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetNotMineScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<CScript, SaltedSipHasher> spks;
    for (const CScript& script : setWatchOnly) {
        if (!IsMine(script)) spks.insert(script);
    }
    return spks;
}

std::optional<MigrationData> LegacyDataSPKM::MigrateToDescriptor()
{
    LOCK(cs_KeyStore);
    if (m_storage.IsLocked()) {
        return std::nullopt;
    }

    MigrationData out;

    std::unordered_set<CScript, SaltedSipHasher> spks{GetScriptPubKeys()};

    // Get all key ids
    std::set<CKeyID> keyids;
    for (const auto& key_pair : mapKeys) {
        keyids.insert(key_pair.first);
    }
    for (const auto& key_pair : mapCryptedKeys) {
        keyids.insert(key_pair.first);
    }

    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.TxnBegin()) {
        LogPrintf("Error generating descriptors for migration, cannot initialize db transaction\n");
        return std::nullopt;
    }

    // keyids is now all non-HD keys. Each key will have its own combo descriptor
    for (const CKeyID& keyid : keyids) {
        CKey key;
        if (!GetKey(keyid, key)) {
            assert(false);
        }

        // Get birthdate from key meta
        uint64_t creation_time = 0;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // Construct the combo descriptor
        std::string desc_str = "combo(" + HexStr(key.GetPubKey()) + ")";
        FlatSigningProvider keys;
        std::string error;
        std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, error, false);
        CHECK_NONFATAL(descs.size() == 1); // It shouldn't be possible to have an invalid or multipath descriptor
        WalletDescriptor w_desc(std::move(descs.at(0)), creation_time, 0, 0, 0);

        // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
        auto desc_spk_man = std::make_unique<DescriptorScriptPubKeyMan>(m_storage, w_desc, /*keypool_size=*/0);
        if (!WITH_LOCK(desc_spk_man->cs_desc_man, return desc_spk_man->AddDescriptorKeyWithDB(batch, key, key.GetPubKey()))) {
            batch.TxnAbort();
            return std::nullopt;
        }
        if (!desc_spk_man->TopUpWithDB(batch)) {
            batch.TxnAbort();
            return std::nullopt;
        }
        auto desc_spks = desc_spk_man->GetScriptPubKeys();

        // Remove the scriptPubKeys from our current set
        for (const CScript& spk : desc_spks) {
            size_t erased = spks.erase(spk);
            assert(erased == 1);
            assert(IsMine(spk));
        }

        out.desc_spkms.push_back(std::move(desc_spk_man));
    }

    // Handle the rest of the scriptPubKeys which must be imports and may not have all info
    for (auto it = spks.begin(); it != spks.end();) {
        const CScript& spk = *it;

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& mit = m_script_metadata.find(CScriptID(spk));
        if (mit != m_script_metadata.end()) {
            creation_time = mit->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(spk, *GetSolvingProvider(spk));

        // Past bugs in InferDescriptor have caused it to create descriptors which cannot be re-parsed.
        // Re-parse the descriptors to detect that, and skip any that do not parse.
        {
            std::string desc_str = desc->ToString();
            FlatSigningProvider parsed_keys;
            std::string parse_error;
            std::vector<std::unique_ptr<Descriptor>> parsed_descs = Parse(desc_str, parsed_keys, parse_error);
            if (parsed_descs.empty()) {
                // Remove this scriptPubKey from the set
                it = spks.erase(it);
                continue;
            }
        }

        // Get the private keys for this descriptor
        std::vector<CScript> scripts;
        FlatSigningProvider keys;
        if (!desc->Expand(0, DUMMY_SIGNING_PROVIDER, scripts, keys)) {
            assert(false);
        }
        std::set<CKeyID> privkeyids;
        for (const auto& key_pair : keys.pubkeys) {
            privkeyids.insert(key_pair.first);
        }

        std::vector<CScript> desc_spks;

        // Make the descriptor string with private keys
        std::string desc_str;
        bool watchonly = !desc->ToPrivateString(*this, desc_str);
        if (watchonly && !m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            out.watch_descs.emplace_back(desc->ToString(), creation_time);

            // Get the scriptPubKeys without writing this to the wallet
            FlatSigningProvider provider;
            desc->Expand(0, provider, desc_spks, provider);
        } else {
            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
            auto desc_spk_man = std::make_unique<DescriptorScriptPubKeyMan>(m_storage, w_desc, /*keypool_size=*/0);
            for (const auto& keyid : privkeyids) {
                CKey key;
                if (!GetKey(keyid, key)) {
                    continue;
                }
                if (!WITH_LOCK(desc_spk_man->cs_desc_man, return desc_spk_man->AddDescriptorKeyWithDB(batch, key, key.GetPubKey()))) {
                    batch.TxnAbort();
                    return std::nullopt;
                }
            }
            if (!desc_spk_man->TopUpWithDB(batch)) {
                batch.TxnAbort();
                return std::nullopt;
            }
            auto desc_spks_set = desc_spk_man->GetScriptPubKeys();
            desc_spks.insert(desc_spks.end(), desc_spks_set.begin(), desc_spks_set.end());

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }

        // Remove the scriptPubKeys from our current set
        for (const CScript& desc_spk : desc_spks) {
            auto del_it = spks.find(desc_spk);
            assert(del_it != spks.end());
            assert(IsMine(desc_spk));
            it = spks.erase(del_it);
        }
    }

    // Make sure that we have accounted for all scriptPubKeys
    if (!Assume(spks.empty())) {
        LogPrintf("%s\n", STR_INTERNAL_BUG("Error: Some output scripts were not migrated.\n"));
        return std::nullopt;
    }

    // Legacy wallets can also contain scripts whose P2SH, P2WSH, or P2SH-P2WSH it is not watching for
    // but can provide script data to a PSBT spending them. These "solvable" output scripts will need to
    // be put into the separate "solvables" wallet.
    // These can be detected by going through the entire candidate output scripts, finding the not IsMine scripts,
    // and checking CanProvide() which will dummy sign.
    for (const CScript& script : GetCandidateScriptPubKeys()) {
        // Since we only care about P2SH, P2WSH, and P2SH-P2WSH, filter out any scripts that are not those
        if (!script.IsPayToScriptHash() && !script.IsPayToWitnessScriptHash()) {
            continue;
        }
        if (IsMine(script)) {
            continue;
        }
        SignatureData dummy_sigdata;
        if (!CanProvide(script, dummy_sigdata)) {
            continue;
        }

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& it = m_script_metadata.find(CScriptID(script));
        if (it != m_script_metadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(script, *GetSolvingProvider(script));
        if (!desc->IsSolvable()) {
            // The wallet was able to provide some information, but not enough to make a descriptor that actually
            // contains anything useful. This is probably because the script itself is actually unsignable (e.g. P2WSH-P2WSH).
            continue;
        }

        // Past bugs in InferDescriptor have caused it to create descriptors which cannot be re-parsed
        // Re-parse the descriptors to detect that, and skip any that do not parse.
        {
            std::string desc_str = desc->ToString();
            FlatSigningProvider parsed_keys;
            std::string parse_error;
            std::vector<std::unique_ptr<Descriptor>> parsed_descs = Parse(desc_str, parsed_keys, parse_error, false);
            if (parsed_descs.empty()) {
                continue;
            }
        }

        out.solvable_descs.emplace_back(desc->ToString(), creation_time);
    }

    // Finalize transaction
    if (!batch.TxnCommit()) {
        LogPrintf("Error generating descriptors for migration, cannot commit db transaction\n");
        return std::nullopt;
    }

    return out;
}

bool LegacyDataSPKM::DeleteRecordsWithDB(WalletBatch& batch)
{
    LOCK(cs_KeyStore);
    return batch.EraseRecords(DBKeys::LEGACY_TYPES);
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetNewDestination(const OutputType type)
{
    if (m_storage.IsWalletRecoveryRequired()) {
        return util::Error{_("Wallet update failed. Restore database access and reload the wallet to recover before issuing addresses.")};
    }
    // Returns true if this descriptor supports getting new addresses. Conditions where we may be unable to fetch them (e.g. locked) are caught later
    if (!CanGetAddresses()) {
        return util::Error{_("No addresses available")};
    }
    {
        LOCK(cs_desc_man);
        assert(m_wallet_descriptor.descriptor->IsSingleType()); // This is a combo descriptor which should not be an active descriptor
        std::optional<OutputType> desc_addr_type = m_wallet_descriptor.descriptor->GetOutputType();
        assert(desc_addr_type);
        if (type != *desc_addr_type) {
            throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
        }

        const int target_height = m_storage.GetTargetHeightForOutputs();
        if (type == OutputType::BECH32PQ && target_height < Params().GetConsensus().nAuxpowStartHeight) {
            return util::Error{strprintf(_("PQ v1 outputs not allowed at height %i"), target_height)};
        }

        // A custom active descriptor may contain several schemes. Checking an
        // optional single scheme would skip mixed descriptors entirely.
        std::set<uint8_t> scheme_prefixes;
        for (const auto& [expression, info] : m_wallet_descriptor.descriptor->GetPQHDKeyPaths()) {
            scheme_prefixes.insert(info.path.at(2) & 0x7fffffffU);
        }
        std::set<CPubKey> explicit_keys;
        m_wallet_descriptor.descriptor->GetPubKeys(explicit_keys);
        for (const auto& pubkey : explicit_keys) scheme_prefixes.insert(pubkey[0]);
        for (const uint8_t prefix : scheme_prefixes) {
            const auto* scheme = pq::SchemeFromPrefix(prefix);
            if (!scheme || !pq::IsSchemeAllowedAtHeight(scheme->id, Params().GetConsensus(), target_height)) {
                return util::Error{strprintf(_("Descriptor key scheme %i not allowed at height %i"), prefix, target_height)};
            }
        }

        if (!IsCacheUsable()) return util::Error{_("PQHD cache does not match wallet seed; wallet may be corrupted")};
        TopUp();

        // Get the scriptPubKey from the descriptor
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (m_wallet_descriptor.next_index >= m_wallet_descriptor.range_end && !TopUp(1)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }
        if (m_wallet_descriptor.next_index >= m_wallet_descriptor.range_end ||
            !m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.next_index, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }

        CTxDestination dest;
        if (!ExtractDestination(scripts_temp[0], dest)) {
            return util::Error{_("Error: Cannot extract destination from the generated scriptpubkey")}; // shouldn't happen
        }
        m_wallet_descriptor.next_index++;
        if (!WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor)) {
            --m_wallet_descriptor.next_index;
            return util::Error{_("Error: Cannot persist address reservation")};
        }
        return dest;
    }
}

bool DescriptorScriptPubKeyMan::IsMine(const CScript& script) const
{
    LOCK(cs_desc_man);
    return m_map_script_pub_keys.contains(script);
}

bool DescriptorScriptPubKeyMan::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty()) {
        return false;
    }

    bool keyPass = m_map_crypted_keys.empty(); // Always pass when there are no encrypted keys
    bool keyFail = false;
    for (const auto& mi : m_map_crypted_keys) {
        const CPubKey &pubkey = mi.second.first;
        const std::vector<unsigned char> &crypted_secret = mi.second.second;
        CKey key;
        if (!DecryptKey(master_key, crypted_secret, pubkey, key)) {
            keyFail = true;
            break;
        }
        keyPass = true;
        if (m_decryption_thoroughly_checked)
            break;
    }
    if (keyPass && keyFail) {
        LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
        throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
    }
    if (keyFail || !keyPass) {
        return false;
    }
    m_decryption_thoroughly_checked = true;
    return true;
}

bool DescriptorScriptPubKeyMan::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_desc_man);
    if (!m_map_crypted_keys.empty()) {
        return false;
    }

    CryptedKeyMap encrypted_keys;
    for (const KeyMap::value_type& key_in : m_map_keys)
    {
        const CKey &key = key_in.second;
        CPubKey pubkey = key.GetPubKey();
        CKeyingMaterial secret{UCharCast(key.begin()), UCharCast(key.end())};
        std::vector<unsigned char> crypted_secret;
        if (!EncryptSecret(master_key, secret, pubkey.GetHash(), crypted_secret)) {
            return false;
        }
        if (!batch->WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret)) return false;
        encrypted_keys.emplace(pubkey.GetID(), std::make_pair(pubkey, std::move(crypted_secret)));
    }
    batch->RegisterTxnListener({
        .on_commit = [this, keys = std::move(encrypted_keys)]() mutable {
            LOCK(cs_desc_man);
            m_map_crypted_keys = std::move(keys);
            m_map_keys.clear();
        },
        .on_abort = {},
    });
    return true;
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, int64_t& index)
{
    LOCK(cs_desc_man);
    auto op_dest = GetNewDestination(type);
    index = m_wallet_descriptor.next_index - 1;
    return op_dest;
}

void DescriptorScriptPubKeyMan::ReturnDestination(int64_t index, bool internal, const CTxDestination& addr)
{
    LOCK(cs_desc_man);
    // Do not move a consumed index backwards after an unsuccessful observation.
    if (m_storage.IsWalletRecoveryRequired()) return;
    if (index < m_wallet_descriptor.range_start || index >= m_wallet_descriptor.range_end) return;
    const auto previous_next = m_wallet_descriptor.next_index;
    // Only return when the index was the most recent
    if (m_wallet_descriptor.next_index - 1 == index) {
        m_wallet_descriptor.next_index--;
    }
    if (!WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor)) {
        // ReturnDestination can run from a reservation destructor. Keep the
        // address reserved on failure instead of throwing or making it reusable.
        m_wallet_descriptor.next_index = previous_next;
        WalletLogPrintf("%s: Cannot persist returned address; keeping it reserved\n", __func__);
        return;
    }
    NotifyCanGetAddressesChanged();
}

std::map<CKeyID, CKey> DescriptorScriptPubKeyMan::GetKeys() const
{
    AssertLockHeld(cs_desc_man);
    if (m_storage.HasEncryptionKeys() && !m_storage.IsLocked()) {
        KeyMap keys;
        for (const auto& key_pair : m_map_crypted_keys) {
            const CPubKey& pubkey = key_pair.second.first;
            const std::vector<unsigned char>& crypted_secret = key_pair.second.second;
            CKey key;
            m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                return DecryptKey(encryption_key, crypted_secret, pubkey, key);
            });
            keys[pubkey.GetID()] = key;
        }
        return keys;
    }
    return m_map_keys;
}

bool DescriptorScriptPubKeyMan::HasPrivKey(const CKeyID& keyid) const
{
    AssertLockHeld(cs_desc_man);
    return m_map_keys.contains(keyid) || m_map_crypted_keys.contains(keyid);
}

std::optional<CKey> DescriptorScriptPubKeyMan::GetKey(const CKeyID& keyid) const
{
    if (m_storage.HasEncryptionKeys()) {
        std::optional<std::pair<CPubKey, std::vector<unsigned char>>> crypted_key;
        {
            LOCK(cs_desc_man);
            const auto& it = m_map_crypted_keys.find(keyid);
            if (it == m_map_crypted_keys.end()) {
                return std::nullopt;
            }
            crypted_key.emplace(it->second.first, it->second.second);
        }
        if (m_storage.IsLocked()) {
            return std::nullopt;
        }
        CKey key;
        if (!Assume(m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            return DecryptKey(encryption_key, crypted_key->second, crypted_key->first, key);
        }))) {
            return std::nullopt;
        }
        return key;
    }

    LOCK(cs_desc_man);
    const auto& it = m_map_keys.find(keyid);
    if (it != m_map_keys.end()) {
        return it->second;
    }
    return std::nullopt;
}

void DescriptorScriptPubKeyMan::RegisterMutationRollback(WalletBatch& batch)
{
    AssertLockHeld(cs_desc_man);
    assert(batch.HasActiveTxn());
    if (!m_mutation_batches.insert(&batch).second) return;
    const std::weak_ptr<int> lifetime{m_lifetime};
    batch.RegisterTxnListener({
        .on_commit = [this, lifetime, ptr = &batch]() {
            if (lifetime.expired()) return;
            LOCK(cs_desc_man);
            m_mutation_batches.erase(ptr);
        },
        .on_abort = [this, lifetime, ptr = &batch, descriptor = m_wallet_descriptor,
                     scripts = m_map_script_pub_keys, pubkeys = m_map_pubkeys,
                     keys = m_map_keys, crypted = m_map_crypted_keys,
                     providers = m_map_signing_providers, max_index = m_max_cached_index, cache_state = m_cache_state]() mutable {
            if (lifetime.expired()) return;
            LOCK(cs_desc_man);
            m_wallet_descriptor = std::move(descriptor);
            m_map_script_pub_keys = std::move(scripts);
            m_map_pubkeys = std::move(pubkeys);
            m_map_keys = std::move(keys);
            m_map_crypted_keys = std::move(crypted);
            m_map_signing_providers = std::move(providers);
            m_max_cached_index = max_index;
            // Rolling back a mutation cannot undo discovery of a mismatch.
            if (m_cache_state != CacheState::INVALID) m_cache_state = cache_state;
            m_mutation_batches.erase(ptr);
        },
    });
}

bool DescriptorScriptPubKeyMan::TopUp(unsigned int size)
{
    LOCK(cs_desc_man);
    return RunWithinTxn(m_storage.GetDatabase(), "descriptor keypool top up", [&](WalletBatch& batch) {
        return TopUpWithDB(batch, size);
    });
}

bool DescriptorScriptPubKeyMan::TopUpWithDB(WalletBatch& batch, unsigned int size, bool expand_range)
{
    LOCK(cs_desc_man);
    assert(batch.HasActiveTxn());
    if (!m_wallet_descriptor.HasValidRange() || !IsCacheUsable()) return false;
    const int64_t target_size = expand_range ? (size > 0 ? size : m_keypool_size) : 0;
    if (target_size < 0 || target_size > std::numeric_limits<int32_t>::max()) return false;
    RegisterMutationRollback(batch);
    m_max_cached_index = std::max(m_max_cached_index, m_wallet_descriptor.range_start - 1);
    std::set<CScript> new_spks;
    const int32_t new_range_end = m_wallet_descriptor.descriptor->IsRange()
        ? std::max(m_wallet_descriptor.range_end, static_cast<int32_t>(std::min<int64_t>(
              int64_t{m_wallet_descriptor.next_index} + target_size, std::numeric_limits<int32_t>::max())))
        : 1;
    if (!m_wallet_descriptor.descriptor->IsRange()) m_wallet_descriptor.range_start = 0;

    FlatSigningProvider base_provider;
    base_provider.keys = GetKeys();
    const PQHDWalletSigningProvider provider{m_storage, base_provider};

    uint256 id = GetID();
    for (int32_t i = std::max(m_wallet_descriptor.range_start, m_max_cached_index + 1); i < new_range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        DescriptorCache temp_cache;
        // Expand from cache if available to avoid re-deriving scripts.
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            if (!m_wallet_descriptor.descriptor->Expand(i, provider, scripts_temp, out_keys, &temp_cache)) return false;
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        new_spks.insert(scripts_temp.begin(), scripts_temp.end());
        for (const CScript& script : scripts_temp) {
            m_map_script_pub_keys[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.count(pubkey) != 0) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and its private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        // Merge and write the cache
        DescriptorCache new_items = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
        if (!batch.WriteDescriptorCacheItems(id, new_items)) {
            throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
        }
        m_max_cached_index = i;
        m_storage.WalletCreationProgressStep();
    }
    m_wallet_descriptor.range_end = new_range_end;
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // By this point, the cache size should be the size of the entire range
    assert(m_wallet_descriptor.range_end - 1 == m_max_cached_index);

    if (batch.HasActiveTxn()) {
        batch.RegisterTxnListener({
            .on_commit = [this, lifetime = std::weak_ptr<int>{m_lifetime}, new_spks = std::move(new_spks)]() {
                if (lifetime.expired()) return;
                m_storage.TopUpCallback(new_spks, this);
                NotifyCanGetAddressesChanged();
            },
            .on_abort = {},
        });
    } else {
        m_storage.TopUpCallback(new_spks, this);
        NotifyCanGetAddressesChanged();
    }
    return true;
}

std::vector<WalletDestination> DescriptorScriptPubKeyMan::MarkUnusedAddresses(const CScript& script)
{
    LOCK(cs_desc_man);
    std::vector<WalletDestination> result;
    if (IsMine(script)) try {
        int32_t index = m_map_script_pub_keys[script];
        if (index >= m_wallet_descriptor.next_index) {
            WalletLogPrintf("%s: Detected a used keypool item at index %d, mark all keypool items up to this item as used\n", __func__, index);
            auto out_keys = std::make_unique<FlatSigningProvider>();
            std::vector<CScript> scripts_temp;
            while (index >= m_wallet_descriptor.next_index) {
                if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.next_index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) {
                    throw std::runtime_error(std::string(__func__) + ": Unable to expand descriptor from cache");
                }
                CTxDestination dest;
                ExtractDestination(scripts_temp[0], dest);
                result.push_back({dest, std::nullopt});
                m_wallet_descriptor.next_index++;
            }
        }
        // Consumption must be durable even when replenishing the cache requires
        // a locked seed. Keep the advanced in-memory index on a write failure
        // and propagate the error before the incoming transaction is recorded.
        // Write on retries too, even if this index is already consumed in memory.
        WriteDescriptor();
        if (!TopUp()) {
            WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
        }
    } catch (...) {
        m_storage.RequireWalletRecovery();
        throw;
    }

    return result;
}

void DescriptorScriptPubKeyMan::AddDescriptorKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!AddDescriptorKeyWithDB(batch, key, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor private key failed");
    }
}

bool DescriptorScriptPubKeyMan::AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey)
{
    AssertLockHeld(cs_desc_man);
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    // Check if provided key already exists
    if (m_map_keys.find(pubkey.GetID()) != m_map_keys.end() ||
        m_map_crypted_keys.find(pubkey.GetID()) != m_map_crypted_keys.end()) {
        return true;
    }

    if (m_storage.HasEncryptionKeys()) {
        if (m_storage.IsLocked()) {
            return false;
        }

        std::vector<unsigned char> crypted_secret;
        CKeyingMaterial secret{UCharCast(key.begin()), UCharCast(key.end())};
        if (!m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                return EncryptSecret(encryption_key, secret, pubkey.GetHash(), crypted_secret);
            })) {
            return false;
        }

        if (!batch.WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret)) return false;
        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, std::move(crypted_secret));
    } else {
        if (!batch.WriteDescriptorKey(GetID(), pubkey, key.GetPrivKey())) return false;
        m_map_keys[pubkey.GetID()] = key;
    }
    return true;
}

bool DescriptorScriptPubKeyMan::SetupDescriptor(WalletBatch& batch, WalletDescriptor&& descriptor)
{
    LOCK(cs_desc_man);
    assert(m_storage.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    // Ignore when there is already a descriptor.
    if (m_wallet_descriptor.descriptor) {
        return false;
    }

    m_wallet_descriptor = std::move(descriptor);

    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // TopUp
    if (!TopUpWithDB(batch)) return false;

    m_storage.UnsetBlankWalletFlag(batch);
    return true;
}

bool DescriptorScriptPubKeyMan::CanGetAddresses(bool internal) const
{
    // We can only give out addresses from descriptors that are single type (not combo), ranged,
    // and either have cached keys or can generate more keys (ignoring encryption)
    LOCK(cs_desc_man);
    const auto seed_ids = m_wallet_descriptor.descriptor->GetPQHDSeedIDs();
    const bool can_derive = std::all_of(seed_ids.begin(), seed_ids.end(),
        [&](const uint256& id) { return m_storage.HavePQHDSeed(id); });
    return !m_storage.IsWalletRecoveryRequired() && IsCacheUsable() &&
           m_wallet_descriptor.descriptor->IsSingleType() &&
           m_wallet_descriptor.descriptor->IsRange() &&
           ((m_wallet_descriptor.next_index < m_wallet_descriptor.range_end) ||
            (can_derive && m_wallet_descriptor.next_index < std::numeric_limits<int32_t>::max()));
}

bool DescriptorScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_desc_man);
    const auto seed_ids = m_wallet_descriptor.descriptor->GetPQHDSeedIDs();
    if (std::any_of(seed_ids.begin(), seed_ids.end(),
            [&](const uint256& id) { return m_storage.HavePQHDSeed(id); })) return true;
    std::set<CPubKey> pubkeys;
    m_wallet_descriptor.descriptor->GetPubKeys(pubkeys);
    return std::any_of(pubkeys.begin(), pubkeys.end(),
        [&](const CPubKey& key) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) { return HasPrivKey(key.GetID()); });
}

bool DescriptorScriptPubKeyMan::HaveCryptedKeys() const
{
    LOCK(cs_desc_man);
    return !m_map_crypted_keys.empty();
}

unsigned int DescriptorScriptPubKeyMan::GetKeyPoolSize() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.range_end - m_wallet_descriptor.next_index;
}

int64_t DescriptorScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.creation_time;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CScript& script, bool include_private) const
{
    int32_t index;
    {
        LOCK(cs_desc_man);

        // Find the index of the script
        auto it = m_map_script_pub_keys.find(script);
        if (it == m_map_script_pub_keys.end()) {
            return nullptr;
        }
        index = it->second;
    }

    return GetSigningProvider(index, include_private);
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CPubKey& pubkey, bool include_private) const
{
    int32_t index;
    {
        LOCK(cs_desc_man);

        // Find index of the pubkey
        auto it = m_map_pubkeys.find(pubkey);
        if (it == m_map_pubkeys.end()) {
            return nullptr;
        }
        index = it->second;
    }

    std::unique_ptr<FlatSigningProvider> out = GetSigningProvider(index, include_private);
    if (!out || (include_private && !out->HaveKey(pubkey.GetID()))) {
        return nullptr;
    }
    return out;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(int32_t index, bool include_private) const
{
    std::unique_ptr<FlatSigningProvider> out_keys = std::make_unique<FlatSigningProvider>();
    std::shared_ptr<Descriptor> descriptor;
    KeyMap keys;
    CryptedKeyMap crypted_keys;
    bool have_pqhd_seeds{false};

    {
        LOCK(cs_desc_man);
        descriptor = m_wallet_descriptor.descriptor;
        if (index < 0 || !IsCacheUsable()) return nullptr;

        // Fetch SigningProvider from cache to avoid re-deriving
        auto it = m_map_signing_providers.find(index);
        if (it != m_map_signing_providers.end()) {
            out_keys->Merge(FlatSigningProvider{it->second});
        } else {
            // Get the scripts and keys for this script
            std::vector<CScript> scripts_temp;
            if (!descriptor->ExpandFromCache(index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) return nullptr;

            // Cache SigningProvider so we don't need to re-derive if we need this SigningProvider again
            m_map_signing_providers[index] = *out_keys;
        }

        if (include_private) {
            keys = m_map_keys;
            crypted_keys = m_map_crypted_keys;
            const auto seed_ids = descriptor->GetPQHDSeedIDs();
            have_pqhd_seeds = std::any_of(seed_ids.begin(), seed_ids.end(),
                [&](const uint256& id) { return m_storage.HavePQHDSeed(id); });
        }
    }

    if (include_private && (!keys.empty() || !crypted_keys.empty() || have_pqhd_seeds)) {
        FlatSigningProvider master_provider;
        master_provider.keys = std::move(keys);
        if (!crypted_keys.empty() && !m_storage.IsLocked()) {
            for (const auto& key_pair : crypted_keys) {
                const CPubKey& pubkey = key_pair.second.first;
                const std::vector<unsigned char>& crypted_secret = key_pair.second.second;
                CKey key;
                m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                    return DecryptKey(encryption_key, crypted_secret, pubkey, key);
                });
                master_provider.keys[pubkey.GetID()] = key;
            }
        }
        const PQHDWalletSigningProvider provider{m_storage, master_provider};
        descriptor->ExpandPrivate(index, provider, *out_keys);
    }

    return out_keys;
}

std::unique_ptr<SigningProvider> DescriptorScriptPubKeyMan::GetSolvingProvider(const CScript& script) const
{
    return GetSigningProvider(script, false);
}

bool DescriptorScriptPubKeyMan::CanProvide(const CScript& script, SignatureData& sigdata)
{
    return IsMine(script);
}

bool DescriptorScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors, std::optional<unsigned int> script_verify_flags, const std::set<COutPoint>* missing_amounts) const
{
    std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
    for (const auto& coin_pair : coins) {
        std::unique_ptr<FlatSigningProvider> coin_keys = GetSigningProvider(coin_pair.second.out.scriptPubKey, true);
        if (!coin_keys) {
            continue;
        }
        keys->Merge(std::move(*coin_keys));
    }

    const unsigned int effective_flags = script_verify_flags.value_or(STANDARD_SCRIPT_VERIFY_FLAGS);
    return ::SignTransaction(tx, keys.get(), coins, sighash, input_errors, effective_flags, missing_amounts);
}

SigningResult DescriptorScriptPubKeyMan::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    std::unique_ptr<FlatSigningProvider> keys = GetSigningProvider(GetScriptForDestination(pkhash), true);
    if (!keys) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    CKey key;
    if (!keys->GetKey(ToKeyID(pkhash), key)) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    if (!MessageSign(key, message, str_sig)) {
        return SigningResult::SIGNING_FAILED;
    }
    return SigningResult::OK;
}

bool DescriptorScriptPubKeyMan::UpdatePQHDOrigins(const FlatSigningProvider& provider,
                                                  std::set<PSBTProprietary>& records,
                                                  uint8_t map_type, bool include_origins) const
{
    LOCK(cs_desc_man);
    if (!IsCacheUsable()) return false;
    auto updated = records;
    for (const auto& [key_id, pubkey] : provider.pubkeys) {
        const auto it = m_map_pubkeys.find(pubkey);
        if (it == m_map_pubkeys.end()) continue;
        for (const auto& [expression, info] : m_wallet_descriptor.descriptor->GetPQHDKeyPaths()) {
            CPubKey cached;
            if (!m_wallet_descriptor.cache.GetCachedDerivedPubKey(expression, info.is_range ? it->second : 0, cached) || cached != pubkey) continue;
            auto path = info.path;
            if (info.is_range) path.push_back(static_cast<uint32_t>(it->second) | 0x80000000U);
            // Compare locally known paths even when the caller requests no new
            // origins. Producer-supplied metadata never selects a derivation path.
            std::set<PSBTProprietary> expected;
            if (!psbt::tidecoin::AddPQHDOrigin(expected, map_type, pubkey, info.seed_id, path)) return false;
            const auto& entry = *expected.begin();
            if (const auto existing = updated.find(entry); existing != updated.end()) {
                if (existing->value != entry.value) return false;
            } else if (include_origins) {
                updated.insert(entry);
            }
        }
    }
    records = std::move(updated);
    return true;
}

std::optional<PSBTError> DescriptorScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbtx, const PrecomputedTransactionData& txdata, std::optional<int> sighash_type, bool sign, int* n_signed, bool finalize, bool include_pqhd_origins, std::optional<unsigned int> script_verify_flags, std::vector<common::PSBTInputError>* input_errors) const
{
    std::optional<PSBTError> refusal;
    const unsigned int effective_flags = script_verify_flags.value_or(STANDARD_SCRIPT_VERIFY_FLAGS);
    if (n_signed) {
        *n_signed = 0;
    }
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        const CTxIn& txin = psbtx.tx->vin[i];
        PSBTInput& input = psbtx.inputs.at(i);

        const bool need_private = sign && !PSBTInputSigned(input);

        // Get the scriptPubKey to know which SigningProvider to use
        CScript script;
        if (!input.witness_utxo.IsNull()) {
            script = input.witness_utxo.scriptPubKey;
        } else if (input.non_witness_utxo) {
            if (txin.prevout.n >= input.non_witness_utxo->vout.size()) {
                return PSBTError::MISSING_INPUTS;
            }
            script = input.non_witness_utxo->vout[txin.prevout.n].scriptPubKey;
        } else {
            // There's no UTXO so we can just skip this now
            continue;
        }

        std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
        std::unique_ptr<FlatSigningProvider> script_keys = GetSigningProvider(script, /*include_private=*/need_private);
        if (script_keys) {
            keys->Merge(std::move(*script_keys));
        } else {
            std::set<CKeyID> seen_keyids;
            std::vector<CPubKey> pubkeys;
            pubkeys.reserve(8);

            const auto collect_pubkeys_from_script = [&](const CScript& script_to_parse) {
                if (script_to_parse.empty()) return;
                std::vector<std::vector<unsigned char>> solutions;
                const TxoutType which = Solver(script_to_parse, solutions);
                if (which == TxoutType::PUBKEY && !solutions.empty()) {
                    CPubKey pubkey(solutions[0]);
                    if (pubkey.IsValid() && seen_keyids.insert(pubkey.GetID()).second) {
                        pubkeys.push_back(std::move(pubkey));
                    }
                } else if (which == TxoutType::MULTISIG && solutions.size() >= 3) {
                    for (size_t i = 1; i + 1 < solutions.size(); ++i) {
                        CPubKey pubkey(solutions[i]);
                        if (pubkey.IsValid() && seen_keyids.insert(pubkey.GetID()).second) {
                            pubkeys.push_back(std::move(pubkey));
                        }
                    }
                }

                // Miniscript (and other advanced templates) can embed public keys in
                // pushed script elements while not matching PUBKEY/MULTISIG solver types.
                // Scan all pushes and collect any byte strings that parse as valid keys.
                CScript::const_iterator pc = script_to_parse.begin();
                opcodetype opcode;
                std::vector<unsigned char> push_data;
                while (script_to_parse.GetOp(pc, opcode, push_data)) {
                    if (push_data.empty()) continue;
                    CPubKey pubkey(push_data);
                    if (pubkey.IsValid() && seen_keyids.insert(pubkey.GetID()).second) {
                        pubkeys.push_back(std::move(pubkey));
                    }
                }
            };

            collect_pubkeys_from_script(script);
            collect_pubkeys_from_script(input.redeem_script);
            collect_pubkeys_from_script(input.witness_script);

            for (const auto& pubkey : pubkeys) {
                std::unique_ptr<FlatSigningProvider> pk_keys = GetSigningProvider(pubkey, /*include_private=*/need_private);
                if (pk_keys) {
                    keys->Merge(std::move(*pk_keys));
                    continue;
                }

                // Descriptor pubkey index lookups can miss keys for some PQHD-derived
                // layouts even though the wallet owns the key. Fall back to direct
                // key-id lookup in the descriptor key store.
                if (!need_private) {
                    if (WITH_LOCK(cs_desc_man, return HasPrivKey(pubkey.GetID()))) keys->pubkeys.emplace(pubkey.GetID(), pubkey);
                    continue;
                }
                std::optional<CKey> key = GetKey(pubkey.GetID());
                if (key) {
                    keys->pubkeys.emplace(pubkey.GetID(), pubkey);
                    if (sign) {
                        keys->keys.emplace(pubkey.GetID(), *key);
                    }
                }
            }
        }

        if (!UpdatePQHDOrigins(*keys, input.m_proprietary, PSBT_IN_PROPRIETARY, include_pqhd_origins)) return PSBTError::PQHD_ORIGIN_MISMATCH;
        if (PSBTInputSigned(input)) continue;

        const auto previous_signatures = input.partial_sigs.size();
        PSBTError res = SignPSBTInput(HidingSigningProvider(keys.get(), /*hide_secret=*/!sign), psbtx, i, &txdata, sighash_type, nullptr, finalize, effective_flags, sign ? PSBTInputIntent::SIGN : PSBTInputIntent::INSPECT);
        if (res != PSBTError::OK && res != PSBTError::INCOMPLETE) {
            // Public filling preserves unresolved mode metadata for analysis;
            // it does not authorize signing or newly finalize conflicting data.
            if (!sign && (res == PSBTError::SIGHASH_MISMATCH || res == PSBTError::SIGHASH_UNSUPPORTED || res == PSBTError::SINGLE_WITHOUT_OUTPUT)) continue;
            if (input_errors) input_errors->push_back({i, sighash_type.value_or(SIGHASH_ALL), input.sighash_type, res});
            if (!refusal) refusal = res;
            continue;
        }

        const bool signed_one = PSBTInputSigned(input) || input.partial_sigs.size() > previous_signatures;
        if (n_signed && (sign ? signed_one : !keys->pubkeys.empty())) ++*n_signed;
    }

    for (unsigned int i = 0; i < psbtx.tx->vout.size(); ++i) {
        std::unique_ptr<SigningProvider> keys = GetSolvingProvider(psbtx.tx->vout.at(i).scriptPubKey);
        if (!keys) {
            continue;
        }
        UpdatePSBTOutput(HidingSigningProvider(keys.get(), /*hide_secret=*/true), psbtx, i);
        {
            const auto* flat_provider = dynamic_cast<const FlatSigningProvider*>(keys.get());
            if (!flat_provider) {
                continue;
            }
            if (!UpdatePQHDOrigins(*flat_provider, psbtx.outputs.at(i).m_proprietary, PSBT_OUT_PROPRIETARY, include_pqhd_origins)) return PSBTError::PQHD_ORIGIN_MISMATCH;
        }
    }

    return refusal;
}

std::unique_ptr<CKeyMetadata> DescriptorScriptPubKeyMan::GetMetadata(const CTxDestination& dest) const
{
    const CScript script = GetScriptForDestination(dest);
    LOCK(cs_desc_man);

    const auto script_it = m_map_script_pub_keys.find(script);
    if (script_it == m_map_script_pub_keys.end()) {
        return nullptr;
    }

    std::unique_ptr<CKeyMetadata> meta = std::make_unique<CKeyMetadata>();
    meta->nCreateTime = m_wallet_descriptor.creation_time;

    if (!m_wallet_descriptor.descriptor) {
        return meta;
    }

    const auto key_path_info = m_wallet_descriptor.descriptor->GetPQHDKeyPathInfo();
    if (!key_path_info || key_path_info->path.empty()) {
        return meta;
    }

    std::vector<uint32_t> full_path = key_path_info->path;
    if (key_path_info->is_range) {
        const int32_t child_index = script_it->second;
        if (child_index >= 0) {
            full_path.push_back(static_cast<uint32_t>(child_index) | 0x80000000U);
        }
    }

    meta->has_pqhd_origin = true;
    meta->pqhd_seed_id = key_path_info->seed_id;
    meta->pqhd_path = std::move(full_path);
    return meta;
}

uint256 DescriptorScriptPubKeyMan::GetID() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.id;
}

void DescriptorScriptPubKeyMan::SetCache(const DescriptorCache& cache)
{
    LOCK(cs_desc_man);
    if (!m_wallet_descriptor.HasValidRange()) throw std::runtime_error("Invalid descriptor range");
    const auto paths = m_wallet_descriptor.descriptor->GetPQHDKeyPaths();
    const auto entries = cache.GetCachedDerivedPubKeys();
    for (const auto& [expression, keys] : entries) {
        const auto path = paths.find(expression);
        if (path == paths.end()) throw std::runtime_error("Unexpected descriptor cache expression");
        const auto scheme = path->second.path.at(2) & 0x7fffffffU;
        for (const auto& [index, key] : keys) {
            if (!key.IsValid() || key[0] != scheme ||
                (path->second.is_range ? (index < uint32_t(m_wallet_descriptor.range_start) || index >= uint32_t(m_wallet_descriptor.range_end)) : index != 0)) {
                throw std::runtime_error("Invalid descriptor cache index or scheme");
            }
        }
    }
    for (const auto& [expression, path] : paths) {
        const size_t expected = m_wallet_descriptor.range_end == m_wallet_descriptor.range_start ? 0 :
            (path.is_range ? m_wallet_descriptor.range_end - m_wallet_descriptor.range_start : 1);
        const auto it = entries.find(expression);
        if ((it == entries.end() ? 0 : it->second.size()) != expected) throw std::runtime_error("Incomplete descriptor cache");
    }
    if (m_cache_state != CacheState::INVALID) {
        m_cache_state = entries.empty() ? CacheState::VERIFIED : CacheState::UNVERIFIED;
    }
    m_max_cached_index = m_wallet_descriptor.range_start - 1;
    std::set<CScript> new_spks;
    m_wallet_descriptor.cache = cache;
    for (int32_t i = m_wallet_descriptor.range_start; i < m_wallet_descriptor.range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            throw std::runtime_error("Error: Unable to expand wallet descriptor from cache");
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        new_spks.insert(scripts_temp.begin(), scripts_temp.end());
        for (const CScript& script : scripts_temp) {
            if (m_map_script_pub_keys.count(script) != 0) {
                throw std::runtime_error(strprintf("Error: Already loaded script at index %d as being at index %d", i, m_map_script_pub_keys[script]));
            }
            m_map_script_pub_keys[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.count(pubkey) != 0) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and its private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        m_max_cached_index = i;
    }
    // Make sure the wallet knows about our new spks
    m_storage.TopUpCallback(new_spks, this);
}

bool DescriptorScriptPubKeyMan::VerifyCache(const SigningProvider& provider, VerifiedPQHDKeys& verified) const
{
    LOCK(cs_desc_man);
    const auto entries = m_wallet_descriptor.cache.GetCachedDerivedPubKeys();
    for (const auto& [expression, info] : m_wallet_descriptor.descriptor->GetPQHDKeyPaths()) {
        const auto found = entries.find(expression);
        if (found == entries.end()) continue;
        std::string text = "pk(pqhd(" + info.seed_id.ToString() + ")";
        for (const auto component : info.path) text += strprintf("/%uh", component & 0x7fffffffU);
        if (info.is_range) text += "/*h";
        text += ")";
        FlatSigningProvider dummy;
        std::string error;
        auto descriptors = Parse(text, dummy, error, false);
        if (descriptors.size() != 1) return false;
        for (const auto& [index, key] : found->second) {
            auto path = info.path;
            if (info.is_range) path.push_back(index | 0x80000000U);
            const auto identity = std::make_pair(info.seed_id, path);
            auto it = verified.find(identity);
            if (it == verified.end()) {
                FlatSigningProvider out;
                std::vector<CScript> scripts;
                if (!descriptors[0]->Expand(index, provider, scripts, out) || out.pubkeys.size() != 1) return false;
                it = verified.emplace(identity, out.pubkeys.begin()->second).first;
            }
            if (it->second != key) return false;
        }
    }
    return true;
}

bool DescriptorScriptPubKeyMan::AddKey(const CKeyID& key_id, const CKey& key)
{
    LOCK(cs_desc_man);
    m_map_keys[key_id] = key;
    return true;
}

bool DescriptorScriptPubKeyMan::AddCryptedKey(const CKeyID& key_id, const CPubKey& pubkey, const std::vector<unsigned char>& crypted_key)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty()) {
        return false;
    }

    m_map_crypted_keys[key_id] = make_pair(pubkey, crypted_key);
    return true;
}

bool DescriptorScriptPubKeyMan::HasWalletDescriptor(const WalletDescriptor& desc) const
{
    LOCK(cs_desc_man);
    return !m_wallet_descriptor.id.IsNull() && !desc.id.IsNull() && m_wallet_descriptor.id == desc.id;
}

void DescriptorScriptPubKeyMan::WriteDescriptor()
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }
}

WalletDescriptor DescriptorScriptPubKeyMan::GetWalletDescriptor() const
{
    return m_wallet_descriptor;
}

std::unordered_set<CScript, SaltedSipHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys() const
{
    return GetScriptPubKeys(0);
}

std::unordered_set<CScript, SaltedSipHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys(int32_t minimum_index) const
{
    LOCK(cs_desc_man);
    std::unordered_set<CScript, SaltedSipHasher> script_pub_keys;
    script_pub_keys.reserve(m_map_script_pub_keys.size());

    for (auto const& [script_pub_key, index] : m_map_script_pub_keys) {
        if (index >= minimum_index) script_pub_keys.insert(script_pub_key);
    }
    return script_pub_keys;
}

int32_t DescriptorScriptPubKeyMan::GetEndRange() const
{
    return m_max_cached_index + 1;
}

bool DescriptorScriptPubKeyMan::GetDescriptorString(std::string& out, const bool priv) const
{
    LOCK(cs_desc_man);

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    if (priv) {
        // For the private version, always return the master key to avoid
        // exposing child private keys. Exposing child keys alongside parent
        // material can be non-obvious for users.
        return m_wallet_descriptor.descriptor->ToPrivateString(provider, out);
    }

    return m_wallet_descriptor.descriptor->ToNormalizedString(provider, out, &m_wallet_descriptor.cache);
}

util::Result<void> DescriptorScriptPubKeyMan::UpdateWalletDescriptor(WalletDescriptor& descriptor, WalletBatch* batch)
{
    LOCK(cs_desc_man);
    std::string error;
    if (!CanUpdateToWalletDescriptor(descriptor, error)) {
        return util::Error{Untranslated(std::move(error))};
    }

    if (batch) RegisterMutationRollback(*batch);
    // Recovery metadata may come from an older backup. Reimporting it must
    // neither reissue consumed addresses nor forget an earlier scan birthday.
    descriptor.next_index = std::max(descriptor.next_index, m_wallet_descriptor.next_index);
    descriptor.creation_time = std::min(descriptor.creation_time, m_wallet_descriptor.creation_time);
    // Preserve the cache and its validation state; range updates may not inject records.
    descriptor.cache = m_wallet_descriptor.cache;
    m_map_signing_providers.clear();
    m_map_pubkeys.clear();
    m_map_script_pub_keys.clear();
    m_max_cached_index = -1;
    m_wallet_descriptor = descriptor;

    if (batch) {
        // The commit listener runs after this descriptor lock has been released.
        batch->RegisterTxnListener({.on_commit = [this, lifetime = std::weak_ptr<int>{m_lifetime}, creation_time = m_wallet_descriptor.creation_time] {
            if (!lifetime.expired()) NotifyFirstKeyTimeChanged(this, creation_time);
        }, .on_abort = {}});
    } else {
        NotifyFirstKeyTimeChanged(this, m_wallet_descriptor.creation_time);
    }
    return {};
}

bool DescriptorScriptPubKeyMan::CanUpdateToWalletDescriptor(const WalletDescriptor& descriptor, std::string& error)
{
    LOCK(cs_desc_man);
    if (!descriptor.HasValidRange()) {
        error = "Invalid wallet descriptor range";
        return false;
    }
    if (!HasWalletDescriptor(descriptor)) {
        error = "can only update matching descriptor";
        return false;
    }

    if (!descriptor.descriptor->IsRange()) {
        // Skip range check for non-range descriptors
        return true;
    }

    if (descriptor.range_start > m_wallet_descriptor.range_start ||
        descriptor.range_end < m_wallet_descriptor.range_end) {
        // Use inclusive range for error
        error = strprintf("new range must include current range = [%d,%d]",
                          m_wallet_descriptor.range_start,
                          m_wallet_descriptor.range_end - 1);
        return false;
    }

    return true;
}
} // namespace wallet
