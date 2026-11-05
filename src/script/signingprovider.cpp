// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <script/solver.h>

#include <hash.h>
#include <logging.h>

const SigningProvider& DUMMY_SIGNING_PROVIDER = SigningProvider();

template<typename M, typename K, typename V>
bool LookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return true;
    }
    return false;
}

bool HidingSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const
{
    return m_provider->GetCScript(scriptid, script);
}

bool HidingSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const
{
    return m_provider->GetPubKey(keyid, pubkey);
}

bool HidingSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const
{
    if (m_hide_secret) return false;
    return m_provider->GetKey(keyid, key);
}

std::optional<pqhd::SecureSeed32> HidingSigningProvider::GetPQHDSeed(const uint256& seed_id) const
{
    if (m_hide_secret) return std::nullopt;
    return m_provider->GetPQHDSeed(seed_id);
}

bool FlatSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const { return LookupHelper(scripts, scriptid, script); }
bool FlatSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const { return LookupHelper(pubkeys, keyid, pubkey); }
bool FlatSigningProvider::HaveKey(const CKeyID &keyid) const
{
    CKey key;
    return LookupHelper(keys, keyid, key);
}
bool FlatSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const { return LookupHelper(keys, keyid, key); }

FlatSigningProvider& FlatSigningProvider::Merge(FlatSigningProvider&& b)
{
    scripts.merge(b.scripts);
    pubkeys.merge(b.pubkeys);
    keys.merge(b.keys);
    return *this;
}

void FillableSigningProvider::ImplicitlyLearnRelatedKeyScripts(const CPubKey& pubkey)
{
    AssertLockHeld(cs_KeyStore);
    CKeyID key_id = pubkey.GetID();
    // This adds the redeemscripts necessary to detect P2WPKH and P2SH-P2WPKH
    // outputs. Technically P2WPKH outputs don't have a redeemscript to be
    // spent. However, our current IsMine logic requires the corresponding
    // P2SH-P2WPKH redeemscript to be present in the wallet in order to accept
    // payment even to P2WPKH outputs.
    // Also note that having superfluous scripts in the keystore never hurts.
    // They're only used to guide recursion in signing and IsMine logic - if
    // a script is present but we can't do anything with it, it has no effect.
    // "Implicitly" refers to fact that scripts are derived automatically from
    // existing keys, and are present in memory, even without being explicitly
    // loaded (e.g. from a file).
    CScript script = GetScriptForDestination(WitnessV0KeyHash(key_id));
    // This does not use AddCScript, as it may be overridden.
    CScriptID id(script);
    mapScripts[id] = std::move(script);

}

bool FillableSigningProvider::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool FillableSigningProvider::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    ImplicitlyLearnRelatedKeyScripts(pubkey);
    return true;
}

bool FillableSigningProvider::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    return mapKeys.count(address) > 0;
}

std::set<CKeyID> FillableSigningProvider::GetKeys() const
{
    LOCK(cs_KeyStore);
    std::set<CKeyID> set_address;
    for (const auto& mi : mapKeys) {
        set_address.insert(mi.first);
    }
    return set_address;
}

bool FillableSigningProvider::GetKey(const CKeyID &address, CKey &keyOut) const
{
    LOCK(cs_KeyStore);
    KeyMap::const_iterator mi = mapKeys.find(address);
    if (mi != mapKeys.end()) {
        keyOut = mi->second;
        return true;
    }
    return false;
}

bool FillableSigningProvider::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        LogError("FillableSigningProvider::AddCScript(): redeemScripts > %i bytes are invalid\n", MAX_SCRIPT_ELEMENT_SIZE);
        return false;
    }

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool FillableSigningProvider::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

std::set<CScriptID> FillableSigningProvider::GetCScripts() const
{
    LOCK(cs_KeyStore);
    std::set<CScriptID> set_script;
    for (const auto& mi : mapScripts) {
        set_script.insert(mi.first);
    }
    return set_script;
}

bool FillableSigningProvider::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

CKeyID GetKeyForDestination(const SigningProvider& store, const CTxDestination& dest)
{
    // Only supports destinations which map to single public keys:
    // P2PKH, P2WPKH, P2SH-P2WPKH, and native wsh512(pk(KEY)).
    if (auto id = std::get_if<PKHash>(&dest)) {
        return ToKeyID(*id);
    }
    if (auto witness_id = std::get_if<WitnessV0KeyHash>(&dest)) {
        return ToKeyID(*witness_id);
    }
    if (auto witness_hash = std::get_if<WitnessV1ScriptHash512>(&dest)) {
        CScript script;
        // The provider's lookup key is only a shortened index. Authenticate the
        // complete witness commitment before choosing the key to export.
        if (!store.GetCScript(CScriptID{RIPEMD160(*witness_hash)}, script) ||
            WitnessV1ScriptHash512{script} != *witness_hash) return {};
        std::vector<std::vector<unsigned char>> solutions;
        if (Solver(script, solutions) != TxoutType::PUBKEY) return {};
        const CPubKey pubkey{solutions[0]};
        if (pubkey.IsFullyValid()) return pubkey.GetID();
        return {};
    }
    if (auto script_hash = std::get_if<ScriptHash>(&dest)) {
        CScript script;
        CScriptID script_id = ToScriptID(*script_hash);
        CTxDestination inner_dest;
        if (store.GetCScript(script_id, script) && ExtractDestination(script, inner_dest)) {
            if (auto inner_witness_id = std::get_if<WitnessV0KeyHash>(&inner_dest)) {
                return ToKeyID(*inner_witness_id);
            }
        }
    }
    return CKeyID();
}

void MultiSigningProvider::AddProvider(std::unique_ptr<SigningProvider> provider)
{
    m_providers.push_back(std::move(provider));
}

bool MultiSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetCScript(scriptid, script)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetPubKey(keyid, pubkey)) return true;
    }
    return false;
}


bool MultiSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetKey(keyid, key)) return true;
    }
    return false;
}

std::optional<pqhd::SecureSeed32> MultiSigningProvider::GetPQHDSeed(const uint256& seed_id) const
{
    for (const auto& provider : m_providers) {
        if (auto seed = provider->GetPQHDSeed(seed_id)) return seed;
    }
    return std::nullopt;
}
