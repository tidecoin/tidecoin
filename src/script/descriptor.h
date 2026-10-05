// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_DESCRIPTOR_H
#define BITCOIN_SCRIPT_DESCRIPTOR_H

#include <outputtype.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <uint256.h>

#include <optional>
#include <set>
#include <vector>

using PubKeyMap = std::unordered_map<uint32_t, CPubKey>;

struct PQHDKeyPathInfo
{
    uint256 seed_id;
    std::vector<uint32_t> path;
    bool is_range{false};
};

/** Cache for single descriptor's derived extended pubkeys */
class DescriptorCache {
private:
    /** Map key expression index -> map of (key derivation index -> pubkey) */
    std::unordered_map<uint32_t, PubKeyMap> m_derived_pubkeys;

public:
    /** Cache a derived pubkey (for non-BIP32 derivation, e.g. PQHD).
     *
     * @param[in] key_exp_pos Position of the key expression within the descriptor
     * @param[in] der_index Derivation index of the pubkey
     * @param[in] pubkey The CPubKey to cache
     */
    void CacheDerivedPubKey(uint32_t key_exp_pos, uint32_t der_index, const CPubKey& pubkey);
    /** Retrieve a cached derived pubkey
     *
     * @param[in] key_exp_pos Position of the key expression within the descriptor
     * @param[in] der_index Derivation index of the pubkey
     * @param[out] pubkey The CPubKey to get from cache
     */
    bool GetCachedDerivedPubKey(uint32_t key_exp_pos, uint32_t der_index, CPubKey& pubkey) const;

    /** Retrieve all cached derived pubkeys */
    std::unordered_map<uint32_t, PubKeyMap> GetCachedDerivedPubKeys() const;

    /** Combine another DescriptorCache into this one.
     * Returns a cache containing the items from the other cache unknown to current cache
     */
    DescriptorCache MergeAndDiff(const DescriptorCache& other);
};

/** \brief Interface for parsed descriptor objects.
 *
 * Descriptors are strings that describe a set of scriptPubKeys, together with
 * all information necessary to solve them. By combining all information into
 * one, they avoid the need to separately import keys and scripts.
 *
 * Descriptors may be ranged, which occurs when the public keys inside are
 * specified in the form of derivation expressions (e.g., PQHD).
 *
 * Descriptors always represent public information - public keys and scripts -
 * but in cases where private keys need to be conveyed along with a descriptor,
 * they can be included inside by changing public keys to private keys (WIF
 * format).
 *
 * Reference documentation about the descriptor language can be found in
 * doc/descriptors.md.
 */
struct Descriptor {
    virtual ~Descriptor() = default;

    /** Whether the expansion of this descriptor depends on the position. */
    virtual bool IsRange() const = 0;

    /** Whether this descriptor has all information about signing ignoring lack of private keys.
     *  This is true for all descriptors except ones that use `raw` or `addr` constructions. */
    virtual bool IsSolvable() const = 0;

    /** Convert the descriptor back to a string, undoing parsing. */
    virtual std::string ToString(bool compat_format=false) const = 0;

    /** Whether this descriptor will return one scriptPubKey or multiple (aka is or is not combo) */
    virtual bool IsSingleType() const = 0;

    /** Convert the descriptor to a private string. This fails if the provided provider does not have the relevant private keys. */
    virtual bool ToPrivateString(const SigningProvider& provider, std::string& out) const = 0;

    /** Convert the descriptor to a normalized string. */
    virtual bool ToNormalizedString(const SigningProvider& provider, std::string& out, const DescriptorCache* cache = nullptr) const = 0;

    /** Expand a descriptor at a specified position.
     *
     * @param[in] pos The position at which to expand the descriptor. If IsRange() is false, this is ignored.
     * @param[in] provider The provider to query for private keys in case of hardened derivation.
     * @param[out] output_scripts The expanded scriptPubKeys.
     * @param[out] out Scripts and public keys necessary for solving the expanded scriptPubKeys (may be equal to `provider`).
     * @param[out] write_cache Cache data necessary to evaluate the descriptor at this point without access to private keys.
     */
    virtual bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const = 0;

    /** Expand a descriptor at a specified position using cached expansion data.
     *
     * @param[in] pos The position at which to expand the descriptor. If IsRange() is false, this is ignored.
     * @param[in] read_cache Cached expansion data.
     * @param[out] output_scripts The expanded scriptPubKeys.
     * @param[out] out Scripts and public keys necessary for solving the expanded scriptPubKeys (may be equal to `provider`).
     */
    virtual bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const = 0;

    /** Expand the private key for a descriptor at a specified position, if possible.
     *
     * @param[in] pos The position at which to expand the descriptor. If IsRange() is false, this is ignored.
     * @param[in] provider The provider to query for the private keys.
     * @param[out] out Any private keys available for the specified `pos`.
     */
    virtual void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const = 0;

    /** @return The OutputType of the scriptPubKey(s) produced by this descriptor. Or nullopt if indeterminate (multiple or none) */
    virtual std::optional<OutputType> GetOutputType() const = 0;

    /** Get the size of the scriptPubKey for this descriptor. */
    virtual std::optional<int64_t> ScriptSize() const = 0;

    /** Get the maximum size of a satisfaction for this descriptor, in weight units.
     *
     * @param use_max_sig Whether to use worst-case signature sizes.
     */
    virtual std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const = 0;

    /** Get the maximum size number of stack elements for satisfying this descriptor. */
    virtual std::optional<int64_t> MaxSatisfactionElems() const = 0;

    /** Return all public keys for this descriptor, including any from subdescriptors.
     *
     * @param[out] pubkeys Any public keys
     */
    virtual void GetPubKeys(std::set<CPubKey>& pubkeys) const = 0;

    /** Return the PQ scheme prefix if this descriptor maps to a single scheme. */
    virtual std::optional<uint8_t> GetPQHDSchemePrefix() const = 0;

    /** Return PQHD seed/path information if this descriptor maps to a single PQHD key path. */
    virtual std::optional<PQHDKeyPathInfo> GetPQHDKeyPathInfo() const = 0;

    /** PQHD key paths indexed by their cache expression position. */
    virtual std::map<uint32_t, PQHDKeyPathInfo> GetPQHDKeyPaths() const = 0;

    /** Return all PQHD seed ids referenced by this descriptor. */
    virtual std::set<uint256> GetPQHDSeedIDs() const = 0;
};

/** Parse a `descriptor` string. Included private keys are put in `out`.
 *
 * If the descriptor has a checksum, it must be valid. If `require_checksum`
 * is set, the checksum is mandatory - otherwise it is optional.
 *
 * If a parse error occurs, or the checksum is missing/invalid, or anything
 * else is wrong, an empty vector is returned.
 */
std::vector<std::unique_ptr<Descriptor>> Parse(const std::string& descriptor, FlatSigningProvider& out, std::string& error, bool require_checksum = false);

/** Get the checksum for a `descriptor`.
 *
 * - If it already has one, and it is correct, return the checksum in the input.
 * - If it already has one that is wrong, return "".
 * - If it does not already have one, return the checksum that would need to be added.
 */
std::string GetDescriptorChecksum(const std::string& descriptor);

/** Find a descriptor for the specified `script`, using information from `provider` where possible.
 *
 * A non-ranged descriptor which only generates the specified script will be returned in all
 * circumstances.
 *
 * For public keys with key origin information, this information will be preserved in the returned
 * descriptor.
 *
 * - If all information for solving `script` is present in `provider`, a descriptor will be returned
 *   which is IsSolvable() and encapsulates said information.
 * - Failing that, if `script` corresponds to a known address type, an "addr()" descriptor will be
 *   returned (which is not IsSolvable()).
 * - Failing that, a "raw()" descriptor is returned.
 */
std::unique_ptr<Descriptor> InferDescriptor(const CScript& script, const SigningProvider& provider);

/** Unique identifier that may not change over time, unless explicitly marked as not backwards compatible.
*   This is not part of BIP 380, not guaranteed to be interoperable and should not be exposed to the user.
*/
uint256 DescriptorID(const Descriptor& desc);

#endif // BITCOIN_SCRIPT_DESCRIPTOR_H
