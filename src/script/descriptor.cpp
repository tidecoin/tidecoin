// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/descriptor.h>

#include <hash.h>
#include <key_io.h>
#include <pubkey.h>
#include <pq/pq_api.h>
#include <pq/pq_scheme.h>
#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>
#include <script/miniscript.h>
#include <script/parsing.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>

#include <common/args.h>
#include <span.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <algorithm>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <vector>

using util::Split;

namespace {

////////////////////////////////////////////////////////////////////////////
// Checksum                                                               //
////////////////////////////////////////////////////////////////////////////

// This section implements a checksum algorithm for descriptors with the
// following properties:
// * Mistakes in a descriptor string are measured in "symbol errors". The higher
//   the number of symbol errors, the harder it is to detect:
//   * An error substituting a character from 0123456789()[],'/*abcdefgh@:$%{} for
//     another in that set always counts as 1 symbol error.
//     * Note that hex encoded keys are covered by these characters. Xprvs and
//       mechanism.
//     * Function names like "multi()" use other characters, but mistakes in
//       these would generally result in an unparsable descriptor.
//   * A case error always counts as 1 symbol error.
//   * Any other 1 character substitution error counts as 1 or 2 symbol errors.
// * Any 1 symbol error is always detected.
// * Any 2 or 3 symbol error in a descriptor of up to 49154 characters is always detected.
// * Any 4 symbol error in a descriptor of up to 507 characters is always detected.
// * Any 5 symbol error in a descriptor of up to 77 characters is always detected.
// * Is optimized to minimize the chance a 5 symbol error in a descriptor up to 387 characters is undetected
// * Random errors have a chance of 1 in 2**40 of being undetected.
//
// These properties are achieved by expanding every group of 3 (non checksum) characters into
// 4 GF(32) symbols, over which a cyclic code is defined.

/*
 * Interprets c as 8 groups of 5 bits which are the coefficients of a degree 8 polynomial over GF(32),
 * multiplies that polynomial by x, computes its remainder modulo a generator, and adds the constant term val.
 *
 * This generator is G(x) = x^8 + {30}x^7 + {23}x^6 + {15}x^5 + {14}x^4 + {10}x^3 + {6}x^2 + {12}x + {9}.
 * It is chosen to define an cyclic error detecting code which is selected by:
 * - Starting from all BCH codes over GF(32) of degree 8 and below, which by construction guarantee detecting
 *   3 errors in windows up to 19000 symbols.
 * - Taking all those generators, and for degree 7 ones, extend them to degree 8 by adding all degree-1 factors.
 * - Selecting just the set of generators that guarantee detecting 4 errors in a window of length 512.
 * - Selecting one of those with best worst-case behavior for 5 errors in windows of length up to 512.
 *
 * The generator and the constants to implement it can be verified using this Sage code:
 *   B = GF(2) # Binary field
 *   BP.<b> = B[] # Polynomials over the binary field
 *   F_mod = b**5 + b**3 + 1
 *   F.<f> = GF(32, modulus=F_mod, repr='int') # GF(32) definition
 *   FP.<x> = F[] # Polynomials over GF(32)
 *   E_mod = x**3 + x + F.fetch_int(8)
 *   E.<e> = F.extension(E_mod) # Extension field definition
 *   alpha = e**2743 # Choice of an element in extension field
 *   for p in divisors(E.order() - 1): # Verify alpha has order 32767.
 *       assert((alpha**p == 1) == (p % 32767 == 0))
 *   G = lcm([(alpha**i).minpoly() for i in [1056,1057,1058]] + [x + 1])
 *   print(G) # Print out the generator
 *   for i in [1,2,4,8,16]: # Print out {1,2,4,8,16}*(G mod x^8), packed in hex integers.
 *       v = 0
 *       for coef in reversed((F.fetch_int(i)*(G % x**8)).coefficients(sparse=True)):
 *           v = v*32 + coef.integer_representation()
 *       print("0x%x" % v)
 */
uint64_t PolyMod(uint64_t c, int val)
{
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989;
    if (c0 & 2) c ^= 0xa9fdca3312;
    if (c0 & 4) c ^= 0x1bab10e32d;
    if (c0 & 8) c ^= 0x3706b1677a;
    if (c0 & 16) c ^= 0x644d626ffd;
    return c;
}

std::string DescriptorChecksum(const std::span<const char>& span)
{
    /** A character set designed such that:
     *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
     *  - Case errors cause an offset that's a multiple of 32.
     *  - As many alphabetic characters are in the same group (while following the above restrictions).
     *
     * If p(x) gives the position of a character c in this character set, every group of 3 characters
     * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
     * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
     * affect a single symbol.
     *
     * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
     * the position within the groups.
     */
    static const std::string INPUT_CHARSET =
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

    /** The character set for the checksum itself (same as bech32). */
    static const std::string CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    uint64_t c = 1;
    int cls = 0;
    int clscount = 0;
    for (auto ch : span) {
        auto pos = INPUT_CHARSET.find(ch);
        if (pos == std::string::npos) return "";
        c = PolyMod(c, pos & 31); // Emit a symbol for the position inside the group, for every character.
        cls = cls * 3 + (pos >> 5); // Accumulate the group numbers
        if (++clscount == 3) {
            // Emit an extra symbol representing the group numbers, for every 3 characters.
            c = PolyMod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0) c = PolyMod(c, cls);
    for (int j = 0; j < 8; ++j) c = PolyMod(c, 0); // Shift further to determine the checksum.
    c ^= 1; // Prevent appending zeroes from not affecting the checksum.

    std::string ret(8, ' ');
    for (int j = 0; j < 8; ++j) ret[j] = CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31];
    return ret;
}

std::string AddChecksum(const std::string& str) { return str + "#" + DescriptorChecksum(str); }

////////////////////////////////////////////////////////////////////////////
// Internal representation                                                //
////////////////////////////////////////////////////////////////////////////

typedef std::vector<uint32_t> KeyPath;

/** Interface for public key objects in descriptors. */
struct PubkeyProvider
{
protected:
    //! Index of this key expression in the descriptor
    //! E.g. If this PubkeyProvider is key1 in multi(2, key1, key2, key3), then m_expr_index = 0
    uint32_t m_expr_index;

public:
    explicit PubkeyProvider(uint32_t exp_index) : m_expr_index(exp_index) {}

    virtual ~PubkeyProvider() = default;

    /** Compare two public keys represented by this provider.
     * Used by the Miniscript descriptors to check for duplicate keys in the script.
     */
    bool operator<(PubkeyProvider& other) const {
        FlatSigningProvider dummy;

        std::optional<CPubKey> a = GetPubKey(0, dummy, dummy);
        std::optional<CPubKey> b = other.GetPubKey(0, dummy, dummy);

        return a < b;
    }

    /** Derive a public key and put it into out.
     *  read_cache is the cache to read keys from (if not nullptr)
     *  write_cache is the cache to write keys to (if not nullptr)
     *  Caches are not exclusive but this is not tested. Currently we use them exclusively
     */
    virtual std::optional<CPubKey> GetPubKey(int pos, const SigningProvider& arg, FlatSigningProvider& out, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const = 0;

    /** Whether this represent multiple public keys at different positions. */
    virtual bool IsRange() const = 0;

    /** Get the size of the generated public key(s) in bytes. */
    virtual size_t GetSize() const = 0;

    enum class StringType {
        PUBLIC,
        COMPAT // string calculation that mustn't change over time to stay compatible with previous software versions
    };

    /** Get the descriptor string form. */
    virtual std::string ToString(StringType type=StringType::PUBLIC) const = 0;

    /** Get the descriptor string form including private data (if available in arg). */
    virtual bool ToPrivateString(const SigningProvider& arg, std::string& out) const = 0;

    /** Get the descriptor string form, normalizing hardened derivation markers. */
    virtual bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache = nullptr) const = 0;

    /** Derive a private key, if private data is available in arg and put it into out. */
    virtual void GetPrivKey(int pos, const SigningProvider& arg, FlatSigningProvider& out) const = 0;

    /** Return the non-extended public key for this PubkeyProvider, if it has one. */
    virtual std::optional<CPubKey> GetRootPubKey() const = 0;
    /** Return the PQ scheme prefix if this PubkeyProvider maps to a single scheme. */
    virtual std::optional<uint8_t> GetSchemePrefix() const { return std::nullopt; }
    /** Return PQHD key path info if this PubkeyProvider represents a single PQHD key path. */
    virtual std::optional<PQHDKeyPathInfo> GetPQHDKeyPathInfo() const { return std::nullopt; }
    /** Collect PQHD seed ids referenced by this PubkeyProvider. */
    virtual void GetPQHDSeedIDs(std::set<uint256>& seed_ids) const {}
    /** Make a deep copy of this PubkeyProvider */
    virtual std::unique_ptr<PubkeyProvider> Clone() const = 0;

};

/** An object representing a parsed constant public key in a descriptor. */
class ConstPubkeyProvider final : public PubkeyProvider
{
    CPubKey m_pubkey;

    std::optional<CKey> GetPrivKey(const SigningProvider& arg) const
    {
        CKey key;
        if (!arg.GetKey(m_pubkey.GetID(), key)) return std::nullopt;
        return key;
    }

public:
    ConstPubkeyProvider(uint32_t exp_index, const CPubKey& pubkey) : PubkeyProvider(exp_index), m_pubkey(pubkey) {}
    std::optional<CPubKey> GetPubKey(int pos, const SigningProvider&, FlatSigningProvider& out, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const override
    {
        out.pubkeys.emplace(m_pubkey.GetID(), m_pubkey);
        return m_pubkey;
    }
    bool IsRange() const override { return false; }
    size_t GetSize() const override { return m_pubkey.size(); }
    std::string ToString(StringType type) const override { return HexStr(m_pubkey); }
    bool ToPrivateString(const SigningProvider& arg, std::string& ret) const override
    {
        std::optional<CKey> key = GetPrivKey(arg);
        if (!key) return false;
        ret = EncodeSecret(*key);
        return true;
    }
    bool ToNormalizedString(const SigningProvider& arg, std::string& ret, const DescriptorCache* cache) const override
    {
        ret = ToString(StringType::PUBLIC);
        return true;
    }
    void GetPrivKey(int pos, const SigningProvider& arg, FlatSigningProvider& out) const override
    {
        std::optional<CKey> key = GetPrivKey(arg);
        if (!key) return;
        out.keys.emplace(key->GetPubKey().GetID(), *key);
    }
    std::optional<CPubKey> GetRootPubKey() const override
    {
        return m_pubkey;
    }
    std::optional<uint8_t> GetSchemePrefix() const override
    {
        if (m_pubkey.size() == 0) return std::nullopt;
        const uint8_t prefix = m_pubkey[0];
        if (pq::SchemeFromPrefix(prefix) == nullptr) return std::nullopt;
        return prefix;
    }
    std::unique_ptr<PubkeyProvider> Clone() const override
    {
        return std::make_unique<ConstPubkeyProvider>(m_expr_index, m_pubkey);
    }
};

enum class DeriveType {
    NO,
    HARDENED,
};

/** A parsed pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/indexh|*h key expression. */
class PQHDPubkeyProvider final : public PubkeyProvider
{
    uint256 m_seed_id;
    KeyPath m_path;
    DeriveType m_derive;
    uint8_t m_scheme_prefix;

    static std::string FormatPQHDKeypath(const KeyPath& path, bool add_derive_wildcard)
    {
        std::string ret;
        for (uint32_t elem : path) {
            const uint32_t index = elem & 0x7FFFFFFFUL;
            ret += strprintf("/%uh", index);
        }
        if (add_derive_wildcard) {
            ret += "/*h";
        }
        return ret;
    }

public:
    PQHDPubkeyProvider(uint32_t exp_index, const uint256& seed_id, KeyPath path, DeriveType derive, uint8_t scheme_prefix)
        : PubkeyProvider(exp_index), m_seed_id(seed_id), m_path(std::move(path)), m_derive(derive), m_scheme_prefix(scheme_prefix) {}

    bool IsRange() const override { return m_derive != DeriveType::NO; }
    size_t GetSize() const override
    {
        const pq::SchemeInfo* scheme = pq::SchemeFromPrefix(m_scheme_prefix);
        Assert(scheme != nullptr);
        return 1 + scheme->pubkey_bytes;
    }

    std::optional<CPubKey> GetPubKey(int pos, const SigningProvider& arg, FlatSigningProvider& out, const DescriptorCache* read_cache, DescriptorCache* write_cache) const override
    {
        const uint32_t der_index = (m_derive == DeriveType::NO) ? 0U : static_cast<uint32_t>(pos);

        if (read_cache) {
            CPubKey cached;
            if (!read_cache->GetCachedDerivedPubKey(m_expr_index, der_index, cached)) {
                return std::nullopt;
            }
            out.pubkeys.emplace(cached.GetID(), cached);
            return cached;
        }

        if (!write_cache) return std::nullopt;

        const auto master_seed = arg.GetPQHDSeed(m_seed_id);
        if (!master_seed) {
            return std::nullopt;
        }

        // Build the full hardened leaf path.
        std::array<uint32_t, 6> leaf_path{};
        if (m_derive == DeriveType::HARDENED) {
            if (m_path.size() != 5) return std::nullopt;
            std::copy_n(m_path.begin(), 5, leaf_path.begin());
            leaf_path[5] = static_cast<uint32_t>(pos) | 0x80000000UL;
        } else {
            if (m_path.size() != 6) return std::nullopt;
            std::copy_n(m_path.begin(), 6, leaf_path.begin());
        }

        if (!pqhd::ValidateV1LeafPath(leaf_path)) {
            return std::nullopt;
        }

        const pqhd::Node master = pqhd::MakeMasterNode(master_seed->Span());
        const auto leaf_node_opt = pqhd::DerivePath(master, leaf_path);
        if (!leaf_node_opt) return std::nullopt;

        const auto leaf_material_opt = pqhd::DeriveLeafMaterialV1((*leaf_node_opt).node_secret, leaf_path);
        if (!leaf_material_opt) return std::nullopt;

        std::vector<uint8_t> pk_raw;
        pq::SecureKeyBytes sk_raw;
        if (!pq::KeyGenFromLeafMaterial(/*pqhd_version=*/1, *leaf_material_opt, pk_raw, sk_raw)) {
            return std::nullopt;
        }

        std::vector<uint8_t> prefixed(pk_raw.size() + 1);
        prefixed[0] = m_scheme_prefix;
        std::copy(pk_raw.begin(), pk_raw.end(), prefixed.begin() + 1);

        CPubKey pubkey{std::span<const uint8_t>{prefixed}};
        if (!pubkey.IsFullyValid()) return std::nullopt;

        out.pubkeys.emplace(pubkey.GetID(), pubkey);
        write_cache->CacheDerivedPubKey(m_expr_index, der_index, pubkey);
        return pubkey;
    }

    std::string ToString(StringType) const override
    {
        std::string ret = "pqhd(" + m_seed_id.ToString() + ")";
        ret += FormatPQHDKeypath(m_path, /*add_derive_wildcard=*/m_derive == DeriveType::HARDENED);
        return ret;
    }

    bool ToPrivateString(const SigningProvider&, std::string& out) const override
    {
        // PQHD seeds are wallet-local and never included in the descriptor string.
        out = ToString(StringType::PUBLIC);
        return true;
    }

    bool ToNormalizedString(const SigningProvider&, std::string& out, const DescriptorCache*) const override
    {
        out = ToString(StringType::PUBLIC);
        return true;
    }

    void GetPrivKey(int pos, const SigningProvider& arg, FlatSigningProvider& out) const override
    {
        const auto master_seed = arg.GetPQHDSeed(m_seed_id);
        if (!master_seed) {
            return;
        }

        // Build the full hardened leaf path.
        std::array<uint32_t, 6> leaf_path{};
        if (m_derive == DeriveType::HARDENED) {
            if (m_path.size() != 5) return;
            std::copy_n(m_path.begin(), 5, leaf_path.begin());
            leaf_path[5] = static_cast<uint32_t>(pos) | 0x80000000UL;
        } else {
            if (m_path.size() != 6) return;
            std::copy_n(m_path.begin(), 6, leaf_path.begin());
        }

        if (!pqhd::ValidateV1LeafPath(leaf_path)) {
            return;
        }

        const pqhd::Node master = pqhd::MakeMasterNode(master_seed->Span());
        const auto leaf_node_opt = pqhd::DerivePath(master, leaf_path);
        if (!leaf_node_opt) return;

        const auto leaf_material_opt = pqhd::DeriveLeafMaterialV1((*leaf_node_opt).node_secret, leaf_path);
        if (!leaf_material_opt) return;

        std::vector<uint8_t> pk_raw;
        pq::SecureKeyBytes sk_raw;
        if (!pq::KeyGenFromLeafMaterial(/*pqhd_version=*/1, *leaf_material_opt, pk_raw, sk_raw)) {
            return;
        }

        std::vector<uint8_t> prefixed(pk_raw.size() + 1);
        prefixed[0] = m_scheme_prefix;
        std::copy(pk_raw.begin(), pk_raw.end(), prefixed.begin() + 1);
        const CPubKey pubkey{std::span<const uint8_t>{prefixed}};
        if (!pubkey.IsFullyValid()) return;

        CKey key;
        key.Set(sk_raw.begin(), sk_raw.end(), pubkey);
        if (!key.IsValid()) return;

        out.pubkeys.emplace(pubkey.GetID(), pubkey);
        out.keys.emplace(pubkey.GetID(), key);
    }
    std::optional<CPubKey> GetRootPubKey() const override { return std::nullopt; }
    std::optional<uint8_t> GetSchemePrefix() const override
    {
        if (pq::SchemeFromPrefix(m_scheme_prefix) == nullptr) return std::nullopt;
        return m_scheme_prefix;
    }
    std::optional<PQHDKeyPathInfo> GetPQHDKeyPathInfo() const override
    {
        return PQHDKeyPathInfo{m_seed_id, m_path, m_derive == DeriveType::HARDENED};
    }
    void GetPQHDSeedIDs(std::set<uint256>& seed_ids) const override
    {
        seed_ids.insert(m_seed_id);
    }
    std::unique_ptr<PubkeyProvider> Clone() const override
    {
        return std::make_unique<PQHDPubkeyProvider>(m_expr_index, m_seed_id, m_path, m_derive, m_scheme_prefix);
    }
};

/** Base class for all Descriptor implementations. */
class DescriptorImpl : public Descriptor
{
protected:
    //! Public key arguments for this descriptor (size 1 for PK, PKH, WPKH; any size for WSH and Multisig).
    const std::vector<std::unique_ptr<PubkeyProvider>> m_pubkey_args;
    //! The string name of the descriptor function.
    const std::string m_name;

    //! The sub-descriptor arguments (empty for everything but SH and WSH).
    //! In doc/descriptors.m this is referred to as SCRIPT expressions sh(SCRIPT)
    //! and wsh(SCRIPT), and distinct from KEY expressions and ADDR expressions.
    //! Subdescriptors can only ever generate a single script.
    const std::vector<std::unique_ptr<DescriptorImpl>> m_subdescriptor_args;

    //! Return a serialization of anything except pubkey and script arguments, to be prepended to those.
    virtual std::string ToStringExtra() const { return ""; }

    /** A helper function to construct the scripts for this descriptor.
     *
     *  This function is invoked once by ExpandHelper.
     *
     *  @param pubkeys The evaluations of the m_pubkey_args field.
     *  @param scripts The evaluations of m_subdescriptor_args (one for each m_subdescriptor_args element).
     *  @param out A FlatSigningProvider to put scripts or public keys in that are necessary to the solver.
     *             The origin info of the provided pubkeys is automatically added.
     *  @return A vector with scriptPubKeys for this descriptor.
     */
    virtual std::vector<CScript> MakeScripts(const std::vector<CPubKey>& pubkeys, std::span<const CScript> scripts, FlatSigningProvider& out) const = 0;

public:
    DescriptorImpl(std::vector<std::unique_ptr<PubkeyProvider>> pubkeys, const std::string& name) : m_pubkey_args(std::move(pubkeys)), m_name(name), m_subdescriptor_args() {}
    DescriptorImpl(std::vector<std::unique_ptr<PubkeyProvider>> pubkeys, std::unique_ptr<DescriptorImpl> script, const std::string& name) : m_pubkey_args(std::move(pubkeys)), m_name(name), m_subdescriptor_args(Vector(std::move(script))) {}

    enum class StringType
    {
        PUBLIC,
        PRIVATE,
        NORMALIZED,
        COMPAT, // string calculation that mustn't change over time to stay compatible with previous software versions
    };

    // NOLINTNEXTLINE(misc-no-recursion)
    bool IsSolvable() const override
    {
        for (const auto& arg : m_subdescriptor_args) {
            if (!arg->IsSolvable()) return false;
        }
        return true;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    bool IsRange() const final
    {
        for (const auto& pubkey : m_pubkey_args) {
            if (pubkey->IsRange()) return true;
        }
        for (const auto& arg : m_subdescriptor_args) {
            if (arg->IsRange()) return true;
        }
        return false;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    virtual bool ToStringSubScriptHelper(const SigningProvider* arg, std::string& ret, const StringType type, const DescriptorCache* cache = nullptr) const
    {
        size_t pos = 0;
        for (const auto& scriptarg : m_subdescriptor_args) {
            if (pos++) ret += ",";
            std::string tmp;
            if (!scriptarg->ToStringHelper(arg, tmp, type, cache)) return false;
            ret += tmp;
        }
        return true;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    virtual bool ToStringHelper(const SigningProvider* arg, std::string& out, const StringType type, const DescriptorCache* cache = nullptr) const
    {
        std::string extra = ToStringExtra();
        size_t pos = extra.size() > 0 ? 1 : 0;
        std::string ret = m_name + "(" + extra;
        for (const auto& pubkey : m_pubkey_args) {
            if (pos++) ret += ",";
            std::string tmp;
            switch (type) {
                case StringType::NORMALIZED:
                    if (!pubkey->ToNormalizedString(*arg, tmp, cache)) return false;
                    break;
                case StringType::PRIVATE:
                    if (!pubkey->ToPrivateString(*arg, tmp)) return false;
                    break;
                case StringType::PUBLIC:
                    tmp = pubkey->ToString();
                    break;
                case StringType::COMPAT:
                    tmp = pubkey->ToString(PubkeyProvider::StringType::COMPAT);
                    break;
            }
            ret += tmp;
        }
        std::string subscript;
        if (!ToStringSubScriptHelper(arg, subscript, type, cache)) return false;
        if (pos && subscript.size()) ret += ',';
        out = std::move(ret) + std::move(subscript) + ")";
        return true;
    }

    std::string ToString(bool compat_format) const final
    {
        std::string ret;
        ToStringHelper(nullptr, ret, compat_format ? StringType::COMPAT : StringType::PUBLIC);
        return AddChecksum(ret);
    }

    bool ToPrivateString(const SigningProvider& arg, std::string& out) const override
    {
        bool ret = ToStringHelper(&arg, out, StringType::PRIVATE);
        out = AddChecksum(out);
        return ret;
    }

    bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache) const override final
    {
        bool ret = ToStringHelper(&arg, out, StringType::NORMALIZED, cache);
        out = AddChecksum(out);
        return ret;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    bool ExpandHelper(int pos, const SigningProvider& arg, const DescriptorCache* read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache) const
    {
        FlatSigningProvider subprovider;
        std::vector<CPubKey> pubkeys;
        pubkeys.reserve(m_pubkey_args.size());

        // Construct temporary data in `pubkeys`, `subscripts`, and `subprovider` to avoid producing output in case of failure.
        for (const auto& p : m_pubkey_args) {
            std::optional<CPubKey> pubkey = p->GetPubKey(pos, arg, subprovider, read_cache, write_cache);
            if (!pubkey) return false;
            pubkeys.push_back(pubkey.value());
        }
        std::vector<CScript> subscripts;
        for (const auto& subarg : m_subdescriptor_args) {
            std::vector<CScript> outscripts;
            if (!subarg->ExpandHelper(pos, arg, read_cache, outscripts, subprovider, write_cache)) return false;
            assert(outscripts.size() == 1);
            subscripts.emplace_back(std::move(outscripts[0]));
        }
        out.Merge(std::move(subprovider));

        output_scripts = MakeScripts(pubkeys, std::span{subscripts}, out);
        return true;
    }

    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const final
    {
        return ExpandHelper(pos, provider, nullptr, output_scripts, out, write_cache);
    }

    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const final
    {
        return ExpandHelper(pos, DUMMY_SIGNING_PROVIDER, &read_cache, output_scripts, out, nullptr);
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const final
    {
        for (const auto& p : m_pubkey_args) {
            p->GetPrivKey(pos, provider, out);
        }
        for (const auto& arg : m_subdescriptor_args) {
            arg->ExpandPrivate(pos, provider, out);
        }
    }

    std::optional<OutputType> GetOutputType() const override { return std::nullopt; }

    std::optional<int64_t> ScriptSize() const override { return {}; }

    /** A helper for MaxSatisfactionWeight.
     *
     * @param use_max_sig Whether to use worst-case signature sizes.
     * @return The maximum size of the satisfaction in raw bytes (with no witness meaning).
     */
    virtual std::optional<int64_t> MaxSatSize(bool use_max_sig) const { return {}; }

    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }

    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }

    // NOLINTNEXTLINE(misc-no-recursion)
    void GetPubKeys(std::set<CPubKey>& pubkeys) const override
    {
        for (const auto& p : m_pubkey_args) {
            std::optional<CPubKey> pub = p->GetRootPubKey();
            if (pub) pubkeys.insert(*pub);
        }
        for (const auto& arg : m_subdescriptor_args) {
            arg->GetPubKeys(pubkeys);
        }
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    std::optional<uint8_t> GetPQHDSchemePrefix() const override
    {
        std::optional<uint8_t> prefix;
        for (const auto& p : m_pubkey_args) {
            const auto pfx = p->GetSchemePrefix();
            if (!pfx) continue;
            if (prefix && *prefix != *pfx) return std::nullopt;
            prefix = pfx;
        }
        for (const auto& arg : m_subdescriptor_args) {
            const auto pfx = arg->GetPQHDSchemePrefix();
            if (!pfx) continue;
            if (prefix && *prefix != *pfx) return std::nullopt;
            prefix = pfx;
        }
        return prefix;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    std::optional<PQHDKeyPathInfo> GetPQHDKeyPathInfo() const override
    {
        std::optional<PQHDKeyPathInfo> info;
        auto merge = [&info](const std::optional<PQHDKeyPathInfo>& candidate) -> bool {
            if (!candidate) return true;
            if (!info) {
                info = *candidate;
                return true;
            }
            if (info->seed_id != candidate->seed_id || info->path != candidate->path || info->is_range != candidate->is_range) {
                info.reset();
                return false;
            }
            return true;
        };

        for (const auto& p : m_pubkey_args) {
            if (!merge(p->GetPQHDKeyPathInfo())) return std::nullopt;
        }
        for (const auto& arg : m_subdescriptor_args) {
            if (!merge(arg->GetPQHDKeyPathInfo())) return std::nullopt;
        }
        return info;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    std::set<uint256> GetPQHDSeedIDs() const override
    {
        std::set<uint256> seed_ids;
        for (const auto& p : m_pubkey_args) {
            p->GetPQHDSeedIDs(seed_ids);
        }
        for (const auto& arg : m_subdescriptor_args) {
            const auto child_seed_ids = arg->GetPQHDSeedIDs();
            seed_ids.insert(child_seed_ids.begin(), child_seed_ids.end());
        }
        return seed_ids;
    }

    virtual std::unique_ptr<DescriptorImpl> Clone() const = 0;
};

/** A parsed addr(A) descriptor. */
class AddressDescriptor final : public DescriptorImpl
{
    const CTxDestination m_destination;
protected:
    std::string ToStringExtra() const override { return EncodeDestination(m_destination); }
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>&, std::span<const CScript>, FlatSigningProvider&) const override { return Vector(GetScriptForDestination(m_destination)); }
public:
    AddressDescriptor(CTxDestination destination) : DescriptorImpl({}, "addr"), m_destination(std::move(destination)) {}
    bool IsSolvable() const final { return false; }

    std::optional<OutputType> GetOutputType() const override
    {
        return OutputTypeFromDestination(m_destination);
    }
    bool IsSingleType() const final { return true; }
    bool ToPrivateString(const SigningProvider& arg, std::string& out) const final { return false; }

    std::optional<int64_t> ScriptSize() const override { return GetScriptForDestination(m_destination).size(); }
    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<AddressDescriptor>(m_destination);
    }
};

/** A parsed raw(H) descriptor. */
class RawDescriptor final : public DescriptorImpl
{
    const CScript m_script;
protected:
    std::string ToStringExtra() const override { return HexStr(m_script); }
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>&, std::span<const CScript>, FlatSigningProvider&) const override { return Vector(m_script); }
public:
    RawDescriptor(CScript script) : DescriptorImpl({}, "raw"), m_script(std::move(script)) {}
    bool IsSolvable() const final { return false; }

    std::optional<OutputType> GetOutputType() const override
    {
        CTxDestination dest;
        ExtractDestination(m_script, dest);
        return OutputTypeFromDestination(dest);
    }
    bool IsSingleType() const final { return true; }
    bool ToPrivateString(const SigningProvider& arg, std::string& out) const final { return false; }

    std::optional<int64_t> ScriptSize() const override { return m_script.size(); }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<RawDescriptor>(m_script);
    }
};

size_t PushDataLen(size_t data_len)
{
    if (data_len < OP_PUSHDATA1) return 1;
    if (data_len <= 0xff) return 2;
    if (data_len <= 0xffff) return 3;
    return 5;
}

size_t SigLenInScript(const PubkeyProvider& pubkey, bool use_max_sig)
{
    if (const auto pfx = pubkey.GetSchemePrefix()) {
        if (const auto* scheme = pq::SchemeFromPrefix(*pfx)) {
            return (use_max_sig ? scheme->sig_bytes_max : scheme->sig_bytes_fixed) + 1;
        }
    }

    // Descriptors are PQ-only. If provider metadata is missing here, overestimate
    // with the largest supported PQ scheme to avoid underestimating fees.
    return pq::MaxKnownSigBytesInScript(use_max_sig);
}

size_t SigElemSize(const PubkeyProvider& pubkey, bool use_max_sig)
{
    const size_t sig_len = SigLenInScript(pubkey, use_max_sig);
    return PushDataLen(sig_len) + sig_len;
}

size_t DataElemSize(size_t data_len)
{
    return PushDataLen(data_len) + data_len;
}

/** A parsed pk(P) descriptor. */
class PKDescriptor final : public DescriptorImpl
{
private:
protected:
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>& keys, std::span<const CScript>, FlatSigningProvider&) const override
    {
        return Vector(GetScriptForRawPubKey(keys[0]));
    }
public:
    PKDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "pk") {}
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override {
        return DataElemSize(m_pubkey_args[0]->GetSize()) + 1;
    }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        return SigElemSize(*m_pubkey_args[0], use_max_sig);
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return *MaxSatSize(use_max_sig) * WITNESS_SCALE_FACTOR;
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return 1; }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<PKDescriptor>(m_pubkey_args.at(0)->Clone());
    }
};

/** A parsed pkh(P) descriptor. */
class PKHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>& keys, std::span<const CScript>, FlatSigningProvider&) const override
    {
        CKeyID id = keys[0].GetID();
        return Vector(GetScriptForDestination(PKHash(id)));
    }
public:
    PKHDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "pkh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::LEGACY; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 1 + 20 + 1 + 1; }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        return SigElemSize(*m_pubkey_args[0], use_max_sig) + DataElemSize(m_pubkey_args[0]->GetSize());
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return *MaxSatSize(use_max_sig) * WITNESS_SCALE_FACTOR;
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return 2; }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<PKHDescriptor>(m_pubkey_args.at(0)->Clone());
    }
};

/** A parsed wpkh(P) descriptor. */
class WPKHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>& keys, std::span<const CScript>, FlatSigningProvider&) const override
    {
        CKeyID id = keys[0].GetID();
        return Vector(GetScriptForDestination(WitnessV0KeyHash(id)));
    }
public:
    WPKHDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "wpkh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 20; }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        return SigElemSize(*m_pubkey_args[0], use_max_sig) + DataElemSize(m_pubkey_args[0]->GetSize());
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return MaxSatSize(use_max_sig);
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return 2; }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<WPKHDescriptor>(m_pubkey_args.at(0)->Clone());
    }
};

/** A parsed combo(P) descriptor. */
class ComboDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>& keys, std::span<const CScript>, FlatSigningProvider& out) const override
    {
        std::vector<CScript> ret;
        CKeyID id = keys[0].GetID();
        ret.emplace_back(GetScriptForRawPubKey(keys[0])); // P2PK
        ret.emplace_back(GetScriptForDestination(PKHash(id))); // P2PKH
        CScript p2wpkh = GetScriptForDestination(WitnessV0KeyHash(id));
        out.scripts.emplace(CScriptID(p2wpkh), p2wpkh);
        ret.emplace_back(p2wpkh);
        ret.emplace_back(GetScriptForDestination(ScriptHash(p2wpkh))); // P2SH-P2WPKH
        return ret;
    }
public:
    ComboDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "combo") {}
    bool IsSingleType() const final { return false; }
    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<ComboDescriptor>(m_pubkey_args.at(0)->Clone());
    }
};

/** A parsed multi(...) or sortedmulti(...) descriptor */
class MultisigDescriptor final : public DescriptorImpl
{
    const int m_threshold;
    const bool m_sorted;
protected:
    std::string ToStringExtra() const override { return strprintf("%i", m_threshold); }
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>& keys, std::span<const CScript>, FlatSigningProvider&) const override {
        if (m_sorted) {
            std::vector<CPubKey> sorted_keys(keys);
            std::sort(sorted_keys.begin(), sorted_keys.end());
            return Vector(GetScriptForMultisig(m_threshold, sorted_keys));
        }
        return Vector(GetScriptForMultisig(m_threshold, keys));
    }
public:
    MultisigDescriptor(int threshold, std::vector<std::unique_ptr<PubkeyProvider>> providers, bool sorted = false) : DescriptorImpl(std::move(providers), sorted ? "sortedmulti" : "multi"), m_threshold(threshold), m_sorted(sorted) {}
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override {
        const auto n_keys = m_pubkey_args.size();
        auto op = [](int64_t acc, const std::unique_ptr<PubkeyProvider>& pk) { return acc + DataElemSize(pk->GetSize());};
        const auto pubkeys_size{std::accumulate(m_pubkey_args.begin(), m_pubkey_args.end(), int64_t{0}, op)};
        return 1 + BuildScript(n_keys).size() + BuildScript(m_threshold).size() + pubkeys_size;
    }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        std::vector<size_t> sig_elem_sizes;
        sig_elem_sizes.reserve(m_pubkey_args.size());
        for (const auto& key_arg : m_pubkey_args) {
            sig_elem_sizes.push_back(SigElemSize(*key_arg, use_max_sig));
        }
        std::sort(sig_elem_sizes.begin(), sig_elem_sizes.end(), std::greater<size_t>());

        // Leading OP_0 dummy element for CHECKMULTISIG bug compatibility.
        size_t sat_size = 1;
        for (size_t i = 0; i < static_cast<size_t>(m_threshold) && i < sig_elem_sizes.size(); ++i) {
            sat_size += sig_elem_sizes[i];
        }
        return sat_size;
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return *MaxSatSize(use_max_sig) * WITNESS_SCALE_FACTOR;
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return 1 + m_threshold; }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        providers.reserve(m_pubkey_args.size());
        std::transform(m_pubkey_args.begin(), m_pubkey_args.end(), providers.begin(), [](const std::unique_ptr<PubkeyProvider>& p) { return p->Clone(); });
        return std::make_unique<MultisigDescriptor>(m_threshold, std::move(providers), m_sorted);
    }
};

/** A parsed sh(...) descriptor. */
class SHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>&, std::span<const CScript> scripts, FlatSigningProvider& out) const override
    {
        auto ret = Vector(GetScriptForDestination(ScriptHash(scripts[0])));
        if (ret.size()) out.scripts.emplace(CScriptID(scripts[0]), scripts[0]);
        return ret;
    }

    bool IsSegwit() const { return m_subdescriptor_args[0]->GetOutputType() == OutputType::BECH32; }

public:
    SHDescriptor(std::unique_ptr<DescriptorImpl> desc) : DescriptorImpl({}, std::move(desc), "sh") {}

    std::optional<OutputType> GetOutputType() const override
    {
        assert(m_subdescriptor_args.size() == 1);
        if (IsSegwit()) return OutputType::P2SH_SEGWIT;
        return OutputType::LEGACY;
    }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 20 + 1; }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        if (const auto sat_size = m_subdescriptor_args[0]->MaxSatSize(use_max_sig)) {
            if (const auto subscript_size = m_subdescriptor_args[0]->ScriptSize()) {
                // The subscript is never witness data.
                const auto subscript_weight = (1 + *subscript_size) * WITNESS_SCALE_FACTOR;
                // The weight depends on whether the inner descriptor is satisfied using the witness stack.
                if (IsSegwit()) return subscript_weight + *sat_size;
                return subscript_weight + *sat_size * WITNESS_SCALE_FACTOR;
            }
        }
        return {};
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        if (const auto sub_elems = m_subdescriptor_args[0]->MaxSatisfactionElems()) return 1 + *sub_elems;
        return {};
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<SHDescriptor>(m_subdescriptor_args.at(0)->Clone());
    }
};

/** A parsed wsh(...) descriptor. */
class WSHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>&, std::span<const CScript> scripts, FlatSigningProvider& out) const override
    {
        auto ret = Vector(GetScriptForDestination(WitnessV0ScriptHash(scripts[0])));
        if (ret.size()) out.scripts.emplace(CScriptID(scripts[0]), scripts[0]);
        return ret;
    }
public:
    WSHDescriptor(std::unique_ptr<DescriptorImpl> desc) : DescriptorImpl({}, std::move(desc), "wsh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 32; }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        if (const auto sat_size = m_subdescriptor_args[0]->MaxSatSize(use_max_sig)) {
            if (const auto subscript_size = m_subdescriptor_args[0]->ScriptSize()) {
                return GetSizeOfCompactSize(*subscript_size) + *subscript_size + *sat_size;
            }
        }
        return {};
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return MaxSatSize(use_max_sig);
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        if (const auto sub_elems = m_subdescriptor_args[0]->MaxSatisfactionElems()) return 1 + *sub_elems;
        return {};
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<WSHDescriptor>(m_subdescriptor_args.at(0)->Clone());
    }
};

/** A parsed wsh512(...) descriptor. */
class WSH512Descriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>&, std::span<const CScript> scripts, FlatSigningProvider& out) const override
    {
        WitnessV1ScriptHash512 wit_hash{scripts[0]};
        auto ret = Vector(GetScriptForDestination(wit_hash));
        if (ret.size()) {
            const CScriptID script_id{RIPEMD160(std::span<const unsigned char>{wit_hash.begin(), wit_hash.size()})};
            out.scripts.emplace(script_id, scripts[0]);
        }
        return ret;
    }
public:
    WSH512Descriptor(std::unique_ptr<DescriptorImpl> desc) : DescriptorImpl({}, std::move(desc), "wsh512") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32PQ; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 64; }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        if (const auto sat_size = m_subdescriptor_args[0]->MaxSatSize(use_max_sig)) {
            if (const auto subscript_size = m_subdescriptor_args[0]->ScriptSize()) {
                return GetSizeOfCompactSize(*subscript_size) + *subscript_size + *sat_size;
            }
        }
        return {};
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return MaxSatSize(use_max_sig);
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        if (const auto sub_elems = m_subdescriptor_args[0]->MaxSatisfactionElems()) return 1 + *sub_elems;
        return {};
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<WSH512Descriptor>(m_subdescriptor_args.at(0)->Clone());
    }
};

/* We instantiate Miniscript with a key type that carries both an index into
 * DescriptorImpl::m_pubkey_args and the serialized pubkey size for script sizing.
 */
struct MiniscriptKey {
    uint32_t index;
    size_t key_size;
    uint8_t scheme_prefix{0};
    size_t size() const { return key_size; }
    uint8_t operator[](size_t) const { return scheme_prefix; }
};

/**
 * The context for converting a Miniscript descriptor into a Script.
 */
class ScriptMaker {
    //! Keys contained in the Miniscript (the evaluation of DescriptorImpl::m_pubkey_args).
    const std::vector<CPubKey>& m_keys;

    //! Get the ripemd160(sha256()) hash of this key.
    uint160 GetHash160(const MiniscriptKey& key) const {
        return m_keys[key.index].GetID();
    }

public:
    explicit ScriptMaker(const std::vector<CPubKey>& keys LIFETIMEBOUND) : m_keys(keys) {}

    std::vector<unsigned char> ToPKBytes(const MiniscriptKey& key) const {
        return {m_keys[key.index].begin(), m_keys[key.index].end()};
    }

    std::vector<unsigned char> ToPKHBytes(const MiniscriptKey& key) const {
        auto id = GetHash160(key);
        return {id.begin(), id.end()};
    }
};

/**
 * The context for converting a Miniscript descriptor to its textual form.
 */
class StringMaker {
    //! To convert private keys for private descriptors.
    const SigningProvider* m_arg;
    //! Keys contained in the Miniscript (a reference to DescriptorImpl::m_pubkey_args).
    const std::vector<std::unique_ptr<PubkeyProvider>>& m_pubkeys;
    //! Whether to serialize keys as private or public.
    bool m_private;

public:
    StringMaker(const SigningProvider* arg LIFETIMEBOUND, const std::vector<std::unique_ptr<PubkeyProvider>>& pubkeys LIFETIMEBOUND, bool priv)
        : m_arg(arg), m_pubkeys(pubkeys), m_private(priv) {}

    std::optional<std::string> ToString(const MiniscriptKey& key) const
    {
        std::string ret;
        if (m_private) {
            if (!m_pubkeys[key.index]->ToPrivateString(*m_arg, ret)) return {};
        } else {
            ret = m_pubkeys[key.index]->ToString();
        }
        return ret;
    }
};

class MiniscriptDescriptor final : public DescriptorImpl
{
private:
    miniscript::NodeRef<MiniscriptKey> m_node;

protected:
    std::vector<CScript> MakeScripts(const std::vector<CPubKey>& keys, std::span<const CScript> scripts,
                                     FlatSigningProvider& provider) const override
    {
        for (const auto& key : keys) {
            provider.pubkeys.emplace(key.GetID(), key);
        }
        return Vector(m_node->ToScript(ScriptMaker(keys)));
    }

public:
    MiniscriptDescriptor(std::vector<std::unique_ptr<PubkeyProvider>> providers, miniscript::NodeRef<MiniscriptKey> node)
        : DescriptorImpl(std::move(providers), "?"), m_node(std::move(node)) {}

    bool ToStringHelper(const SigningProvider* arg, std::string& out, const StringType type,
                        const DescriptorCache* cache = nullptr) const override
    {
        if (const auto res = m_node->ToString(StringMaker(arg, m_pubkey_args, type == StringType::PRIVATE))) {
            out = *res;
            return true;
        }
        return false;
    }

    bool IsSolvable() const override { return true; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return m_node->ScriptSize(); }

    std::optional<int64_t> MaxSatSize(bool) const override {
        // Miniscript internally computes witness sizes using worst-case signatures.
        return m_node->GetWitnessSize();
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        return m_node->GetStackSize();
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        providers.reserve(m_pubkey_args.size());
        for (const auto& arg : m_pubkey_args) {
            providers.push_back(arg->Clone());
        }
        return std::make_unique<MiniscriptDescriptor>(std::move(providers), m_node->Clone());
    }
};

////////////////////////////////////////////////////////////////////////////
// Parser                                                                 //
////////////////////////////////////////////////////////////////////////////

enum class ParseScriptContext {
    TOP,     //!< Top-level context (script goes directly in scriptPubKey)
    P2SH,    //!< Inside sh() (script becomes P2SH redeemScript)
    P2WPKH,  //!< Inside wpkh() (no script, pubkey only)
    P2WSH,   //!< Inside wsh() (script becomes v0 witness script)
};

std::optional<uint32_t> ParseKeyPathNum(std::span<const char> elem, bool& apostrophe, std::string& error, bool& has_hardened)
{
    bool hardened = false;
    if (elem.size() > 0) {
        const char last = elem[elem.size() - 1];
        if (last == '\'' || last == 'h') {
            elem = elem.first(elem.size() - 1);
            hardened = true;
            apostrophe = last == '\'';
        }
    }
    const auto p{ToIntegral<uint32_t>(std::string_view{elem.begin(), elem.end()})};
    if (!p) {
        error = strprintf("Key path value '%s' is not a valid uint32", std::string_view{elem.begin(), elem.end()});
        return std::nullopt;
    } else if (*p > 0x7FFFFFFFUL) {
        error = strprintf("Key path value %u is out of range", *p);
        return std::nullopt;
    }
    has_hardened = has_hardened || hardened;

    return std::make_optional<uint32_t>(*p | (((uint32_t)hardened) << 31));
}

/** Parse a public key that excludes origin information. */
std::vector<std::unique_ptr<PubkeyProvider>> ParsePubkeyInner(uint32_t key_exp_index, const std::span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, bool& apostrophe, std::string& error)
{
    std::vector<std::unique_ptr<PubkeyProvider>> ret;
    auto split = Split(sp, '/');
    std::string str(split[0].begin(), split[0].end());
    if (str.size() == 0) {
        error = "No key provided";
        return {};
    }
    if (IsSpace(str.front()) || IsSpace(str.back())) {
        error = strprintf("Key '%s' is invalid due to whitespace", str);
        return {};
    }
    if (split.size() == 1) {
        if (IsHex(str)) {
            std::vector<unsigned char> data = ParseHex(str);
            CPubKey pubkey(data);
            if (pubkey.IsValid() && !pubkey.IsValidNonHybrid()) {
                error = "Hybrid public keys are not allowed";
                return {};
            }
            if (pubkey.IsFullyValid()) {
                if (pubkey.size() == 0 || pq::SchemeFromPrefix(pubkey[0]) == nullptr) {
                    error = "Pubkey must include a valid PQ scheme prefix";
                    return {};
                }
                ret.emplace_back(std::make_unique<ConstPubkeyProvider>(key_exp_index, pubkey));
                return ret;
            }
            error = strprintf("Pubkey '%s' is invalid", str);
            return {};
        }
        CKey key = DecodeSecret(str);
        if (key.IsValid()) {
            CPubKey pubkey = key.GetPubKey();
            if (pubkey.size() == 0 || pq::SchemeFromPrefix(pubkey[0]) == nullptr) {
                error = "Pubkey must include a valid PQ scheme prefix";
                return {};
            }
            out.keys.emplace(pubkey.GetID(), key);
            ret.emplace_back(std::make_unique<ConstPubkeyProvider>(key_exp_index, pubkey));
            return ret;
        }
        error = "Pubkey must be raw PQ prefixed hex (WIF private keys are not supported)";
        return {};
    }

    // PQHD key expression: pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/indexh|*h
    if (str.starts_with("pqhd(") && str.ends_with(")")) {
        if (ctx == ParseScriptContext::P2WPKH) {
            // No extra restrictions beyond key validity.
        }
        const std::string seed_hex = str.substr(5, str.size() - 6);
        const auto seed_id = uint256::FromHex(seed_hex);
        if (!seed_id) {
            error = strprintf("pqhd() seed id is not 32-byte hex (%u characters)", seed_hex.size());
            return {};
        }
        if (split.size() != 7) {
            error = strprintf("pqhd() expects 6 hardened path elements after the seed id, got %u", split.size() - 1);
            return {};
        }

        KeyPath path;
        path.reserve(6);
        bool wildcard{false};
        bool used_apostrophe{false};
        for (size_t i = 1; i < split.size(); ++i) {
            const std::span<const char>& elem = split[i];
            if (elem.size() >= 2 && elem.front() == '<' && elem.back() == '>') {
                error = "pqhd() does not support multipath derivation";
                return {};
            }
            if (i == split.size() - 1 && (std::ranges::equal(elem, std::span{"*h"}.first(2)) || std::ranges::equal(elem, std::span{"*'"}.first(2)))) {
                wildcard = true;
                used_apostrophe = used_apostrophe || std::ranges::equal(elem, std::span{"*'"}.first(2));
                continue;
            }
            bool elem_apostrophe{false};
            bool has_hardened{false};
            auto v = ParseKeyPathNum(elem, elem_apostrophe, error, has_hardened);
            if (!v) return {};
            used_apostrophe = used_apostrophe || elem_apostrophe;
            if (!(*v >> 31)) {
                error = "pqhd() derivation must be hardened-only";
                return {};
            }
            path.push_back(*v);
        }

        if (wildcard && path.size() != 5) {
            error = "pqhd() wildcard form must have exactly 5 fixed elements before *h";
            return {};
        }
        if (!wildcard && path.size() != 6) {
            error = "pqhd() fixed form must have exactly 6 hardened path elements";
            return {};
        }

        const auto check_eq = [&](size_t idx, uint32_t expected, std::string_view name) -> bool {
            if (idx >= path.size()) return false;
            const uint32_t v = path[idx] & 0x7FFFFFFFUL;
            if (v != expected) {
                error = strprintf("pqhd() %s must be %u, got %u", name, expected, v);
                return false;
            }
            return true;
        };
        if (!check_eq(0, pqhd::PURPOSE, "purpose")) return {};
        if (!check_eq(1, pqhd::COIN_TYPE, "coin_type")) return {};

        const uint32_t scheme_u32 = path[2] & 0x7FFFFFFFUL;
        if (scheme_u32 > 0xFF) {
            error = strprintf("pqhd() scheme id must fit in uint8, got %u", scheme_u32);
            return {};
        }
        const auto scheme_prefix = static_cast<uint8_t>(scheme_u32);
        if (pq::SchemeFromPrefix(scheme_prefix) == nullptr) {
            error = strprintf("pqhd() scheme id %u is not recognized", scheme_u32);
            return {};
        }

        const uint32_t change_u32 = path[4] & 0x7FFFFFFFUL;
        if (change_u32 > 1) {
            error = strprintf("pqhd() change must be 0 or 1, got %u", change_u32);
            return {};
        }

        apostrophe = apostrophe || used_apostrophe;
        ret.emplace_back(std::make_unique<PQHDPubkeyProvider>(key_exp_index, *seed_id, std::move(path), wildcard ? DeriveType::HARDENED : DeriveType::NO, scheme_prefix));
        return ret;
    }

    error = strprintf("key '%s' is not valid", str);
    return {};
}

/** Parse a public key (origin metadata not supported). */
// NOLINTNEXTLINE(misc-no-recursion)
std::vector<std::unique_ptr<PubkeyProvider>> ParsePubkey(uint32_t& key_exp_index, const std::span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, std::string& error)
{
    bool apostrophe = false;
    if (!sp.empty() && sp.front() == '[') {
        error = "Key origin metadata is not supported";
        return {};
    }
    auto ret = ParsePubkeyInner(key_exp_index, sp, ctx, out, apostrophe, error);
    if (ret.empty()) return ret;
    for (const auto& p : ret) {
        const auto pfx = p->GetSchemePrefix();
        if (!pfx || pq::SchemeFromPrefix(*pfx) == nullptr) {
            error = "Pubkey must include a valid PQ scheme prefix";
            return {};
        }
    }
    return ret;
}

std::unique_ptr<PubkeyProvider> InferPubkey(const CPubKey& pubkey, ParseScriptContext ctx, const SigningProvider& provider)
{
    // Key cannot be hybrid
    if (!pubkey.IsValidNonHybrid()) {
        return nullptr;
    }
    if (pubkey.size() == 0 || pq::SchemeFromPrefix(pubkey[0]) == nullptr) {
        return nullptr;
    }
    std::unique_ptr<PubkeyProvider> key_provider = std::make_unique<ConstPubkeyProvider>(0, pubkey);
    return key_provider;
}

/**
 * The context for parsing a Miniscript descriptor (either from Script or from its textual representation).
 */
struct KeyParser {
    //! The Key type for miniscript parsing.
    using Key = MiniscriptKey;
    //! Must not be nullptr if parsing from string.
    FlatSigningProvider* m_out;
    //! Must not be nullptr if parsing from Script.
    const SigningProvider* m_in;
    //! List of multipath expanded keys contained in the Miniscript.
    mutable std::vector<std::vector<std::unique_ptr<PubkeyProvider>>> m_keys;
    //! Used to detect key parsing errors within a Miniscript.
    mutable std::string m_key_parsing_error;
    //! The script context we're operating within (P2WSH only).
    const miniscript::MiniscriptContext m_script_ctx;
    //! The number of keys that were parsed before starting to parse this Miniscript descriptor.
    uint32_t m_offset;

    KeyParser(FlatSigningProvider* out LIFETIMEBOUND, const SigningProvider* in LIFETIMEBOUND,
              miniscript::MiniscriptContext ctx, uint32_t offset = 0)
        : m_out(out), m_in(in), m_script_ctx(ctx), m_offset(offset) {}

    bool KeyCompare(const Key& a, const Key& b) const {
        return *m_keys.at(a.index).at(0) < *m_keys.at(b.index).at(0);
    }

    ParseScriptContext ParseContext() const {
        return ParseScriptContext::P2WSH;
    }

    template<typename I> std::optional<Key> FromString(I begin, I end) const
    {
        assert(m_out);
        Key key{static_cast<uint32_t>(m_keys.size()), 0, 0};
        uint32_t exp_index = m_offset + key.index;
        auto pk = ParsePubkey(exp_index, {&*begin, &*end}, ParseContext(), *m_out, m_key_parsing_error);
        if (pk.empty()) return {};
        key.key_size = pk.at(0)->GetSize();
        const auto pfx = pk.at(0)->GetSchemePrefix();
        if (!pfx || pq::SchemeFromPrefix(*pfx) == nullptr) {
            m_key_parsing_error = "Pubkey must include a valid PQ scheme prefix";
            return {};
        }
        key.scheme_prefix = *pfx;
        m_keys.emplace_back(std::move(pk));
        return key;
    }

    std::optional<std::string> ToString(const Key& key) const
    {
        return m_keys.at(key.index).at(0)->ToString();
    }

    template<typename I> std::optional<Key> FromPKBytes(I begin, I end) const
    {
        assert(m_in);
        Key key{static_cast<uint32_t>(m_keys.size()), 0, 0};
        CPubKey pubkey(begin, end);
        if (auto pubkey_provider = InferPubkey(pubkey, ParseContext(), *m_in)) {
            m_keys.emplace_back();
            key.key_size = pubkey_provider->GetSize();
            if (pubkey.size() == 0 || pq::SchemeFromPrefix(pubkey[0]) == nullptr) {
                m_key_parsing_error = "Pubkey must include a valid PQ scheme prefix";
                return {};
            }
            key.scheme_prefix = pubkey[0];
            m_keys.back().push_back(std::move(pubkey_provider));
            return key;
        }
        return {};
    }

    template<typename I> std::optional<Key> FromPKHBytes(I begin, I end) const
    {
        assert(end - begin == 20);
        assert(m_in);
        uint160 hash;
        std::copy(begin, end, hash.begin());
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (m_in->GetPubKey(keyid, pubkey)) {
            if (auto pubkey_provider = InferPubkey(pubkey, ParseContext(), *m_in)) {
                Key key{static_cast<uint32_t>(m_keys.size()), 0, 0};
                key.key_size = pubkey_provider->GetSize();
                if (pubkey.size() == 0 || pq::SchemeFromPrefix(pubkey[0]) == nullptr) {
                    m_key_parsing_error = "Pubkey must include a valid PQ scheme prefix";
                    return {};
                }
                key.scheme_prefix = pubkey[0];
                m_keys.emplace_back();
                m_keys.back().push_back(std::move(pubkey_provider));
                return key;
            }
        }
        return {};
    }

    miniscript::MiniscriptContext MsContext() const {
        return m_script_ctx;
    }
};

/** Parse a script in a particular context. */
// NOLINTNEXTLINE(misc-no-recursion)
std::vector<std::unique_ptr<DescriptorImpl>> ParseScript(uint32_t& key_exp_index, std::span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, std::string& error)
{
    using namespace script;
    Assume(ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH);
    std::vector<std::unique_ptr<DescriptorImpl>> ret;
    auto expr = Expr(sp);
    if (Func("pk", expr)) {
        auto pubkeys = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (pubkeys.empty()) {
            error = strprintf("pk(): %s", error);
            return {};
        }
        ++key_exp_index;
        for (auto& pubkey : pubkeys) {
            ret.emplace_back(std::make_unique<PKDescriptor>(std::move(pubkey)));
        }
        return ret;
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH) && Func("pkh", expr)) {
        auto pubkeys = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (pubkeys.empty()) {
            error = strprintf("pkh(): %s", error);
            return {};
        }
        ++key_exp_index;
        for (auto& pubkey : pubkeys) {
            ret.emplace_back(std::make_unique<PKHDescriptor>(std::move(pubkey)));
        }
        return ret;
    }
    if (ctx == ParseScriptContext::TOP && Func("combo", expr)) {
        auto pubkeys = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (pubkeys.empty()) {
            error = strprintf("combo(): %s", error);
            return {};
        }
        ++key_exp_index;
        for (auto& pubkey : pubkeys) {
            ret.emplace_back(std::make_unique<ComboDescriptor>(std::move(pubkey)));
        }
        return ret;
    } else if (Func("combo", expr)) {
        error = "Can only have combo() at top level";
        return {};
    }
    const bool multi = Func("multi", expr);
    const bool sortedmulti = !multi && Func("sortedmulti", expr);
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH) && (multi || sortedmulti)) {
        auto threshold = Expr(expr);
        uint32_t thres;
        std::vector<std::vector<std::unique_ptr<PubkeyProvider>>> providers; // List of multipath expanded pubkeys
        if (const auto maybe_thres{ToIntegral<uint32_t>(std::string_view{threshold.begin(), threshold.end()})}) {
            thres = *maybe_thres;
        } else {
            error = strprintf("Multi threshold '%s' is not valid", std::string(threshold.begin(), threshold.end()));
            return {};
        }
        size_t script_size = 0;
        const auto push_size = [](size_t len) -> size_t {
            if (len < 0x4c) return 1;
            if (len <= 0xff) return 2;
            if (len <= 0xffff) return 3;
            return 5;
        };
        size_t max_providers_len = 0;
        while (expr.size()) {
            if (!Const(",", expr)) {
                error = strprintf("Multi: expected ',', got '%c'", expr[0]);
                return {};
            }
            auto arg = Expr(expr);
            auto pks = ParsePubkey(key_exp_index, arg, ctx, out, error);
            if (pks.empty()) {
                error = strprintf("Multi: %s", error);
                return {};
            }
            const size_t key_size = pks.at(0)->GetSize();
            script_size += push_size(key_size) + key_size;
            max_providers_len = std::max(max_providers_len, pks.size());
            providers.emplace_back(std::move(pks));
            key_exp_index++;
        }
        if (providers.empty() || providers.size() > MAX_PUBKEYS_PER_MULTISIG) {
            error = strprintf("Cannot have %u keys in multisig; must have between 1 and %d keys, inclusive", providers.size(), MAX_PUBKEYS_PER_MULTISIG);
            return {};
        } else if (thres < 1) {
            error = strprintf("Multisig threshold cannot be %d, must be at least 1", thres);
            return {};
        } else if (thres > providers.size()) {
            error = strprintf("Multisig threshold cannot be larger than the number of keys; threshold is %d but only %u keys specified", thres, providers.size());
            return {};
        }
        if (ctx == ParseScriptContext::TOP) {
            if (providers.size() > 3) {
                error = strprintf("Cannot have %u pubkeys in bare multisig; only at most 3 pubkeys", providers.size());
                return {};
            }
        }
        if (ctx == ParseScriptContext::P2SH) {
            // Enforce the P2SH script size limit.
            if (script_size + 3 > MAX_SCRIPT_ELEMENT_SIZE) {
                error = strprintf("P2SH script is too large, %d bytes is larger than %d bytes", script_size + 3, MAX_SCRIPT_ELEMENT_SIZE);
                return {};
            }
        }

        // Make sure all vecs are of the same length, or exactly length 1
        // For length 1 vectors, clone key providers until vector is the same length
        for (auto& vec : providers) {
            if (vec.size() == 1) {
                for (size_t i = 1; i < max_providers_len; ++i) {
                    vec.emplace_back(vec.at(0)->Clone());
                }
            } else if (vec.size() != max_providers_len) {
                error = strprintf("multi(): Multipath derivation paths have mismatched lengths");
                return {};
            }
        }

        // Build the final descriptors vector
        for (size_t i = 0; i < max_providers_len; ++i) {
            // Build final pubkeys vectors by retrieving the i'th subscript for each vector in subscripts
            std::vector<std::unique_ptr<PubkeyProvider>> pubs;
            pubs.reserve(providers.size());
            for (auto& pub : providers) {
                pubs.emplace_back(std::move(pub.at(i)));
            }
            ret.emplace_back(std::make_unique<MultisigDescriptor>(thres, std::move(pubs), sortedmulti));
        }
        return ret;
    } else if (multi || sortedmulti) {
        error = "Can only have multi/sortedmulti at top level, in sh(), wsh(), or wsh512()";
        return {};
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH) && Func("wpkh", expr)) {
        auto pubkeys = ParsePubkey(key_exp_index, expr, ParseScriptContext::P2WPKH, out, error);
        if (pubkeys.empty()) {
            error = strprintf("wpkh(): %s", error);
            return {};
        }
        key_exp_index++;
        for (auto& pubkey : pubkeys) {
            ret.emplace_back(std::make_unique<WPKHDescriptor>(std::move(pubkey)));
        }
        return ret;
    } else if (Func("wpkh", expr)) {
        error = "Can only have wpkh() at top level or inside sh()";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("sh", expr)) {
        auto descs = ParseScript(key_exp_index, expr, ParseScriptContext::P2SH, out, error);
        if (descs.empty() || expr.size()) return {};
        std::vector<std::unique_ptr<DescriptorImpl>> ret;
        ret.reserve(descs.size());
        for (auto& desc : descs) {
            ret.push_back(std::make_unique<SHDescriptor>(std::move(desc)));
        }
        return ret;
    } else if (Func("sh", expr)) {
        error = "Can only have sh() at top level";
        return {};
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH) && Func("wsh", expr)) {
        auto descs = ParseScript(key_exp_index, expr, ParseScriptContext::P2WSH, out, error);
        if (descs.empty() || expr.size()) return {};
        for (auto& desc : descs) {
            ret.emplace_back(std::make_unique<WSHDescriptor>(std::move(desc)));
        }
        return ret;
    } else if (Func("wsh", expr)) {
        error = "Can only have wsh() at top level or inside sh()";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("wsh512", expr)) {
        auto descs = ParseScript(key_exp_index, expr, ParseScriptContext::P2WSH, out, error);
        if (descs.empty() || expr.size()) return {};
        for (auto& desc : descs) {
            ret.emplace_back(std::make_unique<WSH512Descriptor>(std::move(desc)));
        }
        return ret;
    } else if (Func("wsh512", expr)) {
        error = "Can only have wsh512() at top level";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("addr", expr)) {
        CTxDestination dest = DecodeDestination(std::string(expr.begin(), expr.end()));
        if (!IsValidDestination(dest)) {
            error = "Address is not valid";
            return {};
        }
        ret.emplace_back(std::make_unique<AddressDescriptor>(std::move(dest)));
        return ret;
    } else if (Func("addr", expr)) {
        error = "Can only have addr() at top level";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("raw", expr)) {
        std::string str(expr.begin(), expr.end());
        if (!IsHex(str)) {
            error = "Raw script is not hex";
            return {};
        }
        auto bytes = ParseHex(str);
        ret.emplace_back(std::make_unique<RawDescriptor>(CScript(bytes.begin(), bytes.end())));
        return ret;
    } else if (Func("raw", expr)) {
        error = "Can only have raw() at top level";
        return {};
    }
    // Process miniscript expressions.
    {
        const auto script_ctx{miniscript::MiniscriptContext::P2WSH};
        KeyParser parser(/*out = */&out, /* in = */nullptr, /* ctx = */script_ctx, key_exp_index);
        auto node = miniscript::FromString(std::string(expr.begin(), expr.end()), parser);
        if (parser.m_key_parsing_error != "") {
            error = std::move(parser.m_key_parsing_error);
            return {};
        }
        if (node) {
            if (ctx != ParseScriptContext::P2WSH) {
                error = "Miniscript expressions can only be used in wsh()/wsh512().";
                return {};
            }
            if (!node->IsSane() || node->IsNotSatisfiable()) {
                // Try to find the first insane sub for better error reporting.
                auto insane_node = node.get();
                if (const auto sub = node->FindInsaneSub()) insane_node = sub;
                if (const auto str = insane_node->ToString(parser)) error = *str;
                if (!insane_node->IsValid()) {
                    error += " is invalid";
                } else if (!node->IsSane()) {
                    error += " is not sane";
                    if (!insane_node->IsNonMalleable()) {
                        error += ": malleable witnesses exist";
                    } else if (insane_node == node.get() && !insane_node->NeedsSignature()) {
                        error += ": witnesses without signature exist";
                    } else if (!insane_node->CheckTimeLocksMix()) {
                        error += ": contains mixes of timelocks expressed in blocks and seconds";
                    } else if (!insane_node->CheckDuplicateKey()) {
                        error += ": contains duplicate public keys";
                    } else if (!insane_node->ValidSatisfactions()) {
                        error += ": needs witnesses that may exceed resource limits";
                    }
                } else {
                    error += " is not satisfiable";
                }
                return {};
            }
            // A signature check is required for a miniscript to be sane. Therefore no sane miniscript
            // may have an empty list of public keys.
            CHECK_NONFATAL(!parser.m_keys.empty());
            key_exp_index += parser.m_keys.size();
            // Make sure all vecs are of the same length, or exactly length 1
            // For length 1 vectors, clone subdescs until vector is the same length
            size_t num_multipath = std::max_element(parser.m_keys.begin(), parser.m_keys.end(),
                    [](const std::vector<std::unique_ptr<PubkeyProvider>>& a, const std::vector<std::unique_ptr<PubkeyProvider>>& b) {
                        return a.size() < b.size();
                    })->size();

            for (auto& vec : parser.m_keys) {
                if (vec.size() == 1) {
                    for (size_t i = 1; i < num_multipath; ++i) {
                        vec.emplace_back(vec.at(0)->Clone());
                    }
                } else if (vec.size() != num_multipath) {
                    error = strprintf("Miniscript: Multipath derivation paths have mismatched lengths");
                    return {};
                }
            }

            // Build the final descriptors vector
            for (size_t i = 0; i < num_multipath; ++i) {
                // Build final pubkeys vectors by retrieving the i'th subscript for each vector in subscripts
                std::vector<std::unique_ptr<PubkeyProvider>> pubs;
                pubs.reserve(parser.m_keys.size());
                for (auto& pub : parser.m_keys) {
                    pubs.emplace_back(std::move(pub.at(i)));
                }
                ret.emplace_back(std::make_unique<MiniscriptDescriptor>(std::move(pubs), node->Clone()));
            }
            return ret;
        }
    }
    if (ctx == ParseScriptContext::P2SH) {
        error = "A function is needed within P2SH";
        return {};
    } else if (ctx == ParseScriptContext::P2WSH) {
        error = "A function is needed within wsh()/wsh512()";
        return {};
    }
    error = strprintf("'%s' is not a valid descriptor function", std::string(expr.begin(), expr.end()));
    return {};
}

// NOLINTNEXTLINE(misc-no-recursion)
std::unique_ptr<DescriptorImpl> InferScript(const CScript& script, ParseScriptContext ctx, const SigningProvider& provider)
{
    std::vector<std::vector<unsigned char>> data;
    TxoutType txntype = Solver(script, data);

    if (txntype == TxoutType::PUBKEY && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        CPubKey pubkey(data[0]);
        if (auto pubkey_provider = InferPubkey(pubkey, ctx, provider)) {
            return std::make_unique<PKDescriptor>(std::move(pubkey_provider));
        }
    }
    if (txntype == TxoutType::PUBKEYHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        uint160 hash(data[0]);
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (provider.GetPubKey(keyid, pubkey)) {
            if (auto pubkey_provider = InferPubkey(pubkey, ctx, provider)) {
                return std::make_unique<PKHDescriptor>(std::move(pubkey_provider));
            }
        }
    }
    if (txntype == TxoutType::WITNESS_V0_KEYHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH)) {
        uint160 hash(data[0]);
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (provider.GetPubKey(keyid, pubkey)) {
            if (auto pubkey_provider = InferPubkey(pubkey, ParseScriptContext::P2WPKH, provider)) {
                return std::make_unique<WPKHDescriptor>(std::move(pubkey_provider));
            }
        }
    }
    if (txntype == TxoutType::MULTISIG && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        bool ok = true;
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        for (size_t i = 1; i + 1 < data.size(); ++i) {
            CPubKey pubkey(data[i]);
            if (auto pubkey_provider = InferPubkey(pubkey, ctx, provider)) {
                providers.push_back(std::move(pubkey_provider));
            } else {
                ok = false;
                break;
            }
        }
        if (ok) return std::make_unique<MultisigDescriptor>((int)data[0][0], std::move(providers));
    }
    if (txntype == TxoutType::SCRIPTHASH && ctx == ParseScriptContext::TOP) {
        uint160 hash(data[0]);
        CScriptID scriptid(hash);
        CScript subscript;
        if (provider.GetCScript(scriptid, subscript)) {
            auto sub = InferScript(subscript, ParseScriptContext::P2SH, provider);
            if (sub) return std::make_unique<SHDescriptor>(std::move(sub));
        }
    }
    if (txntype == TxoutType::WITNESS_V0_SCRIPTHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH)) {
        CScriptID scriptid{RIPEMD160(data[0])};
        CScript subscript;
        if (provider.GetCScript(scriptid, subscript)) {
            auto sub = InferScript(subscript, ParseScriptContext::P2WSH, provider);
            if (sub) return std::make_unique<WSHDescriptor>(std::move(sub));
        }
    }
    if (txntype == TxoutType::WITNESS_V1_SCRIPTHASH_512 && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH)) {
        CScriptID scriptid{RIPEMD160(data[0])};
        CScript subscript;
        if (provider.GetCScript(scriptid, subscript)) {
            auto sub = InferScript(subscript, ParseScriptContext::P2WSH, provider);
            if (sub) return std::make_unique<WSH512Descriptor>(std::move(sub));
        }
    }
    if (ctx == ParseScriptContext::P2WSH) {
        const auto script_ctx{miniscript::MiniscriptContext::P2WSH};
        KeyParser parser(/* out = */nullptr, /* in = */&provider, /* ctx = */script_ctx);
        auto node = miniscript::FromScript(script, parser);
        if (node && node->IsSane()) {
            std::vector<std::unique_ptr<PubkeyProvider>> keys;
            keys.reserve(parser.m_keys.size());
            for (auto& key : parser.m_keys) {
                keys.emplace_back(std::move(key.at(0)));
            }
            return std::make_unique<MiniscriptDescriptor>(std::move(keys), std::move(node));
        }
    }

    // The following descriptors are all top-level only descriptors.
    // So if we are not at the top level, return early.
    if (ctx != ParseScriptContext::TOP) return nullptr;

    CTxDestination dest;
    if (ExtractDestination(script, dest)) {
        if (GetScriptForDestination(dest) == script) {
            return std::make_unique<AddressDescriptor>(std::move(dest));
        }
    }

    return std::make_unique<RawDescriptor>(script);
}


} // namespace

/** Check a descriptor checksum, and update desc to be the checksum-less part. */
bool CheckChecksum(std::span<const char>& sp, bool require_checksum, std::string& error, std::string* out_checksum = nullptr)
{
    auto check_split = Split(sp, '#');
    if (check_split.size() > 2) {
        error = "Multiple '#' symbols";
        return false;
    }
    if (check_split.size() == 1 && require_checksum){
        error = "Missing checksum";
        return false;
    }
    if (check_split.size() == 2) {
        if (check_split[1].size() != 8) {
            error = strprintf("Expected 8 character checksum, not %u characters", check_split[1].size());
            return false;
        }
    }
    auto checksum = DescriptorChecksum(check_split[0]);
    if (checksum.empty()) {
        error = "Invalid characters in payload";
        return false;
    }
    if (check_split.size() == 2) {
        if (!std::equal(checksum.begin(), checksum.end(), check_split[1].begin())) {
            error = strprintf("Provided checksum '%s' does not match computed checksum '%s'", std::string(check_split[1].begin(), check_split[1].end()), checksum);
            return false;
        }
    }
    if (out_checksum) *out_checksum = std::move(checksum);
    sp = check_split[0];
    return true;
}

std::vector<std::unique_ptr<Descriptor>> Parse(const std::string& descriptor, FlatSigningProvider& out, std::string& error, bool require_checksum)
{
    std::span<const char> sp{descriptor};
    if (!CheckChecksum(sp, require_checksum, error)) return {};
    uint32_t key_exp_index = 0;
    auto ret = ParseScript(key_exp_index, sp, ParseScriptContext::TOP, out, error);
    if (sp.size() == 0 && !ret.empty()) {
        std::vector<std::unique_ptr<Descriptor>> descs;
        descs.reserve(ret.size());
        for (auto& r : ret) {
            descs.emplace_back(std::unique_ptr<Descriptor>(std::move(r)));
        }
        return descs;
    }
    return {};
}

std::string GetDescriptorChecksum(const std::string& descriptor)
{
    std::string ret;
    std::string error;
    std::span<const char> sp{descriptor};
    if (!CheckChecksum(sp, false, error, &ret)) return "";
    return ret;
}

std::unique_ptr<Descriptor> InferDescriptor(const CScript& script, const SigningProvider& provider)
{
    return InferScript(script, ParseScriptContext::TOP, provider);
}

uint256 DescriptorID(const Descriptor& desc)
{
    std::string desc_str = desc.ToString(/*compat_format=*/true);
    uint256 id;
    CSHA256().Write((unsigned char*)desc_str.data(), desc_str.size()).Finalize(id.begin());
    return id;
}

void DescriptorCache::CacheDerivedPubKey(uint32_t key_exp_pos, uint32_t der_index, const CPubKey& pubkey)
{
    auto& pubkeys = m_derived_pubkeys[key_exp_pos];
    pubkeys[der_index] = pubkey;
}

bool DescriptorCache::GetCachedDerivedPubKey(uint32_t key_exp_pos, uint32_t der_index, CPubKey& pubkey) const
{
    const auto& key_exp_it = m_derived_pubkeys.find(key_exp_pos);
    if (key_exp_it == m_derived_pubkeys.end()) return false;
    const auto& der_it = key_exp_it->second.find(der_index);
    if (der_it == key_exp_it->second.end()) return false;
    pubkey = der_it->second;
    return true;
}

DescriptorCache DescriptorCache::MergeAndDiff(const DescriptorCache& other)
{
    DescriptorCache diff;
    for (const auto& derived_pubkey_map_pair : other.GetCachedDerivedPubKeys()) {
        for (const auto& derived_pubkey_pair : derived_pubkey_map_pair.second) {
            CPubKey pubkey;
            if (GetCachedDerivedPubKey(derived_pubkey_map_pair.first, derived_pubkey_pair.first, pubkey)) {
                if (pubkey != derived_pubkey_pair.second) {
                    throw std::runtime_error(std::string(__func__) + ": New cached derived pubkey does not match already cached derived pubkey");
                }
                continue;
            }
            CacheDerivedPubKey(derived_pubkey_map_pair.first, derived_pubkey_pair.first, derived_pubkey_pair.second);
            diff.CacheDerivedPubKey(derived_pubkey_map_pair.first, derived_pubkey_pair.first, derived_pubkey_pair.second);
        }
    }
    return diff;
}

std::unordered_map<uint32_t, PubKeyMap> DescriptorCache::GetCachedDerivedPubKeys() const
{
    return m_derived_pubkeys;
}
