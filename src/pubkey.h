// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include <hash.h>
#include <pq/pq_scheme.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>
#include <uint512.h>

#include <cstring>
#include <vector>

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    explicit CKeyID(const uint160& in) : uint160(in) {}
};

/** An encapsulated public key. */
class CPubKey
{
public:
    // Maximum serialized pubkey size (supports all currently defined PQ schemes).
    static constexpr unsigned int MAX_SIZE = pq::kMLDSA87Info.pubkey_bytes + 1;

private:

    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
     */
    std::vector<unsigned char> vch;

    //! Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader)
    {
        // PQ scheme-prefixed keys.
        if (const auto* scheme = pq::SchemeFromPrefix(chHeader)) {
            return scheme->pubkey_bytes + 1;
        }
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate()
    {
        vch.clear();
    }

public:

    bool static ValidSize(const std::vector<unsigned char> &vch) {
      return vch.size() > 0 && vch.size() <= MAX_SIZE && GetLen(vch[0]) == vch.size();
    }

    //! Construct an invalid public key.
    CPubKey()
    {
        Invalidate();
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        if (pbegin == pend) {
            Invalidate();
            return;
        }
        const unsigned int len = GetLen(pbegin[0]);
        if (len && len == static_cast<unsigned int>(pend - pbegin) && len <= MAX_SIZE) {
            vch.assign(pbegin, pend);
        } else {
            Invalidate();
        }
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    explicit CPubKey(std::span<const uint8_t> _vch)
    {
        Set(_vch.begin(), _vch.end());
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return static_cast<unsigned int>(vch.size()); }
    const unsigned char* data() const { return vch.data(); }
    const unsigned char* begin() const { return vch.data(); }
    const unsigned char* end() const { return vch.data() + vch.size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey& a, const CPubKey& b)
    {
        return a.vch == b.vch;
    }
    friend bool operator!=(const CPubKey& a, const CPubKey& b)
    {
        return !(a == b);
    }
    friend bool operator<(const CPubKey& a, const CPubKey& b)
    {
        return a.vch < b.vch;
    }
    friend bool operator>(const CPubKey& a, const CPubKey& b)
    {
        return a.vch > b.vch;
    }

    //! Implement serialization, as if this was a byte vector.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        if (len > 0) {
            s << std::span{vch.data(), len};
        }
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const unsigned int len(::ReadCompactSize(s));
        if (len == 0 || len > MAX_SIZE) {
            // invalid pubkey, skip available data
            s.ignore(len);
            Invalidate();
            return;
        }
        vch.assign(len, 0);
        s >> std::span{vch.data(), len};
        if (GetLen(vch[0]) != len) {
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const
    {
        return CKeyID(Hash160(std::span{vch}.first(size())));
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const
    {
        return Hash(std::span{vch}.first(size()));
    }

    /*
     * Check syntactic correctness.
     *
     * When setting a pubkey (Set()) or deserializing fails (its header bytes
     * don't match the length of the data), the size is set to 0. Thus,
     * by checking size, one can observe whether Set() or deserialization has
     * failed.
     *
     * This does not validate the scheme's internal public-key encoding; use
     * IsFullyValid() for that instead.
     *
     * Note that this is consensus critical as CheckPostQuantumSignature() calls it!
     */
    bool IsValid() const
    {
        return size() > 0;
    }

    /** Check if a public key is syntactically valid for a known PQ scheme. */
    bool IsValidNonHybrid() const noexcept
    {
        return IsValid() && pq::SchemeFromPrefix(vch[0]) != nullptr;
    }

    //! Validate the full public-key encoding, not possession of a matching private key.
    bool IsFullyValid() const;


    /**
     * Verify a signature
     * If this public key is not fully valid, the return value will be false.
     */
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig, bool legacy_mode = false) const;

    /**
     * Verify a signature for 64-byte sighashes (v1_512).
     */
    bool Verify512(const uint512& hash, const std::vector<unsigned char>& vchSig, bool legacy_mode = false) const;


    //! Recover a message-signing public key, including legacy Falcon-512 signatures.
    bool Recover(const uint256& hash, const std::vector<unsigned char>& vchSig);

};

#endif // BITCOIN_PUBKEY_H
