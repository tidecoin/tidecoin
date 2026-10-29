// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>

#include <base58.h>
#include <bech32.h>
#include <pq/pq_scheme.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <support/allocators/secure.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <utility>

namespace {
class DestinationEncoder
{
private:
    const CChainParams& m_params;

public:
    explicit DestinationEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const PKHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const ScriptHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS2);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const WitnessV0KeyHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(33);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV0ScriptHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV1ScriptHash512& id) const
    {
        std::vector<unsigned char> data = {1};
        data.reserve(103);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32PQHRP(), data);
    }

    std::string operator()(const CNoDestination& no) const { return {}; }
    std::string operator()(const PubKeyDestination& pk) const { return {}; }
};

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str, std::vector<int>* error_locations)
{
    std::vector<unsigned char> data;
    uint160 hash;
    error_str = "";

    const std::string& legacy_hrp = params.Bech32HRP();
    const std::string& pq_hrp = params.Bech32PQHRP();

    // Only treat a string as bech32 if it contains the separator and the HRP matches.
    const auto sep_pos = str.rfind('1');
    const bool has_sep = sep_pos != std::string::npos && sep_pos > 0;
    const std::string hrp = has_sep ? ToLower(str.substr(0, sep_pos)) : std::string{};
    const bool hrp_prefix_match_legacy = str.size() >= legacy_hrp.size() &&
        ToLower(str.substr(0, legacy_hrp.size())) == legacy_hrp;
    const bool hrp_prefix_match_pq = str.size() >= pq_hrp.size() &&
        ToLower(str.substr(0, pq_hrp.size())) == pq_hrp;
    const bool hrp_prefix_match = hrp_prefix_match_legacy || hrp_prefix_match_pq;

    if (DecodeBase58Check(str, data, 21)) {
        // base58-encoded Bitcoin addresses.
        // Public-key-hash-addresses have version 0 (or 111 testnet).
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return PKHash(hash);
        }
        // Script-hash-addresses.
        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return ScriptHash(hash);
        }
        const std::vector<unsigned char>& script_prefix2 = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS2);
        if (data.size() == hash.size() + script_prefix2.size() && std::equal(script_prefix2.begin(), script_prefix2.end(), data.begin())) {
            std::copy(data.begin() + script_prefix2.size(), data.end(), hash.begin());
            return ScriptHash(hash);
        }

        // If the prefix of data matches either the script or pubkey prefix, the length must have been wrong
        if ((data.size() >= script_prefix.size() &&
                std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) ||
            (data.size() >= script_prefix2.size() &&
                std::equal(script_prefix2.begin(), script_prefix2.end(), data.begin())) ||
            (data.size() >= pubkey_prefix.size() &&
                std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin()))) {
            error_str = "Invalid length for Base58 address (P2PKH or P2SH)";
        } else {
            error_str = "Invalid or unsupported Base58-encoded address.";
        }
        return CNoDestination();
    } else if (!hrp_prefix_match) {
        // Try Base58 decoding without the checksum, using a much larger max length
        if (!DecodeBase58(str, data, 100)) {
            error_str = "Invalid or unsupported Segwit (Bech32) or Base58 encoding.";
        } else {
            error_str = "Invalid checksum or length of Base58 address (P2PKH or P2SH)";
        }
        return CNoDestination();
    }

    data.clear();
    const auto bech32_limit = hrp_prefix_match_pq ? bech32::CharLimit::BECH32_PQ : bech32::CharLimit::BECH32;
    const auto dec = bech32::Decode(str, bech32_limit);
    if (dec.encoding == bech32::Encoding::BECH32 || dec.encoding == bech32::Encoding::BECH32M) {
        if (dec.data.empty()) {
            error_str = "Empty Bech32 data section";
            return CNoDestination();
        }
        // Bech32 decoding
        if (dec.hrp != legacy_hrp && dec.hrp != pq_hrp) {
            error_str = strprintf("Invalid or unsupported prefix for Segwit (Bech32) address (expected %s or %s, got %s).", legacy_hrp, pq_hrp, dec.hrp);
            return CNoDestination();
        }
        const bool is_pq = (dec.hrp == pq_hrp);
        int version = dec.data[0]; // The first 5 bit symbol is the witness version (0-16)
        if (version > 16) {
            error_str = "Invalid Bech32 address witness version";
            return CNoDestination();
        }
        if (!is_pq && dec.encoding == bech32::Encoding::BECH32M && version == 0) {
            error_str = "Version 0 witness address must use Bech32 checksum";
            return CNoDestination();
        }
        if (is_pq) {
            if (dec.encoding != bech32::Encoding::BECH32M) {
                error_str = "PQ witness v1 address must use Bech32m checksum";
                return CNoDestination();
            }
            if (version != 1) {
                error_str = "Unsupported PQ witness version";
                return CNoDestination();
            }
        } else {
            if (version != 0) {
                error_str = "Unsupported Segwit witness version";
                return CNoDestination();
            }
        }
        // The rest of the symbols are converted witness program bytes.
        data.reserve(((dec.data.size() - 1) * 5) / 8);
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, dec.data.begin() + 1, dec.data.end())) {

            std::string_view byte_str{data.size() == 1 ? "byte" : "bytes"};

            if (version == 0 && !is_pq) {
                {
                    WitnessV0KeyHash keyid;
                    if (data.size() == keyid.size()) {
                        std::copy(data.begin(), data.end(), keyid.begin());
                        return keyid;
                    }
                }
                {
                    WitnessV0ScriptHash scriptid;
                    if (data.size() == scriptid.size()) {
                        std::copy(data.begin(), data.end(), scriptid.begin());
                        return scriptid;
                    }
                }

                error_str = strprintf("Invalid Bech32 v0 address program size (%d %s), per BIP141", data.size(), byte_str);
                return CNoDestination();
            }
            if (version == 1 && is_pq) {
                WitnessV1ScriptHash512 scriptid;
                if (data.size() == scriptid.size()) {
                    std::copy(data.begin(), data.end(), scriptid.begin());
                    return scriptid;
                }
                error_str = strprintf("Invalid Bech32 v1 address program size (%d %s), expected 64 bytes", data.size(), byte_str);
                return CNoDestination();
            }

        } else {
            error_str = strprintf("Invalid padding in Bech32 data section");
            return CNoDestination();
        }
    }

    // Perform Bech32 error location
    auto res = bech32::LocateErrors(str, bech32_limit);
    error_str = res.first;
    if (error_locations) *error_locations = std::move(res.second);
    return CNoDestination();
}
} // namespace

CKey DecodeSecret(const std::string& str)
{
    CKey key;
    std::vector<unsigned char> data;
    constexpr int kMaxSecretKeyPayload = static_cast<int>(
        pq::kMLDSA87Info.seckey_bytes + pq::kMLDSA87Info.pubkey_bytes + 16);
    if (DecodeBase58Check(str, data, kMaxSecretKeyPayload)) {
        const std::vector<unsigned char>& privkey_prefix = Params().Base58Prefix(CChainParams::SECRET_KEY);
        if (data.size() > privkey_prefix.size() &&
            std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
            const size_t payload_off = privkey_prefix.size();
            const size_t payload_len_full = data.size() - payload_off;
            // v0.18.3 WIF: raw secret || 0x01 || raw public key (Falcon-512 only).
            // The embedded public key has no Tidecoin scheme prefix.
            const pq::SchemeInfo& legacy_scheme = pq::kFalcon512Info;
            const size_t legacy_pub_len = legacy_scheme.pubkey_bytes;
            const size_t legacy_total_len = legacy_scheme.seckey_bytes + 1 + legacy_pub_len;
            if (payload_len_full == legacy_total_len &&
                data[payload_off + legacy_scheme.seckey_bytes] == 1) {
                const unsigned char* pub_begin = data.data() + payload_off + legacy_scheme.seckey_bytes + 1;
                const unsigned char* pub_end = pub_begin + legacy_pub_len;
                std::vector<unsigned char> prefixed_pubkey{legacy_scheme.prefix};
                prefixed_pubkey.insert(prefixed_pubkey.end(), pub_begin, pub_end);
                const CPubKey pubkey{prefixed_pubkey};
                if (pubkey.IsFullyValid()) {
                    // Derive instead of trusting the supplied identity. Otherwise
                    // an inconsistent pair could be saved and fail on wallet unlock.
                    CKey derived;
                    derived.Set(data.begin() + payload_off,
                                data.begin() + payload_off + legacy_scheme.seckey_bytes);
                    if (derived.IsValid() && derived.GetPubKey() == pubkey) {
                        key = std::move(derived);
                    }
                }
            } else {
                size_t payload_len = payload_len_full;
                const bool has_scheme_prefix = payload_len_full > 0 && pq::SchemeFromPrefix(data[payload_off]) != nullptr;
                if (!has_scheme_prefix && payload_len > 0 && data.back() == 1) {
                    --payload_len;
                }
                if (payload_len > 0) {
                    key.Set(data.begin() + payload_off,
                            data.begin() + payload_off + payload_len);
                }
            }
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeSecret(const CKey& key)
{
    assert(key.IsValid());
    const std::vector<unsigned char> prefix = Params().Base58Prefix(CChainParams::SECRET_KEY);
    std::vector<unsigned char, secure_allocator<unsigned char>> data(prefix.begin(), prefix.end());
    const CPrivKey privkey = key.GetPrivKey();
    data.insert(data.end(), privkey.begin(), privkey.end());
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

std::string EncodeSecretLegacy(const CKey& key)
{
    assert(key.IsValid());
    const CPubKey pubkey = key.GetPubKey();
    if (pubkey.size() == 0) {
        return {};
    }
    const pq::SchemeInfo* scheme = pq::SchemeFromPrefix(pubkey[0]);
    if (scheme == nullptr || scheme->id != pq::SchemeId::FALCON_512) {
        return {};
    }
    const CPrivKey privkey = key.GetPrivKey();
    std::span<const unsigned char> raw = privkey;
    if (raw.size() == scheme->seckey_bytes + 1 && raw[0] == scheme->prefix) {
        raw = raw.subspan(1);
    } else if (raw.size() != scheme->seckey_bytes) {
        return {};
    }
    const std::vector<unsigned char> prefix = Params().Base58Prefix(CChainParams::SECRET_KEY);
    std::vector<unsigned char, secure_allocator<unsigned char>> data(prefix.begin(), prefix.end());
    data.insert(data.end(), raw.begin(), raw.end());
    data.push_back(1);
    data.insert(data.end(), pubkey.begin() + 1, pubkey.end());
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

std::string EncodeDestination(const CTxDestination& dest)
{
    return std::visit(DestinationEncoder(Params()), dest);
}

CTxDestination DecodeDestination(const std::string& str, std::string& error_msg, std::vector<int>* error_locations)
{
    return DecodeDestination(str, Params(), error_msg, error_locations);
}

CTxDestination DecodeDestination(const std::string& str)
{
    std::string error_msg;
    return DecodeDestination(str, error_msg);
}

bool IsValidDestinationString(const std::string& str, const CChainParams& params)
{
    std::string error_msg;
    return IsValidDestination(DecodeDestination(str, params, error_msg, nullptr));
}

bool IsValidDestinationString(const std::string& str)
{
    return IsValidDestinationString(str, Params());
}
