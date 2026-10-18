// Copyright (c) 2026
// Distributed under the MIT software license.

#include <key.h>
#include <key_io.h>
#include <pubkey.h>
#include <chainparams.h>
#include <pq/pq_api.h>
#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>
#include <pq/pq_scheme.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <uint512.h>

#include <univalue.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Provide a translation stub for this standalone test tool.
const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

struct Options {
    pq::SchemeId scheme_id{pq::SchemeId::FALCON_512};
    std::array<uint8_t, 32> master_seed{};
    bool have_seed{false};
    std::vector<uint32_t> path_hardened;
    int count{1};
    int index_start{0};
    bool index_set{false};
    std::string sign_key;
    std::string sign_hash;
};

bool ParseSchemeId(const std::string& in, pq::SchemeId& out)
{
    if (in.empty()) return false;
    const std::string lower = ToLower(in);
    if (lower == "falcon-512" || lower == "falcon512" || lower == "7") {
        out = pq::SchemeId::FALCON_512;
        return true;
    }
    if (lower == "falcon-1024" || lower == "falcon1024" || lower == "8") {
        out = pq::SchemeId::FALCON_1024;
        return true;
    }
    if (lower == "ml-dsa-44" || lower == "mldsa-44" || lower == "9") {
        out = pq::SchemeId::MLDSA_44;
        return true;
    }
    if (lower == "ml-dsa-65" || lower == "mldsa-65" || lower == "10") {
        out = pq::SchemeId::MLDSA_65;
        return true;
    }
    if (lower == "ml-dsa-87" || lower == "mldsa-87" || lower == "11") {
        out = pq::SchemeId::MLDSA_87;
        return true;
    }
    return false;
}

std::optional<std::array<uint8_t, 32>> ParseSeed32(const std::string& hex)
{
    const std::vector<unsigned char> bytes = ParseHex(hex);
    if (bytes.size() != 32) return std::nullopt;
    std::array<uint8_t, 32> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

bool ParsePathElement(const std::string& elem, uint32_t& out)
{
    if (elem.empty()) return false;
    bool hardened = false;
    std::string number = elem;
    if (elem.back() == 'h' || elem.back() == '\'') {
        hardened = true;
        number = elem.substr(0, elem.size() - 1);
    }
    if (number.empty()) return false;
    const auto parsed = ToIntegral<uint64_t>(number);
    if (!parsed) return false;
    const uint64_t val = *parsed;
    if (val > 0x7FFFFFFFULL) return false;
    out = static_cast<uint32_t>(val);
    if (hardened) out |= 0x80000000U;
    return true;
}

std::optional<std::vector<uint32_t>> ParsePath(const std::string& path)
{
    std::string_view p = path;
    if (p.starts_with("m/")) p.remove_prefix(2);
    std::vector<uint32_t> out;
    while (!p.empty()) {
        const size_t slash = p.find('/');
        const std::string elem = std::string(p.substr(0, slash));
        uint32_t val{0};
        if (!ParsePathElement(elem, val)) return std::nullopt;
        out.push_back(val);
        if (slash == std::string_view::npos) break;
        p.remove_prefix(slash + 1);
    }
    return out;
}

void PrintUsage(const char* argv0)
{
    std::cerr << "Usage: " << argv0 << " --scheme=<id|name> --seed=<hex32> [--path=<m/...>] [--count=N]\n";
    std::cerr << "Example: " << argv0 << " --scheme=7 --seed=000102... --count=1\n";
}

bool ParseArgs(int argc, char* argv[], Options& opt)
{
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg.starts_with("--sign-key=")) { opt.sign_key = arg.substr(11); continue; }
        if (arg.starts_with("--sign-hash=")) { opt.sign_hash = arg.substr(12); continue; }
        if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return false;
        }
        if (arg.starts_with("--scheme=")) {
            const std::string val = arg.substr(strlen("--scheme="));
            if (!ParseSchemeId(val, opt.scheme_id)) return false;
            continue;
        }
        if (arg.starts_with("--seed=")) {
            const std::string val = arg.substr(strlen("--seed="));
            auto seed = ParseSeed32(val);
            if (!seed) return false;
            opt.master_seed = *seed;
            opt.have_seed = true;
            continue;
        }
        if (arg.starts_with("--path=")) {
            const std::string val = arg.substr(strlen("--path="));
            auto parsed = ParsePath(val);
            if (!parsed) return false;
            opt.path_hardened = *parsed;
            continue;
        }
        if (arg.starts_with("--count=")) {
            const std::string val = arg.substr(strlen("--count="));
            const auto parsed = ToIntegral<int64_t>(val);
            if (!parsed || *parsed <= 0 || *parsed > 1000) return false;
            opt.count = static_cast<int>(*parsed);
            continue;
        }
        if (arg.starts_with("--index=")) {
            const std::string val = arg.substr(strlen("--index="));
            const auto parsed = ToIntegral<int64_t>(val);
            if (!parsed || *parsed < 0 || *parsed > 0x7FFFFFFFLL) return false;
            opt.index_start = static_cast<int>(*parsed);
            opt.index_set = true;
            continue;
        }
        return false;
    }

    if (!opt.sign_key.empty()) return IsHex(opt.sign_hash) && (opt.sign_hash.size() == 64 || opt.sign_hash.size() == 128);
    if (!opt.have_seed) return false;

    if (opt.path_hardened.empty()) {
        opt.path_hardened = {
            0x80000000U | pqhd::PURPOSE,
            0x80000000U | pqhd::COIN_TYPE,
            0x80000000U | static_cast<uint32_t>(opt.scheme_id),
            0x80000000U | 0U,
            0x80000000U | 0U,
            0x80000000U | 0U,
        };
    }
    return true;
}

} // namespace

int main(int argc, char* argv[])
{
    SelectParams(ChainType::REGTEST);
    Options opt;
    if (!ParseArgs(argc, argv, opt)) {
        PrintUsage(argv[0]);
        return 1;
    }

    // Test-only signing of explicitly supplied digests permits constructing
    // consensus fixtures for modes the production signing API will not create.
    if (!opt.sign_key.empty()) {
        const CKey key = DecodeSecret(opt.sign_key);
        if (!key.IsValid()) return 1;
        const auto bytes = ParseHex(opt.sign_hash);
        std::vector<unsigned char> signature;
        bool signed_ok;
        if (bytes.size() == 64) {
            uint512 hash;
            std::copy(bytes.begin(), bytes.end(), hash.begin());
            signed_ok = key.Sign512(hash, signature, false);
        } else {
            uint256 hash;
            std::copy(bytes.begin(), bytes.end(), hash.begin());
            signed_ok = key.Sign(hash, signature, false, 0, false);
        }
        if (!signed_ok) return 1;
        std::cout << HexStr(signature) << '\n';
        return 0;
    }

    const pq::SchemeInfo* info = pq::SchemeFromId(opt.scheme_id);
    if (!info) {
        std::cerr << "Unknown scheme id\n";
        return 1;
    }

    const pqhd::Node master = pqhd::MakeMasterNode(opt.master_seed);

    UniValue out(UniValue::VARR);

    for (int i = 0; i < opt.count; ++i) {
        std::vector<uint32_t> path = opt.path_hardened;
        if (!path.empty()) {
            const uint32_t index = static_cast<uint32_t>(opt.index_start + i);
            path.back() = (path.back() & 0x80000000U) | (index | 0x80000000U);
        }
        if (!pqhd::ValidateV1LeafPath(path)) {
            std::cerr << "Invalid PQHD v1 path\n";
            return 1;
        }

        auto node_opt = pqhd::DerivePath(master, path);
        if (!node_opt) {
            std::cerr << "DerivePath failed\n";
            return 1;
        }
        auto stream_key_opt = pqhd::DeriveKeygenStreamKey(node_opt->node_secret, path);
        if (!stream_key_opt) {
            std::cerr << "DeriveKeygenStreamKey failed\n";
            return 1;
        }

        std::vector<uint8_t> pk_raw(info->pubkey_bytes);
        pq::SecureKeyBytes sk_raw(info->seckey_bytes);
        if (!pq::KeyGenFromSeed(1, opt.scheme_id, stream_key_opt->Span(), pk_raw, sk_raw)) {
            std::cerr << "KeyGenFromSeed failed\n";
            return 1;
        }

        std::vector<uint8_t> pk_prefixed;
        pk_prefixed.reserve(pk_raw.size() + 1);
        pk_prefixed.push_back(info->prefix);
        pk_prefixed.insert(pk_prefixed.end(), pk_raw.begin(), pk_raw.end());

        CPubKey pubkey(pk_prefixed.begin(), pk_prefixed.end());

        CKey key;
        key.Set(sk_raw.begin(), sk_raw.end(), pubkey);
        if (!key.IsValid()) {
            std::cerr << "CKey invalid\n";
            return 1;
        }

        UniValue item(UniValue::VOBJ);
        item.pushKV("scheme_id", int(info->prefix));
        item.pushKV("scheme_name", info->name);
        item.pushKV("pubkey_hex", HexStr(pk_prefixed));
        item.pushKV("privkey_wif", EncodeSecret(key));
        out.push_back(item);
    }

    std::cout << out.write(1, false) << "\n";
    return 0;
}
