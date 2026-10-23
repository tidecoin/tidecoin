// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletutil.h>

#include <chainparams.h>
#include <common/args.h>
#include <key_io.h>
#include <logging.h>
#include <pq/pqhd_params.h>
#include <pq/pq_scheme.h>

namespace wallet {
fs::path GetWalletDir()
{
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetPathArg("-walletdir");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = gArgs.GetDataDirNet();
        // If a wallets directory exists, use that, otherwise default to GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

uint32_t PQHDPurposeForOutputType(OutputType output_type)
{
    switch (output_type) {
    case OutputType::LEGACY: return pqhd::PURPOSE_PKH;
    case OutputType::P2SH_SEGWIT: return pqhd::PURPOSE_SH_WPKH;
    case OutputType::BECH32: return pqhd::PURPOSE_WPKH;
    case OutputType::BECH32PQ: return pqhd::PURPOSE_WSH512;
    case OutputType::UNKNOWN: break;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

WalletDescriptor GeneratePQHDWalletDescriptor(const uint256& seed_id,
                                              uint8_t scheme_prefix,
                                              const OutputType& addr_type,
                                              bool internal,
                                              const Consensus::Params& consensus,
                                              int target_height)
{
    int64_t creation_time = GetTime();

    const auto* scheme = pq::SchemeFromPrefix(scheme_prefix);
    if (scheme == nullptr) {
        throw std::runtime_error(strprintf("Unknown PQ scheme prefix: %u", scheme_prefix));
    }
    if (!pq::IsSchemeAllowedAtHeight(scheme->id, consensus, target_height)) {
        throw std::runtime_error(strprintf("PQ scheme %s not allowed at height %i", scheme->name, target_height));
    }
    if (addr_type == OutputType::BECH32PQ && target_height < consensus.nAuxpowStartHeight) {
        throw std::runtime_error(strprintf("PQ v1 outputs not allowed at height %i", target_height));
    }

    // pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/*h
    const uint32_t scheme_u32{scheme_prefix};
    std::string key_expr = strprintf("pqhd(%s)/%uh/%uh/%uh/0h/%uh/*h",
                                     seed_id.ToString(),
                                     PQHDPurposeForOutputType(addr_type),
                                     Params().PQHDCoinType(),
                                     scheme_u32,
                                     internal ? 1U : 0U);

    std::string desc_str;
    switch (addr_type) {
    case OutputType::LEGACY: {
        desc_str = "pkh(" + key_expr + ")";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_str = "sh(wpkh(" + key_expr + "))";
        break;
    }
    case OutputType::BECH32: {
        desc_str = "wpkh(" + key_expr + ")";
        break;
    }
    case OutputType::BECH32PQ: {
        desc_str = "wsh512(pk(" + key_expr + "))";
        break;
    }
    case OutputType::UNKNOWN: {
        assert(false);
    }
    }

    // Make the descriptor.
    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> desc = Parse(desc_str, keys, error, /*require_checksum=*/false);
    if (desc.empty()) {
        throw std::runtime_error(strprintf("Invalid PQHD wallet descriptor: %s", error));
    }
    WalletDescriptor w_desc(std::move(desc.at(0)), creation_time, 0, 0, 0);
    return w_desc;
}

} // namespace wallet
