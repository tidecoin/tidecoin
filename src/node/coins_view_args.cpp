// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coins_view_args.h>

#include <common/args.h>
#include <txdb.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <stdexcept>

namespace node {
void ReadCoinsViewArgs(const ArgsManager& args, CoinsViewOptions& options)
{
    if (auto value = args.GetIntArg("-dbbatchsize")) options.batch_write_bytes = *value;
    if (auto value = args.GetIntArg("-dbcrashratio")) options.simulate_crash_ratio = *value;
    if (args.IsArgSet("-dbcrashat")) {
        if (args.GetChainType() != ChainType::REGTEST) throw std::runtime_error("-dbcrashat is only supported on regtest");
        if (args.GetArg("-dbcrashat", "") == "final") {
            options.simulate_crash_before_final = true;
        } else {
            const auto value = ToIntegral<int64_t>(args.GetArg("-dbcrashat", ""));
            if (!value || *value < 0) throw std::runtime_error("-dbcrashat must be a non-negative batch number or final");
            options.simulate_crash_after_batch = *value;
        }
    }
}
} // namespace node
