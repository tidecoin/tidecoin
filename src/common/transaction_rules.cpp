// Copyright (c) 2026 The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/transaction_rules.h>

#include <consensus/params.h>
#include <policy/policy.h>
#include <script/interpreter.h>

#include <cstdint>

namespace common {

std::optional<ScriptRuleEra> ParseScriptRuleEra(std::string_view name)
{
    if (name == "pre-auxpow") return ScriptRuleEra::PRE_AUXPOW;
    if (name == "post-auxpow") return ScriptRuleEra::POST_AUXPOW;
    return std::nullopt;
}

std::string_view ScriptRuleEraName(ScriptRuleEra era)
{
    return era == ScriptRuleEra::PRE_AUXPOW ? "pre-auxpow" : "post-auxpow";
}

unsigned int ScriptFlagsForEra(ScriptRuleEra era)
{
    constexpr unsigned int era_flags{SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512 | SCRIPT_VERIFY_SHA512};
    return (STANDARD_SCRIPT_VERIFY_FLAGS & ~era_flags) | (era == ScriptRuleEra::POST_AUXPOW ? era_flags : 0);
}

ScriptRuleEra LocalScriptRuleEra(std::optional<int> tip_height, int activation_height)
{
    const int64_t next_height{tip_height ? int64_t{*tip_height} + 1 : 0};
    return activation_height != Consensus::AUXPOW_DISABLED && next_height >= activation_height
        ? ScriptRuleEra::POST_AUXPOW : ScriptRuleEra::PRE_AUXPOW;
}

TransactionRules::TransactionRules(ScriptRuleEra local_era, std::optional<ScriptRuleEra> requested)
    : local{local_era}, effective{requested.value_or(local_era)}, explicit_selection{requested.has_value()}, flags{ScriptFlagsForEra(effective)}
{
}

} // namespace common
