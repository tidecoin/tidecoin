// Copyright (c) 2026 The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_TRANSACTION_RULES_H
#define BITCOIN_COMMON_TRANSACTION_RULES_H

#include <optional>
#include <string_view>

namespace common {

/** Script rules for local transaction processing, not a network activation override. */
enum class ScriptRuleEra { PRE_AUXPOW, POST_AUXPOW };

std::optional<ScriptRuleEra> ParseScriptRuleEra(std::string_view name);
std::string_view ScriptRuleEraName(ScriptRuleEra era);
unsigned int ScriptFlagsForEra(ScriptRuleEra era);
ScriptRuleEra LocalScriptRuleEra(std::optional<int> tip_height, int activation_height);

/** Retain this selection through processing and extraction, even if the tip changes. */
struct TransactionRules {
    const ScriptRuleEra local;
    const ScriptRuleEra effective;
    const bool explicit_selection;
    const unsigned int flags;

    TransactionRules(ScriptRuleEra local_era, std::optional<ScriptRuleEra> requested = std::nullopt);
};

} // namespace common

#endif // BITCOIN_COMMON_TRANSACTION_RULES_H
