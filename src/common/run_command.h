// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_RUN_COMMAND_H
#define BITCOIN_COMMON_RUN_COMMAND_H

#include <string>
#include <vector>

class UniValue;

/** Split a configured command without shell expansion. Single and double quotes
 * group arguments; inside double quotes, backslash escapes backslash and double
 * quote only. Elsewhere backslashes are literal. Throws on unmatched quotes,
 * embedded NULs, or an empty executable. Whitespace-only input returns {}.
 */
std::vector<std::string> ParseCommandArguments(const std::string& command);

/**
 * Execute a command which returns JSON, and parse the result.
 *
 * @param cmd_args Executable and arguments, passed directly without shell parsing
 * @param str_std_in string to pass to stdin
 * @return parsed JSON
 */
UniValue RunCommandParseJSON(const std::vector<std::string>& cmd_args, const std::string& str_std_in="");

#endif // BITCOIN_COMMON_RUN_COMMAND_H
