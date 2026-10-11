// Copyright (c) 2026-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_RUN_COMMAND_H
#define BITCOIN_TEST_UTIL_RUN_COMMAND_H

#include <util/exec.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace test {
// Encode one argument using ParseCommandArguments' double-quote rules.
inline std::string QuoteCommandArgument(const std::string& arg)
{
    std::string result{"\""};
    for (char c : arg) {
        if (c == '\\' || c == '"') result += '\\';
        result += c;
    }
    return result + '"';
}

inline fs::path CopyMockProcess(const fs::path& directory)
{
    const auto executable{util::GetExePath(boost::unit_test::framework::master_test_suite().argv[0])};
    const auto source{fs::path{executable.parent_path()} / fs::PathFromString(TEST_RUN_COMMAND_HELPER)};
    fs::create_directories(directory);
    const auto destination{directory / fs::PathFromString("mock signer" + fs::PathToString(source.extension()))};
    fs::copy_file(source, destination, fs::copy_options::none);
    return destination;
}
} // namespace test

#endif // BITCOIN_TEST_UTIL_RUN_COMMAND_H
