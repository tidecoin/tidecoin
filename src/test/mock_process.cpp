// Copyright (c) 2026-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Portable subprocess fixture. Never linked into a production executable.
#include <univalue.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>

int main(int argc, char* argv[])
{
    if (argc < 2) return 1;
    const std::string mode{argv[1]};
    if (mode == "fail") {
        std::cerr << "mock failure\n";
        return 7;
    }
    if (mode == "invalid-json") {
        std::cout << "{\n";
        return 0;
    }
    if (mode == "stdin") {
        std::cout << std::cin.rdbuf();
        return 0;
    }
    if (mode == "echo") {
        UniValue args{UniValue::VARR};
        for (int i = 2; i < argc; ++i) args.push_back(argv[i]);
        UniValue result{UniValue::VOBJ};
        result.pushKV("args", args);
        std::cout << result.write() << '\n';
        return 0;
    }
    if (mode == "signer" && argc >= 4) {
        const std::string_view filename{argv[2]};
        std::ifstream file{std::filesystem::path{std::u8string{filename.begin(), filename.end()}}};
        const std::string text{std::istreambuf_iterator<char>{file}, {}};
        UniValue responses;
        if (!file || !responses.read(text)) return 2;
        for (int i = 3; i < argc; ++i) {
            if (std::string{argv[i]} == "--stdin") {
                const std::string request{std::istreambuf_iterator<char>{std::cin}, {}};
                if (!request.starts_with("signtx ")) return 4;
                std::cout << responses.find_value("signtx").write() << '\n';
                return 0;
            }
            const std::string arg{argv[i]};
            if (arg == "enumerate" || arg == "getdescriptors") {
                std::cout << responses.find_value(arg).write() << '\n';
                return 0;
            }
        }
    }
    return 3;
}
