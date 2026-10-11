// Copyright (c) 2026-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Portable subprocess fixture. Never linked into a production executable.
#include <univalue.h>
#include <util/fs.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#ifdef WIN32
#include <codecvt>
#include <locale>
#endif

static int Run(const std::vector<std::string>& args)
{
    const auto argc{args.size()};
    if (argc < 2) return 1;
    const std::string mode{args[1]};
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
        UniValue echoed{UniValue::VARR};
        for (size_t i = 2; i < argc; ++i) echoed.push_back(args[i]);
        UniValue result{UniValue::VOBJ};
        result.pushKV("args", echoed);
        std::cout << result.write() << '\n';
        return 0;
    }
    if (mode == "signer" && argc >= 4) {
        std::ifstream file{fs::PathFromString(args[2])};
        const std::string text{std::istreambuf_iterator<char>{file}, {}};
        UniValue responses;
        if (!file || !responses.read(text)) return 2;
        for (size_t i = 3; i < argc; ++i) {
            if (std::string{args[i]} == "--stdin") {
                const std::string request{std::istreambuf_iterator<char>{std::cin}, {}};
                if (!request.starts_with("signtx ")) return 4;
                std::cout << responses.find_value("signtx").write() << '\n';
                return 0;
            }
            const std::string arg{args[i]};
            if (arg == "enumerate" || arg == "getdescriptors") {
                std::cout << responses.find_value(arg).write() << '\n';
                return 0;
            }
        }
    }
    return 3;
}

#ifdef WIN32
// Read the CRT's wide arguments, independently of the system code page. The
// production launcher sends UTF-16; JSON and response-file paths use UTF-8.
int wmain(int argc, wchar_t* argv[])
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) args.push_back(converter.to_bytes(argv[i]));
    return Run(args);
}
#else
int main(int argc, char* argv[])
{
    return Run({argv, argv + argc});
}
#endif
