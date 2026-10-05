// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tidecoin-build-config.h> // IWYU pragma: keep

#include <common/run_command.h>

#include <tinyformat.h>
#include <univalue.h>
#include <util/string.h>

#include <sstream>
#include <stdexcept>
#include <utility>

#ifdef ENABLE_EXTERNAL_SIGNER
#include <util/subprocess.h>
#endif // ENABLE_EXTERNAL_SIGNER

std::vector<std::string> ParseCommandArguments(const std::string& command)
{
    std::vector<std::string> args;
    std::string arg;
    char quote{0};
    bool started{false};
    for (size_t i = 0; i < command.size(); ++i) {
        const char c{command[i]};
        if (c == '\0') throw std::invalid_argument("Command contains a NUL character");
        if (quote) {
            if (c == quote) {
                quote = 0;
            } else if (quote == '"' && c == '\\' && i + 1 < command.size() &&
                       (command[i + 1] == '"' || command[i + 1] == '\\')) {
                arg += command[++i];
            } else {
                arg += c;
            }
        } else if (c == '\'' || c == '"') {
            quote = c;
            started = true;
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            if (started) {
                args.push_back(std::move(arg));
                arg.clear();
                started = false;
            }
        } else {
            arg += c;
            started = true;
        }
    }
    if (quote) throw std::invalid_argument("Unterminated quote in command");
    if (started) args.push_back(std::move(arg));
    if (!args.empty() && args.front().empty()) throw std::invalid_argument("Command executable is empty");
    return args;
}

UniValue RunCommandParseJSON(const std::vector<std::string>& cmd_args, const std::string& str_std_in)
{
#ifdef ENABLE_EXTERNAL_SIGNER
    namespace sp = subprocess;

    UniValue result_json;
    std::istringstream stdout_stream;
    std::istringstream stderr_stream;

    if (cmd_args.empty()) return UniValue::VNULL;
    if (cmd_args.front().empty()) throw std::invalid_argument("Command executable is empty");
    for (const auto& arg : cmd_args) {
        if (arg.find('\0') != std::string::npos) throw std::invalid_argument("Command contains a NUL character");
    }

    auto c = sp::Popen(cmd_args, sp::input{sp::PIPE}, sp::output{sp::PIPE}, sp::error{sp::PIPE});
    if (!str_std_in.empty()) {
        c.send(str_std_in);
    }
    auto [out_res, err_res] = c.communicate();
    stdout_stream.str(std::string{out_res.buf.begin(), out_res.buf.end()});
    stderr_stream.str(std::string{err_res.buf.begin(), err_res.buf.end()});

    std::string result;
    std::string error;
    std::getline(stdout_stream, result);
    std::getline(stderr_stream, error);

    const int n_error = c.retcode();
    if (n_error) throw std::runtime_error(strprintf("RunCommandParseJSON error: process(%s) returned %d: %s\n", util::Join(cmd_args, " "), n_error, error));
    if (!result_json.read(result)) throw std::runtime_error("Unable to parse JSON: " + result);

    return result_json;
#else
    throw std::runtime_error("Compiled without external signing support (required for external signing).");
#endif // ENABLE_EXTERNAL_SIGNER
}
