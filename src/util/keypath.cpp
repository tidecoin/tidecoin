// Copyright (c) 2024-present The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/keypath.h>
#include <util/string.h>

namespace {
std::string FormatPathElem(uint32_t elem, bool hardened_suffix)
{
    const bool hardened = (elem & 0x80000000U) != 0;
    const uint32_t index = elem & 0x7fffffffU;
    std::string out = util::ToString(index);
    if (hardened) out += (hardened_suffix ? "h" : "'");
    return out;
}
} // namespace

std::string FormatKeypath(const std::vector<uint32_t>& path, bool hardened_suffix)
{
    std::string out;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i != 0) out += '/';
        out += FormatPathElem(path[i], hardened_suffix);
    }
    return out;
}

std::string WriteKeypath(const std::vector<uint32_t>& path, bool hardened_suffix)
{
    if (path.empty()) return "m";
    return "m/" + FormatKeypath(path, hardened_suffix);
}
