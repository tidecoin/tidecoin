// Copyright (c) 2026 The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_FALCON_H
#define BITCOIN_TEST_UTIL_FALCON_H

#include <key.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace test {
struct Falcon512Encoding {
    std::array<int16_t, 512> coefficients;
    std::vector<size_t> zero_sign_bits;
    unsigned unused_bits;
};

/** Independent, bit-at-a-time parser used to locate alternate legacy encodings.
 * Input is a detached signature, without a transaction's sighash byte. */
inline std::optional<Falcon512Encoding> ParseFalcon512(std::span<const unsigned char> sig)
{
    if (sig.size() <= 41 || sig[0] != 0x39) return std::nullopt;
    size_t pos{41 * 8};
    const auto bit = [&]() -> std::optional<unsigned> {
        if (pos / 8 >= sig.size()) return std::nullopt;
        const unsigned value{(sig[pos / 8] >> (7 - pos % 8)) & 1U};
        ++pos;
        return value;
    };
    Falcon512Encoding result{};
    for (auto& coefficient : result.coefficients) {
        const size_t sign_pos{pos};
        const auto sign = bit();
        if (!sign) return std::nullopt;
        unsigned magnitude{0};
        for (int i = 0; i < 7; ++i) {
            const auto b = bit();
            if (!b) return std::nullopt;
            magnitude = magnitude * 2 + *b;
        }
        for (;;) {
            const auto b = bit();
            if (!b) return std::nullopt;
            if (*b) break;
            magnitude += 128;
            if (magnitude > 2047) return std::nullopt;
        }
        coefficient = *sign ? -static_cast<int16_t>(magnitude) : static_cast<int16_t>(magnitude);
        if (magnitude == 0) result.zero_sign_bits.push_back(sign_pos);
    }
    if ((pos + 7) / 8 != sig.size()) return std::nullopt;
    result.unused_bits = (8 - pos % 8) % 8;
    return result;
}

/** Independent serializer; deliberately permits 2048 for malformed-input tests. */
inline std::vector<unsigned char> EncodeFalcon512(const std::array<int16_t, 512>& coefficients)
{
    std::vector<unsigned char> result(41, 0);
    result[0] = 0x39;
    size_t pos{41 * 8};
    const auto bit = [&](unsigned b) {
        if (pos / 8 == result.size()) result.push_back(0);
        result[pos / 8] |= b << (7 - pos % 8);
        ++pos;
    };
    for (const auto coefficient : coefficients) {
        const unsigned magnitude = coefficient < 0 ? -coefficient : coefficient;
        bit(coefficient < 0);
        for (int i = 6; i >= 0; --i) bit((magnitude >> i) & 1);
        for (unsigned i = 0; i < magnitude / 128; ++i) bit(0);
        bit(1);
    }
    return result;
}

inline void SetFalconBit(std::vector<unsigned char>& sig, size_t pos)
{
    sig.at(pos / 8) |= 1U << (7 - pos % 8);
}

/** Obtain a canonical signature with both alternate forms available. */
inline std::vector<unsigned char> SignFalcon512WithAlternates(const CKey& key, const uint256& hash)
{
    for (int attempt = 0; attempt < 100; ++attempt) {
        std::vector<unsigned char> sig;
        if (!key.Sign(hash, sig)) return {};
        const auto parsed = ParseFalcon512(sig);
        if (parsed && !parsed->zero_sign_bits.empty() && parsed->unused_bits) return sig;
    }
    return {};
}
} // namespace test

#endif // BITCOIN_TEST_UTIL_FALCON_H
