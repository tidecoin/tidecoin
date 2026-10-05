#ifndef TIDECOIN_PQ_PQHD_KDF_H
#define TIDECOIN_PQ_PQHD_KDF_H

#include <array>
#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>

#include <pq/pq_scheme.h>
#include <uint256.h>

// Used for cleansing secret key material in small RAII wrappers.
#include <support/cleanse.h>

/**
 * PQHD KDF primitives (PQHD v1).
 *
 * These are deterministic derivation helpers used to build PQHD (hardened-only)
 * wallets. This module intentionally does not depend on wallet storage or RPC
 * code. It only implements cryptographic derivation primitives and testable
 * vectors described in `doc/design/pqhd.md`.
 */
namespace pqhd {

using SeedID32 = std::array<uint8_t, 32>;
using NodeSecret = std::array<uint8_t, 32>;
using ChainCode = std::array<uint8_t, 32>;

/** RAII wrapper for 32-byte master seed material. */
class SecureSeed32
{
public:
    static constexpr size_t SIZE = 32;

    SecureSeed32() = default;
    ~SecureSeed32() { memory_cleanse(m_bytes.data(), m_bytes.size()); }

    SecureSeed32(const SecureSeed32&) = delete;
    SecureSeed32& operator=(const SecureSeed32&) = delete;

    SecureSeed32(SecureSeed32&& other) noexcept
    {
        m_bytes = other.m_bytes;
        memory_cleanse(other.m_bytes.data(), other.m_bytes.size());
    }

    SecureSeed32& operator=(SecureSeed32&& other) noexcept
    {
        if (this == &other) return *this;
        memory_cleanse(m_bytes.data(), m_bytes.size());
        m_bytes = other.m_bytes;
        memory_cleanse(other.m_bytes.data(), other.m_bytes.size());
        return *this;
    }

    bool Set(std::span<const uint8_t> seed) noexcept
    {
        if (seed.size() != m_bytes.size()) return false;
        std::copy_n(seed.begin(), m_bytes.size(), m_bytes.begin());
        return true;
    }

    std::span<uint8_t, SIZE> MutableSpan() noexcept { return std::span<uint8_t, SIZE>(m_bytes); }
    std::span<const uint8_t, SIZE> Span() const noexcept { return std::span<const uint8_t, SIZE>(m_bytes); }

private:
    std::array<uint8_t, SIZE> m_bytes{};
};

class KeygenStreamKey64
{
public:
    KeygenStreamKey64() = default;
    ~KeygenStreamKey64() { memory_cleanse(m_bytes.data(), m_bytes.size()); }

    KeygenStreamKey64(const KeygenStreamKey64&) = delete;
    KeygenStreamKey64& operator=(const KeygenStreamKey64&) = delete;

    KeygenStreamKey64(KeygenStreamKey64&& other) noexcept
    {
        m_bytes = other.m_bytes;
        memory_cleanse(other.m_bytes.data(), other.m_bytes.size());
    }

    KeygenStreamKey64& operator=(KeygenStreamKey64&& other) noexcept
    {
        if (this == &other) return *this;
        memory_cleanse(m_bytes.data(), m_bytes.size());
        m_bytes = other.m_bytes;
        memory_cleanse(other.m_bytes.data(), other.m_bytes.size());
        return *this;
    }

    uint8_t* data() noexcept { return m_bytes.data(); }
    const uint8_t* data() const noexcept { return m_bytes.data(); }
    size_t size() const noexcept { return m_bytes.size(); }
    auto begin() noexcept { return m_bytes.begin(); }
    auto end() noexcept { return m_bytes.end(); }
    auto begin() const noexcept { return m_bytes.begin(); }
    auto end() const noexcept { return m_bytes.end(); }

    std::span<uint8_t, 64> MutableSpan() noexcept { return std::span<uint8_t, 64>(m_bytes); }
    std::span<const uint8_t, 64> Span() const noexcept { return std::span<const uint8_t, 64>(m_bytes); }

private:
    std::array<uint8_t, 64> m_bytes{};
};

using KeygenStreamBlock64 = KeygenStreamKey64;

struct LeafMaterialV1 {
    pq::SchemeId scheme_id;
    KeygenStreamKey64 stream_key;
};

struct Node {
    NodeSecret node_secret{};
    ChainCode chain_code{};

    Node() = default;
    Node(const Node&) = default;
    ~Node() { Clear(); }
    Node& operator=(const Node& other) noexcept
    {
        if (this != &other) {
            Clear();
            node_secret = other.node_secret;
            chain_code = other.chain_code;
        }
        return *this;
    }
    Node(Node&& other) noexcept : node_secret(other.node_secret), chain_code(other.chain_code) { other.Clear(); }
    Node& operator=(Node&& other) noexcept
    {
        if (this != &other) {
            *this = other;
            other.Clear();
        }
        return *this;
    }
    void Clear() noexcept
    {
        memory_cleanse(node_secret.data(), node_secret.size());
        memory_cleanse(chain_code.data(), chain_code.size());
    }
};

/** Compute SeedID32 = SHA256("Tidecoin PQHD seedid v1" || master_seed). */
SeedID32 ComputeSeedID32(std::span<const uint8_t, 32> master_seed);

/** Convert canonical SeedID32 bytes (big-endian digest order) into uint256 storage form. */
uint256 SeedID32ToUint256(std::span<const uint8_t, 32> seedid_be);

/** Convert uint256 seed-id storage form into canonical SeedID32 bytes. */
SeedID32 SeedID32FromUint256(const uint256& seed_id);

/** Convenience: ComputeSeedID32(master_seed) and convert to uint256 storage form. */
uint256 ComputeSeedID32AsUint256(std::span<const uint8_t, 32> master_seed);

/** Compute PQHD master node (NodeSecret/ChainCode) from master seed. */
Node MakeMasterNode(std::span<const uint8_t, 32> master_seed);

/** Hardened-only child derivation (CKD). `index_hardened` must have bit 31 set. */
[[nodiscard]] std::optional<Node> DeriveChild(const Node& parent, uint32_t index_hardened);

/** Convenience: derive a node by iterating hardened CKD along `path_hardened`. */
[[nodiscard]] std::optional<Node> DerivePath(const Node& master, std::span<const uint32_t> path_hardened);

/** Validate a PQHD v1 leaf derivation path (shape + hardened-only). */
[[nodiscard]] bool ValidateV1LeafPath(std::span<const uint32_t> path_hardened);

/** Derive the PQHD v1 leaf material (scheme id + 64-byte stream key) for a leaf path. */
[[nodiscard]] std::optional<LeafMaterialV1> DeriveLeafMaterialV1(std::span<const uint8_t, 32> node_secret_leaf,
                                                                 std::span<const uint32_t> path_hardened);

/**
 * Derive the PQHD v1 64-byte stream key used as internal keygen material.
 *
 * `path_hardened` must be the full hardened path for the leaf (including the
 * scheme element, which must fit in one byte). The scheme id is derived from
 * `path_hardened[2]` and is included in HKDF "info" to domain-separate material
 * per scheme.
 */
[[nodiscard]] std::optional<KeygenStreamKey64> DeriveKeygenStreamKey(std::span<const uint8_t, 32> node_secret_leaf,
                                                                     std::span<const uint32_t> path_hardened);

/** Derive the PQHD v1 stream block for `ctr` (0,1,2,...) from a stream key. */
[[nodiscard]] KeygenStreamBlock64 DeriveKeygenStreamBlock(std::span<const uint8_t, 64> stream_key, uint32_t ctr);

} // namespace pqhd

#endif // TIDECOIN_PQ_PQHD_KDF_H
