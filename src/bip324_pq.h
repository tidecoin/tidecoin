// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TIDECOIN_BIP324_PQ_H
#define TIDECOIN_BIP324_PQ_H

#include <array>
#include <cstddef>
#include <optional>

#include <crypto/chacha20.h>
#include <crypto/chacha20poly1305.h>
#include <span.h>

/** The Tidecoin v2 PQ packet cipher, encapsulating its key derivation, stream cipher, and AEAD. */
class BIP324PQCipher
{
public:
    static constexpr unsigned SESSION_ID_LEN{32};
    static constexpr unsigned GARBAGE_TERMINATOR_LEN{16};
    static constexpr unsigned REKEY_INTERVAL{224};
    static constexpr unsigned LENGTH_LEN{3};
    static constexpr unsigned HEADER_LEN{1};
    static constexpr unsigned EXPANSION = LENGTH_LEN + HEADER_LEN + FSChaCha20Poly1305::EXPANSION;
    static constexpr std::byte IGNORE_BIT{0x80};

private:
    std::optional<FSChaCha20> m_send_l_cipher;
    std::optional<FSChaCha20> m_recv_l_cipher;
    std::optional<FSChaCha20Poly1305> m_send_p_cipher;
    std::optional<FSChaCha20Poly1305> m_recv_p_cipher;

    std::array<std::byte, SESSION_ID_LEN> m_session_id{};
    std::array<std::byte, GARBAGE_TERMINATOR_LEN> m_send_garbage_terminator{};
    std::array<std::byte, GARBAGE_TERMINATOR_LEN> m_recv_garbage_terminator{};

public:
    /** Default constructor. Call InitializeFromSharedSecret before use. */
    BIP324PQCipher() = default;

    /** Initialize from a shared secret. Can only be called once.
     *
     * initiator is set to true if we are the initiator establishing the v2 P2P connection.
     * self_decrypt is only for testing, and swaps encryption/decryption keys, so that encryption
     * and decryption can be tested without knowing the other side's private key.
     */
    void InitializeFromSharedSecret(std::span<const std::byte> shared_secret,
                                    bool initiator,
                                    bool self_decrypt = false) noexcept;

    /** Determine whether this cipher is fully initialized. */
    explicit operator bool() const noexcept { return m_send_l_cipher.has_value(); }

    /** Encrypt a packet. Only after Initialize().
     *
     * It must hold that output.size() == contents.size() + EXPANSION.
     */
    void Encrypt(std::span<const std::byte> contents, std::span<const std::byte> aad, bool ignore, std::span<std::byte> output) noexcept;

    /** Decrypt the length of a packet. Only after Initialize().
     *
     * It must hold that input.size() == LENGTH_LEN.
     */
    unsigned DecryptLength(std::span<const std::byte> input) noexcept;

    /** Decrypt a packet. Only after Initialize().
     *
     * It must hold that input.size() + LENGTH_LEN == contents.size() + EXPANSION.
     * Contents.size() must equal the length returned by DecryptLength.
     */
    bool Decrypt(std::span<const std::byte> input, std::span<const std::byte> aad, bool& ignore, std::span<std::byte> contents) noexcept;

    /** Get the Session ID. Only after Initialize(). */
    std::span<const std::byte> GetSessionID() const noexcept { return m_session_id; }

    /** Get the Garbage Terminator to send. Only after Initialize(). */
    std::span<const std::byte> GetSendGarbageTerminator() const noexcept { return m_send_garbage_terminator; }

    /** Get the expected Garbage Terminator to receive. Only after Initialize(). */
    std::span<const std::byte> GetReceiveGarbageTerminator() const noexcept { return m_recv_garbage_terminator; }
};

#endif // TIDECOIN_BIP324_PQ_H
