#ifndef TIDECOIN_PQ_PQ_TXSIZE_H
#define TIDECOIN_PQ_PQ_TXSIZE_H

#include <consensus/consensus.h>
#include <pq/pq_scheme.h>
#include <serialize.h>

#include <cstddef>
#include <cstdint>

namespace pq {

inline constexpr size_t PubKeyLenWithPrefix(const SchemeInfo& info)
{
    return info.pubkey_bytes + 1;
}

inline constexpr size_t SigLenMaxInScript(const SchemeInfo& info)
{
    // Signatures are serialized with a trailing sighash byte.
    return info.sig_bytes_max + 1;
}

inline constexpr size_t SigLenFixedInScript(const SchemeInfo& info)
{
    // Fixed-size encoding (when applicable), plus sighash byte.
    return info.sig_bytes_fixed + 1;
}

inline int64_t VSizeFromWeight(int64_t weight)
{
    return (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

inline int64_t WitnessStackSizeForSigAndPubkey(size_t sig_len, size_t pubkey_len)
{
    return GetSizeOfCompactSize(2) +
           GetSizeOfCompactSize(sig_len) + sig_len +
           GetSizeOfCompactSize(pubkey_len) + pubkey_len;
}

inline int64_t VSizeP2WPKHInput(size_t sig_len, size_t pubkey_len)
{
    // Outpoint (36) + scriptSig len (1, empty) + sequence (4)
    const int64_t base = 32 + 4 + 1 + 4;
    const int64_t witness = WitnessStackSizeForSigAndPubkey(sig_len, pubkey_len);
    return VSizeFromWeight(base * WITNESS_SCALE_FACTOR + witness);
}

inline int64_t VSizeP2SH_P2WPKHInput(size_t sig_len, size_t pubkey_len)
{
    // scriptSig is a push of the 22-byte redeem script (0x00 0x14 <20-byte keyhash>).
    constexpr int64_t redeem_script_len = 22;
    const int64_t script_sig_len = 1 + redeem_script_len;
    const int64_t base = 32 + 4 + GetSizeOfCompactSize(script_sig_len) + script_sig_len + 4;
    const int64_t witness = WitnessStackSizeForSigAndPubkey(sig_len, pubkey_len);
    return VSizeFromWeight(base * WITNESS_SCALE_FACTOR + witness);
}

} // namespace pq

#endif // TIDECOIN_PQ_PQ_TXSIZE_H
