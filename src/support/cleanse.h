// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SUPPORT_CLEANSE_H
#define BITCOIN_SUPPORT_CLEANSE_H

#include <cstdlib>

/** Secure overwrite a buffer (possibly containing secret data) with zero-bytes. The write
 * operation will not be optimized out by the compiler. */
void memory_cleanse(void *ptr, size_t len);

/** Clean a borrowed buffer on every scope exit. The buffer must outlive this guard. */
class ScopedMemoryCleanse
{
    void* const m_ptr;
    const size_t m_len;

public:
    ScopedMemoryCleanse(void* ptr, size_t len) noexcept : m_ptr(ptr), m_len(len) {}
    ~ScopedMemoryCleanse() { if (m_len) memory_cleanse(m_ptr, m_len); }
    ScopedMemoryCleanse(const ScopedMemoryCleanse&) = delete;
    ScopedMemoryCleanse& operator=(const ScopedMemoryCleanse&) = delete;
};

#endif // BITCOIN_SUPPORT_CLEANSE_H
