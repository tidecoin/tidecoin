// Copyright (c) 2026-present The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_PQ_CLEANSE_H
#define BITCOIN_PQ_CLEANSE_H

#include <stddef.h>
#include <string.h>

/* C-compatible cleanup for PQ workspaces. As in memory_cleanse(), the compiler
 * barrier retains the memset while allowing efficient block writes. Other
 * compilers retain the volatile-store fallback. */
static inline void pq_cleanse(void *ptr, size_t len) {
    if (len == 0) {
        return;
    }
#if defined(__GNUC__) || defined(__clang__)
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
#endif
}

#endif // BITCOIN_PQ_CLEANSE_H
