// Copyright (c) 2026-present The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_PQ_CLEANSE_H
#define BITCOIN_PQ_CLEANSE_H

#include <stddef.h>

/* C-compatible cleanup for PQClean workspaces. Volatile stores must not be
 * removed as dead writes. The size and control flow do not depend on secrets. */
static inline void pq_cleanse(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

#endif // BITCOIN_PQ_CLEANSE_H
