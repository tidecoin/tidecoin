// Copyright (c) 2024-present The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <pq/cleanse.h>

#include <stddef.h>

#include <pq/falcon-1024/api.h>
#include <pq/falcon-1024/inner.h>

int tidecoin_falcon1024_is_valid_pubkey(const uint8_t* pk, size_t pklen)
{
    if (pklen != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES || pk[0] != 10) {
        return 0;
    }
    uint16_t h[1024];
    return PQCLEAN_FALCON1024_CLEAN_modq_decode(h, 10, pk + 1, pklen - 1) == pklen - 1;
}

int tidecoin_falcon1024_pubkey_from_sk(const uint8_t* sk, size_t sklen,
                                       uint8_t* pk, size_t pklen)
{
    if (sklen != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES ||
        pklen != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return -1;
    }

    int8_t f[1024];
    int8_t g[1024];
    uint16_t h[1024];
    union {
        uint8_t b[2 * 1024 * sizeof(uint16_t)];
        uint16_t dummy_u16;
    } tmp;

    int result = -1;
    size_t u = 1;
    size_t v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(
        f, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10],
        sk + u, sklen - u);
    if (v == 0) {
        goto cleanup;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(
        g, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10],
        sk + u, sklen - u);
    if (v == 0) {
        goto cleanup;
    }

    if (!PQCLEAN_FALCON1024_CLEAN_compute_public(h, f, g, 10, tmp.b)) {
        goto cleanup;
    }

    pk[0] = 0x00 + 10;
    v = PQCLEAN_FALCON1024_CLEAN_modq_encode(
        pk + 1, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1,
        h, 10);
    if (v != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
        goto cleanup;
    }

    result = 0;
cleanup:
    pq_cleanse(&f, sizeof f);
    pq_cleanse(&g, sizeof g);
    pq_cleanse(&h, sizeof h);
    pq_cleanse(&tmp, sizeof tmp);
    return result;
}
