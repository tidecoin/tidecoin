// Copyright (c) 2024-present The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <pq/cleanse.h>

#include <stddef.h>
#include <stdint.h>

#include <pq/falcon-512/api.h>
#include <pq/falcon-512/inner.h>
#include <pq/randombytes.h>

enum {
    TIDECOIN_FALCON512_NONCELEN = 40,
    TIDECOIN_FALCON512_LEGACY_CRYPTO_BYTES = 690,
    TIDECOIN_FALCON512_LEGACY_VLEN_MAX =
        TIDECOIN_FALCON512_LEGACY_CRYPTO_BYTES - TIDECOIN_FALCON512_NONCELEN - 3,
};

/*
 * Encoding/decoding of keys and signatures.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2017-2019  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@nccgroup.com>
 */
/*
 * Tidecoin 0.18.3 src/codec.cpp, commit
 * 7b525367e9ea1b614aa380a52394f0e3d3878aa9. Preserve the old treatment of
 * negative zero and unused final bits for preactivation block verification.
 * The caller still requires exact consumption. Strict verification continues
 * to use the canonical PQClean decoder.
 */
static size_t
tidecoin_falcon512_comp_decode_legacy(
    int16_t *x, unsigned logn,
    const void *in, size_t max_in_len) {
    const uint8_t *buf;
    size_t n, u, v;
    uint32_t acc;
    unsigned acc_len;

    n = (size_t)1 << logn;
    buf = (const uint8_t *)in;
    acc = 0;
    acc_len = 0;
    v = 0;
    for (u = 0; u < n; u ++) {
        unsigned b, s, m;

        /*
         * Get next eight bits: sign and low seven bits of the
         * absolute value.
         */
        if (v >= max_in_len) {
            return 0;
        }
        /* Explicitly discard the high byte, as the old uint32_t shift did. */
        acc = ((acc & 0x00FFFFFFu) << 8) | (uint32_t)buf[v ++];
        b = acc >> acc_len;
        s = b & 128;
        m = b & 127;

        /*
         * Get next bits until a 1 is reached.
         */
        for (;;) {
            if (acc_len == 0) {
                if (v >= max_in_len) {
                    return 0;
                }
                acc = ((acc & 0x00FFFFFFu) << 8) | (uint32_t)buf[v ++];
                acc_len = 8;
            }
            acc_len --;
            if (((acc >> acc_len) & 1) != 0) {
                break;
            }
            m += 128;
            if (m > 2047) {
                return 0;
            }
        }
        x[u] = (int16_t) m;
        if (s) {
            x[u] = (int16_t) - x[u];
        }
    }
    return v;
}

/* Format only: false for canonical encodings and malformed full buffers. */
int tidecoin_falcon512_is_noncanonical_legacy(const uint8_t* sig, size_t siglen)
{
    int16_t decoded[512];
    if (siglen <= 1 + TIDECOIN_FALCON512_NONCELEN) {
        return 0;
    }
    if (sig[0] != 0x30 + 9) {
        return 0;
    }
    const uint8_t* body = sig + 1 + TIDECOIN_FALCON512_NONCELEN;
    const size_t bodylen = siglen - 1 - TIDECOIN_FALCON512_NONCELEN;
    if (PQCLEAN_FALCON512_CLEAN_comp_decode(decoded, 9, body, bodylen) == bodylen) {
        return 0;
    }
    return tidecoin_falcon512_comp_decode_legacy(decoded, 9, body, bodylen) == bodylen;
}

static int tidecoin_falcon512_is_short_legacy(const int16_t* s1,
                                              const int16_t* s2,
                                              unsigned logn)
{
    if (logn < 1 || logn > 10) {
        return 0;
    }

    /*
     * Legacy bound: floor((7085 * 12289) >> (10 - logn)).
     * See oldtidecoin src/common.cpp.
     */
    const uint32_t bound = (uint32_t)(((uint64_t)7085 * 12289) >> (10 - logn));

    size_t n = (size_t)1 << logn;
    uint32_t s = 0;
    uint32_t ng = 0;
    for (size_t u = 0; u < n; ++u) {
        int32_t z = s1[u];
        s += (uint32_t)(z * z);
        ng |= s;
        z = s2[u];
        s += (uint32_t)(z * z);
        ng |= s;
    }
    s |= -(ng >> 31);

    return s < bound;
}

static int tidecoin_falcon512_verify_legacy(const uint8_t* sig, size_t siglen,
                                            const uint8_t* m, size_t mlen,
                                            const uint8_t* pk)
{
    union {
        uint8_t b[2 * 512];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    uint16_t h[512];
    uint16_t hm[512];
    int16_t sig_dec[512];
    inner_shake256_context sc;

    if (siglen < 1 + TIDECOIN_FALCON512_NONCELEN) {
        return -1;
    }
    if (sig[0] != 0x30 + 9) {
        return -1;
    }
    if (pk[0] != 0x00 + 9) {
        return -1;
    }
    if (PQCLEAN_FALCON512_CLEAN_modq_decode(
            h, 9, pk + 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) !=
        PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }
    PQCLEAN_FALCON512_CLEAN_to_ntt_monty(h, 9);

    const uint8_t* nonce = sig + 1;
    const uint8_t* sigbuf = sig + 1 + TIDECOIN_FALCON512_NONCELEN;
    const size_t sigbuflen = siglen - 1 - TIDECOIN_FALCON512_NONCELEN;

    if (sigbuflen == 0) {
        return -1;
    }
    if (tidecoin_falcon512_comp_decode_legacy(sig_dec, 9, sigbuf, sigbuflen) != sigbuflen) {
        return -1;
    }

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, TIDECOIN_FALCON512_NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc, hm, 9, tmp.b);
    inner_shake256_ctx_release(&sc);

    if (!PQCLEAN_FALCON512_CLEAN_verify_raw(hm, sig_dec, h, 9, tmp.b)) {
        const int16_t* s1 = (const int16_t*)tmp.b;
        if (!tidecoin_falcon512_is_short_legacy(s1, sig_dec, 9)) {
            return -1;
        }
    }
    return 0;
}

static int tidecoin_falcon512_do_sign_legacy(uint8_t* nonce, uint8_t* sigbuf,
                                             size_t* sigbuflen,
                                             const uint8_t* m, size_t mlen,
                                             const uint8_t* sk)
{
    union {
        uint8_t b[72 * 512];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[512], g[512], F[512], G[512];
    struct {
        int16_t sig[512];
        uint16_t hm[512];
    } r;
    unsigned char seed[48];
    inner_shake256_context sc;
    size_t u, v;
    int result = -1;

    if (sk[0] != 0x50 + 9) {
        goto cleanup;
    }
    u = 1;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        f, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        goto cleanup;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        g, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        goto cleanup;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        F, 9, PQCLEAN_FALCON512_CLEAN_max_FG_bits[9],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        goto cleanup;
    }
    u += v;
    if (u != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES) {
        goto cleanup;
    }
    if (!PQCLEAN_FALCON512_CLEAN_complete_private(G, f, g, F, 9, tmp.b)) {
        goto cleanup;
    }

    randombytes(nonce, TIDECOIN_FALCON512_NONCELEN);

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, TIDECOIN_FALCON512_NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc, r.hm, 9, tmp.b);
    inner_shake256_ctx_release(&sc);

    randombytes(seed, sizeof seed);
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, seed, sizeof seed);
    inner_shake256_flip(&sc);

    PQCLEAN_FALCON512_CLEAN_sign_dyn(r.sig, &sc, f, g, F, G, r.hm, 9, tmp.b);
    v = PQCLEAN_FALCON512_CLEAN_comp_encode(sigbuf, *sigbuflen, r.sig, 9);
    inner_shake256_ctx_release(&sc);
    if (v != 0) {
        *sigbuflen = v;
        result = 0;
    }
cleanup:
    pq_cleanse(&tmp, sizeof tmp);
    pq_cleanse(&f, sizeof f);
    pq_cleanse(&g, sizeof g);
    pq_cleanse(&F, sizeof F);
    pq_cleanse(&G, sizeof G);
    pq_cleanse(&r, sizeof r);
    pq_cleanse(&seed, sizeof seed);
    return result;
}

/* One signing attempt; pq::SignFalcon handles retries and the local size bound. */
int tidecoin_falcon512_sign_legacy_attempt(uint8_t* sig, size_t* siglen,
                                         const uint8_t* m, size_t mlen,
                                         const uint8_t* sk, size_t sklen)
{
    if (sklen != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }

    size_t vlen = TIDECOIN_FALCON512_LEGACY_VLEN_MAX;
    if (tidecoin_falcon512_do_sign_legacy(sig + 1,
                                        sig + 1 + TIDECOIN_FALCON512_NONCELEN,
                                        &vlen, m, mlen, sk) == 0) {
        sig[0] = 0x30 + 9;
        *siglen = 1 + TIDECOIN_FALCON512_NONCELEN + vlen;
        return 0;
    }

    return -1;
}

int tidecoin_falcon512_verify(const uint8_t* sig, size_t siglen,
                              const uint8_t* m, size_t mlen,
                              const uint8_t* pk, size_t pklen,
                              int legacy_mode)
{
    if (pklen != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return -1;
    }
    if (legacy_mode) {
        return tidecoin_falcon512_verify_legacy(sig, siglen, m, mlen, pk);
    }
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

int tidecoin_falcon512_pubkey_from_sk(const uint8_t* sk, size_t sklen,
                                      uint8_t* pk, size_t pklen)
{
    if (sklen != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES ||
        pklen != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return -1;
    }

    int8_t f[512];
    int8_t g[512];
    uint16_t h[512];
    union {
        uint8_t b[2 * 512 * sizeof(uint16_t)];
        uint16_t dummy_u16;
    } tmp;

    int result = -1;
    size_t u = 1;
    size_t v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        f, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9],
        sk + u, sklen - u);
    if (v == 0) {
        goto cleanup;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        g, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9],
        sk + u, sklen - u);
    if (v == 0) {
        goto cleanup;
    }

    if (!PQCLEAN_FALCON512_CLEAN_compute_public(h, f, g, 9, tmp.b)) {
        goto cleanup;
    }

    pk[0] = 0x00 + 9;
    v = PQCLEAN_FALCON512_CLEAN_modq_encode(
        pk + 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1,
        h, 9);
    if (v != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
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
