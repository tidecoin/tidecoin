// Copyright (c) 2024-present The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <pq/cleanse.h>

#include <stddef.h>

#include <pq/ml-dsa-87/packing.h>

int tidecoin_mldsa87_pubkey_from_sk(const uint8_t* sk, size_t sklen,
                                    uint8_t* pk, size_t pklen)
{
    if (sklen != PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES ||
        pklen != PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return -1;
    }

    uint8_t rho[SEEDBYTES];
    uint8_t tr[TRBYTES];
    uint8_t key[SEEDBYTES];
    polyvecl mat[K];
    polyvecl s1;
    polyvecl s1hat;
    polyveck s2;
    polyveck t0;
    polyveck t1;

    PQCLEAN_MLDSA87_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    PQCLEAN_MLDSA87_CLEAN_polyvec_matrix_expand(mat, rho);

    s1hat = s1;
    PQCLEAN_MLDSA87_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_MLDSA87_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_MLDSA87_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_MLDSA87_CLEAN_polyveck_invntt_tomont(&t1);
    PQCLEAN_MLDSA87_CLEAN_polyveck_add(&t1, &t1, &s2);
    PQCLEAN_MLDSA87_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_MLDSA87_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_MLDSA87_CLEAN_pack_pk(pk, rho, &t1);
    pq_cleanse(&rho, sizeof rho);
    pq_cleanse(&tr, sizeof tr);
    pq_cleanse(&key, sizeof key);
    pq_cleanse(&s1, sizeof s1);
    pq_cleanse(&s1hat, sizeof s1hat);
    pq_cleanse(&s2, sizeof s2);
    pq_cleanse(&t0, sizeof t0);
    pq_cleanse(&t1, sizeof t1);
    return 0;
}
