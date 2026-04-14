# Copyright (c) 2024-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(tidecoin_quantum STATIC EXCLUDE_FROM_ALL
  fips202.c
  randombytes.cpp
  falcon512.c
  falcon1024.c
  mldsa44.c
  mldsa65.c
  mldsa87.c
  falcon-512/codec.c
  falcon-512/common.c
  falcon-512/fft.c
  falcon-512/fpr.c
  falcon-512/keygen.c
  falcon-512/pqclean.c
  falcon-512/rng.c
  falcon-512/sign.c
  falcon-512/vrfy.c
  falcon-1024/codec.c
  falcon-1024/common.c
  falcon-1024/fft.c
  falcon-1024/fpr.c
  falcon-1024/keygen.c
  falcon-1024/pqclean.c
  falcon-1024/rng.c
  falcon-1024/sign.c
  falcon-1024/vrfy.c
  ml-dsa-44/ntt.c
  ml-dsa-44/packing.c
  ml-dsa-44/poly.c
  ml-dsa-44/polyvec.c
  ml-dsa-44/reduce.c
  ml-dsa-44/rounding.c
  ml-dsa-44/sign.c
  ml-dsa-44/symmetric-shake.c
  ml-dsa-65/ntt.c
  ml-dsa-65/packing.c
  ml-dsa-65/poly.c
  ml-dsa-65/polyvec.c
  ml-dsa-65/reduce.c
  ml-dsa-65/rounding.c
  ml-dsa-65/sign.c
  ml-dsa-65/symmetric-shake.c
  ml-dsa-87/ntt.c
  ml-dsa-87/packing.c
  ml-dsa-87/poly.c
  ml-dsa-87/polyvec.c
  ml-dsa-87/reduce.c
  ml-dsa-87/rounding.c
  ml-dsa-87/sign.c
  ml-dsa-87/symmetric-shake.c
  ml-kem-512/cbd.c
  ml-kem-512/indcpa.c
  ml-kem-512/kem.c
  ml-kem-512/ntt.c
  ml-kem-512/poly.c
  ml-kem-512/polyvec.c
  ml-kem-512/reduce.c
  ml-kem-512/symmetric-shake.c
  ml-kem-512/verify.c
)
set_target_properties(tidecoin_quantum PROPERTIES
  C_STANDARD 11
  C_STANDARD_REQUIRED ON
)

target_link_libraries(tidecoin_quantum
  PRIVATE
    core_interface
    tidecoin_util
)

target_include_directories(tidecoin_quantum
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
