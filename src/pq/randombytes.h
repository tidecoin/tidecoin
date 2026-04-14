#ifndef TIDECOIN_PQ_RANDOMBYTES_H
#define TIDECOIN_PQ_RANDOMBYTES_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
#else
#include <stddef.h>
#include <stdint.h>
#endif // TIDECOIN_PQ_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

int randombytes(uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif
