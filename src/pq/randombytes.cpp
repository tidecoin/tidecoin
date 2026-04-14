#include <pq/randombytes.h>

#include <random.h>

#include <algorithm>
#include <span>

int randombytes(uint8_t *buf, size_t n)
{
    if (n == 0) {
        return 0;
    }
    size_t offset = 0;
    while (offset < n) {
        const size_t chunk = std::min<size_t>(32, n - offset);
        GetStrongRandBytes(std::span<unsigned char>(buf + offset, chunk));
        offset += chunk;
    }
    return 0;
}
