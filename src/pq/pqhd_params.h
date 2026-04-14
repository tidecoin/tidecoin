#ifndef TIDECOIN_PQ_PQHD_PARAMS_H
#define TIDECOIN_PQ_PQHD_PARAMS_H

#include <cstdint>

namespace pqhd {

// PQHD derivation path constants (see `doc/design/pqhd.md`).
// These are wallet specification constants and must remain stable once shipped;
// changing them breaks wallet restore/discovery.
constexpr uint32_t PURPOSE{10007};
constexpr uint32_t COIN_TYPE{6868};

} // namespace pqhd

#endif // TIDECOIN_PQ_PQHD_PARAMS_H
