#ifndef TIDECOIN_PQ_PQHD_PARAMS_H
#define TIDECOIN_PQ_PQHD_PARAMS_H

#include <cstdint>

namespace pqhd {

// PQHD derivation path constants (see `doc/design/pqhd.md`).
// These are wallet specification constants and must remain stable once shipped;
// changing them breaks wallet restore/discovery.

// Purpose (path element 0). Each standard script family has its own purpose,
// so one seed and index never yield the same key for two families. Otherwise
// pkh and wpkh addresses would share HASH160(pubkey). PURPOSE_GENERIC is for
// custom and multisig descriptors.
constexpr uint32_t PURPOSE_GENERIC{10007};
constexpr uint32_t PURPOSE_PKH{10044};
constexpr uint32_t PURPOSE_SH_WPKH{10049};
constexpr uint32_t PURPOSE_WPKH{10084};
constexpr uint32_t PURPOSE_WSH512{10087};

constexpr bool IsKnownPurpose(uint32_t purpose)
{
    return purpose == PURPOSE_GENERIC || purpose == PURPOSE_PKH || purpose == PURPOSE_SH_WPKH ||
           purpose == PURPOSE_WPKH || purpose == PURPOSE_WSH512;
}

// Coin type (path element 1). Test networks share one value, so default
// descriptors from one seed differ between test networks and mainnet. Explicit
// paths may use either known coin type on any network.
constexpr uint32_t COIN_TYPE_MAIN{6868};
constexpr uint32_t COIN_TYPE_TEST{1};

constexpr bool IsKnownCoinType(uint32_t coin_type)
{
    return coin_type == COIN_TYPE_MAIN || coin_type == COIN_TYPE_TEST;
}

} // namespace pqhd

#endif // TIDECOIN_PQ_PQHD_PARAMS_H
