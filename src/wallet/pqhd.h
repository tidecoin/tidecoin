#ifndef BITCOIN_WALLET_PQHD_H
#define BITCOIN_WALLET_PQHD_H

#include <serialize.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace wallet {

//! Wallet DB record containing PQHD master seed material (plaintext wallet only).
struct PQHDSeed
{
    static constexpr int VERSION_BASIC{1};
    static constexpr int CURRENT_VERSION{VERSION_BASIC};

    int nVersion{CURRENT_VERSION};
    int64_t nCreateTime{0};
    std::vector<unsigned char, secure_allocator<unsigned char>> seed;

    SERIALIZE_METHODS(PQHDSeed, obj)
    {
        READWRITE(obj.nVersion);
        SER_READ(obj, if (obj.nVersion != CURRENT_VERSION) throw std::ios_base::failure("Unsupported PQHD seed version"));
        READWRITE(obj.nCreateTime, obj.seed);
    }
};

//! Wallet DB record containing PQHD master seed material encrypted with the wallet master key.
struct PQHDCryptedSeed
{
    static constexpr int VERSION_BASIC{1};
    static constexpr int CURRENT_VERSION{VERSION_BASIC};

    int nVersion{CURRENT_VERSION};
    int64_t nCreateTime{0};
    std::vector<unsigned char> crypted_seed;

    SERIALIZE_METHODS(PQHDCryptedSeed, obj)
    {
        READWRITE(obj.nVersion);
        SER_READ(obj, if (obj.nVersion != CURRENT_VERSION) throw std::ios_base::failure("Unsupported encrypted PQHD seed version"));
        READWRITE(obj.nCreateTime, obj.crypted_seed);
    }
};

//! Wallet policy record for selecting active PQ schemes/seeds for new outputs.
struct PQHDPolicy
{
    static constexpr int VERSION_BASIC{1};
    static constexpr int CURRENT_VERSION{VERSION_BASIC};

    int nVersion{CURRENT_VERSION};
    uint8_t default_receive_scheme{0};
    uint8_t default_change_scheme{0};
    uint256 default_seed_id;
    uint256 default_change_seed_id;

    SERIALIZE_METHODS(PQHDPolicy, obj)
    {
        READWRITE(obj.nVersion);
        SER_READ(obj, if (obj.nVersion != CURRENT_VERSION) throw std::ios_base::failure("Unsupported PQHD policy version"));
        READWRITE(obj.default_receive_scheme, obj.default_change_scheme, obj.default_seed_id,
                  obj.default_change_seed_id);
    }
};

} // namespace wallet

#endif // BITCOIN_WALLET_PQHD_H
