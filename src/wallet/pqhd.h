#ifndef BITCOIN_WALLET_PQHD_H
#define BITCOIN_WALLET_PQHD_H

#include <serialize.h>
#include <support/allocators/secure.h>
#include <uint256.h>
#include <util/result.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace wallet {

//! RPC callers must identify an unlock requirement independently of its wording.
enum class PQHDErrorCode { Generic, UnlockNeeded };

//! Keep typed PQHD errors local while retaining util::Result's value/message API.
template <typename T>
struct PQHDResult : util::Result<T> {
    using util::Result<T>::Result;
    PQHDResult() = default;
    PQHDResult(util::Error error, PQHDErrorCode code = PQHDErrorCode::Generic)
        : util::Result<T>(std::move(error)), error_code(code) {}

    PQHDErrorCode error_code{PQHDErrorCode::Generic};
};

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
