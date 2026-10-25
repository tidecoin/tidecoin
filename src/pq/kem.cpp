#include <pq/pq_api.h>

#include <support/cleanse.h>

namespace pq {

namespace {

bool IsValidEncapsulationKey(std::span<const uint8_t> pk)
{
    if (pk.size() != MLKEM512_PUBLICKEY_BYTES) return false;

    // FIPS 203, section 7.2: the first 768 bytes encode 512 coefficients,
    // two per three bytes. The final 32-byte public seed is unrestricted.
    constexpr size_t ENCODED_COEFFICIENT_BYTES{768};
    static_assert(ENCODED_COEFFICIENT_BYTES + 32 == MLKEM512_PUBLICKEY_BYTES);
    for (size_t i = 0; i < ENCODED_COEFFICIENT_BYTES; i += 3) {
        const uint16_t a = pk[i] | ((pk[i + 1] & 0x0f) << 8);
        const uint16_t b = (pk[i + 1] >> 4) | (pk[i + 2] << 4);
        if (a >= 3329 || b >= 3329) return false;
    }
    return true;
}

} // namespace

MLKEM512Keypair::~MLKEM512Keypair()
{
    Clear();
}

void MLKEM512Keypair::Clear() noexcept
{
    memory_cleanse(m_pk.data(), m_pk.size());
    memory_cleanse(m_sk.data(), m_sk.size());
    m_initialized = false;
}

bool MLKEM512Keypair::Generate()
{
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(m_pk.data(), m_sk.data()) != 0) {
        return false;
    }
    m_initialized = true;
    return true;
}

bool MLKEM512Keypair::GenerateDeterministic(std::span<const uint8_t> coins)
{
    if (coins.size() != MLKEM512_KEYPAIR_COINS_BYTES) {
        return false;
    }
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(m_pk.data(), m_sk.data(), coins.data()) != 0) {
        return false;
    }
    m_initialized = true;
    return true;
}

bool MLKEM512Keypair::Set(std::span<const uint8_t> pk, std::span<const uint8_t> sk)
{
    if (pk.size() != m_pk.size() || sk.size() != m_sk.size()) {
        return false;
    }
    std::copy(pk.begin(), pk.end(), m_pk.begin());
    std::copy(sk.begin(), sk.end(), m_sk.begin());
    m_initialized = true;
    return true;
}

bool MLKEM512Encaps(std::span<const uint8_t> pk,
                    std::span<uint8_t> ct,
                    std::span<uint8_t> ss)
{
    if (!IsValidEncapsulationKey(pk) ||
        ct.size() != MLKEM512_CIPHERTEXT_BYTES ||
        ss.size() != MLKEM512_SHARED_SECRET_BYTES) {
        return false;
    }
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct.data(), ss.data(), pk.data()) == 0;
}

bool MLKEM512EncapsDeterministic(std::span<const uint8_t> pk,
                                 std::span<const uint8_t> coins,
                                 std::span<uint8_t> ct,
                                 std::span<uint8_t> ss)
{
    if (!IsValidEncapsulationKey(pk) ||
        coins.size() != MLKEM512_SHARED_SECRET_BYTES ||
        ct.size() != MLKEM512_CIPHERTEXT_BYTES ||
        ss.size() != MLKEM512_SHARED_SECRET_BYTES) {
        return false;
    }
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct.data(), ss.data(), pk.data(), coins.data()) == 0;
}

bool MLKEM512Decaps(std::span<const uint8_t> ct,
                    std::span<const uint8_t> sk,
                    std::span<uint8_t> ss)
{
    if (ct.size() != MLKEM512_CIPHERTEXT_BYTES ||
        sk.size() != MLKEM512_SECRETKEY_BYTES ||
        ss.size() != MLKEM512_SHARED_SECRET_BYTES) {
        return false;
    }
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss.data(), ct.data(), sk.data()) == 0;
}

} // namespace pq
