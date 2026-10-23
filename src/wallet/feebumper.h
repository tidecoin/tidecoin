// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_FEEBUMPER_H
#define BITCOIN_WALLET_FEEBUMPER_H

#include <consensus/consensus.h>
#include <pq/pq_scheme.h>
#include <script/interpreter.h>
#include <primitives/transaction.h>
#include <serialize.h>

#include <algorithm>

class uint256;
enum class FeeEstimateMode;
struct bilingual_str;

namespace wallet {
class CCoinControl;
class CWallet;
class CWalletTx;

namespace feebumper {

enum class Result
{
    OK,
    INVALID_ADDRESS_OR_KEY,
    INVALID_REQUEST,
    INVALID_PARAMETER,
    WALLET_ERROR,
    MISC_ERROR,
};

//! Return whether transaction can be bumped.
bool TransactionCanBeBumped(const CWallet& wallet, const Txid& txid);

/** Create bumpfee transaction based on feerate estimates.
 *
 * @param[in] wallet The wallet to use for this bumping
 * @param[in] txid The txid of the transaction to bump
 * @param[in] coin_control A CCoinControl object which provides feerates and other information used for coin selection
 * @param[out] errors Errors
 * @param[out] old_fee The fee the original transaction pays
 * @param[out] new_fee the fee that the bump transaction pays
 * @param[out] mtx The bump transaction itself
 * @param[in] require_mine Whether the original transaction must consist of inputs that can be spent by the wallet
 * @param[in] outputs Vector of new outputs to replace the bumped transaction's outputs
 * @param[in] original_change_index The position of the change output to deduct the fee from in the transaction being bumped
 */
Result CreateRateBumpTransaction(CWallet& wallet,
    const Txid& txid,
    const CCoinControl& coin_control,
    std::vector<bilingual_str>& errors,
    CAmount& old_fee,
    CAmount& new_fee,
    CMutableTransaction& mtx,
    bool require_mine,
    const std::vector<CTxOut>& outputs,
    std::optional<uint32_t> original_change_index = std::nullopt);

//! Sign the new transaction,
//! @return false if the tx couldn't be found or if it was
//! impossible to create the signature(s)
bool SignTransaction(CWallet& wallet, CMutableTransaction& mtx);

//! Commit the bumpfee transaction.
//! @return success in case of CWallet::CommitTransaction was successful,
//! but sets errors if the tx could not be added to the mempool (will try later)
//! or if the old transaction could not be marked as replaced.
Result CommitTransaction(CWallet& wallet,
    const Txid& txid,
    CMutableTransaction&& mtx,
    std::vector<bilingual_str>& errors,
    Txid& bumped_txid);

struct SignatureWeights
{
private:
    int64_t m_weight_diff{0};

    //! Size of a minimal script push of len bytes.
    static size_t PushSize(size_t len)
    {
        if (len < OP_PUSHDATA1) return 1 + len;
        if (len <= 0xff) return 2 + len;
        if (len <= 0xffff) return 3 + len;
        return 5 + len;
    }

    //! Size of a witness stack element of len bytes.
    static size_t WitnessElementSize(size_t len) { return GetSizeOfCompactSize(len) + len; }

public:
    //! Record a signature of sig_size bytes that could be up to max_sig_size bytes.
    void AddSigWeight(size_t sig_size, size_t max_sig_size, SigVersion sigversion)
    {
        max_sig_size = std::max(max_sig_size, sig_size);
        switch (sigversion) {
        case SigVersion::BASE:
            m_weight_diff += (int64_t(PushSize(max_sig_size)) - int64_t(PushSize(sig_size))) * WITNESS_SCALE_FACTOR;
            break;
        case SigVersion::WITNESS_V0:
        case SigVersion::WITNESS_V1_512:
            m_weight_diff += int64_t(WitnessElementSize(max_sig_size)) - int64_t(WitnessElementSize(sig_size));
            break;
        }
    }

    //! Weight to add for every recorded signature to be its maximum size.
    int64_t GetWeightDiffToMax() const { return m_weight_diff; }
};

class SignatureWeightChecker : public DeferringSignatureChecker
{
private:
    SignatureWeights& m_weights;

public:
    SignatureWeightChecker(SignatureWeights& weights, const BaseSignatureChecker& checker) : DeferringSignatureChecker(checker), m_weights(weights) {}

    bool CheckPostQuantumSignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey, const CScript& script, SigVersion sigversion) const override
    {
        if (m_checker.CheckPostQuantumSignature(sig, pubkey, script, sigversion)) {
            // Falcon signatures vary in size; the maximum includes the sighash byte.
            const pq::SchemeInfo* scheme{pubkey.empty() ? nullptr : pq::SchemeFromPrefix(pubkey[0])};
            const size_t max_sig_size{scheme ? scheme->sig_bytes_max + 1 : pq::MaxKnownSigBytesInScript(/*use_max_sig=*/true)};
            m_weights.AddSigWeight(sig.size(), max_sig_size, sigversion);
            return true;
        }
        return false;
    }
};

} // namespace feebumper
} // namespace wallet

#endif // BITCOIN_WALLET_FEEBUMPER_H
