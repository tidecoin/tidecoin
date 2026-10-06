// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include <policy/policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <pq/pq_scheme.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <vector>

namespace {
constexpr size_t CompactSizeLen(size_t size)
{
    if (size < 253) return 1;
    if (size <= std::numeric_limits<uint16_t>::max()) return 3;
    if (size <= std::numeric_limits<uint32_t>::max()) return 5;
    return 9;
}

constexpr size_t ScriptPushLen(size_t payload_size)
{
    if (payload_size < OP_PUSHDATA1) return 1 + payload_size;
    if (payload_size <= std::numeric_limits<uint8_t>::max()) return 2 + payload_size;
    if (payload_size <= std::numeric_limits<uint16_t>::max()) return 3 + payload_size;
    return 5 + payload_size;
}

// Tidecoin scriptSig spend proxy for non-witness key spends.
constexpr size_t NonWitnessPQScriptSigBytes()
{
    const size_t sig_len = pq::MaxKnownSigBytesInScript(/*use_max_sig=*/true);
    const size_t pubkey_len = pq::MaxKnownPubKeyBytesInScript();
    return CompactSizeLen(sig_len) + sig_len +
        CompactSizeLen(pubkey_len) + pubkey_len;
}

// Tidecoin witness spend proxy for standard v0 keyhash outputs.
constexpr size_t P2WPKHPQWitnessBytes()
{
    const size_t sig_len = pq::MaxKnownSigBytesInScript(/*use_max_sig=*/true);
    const size_t pubkey_len = pq::MaxKnownPubKeyBytesInScript();
    return CompactSizeLen(/*stack items=*/2) +
        CompactSizeLen(sig_len) + sig_len +
        CompactSizeLen(pubkey_len) + pubkey_len;
}

// Tidecoin witness spend proxy for standard script-hash outputs.
constexpr size_t P2WSHPQWitnessBytes()
{
    const size_t sig_len = pq::MaxKnownSigBytesInScript(/*use_max_sig=*/true);
    const size_t pubkey_len = pq::MaxKnownPubKeyBytesInScript();
    const size_t witness_script_len = ScriptPushLen(pubkey_len) + 1; // <pubkey> OP_CHECKSIG
    return CompactSizeLen(/*stack items=*/2) +
        CompactSizeLen(sig_len) + sig_len +
        CompactSizeLen(witness_script_len) + witness_script_len;
}
} // namespace

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // Tidecoin policy uses conservative PQ-sized spend proxies for non-witness
    // and witness outputs, based on largest known supported key/signature sizes.
    if (txout.scriptPubKey.IsUnspendable())
        return 0;

    size_t nSize = GetSerializeSize(txout);
    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    // Tidecoin uses PQ signatures/keys for witness spends. Apply scheme-aware,
    // conservative witness proxies for v0 and v1 script types.
    if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_KEYHASH_SIZE) {
            nSize += (32 + 4 + 1 + (P2WPKHPQWitnessBytes() / WITNESS_SCALE_FACTOR) + 4);
        } else if ((witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) ||
                   (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_SCRIPTHASH_512_SIZE)) {
            nSize += (32 + 4 + 1 + (P2WSHPQWitnessBytes() / WITNESS_SCALE_FACTOR) + 4);
        } else {
            // Unknown witness shapes use a conservative PQ witness script proxy.
            nSize += (32 + 4 + 1 + (P2WSHPQWitnessBytes() / WITNESS_SCALE_FACTOR) + 4);
        }
    } else {
        nSize += (32 + 4 + 1 + NonWitnessPQScriptSigBytes() + 4);
    }

    return dustRelayFeeIn.GetFee(nSize);
}

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    return (txout.nValue < GetDustThreshold(txout, dustRelayFeeIn));
}

std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate)
{
    std::vector<uint32_t> dust_outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        if (IsDust(tx.vout[i], dust_relay_rate)) dust_outputs.push_back(i);
    }
    return dust_outputs;
}

bool IsStandard(const CScript& scriptPubKey, TxoutType& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    whichType = Solver(scriptPubKey, vSolutions);

    if (whichType == TxoutType::NONSTANDARD) {
        return false;
    } else if (whichType == TxoutType::MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    }

    return true;
}

bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, bool permit_bare_multisig, const CFeeRate& dust_relay_fee, std::string& reason)
{
    if (tx.version > TX_MAX_STANDARD_VERSION || tx.version < TX_MIN_STANDARD_VERSION) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    unsigned int sz = GetTransactionWeight(tx);
    if (sz > MAX_STANDARD_TX_WEIGHT) {
        reason = "tx-size";
        return false;
    }

    for (const CTxIn& txin : tx.vin)
    {
        // Biggest 'standard' txin involving only keys is a 15-of-15 P2SH multisig.
        // The MAX_SCRIPT_ELEMENT_SIZE byte limit on redeemScript size bounds this,
        // and MAX_STANDARD_SCRIPTSIG_SIZE leaves some future-proofing room.
        if (txin.scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    unsigned int datacarrier_bytes_left = max_datacarrier_bytes.value_or(0);
    TxoutType whichType;
    for (const CTxOut& txout : tx.vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            reason = "scriptpubkey";
            return false;
        }

        if (whichType == TxoutType::NULL_DATA) {
            unsigned int size = txout.scriptPubKey.size();
            if (size > datacarrier_bytes_left) {
                reason = "datacarrier";
                return false;
            }
            datacarrier_bytes_left -= size;
        } else if ((whichType == TxoutType::MULTISIG) && (!permit_bare_multisig)) {
            reason = "bare-multisig";
            return false;
        }
    }

    // Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
    if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
        reason = "dust";
        return false;
    }

    return true;
}

/**
 * Check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
static bool CheckSigopsBIP54(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    Assert(!tx.IsCoinBase());

    unsigned int sigops{0};
    for (const auto& txin: tx.vin) {
        const auto& prev_txo{inputs.AccessCoin(txin.prevout).out};

        // Unlike the existing block wide sigop limit which counts sigops present in the block
        // itself (including the scriptPubKey which is not executed until spending later), BIP54
        // counts sigops in the block where they are potentially executed (only).
        // This means sigops in the spent scriptPubKey count toward the limit.
        // `fAccurate` means correctly accounting sigops for CHECKMULTISIGs(VERIFY) with 16 pubkeys
        // or fewer. This method of accounting was introduced by BIP16, and BIP54 reuses it.
        // The GetSigOpCount call on the previous scriptPubKey counts both bare and P2SH sigops.
        sigops += txin.scriptSig.GetSigOpCount(/*fAccurate=*/true);
        sigops += prev_txo.scriptPubKey.GetSigOpCount(txin.scriptSig);

        if (sigops > MAX_TX_LEGACY_SIGOPS) {
            return false;
        }
    }

    return true;
}

/**
 * Check transaction inputs.
 *
 * This does three things:
 *  * Prevents mempool acceptance of spends of future
 *    segwit versions we don't know how to validate
 *  * Mitigates a potential denial-of-service attack with
 *    P2SH scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations.
 *  * Prevents spends of unknown/irregular scriptPubKeys,
 *    which mitigates potential denial-of-service attacks
 *    involving expensive scripts and helps reserve them
 *    as potential new upgrade hooks.
 *
 * Note that only the non-witness portion of the transaction is checked here.
 *
 * We also check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase()) {
        return true; // Coinbases don't use vin normally
    }

    if (!CheckSigopsBIP54(tx, mapInputs)) {
        return false;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        std::vector<std::vector<unsigned char> > vSolutions;
        TxoutType whichType = Solver(prev.scriptPubKey, vSolutions);
        if (whichType == TxoutType::NONSTANDARD) {
            return false;
        } else if (whichType == TxoutType::SCRIPTHASH) {
            std::vector<std::vector<unsigned char> > stack;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            if (subscript.GetSigOpCount(true) > MAX_P2SH_SIGOPS) {
                return false;
            }
        }
    }

    return true;
}

bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.vin[i].scriptWitness.IsNull())
            continue;

        const CTxOut &prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;

        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            prevScript = CScript(stack.back().begin(), stack.back().end());
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        if (witnessversion == 0) {
            // Check P2WSH standard limits
            if (witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
                if (tx.vin[i].scriptWitness.stack.empty()) return false;
                if (tx.vin[i].scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                    return false;
                size_t sizeWitnessStack = tx.vin[i].scriptWitness.stack.size() - 1;
                if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                    return false;
                for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                    if (tx.vin[i].scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                        return false;
                }
            }
            continue;
        }

        if (witnessversion == 1) {
            if (witnessprogram.size() != WITNESS_V1_SCRIPTHASH_512_SIZE) {
                return false;
            }
            if (tx.vin[i].scriptWitness.stack.empty()) return false;
            if (tx.vin[i].scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                return false;
            size_t sizeWitnessStack = tx.vin[i].scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                return false;
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (tx.vin[i].scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    return false;
            }
            continue;
        }

        return false;

    }
    return true;
}

bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts)
{
    if (tx.IsCoinBase()) {
        return false;
    }

    int version;
    std::vector<uint8_t> program;
    for (const auto& txin: tx.vin) {
        const auto& prev_spk{prevouts.AccessCoin(txin.prevout).out.scriptPubKey};

        if (prev_spk.IsWitnessProgram(version, program)) {
            if (version == 0) return true;
            continue;
        }

        // For P2SH extract the redeem script and check if it spends a non-anchor witness program. Note
        // this is fine to call EvalScript (as done in AreInputsStandard/IsWitnessStandard) because this
        // function is only ever called after IsStandardTx, which checks the scriptsig is pushonly.
        if (prev_spk.IsPayToScriptHash()) {
            // If EvalScript fails or results in an empty stack, the transaction is invalid by consensus.
            std::vector <std::vector<uint8_t>> stack;
            if (!EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::BASE)
                || stack.empty()) {
                continue;
            }
            const CScript redeem_script{stack.back().begin(), stack.back().end()};
            if (redeem_script.IsWitnessProgram(version, program)) {
                if (version == 0) return true;
            }
        }
    }

    return false;
}

int64_t GetSigOpsAdjustedWeight(int64_t weight, int64_t sigop_cost, unsigned int bytes_per_sigop)
{
    return std::max(weight, sigop_cost * bytes_per_sigop);
}

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return (GetSigOpsAdjustedWeight(nWeight, nSigOpCost, bytes_per_sigop) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx), nSigOpCost, bytes_per_sigop);
}

int64_t GetVirtualTransactionInputSize(const CTxIn& txin, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionInputWeight(txin), nSigOpCost, bytes_per_sigop);
}
