// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <common/messages.h>
#include <consensus/amount.h>
#include <consensus/tx_verify.h>
#include <node/psbt.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <tinyformat.h>
#include <util/translation.h>

#include <numeric>

namespace node {
PSBTAnalysis AnalyzePSBT(PartiallySignedTransaction psbtx, unsigned int script_verify_flags)
{
    // Go through each input and build status
    PSBTAnalysis result;

    bool calc_fee = true;

    CAmount in_amt = 0;

    result.inputs.resize(psbtx.tx->vin.size());

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& input = psbtx.inputs[i];
        PSBTInputAnalysis& input_analysis = result.inputs[i];
        if (!input.IsUTXOConsistent(psbtx.tx->vin[i].prevout)) {
            result.SetInvalid(strprintf("PSBT is not valid. Input %u has inconsistent UTXO data", i));
            return result;
        }

        // We set next role here and ratchet backwards as required
        input_analysis.next = PSBTRole::EXTRACTOR;

        // Check for a UTXO
        CTxOut utxo;
        if (psbtx.GetInputUTXO(utxo, i)) {
            if (!MoneyRange(utxo.nValue) || !MoneyRange(in_amt + utxo.nValue)) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u has invalid value", i));
                return result;
            }
            in_amt += utxo.nValue;
            input_analysis.has_utxo = true;
        } else {
            if (input.non_witness_utxo && psbtx.tx->vin[i].prevout.n >= input.non_witness_utxo->vout.size()) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u specifies invalid prevout", i));
                return result;
            }
            input_analysis.has_utxo = false;
            input_analysis.is_final = false;
            input_analysis.next = PSBTRole::UPDATER;
            calc_fee = false;
        }

        if (!utxo.IsNull() && utxo.scriptPubKey.IsUnspendable()) {
            result.SetInvalid(strprintf("PSBT is not valid. Input %u spends unspendable output", i));
            return result;
        }

        // Check if it is final
        if (!PSBTInputSignedAndVerified(psbtx, i, &txdata, script_verify_flags)) {
            input_analysis.is_final = false;

            // Figure out what is missing
            SignatureData outdata;
            const auto error = SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, input.sighash_type, &outdata, /*finalize=*/true, script_verify_flags, PSBTInputIntent::INSPECT);
            const bool complete = error == PSBTError::OK;

            // Things are missing
            if (!complete) {
                input_analysis.missing_pubkeys = outdata.missing_pubkeys;
                input_analysis.missing_redeem_script = outdata.missing_redeem_script;
                input_analysis.missing_witness_script = outdata.missing_witness_script;
                input_analysis.missing_sigs = outdata.missing_sigs;

                // If we are only missing signatures and nothing else, then next is signer
                if (outdata.missing_pubkeys.empty() && outdata.missing_redeem_script.IsNull() && outdata.missing_witness_script.empty() && !outdata.missing_sigs.empty()) {
                    input_analysis.next = PSBTRole::SIGNER;
                } else {
                    input_analysis.next = PSBTRole::UPDATER;
                }
            } else {
                input_analysis.next = PSBTRole::FINALIZER;
            }
            if (!complete || !IsSupportedSighash(input.sighash_type.value_or(SIGHASH_ALL))) {
                const int mode = input.sighash_type.value_or(SIGHASH_ALL);
                if (error == PSBTError::SINGLE_WITHOUT_OUTPUT || SingleWithoutOutput(mode, i, psbtx.tx->vout.size())) {
                    input_analysis.issue = PSBTError::SINGLE_WITHOUT_OUTPUT;
                    input_analysis.next = PSBTRole::CREATOR;
                } else if (!IsSupportedSighash(mode)) {
                    input_analysis.issue = PSBTError::SIGHASH_UNSUPPORTED;
                    input_analysis.next = PSBTRole::UPDATER;
                } else if (error == PSBTError::SIGHASH_MISMATCH) {
                    input_analysis.issue = error;
                    input_analysis.next = PSBTRole::UPDATER;
                }
                if (input_analysis.issue) {
                    input_analysis.issue_message = common::PSBTErrorString(*input_analysis.issue).original;
                    input_analysis.missing_sigs.clear();
                }
            }
        } else if (!utxo.IsNull()){
            input_analysis.is_final = true;
            const MutableTransactionSignatureChecker checker{&*psbtx.tx, i, utxo.nValue, txdata, MissingDataBehavior::FAIL, !(script_verify_flags & SCRIPT_VERIFY_PQ_STRICT)};
            const SignatureCheckObserver observer{checker, i, psbtx.tx->vout.size()};
            if (VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, script_verify_flags, observer) && observer.legacy_single_without_output) {
                input_analysis.issue = PSBTError::SINGLE_WITHOUT_OUTPUT;
                input_analysis.issue_message = "Existing legacy SINGLE signature is not bound to this transaction";
            }
        }
    }

    // Calculate next role for PSBT by grabbing "minimum" PSBTInput next role
    result.next = PSBTRole::EXTRACTOR;
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInputAnalysis& input_analysis = result.inputs[i];
        result.next = std::min(result.next, input_analysis.next);
    }

    if (calc_fee) {
        // Get the output amount
        CAmount out_amt = std::accumulate(psbtx.tx->vout.begin(), psbtx.tx->vout.end(), CAmount(0),
            [](CAmount a, const CTxOut& b) {
                if (!MoneyRange(a) || !MoneyRange(b.nValue) || !MoneyRange(a + b.nValue)) {
                    return CAmount(-1);
                }
                return a += b.nValue;
            }
        );
        if (!MoneyRange(out_amt)) {
            result.SetInvalid("PSBT is not valid. Output amount invalid");
            return result;
        }

        // Get the fee
        CAmount fee = in_amt - out_amt;
        result.fee = fee;

        // Estimate the size
        CMutableTransaction mtx(*psbtx.tx);
        CCoinsView view_dummy;
        CCoinsViewCache view(&view_dummy);
        bool success = true;

        for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
            PSBTInput& input = psbtx.inputs[i];
            Coin newcoin;
            if (result.inputs[i].issue && !result.inputs[i].is_final) {
                success = false;
                break;
            }

            // Verify final fields with the spent outputs, including inputs finalized
            // above. Only unfinished inputs need dummy signatures for estimation.
            const auto* input_txdata = PSBTInputSigned(input) ? &txdata : nullptr;
            if (SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, input_txdata, input.sighash_type, nullptr, /*finalize=*/true, script_verify_flags, PSBTInputIntent::INSPECT) != PSBTError::OK || !psbtx.GetInputUTXO(newcoin.out, i)) {
                success = false;
                break;
            } else {
                mtx.vin[i].scriptSig = input.final_script_sig;
                mtx.vin[i].scriptWitness = input.final_script_witness;
                newcoin.nHeight = 1;
                view.AddCoin(psbtx.tx->vin[i].prevout, std::move(newcoin), true);
            }
        }

        if (success) {
            CTransaction ctx = CTransaction(mtx);
            size_t size(GetVirtualTransactionSize(ctx, GetTransactionSigOpCost(ctx, view, script_verify_flags), ::nBytesPerSigOp));
            result.estimated_vsize = size;
            // Estimate fee rate
            CFeeRate feerate(fee, size);
            result.estimated_feerate = feerate;
        }

    }

    return result;
}

PSBTAnalysis AnalyzePSBT(PartiallySignedTransaction psbtx)
{
    return AnalyzePSBT(std::move(psbtx), STANDARD_SCRIPT_VERIFY_FLAGS);
}
} // namespace node
