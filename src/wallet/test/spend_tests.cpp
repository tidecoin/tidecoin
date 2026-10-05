// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <algorithm>
#include <consensus/amount.h>
#include <policy/fees.h>
#include <script/solver.h>
#include <util/result.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <test/util/test_controls.h>
#include <test/util/txmempool.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(long_chain_error_uses_remaining_amount)
{
    LOCK2(cs_main, m_wallet.cs_wallet);
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(6 * COIN, CScript{} << OP_TRUE);
    TestMemPoolEntryHelper entry;
    unsigned int ancestors, descendants;
    m_wallet.chain().getPackageLimits(ancestors, descendants);
    for (unsigned int i = 0; i < ancestors; ++i) {
        AddToMempool(*m_node.mempool, entry.FromTx(tx));
        if (i + 1 < ancestors) tx.vin[0].prevout.hash = tx.GetHash();
    }
    CoinsResult coins;
    coins.Add(OutputType::BECH32, COutput{COutPoint{Txid::FromUint256(uint256::ZERO), 0}, CTxOut{4 * COIN, CScript{} << OP_TRUE}, 6, 100, true, true, 0, true, CAmount{0}});
    coins.Add(OutputType::BECH32, COutput{COutPoint{tx.GetHash(), 0}, tx.vout[0], 0, 100, true, true, 0, true, CAmount{0}});
    CoinSelectionParams params{m_rng};
    params.m_subtract_fee_outputs = true;
    const auto result = AutomaticCoinSelection(m_wallet, coins, 7 * COIN, params);
    BOOST_REQUIRE(!result);
    // Four confirmed coins plus six excluded coins can cover seven. Treating
    // the remaining amount as a boolean incorrectly reports generic failure.
    BOOST_CHECK_EQUAL(util::ErrorString(result).original, "Unconfirmed UTXOs are available, but spending them creates a chain of transactions that will be rejected by the mempool");

    // With APS enabled, the discarded positive group overlaps its mixed group.
    // Give the confirmed output another script so it remains independently usable.
    coins.coins.at(OutputType::BECH32).front().txout.scriptPubKey = CScript{} << OP_TRUE << OP_DROP << OP_TRUE;
    params.m_avoid_partial_spends = true;
    const auto affordable = AutomaticCoinSelection(m_wallet, coins, 3 * COIN, params);
    BOOST_REQUIRE(affordable);
    BOOST_CHECK_EQUAL(affordable->GetSelectedValue(), 4 * COIN);
    const auto too_long = AutomaticCoinSelection(m_wallet, coins, 7 * COIN, params);
    BOOST_REQUIRE(!too_long);
    BOOST_CHECK_EQUAL(util::ErrorString(too_long).original, util::ErrorString(result).original);
    const auto insufficient = AutomaticCoinSelection(m_wallet, coins, 11 * COIN, params);
    BOOST_CHECK(!insufficient);
}

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const int tip_height = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Height());
    const CAmount coinbase_subsidy = GetBlockSubsidy(tip_height, Params().GetConsensus());

    // Check that a subtract-from-recipient transaction near the input amount
    // deducts the fee from the recipient output (not the miner), regardless of
    // whether change is created.
    auto check_tx = [&wallet, coinbase_subsidy](CAmount leftover_input_amount) {
        CRecipient recipient{PubKeyDestination({}), coinbase_subsidy - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        // Use a high-cost change type to keep fee subtraction behavior stable across runs.
        coin_control.m_change_type = OutputType::LEGACY;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        const auto& txr = *res;
        const CScript recipient_script = GetScriptForDestination(recipient.dest);
        const auto it = std::find_if(txr.tx->vout.begin(), txr.tx->vout.end(), [&](const CTxOut& out) {
            return out.scriptPubKey == recipient_script;
        });
        BOOST_REQUIRE(it != txr.tx->vout.end());
        BOOST_CHECK_EQUAL(it->nValue, recipient.nAmount - txr.fee);
        BOOST_CHECK_GT(txr.fee, 0);
        return txr.fee;
    };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

    // Send full input minus fee amount to recipient, check leftover input
    // amount is paid to recipient not the miner (to_reduce == 0)
    BOOST_CHECK_EQUAL(fee, check_tx(fee));

    // Send full input minus more than the fee amount to recipient, check
    // leftover input amount is paid to recipient not the miner (to_reduce ==
    // -123). This overpays the recipient instead of overpaying the miner more
    // than double the necessary fee.
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable UTXO, each at the current subsidy, to the wallet.
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    const CAmount wallet_total = available_coins.GetTotalAmount();
    std::vector<COutput> coins = available_coins.All();
    // Preselect the first 3 UTXO (150 BTC total)
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs are covering for.
    // The wallet can cover up to its available total, and the tx target exceeds that amount.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::BECH32, "dummy")),
                                           /*nAmount=*/wallet_total + COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to send more than the wallet total. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send the wallet total.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs (in this case 99 BTC)
    // so that the recipient's amount is no longer equal to the user's selected target of 299 BTC.

    // First case, use 'subtract_fee_from_outputs=true'
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
