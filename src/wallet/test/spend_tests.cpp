// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <policy/fees.h>
#include <policy/truc_policy.h>
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

#include <algorithm>

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

BOOST_FIXTURE_TEST_CASE(transaction_preview_and_exact_input_weights, TestChain100Setup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    LOCK(wallet->cs_wallet);
    CCoinControl control;
    control.m_feerate = CFeeRate{1000};
    control.fOverrideFeeRate = true;
    control.destChange = WitnessV1ScriptHash512{};
    const std::vector<CRecipient> recipients{{WitnessV1ScriptHash512{}, COIN / 2, false}};
    for (const auto scheme : {pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_1024, pq::SchemeId::MLDSA_44, pq::SchemeId::MLDSA_65, pq::SchemeId::MLDSA_87}) {
        CKey key;
        key.MakeNewKey(scheme);
        const auto* info = pq::SchemeFromPrefix(static_cast<uint8_t>(scheme));
        BOOST_REQUIRE(info);
        auto* manager = CreateDescriptor(*wallet, "wpkh(" + EncodeSecret(key) + ")", true);
        BOOST_REQUIRE(manager);
        const CScript script = GetScriptForDestination(WitnessV0KeyHash{key.GetPubKey()});
        CMutableTransaction previous;
        previous.vin.emplace_back(Txid::FromUint256(uint256::ONE), static_cast<uint8_t>(scheme));
        previous.vout.emplace_back(COIN, script);
        const auto block = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(previous), TxStateConfirmed{block, 100, 0}));
        const COutPoint outpoint{previous.GetHash(), 0};
        control.UnSelectAll();
        control.Select(outpoint);

        // Serialize a maximum satisfaction independently of descriptor weight calculation.
        CMutableTransaction maximum;
        maximum.vin.emplace_back(outpoint);
        maximum.vin[0].scriptWitness.stack = {std::vector<unsigned char>(info->sig_bytes_sign_max + 1), ToByteVector(key.GetPubKey())};
        maximum.vout.emplace_back(COIN / 2, GetScriptForDestination(recipients[0].dest));
        maximum.vout.emplace_back(0, GetScriptForDestination(control.destChange));
        const int64_t expected_weight = GetTransactionWeight(CTransaction(maximum));
        const int64_t input_weight = GetTransactionInputWeight(maximum.vin[0]);
        const auto records_before = GetMockableDatabase(*wallet).m_records;
        const auto transactions_before = wallet->mapWallet.size();
        for (int repetition = 0; repetition < 2; ++repetition) {
            const auto preview = PreviewTransaction(*wallet, recipients, control);
            BOOST_REQUIRE_MESSAGE(preview, util::ErrorString(preview).original);
            BOOST_CHECK_EQUAL(preview->weight, expected_weight);
            BOOST_CHECK_EQUAL(preview->fee, (expected_weight + 3) / 4);
            BOOST_CHECK_EQUAL(preview->change, COIN / 2 - preview->fee);
            BOOST_CHECK(!preview->insufficient_funds);
            BOOST_CHECK(GetMockableDatabase(*wallet).m_records == records_before);
            BOOST_CHECK_EQUAL(wallet->mapWallet.size(), transactions_before);
            BOOST_CHECK(!wallet->IsLockedCoin(outpoint));
        }
        if (scheme == pq::SchemeId::FALCON_512) {
            control.destChange = CNoDestination{};
            control.m_change_type = OutputType::BECH32;
            BOOST_REQUIRE(wallet->GetChangeScriptForPreview(OutputType::BECH32, std::nullopt));
            BOOST_REQUIRE(PreviewTransaction(*wallet, recipients, control));
            BOOST_CHECK(GetMockableDatabase(*wallet).m_records == records_before);
            control.destChange = WitnessV1ScriptHash512{};
            control.m_change_type.reset();
        }
        for (int delta : {-3, -2, -1, 0, 1}) {
            control.SetInputWeight(outpoint, input_weight + delta);
            FastRandomContext rng;
            CoinSelectionParams params{rng};
            params.m_effective_feerate = CFeeRate{1000};
            const auto fetched = FetchSelectedInputs(*wallet, control, params);
            BOOST_CHECK_EQUAL(bool(fetched), delta >= 0);
        }
        control.SetInputWeight(outpoint, input_weight);
        auto incomplete = recipients;
        incomplete[0].dest = CNoDestination{};
        BOOST_CHECK(!PreviewTransaction(*wallet, incomplete, control));
        control.m_max_tx_weight = expected_weight - 1;
        BOOST_CHECK(!PreviewTransaction(*wallet, recipients, control));
        control.m_max_tx_weight = expected_weight;
        BOOST_CHECK(PreviewTransaction(*wallet, recipients, control));
        control.m_max_tx_weight.reset();
        auto subtract = recipients;
        subtract[0].nAmount = COIN;
        subtract[0].fSubtractFeeFromAmount = true;
        const auto no_change = PreviewTransaction(*wallet, subtract, control);
        BOOST_REQUIRE(no_change);
        BOOST_CHECK_EQUAL(no_change->change, 0);
        BOOST_CHECK_EQUAL(no_change->weight, expected_weight - 75 * 4);
    }
    BOOST_REQUIRE(wallet->EncryptWallet(SecureString{"preview test passphrase"}));
    BOOST_REQUIRE(wallet->IsLocked());
    control.destChange = CNoDestination{};
    control.m_change_type = OutputType::BECH32;
    const auto locked_records = GetMockableDatabase(*wallet).m_records;
    for (int repetition = 0; repetition < 2; ++repetition) {
        BOOST_REQUIRE(PreviewTransaction(*wallet, recipients, control));
        BOOST_CHECK(wallet->IsLocked());
        BOOST_CHECK(GetMockableDatabase(*wallet).m_records == locked_records);
    }
    control.m_change_scheme_override = 0xff;
    BOOST_CHECK(!PreviewTransaction(*wallet, recipients, control));
    BOOST_CHECK(GetMockableDatabase(*wallet).m_records == locked_records);
}

BOOST_FIXTURE_TEST_CASE(truc_final_weight_and_preview, TestChain100Setup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    LOCK(wallet->cs_wallet);
    CKey key;
    key.MakeNewKey(pq::SchemeId::MLDSA_44);
    BOOST_REQUIRE(CreateDescriptor(*wallet, "wpkh(" + EncodeSecret(key) + ")", true));
    CMutableTransaction parent;
    parent.version = TRUC_VERSION;
    parent.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
    for (int i = 0; i < 4; ++i) parent.vout.emplace_back(COIN, GetScriptForDestination(WitnessV0KeyHash{key.GetPubKey()}));
    BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(parent), TxStateInactive{}));
    CCoinControl control;
    control.m_version = TRUC_VERSION;
    control.m_feerate = CFeeRate{1000};
    control.fOverrideFeeRate = true;
    control.destChange = WitnessV1ScriptHash512{};
    const std::vector<CRecipient> recipients{{WitnessV1ScriptHash512{}, COIN, false}};
    for (int count : {3, 4}) {
        control.UnSelectAll();
        for (int i = 0; i < count; ++i) control.Select(COutPoint{parent.GetHash(), static_cast<uint32_t>(i)});
        const auto preview = PreviewTransaction(*wallet, recipients, control);
        BOOST_CHECK_EQUAL(bool(preview), count == 3);
        for (bool sign : {false, true}) {
            const auto created = CreateTransaction(*wallet, recipients, std::nullopt, control, sign);
            BOOST_REQUIRE_MESSAGE(bool(created) == (count == 3), util::ErrorString(created).original);
            if (!created) BOOST_CHECK_EQUAL(util::ErrorString(created).original, "Transaction too large");
        }
    }
    const auto block = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(parent), TxStateConfirmed{block, 100, 0}));
    const auto confirmed = PreviewTransaction(*wallet, recipients, control);
    BOOST_REQUIRE(confirmed);
    BOOST_CHECK_EQUAL(confirmed->weight, 16262);
    BOOST_REQUIRE(CreateTransaction(*wallet, recipients, std::nullopt, control, true));
}

BOOST_FIXTURE_TEST_CASE(transaction_preview_script_shapes, TestChain100Setup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    LOCK(wallet->cs_wallet);
    const auto block = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    unsigned int serial{0};
    for (const auto scheme : {pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_1024, pq::SchemeId::MLDSA_44, pq::SchemeId::MLDSA_65, pq::SchemeId::MLDSA_87}) {
        CKey key, second;
        key.MakeNewKey(scheme);
        second.MakeNewKey(scheme);
        const auto* info = Assert(pq::SchemeFromPrefix(static_cast<uint8_t>(scheme)));
        const std::vector<unsigned char> sig(info->sig_bytes_sign_max + 1);
        const auto pub = ToByteVector(key.GetPubKey());
        const std::string secret = EncodeSecret(key);
        struct Shape {
            std::string descriptor;
            CScript output;
            CTxIn input;
        };
        std::vector<Shape> shapes;
        CTxIn legacy;
        legacy.scriptSig = CScript{} << sig << pub;
        shapes.push_back({"pkh(" + secret + ")", GetScriptForDestination(PKHash{key.GetPubKey()}), legacy});
        CTxIn wpkh;
        wpkh.scriptWitness.stack = {sig, pub};
        const auto wpkh_script = GetScriptForDestination(WitnessV0KeyHash{key.GetPubKey()});
        shapes.push_back({"wpkh(" + secret + ")", wpkh_script, wpkh});
        wpkh.scriptSig = CScript{} << ToByteVector(wpkh_script);
        shapes.push_back({"sh(wpkh(" + secret + "))", GetScriptForDestination(ScriptHash{wpkh_script}), wpkh});
        const CScript pk_script = GetScriptForRawPubKey(key.GetPubKey());
        const CScript multi_script = GetScriptForMultisig(2, {key.GetPubKey(), second.GetPubKey()});
        const CScript miniscript = CScript{} << pub << OP_CHECKSIGVERIFY << OP_1 << OP_CHECKLOCKTIMEVERIFY;
        for (int kind = 0; kind < 4; ++kind) {
            const CScript script = kind == 0 ? pk_script : kind == 1 ? GetScriptForDestination(PKHash{key.GetPubKey()}) : kind == 2 ? multi_script : miniscript;
            const std::string inner = kind == 0 ? "pk(" + secret + ")" : kind == 1 ? "pkh(" + secret + ")" : kind == 2 ? "multi(2," + secret + "," + EncodeSecret(second) + ")" : "and_v(v:pk(" + secret + "),after(1))";
            for (int wrapper = 0; wrapper < 3; ++wrapper) {
                const bool v1 = wrapper == 2;
                const CScript program = v1 ? GetScriptForDestination(WitnessV1ScriptHash512{script}) : GetScriptForDestination(WitnessV0ScriptHash{script});
                CTxIn input;
                if (kind == 2) input.scriptWitness.stack = {{}, sig, sig};
                else if (kind == 1) input.scriptWitness.stack = {sig, pub};
                // Miniscript's existing estimator uses the conservative external
                // signature bound even for a locally held Falcon key.
                else input.scriptWitness.stack = {kind == 3 ? std::vector<unsigned char>(info->sig_bytes_max + 1) : sig};
                input.scriptWitness.stack.push_back(ToByteVector(script));
                if (wrapper == 1) input.scriptSig = CScript{} << ToByteVector(program);
                const std::string descriptor = (v1 ? "wsh512(" : "wsh(") + inner + ")";
                shapes.push_back({wrapper == 1 ? "sh(" + descriptor + ")" : descriptor,
                                  wrapper == 1 ? GetScriptForDestination(ScriptHash{program}) : program, input});
            }
        }
        CCoinControl control;
        control.m_feerate = CFeeRate{1000};
        control.fOverrideFeeRate = true;
        control.destChange = WitnessV1ScriptHash512{};
        const std::vector<CRecipient> recipients{{PKHash{key.GetPubKey()}, COIN / 4, false}, {WitnessV1ScriptHash512{}, COIN / 4, true}};
        CMutableTransaction mixed;
        for (const auto& shape : shapes) {
            BOOST_TEST_CONTEXT(shape.descriptor.substr(0, 20) << " scheme " << int(scheme)) {
                BOOST_REQUIRE(CreateDescriptor(*wallet, shape.descriptor, true));
                CMutableTransaction previous;
                previous.vin.emplace_back(Txid::FromUint256(uint256::ONE), serial++);
                previous.vout.emplace_back(COIN, shape.output);
                BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(previous), TxStateConfirmed{block, 100, 0}));
                CTxIn input{shape.input};
                input.prevout = COutPoint{previous.GetHash(), 0};
                control.UnSelectAll();
                control.Select(input.prevout);
                CMutableTransaction maximum;
                maximum.vin.push_back(input);
                for (const auto& recipient : recipients) maximum.vout.emplace_back(recipient.nAmount, GetScriptForDestination(recipient.dest));
                maximum.vout.emplace_back(0, GetScriptForDestination(control.destChange));
                const auto records = GetMockableDatabase(*wallet).m_records;
                const auto preview = PreviewTransaction(*wallet, recipients, control);
                BOOST_REQUIRE_MESSAGE(preview, util::ErrorString(preview).original);
                BOOST_CHECK_EQUAL(preview->weight, GetTransactionWeight(CTransaction(maximum)));
                BOOST_CHECK_EQUAL(preview->fee, (preview->weight + 3) / 4);
                BOOST_CHECK_EQUAL(preview->change, COIN / 2);
                BOOST_CHECK(GetMockableDatabase(*wallet).m_records == records);
                // The override convention always includes an empty witness count,
                // including when the complete transaction is legacy-only.
                const auto input_weight = GetTransactionInputWeight(input);
                FastRandomContext rng;
                CoinSelectionParams params{rng};
                for (const int delta : {-3, -2, -1, 0, 1}) {
                    control.SetInputWeight(input.prevout, input_weight + delta);
                    BOOST_CHECK_EQUAL(bool(FetchSelectedInputs(*wallet, control, params)), delta >= 0);
                }
                mixed.vin.push_back(input);
            }
        }
        // Mixed legacy, nested-v0, native-v0 and v1: empty legacy witnesses and
        // marker/flag are counted by serialization, once for the whole transaction.
        for (const auto& recipient : recipients) mixed.vout.emplace_back(recipient.nAmount, GetScriptForDestination(recipient.dest));
        mixed.vout.emplace_back(0, GetScriptForDestination(control.destChange));
        // Use a fresh control to avoid the deliberately conservative overrides above.
        CCoinControl mixed_control;
        mixed_control.m_feerate = CFeeRate{1000};
        mixed_control.fOverrideFeeRate = true;
        mixed_control.destChange = control.destChange;
        for (const auto& input : mixed.vin) mixed_control.Select(input.prevout);
        const auto preview = PreviewTransaction(*wallet, recipients, mixed_control);
        BOOST_REQUIRE(preview);
        BOOST_CHECK_EQUAL(preview->weight, GetTransactionWeight(CTransaction(mixed)));
    }
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

BOOST_FIXTURE_TEST_CASE(witness_v1_coin_classification, TestChain100Setup)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    LOCK(wallet->cs_wallet);
    FlatSigningProvider provider;
    CMutableTransaction tx;
    tx.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
    for (bool wrapped : {false, true}) {
        std::string error;
        std::string descriptor = "wsh512(pk(" + EncodeSecret(coinbaseKey) + "))";
        if (wrapped) descriptor = "sh(wpkh(" + EncodeSecret(coinbaseKey) + "))";
        auto parsed = Parse(descriptor, provider, error, false);
        BOOST_REQUIRE(!parsed.empty());
        std::vector<CScript> scripts;
        FlatSigningProvider expanded;
        BOOST_REQUIRE(parsed[0]->Expand(0, provider, scripts, expanded));
        WalletDescriptor desc(std::move(parsed[0]), 0, 0, 1, 1);
        BOOST_REQUIRE(wallet->AddWalletDescriptor(desc, provider, "", false));
        tx.vout.emplace_back(COIN, scripts[0]);
    }
    const auto block = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(tx), TxStateConfirmed{block, 100, 0}));
    const auto coins = AvailableCoins(*wallet);
    for (int index = 0; index < 2; ++index) {
        const auto type = index ? OutputType::P2SH_SEGWIT : OutputType::BECH32PQ;
        BOOST_REQUIRE(coins.coins.contains(type));
        const auto& group = coins.coins.at(type);
        BOOST_CHECK(std::any_of(group.begin(), group.end(), [&](const auto& coin) { return coin.outpoint == COutPoint(tx.GetHash(), index); }));
    }
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

BOOST_AUTO_TEST_CASE(recipient_total_rejects_sum_above_max_money)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    // Two individually valid maximum outputs exceed MAX_MONEY.
    // CreateTransaction must reject the total before adding the second amount.
    const CRecipient one{CNoDestination{}, MAX_MONEY, false};
    CCoinControl coin_control;
    const auto overflow = CreateTransaction(m_wallet, {one, one}, /*change_pos=*/std::nullopt, coin_control);
    BOOST_CHECK(!overflow);
    BOOST_CHECK(util::ErrorString(overflow).original.find("too large") != std::string::npos);

    // A single maximum output is representable. An empty wallet fails later
    // for lack of funds, not because the amount itself was rejected.
    const auto one_output = CreateTransaction(m_wallet, {one}, /*change_pos=*/std::nullopt, coin_control);
    BOOST_CHECK(!one_output);
    BOOST_CHECK(util::ErrorString(one_output).original.find("Insufficient funds") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
