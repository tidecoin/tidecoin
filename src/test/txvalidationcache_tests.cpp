// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/validation.h>
#include <key.h>
#include <random.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/chaintype.h>
#include <validation.h>

#include <algorithm>

#include <boost/test/unit_test.hpp>

struct Dersig100Setup : public TestChain100Setup {
    Dersig100Setup()
        : TestChain100Setup{ChainType::REGTEST, {.extra_args = {"-testactivationheight=dersig@102"}}} {}
};

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

BOOST_AUTO_TEST_SUITE(txvalidationcache_tests)

BOOST_FIXTURE_TEST_CASE(pq_scheme_activation, BasicTestingSetup)
{
    CKey falcon;
    falcon.MakeNewKey(pq::SchemeId::FALCON_512);
    for (const auto* scheme : pq::kKnownSchemes) {
        BOOST_TEST_CONTEXT(scheme->name) {
            CKey key;
            key.MakeNewKey(scheme->id);
            const auto pubkey = ToByteVector(key.GetPubKey());
            const bool is_falcon{scheme->id == pq::SchemeId::FALCON_512};
            for (const auto version : {SigVersion::BASE, SigVersion::WITNESS_V0, SigVersion::WITNESS_V1_512}) {
                for (const auto opcode : {OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY}) {
                    const bool multisig{opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY};
                    const bool verify{opcode == OP_CHECKSIGVERIFY || opcode == OP_CHECKMULTISIGVERIFY};
                    for (bool inspect_false : {false, true}) {
                        if (verify && inspect_false) continue;
                        CScript script;
                        if (multisig) script << OP_1;
                        script << pubkey;
                        if (multisig) script << OP_1;
                        script << opcode;
                        if (verify) script << OP_TRUE;
                        if (inspect_false) script << OP_NOT;
                        CMutableTransaction mtx;
                        mtx.vin.resize(1);
                        mtx.vout.emplace_back(9'000, CScript{} << OP_TRUE);
                        constexpr CAmount amount{10'000};
                        PrecomputedTransactionData txdata;
                        txdata.Init(mtx, {CTxOut{amount, GetScriptForDestination(WitnessV1ScriptHash512{script})}}, true);
                        std::vector<unsigned char> sig;
                        if (version == SigVersion::WITNESS_V1_512) {
                            uint512 hash;
                            BOOST_REQUIRE(SignatureHash512(hash, script, mtx, 0, SIGHASH_ALL, amount, &txdata));
                            BOOST_REQUIRE(key.Sign512(hash, sig));
                        } else {
                            BOOST_REQUIRE(key.Sign(SignatureHash(script, mtx, 0, SIGHASH_ALL, amount, version), sig));
                        }
                        sig.push_back(SIGHASH_ALL);
                        const CTransaction tx{mtx};
                        SignatureCache cache{1 << 20};
                        // Populate caches after activation, then revisit the same
                        // signature before activation, including the 512-bit path.
                        for (bool active : {true, false, true}) {
                            const unsigned int flags{active ? SCRIPT_VERIFY_PQ_STRICT : SCRIPT_VERIFY_NONE};
                            CachingTransactionSignatureChecker checker{&tx, 0, amount, true, cache, txdata, !active};
                            std::vector<std::vector<unsigned char>> stack;
                            if (multisig) stack.emplace_back();
                            stack.push_back(sig);
                            ScriptError error;
                            const bool success{EvalScript(stack, script, flags, checker, version, &error)};
                            const bool eligible{active || is_falcon};
                            BOOST_CHECK_EQUAL(success, !verify || eligible);
                            if (success) {
                                BOOST_REQUIRE_EQUAL(stack.size(), 1U);
                                BOOST_CHECK_EQUAL(!stack.back().empty(), inspect_false ? !eligible : eligible);
                            }
                            if (!eligible) {
                                stack.clear();
                                if (multisig) stack.emplace_back();
                                stack.push_back(sig);
                                BOOST_CHECK(!EvalScript(stack, script, flags | SCRIPT_VERIFY_NULLFAIL, checker, version, &error));
                                BOOST_CHECK_EQUAL(error, SCRIPT_ERR_SIG_NULLFAIL);
                            }
                        }
                    }
                }
            }

            // An unavailable key is a failed match, so multisig may continue
            // to a later Falcon-512 key. CHECKMULTISIG examines the last key first.
            const CScript mixed = CScript{} << OP_1 << ToByteVector(falcon.GetPubKey()) << pubkey << OP_2 << OP_CHECKMULTISIG;
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.emplace_back(1, CScript{} << OP_TRUE);
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(falcon.Sign(SignatureHash(mixed, mtx, 0, SIGHASH_ALL, 0, SigVersion::BASE), sig));
            sig.push_back(SIGHASH_ALL);
            MutableTransactionSignatureChecker checker{&mtx, 0, 0, MissingDataBehavior::ASSERT_FAIL, true};
            ScriptError error;
            BOOST_CHECK(VerifyScript(CScript{} << OP_0 << sig, mixed, nullptr, SCRIPT_VERIFY_NONE, checker, &error));

            // Merely storing a key, or skipping its signature opcode, does not
            // require that scheme to be active.
            const CScript skipped = CScript{} << OP_0 << OP_IF << pubkey << OP_CHECKSIG << OP_ENDIF << OP_TRUE;
            BOOST_CHECK(VerifyScript(CScript{}, skipped, nullptr, SCRIPT_VERIFY_NONE, checker, &error));
            const CScript empty_sig = CScript{} << pubkey << OP_CHECKSIG << OP_NOT;
            BOOST_CHECK(VerifyScript(CScript{} << OP_0, empty_sig, nullptr, SCRIPT_VERIFY_NULLFAIL, checker, &error));
        }
    }
}

BOOST_FIXTURE_TEST_CASE(pq_scheme_activation_script_cache, BasicTestingSetup)
{
    for (const auto* scheme : pq::kKnownSchemes) {
        for (bool witness : {false, true}) {
            BOOST_TEST_CONTEXT(scheme->name << " witness=" << witness) {
                CKey key;
                key.MakeNewKey(scheme->id);
                const CScript script = CScript{} << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
                const CTxOut prevout{10'000, witness ? GetScriptForDestination(WitnessV0ScriptHash{script}) : script};
                CMutableTransaction mtx;
                mtx.vin.resize(1);
                mtx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256{1}), 0};
                mtx.vout.emplace_back(9'000, CScript{} << OP_TRUE);
                std::vector<unsigned char> sig;
                BOOST_REQUIRE(key.Sign(SignatureHash(script, mtx, 0, SIGHASH_ALL, prevout.nValue, witness ? SigVersion::WITNESS_V0 : SigVersion::BASE), sig));
                sig.push_back(SIGHASH_ALL);
                if (witness) {
                    mtx.vin[0].scriptWitness.stack = {sig, {script.begin(), script.end()}};
                } else {
                    mtx.vin[0].scriptSig << sig;
                }
                const CTransaction tx{mtx};
                CCoinsView dummy;
                CCoinsViewCache coins{&dummy};
                coins.AddCoin(tx.vin[0].prevout, Coin{prevout, 1, false}, false);
                ValidationCache cache{1 << 20, 1 << 20};
                PrecomputedTransactionData txdata;
                LOCK(cs_main);
                for (bool active : {false, true, true, false}) {
                    TxValidationState state;
                    const unsigned int flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | (active ? SCRIPT_VERIFY_PQ_STRICT : SCRIPT_VERIFY_NONE)};
                    const bool expected{active || scheme->id == pq::SchemeId::FALCON_512};
                    BOOST_CHECK_EQUAL(CheckInputScripts(tx, state, coins, flags, true, true, txdata, cache), expected);
                }
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(pq512_signature_cache, BasicTestingSetup)
{
    for (const auto* scheme : pq::kKnownSchemes) {
        BOOST_TEST_CONTEXT(scheme->name) {
            CKey key, other_key;
            key.MakeNewKey(scheme->id);
            other_key.MakeNewKey(scheme->id);
            const auto pubkey = key.GetPubKey();
            uint512 hash;
            hash.begin()[0] = 1;
            hash.begin()[63] = 2;
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(key.Sign512(hash, sig));
            SignatureCache cache{1 << 20};
            PrecomputedTransactionData txdata;
            CachingTransactionSignatureChecker store{nullptr, 0, 0, true, cache, txdata};
            CachingTransactionSignatureChecker no_store{nullptr, 0, 0, false, cache, txdata};
            uint256 entry;
            cache.ComputeEntryPQ512(entry, hash, sig, pubkey);
            BOOST_CHECK(!cache.Get(entry, false));
            BOOST_CHECK(no_store.VerifyPostQuantumSignature512(sig, pubkey, hash));
            BOOST_CHECK(!cache.Get(entry, false));
            BOOST_CHECK(store.VerifyPostQuantumSignature512(sig, pubkey, hash));
            BOOST_REQUIRE(cache.Get(entry, false));
            BOOST_CHECK(store.VerifyPostQuantumSignature512(sig, pubkey, hash));
            // A hit with store=false is usable and marked discardable, not
            // necessarily removed immediately by the cuckoo cache.
            BOOST_CHECK(no_store.VerifyPostQuantumSignature512(sig, pubkey, hash));

            // Every digest byte, including the entire second half, binds the entry.
            for (size_t i = 0; i < hash.size(); ++i) {
                auto changed = hash;
                changed.begin()[i] ^= 1;
                uint256 changed_entry;
                cache.ComputeEntryPQ512(changed_entry, changed, sig, pubkey);
                BOOST_CHECK(changed_entry != entry);
                BOOST_CHECK(!cache.Get(changed_entry, false));
            }
            auto changed = hash;
            changed.begin()[63] ^= 1;
            BOOST_CHECK(!store.VerifyPostQuantumSignature512(sig, pubkey, changed));
            uint256 changed_entry;
            cache.ComputeEntryPQ512(changed_entry, changed, sig, pubkey);
            BOOST_CHECK(!cache.Get(changed_entry, false));
            BOOST_CHECK(!store.VerifyPostQuantumSignature512(sig, other_key.GetPubKey(), hash));
            cache.ComputeEntryPQ512(changed_entry, hash, sig, other_key.GetPubKey());
            BOOST_CHECK(!cache.Get(changed_entry, false));

            auto invalid_sig = sig;
            invalid_sig[0] ^= 0x80;
            BOOST_CHECK(!store.VerifyPostQuantumSignature512(invalid_sig, pubkey, hash));
            BOOST_CHECK(!store.VerifyPostQuantumSignature512(invalid_sig, pubkey, hash));
            cache.ComputeEntryPQ512(changed_entry, hash, invalid_sig, pubkey);
            BOOST_CHECK(!cache.Get(changed_entry, false));

            uint256 hash256;
            std::copy_n(hash.begin(), hash256.size(), hash256.begin());
            for (bool legacy : {false, true}) {
                cache.ComputeEntryPQ(changed_entry, hash256, sig, pubkey, legacy);
                BOOST_CHECK(changed_entry != entry);
                BOOST_CHECK(!cache.Get(changed_entry, false));
                CachingTransactionSignatureChecker checker{nullptr, 0, 0, true, cache, txdata, legacy};
                BOOST_CHECK(!checker.VerifyPostQuantumSignature(sig, pubkey, hash256));
                BOOST_CHECK(checker.VerifyPostQuantumSignature512(sig, pubkey, hash));
                BOOST_CHECK(!checker.VerifyPostQuantumSignature512(invalid_sig, pubkey, hash));
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(pq512_script_cache_integration, BasicTestingSetup)
{
    for (const auto* scheme : pq::kKnownSchemes) {
        BOOST_TEST_CONTEXT(scheme->name) {
            CKey key;
            key.MakeNewKey(scheme->id);
            const auto pubkey = key.GetPubKey();
            const CScript script = CScript{} << ToByteVector(pubkey) << OP_CHECKSIG;
            const CTxOut prevout{10'000, GetScriptForDestination(WitnessV1ScriptHash512{script})};
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256{1}), 0};
            mtx.vout.emplace_back(9'000, CScript{} << OP_TRUE);
            PrecomputedTransactionData signing_data;
            signing_data.Init(mtx, {prevout}, true);
            uint512 hash;
            BOOST_REQUIRE(SignatureHash512(hash, script, mtx, 0, SIGHASH_ALL, prevout.nValue, &signing_data));
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(key.Sign512(hash, sig));
            auto script_sig = sig;
            script_sig.push_back(SIGHASH_ALL);
            mtx.vin[0].scriptWitness.stack = {script_sig, {script.begin(), script.end()}};
            const CTransaction tx{mtx};
            CCoinsView dummy;
            CCoinsViewCache coins{&dummy};
            coins.AddCoin(tx.vin[0].prevout, Coin{prevout, 1, false}, false);
            ValidationCache cache{1 << 20, 1 << 20};
            PrecomputedTransactionData txdata;
            TxValidationState state;
            constexpr unsigned int flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_WITNESS_V1_512 | SCRIPT_VERIFY_PQ_STRICT};
            LOCK(cs_main);
            // Like policy checks: populate signatures, not the whole-script cache.
            BOOST_REQUIRE(CheckInputScripts(tx, state, coins, flags | SCRIPT_VERIFY_CLEANSTACK, true, false, txdata, cache));
            uint256 entry;
            cache.m_signature_cache.ComputeEntryPQ512(entry, hash, sig, pubkey);
            BOOST_REQUIRE(cache.m_signature_cache.Get(entry, false));
            // Different flags still require script checks despite signature hits.
            std::vector<CScriptCheck> checks;
            BOOST_REQUIRE(CheckInputScripts(tx, state, coins, flags, true, true, txdata, cache, &checks));
            BOOST_REQUIRE_EQUAL(checks.size(), 1U);
            BOOST_CHECK(!checks.front()().has_value());
            BOOST_REQUIRE(CheckInputScripts(tx, state, coins, flags, true, true, txdata, cache));
            checks.clear();
            BOOST_REQUIRE(CheckInputScripts(tx, state, coins, flags, false, false, txdata, cache, &checks));
            BOOST_CHECK(checks.empty());
            // Mutated witnesses cannot borrow the complete-script cache entry.
            mtx.vin[0].scriptWitness.stack[0][0] ^= 0x80;
            PrecomputedTransactionData invalid_data;
            TxValidationState invalid_state;
            BOOST_CHECK(!CheckInputScripts(CTransaction{mtx}, invalid_state, coins, flags, true, true, invalid_data, cache));
        }
    }
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, Dersig100Setup)
{
    // Make sure skipping validation of transactions that were
    // validated going into the memory pool does not allow
    // double-spends in blocks to pass validation when they should not.

    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    const auto ToMemPool = [this](const CMutableTransaction& tx) {
        LOCK(cs_main);

        const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
        return result.m_result_type == MempoolAcceptResult::ResultType::VALID;
    };

    // Create a double-spend of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++)
    {
        spends[i].version = 1;
        spends[i].vin.resize(1);
        spends[i].vin[0].prevout.hash = m_coinbase_txns[0]->GetHash();
        spends[i].vin[0].prevout.n = 0;
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = 11*CENT;
        spends[i].vout[0].scriptPubKey = scriptPubKey;

        // Sign:
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(scriptPubKey, spends[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends[i].vin[0].scriptSig << vchSig;
    }

    CBlock block;

    // Test 1: block with both of those transactions should be rejected.
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{spends[0]}, MemPoolRemovalReason::CONFLICT));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{spends[1]}, MemPoolRemovalReason::CONFLICT));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);

    // Final sanity test: first spend in *m_node.mempool, second in block, that's OK:
    std::vector<CMutableTransaction> oneSpend;
    oneSpend.push_back(spends[0]);
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(oneSpend, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
    }
    // spends[1] should have been removed from the mempool when the
    // block with spends[0] is accepted:
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}

// Run CheckInputScripts (using CoinsTip()) on the given transaction, for all script
// flags.  Test that CheckInputScripts passes for all flags that don't overlap with
// the failing_flags argument, but otherwise fails.
// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY (and future NOP codes that may
// get reassigned) have an interaction with DISCOURAGE_UPGRADABLE_NOPS: if
// the script flags used contain DISCOURAGE_UPGRADABLE_NOPS but don't contain
// CHECKLOCKTIMEVERIFY (or CHECKSEQUENCEVERIFY), but the script does contain
// OP_CHECKLOCKTIMEVERIFY (or OP_CHECKSEQUENCEVERIFY), then script execution
// should fail.
// Capture this interaction with the upgraded_nop argument: set it when evaluating
// any script flag that is implemented as an upgraded NOP code.
static void ValidateCheckInputsForAllFlags(const CTransaction &tx, uint32_t failing_flags, bool add_to_cache, CCoinsViewCache& active_coins_tip, ValidationCache& validation_cache) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    PrecomputedTransactionData txdata;

    FastRandomContext insecure_rand(true);

    for (int count = 0; count < 10000; ++count) {
        TxValidationState state;

        // Randomly selects flag combinations
        uint32_t test_flags = (uint32_t) insecure_rand.randrange((SCRIPT_VERIFY_END_MARKER - 1) << 1);

        // Filter out incompatible flag choices
        if ((test_flags & SCRIPT_VERIFY_CLEANSTACK)) {
            // CLEANSTACK requires P2SH and WITNESS, see VerifyScript() in
            // script/interpreter.cpp
            test_flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        }
        if ((test_flags & SCRIPT_VERIFY_WITNESS)) {
            // WITNESS requires P2SH
            test_flags |= SCRIPT_VERIFY_P2SH;
        }
        bool ret = CheckInputScripts(tx, state, &active_coins_tip, test_flags, true, add_to_cache, txdata, validation_cache, nullptr);
        // CheckInputScripts should succeed iff test_flags doesn't intersect with
        // failing_flags
        bool expected_return_value = !(test_flags & failing_flags);
        BOOST_CHECK_EQUAL(ret, expected_return_value);

        // Test the caching
        if (ret && add_to_cache) {
            // Check that we get a cache hit if the tx was valid
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputScripts(tx, state, &active_coins_tip, test_flags, true, add_to_cache, txdata, validation_cache, &scriptchecks));
            BOOST_CHECK(scriptchecks.empty());
        } else {
            // Check that we get script executions to check, if the transaction
            // was invalid, or we didn't add to cache.
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputScripts(tx, state, &active_coins_tip, test_flags, true, add_to_cache, txdata, validation_cache, &scriptchecks));
            BOOST_CHECK_EQUAL(scriptchecks.size(), tx.vin.size());
        }
    }
}

BOOST_FIXTURE_TEST_CASE(checkinputs_test, Dersig100Setup)
{
    // Test that passing CheckInputScripts with one set of script flags doesn't imply
    // that we would pass again with a different set of flags.
    CScript p2pk_scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CScript p2sh_scriptPubKey = GetScriptForDestination(ScriptHash(p2pk_scriptPubKey));
    CScript p2pkh_scriptPubKey = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CScript p2wpkh_scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(coinbaseKey));
    BOOST_CHECK(keystore.AddCScript(p2pk_scriptPubKey));

    // flags to test: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCE_VERIFY, SCRIPT_VERIFY_NULLDUMMY

    // Create 2 outputs that match the three scripts above, spending the first
    // coinbase tx.
    CMutableTransaction spend_tx;

    spend_tx.version = 1;
    spend_tx.vin.resize(1);
    spend_tx.vin[0].prevout.hash = m_coinbase_txns[0]->GetHash();
    spend_tx.vin[0].prevout.n = 0;
    spend_tx.vout.resize(4);
    spend_tx.vout[0].nValue = 11*CENT;
    spend_tx.vout[0].scriptPubKey = p2sh_scriptPubKey;
    spend_tx.vout[1].nValue = 11*CENT;
    spend_tx.vout[1].scriptPubKey = p2wpkh_scriptPubKey;
    spend_tx.vout[2].nValue = 11*CENT;
    spend_tx.vout[2].scriptPubKey = CScript() << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    spend_tx.vout[3].nValue = 11*CENT;
    spend_tx.vout[3].scriptPubKey = CScript() << OP_CHECKSEQUENCEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Sign.
    {
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(p2pk_scriptPubKey, spend_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spend_tx.vin[0].scriptSig << vchSig;
    }

    // This transaction should be valid under all script flag combinations. Don't add these checks
    // to the cache, so we can test that block validation works fine in the absence of cached
    // successes.
    {
        LOCK(cs_main);
        ValidateCheckInputsForAllFlags(CTransaction(spend_tx), 0 | 0 | 0, false, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    // And if we produce a block with this tx, it should be valid even though there's no cache entry.
    CBlock block;

    block = CreateAndProcessBlock({spend_tx}, p2pk_scriptPubKey);
    LOCK(cs_main);
    BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK(m_node.chainman->ActiveChainstate().CoinsTip().GetBestBlock() == block.GetHash());

    // Test P2SH: construct a transaction that is valid without P2SH, and
    // then test validity with P2SH.
    {
        CMutableTransaction invalid_under_p2sh_tx;
        invalid_under_p2sh_tx.version = 1;
        invalid_under_p2sh_tx.vin.resize(1);
        invalid_under_p2sh_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_under_p2sh_tx.vin[0].prevout.n = 0;
        invalid_under_p2sh_tx.vout.resize(1);
        invalid_under_p2sh_tx.vout[0].nValue = 11*CENT;
        invalid_under_p2sh_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;
        std::vector<unsigned char> vchSig2(p2pk_scriptPubKey.begin(), p2pk_scriptPubKey.end());
        invalid_under_p2sh_tx.vin[0].scriptSig << vchSig2;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_under_p2sh_tx), SCRIPT_VERIFY_P2SH, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    // Test CHECKLOCKTIMEVERIFY
    {
        CMutableTransaction invalid_with_cltv_tx;
        invalid_with_cltv_tx.version = 1;
        invalid_with_cltv_tx.nLockTime = 100;
        invalid_with_cltv_tx.vin.resize(1);
        invalid_with_cltv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_cltv_tx.vin[0].prevout.n = 2;
        invalid_with_cltv_tx.vin[0].nSequence = 0;
        invalid_with_cltv_tx.vout.resize(1);
        invalid_with_cltv_tx.vout[0].nValue = 11*CENT;
        invalid_with_cltv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[2].scriptPubKey, invalid_with_cltv_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_with_cltv_tx), SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Make it valid, and check again
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(CTransaction(invalid_with_cltv_tx), state, m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, true, txdata, m_node.chainman->m_validation_cache, nullptr));
    }

    // TEST CHECKSEQUENCEVERIFY
    {
        CMutableTransaction invalid_with_csv_tx;
        invalid_with_csv_tx.version = 2;
        invalid_with_csv_tx.vin.resize(1);
        invalid_with_csv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_csv_tx.vin[0].prevout.n = 3;
        invalid_with_csv_tx.vin[0].nSequence = 100;
        invalid_with_csv_tx.vout.resize(1);
        invalid_with_csv_tx.vout[0].nValue = 11*CENT;
        invalid_with_csv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[3].scriptPubKey, invalid_with_csv_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_with_csv_tx), SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Make it valid, and check again
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(CTransaction(invalid_with_csv_tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, true, txdata, m_node.chainman->m_validation_cache, nullptr));
    }

    // TODO: add tests for remaining script flags

    // Test that passing CheckInputScripts with a valid witness doesn't imply success
    // for the same tx with a different witness.
    {
        CMutableTransaction valid_with_witness_tx;
        valid_with_witness_tx.version = 1;
        valid_with_witness_tx.vin.resize(1);
        valid_with_witness_tx.vin[0].prevout.hash = spend_tx.GetHash();
        valid_with_witness_tx.vin[0].prevout.n = 1;
        valid_with_witness_tx.vout.resize(1);
        valid_with_witness_tx.vout[0].nValue = 11*CENT;
        valid_with_witness_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        SignatureData sigdata;
        BOOST_CHECK(ProduceSignature(keystore, MutableTransactionSignatureCreator(valid_with_witness_tx, 0, 11 * CENT, SIGHASH_ALL), spend_tx.vout[1].scriptPubKey, sigdata));
        UpdateInput(valid_with_witness_tx.vin[0], sigdata);

        // This should be valid under all script flags.
        ValidateCheckInputsForAllFlags(CTransaction(valid_with_witness_tx), 0, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Remove the witness, and check that it is now invalid.
        valid_with_witness_tx.vin[0].scriptWitness.SetNull();
        ValidateCheckInputsForAllFlags(CTransaction(valid_with_witness_tx), SCRIPT_VERIFY_WITNESS, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    {
        // Test a transaction with multiple inputs.
        CMutableTransaction tx;

        tx.version = 1;
        tx.vin.resize(2);
        tx.vin[0].prevout.hash = spend_tx.GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[1].prevout.hash = spend_tx.GetHash();
        tx.vin[1].prevout.n = 1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 22*CENT;
        tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        for (int i = 0; i < 2; ++i) {
            SignatureData sigdata;
            BOOST_CHECK(ProduceSignature(keystore, MutableTransactionSignatureCreator(tx, i, 11 * CENT, SIGHASH_ALL), spend_tx.vout[i].scriptPubKey, sigdata));
            UpdateInput(tx.vin[i], sigdata);
        }

        // This should be valid under all script flags
        ValidateCheckInputsForAllFlags(CTransaction(tx), 0, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Check that if the second input is invalid, but the first input is
        // valid, the transaction is not cached.
        // Invalidate vin[1]
        tx.vin[1].scriptWitness.SetNull();

        TxValidationState state;
        PrecomputedTransactionData txdata;
        // This transaction is now invalid under segwit, because of the second input.
        BOOST_CHECK(!CheckInputScripts(CTransaction(tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata, m_node.chainman->m_validation_cache, nullptr));

        std::vector<CScriptCheck> scriptchecks;
        // Make sure this transaction was not cached (ie because the first
        // input was valid)
        BOOST_CHECK(CheckInputScripts(CTransaction(tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata, m_node.chainman->m_validation_cache, &scriptchecks));
        // Should get 2 script checks back -- caching is on a whole-transaction basis.
        BOOST_CHECK_EQUAL(scriptchecks.size(), 2U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
