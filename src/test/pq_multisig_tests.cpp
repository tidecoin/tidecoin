// Copyright (c) 2026 The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/validation.h>
#include <key.h>
#include <addresstype.h>
#include <policy/policy.h>
#include <policy/feerate.h>
#include <pq/pq_api.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>
#include <hash.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <optional>
#include <vector>

namespace {

struct KeyPair {
    CKey key;
    CPubKey pubkey;
};

std::array<uint8_t, 64> MakeMaterial(uint8_t tag)
{
    std::array<uint8_t, 64> out{};
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(tag ^ static_cast<uint8_t>(i * 131));
    }
    return out;
}

KeyPair MakeDeterministicKey(pq::SchemeId scheme_id, uint8_t tag)
{
    const pq::SchemeInfo* info = pq::SchemeFromId(scheme_id);
    BOOST_REQUIRE(info != nullptr);

    const auto material = MakeMaterial(tag);
    std::vector<uint8_t> pk_raw;
    pq::SecureKeyBytes sk_raw;
    BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1, scheme_id, material, pk_raw, sk_raw));

    std::vector<uint8_t> prefixed_pk(pk_raw.size() + 1);
    prefixed_pk[0] = info->prefix;
    std::copy(pk_raw.begin(), pk_raw.end(), prefixed_pk.begin() + 1);
    CPubKey pubkey{std::span<const uint8_t>(prefixed_pk)};

    CKey key;
    key.Set(sk_raw.begin(), sk_raw.end(), pubkey);
    BOOST_REQUIRE(key.IsValid());
    return {std::move(key), std::move(pubkey)};
}

std::vector<KeyPair> MakeKeys(const std::vector<pq::SchemeId>& schemes, uint8_t tag_base)
{
    std::vector<KeyPair> out;
    out.reserve(schemes.size());
    for (size_t i = 0; i < schemes.size(); ++i) {
        out.emplace_back(MakeDeterministicKey(schemes[i], static_cast<uint8_t>(tag_base + i)));
    }
    return out;
}

CScriptWitness SignMultisigWitness(const CScript& witness_script,
                                   const std::vector<CKey>& keys,
                                   const CTransaction& tx,
                                   const CAmount& amount)
{
    const uint256 sighash = SignatureHash(witness_script, tx, 0, SIGHASH_ALL, amount, SigVersion::WITNESS_V0);
    CScriptWitness witness;
    witness.stack.emplace_back(); // CHECKMULTISIG bug workaround
    for (const CKey& key : keys) {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(sighash, sig));
        sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
        witness.stack.emplace_back(std::move(sig));
    }
    witness.stack.emplace_back(witness_script.begin(), witness_script.end());
    return witness;
}

CScriptWitness BuildMultisigWitness(const CScript& witness_script,
                                    std::vector<std::vector<unsigned char>> sigs)
{
    CScriptWitness witness;
    witness.stack.emplace_back(); // CHECKMULTISIG bug workaround
    for (auto& sig : sigs) {
        witness.stack.emplace_back(std::move(sig));
    }
    witness.stack.emplace_back(witness_script.begin(), witness_script.end());
    return witness;
}

std::vector<unsigned char> MakeSignature(const CKey& key,
                                         const CScript& witness_script,
                                         const CTransaction& tx,
                                         const CAmount& amount,
                                         int sighash_type)
{
    const uint256 sighash = SignatureHash(witness_script, tx, 0, sighash_type, amount, SigVersion::WITNESS_V0);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(sighash_type));
    return sig;
}

std::vector<unsigned char> MakeLegacySignature(const CKey& key,
                                               const CScript& script_pubkey,
                                               const CTransaction& tx,
                                               int sighash_type)
{
    const uint256 sighash = SignatureHash(script_pubkey, tx, 0, sighash_type, /*amount=*/0, SigVersion::BASE);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(sighash_type));
    return sig;
}

std::array<unsigned char, 32> Sha256Commitment(const CPubKey& pubkey)
{
    std::array<unsigned char, 32> hash{};
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(hash.data());
    return hash;
}

CScript BuildCommittedHashScript(const std::vector<CPubKey>& pubs, int m)
{
    std::vector<std::array<unsigned char, 32>> hashes;
    hashes.reserve(pubs.size());
    for (const auto& pub : pubs) {
        hashes.push_back(Sha256Commitment(pub));
    }

    CScript script;
    for (int i = static_cast<int>(hashes.size()) - 1; i >= 0; --i) {
        script << OP_DUP << OP_SHA256 << std::vector<unsigned char>(hashes[i].begin(), hashes[i].end())
               << OP_EQUALVERIFY << OP_CHECKSIG;
        if (i != 0) {
            script << OP_TOALTSTACK;
        }
    }
    for (size_t i = 0; i + 1 < hashes.size(); ++i) {
        script << OP_FROMALTSTACK << OP_ADD;
    }
    script << m << OP_NUMEQUAL;
    return script;
}

CScriptWitness SignCommittedHashWitness(const CScript& witness_script,
                                        const std::vector<KeyPair>& keys,
                                        int sign_count,
                                        const CTransaction& tx,
                                        const CAmount& amount)
{
    const uint256 sighash = SignatureHash(witness_script, tx, 0, SIGHASH_ALL, amount, SigVersion::WITNESS_V0);
    CScriptWitness witness;
    for (size_t i = 0; i < keys.size(); ++i) {
        if (static_cast<int>(i) < sign_count) {
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(keys[i].key.Sign(sighash, sig));
            sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
            witness.stack.emplace_back(std::move(sig));
        } else {
            witness.stack.emplace_back();
        }
        witness.stack.emplace_back(keys[i].pubkey.begin(), keys[i].pubkey.end());
    }
    witness.stack.emplace_back(witness_script.begin(), witness_script.end());
    return witness;
}

void BuildTxs(CMutableTransaction& spending_tx,
              CCoinsViewCache& coins,
              CMutableTransaction& creation_tx,
              const CScript& script_pubkey,
              const CScript& script_sig,
              const CScriptWitness& witness)
{
    creation_tx = BuildCreditingTransaction(script_pubkey, /*nValue=*/1);
    const CTransaction credit_tx(creation_tx);
    spending_tx = BuildSpendingTransaction(script_sig, witness, credit_tx);
    AddCoins(coins, CTransaction(creation_tx), /*nHeight=*/0);
}

void RunMultisigCase(const std::vector<KeyPair>& keys,
                     int m,
                     int n,
                     bool p2sh_wrap,
                     unsigned int flags,
                     const CAmount& amount)
{
    std::vector<CPubKey> pubs;
    std::vector<CKey> sign_keys;
    pubs.reserve(n);
    sign_keys.reserve(m);
    for (int i = 0; i < n; ++i) {
        pubs.emplace_back(keys.at(i).pubkey);
        if (i < m) {
            sign_keys.emplace_back(keys.at(i).key);
        }
    }

    const CScript witness_script = GetScriptForMultisig(m, pubs);
    CScript script_pubkey;
    CScript script_sig;
    if (p2sh_wrap) {
        const CScript redeem_script = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
        script_pubkey = GetScriptForDestination(ScriptHash(redeem_script));
        script_sig = CScript() << ToByteVector(redeem_script);
    } else {
        script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
    }

    CMutableTransaction credit_tx;
    CMutableTransaction spend_tx;
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    BuildTxs(spend_tx, coins, credit_tx, script_pubkey, script_sig, CScriptWitness());
    CScriptWitness witness = SignMultisigWitness(witness_script, sign_keys, CTransaction(spend_tx), amount);
    spend_tx.vin[0].scriptWitness = witness;

    ScriptError err;
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    BOOST_CHECK(VerifyScript(script_sig, script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                             MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                             &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

void RunCommittedHashCase(const std::vector<KeyPair>& keys,
                          int m,
                          int n,
                          bool p2sh_wrap,
                          unsigned int flags,
                          const CAmount& amount)
{
    std::vector<CPubKey> pubs;
    pubs.reserve(n);
    for (int i = 0; i < n; ++i) {
        pubs.emplace_back(keys.at(i).pubkey);
    }

    const CScript witness_script = BuildCommittedHashScript(pubs, m);
    CScript script_pubkey;
    CScript script_sig;
    if (p2sh_wrap) {
        const CScript redeem_script = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
        script_pubkey = GetScriptForDestination(ScriptHash(redeem_script));
        script_sig = CScript() << ToByteVector(redeem_script);
    } else {
        script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
    }

    CMutableTransaction credit_tx;
    CMutableTransaction spend_tx;
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    BuildTxs(spend_tx, coins, credit_tx, script_pubkey, script_sig, CScriptWitness());
    CScriptWitness witness = SignCommittedHashWitness(witness_script, keys, m, CTransaction(spend_tx), amount);
    spend_tx.vin[0].scriptWitness = witness;

    ScriptError err;
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    BOOST_CHECK(VerifyScript(script_sig, script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                             MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                             &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_multisig_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_multisig_single_scheme_p2wsh_and_wrapped)
{
    const std::vector<pq::SchemeId> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_87,
    };

    const unsigned int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
    constexpr CAmount amount{1};
    const std::vector<std::pair<int, int>> cases{{1, 1}, {2, 3}, {3, 5}, {15, 15}, {20, 20}};

    for (pq::SchemeId scheme : schemes) {
        for (const auto& [m, n] : cases) {
            const auto keys = MakeKeys(std::vector<pq::SchemeId>(n, scheme), static_cast<uint8_t>(0x10 + n));
            RunMultisigCase(keys, m, n, /*p2sh_wrap=*/false, flags, amount);
            RunMultisigCase(keys, m, n, /*p2sh_wrap=*/true, flags, amount);
        }
    }
}

BOOST_AUTO_TEST_CASE(pq_multisig_mixed_scheme)
{
    const std::vector<pq::SchemeId> schemes3{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_87,
    };
    const std::vector<pq::SchemeId> schemes5{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_512,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::FALCON_1024,
    };
    std::vector<pq::SchemeId> schemes20;
    const std::vector<pq::SchemeId> base{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_87,
    };
    schemes20.reserve(20);
    while (schemes20.size() < 20) {
        for (pq::SchemeId id : base) {
            if (schemes20.size() >= 20) break;
            schemes20.push_back(id);
        }
    }
    const auto keys3 = MakeKeys(schemes3, /*tag_base=*/0x80);
    const auto keys5 = MakeKeys(schemes5, /*tag_base=*/0x90);
    const auto keys20 = MakeKeys(schemes20, /*tag_base=*/0xA0);

    std::vector<CPubKey> pubs;
    std::vector<CKey> sign_keys;
    for (size_t i = 0; i < keys3.size(); ++i) {
        pubs.emplace_back(keys3[i].pubkey);
        sign_keys.emplace_back(keys3[i].key);
    }
    const CScript witness_script = GetScriptForMultisig(/*nRequired=*/2, pubs);
    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));

    const unsigned int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    constexpr CAmount amount{1};

    CMutableTransaction credit_tx;
    CMutableTransaction spend_tx;
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);

    BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());
    CScriptWitness witness = SignMultisigWitness(witness_script, {sign_keys[0], sign_keys[1]}, CTransaction(spend_tx), amount);
    spend_tx.vin[0].scriptWitness = witness;

    ScriptError err;
    BOOST_CHECK(VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                             MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                             &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Invalid signature payload should fail.
    {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(sign_keys[0].Sign(SignatureHash(witness_script, spend_tx, 0, SIGHASH_ALL, amount, SigVersion::WITNESS_V0), sig));
        sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
        CScriptWitness bad_witness;
        bad_witness.stack.emplace_back(); // CHECKMULTISIG dummy
        bad_witness.stack.emplace_back(std::move(sig));
        bad_witness.stack.emplace_back(1, 0x01); // invalid signature blob
        bad_witness.stack.emplace_back(witness_script.begin(), witness_script.end());
        spend_tx.vin[0].scriptWitness = bad_witness;
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // Mixed-scheme P2WSH + P2SH-P2WSH happy paths.
    RunMultisigCase(keys3, /*m=*/2, /*n=*/3, /*p2sh_wrap=*/false, flags, amount);
    RunMultisigCase(keys3, /*m=*/2, /*n=*/3, /*p2sh_wrap=*/true, flags, amount);
    RunMultisigCase(keys5, /*m=*/3, /*n=*/5, /*p2sh_wrap=*/false, flags, amount);
    RunMultisigCase(keys5, /*m=*/3, /*n=*/5, /*p2sh_wrap=*/true, flags, amount);
    RunMultisigCase(keys20, /*m=*/20, /*n=*/20, /*p2sh_wrap=*/false, flags, amount);
    RunMultisigCase(keys20, /*m=*/20, /*n=*/20, /*p2sh_wrap=*/true, flags, amount);
}

BOOST_AUTO_TEST_CASE(pq_multisig_policy_limits)
{
    const auto keys = MakeKeys({pq::SchemeId::MLDSA_87, pq::SchemeId::MLDSA_87}, /*tag_base=*/0x40);
    std::vector<CPubKey> pubs{keys[0].pubkey, keys[1].pubkey};
    std::vector<CKey> sign_keys{keys[0].key};
    const CScript witness_script = GetScriptForMultisig(/*nRequired=*/1, pubs);

    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
    const unsigned int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    constexpr CAmount amount{1};

    CMutableTransaction credit_tx;
    CMutableTransaction spend_tx;
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);

    // Oversized stack item: policy reject, consensus ok (under MAX_SCRIPT_ELEMENT_SIZE)
    {
        BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());
        CScriptWitness witness = SignMultisigWitness(witness_script, sign_keys, CTransaction(spend_tx), amount);
        witness.stack[1].assign(MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1, 0x42);
        spend_tx.vin[0].scriptWitness = witness;
        BOOST_CHECK(!IsWitnessStandard(CTransaction(spend_tx), coins));
    }

    // Oversized stack item: consensus reject
    {
        BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());
        CScriptWitness witness = SignMultisigWitness(witness_script, sign_keys, CTransaction(spend_tx), amount);
        witness.stack[1].assign(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x42);
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
    }

    // Oversized witnessScript: consensus + policy reject
    {
        CScript big_script;
        std::vector<unsigned char> elem(MAX_SCRIPT_ELEMENT_SIZE, 1);
        for (int i = 0; i < 9; ++i) {
            big_script << elem;
        }
        const CScript big_spk = GetScriptForDestination(WitnessV0ScriptHash(big_script));
        CScriptWitness witness;
        witness.stack.emplace_back(big_script.begin(), big_script.end());
        BuildTxs(spend_tx, coins, credit_tx, big_spk, CScript(), CScriptWitness());
        spend_tx.vin[0].scriptWitness = witness;
        BOOST_CHECK(!IsWitnessStandard(CTransaction(spend_tx), coins));
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), big_spk, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SCRIPT_SIZE);
    }

    // Too many pubkeys: consensus reject with SCRIPT_ERR_PUBKEY_COUNT
    {
        const int n = MAX_PUBKEYS_PER_MULTISIG + 1;
        const int m = n;
        const auto too_many_keys = MakeKeys(std::vector<pq::SchemeId>(n, pq::SchemeId::FALCON_512), /*tag_base=*/0x60);
        std::vector<CPubKey> many_pubs;
        many_pubs.reserve(n);
        for (int i = 0; i < n; ++i) {
            many_pubs.emplace_back(too_many_keys.at(i).pubkey);
        }
        const CScript many_script = GetScriptForMultisig(m, many_pubs);
        const CScript many_spk = GetScriptForDestination(WitnessV0ScriptHash(many_script));
        CScriptWitness witness;
        witness.stack.emplace_back();
        for (int i = 0; i < m; ++i) {
            witness.stack.emplace_back(1, 0x00);
        }
        witness.stack.emplace_back(many_script.begin(), many_script.end());
        BuildTxs(spend_tx, coins, credit_tx, many_spk, CScript(), CScriptWitness());
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), many_spk, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEY_COUNT);
    }
}

BOOST_AUTO_TEST_CASE(pq_multisig_strict_mode)
{
    const unsigned int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_PQ_STRICT;
    constexpr CAmount amount{1};

    const auto keys = MakeKeys({pq::SchemeId::FALCON_512}, /*tag_base=*/0x11);
    RunMultisigCase(keys, /*m=*/1, /*n=*/1, /*p2sh_wrap=*/false, flags, amount);
    RunCommittedHashCase(keys, /*m=*/1, /*n=*/1, /*p2sh_wrap=*/false, flags, amount);
}

BOOST_AUTO_TEST_CASE(pq_multisig_negative_cases)
{
    const unsigned int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    constexpr CAmount amount{1};

    const auto keys = MakeKeys({pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_512}, 0x21);
    std::vector<CPubKey> pubs{keys[0].pubkey, keys[1].pubkey, keys[2].pubkey};
    const CScript witness_script = GetScriptForMultisig(/*nRequired=*/2, pubs);
    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));

    CMutableTransaction credit_tx;
    CMutableTransaction spend_tx;
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());

    // m-1 signatures should fail.
    {
        std::vector<std::vector<unsigned char>> sigs;
        sigs.emplace_back(MakeSignature(keys[0].key, witness_script, CTransaction(spend_tx), amount, SIGHASH_ALL));
        sigs.emplace_back(); // missing signature
        CScriptWitness witness = BuildMultisigWitness(witness_script, std::move(sigs));
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // Signatures out of pubkey order should fail.
    {
        auto sig1 = MakeSignature(keys[0].key, witness_script, CTransaction(spend_tx), amount, SIGHASH_ALL);
        auto sig2 = MakeSignature(keys[1].key, witness_script, CTransaction(spend_tx), amount, SIGHASH_ALL);
        std::vector<std::vector<unsigned char>> sigs;
        sigs.emplace_back(std::move(sig2));
        sigs.emplace_back(std::move(sig1));
        CScriptWitness witness = BuildMultisigWitness(witness_script, std::move(sigs));
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // Signature from non-participant key should fail.
    {
        const auto outsider = MakeDeterministicKey(pq::SchemeId::FALCON_512, 0x31);
        std::vector<std::vector<unsigned char>> sigs;
        sigs.emplace_back(MakeSignature(outsider.key, witness_script, CTransaction(spend_tx), amount, SIGHASH_ALL));
        sigs.emplace_back(MakeSignature(keys[1].key, witness_script, CTransaction(spend_tx), amount, SIGHASH_ALL));
        CScriptWitness witness = BuildMultisigWitness(witness_script, std::move(sigs));
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // Wrong sighash type should fail.
    {
        auto sig1 = MakeSignature(keys[0].key, witness_script, CTransaction(spend_tx), amount, SIGHASH_ALL);
        sig1.back() = static_cast<unsigned char>(SIGHASH_NONE);
        auto sig2 = MakeSignature(keys[1].key, witness_script, CTransaction(spend_tx), amount, SIGHASH_ALL);
        std::vector<std::vector<unsigned char>> sigs;
        sigs.emplace_back(std::move(sig1));
        sigs.emplace_back(std::move(sig2));
        CScriptWitness witness = BuildMultisigWitness(witness_script, std::move(sigs));
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // m > n should fail.
    {
        std::vector<CPubKey> one_pub{keys[0].pubkey};
        const CScript bad_script = GetScriptForMultisig(/*nRequired=*/2, one_pub);
        const CScript bad_spk = GetScriptForDestination(WitnessV0ScriptHash(bad_script));
        CScriptWitness witness;
        witness.stack.emplace_back();
        witness.stack.emplace_back();
        witness.stack.emplace_back(bad_script.begin(), bad_script.end());
        BuildTxs(spend_tx, coins, credit_tx, bad_spk, CScript(), CScriptWitness());
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), bad_spk, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // n=0 with m=1 should fail.
    {
        std::vector<CPubKey> none;
        const CScript bad_script = GetScriptForMultisig(/*nRequired=*/1, none);
        const CScript bad_spk = GetScriptForDestination(WitnessV0ScriptHash(bad_script));
        CScriptWitness witness;
        witness.stack.emplace_back();
        witness.stack.emplace_back(bad_script.begin(), bad_script.end());
        BuildTxs(spend_tx, coins, credit_tx, bad_spk, CScript(), CScriptWitness());
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(!VerifyScript(CScript(), bad_spk, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // m=0, n=0: document consensus behavior.
    {
        std::vector<CPubKey> none;
        const CScript zero_script = GetScriptForMultisig(/*nRequired=*/0, none);
        const CScript zero_spk = GetScriptForDestination(WitnessV0ScriptHash(zero_script));
        CScriptWitness witness;
        witness.stack.emplace_back();
        witness.stack.emplace_back(zero_script.begin(), zero_script.end());
        BuildTxs(spend_tx, coins, credit_tx, zero_spk, CScript(), CScriptWitness());
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        BOOST_CHECK(VerifyScript(CScript(), zero_spk, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(pq_multisig_committed_hash_single_scheme)
{
    const std::vector<pq::SchemeId> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_87,
    };
    const unsigned int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
    constexpr CAmount amount{1};
    const std::vector<std::pair<int, int>> cases{{1, 1}, {2, 3}, {3, 5}, {15, 15}, {20, 20}};

    for (pq::SchemeId scheme : schemes) {
        for (const auto& [m, n] : cases) {
            const auto keys = MakeKeys(std::vector<pq::SchemeId>(n, scheme), static_cast<uint8_t>(0xC0 + n));
            RunCommittedHashCase(keys, m, n, /*p2sh_wrap=*/false, flags, amount);
            RunCommittedHashCase(keys, m, n, /*p2sh_wrap=*/true, flags, amount);
        }
    }
}

BOOST_AUTO_TEST_CASE(pq_multisig_committed_hash_mixed_scheme)
{
    const std::vector<pq::SchemeId> schemes3{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_87,
    };
    const std::vector<pq::SchemeId> schemes5{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_512,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::FALCON_1024,
    };
    std::vector<pq::SchemeId> schemes20;
    const std::vector<pq::SchemeId> base{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_87,
    };
    schemes20.reserve(20);
    while (schemes20.size() < 20) {
        for (pq::SchemeId id : base) {
            if (schemes20.size() >= 20) break;
            schemes20.push_back(id);
        }
    }

    const unsigned int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
    constexpr CAmount amount{1};

    const auto keys3 = MakeKeys(schemes3, /*tag_base=*/0xD0);
    const auto keys5 = MakeKeys(schemes5, /*tag_base=*/0xE0);
    const auto keys20 = MakeKeys(schemes20, /*tag_base=*/0xF0);

    RunCommittedHashCase(keys3, /*m=*/2, /*n=*/3, /*p2sh_wrap=*/false, flags, amount);
    RunCommittedHashCase(keys3, /*m=*/2, /*n=*/3, /*p2sh_wrap=*/true, flags, amount);
    RunCommittedHashCase(keys5, /*m=*/3, /*n=*/5, /*p2sh_wrap=*/false, flags, amount);
    RunCommittedHashCase(keys5, /*m=*/3, /*n=*/5, /*p2sh_wrap=*/true, flags, amount);
    RunCommittedHashCase(keys20, /*m=*/20, /*n=*/20, /*p2sh_wrap=*/false, flags, amount);
    RunCommittedHashCase(keys20, /*m=*/20, /*n=*/20, /*p2sh_wrap=*/true, flags, amount);

    // pubkey hash mismatch should fail
    {
        std::vector<KeyPair> bad_keys = keys3;
        std::swap(bad_keys[0].pubkey, bad_keys[1].pubkey);
        const CScript witness_script = BuildCommittedHashScript(
            {keys3[0].pubkey, keys3[1].pubkey, keys3[2].pubkey}, /*m=*/2);
        const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
        CMutableTransaction credit_tx;
        CMutableTransaction spend_tx;
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());
        CScriptWitness witness = SignCommittedHashWitness(witness_script, bad_keys, /*sign_count=*/2, CTransaction(spend_tx), amount);
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // invalid signature blob should fail
    {
        const CScript witness_script = BuildCommittedHashScript(
            {keys3[0].pubkey, keys3[1].pubkey, keys3[2].pubkey}, /*m=*/2);
        const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
        CMutableTransaction credit_tx;
        CMutableTransaction spend_tx;
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());
        CScriptWitness witness = SignCommittedHashWitness(witness_script, keys3, /*sign_count=*/2, CTransaction(spend_tx), amount);
        if (!witness.stack.empty()) {
            witness.stack[0].assign(1, 0x01);
        }
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // threshold failure (m-1 signatures) should fail
    {
        const CScript witness_script = BuildCommittedHashScript(
            {keys3[0].pubkey, keys3[1].pubkey, keys3[2].pubkey}, /*m=*/2);
        const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
        CMutableTransaction credit_tx;
        CMutableTransaction spend_tx;
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());
        CScriptWitness witness = SignCommittedHashWitness(witness_script, keys3, /*sign_count=*/1, CTransaction(spend_tx), amount);
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }

    // swapped signatures (pubkeys fixed) should fail
    {
        const CScript witness_script = BuildCommittedHashScript(
            {keys3[0].pubkey, keys3[1].pubkey, keys3[2].pubkey}, /*m=*/2);
        const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
        CMutableTransaction credit_tx;
        CMutableTransaction spend_tx;
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());
        CScriptWitness witness = SignCommittedHashWitness(witness_script, keys3, /*sign_count=*/2, CTransaction(spend_tx), amount);
        if (witness.stack.size() >= 4) {
            std::swap(witness.stack[0], witness.stack[2]);
        }
        spend_tx.vin[0].scriptWitness = witness;
        ScriptError err;
        const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
        BOOST_CHECK(!VerifyScript(CScript(), script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                                  MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                                  &err));
    }
}

BOOST_AUTO_TEST_CASE(pq_multisig_weight_limits)
{
    constexpr CAmount amount{1};

    const int n = 20;
    const int m = 20;
    const auto keys = MakeKeys(std::vector<pq::SchemeId>(n, pq::SchemeId::MLDSA_87), /*tag_base=*/0x55);
    std::vector<CPubKey> pubs;
    std::vector<CKey> sign_keys;
    pubs.reserve(n);
    sign_keys.reserve(m);
    for (int i = 0; i < n; ++i) {
        pubs.emplace_back(keys.at(i).pubkey);
        sign_keys.emplace_back(keys.at(i).key);
    }

    const CScript witness_script = GetScriptForMultisig(m, pubs);
    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));

    CMutableTransaction credit_tx;
    CMutableTransaction spend_tx;
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());
    spend_tx.vout[0].scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(keys[0].pubkey));
    CScriptWitness witness = SignMultisigWitness(witness_script, sign_keys, CTransaction(spend_tx), amount);
    spend_tx.vin[0].scriptWitness = witness;

    const CTransaction tx(spend_tx);
    BOOST_CHECK(GetTransactionWeight(tx) <= MAX_STANDARD_TX_WEIGHT);

    std::string reason;
    BOOST_CHECK_MESSAGE(IsStandardTx(tx, std::make_optional(MAX_OP_RETURN_RELAY), DEFAULT_PERMIT_BAREMULTISIG,
                                     CFeeRate(DUST_RELAY_TX_FEE), reason),
                        "IsStandardTx failed: " << reason);
}

BOOST_AUTO_TEST_CASE(pq_multisig_bare_policy)
{
    const unsigned int flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    constexpr CAmount amount{1};

    const auto keys = MakeKeys({pq::SchemeId::FALCON_512, pq::SchemeId::FALCON_512}, 0x77);
    std::vector<CPubKey> pubs{keys[0].pubkey, keys[1].pubkey};
    const CScript script_pubkey = GetScriptForMultisig(/*nRequired=*/2, pubs);

    CMutableTransaction credit_tx;
    CMutableTransaction spend_tx;
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    BuildTxs(spend_tx, coins, credit_tx, script_pubkey, CScript(), CScriptWitness());

    std::vector<unsigned char> sig1 = MakeLegacySignature(keys[0].key, script_pubkey, CTransaction(spend_tx), SIGHASH_ALL);
    std::vector<unsigned char> sig2 = MakeLegacySignature(keys[1].key, script_pubkey, CTransaction(spend_tx), SIGHASH_ALL);
    CScript script_sig;
    script_sig << OP_0 << sig1 << sig2;
    spend_tx.vin[0].scriptSig = script_sig;

    ScriptError err;
    BOOST_CHECK(VerifyScript(script_sig, script_pubkey, &spend_tx.vin[0].scriptWitness, flags,
                             MutableTransactionSignatureChecker(&spend_tx, 0, amount, MissingDataBehavior::ASSERT_FAIL, allow_legacy),
                             &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    std::string reason;
    BOOST_CHECK_MESSAGE(!IsStandardTx(CTransaction(spend_tx), std::make_optional(MAX_OP_RETURN_RELAY),
                                      DEFAULT_PERMIT_BAREMULTISIG, CFeeRate(DUST_RELAY_TX_FEE), reason),
                        "Expected bare multisig to be non-standard");
    BOOST_CHECK(reason == "scriptpubkey" || reason == "bare-multisig");
}

BOOST_AUTO_TEST_SUITE_END()
