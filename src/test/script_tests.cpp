// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/script_tests_pq.json.h>

#include <common/system.h>
#include <core_io.h>
#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <crypto/sha512.h>
#include <hash.h>
#include <key.h>
#include <policy/policy.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <uint512.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

extern "C" {
#include <pq/falcon-512/api.h>
#include <pq/falcon-512/inner.h>
}

// Uncomment if you want to output updated JSON tests.
// #define UPDATE_JSON_TESTS

using namespace util::hex_literals;

static const unsigned int gFlags = SCRIPT_VERIFY_P2SH;
static const bool gAllowLegacy = !(gFlags & SCRIPT_VERIFY_PQ_STRICT);

unsigned int ParseScriptFlags(std::string strFlags);
std::string FormatScriptFlags(unsigned int flags);

struct ScriptErrorDesc
{
    ScriptError_t err;
    const char *name;
};

static ScriptErrorDesc script_errors[]={
    {SCRIPT_ERR_OK, "OK"},
    {SCRIPT_ERR_UNKNOWN_ERROR, "UNKNOWN_ERROR"},
    {SCRIPT_ERR_EVAL_FALSE, "EVAL_FALSE"},
    {SCRIPT_ERR_OP_RETURN, "OP_RETURN"},
    {SCRIPT_ERR_SCRIPT_SIZE, "SCRIPT_SIZE"},
    {SCRIPT_ERR_PUSH_SIZE, "PUSH_SIZE"},
    {SCRIPT_ERR_OP_COUNT, "OP_COUNT"},
    {SCRIPT_ERR_STACK_SIZE, "STACK_SIZE"},
    {SCRIPT_ERR_SIG_COUNT, "SIG_COUNT"},
    {SCRIPT_ERR_PUBKEY_COUNT, "PUBKEY_COUNT"},
    {SCRIPT_ERR_VERIFY, "VERIFY"},
    {SCRIPT_ERR_EQUALVERIFY, "EQUALVERIFY"},
    {SCRIPT_ERR_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY"},
    {SCRIPT_ERR_CHECKSIGVERIFY, "CHECKSIGVERIFY"},
    {SCRIPT_ERR_NUMEQUALVERIFY, "NUMEQUALVERIFY"},
    {SCRIPT_ERR_BAD_OPCODE, "BAD_OPCODE"},
    {SCRIPT_ERR_DISABLED_OPCODE, "DISABLED_OPCODE"},
    {SCRIPT_ERR_INVALID_STACK_OPERATION, "INVALID_STACK_OPERATION"},
    {SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "INVALID_ALTSTACK_OPERATION"},
    {SCRIPT_ERR_UNBALANCED_CONDITIONAL, "UNBALANCED_CONDITIONAL"},
    {SCRIPT_ERR_NEGATIVE_LOCKTIME, "NEGATIVE_LOCKTIME"},
    {SCRIPT_ERR_UNSATISFIED_LOCKTIME, "UNSATISFIED_LOCKTIME"},
    {SCRIPT_ERR_SIG_HASHTYPE, "SIG_HASHTYPE"},
    {SCRIPT_ERR_MINIMALDATA, "MINIMALDATA"},
    {SCRIPT_ERR_SIG_PUSHONLY, "SIG_PUSHONLY"},
    {SCRIPT_ERR_SIG_HIGH_S, "SIG_HIGH_S"},
    {SCRIPT_ERR_SIG_NULLDUMMY, "SIG_NULLDUMMY"},
    {SCRIPT_ERR_PUBKEYTYPE, "PUBKEYTYPE"},
    {SCRIPT_ERR_CLEANSTACK, "CLEANSTACK"},
    {SCRIPT_ERR_MINIMALIF, "MINIMALIF"},
    {SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "DISCOURAGE_UPGRADABLE_NOPS"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH, "WITNESS_PROGRAM_WRONG_LENGTH"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, "WITNESS_PROGRAM_WITNESS_EMPTY"},
    {SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "WITNESS_PROGRAM_MISMATCH"},
    {SCRIPT_ERR_WITNESS_MALLEATED, "WITNESS_MALLEATED"},
    {SCRIPT_ERR_WITNESS_MALLEATED_P2SH, "WITNESS_MALLEATED_P2SH"},
    {SCRIPT_ERR_WITNESS_UNEXPECTED, "WITNESS_UNEXPECTED"},
    {SCRIPT_ERR_OP_CODESEPARATOR, "OP_CODESEPARATOR"},
    {SCRIPT_ERR_SIG_FINDANDDELETE, "SIG_FINDANDDELETE"},
};

static std::string FormatScriptError(ScriptError_t err)
{
    for (const auto& se : script_errors)
        if (se.err == err)
            return se.name;
    BOOST_ERROR("Unknown scripterror enumeration value, update script_errors in script_tests.cpp.");
    return "";
}

static ScriptError_t ParseScriptError(const std::string& name)
{
    for (const auto& se : script_errors)
        if (se.name == name)
            return se.err;
    BOOST_ERROR("Unknown scripterror \"" << name << "\" in test description");
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

struct ScriptTest : BasicTestingSetup {
void DoTest(const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& scriptWitness, uint32_t flags, const std::string& message, int scriptError, CAmount nValue = 0)
{
    bool expect = (scriptError == SCRIPT_ERR_OK);
    if (flags & SCRIPT_VERIFY_CLEANSTACK) {
        flags |= SCRIPT_VERIFY_P2SH;
        flags |= SCRIPT_VERIFY_WITNESS;
    }
    ScriptError err;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, nValue)};
    CMutableTransaction tx = BuildSpendingTransaction(scriptSig, scriptWitness, txCredit);
    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    MutableTransactionSignatureChecker checker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, allow_legacy);
    BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, flags, checker, &err) == expect, message);
    BOOST_CHECK_MESSAGE(err == scriptError, FormatScriptError(err) + " where " + FormatScriptError((ScriptError_t)scriptError) + " expected: " + message);

    // Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
    for (int i = 0; i < 16; ++i) {
        uint32_t extra_flags(m_rng.randbits(16));
        uint32_t combined_flags{expect ? (flags & ~extra_flags) : (flags | extra_flags)};
        // Activation-style flags can intentionally change script semantics.
        // Keep them fixed in monotonicity fuzz checks.
        if ((combined_flags ^ flags) & (SCRIPT_VERIFY_SHA512 | SCRIPT_VERIFY_WITNESS_V1_512)) continue;
        // Weed out some invalid flag combinations.
        if (combined_flags & SCRIPT_VERIFY_CLEANSTACK && ~combined_flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) continue;
        if (combined_flags & SCRIPT_VERIFY_WITNESS && ~combined_flags & SCRIPT_VERIFY_P2SH) continue;
        const bool combined_allow_legacy = !(combined_flags & SCRIPT_VERIFY_PQ_STRICT);
        MutableTransactionSignatureChecker combined_checker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, combined_allow_legacy);
        BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, combined_flags, combined_checker, &err) == expect, message + strprintf(" (with flags %x)", combined_flags));
    }
}
}; // struct ScriptTest

namespace
{
static constexpr std::string_view SCRIPT_BUILD_KEY0_SECRET_HEX{
    "0759ec40f9fc1f7efb92b7f82e821feefcef7ffd03c13f14313bff9e47fc1e80eff03d0c52800fcebf0be105ffffc0f00e4303dffb0ca1be044fb9fff043fc1fff0fef8600013cffffba177f44fbe00307efc103ff83041f04f41040042fbc03e042107f811c2fbefc2f080830fdf02e7a00007b001002080f83efcfbe143f41efc201fc1f42fc717b001f7a03ce3e0bd13df3f0baf8a141f442c8038f7bf3c049f3f0beffe080e44ffbf010bbfc4f42003002ebdffb07b13e045fbd04018613febb04cf7ffb9ec1080f850450010430012020bc044e87e41f84e85080fc6087040f81101e00ebdf06ffcec41c21440c2f040c6fbd0bf03bf82103141ffffbe0c1088f832840c6fc2f7d13d0c10c308417efc210117febf03ff7afc5ec3fc31c1f7f2401411020bc307f7dfc00bc104fc2f0103cfffec7180001086f3ff4507f03debe047f80140ebf07cefd0fd245f43081ec107d08113f105046047fc0f430be0071bbe3c0c1dbfefb1bdfb6f7d102f82fff0c21c1085e79f84000045f79f860bef43f44182f84f81f7ef0407b000ec1f3ff81f3ef7d045100003f03fbc186f40f3fdff0c4045082fc2fc017e1450c8f01eba0fb0be03c046fbc07f144f86f82f3ef7f079f3d20d146ffdf83ec0201143f3f1451bffc4f85141f4203f07b0861bf03cf78e80fff0bb082fc5f43208fc3e00183142efff45fb40bef4008017cf471c30bd04500203dfbefc70051bc03e0811411faf7cf81ffdec50fd0420c00fae01ffe0c5e82e4113f03b1bde01efd03efc0108f00002fbfffefc0f41ffff43fbdf81f04dc3f0110327f0c10010fe0c2f41dc1f80e80ec2f40ffbe7ce80088138fc6fc2e02ffe0c80bae81fbd03ce402ff009f49fc5e7f1fdfc2e42f7de02103f3d0010c01441c3f020c4004ef80befc117ff01f3d0c0ffe245ec2fba07be7bffbffefbe0fd0451bf04313c006fbef85f01f810c3079f7f0fb0440be0c0f83f01004143fbeefdffcfc1042efafbe13e002048043008ec213ef7d185044fc1f010ffe471c2fc2083fff0fd0801030bd17ff80082104175ffc000fc6ffe1061bbe7a250917030420e9cffadd0400f9e6daf51e31d8ecfede03f0fd0d05f609e80cfc01f4e61c1812fd0111f4f40501fdf8cdf8e126f625f9ee001408fbff1bfbff3b0d20e72de4df16fefc1130e91fd7d219eb0adcd6fccff716f00beef0f9ef1d10220ff51b1c23d6daf51be8d51cc1f8e803f72b03ede7dc28ed07f9f2f935db13030824ddd2f6e1e3fd010e3805e70ee10b14e1f3ee04e9f40355fcef03e500ede5140900f1fbfecd33dd3602e9f5f7e5d70ce303cdcdebf0f314d0d9f6060e0bceee07d01f08fe0205da0fe41a0fe31cd008e90106ffe0ea04ffe6fae5f107da1ff9d615eafd1fcbc30deec7f1f70afbf6110511e3fbd332ece1e2c2f302f0d80a01f3dfd80afe21e30b0c072d01f22df2ffe71813dfeff51814efe3e2f010fe37e8fbd3cd281aeefcebeef6c81a20f1ea3afe051acdea11ef1c240e1109d60ae8cff6c9f90701e8e8080917041a12f5f90f13090ddc3907022219c0f6e8ed4ef1fbec081b3af80700d4f5e8d5e9e00aef17f2ffed0434feff15f412e4eafdecf3f6041fefeffb130500ebdff5e926e4032b01d3dc031dd40b1e0713ddfd161a21492ee91eeadc1cfb13dff0e8f2eaf0ebf3e7e1ef06f118eef528f4ea18013becfff20afbf01c0e1e101707fefcc5fcbfcde90af3f5e9fe1b10040ed41bf2121207f4f7140f070af4e10700f4f5f01503fccc1d01041e020f20f9e2bef71eed"};

static constexpr std::string_view LEGACY_ONLY_STRICT_DIFF_SIG_HEX{
    "390d01e92ed24a254e9b7536a54b3567105edbcaa3b0de653bf5253a246631aa574d951b71021cbfcaf6e174231d8e2600d8413bf98606708d75b976a663d3073796fc6418c12d122c5b176c7cac5ad6133d505c50fc9c0520788e451176e6ace826fa084bde083505b6a72893628b3cb9b833654fb3f378516dcc2c70784828e19009146d5fc3221fa701d3f4ec1f83f3efd6a0f6cac5dd1d7a635236d742af54dd8bfb44555c3b3be3d410bb6ad7698139888358852084dda5d499f8aed9bdcddbd39b8df8e62ed72ac1639f5b1355f6bc485be393b88f4aa002650739f92c1ec3bcddd567678cdf885a59859b46f4cfbd6a6f0c23397a163243f8f94b36d7730f089cd2a9fe6d8cb73b1c2dd9a29fea84747a74554f5ccea21d4a8e124f9741e43f9a166fee8ce5c5fa69692e890e55157bd0da7e1d68a5ef97098b449b608eabfc581f062d5a1144f58b9629527ec11a4c921c41ddbb4036923e7efc7c58e18b81a3440d8976f5750dbdb2d9f4ce756719137731a428ec01864d5883306c350e4e617e2fa93388f3ca65e4c887aa274e58261cab68f2a278952a078a62b67e25bb3348631190c3542bc21cd8b273b3c1d543afb1dc32b8d20d5f2623b87a9ddae73a1ecfee73c99b3d2b605f57e65c5f6912b699a65059bfbf515f97a53bcb4c094f507cd2426535c830eaf310824ac93d47d10c28eefca68234d398ee3f6069640f543eedb6266a61a7e227738982e1fccc909a7e1aced453fd5e141ce74a3a0e22e143da3eb1c2adec836dd99cc354d8565a4a5bb741dd570eba9efba4c32680b3f6c58ef44d5f15949e47693a22488a8a84ec88903b34c2c47a574c2e79b16730893ad3e5c3a30fc30e3868e1b06b4c35af88a14949cd6b79188de3d6838c968c6a452044623b3ba62ebd19fec6311001"};

enum class WitnessMode {
    NONE,
    PKH,
    SH
};

class TestBuilder
{
private:
    //! Actually executed script
    CScript script;
    //! The P2SH redeemscript
    CScript redeemscript;
    //! The Witness embedded script
    CScript witscript;
    CScriptWitness scriptWitness;
    CTransactionRef creditTx;
    CMutableTransaction spendTx;
    bool havePush{false};
    std::vector<unsigned char> push;
    std::string comment;
    uint32_t flags;
    int scriptError{SCRIPT_ERR_OK};
    CAmount nValue;

    void DoPush()
    {
        if (havePush) {
            spendTx.vin[0].scriptSig << push;
            havePush = false;
        }
    }

    void DoPush(const std::vector<unsigned char>& data)
    {
        DoPush();
        push = data;
        havePush = true;
    }

public:
    TestBuilder(const CScript& script_, const std::string& comment_, uint32_t flags_, bool P2SH = false, WitnessMode wm = WitnessMode::NONE, int witnessversion = 0, CAmount nValue_ = 0) : script(script_), comment(comment_), flags(flags_), nValue(nValue_)
    {
        CScript scriptPubKey = script;
        if (wm == WitnessMode::PKH) {
            std::vector<unsigned char> pubkey_bytes;
            opcodetype opcode{};
            CScript::const_iterator pc = script.begin();
            BOOST_REQUIRE_MESSAGE(script.GetOp(pc, opcode, pubkey_bytes) && pc == script.end() && opcode <= OP_PUSHDATA4,
                                  "WitnessMode::PKH requires a single pushed pubkey script");
            uint160 hash;
            CHash160().Write(pubkey_bytes).Finalize(hash);
            script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(hash) << OP_EQUALVERIFY << OP_CHECKSIG;
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        } else if (wm == WitnessMode::SH) {
            witscript = scriptPubKey;
            if (witnessversion == 1) {
                uint512 hash;
                CSHA512().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
                scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
            } else {
                uint256 hash;
                CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
                scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
            }
        }
        if (P2SH) {
            redeemscript = scriptPubKey;
            scriptPubKey = CScript() << OP_HASH160 << ToByteVector(CScriptID(redeemscript)) << OP_EQUAL;
        }
        creditTx = MakeTransactionRef(BuildCreditingTransaction(scriptPubKey, nValue));
        spendTx = BuildSpendingTransaction(CScript(), CScriptWitness(), *creditTx);
    }

    TestBuilder& ScriptError(ScriptError_t err)
    {
        scriptError = err;
        return *this;
    }

    TestBuilder& Opcode(const opcodetype& _op)
    {
        DoPush();
        spendTx.vin[0].scriptSig << _op;
        return *this;
    }

    TestBuilder& Num(int num)
    {
        DoPush();
        spendTx.vin[0].scriptSig << num;
        return *this;
    }

    TestBuilder& Push(const std::string& hex)
    {
        DoPush(ParseHex(hex));
        return *this;
    }

    TestBuilder& Push(const CScript& _script)
    {
        DoPush(std::vector<unsigned char>(_script.begin(), _script.end()));
        return *this;
    }

    TestBuilder& PushSig(const CKey& key, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::BASE, CAmount amount = 0, bool legacy_mode = false)
    {
        (void)lenR;
        (void)lenS;
        std::vector<unsigned char> vchSig;
        if (sigversion == SigVersion::WITNESS_V1_512) {
            const uint512 hash = SignatureHash512(script, spendTx, 0, nHashType, amount, nullptr);
            key.Sign512(hash, vchSig, legacy_mode);
        } else {
            const uint256 hash = SignatureHash(script, spendTx, 0, nHashType, amount, sigversion);
            key.Sign(hash, vchSig, false, 0, legacy_mode);
        }
        vchSig.push_back(static_cast<unsigned char>(nHashType));
        DoPush(vchSig);
        return *this;
    }

    TestBuilder& PushWitSig(const CKey& key, CAmount amount = -1, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::WITNESS_V0)
    {
        if (amount == -1)
            amount = nValue;
        return PushSig(key, nHashType, lenR, lenS, sigversion, amount).AsWit();
    }

    TestBuilder& Push(const CPubKey& pubkey)
    {
        DoPush(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
        return *this;
    }

    TestBuilder& PushRedeem()
    {
        DoPush(std::vector<unsigned char>(redeemscript.begin(), redeemscript.end()));
        return *this;
    }

    TestBuilder& PushWitRedeem()
    {
        DoPush(std::vector<unsigned char>(witscript.begin(), witscript.end()));
        return AsWit();
    }

    TestBuilder& DamagePush(unsigned int pos)
    {
        assert(havePush);
        assert(pos < push.size());
        push[pos] ^= 1;
        return *this;
    }

    TestBuilder& Test(ScriptTest& test)
    {
        TestBuilder copy = *this; // Make a copy so we can rollback the push.
        DoPush();
        test.DoTest(creditTx->vout[0].scriptPubKey, spendTx.vin[0].scriptSig, scriptWitness, flags, comment, scriptError, nValue);
        *this = copy;
        return *this;
    }

    TestBuilder& AsWit()
    {
        assert(havePush);
        scriptWitness.stack.push_back(push);
        havePush = false;
        return *this;
    }

    UniValue GetJSON()
    {
        DoPush();
        UniValue array(UniValue::VARR);
        if (!scriptWitness.stack.empty()) {
            UniValue wit(UniValue::VARR);
            for (unsigned i = 0; i < scriptWitness.stack.size(); i++) {
                wit.push_back(HexStr(scriptWitness.stack[i]));
            }
            wit.push_back(ValueFromAmount(nValue));
            array.push_back(std::move(wit));
        }
        array.push_back(FormatScript(spendTx.vin[0].scriptSig));
        array.push_back(FormatScript(creditTx->vout[0].scriptPubKey));
        array.push_back(FormatScriptFlags(flags));
        array.push_back(FormatScriptError((ScriptError_t)scriptError));
        array.push_back(comment);
        return array;
    }

    std::string GetComment() const
    {
        return comment;
    }
};

std::string JSONPrettyPrint(const UniValue& univalue)
{
    std::string ret = univalue.write(4);
    // Workaround for libunivalue pretty printer, which puts a space between commas and newlines
    size_t pos = 0;
    while ((pos = ret.find(" \n", pos)) != std::string::npos) {
        ret.replace(pos, 2, "\n");
        pos++;
    }
    return ret;
}

void WriteGeneratedScriptVectors(const std::string& raw_entries, const char* output_path, bool emit_full_json)
{
    FILE* file = fsbridge::fopen(output_path, "w");
    if (emit_full_json) {
        std::string body = raw_entries;
        if (body.ends_with(",\n")) {
            body.resize(body.size() - 2);
        } else if (!body.empty() && body.back() == ',') {
            body.pop_back();
        }
        const std::string wrapped = "[\n" + body + (body.empty() ? "" : "\n") + "]\n";
        fputs(wrapped.c_str(), file);
    } else {
        fputs(raw_entries.c_str(), file);
    }
    fclose(file);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(script_tests, ScriptTest)

BOOST_AUTO_TEST_CASE(script_build)
{
    const std::string_view vector_json{std::string_view{json_tests::script_tests_pq}};
    const char* const default_gen_output{"script_tests_pq.json.gen"};
    const char* const env_gen_output{std::getenv("TIDE_SCRIPT_TESTS_GEN_OUTPUT")};
    const bool regenerate_from_env{env_gen_output != nullptr && env_gen_output[0] != '\0'};
#ifdef UPDATE_JSON_TESTS
    const bool emit_generated_json{true};
#else
    const bool emit_generated_json{regenerate_from_env};
#endif
    // PQ signatures are intentionally non-deterministic (Falcon nonce randomness), so
    // exact JSON membership checks against static fixtures are not stable.
    const bool verify_json_membership{false};

    CKey key0, key1, key2, key3, key4;
    {
        const std::vector<unsigned char> key0_secret{ParseHex(std::string{SCRIPT_BUILD_KEY0_SECRET_HEX})};
        key0.Set(key0_secret.begin(), key0_secret.end());
        BOOST_REQUIRE_MESSAGE(key0.IsValid(), "SCRIPT_BUILD_KEY0_SECRET_HEX is invalid");
    }
    key1.MakeNewKey(pq::SchemeId::FALCON_512);
    key2.MakeNewKey(pq::SchemeId::FALCON_512);
    key3.MakeNewKey(pq::SchemeId::FALCON_512);
    key4.MakeNewKey(pq::SchemeId::FALCON_512);

    const CPubKey pubkey0 = key0.GetPubKey();
    const CPubKey pubkey1 = key1.GetPubKey();
    const CPubKey pubkey2 = key2.GetPubKey();
    const CPubKey pubkey3 = key3.GetPubKey();
    const CPubKey pubkey4 = key4.GetPubKey();

    std::vector<TestBuilder> tests;

    // P2PK
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2PK", 0).PushSig(key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2PK, bad sig", 0).PushSig(key0).DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    // P2PKH
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "PQ P2PKH", 0).PushSig(key1).Push(pubkey1));
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey2.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "PQ P2PKH, bad pubkey", 0).PushSig(key2).Push(pubkey2).DamagePush(5).ScriptError(SCRIPT_ERR_EQUALVERIFY));

    // Sighash behavior.
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ P2PK sighash ANYONECANPAY", 0).PushSig(key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ P2PK sighash ANYONECANPAY, bad sig", 0).PushSig(key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY).DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ P2PK sighash NONE", 0).PushSig(key1, SIGHASH_NONE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ P2PK sighash SINGLE", 0).PushSig(key1, SIGHASH_SINGLE));

    // P2SH semantics.
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2SH(P2PK)", SCRIPT_VERIFY_P2SH, true).PushSig(key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2SH(P2PK), bad redeemscript", SCRIPT_VERIFY_P2SH, true).PushSig(key0).PushRedeem().DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey0.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "PQ P2SH(P2PKH)", SCRIPT_VERIFY_P2SH, true).PushSig(key0).Push(pubkey0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "PQ P2SH(P2PKH), bad sig without P2SH", 0, true).PushSig(key0).DamagePush(10).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "PQ P2SH(P2PKH), bad sig with P2SH", SCRIPT_VERIFY_P2SH, true).PushSig(key0).DamagePush(10).PushRedeem().ScriptError(SCRIPT_ERR_EQUALVERIFY));

    const uint32_t witness_flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;

    // PR-15: multisig/policy cartesian matrix cells.
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(pubkey0) << OP_1 << OP_CHECKMULTISIG,
                                "PQ MSIG-ARITY-1OF1-OK", 0).Num(0).PushSig(key0));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << OP_2 << OP_CHECKMULTISIG,
                                "PQ MSIG-ARITY-1OF2-OK", 0).Num(0).PushSig(key1));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << ToByteVector(pubkey2) << OP_3 << OP_CHECKMULTISIG,
                                "PQ MSIG-ARITY-1OF3-OK", 0).Num(0).PushSig(key2));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << OP_2 << OP_CHECKMULTISIG,
                                "PQ MSIG-ARITY-2OF2-OK", witness_flags, false, WitnessMode::SH, 0, 1)
                                   .Push("").AsWit().PushWitSig(key0).PushWitSig(key1).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << ToByteVector(pubkey2) << OP_3 << OP_CHECKMULTISIG,
                                "PQ MSIG-ARITY-2OF3-OK", SCRIPT_VERIFY_P2SH, true).Num(0).PushSig(key1).PushSig(key2).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << ToByteVector(pubkey2) << ToByteVector(pubkey3) << ToByteVector(pubkey4) << OP_5 << OP_CHECKMULTISIG,
                                "PQ MSIG-ARITY-3OF5-OK", 0).Num(0).PushSig(key0).PushSig(key3).PushSig(key4));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << ToByteVector(pubkey2) << OP_3 << OP_CHECKMULTISIG,
                                "PQ MSIG-ORDER-WRONG", 0).Num(0).PushSig(key2).PushSig(key0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << ToByteVector(pubkey2) << OP_3 << OP_CHECKMULTISIG,
                                "PQ MSIG-MISSING-SIG", 0).Num(0).PushSig(key0).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << ToByteVector(pubkey2) << OP_3 << OP_CHECKMULTISIG,
                                "PQ MSIG-WRONG-SIG", 0).Num(0).PushSig(key0).PushSig(key1).DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << OP_2 << OP_CHECKMULTISIG,
                                "PQ MSIG-WRONG-KEY", 0).Num(0).PushSig(key2).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(pubkey0) << OP_1 << OP_CHECKMULTISIG,
                                "PQ MSIG-EXTRA-SIG", 0).Num(42).Num(0).PushSig(key0));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << ToByteVector(pubkey2) << OP_3 << OP_CHECKMULTISIG,
                                "PQ MSIG-NULLDUMMY-NOT-ENFORCED", 0).Num(1).PushSig(key0).PushSig(key1).PushSig(key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << ToByteVector(pubkey2) << OP_3 << OP_CHECKMULTISIG,
                                "PQ MSIG-NULLDUMMY-ENFORCED", SCRIPT_VERIFY_NULLDUMMY).Num(1).PushSig(key0).PushSig(key1).PushSig(key2).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey1) << ToByteVector(pubkey1) << OP_2 << OP_CHECKMULTISIG,
                                "PQ MSIG-SIGPUSHONLY-NOT-ENFORCED", 0).Num(0).PushSig(key1).Opcode(OP_DUP));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey1) << ToByteVector(pubkey1) << OP_2 << OP_CHECKMULTISIG,
                                "PQ MSIG-SIGPUSHONLY-ENFORCED", SCRIPT_VERIFY_SIGPUSHONLY).Num(0).PushSig(key1).Opcode(OP_DUP).ScriptError(SCRIPT_ERR_SIG_PUSHONLY));

    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(pubkey0) << OP_1 << OP_CHECKMULTISIG,
                                "PQ MSIG-CLEANSTACK-NOT-ENFORCED", SCRIPT_VERIFY_P2SH).Num(42).Num(0).PushSig(key0));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(pubkey0) << OP_1 << OP_CHECKMULTISIG,
                                "PQ MSIG-CLEANSTACK-ENFORCED", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH).Num(42).Num(0).PushSig(key0).ScriptError(SCRIPT_ERR_CLEANSTACK));

    // CLEANSTACK
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ CLEANSTACK extra element", SCRIPT_VERIFY_P2SH).Num(11).PushSig(key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ CLEANSTACK enforced", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH).Num(11).PushSig(key0).ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2SH CLEANSTACK extra element", SCRIPT_VERIFY_P2SH, true).Num(11).PushSig(key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2SH CLEANSTACK enforced", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true).Num(11).PushSig(key0).PushRedeem().ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2SH CLEANSTACK success", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true).PushSig(key0).PushRedeem());

    // Additional SIGPUSHONLY/P2SH flag interactions.
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey2) << OP_CHECKSIG,
                                "PQ P2SH(P2PK) non-push scriptSig without P2SH/SIGPUSHONLY", 0, true)
                                   .PushSig(key2)
                                   .Opcode(OP_NOP8)
                                   .PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey2) << OP_CHECKSIG,
                                "PQ P2PK non-push scriptSig under base rules", 0)
                                   .PushSig(key2)
                                   .Opcode(OP_NOP8));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey2) << OP_CHECKSIG,
                                "PQ P2SH(P2PK) non-push scriptSig with P2SH", SCRIPT_VERIFY_P2SH, true)
                                   .PushSig(key2)
                                   .Opcode(OP_NOP8)
                                   .PushRedeem()
                                   .ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey2) << OP_CHECKSIG,
                                "PQ P2SH(P2PK) non-push scriptSig with SIGPUSHONLY only", SCRIPT_VERIFY_SIGPUSHONLY, true)
                                   .PushSig(key2)
                                   .Opcode(OP_NOP8)
                                   .PushRedeem()
                                   .ScriptError(SCRIPT_ERR_SIG_PUSHONLY));

    // PR-14: interpreter negative-surface matrix cells.
    tests.push_back(TestBuilder(CScript() << OP_VERIF,
                                "PQ INT-BADOP-BARE", 0)
                                   .ScriptError(SCRIPT_ERR_BAD_OPCODE));
    tests.push_back(TestBuilder(CScript() << OP_VERIF,
                                "PQ INT-BADOP-P2SH", SCRIPT_VERIFY_P2SH, true)
                                   .PushRedeem()
                                   .ScriptError(SCRIPT_ERR_BAD_OPCODE));
    tests.push_back(TestBuilder(CScript() << OP_VERIF,
                                "PQ INT-BADOP-P2WSH", witness_flags, false, WitnessMode::SH)
                                   .PushWitRedeem()
                                   .ScriptError(SCRIPT_ERR_BAD_OPCODE));

    tests.push_back(TestBuilder(CScript() << OP_CAT,
                                "PQ INT-DISABLED-BARE", 0)
                                   .ScriptError(SCRIPT_ERR_DISABLED_OPCODE));
    tests.push_back(TestBuilder(CScript() << OP_CAT,
                                "PQ INT-DISABLED-P2SH", SCRIPT_VERIFY_P2SH, true)
                                   .PushRedeem()
                                   .ScriptError(SCRIPT_ERR_DISABLED_OPCODE));
    tests.push_back(TestBuilder(CScript() << OP_CAT,
                                "PQ INT-DISABLED-P2WSH", witness_flags, false, WitnessMode::SH)
                                   .PushWitRedeem()
                                   .ScriptError(SCRIPT_ERR_DISABLED_OPCODE));

    tests.push_back(TestBuilder(CScript() << OP_0 << OP_VERIFY,
                                "PQ INT-VERIFY-FAIL-BARE", 0)
                                   .ScriptError(SCRIPT_ERR_VERIFY));
    tests.push_back(TestBuilder(CScript() << OP_0 << OP_VERIFY,
                                "PQ INT-VERIFY-FAIL-P2SH", SCRIPT_VERIFY_P2SH, true)
                                   .PushRedeem()
                                   .ScriptError(SCRIPT_ERR_VERIFY));
    tests.push_back(TestBuilder(CScript() << OP_0 << OP_VERIFY,
                                "PQ INT-VERIFY-FAIL-P2WSH", witness_flags, false, WitnessMode::SH)
                                   .PushWitRedeem()
                                   .ScriptError(SCRIPT_ERR_VERIFY));

    tests.push_back(TestBuilder(CScript() << OP_2DROP,
                                "PQ INT-STACK-UFLOW-2DROP", 0)
                                   .Num(1)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_2DUP,
                                "PQ INT-STACK-UFLOW-2DUP", 0)
                                   .Num(1)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_2OVER,
                                "PQ INT-STACK-UFLOW-2OVER", 0)
                                   .Num(1)
                                   .Num(2)
                                   .Num(3)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_2ROT,
                                "PQ INT-STACK-UFLOW-2ROT", 0)
                                   .Num(1)
                                   .Num(2)
                                   .Num(3)
                                   .Num(4)
                                   .Num(5)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_2SWAP,
                                "PQ INT-STACK-UFLOW-2SWAP", 0)
                                   .Num(1)
                                   .Num(2)
                                   .Num(3)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_3DUP,
                                "PQ INT-STACK-UFLOW-3DUP", 0)
                                   .Num(1)
                                   .Num(2)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_2 << OP_PICK,
                                "PQ INT-STACK-UFLOW-PICK", 0)
                                   .Num(11)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_1 << OP_ROLL,
                                "PQ INT-STACK-UFLOW-ROLL", 0)
                                   .Num(11)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_FROMALTSTACK,
                                "PQ INT-ALT-UFLOW-FROMALTSTACK", 0)
                                   .ScriptError(SCRIPT_ERR_INVALID_ALTSTACK_OPERATION));

    tests.push_back(TestBuilder(CScript() << OP_1 << OP_IF << OP_1,
                                "PQ INT-COND-UNBAL-IF-NO-ENDIF", 0)
                                   .ScriptError(SCRIPT_ERR_UNBALANCED_CONDITIONAL));
    tests.push_back(TestBuilder(CScript() << OP_ELSE << OP_1,
                                "PQ INT-COND-UNBAL-ELSE-WO-IF", 0)
                                   .ScriptError(SCRIPT_ERR_UNBALANCED_CONDITIONAL));
    tests.push_back(TestBuilder(CScript() << OP_ENDIF,
                                "PQ INT-COND-UNBAL-ENDIF-WO-IF", 0)
                                   .ScriptError(SCRIPT_ERR_UNBALANCED_CONDITIONAL));

    // Generic interpreter stack/altstack/flow/comparison coverage.
    tests.push_back(TestBuilder(CScript() << OP_TOALTSTACK << OP_FROMALTSTACK << OP_7 << OP_EQUAL,
                                "PQ interpreter altstack roundtrip", 0)
                                   .Num(7));
    tests.push_back(TestBuilder(CScript() << OP_FROMALTSTACK,
                                "PQ interpreter altstack underflow", 0)
                                   .ScriptError(SCRIPT_ERR_INVALID_ALTSTACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_DROP,
                                "PQ interpreter stack underflow", 0)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_SWAP << OP_1 << OP_EQUALVERIFY << OP_2 << OP_EQUAL,
                                "PQ interpreter swap ordering", 0)
                                   .Num(1)
                                   .Num(2));
    tests.push_back(TestBuilder(CScript() << OP_2DROP << OP_1 << OP_EQUAL,
                                "PQ interpreter 2DROP", 0)
                                   .Num(1)
                                   .Num(2)
                                   .Num(3));
    tests.push_back(TestBuilder(CScript() << OP_2DUP << OP_2DROP << OP_8 << OP_EQUAL,
                                "PQ interpreter 2DUP", 0)
                                   .Num(7)
                                   .Num(8));
    tests.push_back(TestBuilder(CScript() << OP_2OVER << OP_2 << OP_EQUAL,
                                "PQ interpreter 2OVER", 0)
                                   .Num(1)
                                   .Num(2)
                                   .Num(3)
                                   .Num(4));
    tests.push_back(TestBuilder(CScript() << OP_2ROT << OP_2 << OP_EQUAL,
                                "PQ interpreter 2ROT", 0)
                                   .Num(1)
                                   .Num(2)
                                   .Num(3)
                                   .Num(4)
                                   .Num(5)
                                   .Num(6));
    tests.push_back(TestBuilder(CScript() << OP_2SWAP << OP_2 << OP_EQUAL,
                                "PQ interpreter 2SWAP", 0)
                                   .Num(1)
                                   .Num(2)
                                   .Num(3)
                                   .Num(4));
    tests.push_back(TestBuilder(CScript() << OP_3DUP << OP_DROP << OP_DROP << OP_DROP << OP_3 << OP_EQUAL,
                                "PQ interpreter 3DUP", 0)
                                   .Num(1)
                                   .Num(2)
                                   .Num(3));
    tests.push_back(TestBuilder(CScript() << OP_2 << OP_PICK << OP_11 << OP_EQUAL,
                                "PQ interpreter PICK", 0)
                                   .Num(10)
                                   .Num(11)
                                   .Num(12)
                                   .Num(13));
    tests.push_back(TestBuilder(CScript() << OP_2 << OP_ROLL << OP_11 << OP_EQUAL,
                                "PQ interpreter ROLL", 0)
                                   .Num(10)
                                   .Num(11)
                                   .Num(12)
                                   .Num(13));

    tests.push_back(TestBuilder(CScript() << OP_IF << OP_1 << OP_ELSE << OP_2 << OP_ENDIF << OP_2 << OP_EQUAL,
                                "PQ interpreter IF false branch", 0)
                                   .Num(0));
    tests.push_back(TestBuilder(CScript() << OP_NOTIF << OP_3 << OP_ELSE << OP_4 << OP_ENDIF << OP_3 << OP_EQUAL,
                                "PQ interpreter NOTIF true branch", 0)
                                   .Num(0));
    tests.push_back(TestBuilder(CScript() << OP_IF << OP_1 << OP_ELSE << OP_2 << OP_ENDIF << OP_2 << OP_EQUAL,
                                "PQ interpreter IF wrong branch result", 0)
                                   .Num(1)
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_1 << OP_IF << OP_1,
                                "PQ interpreter unbalanced conditional", 0)
                                   .ScriptError(SCRIPT_ERR_UNBALANCED_CONDITIONAL));

    tests.push_back(TestBuilder(CScript() << OP_ADD << OP_5 << OP_NUMEQUAL,
                                "PQ interpreter arithmetic add", 0)
                                   .Num(2)
                                   .Num(3));
    tests.push_back(TestBuilder(CScript() << OP_ADD << OP_6 << OP_NUMEQUAL,
                                "PQ interpreter arithmetic add mismatch", 0)
                                   .Num(2)
                                   .Num(3)
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_SUB << OP_2 << OP_NUMEQUAL,
                                "PQ interpreter arithmetic subtract", 0)
                                   .Num(5)
                                   .Num(3));
    tests.push_back(TestBuilder(CScript() << OP_0 << OP_BOOLAND,
                                "PQ interpreter boolean and false", 0)
                                   .Num(1)
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_5 << OP_LESSTHAN,
                                "PQ interpreter less-than comparison", 0)
                                   .Num(2));
    tests.push_back(TestBuilder(CScript() << OP_2 << OP_7 << OP_WITHIN,
                                "PQ interpreter within true", 0)
                                   .Num(5));
    tests.push_back(TestBuilder(CScript() << OP_2 << OP_7 << OP_WITHIN,
                                "PQ interpreter within false", 0)
                                   .Num(7)
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_MIN << OP_3 << OP_NUMEQUAL,
                                "PQ interpreter min", 0)
                                   .Num(3)
                                   .Num(5));
    tests.push_back(TestBuilder(CScript() << OP_MAX << OP_5 << OP_NUMEQUAL,
                                "PQ interpreter max", 0)
                                   .Num(3)
                                   .Num(5));
    tests.push_back(TestBuilder(CScript() << OP_GREATERTHAN,
                                "PQ interpreter greater-than", 0)
                                   .Num(5)
                                   .Num(3));
    tests.push_back(TestBuilder(CScript() << OP_ABS << OP_5 << OP_NUMEQUAL,
                                "PQ interpreter abs", 0)
                                   .Num(-5));
    tests.push_back(TestBuilder(CScript() << OP_NEGATE << -5 << OP_NUMEQUAL,
                                "PQ interpreter negate", 0)
                                   .Num(5));
    tests.push_back(TestBuilder(CScript() << OP_1ADD << OP_5 << OP_NUMEQUAL,
                                "PQ interpreter 1ADD", 0)
                                   .Num(4));
    tests.push_back(TestBuilder(CScript() << OP_1SUB << OP_3 << OP_NUMEQUAL,
                                "PQ interpreter 1SUB", 0)
                                   .Num(4));
    {
        const std::vector<unsigned char> hash_input = ParseHex("01020304");

        std::vector<unsigned char> hash256(32);
        CHash256().Write(hash_input).Finalize(hash256);
        tests.push_back(TestBuilder(CScript() << OP_HASH256 << hash256 << OP_EQUAL,
                                    "PQ interpreter HASH256", 0)
                                       .Push("01020304"));

        std::vector<unsigned char> sha256(32);
        CSHA256().Write(hash_input.data(), hash_input.size()).Finalize(sha256.data());
        tests.push_back(TestBuilder(CScript() << OP_SHA256 << sha256 << OP_EQUAL,
                                    "PQ interpreter SHA256", 0)
                                       .Push("01020304"));

        std::vector<unsigned char> sha1(20);
        CSHA1().Write(hash_input.data(), hash_input.size()).Finalize(sha1.data());
        tests.push_back(TestBuilder(CScript() << OP_SHA1 << sha1 << OP_EQUAL,
                                    "PQ interpreter SHA1", 0)
                                       .Push("01020304"));

        std::vector<unsigned char> ripemd160(20);
        CRIPEMD160().Write(hash_input.data(), hash_input.size()).Finalize(ripemd160.data());
        tests.push_back(TestBuilder(CScript() << OP_RIPEMD160 << ripemd160 << OP_EQUAL,
                                    "PQ interpreter RIPEMD160", 0)
                                       .Push("01020304"));
    }

    // Interpreter size/count boundaries.
    {
        CScript opcount_limit_script;
        for (int i = 0; i < 200; ++i) {
            opcount_limit_script << OP_NOP;
        }
        opcount_limit_script << OP_TRUE;
        tests.emplace_back(opcount_limit_script,
                           "PQ interpreter opcount limit", 0);

        CScript opcount_overflow_script;
        for (int i = 0; i < 202; ++i) {
            opcount_overflow_script << OP_NOP;
        }
        opcount_overflow_script << OP_TRUE;
        tests.push_back(TestBuilder(opcount_overflow_script,
                                    "PQ interpreter opcount overflow", 0)
                                       .ScriptError(SCRIPT_ERR_OP_COUNT));
    }
    {
        const std::vector<unsigned char> oversized_script_bytes(65537, static_cast<unsigned char>(OP_TRUE));
        const CScript oversized_script{oversized_script_bytes.begin(), oversized_script_bytes.end()};
        tests.push_back(TestBuilder(oversized_script,
                                    "PQ interpreter script size overflow", 0)
                                       .ScriptError(SCRIPT_ERR_SCRIPT_SIZE));
    }

    // MINIMALDATA behavior.
    tests.push_back(TestBuilder(CScript() << OP_1 << OP_EQUAL,
                                "PQ MINIMALDATA minimal push", SCRIPT_VERIFY_MINIMALDATA)
                                   .Num(1));
    tests.push_back(TestBuilder(CScript() << OP_1 << OP_EQUAL,
                                "PQ MINIMALDATA non-minimal scriptSig push not enforced", 0)
                                   .Opcode(OP_PUSHDATA1)
                                   .Push("01"));
    tests.push_back(TestBuilder(CScript() << OP_1 << OP_EQUAL,
                                "PQ MINIMALDATA non-minimal scriptSig push enforced", SCRIPT_VERIFY_MINIMALDATA)
                                   .Opcode(OP_PUSHDATA1)
                                   .Push("01")
                                   .ScriptError(SCRIPT_ERR_MINIMALDATA));
    tests.push_back(TestBuilder(CScript() << OP_0 << OP_EQUAL,
                                "PQ MINIMALDATA non-minimal zero push not enforced", 0)
                                   .Opcode(OP_PUSHDATA1)
                                   .Push(""));
    tests.push_back(TestBuilder(CScript() << OP_0 << OP_EQUAL,
                                "PQ MINIMALDATA non-minimal zero push enforced", SCRIPT_VERIFY_MINIMALDATA)
                                   .Opcode(OP_PUSHDATA1)
                                   .Push("")
                                   .ScriptError(SCRIPT_ERR_MINIMALDATA));
    {
        const std::vector<unsigned char> non_minimal_spk_bytes{
            static_cast<unsigned char>(OP_PUSHDATA1), 0x01, 0x01,
            static_cast<unsigned char>(OP_1),
            static_cast<unsigned char>(OP_EQUAL),
        };
        const CScript non_minimal_spk{non_minimal_spk_bytes.begin(), non_minimal_spk_bytes.end()};
        tests.emplace_back(non_minimal_spk,
                           "PQ MINIMALDATA non-minimal scriptPubKey push not enforced", 0);
        tests.push_back(TestBuilder(non_minimal_spk,
                                    "PQ MINIMALDATA non-minimal scriptPubKey push enforced", SCRIPT_VERIFY_MINIMALDATA)
                                       .ScriptError(SCRIPT_ERR_MINIMALDATA));
    }

    // PR-16: timelock matrix (TIME-*). SAT cells use guarded branches so they
    // remain stable under the fixed JSON tx schema used by script_json_test.
    const uint32_t cltv_flags{SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY};
    const uint32_t csv_flags{SCRIPT_VERIFY_CHECKSEQUENCEVERIFY};
    const uint32_t cltv_witness_flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY};
    const uint32_t csv_witness_flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY};
    const uint32_t cltv_csv_flags{SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY};

    tests.push_back(TestBuilder(CScript() << OP_CHECKLOCKTIMEVERIFY,
                                "PQ TIME-CLTV-EMPTY-STACK", cltv_flags)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_CHECKLOCKTIMEVERIFY,
                                "PQ TIME-CLTV-NEGATIVE", cltv_flags)
                                   .Num(-1)
                                   .ScriptError(SCRIPT_ERR_NEGATIVE_LOCKTIME));
    tests.push_back(TestBuilder(CScript() << OP_CHECKLOCKTIMEVERIFY,
                                "PQ TIME-CLTV-UNSAT", cltv_flags)
                                   .Num(1)
                                   .ScriptError(SCRIPT_ERR_UNSATISFIED_LOCKTIME));
    {
        const CScript cltv_sat_script = CScript() << OP_0 << OP_IF << OP_CHECKLOCKTIMEVERIFY << OP_ENDIF << OP_TRUE;
        tests.emplace_back(cltv_sat_script,
                           "PQ TIME-CLTV-SAT-BARE", cltv_flags);
        tests.push_back(TestBuilder(cltv_sat_script,
                                    "PQ TIME-CLTV-SAT-P2SH", cltv_flags, true)
                                       .PushRedeem());
        tests.push_back(TestBuilder(cltv_sat_script,
                                    "PQ TIME-CLTV-SAT-P2WSH", cltv_witness_flags, false, WitnessMode::SH, 0, 1)
                                       .PushWitRedeem());
    }

    tests.push_back(TestBuilder(CScript() << OP_CHECKSEQUENCEVERIFY,
                                "PQ TIME-CSV-EMPTY-STACK", csv_flags)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    tests.push_back(TestBuilder(CScript() << OP_CHECKSEQUENCEVERIFY,
                                "PQ TIME-CSV-NEGATIVE", csv_flags)
                                   .Num(-1)
                                   .ScriptError(SCRIPT_ERR_NEGATIVE_LOCKTIME));
    tests.push_back(TestBuilder(CScript() << OP_CHECKSEQUENCEVERIFY,
                                "PQ TIME-CSV-UNSAT", csv_flags)
                                   .Num(1)
                                   .ScriptError(SCRIPT_ERR_UNSATISFIED_LOCKTIME));
    {
        const CScript csv_sat_script = CScript() << OP_0 << OP_IF << OP_CHECKSEQUENCEVERIFY << OP_ENDIF << OP_TRUE;
        tests.emplace_back(csv_sat_script,
                           "PQ TIME-CSV-SAT-BARE", csv_flags);
        tests.push_back(TestBuilder(csv_sat_script,
                                    "PQ TIME-CSV-SAT-P2SH", csv_flags, true)
                                       .PushRedeem());
        tests.push_back(TestBuilder(csv_sat_script,
                                    "PQ TIME-CSV-SAT-P2WSH", csv_witness_flags, false, WitnessMode::SH, 0, 1)
                                       .PushWitRedeem());
    }
    {
        const CScript cltv_csv_sat_script = CScript() << OP_0 << OP_IF << OP_CHECKLOCKTIMEVERIFY << OP_CHECKSEQUENCEVERIFY << OP_ENDIF << OP_TRUE;
        tests.emplace_back(cltv_csv_sat_script,
                           "PQ TIME-CLTVCSV-COMBINED-SAT", cltv_csv_flags);
        const CScript cltv_csv_unsat_script = CScript() << 1 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << 1 << OP_CHECKSEQUENCEVERIFY;
        tests.push_back(TestBuilder(cltv_csv_unsat_script,
                                    "PQ TIME-CLTVCSV-COMBINED-UNSAT", cltv_csv_flags)
                                       .ScriptError(SCRIPT_ERR_UNSATISFIED_LOCKTIME));
    }

    // MINIMALIF for witness script paths.
    const uint32_t minimalif_flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_MINIMALIF;
    const CScript minimalif_script = CScript() << OP_IF << OP_TRUE << OP_ENDIF;
    tests.push_back(TestBuilder(minimalif_script,
                                "PQ MINIMALIF minimal true", minimalif_flags, false, WitnessMode::SH, 0, 1)
                                   .Push("01")
                                   .AsWit()
                                   .PushWitRedeem());
    tests.push_back(TestBuilder(minimalif_script,
                                "PQ MINIMALIF non-minimal true", minimalif_flags, false, WitnessMode::SH, 0, 1)
                                   .Push("02")
                                   .AsWit()
                                   .PushWitRedeem()
                                   .ScriptError(SCRIPT_ERR_MINIMALIF));
    tests.push_back(TestBuilder(minimalif_script,
                                "PQ MINIMALIF non-minimal true in P2SH(P2WSH)", minimalif_flags, true, WitnessMode::SH, 0, 1)
                                   .Push("02")
                                   .AsWit()
                                   .PushWitRedeem()
                                   .PushRedeem()
                                   .ScriptError(SCRIPT_ERR_MINIMALIF));

    // NULLFAIL for failed non-null signatures.
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG << OP_NOT,
                                "PQ NULLFAIL not enforced", 0)
                                   .PushSig(key0)
                                   .DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG << OP_NOT,
                                "PQ NULLFAIL enforced", SCRIPT_VERIFY_NULLFAIL)
                                   .PushSig(key0)
                                   .DamagePush(10)
                                   .ScriptError(SCRIPT_ERR_SIG_NULLFAIL));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG << OP_NOT,
                                "PQ NULLFAIL with empty signature", SCRIPT_VERIFY_NULLFAIL)
                                   .Num(0));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "PQ MSIG-NULLFAIL-NOT-ENFORCED", 0)
                                   .Num(0)
                                   .PushSig(key0)
                                   .PushSig(key1)
                                   .DamagePush(10));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(pubkey0) << ToByteVector(pubkey1) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "PQ MSIG-NULLFAIL-ENFORCED", SCRIPT_VERIFY_NULLFAIL)
                                   .Num(0)
                                   .PushSig(key0)
                                   .PushSig(key1)
                                   .DamagePush(10)
                                   .ScriptError(SCRIPT_ERR_SIG_NULLFAIL));

    // CONST_SCRIPTCODE behavior.
    tests.emplace_back(CScript() << OP_0 << OP_IF << OP_CODESEPARATOR << OP_ENDIF << OP_TRUE,
                       "PQ CONST_SCRIPTCODE not enforced", 0);
    tests.push_back(TestBuilder(CScript() << OP_0 << OP_IF << OP_CODESEPARATOR << OP_ENDIF << OP_TRUE,
                                "PQ CONST_SCRIPTCODE rejects OP_CODESEPARATOR", SCRIPT_VERIFY_CONST_SCRIPTCODE)
                                   .ScriptError(SCRIPT_ERR_OP_CODESEPARATOR));
    tests.push_back(TestBuilder(CScript() << ParseHex("51") << OP_DROP << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ CONST_SCRIPTCODE find-and-delete not enforced", 0)
                                   .Push("51")
                                   .Push(pubkey0)
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ParseHex("51") << OP_DROP << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ CONST_SCRIPTCODE rejects find-and-delete", SCRIPT_VERIFY_CONST_SCRIPTCODE)
                                   .Push("51")
                                   .Push(pubkey0)
                                   .ScriptError(SCRIPT_ERR_SIG_FINDANDDELETE));

    // PQ_STRICT behavior.
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ strict modern signature", SCRIPT_VERIFY_PQ_STRICT)
                                   .PushSig(key0));
    {
        const CScript strict_script = CScript() << ToByteVector(pubkey0) << OP_CHECKSIG;
        tests.push_back(TestBuilder(strict_script,
                                    "PQ strict rejects legacy-only falcon signature", SCRIPT_VERIFY_PQ_STRICT)
                                       .Push(std::string{LEGACY_ONLY_STRICT_DIFF_SIG_HEX})
                                       .ScriptError(SCRIPT_ERR_EVAL_FALSE));
        tests.push_back(TestBuilder(strict_script,
                                    "PQ non-strict accepts legacy-only falcon signature", 0)
                                       .Push(std::string{LEGACY_ONLY_STRICT_DIFF_SIG_HEX}));
    }

    // Witness behavior.
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).PushWitSig(key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0),
                                "PQ P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 1).PushWitSig(key0).Push(pubkey0).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).PushWitSig(key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0),
                                "PQ P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 1).PushWitSig(key0).Push(pubkey0).AsWit().PushRedeem());

    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ P2WSH wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH)
                                   .PushWitSig(key0).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1),
                                "PQ P2WPKH wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH)
                                   .PushWitSig(key0).Push(pubkey1).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ P2SH(P2WSH) wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH)
                                   .PushWitSig(key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1),
                                "PQ P2SH(P2WPKH) wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH)
                                   .PushWitSig(key0).Push(pubkey1).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ P2WSH wrong key without WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::SH)
                                   .PushWitSig(key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1),
                                "PQ P2WPKH wrong key without WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH)
                                   .PushWitSig(key0).Push(pubkey1).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ P2SH(P2WSH) wrong key without WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::SH)
                                   .PushWitSig(key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1),
                                "PQ P2SH(P2WPKH) wrong key without WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH)
                                   .PushWitSig(key0).Push(pubkey1).AsWit().PushRedeem());

    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V0-WRONG-VALUE", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 0).PushWitSig(key0, 1).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0),
                                "PQ P2WPKH wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 0).PushWitSig(key0, 1).Push(pubkey0).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2SH(P2WSH) wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 0).PushWitSig(key0, 1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0),
                                "PQ P2SH(P2WPKH) wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 0).PushWitSig(key0, 1).Push(pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0),
                                "PQ witness future version discouraged", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH |
                                SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, false, WitnessMode::PKH, 1)
                                   .PushWitSig(key0).Push(pubkey0).AsWit().ScriptError(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM));
    {
        CScript witscript = CScript() << ToByteVector(pubkey0);
        uint256 hash;
        CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
        std::vector<unsigned char> hash_bytes = ToByteVector(hash);
        hash_bytes.pop_back();
        tests.push_back(TestBuilder(CScript() << OP_0 << hash_bytes,
                                    "PQ WIT-V0-WRONG-LEN", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false)
                                       .PushWitSig(key0).Push(pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2WSH empty witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH)
                                   .ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY));
    {
        CScript witscript = CScript() << ToByteVector(pubkey0) << OP_CHECKSIG;
        tests.push_back(TestBuilder(witscript,
                                    "PQ WIT-V0-MISMATCH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH)
                                       .PushWitSig(key0).Push(witscript).DamagePush(0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0),
                                "PQ P2WPKH witness mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH)
                                   .PushWitSig(key0).Push(pubkey0).AsWit().Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0),
                                "PQ WIT-V0-MALLEATED", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH)
                                   .PushWitSig(key0).Push(pubkey0).AsWit().Num(11).ScriptError(SCRIPT_ERR_WITNESS_MALLEATED));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1),
                                "PQ P2SH(P2WPKH) superfluous scriptSig push", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH)
                                   .PushWitSig(key0).Push(pubkey1).AsWit().Num(11).PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_MALLEATED_P2SH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V0-UNEXPECTED", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH)
                                   .PushSig(key0).Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_UNEXPECTED));

    // Tidecoin-specific OP_SHA512 behavior.
    const CScript sha512_size_script = CScript() << OP_SHA512 << OP_SIZE << 64 << OP_EQUAL;
    tests.push_back(TestBuilder(sha512_size_script,
                                "PQ OP_SHA512 enabled", SCRIPT_VERIFY_SHA512)
                                   .Push("01020304"));
    tests.push_back(TestBuilder(sha512_size_script,
                                "PQ OP_SHA512 disabled acts as NOP", SCRIPT_VERIFY_NONE)
                                   .Push("01020304")
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(sha512_size_script,
                                "PQ OP_SHA512 discouraged when disabled", SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                   .Push("01020304")
                                   .ScriptError(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS));
    tests.push_back(TestBuilder(sha512_size_script,
                                "PQ OP_SHA512 enabled despite discourage", SCRIPT_VERIFY_SHA512 | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                   .Push("01020304"));
    tests.push_back(TestBuilder(CScript() << OP_SHA512,
                                "PQ OP_SHA512 empty stack", SCRIPT_VERIFY_SHA512)
                                   .ScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));

    // Tidecoin-specific witness v1_512 behavior.
    const uint32_t witness_v1_512_flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_V1_512};
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-SIGHASH-ALL v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_ALL, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-SIGHASH-NONE v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_NONE, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-SIGHASH-SINGLE v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_SINGLE, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-SIGHASH-ALL-ACP v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_ALL | SIGHASH_ANYONECANPAY, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-SIGHASH-NONE-ACP v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_NONE | SIGHASH_ANYONECANPAY, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-SIGHASH-SINGLE-ACP v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey1) << OP_CHECKSIG,
                                "PQ WIT-V1512-WRONG-KEY v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_ALL, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem()
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-WRONG-VALUE v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 0)
                                   .PushWitSig(key0, 1, SIGHASH_ALL, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem()
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-DISCOURAGED v1_512", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH |
                                SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_ALL, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem()
                                   .ScriptError(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0),
                                "PQ WIT-V1512-WRONG-LEN v1_512", witness_v1_512_flags, false, WitnessMode::PKH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_ALL, 32, 32, SigVersion::WITNESS_V1_512)
                                   .Push(pubkey0).AsWit()
                                   .ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-ZERO-SIGHASH-REJECT v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, 0, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem()
                                   .ScriptError(SCRIPT_ERR_EVAL_FALSE));
    {
        const CScript witscript = CScript() << ToByteVector(pubkey0) << OP_CHECKSIG;
        tests.push_back(TestBuilder(witscript,
                                    "PQ WIT-V1512-MISMATCH v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                       .PushWitSig(key0, 1, SIGHASH_ALL, 32, 32, SigVersion::WITNESS_V1_512)
                                       .Push(witscript).DamagePush(0).AsWit()
                                       .ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-MALLEATED v1_512", witness_v1_512_flags, false, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_ALL, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem()
                                   .Num(11)
                                   .ScriptError(SCRIPT_ERR_WITNESS_MALLEATED));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ WIT-V1512-UNEXPECTED v1_512", witness_v1_512_flags)
                                   .PushSig(key0)
                                   .Push("0").AsWit()
                                   .ScriptError(SCRIPT_ERR_WITNESS_UNEXPECTED));
    tests.push_back(TestBuilder(CScript() << ToByteVector(pubkey0) << OP_CHECKSIG,
                                "PQ P2SH(v1_512 P2WSH)", witness_v1_512_flags, true, WitnessMode::SH, 1, 1)
                                   .PushWitSig(key0, 1, SIGHASH_ALL, 32, 32, SigVersion::WITNESS_V1_512)
                                   .PushWitRedeem()
                                   .PushRedeem());

    std::set<std::string> tests_set;

    if (verify_json_membership) {
        UniValue json_tests = read_json(vector_json);

        for (unsigned int idx = 0; idx < json_tests.size(); idx++) {
            const UniValue& tv = json_tests[idx];
            tests_set.insert(JSONPrettyPrint(tv.get_array()));
        }
    }

    std::string strGen;
    for (TestBuilder& test : tests) {
        test.Test(*this);
        std::string str = JSONPrettyPrint(test.GetJSON());
        if (emit_generated_json) {
            strGen += str + ",\n";
        } else if (verify_json_membership && tests_set.count(str) == 0) {
            BOOST_CHECK_MESSAGE(false, "Missing auto script_valid test: " + test.GetComment());
        }
    }

    if (emit_generated_json) {
        const char* const output_path{regenerate_from_env ? env_gen_output : default_gen_output};
        WriteGeneratedScriptVectors(strGen, output_path, regenerate_from_env);
    }
}
BOOST_AUTO_TEST_CASE(script_json_test)
{
    const std::string_view vector_json{std::string_view{json_tests::script_tests_pq}};
    // Read tests from test/data/script_tests_pq.json
    // Format is an array of arrays
    // Inner arrays are [ ["wit"..., nValue]?, "scriptSig", "scriptPubKey", "flags", "expected_scripterror" ]
    // ... where scriptSig and scriptPubKey are stringified
    // scripts.
    // If a witness is given, then the last value in the array should be the
    // amount (nValue) to use in the crediting tx
    UniValue tests = read_json(vector_json);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        CScriptWitness witness;
        CAmount nValue = 0;
        unsigned int pos = 0;
        if (test.size() > 0 && test[pos].isArray()) {
            unsigned int i=0;
            for (i = 0; i < test[pos].size()-1; i++) {
                auto element = test[pos][i].get_str();
                const auto witness_value{TryParseHex<unsigned char>(element)};
                if (!witness_value.has_value()) {
                    BOOST_ERROR("Bad witness in test: " << strTest << " witness is not hex: " << element);
                }
                witness.stack.push_back(witness_value.value());
            }
            nValue = AmountFromValue(test[pos][i]);
            pos++;
        }
        if (test.size() < 4 + pos) // Allow size > 3; extra stuff ignored (useful for comments)
        {
            if (test.size() != 1) {
                BOOST_ERROR("Bad test: " << strTest);
            }
            continue;
        }
        std::string scriptSigString = test[pos++].get_str();
        CScript scriptSig = ParseScript(scriptSigString);
        std::string scriptPubKeyString = test[pos++].get_str();
        CScript scriptPubKey = ParseScript(scriptPubKeyString);
        unsigned int scriptflags = ParseScriptFlags(test[pos++].get_str());
        int scriptError = ParseScriptError(test[pos++].get_str());

        DoTest(scriptPubKey, scriptSig, witness, scriptflags, strTest, scriptError, nValue);
    }
}

BOOST_AUTO_TEST_CASE(script_PushData)
{
    // Check that PUSHDATA1, PUSHDATA2, and PUSHDATA4 create the same value on
    // the stack as the 1-75 opcodes do.
    static const unsigned char direct[] = { 1, 0x5a };
    static const unsigned char pushdata1[] = { OP_PUSHDATA1, 1, 0x5a };
    static const unsigned char pushdata2[] = { OP_PUSHDATA2, 1, 0, 0x5a };
    static const unsigned char pushdata4[] = { OP_PUSHDATA4, 1, 0, 0, 0, 0x5a };

    ScriptError err;
    std::vector<std::vector<unsigned char> > directStack;
    BOOST_CHECK(EvalScript(directStack, CScript(direct, direct + sizeof(direct)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata1Stack;
    BOOST_CHECK(EvalScript(pushdata1Stack, CScript(pushdata1, pushdata1 + sizeof(pushdata1)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata1Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata2Stack;
    BOOST_CHECK(EvalScript(pushdata2Stack, CScript(pushdata2, pushdata2 + sizeof(pushdata2)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata2Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata4Stack;
    BOOST_CHECK(EvalScript(pushdata4Stack, CScript(pushdata4, pushdata4 + sizeof(pushdata4)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata4Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    const std::vector<unsigned char> pushdata1_trunc{OP_PUSHDATA1, 1};
    const std::vector<unsigned char> pushdata2_trunc{OP_PUSHDATA2, 1, 0};
    const std::vector<unsigned char> pushdata4_trunc{OP_PUSHDATA4, 1, 0, 0, 0};

    std::vector<std::vector<unsigned char>> stack_ignore;
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata1_trunc.begin(), pushdata1_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata2_trunc.begin(), pushdata2_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata4_trunc.begin(), pushdata4_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(script_cltv_truncated)
{
    const auto script_cltv_trunc = CScript() << OP_CHECKLOCKTIMEVERIFY;

    std::vector<std::vector<unsigned char>> stack_ignore;
    ScriptError err;
    BOOST_CHECK(!EvalScript(stack_ignore, script_cltv_trunc, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

static CScript
sign_multisig(const CScript& scriptPubKey, const std::vector<CKey>& keys, const CTransaction& transaction)
{
    uint256 hash = SignatureHash(scriptPubKey, transaction, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    CScript result;
    //
    // NOTE: CHECKMULTISIG has an unfortunate bug; it requires
    // one extra item on the stack, before the signatures.
    // Putting OP_0 on the stack is the workaround;
    // fixing the bug would mean splitting the block chain (old
    // clients would not accept new CHECKMULTISIG transactions,
    // and vice-versa)
    //
    result << OP_0;
    for (const CKey &key : keys)
    {
        std::vector<unsigned char> vchSig;
        BOOST_CHECK(key.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        result << vchSig;
    }
    return result;
}
static CScript
sign_multisig(const CScript& scriptPubKey, const CKey& key, const CTransaction& transaction)
{
    std::vector<CKey> keys;
    keys.push_back(key);
    return sign_multisig(scriptPubKey, keys, transaction);
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG12)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CKey key2 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CKey key3 = GenerateRandomKey(pq::SchemeId::FALCON_512);

    CScript scriptPubKey12;
    scriptPubKey12 << OP_1 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    const CTransaction txFrom12{BuildCreditingTransaction(scriptPubKey12)};
    CMutableTransaction txTo12 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom12);

    CScript goodsig1 = sign_multisig(scriptPubKey12, key1, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    txTo12.vout[0].nValue = 2;
    BOOST_CHECK(!VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    CScript goodsig2 = sign_multisig(scriptPubKey12, key2, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    CScript badsig1 = sign_multisig(scriptPubKey12, key3, CTransaction(txTo12));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG23)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CKey key2 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CKey key3 = GenerateRandomKey(pq::SchemeId::FALCON_512);
    CKey key4 = GenerateRandomKey(pq::SchemeId::FALCON_512);

    CScript scriptPubKey23;
    scriptPubKey23 << OP_2 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << ToByteVector(key3.GetPubKey()) << OP_3 << OP_CHECKMULTISIG;

    const CTransaction txFrom23{BuildCreditingTransaction(scriptPubKey23)};
    CMutableTransaction txTo23 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom23);

    std::vector<CKey> keys;
    keys.push_back(key1); keys.push_back(key2);
    CScript goodsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key3);
    CScript goodsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key3);
    CScript goodsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key2); // Can't reuse sig
    CScript badsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key1); // sigs must be in correct order
    CScript badsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key3); keys.push_back(key2); // sigs must be in correct order
    CScript badsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key4); keys.push_back(key2); // sigs must match pubkeys
    CScript badsig4 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig4, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key4); // sigs must match pubkeys
    CScript badsig5 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig5, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear(); // Must have signatures
    CScript badsig6 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig6, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL, gAllowLegacy), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_INVALID_STACK_OPERATION, ScriptErrorString(err));
}

/** Return the TxoutType of a script without exposing Solver details. */
static TxoutType GetTxoutType(const CScript& output_script)
{
    std::vector<std::vector<uint8_t>> unused;
    return Solver(output_script, unused);
}

#define CHECK_SCRIPT_STATIC_SIZE(script, expected_size)                   \
    do {                                                                  \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));              \
        BOOST_CHECK_EQUAL((script).capacity(), CScriptBase::STATIC_SIZE); \
        BOOST_CHECK_EQUAL((script).allocated_memory(), 0);                \
    } while (0)

#define CHECK_SCRIPT_DYNAMIC_SIZE(script, expected_size, expected_extra)                 \
    do {                                                                 \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));             \
        BOOST_CHECK_EQUAL((script).capacity(), (expected_extra));         \
        BOOST_CHECK_EQUAL((script).allocated_memory(), (expected_extra)); \
    } while (0)

BOOST_AUTO_TEST_CASE(script_size_and_capacity_test)
{
    // CompressedScript is prevector<21>. It is 32 bytes on 64-bit hosts and
    // 28 bytes on 32-bit hosts because the internal pointer-sized storage has
    // different alignment.
    BOOST_CHECK_EQUAL(sizeof(CompressedScript), sizeof(void*) == 4 ? 28 : 32);
    BOOST_CHECK_EQUAL(sizeof(CScriptBase), 40);
    BOOST_CHECK_NE(sizeof(CScriptBase), sizeof(prevector<CScriptBase::STATIC_SIZE + 1, uint8_t>)); // CScriptBase size should be set to avoid wasting space in padding
    BOOST_CHECK_EQUAL(sizeof(CScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CTxOut), 48);

    CKey dummy_key;
    dummy_key.MakeNewKey(pq::SchemeId::FALCON_512);
    const CPubKey dummy_pubkey{dummy_key.GetPubKey()};

    // Small OP_RETURN has direct allocation
    {
        const auto script{CScript() << OP_RETURN << std::vector<uint8_t>(10, 0xaa)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::NULL_DATA);
        CHECK_SCRIPT_STATIC_SIZE(script, 12);
    }

    // P2WPKH has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV0KeyHash{PKHash{dummy_pubkey}})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::WITNESS_V0_KEYHASH);
        CHECK_SCRIPT_STATIC_SIZE(script, 22);
    }

    // P2SH has direct allocation
    {
        const auto script{GetScriptForDestination(ScriptHash{CScript{} << OP_TRUE})};
        BOOST_CHECK(script.IsPayToScriptHash());
        CHECK_SCRIPT_STATIC_SIZE(script, 23);
    }

    // P2PKH has direct allocation
    {
        const auto script{GetScriptForDestination(PKHash{dummy_pubkey})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEYHASH);
        CHECK_SCRIPT_STATIC_SIZE(script, 25);
    }

    // P2WSH has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV0ScriptHash{CScript{} << OP_TRUE})};
        BOOST_CHECK(script.IsPayToWitnessScriptHash());
        CHECK_SCRIPT_STATIC_SIZE(script, 34);
    }

    // Bare multisig needs extra allocation
    {
        const auto script{GetScriptForMultisig(1, std::vector{2, dummy_pubkey})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::MULTISIG);
        BOOST_CHECK_GT(script.size(), CScriptBase::STATIC_SIZE);
        BOOST_CHECK_GE(script.capacity(), script.size());
        BOOST_CHECK_GT(script.allocated_memory(), 0U);
    }
}

/* Wrapper around ProduceSignature to combine two scriptsigs */
SignatureData CombineSignatures(const CTxOut& txout, const CMutableTransaction& tx, const SignatureData& scriptSig1, const SignatureData& scriptSig2)
{
    SignatureData data;
    data.MergeSignatureData(scriptSig1);
    data.MergeSignatureData(scriptSig2);
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(tx, 0, txout.nValue, SIGHASH_ALL), txout.scriptPubKey, data);
    return data;
}

BOOST_AUTO_TEST_CASE(script_combineSigs)
{
    // Test the ProduceSignature's ability to combine signatures function
    FillableSigningProvider keystore;
    std::vector<CKey> keys;
    std::vector<CPubKey> pubkeys;
    for (int i = 0; i < 3; i++)
    {
        CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
        keys.push_back(key);
        pubkeys.push_back(key.GetPubKey());
        BOOST_CHECK(keystore.AddKey(key));
    }

    CMutableTransaction txFrom = BuildCreditingTransaction(GetScriptForDestination(PKHash(keys[0].GetPubKey())));
    CMutableTransaction txTo = BuildSpendingTransaction(CScript(), CScriptWitness(), CTransaction(txFrom));
    CScript& scriptPubKey = txFrom.vout[0].scriptPubKey;
    SignatureData scriptSig;

    SignatureData empty;
    SignatureData combined = CombineSignatures(txFrom.vout[0], txTo, empty, empty);
    BOOST_CHECK(combined.scriptSig.empty());

    // Single signature case:
    SignatureData dummy;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy)); // changes scriptSig
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    SignatureData scriptSigCopy = scriptSig;
    // Signing again will give a different, valid signature:
    SignatureData dummy_b;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_b));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // P2SH, single-signature case:
    CScript pkSingle; pkSingle << ToByteVector(keys[0].GetPubKey()) << OP_CHECKSIG;
    BOOST_CHECK(keystore.AddCScript(pkSingle));
    scriptPubKey = GetScriptForDestination(ScriptHash(pkSingle));
    SignatureData dummy_c;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_c));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    scriptSigCopy = scriptSig;
    SignatureData dummy_d;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_d));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // Hardest case:  Multisig 2-of-3
    scriptPubKey = GetScriptForMultisig(2, pubkeys);
    BOOST_CHECK(keystore.AddCScript(scriptPubKey));
    SignatureData dummy_e;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_e));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);

    // A couple of partially-signed versions:
    std::vector<unsigned char> sig1;
    uint256 hash1 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_CHECK(keys[0].Sign(hash1, sig1));
    sig1.push_back(SIGHASH_ALL);
    std::vector<unsigned char> sig2;
    uint256 hash2 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_NONE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[1].Sign(hash2, sig2));
    sig2.push_back(SIGHASH_NONE);
    std::vector<unsigned char> sig3;
    uint256 hash3 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_SINGLE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[2].Sign(hash3, sig3));
    sig3.push_back(SIGHASH_SINGLE);

    // Not fussy about order (or even existence) of placeholders or signatures:
    CScript partial1a = CScript() << OP_0 << sig1 << OP_0;
    CScript partial1b = CScript() << OP_0 << OP_0 << sig1;
    CScript partial2a = CScript() << OP_0 << sig2;
    CScript partial2b = CScript() << sig2 << OP_0;
    CScript partial3a = CScript() << sig3;
    CScript partial3b = CScript() << OP_0 << OP_0 << sig3;
    CScript partial3c = CScript() << OP_0 << sig3 << OP_0;
    CScript complete12 = CScript() << OP_0 << sig1 << sig2;
    CScript complete13 = CScript() << OP_0 << sig1 << sig3;
    CScript complete23 = CScript() << OP_0 << sig2 << sig3;
    SignatureData partial1_sigs;
    partial1_sigs.signatures.emplace(keys[0].GetPubKey().GetID(), SigPair(keys[0].GetPubKey(), sig1));
    SignatureData partial2_sigs;
    partial2_sigs.signatures.emplace(keys[1].GetPubKey().GetID(), SigPair(keys[1].GetPubKey(), sig2));
    SignatureData partial3_sigs;
    partial3_sigs.signatures.emplace(keys[2].GetPubKey().GetID(), SigPair(keys[2].GetPubKey(), sig3));

    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == partial1a);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete13);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == partial3c);
}

BOOST_AUTO_TEST_CASE(script_standard_push)
{
    ScriptError err;
    for (int i=0; i<67000; i++) {
        CScript script;
        script << i;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Number " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Number " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    for (unsigned int i=0; i<=MAX_SCRIPT_ELEMENT_SIZE; i++) {
        std::vector<unsigned char> data(i, '\111');
        CScript script;
        script << data;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Length " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Length " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }
}

BOOST_AUTO_TEST_CASE(script_IsPushOnly_on_invalid_scripts)
{
    // IsPushOnly returns false when given a script containing only pushes that
    // are invalid due to truncation. IsPushOnly() is consensus critical
    // because P2SH evaluation uses it, although this specific behavior should
    // not be consensus critical as the P2SH evaluation would fail first due to
    // the invalid push. Still, it doesn't hurt to test it explicitly.
    static const unsigned char direct[] = { 1 };
    BOOST_CHECK(!CScript(direct, direct+sizeof(direct)).IsPushOnly());
}

BOOST_AUTO_TEST_CASE(script_GetScriptAsm)
{
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY));

    std::string derSig("304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c5090");
    std::string pubKey("03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2");
    std::vector<unsigned char> vchPubKey = ToByteVector(ParseHex(pubKey));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "01 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "02 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "03 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "81 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "82 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "83 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey, true));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "01 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "02 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "03 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "81 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "82 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "83 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey));
}

template <typename T>
CScript ToScript(const T& byte_container)
{
    auto span{MakeUCharSpan(byte_container)};
    return {span.begin(), span.end()};
}

BOOST_AUTO_TEST_CASE(script_byte_array_u8_vector_equivalence)
{
    const CScript scriptPubKey1 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex_v_u8 << OP_CHECKSIG;
    const CScript scriptPubKey2 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    BOOST_CHECK(scriptPubKey1 == scriptPubKey2);
}

BOOST_AUTO_TEST_CASE(script_FindAndDelete)
{
    // Exercise the FindAndDelete functionality
    CScript s;
    CScript d;
    CScript expect;

    s = CScript() << OP_1 << OP_2;
    d = CScript(); // delete nothing should be a no-op
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_1 << OP_2 << OP_3;
    d = CScript() << OP_2;
    expect = CScript() << OP_1 << OP_3;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_3 << OP_1 << OP_3 << OP_3 << OP_4 << OP_3;
    d = CScript() << OP_3;
    expect = CScript() << OP_1 << OP_4;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 4);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff03"_hex); // PUSH 0x02ff03 onto stack
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex); // PUSH 0x02ff03 PUSH 0x02ff03
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("02"_hex);
    expect = s; // FindAndDelete matches entire opcodes
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("ff"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    // This is an odd edge case: strip of the push-three-bytes
    // prefix, leaving 02ff03 which is push-two-bytes:
    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("03"_hex);
    expect = CScript() << "ff03"_hex << "ff03"_hex;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Byte sequence that spans multiple opcodes:
    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0); // doesn't match 'inside' opcodes
    BOOST_CHECK(s == expect);

    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("02feed51"_hex);
    expect = ToScript("69"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("02feed51"_hex);
    expect = ToScript("516969"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Another weird edge case:
    // End with invalid push (not enough data)...
    s = ToScript("0003feed"_hex);
    d = ToScript("03feed"_hex); // ... can remove the invalid push
    expect = ToScript("00"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0003feed"_hex);
    d = ToScript("00"_hex);
    expect = ToScript("03feed"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);
}

BOOST_AUTO_TEST_CASE(script_HasValidOps)
{
    // Exercise the HasValidOps functionality
    CScript script;
    script = ToScript("76a9141234567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex); // Normal script
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("76a914ff34567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex);
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("ff88ac"_hex); // Script with OP_INVALIDOPCODE explicit
    BOOST_CHECK(!script.HasValidOps());
    script = ToScript("88acc0"_hex); // Script with undefined opcode
    BOOST_CHECK(!script.HasValidOps());
}

BOOST_AUTO_TEST_CASE(script_op_sha512)
{
    const std::vector<unsigned char> input{0x01, 0x02, 0x03};
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err = SCRIPT_ERR_OK;

    const CScript script = CScript() << input << OP_SHA512;

    BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_SHA512, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    std::vector<unsigned char> expected(64);
    CSHA512().Write(input.data(), input.size()).Finalize(expected.data());
    BOOST_CHECK(stack.back() == expected);

    stack.clear();
    BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack.back() == input);

    stack.clear();
    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);

    stack.clear();
    const CScript empty_script = CScript() << OP_SHA512;
    BOOST_CHECK(!EvalScript(stack, empty_script, SCRIPT_VERIFY_SHA512, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    stack.clear();
    const std::vector<unsigned char> max_input(MAX_SCRIPT_ELEMENT_SIZE, 0x42);
    const CScript max_script = CScript() << max_input << OP_SHA512;
    BOOST_CHECK(EvalScript(stack, max_script, SCRIPT_VERIFY_SHA512, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK_EQUAL(stack.back().size(), 64U);

    stack.clear();
    const std::vector<unsigned char> too_big_input(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x42);
    const CScript too_big_script = CScript() << too_big_input << OP_SHA512;
    BOOST_CHECK(!EvalScript(stack, too_big_script, SCRIPT_VERIFY_SHA512, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(script_sighash_v1_512_single_oob)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;

    CScript scriptCode;
    scriptCode << OP_TRUE;

    const uint512 hash = SignatureHash512(scriptCode, tx, 0, SIGHASH_SINGLE, 0, nullptr);
    BOOST_CHECK(hash == uint512::ONE);
}

BOOST_AUTO_TEST_CASE(script_sighash_v1_512_zero_rejected)
{
    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    FlatSigningProvider provider;
    const CPubKey pubkey = key.GetPubKey();
    provider.keys.emplace(pubkey.GetID(), key);
    provider.pubkeys.emplace(pubkey.GetID(), pubkey);

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(1);

    CScript scriptCode = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;

    MutableTransactionSignatureCreator creator(tx, 0, /*amount=*/1, 0);
    std::vector<unsigned char> sig;
    BOOST_CHECK(!creator.CreateSig(provider, sig, pubkey.GetID(), scriptCode, SigVersion::WITNESS_V1_512));
}

BOOST_AUTO_TEST_CASE(pq_falcon_legacy_boundary_fixture_spans_strict_and_legacy_bounds)
{
    CKey key0;
    {
        const std::vector<unsigned char> key0_secret{ParseHex(std::string{SCRIPT_BUILD_KEY0_SECRET_HEX})};
        key0.Set(key0_secret.begin(), key0_secret.end());
        BOOST_REQUIRE(key0.IsValid());
    }
    const CPubKey pubkey0 = key0.GetPubKey();

    const CScript strict_script = CScript() << ToByteVector(pubkey0) << OP_CHECKSIG;
    const CTransaction tx_credit{BuildCreditingTransaction(strict_script, /*nValue=*/0)};
    const CMutableTransaction tx_spend = BuildSpendingTransaction(CScript(), CScriptWitness(), tx_credit);
    const uint256 sighash = SignatureHash(strict_script, tx_spend, 0, SIGHASH_ALL, /*amount=*/0, SigVersion::BASE);

    const std::vector<unsigned char> sig_with_hashtype = ParseHex(std::string{LEGACY_ONLY_STRICT_DIFF_SIG_HEX});
    BOOST_REQUIRE(!sig_with_hashtype.empty());
    BOOST_REQUIRE_EQUAL(sig_with_hashtype.back(), SIGHASH_ALL);
    const std::span<const unsigned char> msg{sighash.begin(), sighash.size()};
    const std::vector<unsigned char> sig_no_hashtype(sig_with_hashtype.begin(), sig_with_hashtype.end() - 1);
    const std::span<const unsigned char> sig{sig_no_hashtype.data(), sig_no_hashtype.size()};
    const std::span<const unsigned char> raw_pk{pubkey0.begin() + 1, pubkey0.size() - 1};

    BOOST_CHECK(!pubkey0.Verify(sighash, sig_no_hashtype, /*legacy_mode=*/false));
    BOOST_CHECK(pubkey0.Verify(sighash, sig_no_hashtype, /*legacy_mode=*/true));

    union {
        uint8_t b[2 * 512];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    uint16_t h[512], hm[512];
    int16_t sig_dec[512];
    inner_shake256_context sc;

    BOOST_REQUIRE(sig.size() >= 1 + 40);
    const uint8_t* const nonce = sig.data() + 1;
    const uint8_t* const sigbuf = sig.data() + 1 + 40;
    const size_t sigbuflen = sig.size() - 1 - 40;

    BOOST_REQUIRE_EQUAL(raw_pk[0], 0x00 + 9);
    BOOST_REQUIRE_EQUAL(PQCLEAN_FALCON512_CLEAN_modq_decode(
                            h, 9, raw_pk.data() + 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1),
                        PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1);
    PQCLEAN_FALCON512_CLEAN_to_ntt_monty(h, 9);

    BOOST_REQUIRE_EQUAL(PQCLEAN_FALCON512_CLEAN_comp_decode(sig_dec, 9, sigbuf, sigbuflen), sigbuflen);

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, 40);
    inner_shake256_inject(&sc, msg.data(), msg.size());
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc, hm, 9, tmp.b);
    inner_shake256_ctx_release(&sc);

    BOOST_CHECK(!PQCLEAN_FALCON512_CLEAN_verify_raw(hm, sig_dec, h, 9, tmp.b));

    const int16_t* const s1 = reinterpret_cast<const int16_t*>(tmp.b);
    uint32_t sqnorm = 0;
    uint32_t overflow = 0;
    for (size_t i = 0; i < 512; ++i) {
        int32_t z = s1[i];
        sqnorm += static_cast<uint32_t>(z * z);
        overflow |= sqnorm;
        z = sig_dec[i];
        sqnorm += static_cast<uint32_t>(z * z);
        overflow |= sqnorm;
    }
    sqnorm |= -(overflow >> 31);

    constexpr uint32_t strict_bound = 34034726;
    constexpr uint32_t legacy_bound = static_cast<uint32_t>(((uint64_t)7085 * 12289) >> 1);
    BOOST_CHECK_GT(sqnorm, strict_bound);
    BOOST_CHECK_LT(sqnorm, legacy_bound);
}

BOOST_AUTO_TEST_CASE(script_witness_v1_512_preauxpow_policy)
{
    const CScript witness_script = CScript() << OP_TRUE;
    std::vector<unsigned char> program(WITNESS_V1_SCRIPTHASH_512_SIZE);
    CSHA512().Write(witness_script.data(), witness_script.size()).Finalize(program.data());

    const CScript script_pub_key = CScript() << OP_1 << program;
    CScriptWitness witness;
    witness.stack.emplace_back(witness_script.begin(), witness_script.end());

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(CScript(), script_pub_key, &witness, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), &err));

    err = SCRIPT_ERR_OK;
    BOOST_CHECK(!VerifyScript(CScript(), script_pub_key, &witness, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker(), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
}

BOOST_AUTO_TEST_SUITE_END()
