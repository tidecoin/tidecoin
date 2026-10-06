// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <core_io.h>
#include <interfaces/chain.h>
#include <key.h>
#include <key_io.h>
#include <node/context.h>
#include <node/blockstorage.h>
#include <pq/pq_api.h>
#include <rpc/blockchain.h>
#include <rpc/client.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <array>
#include <any>
#include <tuple>

#include <boost/test/unit_test.hpp>

using util::SplitString;

static UniValue JSON(std::string_view json)
{
    UniValue value;
    BOOST_CHECK(value.read(json));
    return value;
}

class HasJSON
{
public:
    explicit HasJSON(std::string json) : m_json(std::move(json)) {}
    bool operator()(const UniValue& value) const
    {
        std::string json{value.write()};
        BOOST_CHECK_EQUAL(json, m_json);
        return json == m_json;
    };

private:
    const std::string m_json;
};

class RPCTestingSetup : public TestingSetup
{
public:
    UniValue TransformParams(const UniValue& params, std::vector<std::pair<std::string, bool>> arg_names) const;
    UniValue CallRPC(std::string args);
};

UniValue RPCTestingSetup::TransformParams(const UniValue& params, std::vector<std::pair<std::string, bool>> arg_names) const
{
    UniValue transformed_params;
    CRPCTable table;
    CRPCCommand command{"category", "method", [&](const JSONRPCRequest& request, UniValue&, bool) -> bool { transformed_params = request.params; return true; }, arg_names, /*unique_id=*/0};
    table.appendCommand("method", &command);
    JSONRPCRequest request;
    request.strMethod = "method";
    request.params = params;
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    table.execute(request);
    return transformed_params;
}

UniValue RPCTestingSetup::CallRPC(std::string args)
{
    std::vector<std::string> vArgs{SplitString(args, ' ')};
    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = strMethod;
    request.params = RPCConvertValues(strMethod, vArgs);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    try {
        UniValue result = tableRPC.execute(request);
        return result;
    }
    catch (const UniValue& objError) {
        throw std::runtime_error(objError.find_value("message").get_str());
    }
}


BOOST_FIXTURE_TEST_SUITE(rpc_tests, RPCTestingSetup)

BOOST_AUTO_TEST_CASE(descriptor_range_boundaries)
{
    for (const auto& [input, low, high] : std::vector<std::tuple<std::string, int64_t, int64_t>>{
             {"0", 0, 0}, {"999999", 0, 999999}, {"[7,8]", 7, 8},
             {"[2147483647,2147483647]", INT32_MAX, INT32_MAX},
             {"[2147483646,2147483647]", INT32_MAX - 1, INT32_MAX},
             {"[2146483648,2147483647]", INT32_MAX - 999999, INT32_MAX}}) {
        const auto range = ParseDescriptorRange(JSON(input));
        BOOST_CHECK_EQUAL(range.first, low);
        BOOST_CHECK_EQUAL(range.second, high);
    }
    for (const auto& [input, message] : std::vector<std::pair<std::string, std::string>>{
             {"[]", "Range must be specified as end or as [begin,end]"},
             {"[0,1,2]", "Range must be specified as end or as [begin,end]"},
             {"[0,\"1\"]", "Range must be specified as end or as [begin,end]"},
             {"[-1,0]", "Range should be greater or equal than 0"},
             {"[2,1]", "Range specified as [begin,end] must not have begin after end"},
             {"-1", "End of range is too high"},
             {"[2147483647,2147483648]", "End of range is too high"},
             {"[0,9223372036854775807]", "End of range is too high"},
             {"1000000", "Range is too large"},
             {"[2146483647,2147483647]", "Range is too large"}}) {
        BOOST_CHECK_EXCEPTION(ParseDescriptorRange(JSON(input)), UniValue,
                              HasJSON("{\"code\":-8,\"message\":\"" + message + "\"}"));
    }
}

BOOST_AUTO_TEST_CASE(descriptor_range_expansion)
{
    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("raw(51)", provider, error);
    auto second = Parse("raw(52)", provider, error);
    BOOST_REQUIRE_EQUAL(descs.size(), 1U);
    BOOST_REQUIRE_EQUAL(second.size(), 1U);
    descs.push_back(std::move(second.front()));
    for (const bool expand_priv : {false, true}) {
        const auto single = ExpandDescriptorRange(descs, {1, 1}, provider, provider, expand_priv);
        BOOST_REQUIRE(single.has_value());
        BOOST_CHECK(*single == std::vector<CScript>({CScript() << OP_TRUE, CScript() << OP_2}));
        const auto pair = ExpandDescriptorRange(descs, {0, 1}, provider, provider, expand_priv);
        BOOST_REQUIRE(pair.has_value());
        BOOST_CHECK(*pair == std::vector<CScript>({CScript() << OP_TRUE, CScript() << OP_2, CScript() << OP_TRUE, CScript() << OP_2}));
        // The public entry point still normalizes a fixed descriptor to index 0.
        const auto fixed = EvalDescriptorStringOrObject(JSON(R"json({"desc":"raw(51)","range":[2147483647,2147483647]})json"), provider, expand_priv);
        BOOST_CHECK(fixed == std::vector<CScript>({CScript() << OP_TRUE}));
    }

    // Bound the work even if the counter regresses and wraps: private expansion
    // calls GetKey once per index, so an unexpected extra iteration throws.
    struct BoundedProvider : SigningProvider {
        CKey key;
        mutable int remaining{0};
        bool GetKey(const CKeyID& id, CKey& out_key) const override
        {
            if (remaining-- <= 0) throw std::runtime_error("Descriptor range expanded past its endpoint");
            if (id != key.GetPubKey().GetID()) return false;
            out_key = key;
            return true;
        }
    } bounded;
    bounded.key.MakeNewKey(pq::SchemeId::FALCON_512);
    auto terminal_desc = Parse("pkh(" + HexStr(bounded.key.GetPubKey()) + ")", provider, error);
    BOOST_REQUIRE_EQUAL(terminal_desc.size(), 1U);
    const CScript expected = GetScriptForDestination(PKHash(bounded.key.GetPubKey()));
    for (const int count : {1, 2}) {
        bounded.remaining = count;
        const auto scripts = ExpandDescriptorRange(terminal_desc, {int64_t{INT32_MAX} - count + 1, INT32_MAX}, bounded, provider, /*expand_priv=*/true);
        BOOST_REQUIRE(scripts.has_value());
        BOOST_CHECK(*scripts == std::vector<CScript>(count, expected));
        BOOST_CHECK_EQUAL(bounded.remaining, 0);
    }

    const std::string pqhd_desc = "wpkh(pqhd(" + std::string(64, '0') + ")/10007h/6868h/7h/0h/0h/*h)";
    auto ranged = Parse(pqhd_desc, provider, error);
    BOOST_REQUIRE_EQUAL(ranged.size(), 1U);
    BOOST_REQUIRE(ranged.front()->IsRange());
    BOOST_CHECK(!ExpandDescriptorRange(ranged, {INT32_MAX, INT32_MAX}, provider, provider, false));
    UniValue scan{UniValue::VOBJ};
    scan.pushKV("desc", pqhd_desc);
    scan.pushKV("range", JSON("[2147483647,2147483647]"));
    BOOST_CHECK_EXCEPTION(EvalDescriptorStringOrObject(scan, provider), UniValue,
                          HasJSON("{\"code\":-5,\"message\":\"PQHD expansion requires wallet seed access or cached public keys.\"}"));
}

BOOST_AUTO_TEST_CASE(descriptor_rpc_resolution)
{
    FlatSigningProvider provider;
    std::string error;
    const auto pqhd = Parse("wpkh(pqhd(" + std::string(64, '0') + ")/10007h/6868h/7h/0h/0h/*h)", provider, error);
    BOOST_REQUIRE_EQUAL(pqhd.size(), 1U);
    JSONRPCRequest request;
    request.context = &m_node;
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    RPCDescriptorResolver resolver{request};
    BOOST_CHECK_EXCEPTION(resolver.Expand(*pqhd[0], 0, provider, scripts, out), UniValue,
        HasJSON(R"({"code":-5,"message":"PQHD expansion requires wallet seed access or cached public keys. Select the owning wallet explicitly with -rpcwallet."})"));
    BOOST_CHECK(scripts.empty());
    BOOST_CHECK(out.keys.empty());

    // An explicit endpoint must not fall back to another wallet or to a seed
    // supplied by a node-only provider. This fixture has no wallet loader.
    BOOST_REQUIRE(m_node.wallet_loader == nullptr);
    request.URI = "/wallet/selected";
    BOOST_CHECK_EXCEPTION(resolver.Expand(*pqhd[0], 0, provider, scripts, out), UniValue,
        HasJSON(R"({"code":-18,"message":"Wallet support is not available"})"));

    // Self-contained scripts remain independent of the selected wallet.
    const auto fixed = Parse("raw(51)", provider, error);
    BOOST_REQUIRE_EQUAL(fixed.size(), 1U);
    BOOST_REQUIRE(resolver.Expand(*fixed[0], 0, provider, scripts, out));
    BOOST_CHECK(scripts == std::vector<CScript>{CScript{} << OP_TRUE});
    resolver.Finish();

    int interruptions{0};
    RPCDescriptorResolver interrupted{request, [&] {
        ++interruptions;
        throw std::runtime_error("test abort");
    }};
    BOOST_CHECK_THROW(interrupted.Expand(*fixed[0], 0, provider, scripts, out), std::runtime_error);
    BOOST_CHECK_EQUAL(interruptions, 1);

    // The shared range path must invoke the resolver at every inclusive index,
    // including INT32_MAX, and propagate interruption without a partial result.
    std::vector<int32_t> indices;
    const DescriptorExpandFn expand = [&](const Descriptor& desc, int32_t index, const SigningProvider&, std::vector<CScript>& result, FlatSigningProvider&) {
        BOOST_CHECK_EQUAL(desc.ToString(), pqhd[0]->ToString());
        indices.push_back(index);
        result = {CScript{} << OP_TRUE};
        return true;
    };
    auto expanded = ExpandDescriptorRange(pqhd, {INT32_MAX - 1, INT32_MAX}, provider, out, false, expand);
    BOOST_REQUIRE(expanded.has_value());
    BOOST_CHECK_EQUAL(expanded->size(), 2U);
    BOOST_CHECK(indices == std::vector<int32_t>({INT32_MAX - 1, INT32_MAX}));
    const DescriptorExpandFn abort = [&](const Descriptor&, int32_t index, const SigningProvider&, std::vector<CScript>& result, FlatSigningProvider&) {
        if (index == INT32_MAX) throw std::runtime_error("test abort");
        result = {CScript{} << OP_TRUE};
        return true;
    };
    BOOST_CHECK_THROW(ExpandDescriptorRange(pqhd, {INT32_MAX - 1, INT32_MAX}, provider, out, false, abort), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_namedparams)
{
    const std::vector<std::pair<std::string, bool>> arg_names{{"arg1", false}, {"arg2", false}, {"arg3", false}, {"arg4", false}, {"arg5", false}};

    // Make sure named arguments are transformed into positional arguments in correct places separated by nulls
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg2": 2, "arg4": 4})"), arg_names).write(), "[null,2,null,4]");

    // Make sure named argument specified multiple times raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg2": 2, "arg2": 4})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter arg2 specified multiple times"})"));

    // Make sure named and positional arguments can be combined.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg5": 5, "args": [1, 2], "arg4": 4})"), arg_names).write(), "[1,2,null,4,5]");

    // Make sure a unknown named argument raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg2": 2, "unknown": 6})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Unknown named parameter unknown"})"));

    // Make sure an overlap between a named argument and positional argument raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"args": [1,2,3], "arg4": 4, "arg2": 2})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter arg2 specified twice both as positional and named argument"})"));

    // Make sure extra positional arguments can be passed through to the method implementation, as long as they don't overlap with named arguments.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"args": [1,2,3,4,5,6,7,8,9,10]})"), arg_names).write(), "[1,2,3,4,5,6,7,8,9,10]");
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"([1,2,3,4,5,6,7,8,9,10])"), arg_names).write(), "[1,2,3,4,5,6,7,8,9,10]");
}

BOOST_AUTO_TEST_CASE(rpc_namedonlyparams)
{
    const std::vector<std::pair<std::string, bool>> arg_names{{"arg1", false}, {"arg2", false}, {"opt1", true}, {"opt2", true}, {"options", false}};

    // Make sure optional parameters are really optional.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2})"), arg_names).write(), "[1,2]");

    // Make sure named-only parameters are passed as options.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "opt1": 10, "opt2": 20})"), arg_names).write(), R"([1,2,{"opt1":10,"opt2":20}])");

    // Make sure options can be passed directly.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "options":{"opt1": 10, "opt2": 20}})"), arg_names).write(), R"([1,2,{"opt1":10,"opt2":20}])");

    // Make sure options and named parameters conflict.
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "opt1": 10, "options":{"opt1": 10}})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter options conflicts with parameter opt1"})"));

    // Make sure options object specified through args array conflicts.
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"args": [1, 2, {"opt1": 10}], "opt2": 20})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter options specified twice both as positional and named argument"})"));
}

BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    UniValue r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed not_int"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {}"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [] {}"));
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] {} extra"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), std::runtime_error);
    std::string rawtx = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx));
    BOOST_CHECK_EQUAL(r.get_obj().find_value("size").getInt<int>(), 193);
    BOOST_CHECK_EQUAL(r.get_obj().find_value("version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(r.get_obj().find_value("locktime").getInt<int>(), 0);
    BOOST_CHECK_THROW(CallRPC(std::string("decoderawtransaction ")+rawtx+" extra"), std::runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false"));
    BOOST_CHECK_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false extra"), std::runtime_error);

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(std::string("sendrawtransaction ")+rawtx+" extra"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_togglenetwork)
{
    UniValue r;

    r = CallRPC("getnetworkinfo");
    bool netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive false"));
    r = CallRPC("getnetworkinfo");
    int numConnection = r.get_obj().find_value("connections").getInt<int>();
    BOOST_CHECK_EQUAL(numConnection, 0);

    netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, false);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive true"));
    r = CallRPC("getnetworkinfo");
    netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    UniValue r;
    auto make_key = [](uint8_t tag) {
        std::array<uint8_t, 64> material{};
        for (size_t i = 0; i < material.size(); ++i) {
            material[i] = static_cast<uint8_t>(tag ^ static_cast<uint8_t>(i * 131));
        }
        std::vector<uint8_t> pk_raw;
        pq::SecureKeyBytes sk_raw;
        BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1,
                                         pq::SchemeId::FALCON_512,
                                         material,
                                         pk_raw,
                                         sk_raw));
        CPrivKey sk_encoded;
        BOOST_REQUIRE(pq::EncodeSecretKey(pq::kFalcon512Info,
                                          std::span<const unsigned char>{sk_raw.data(), sk_raw.size()},
                                          sk_encoded));
        CKey key;
        key.Set(sk_encoded.begin(), sk_encoded.end());
        BOOST_REQUIRE(key.IsValid());
        return key;
    };

    // input is a 1-of-2 PQ multisig (so is output):
    const CKey key1 = make_key(1);
    const CKey key2 = make_key(2);
    const CPubKey pubkey1 = key1.GetPubKey();
    const CPubKey pubkey2 = key2.GetPubKey();
    const CScript redeem_script = CScript() << OP_1
                                           << ToByteVector(pubkey1)
                                           << ToByteVector(pubkey2)
                                           << OP_2 << OP_CHECKMULTISIG;
    const CScript script_pubkey = GetScriptForDestination(ScriptHash(redeem_script));
    const std::string p2sh_addr = EncodeDestination(ScriptHash(redeem_script));
    const std::string prevout = strprintf(
        "[{\"txid\":\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b7248f50977c8493f3\","
        "\"vout\":1,\"scriptPubKey\":\"%s\",\"redeemScript\":\"%s\"}]",
        HexStr(script_pubkey), HexStr(redeem_script));
    r = CallRPC(strprintf("createrawtransaction %s {\"%s\":11}", prevout, p2sh_addr));
    std::string notsigned = r.get_str();
    std::string privkey1 = strprintf("\"%s\"", EncodeSecret(key1));
    std::string privkey2 = strprintf("\"%s\"", EncodeSecret(key2));
    r = CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" [] "+prevout);
    BOOST_CHECK(r.get_obj().find_value("complete").get_bool() == false);
    r = CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" ["+privkey1+","+privkey2+"] "+prevout);
    BOOST_CHECK(r.get_obj().find_value("complete").get_bool() == true);
}

BOOST_AUTO_TEST_CASE(rpc_createraw_op_return)
{
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"68656c6c6f776f726c64\"}"));

    // Key not "data" (bad address)
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"somedata\":\"68656c6c6f776f726c64\"}"), std::runtime_error);

    // Bad hex encoding of data output
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"12345\"}"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"12345g\"}"), std::runtime_error);

    // Data 81 bytes long
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081\"}"));
}

BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(0LL).write() == "0.00000000");
    BOOST_CHECK(ValueFromAmount(1LL).write() == "0.00000001");
    BOOST_CHECK(ValueFromAmount(17622195LL).write() == "0.17622195");
    BOOST_CHECK(ValueFromAmount(50000000LL).write() == "0.50000000");
    BOOST_CHECK(ValueFromAmount(89898989LL).write() == "0.89898989");
    BOOST_CHECK(ValueFromAmount(100000000LL).write() == "1.00000000");
    BOOST_CHECK(ValueFromAmount(2099999999999990LL).write() == "20999999.99999990");
    BOOST_CHECK(ValueFromAmount(2099999999999999LL).write() == "20999999.99999999");

    BOOST_CHECK_EQUAL(ValueFromAmount(0).write(), "0.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount((COIN/10000)*123456789).write(), "12345.67890000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN).write(), "-1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN/10).write(), "-0.10000000");

    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000000).write(), "100000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000000).write(), "10000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000000).write(), "1000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000).write(), "100000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000).write(), "10000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000).write(), "1000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100).write(), "100.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10).write(), "10.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN).write(), "1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10).write(), "0.10000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100).write(), "0.01000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000).write(), "0.00100000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000).write(), "0.00010000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000).write(), "0.00001000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000000).write(), "0.00000100");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000000).write(), "0.00000010");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000000).write(), "0.00000001");

    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max()).write(), "92233720368.54775807");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 1).write(), "92233720368.54775806");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 2).write(), "92233720368.54775805");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 3).write(), "92233720368.54775804");
    // ...
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 3).write(), "-92233720368.54775805");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 2).write(), "-92233720368.54775806");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 1).write(), "-92233720368.54775807");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min()).write(), "-92233720368.54775808");
}

static UniValue ValueFromString(const std::string& str) noexcept
{
    UniValue value;
    value.setNumStr(str);
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("-0.00000001")), UniValue);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001")), 1LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.17622195")), 17622195LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.5")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.50000000")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.89898989")), 89898989LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1.00000000")), 100000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.9999999")), 2099999999999990LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.99999999")), 2099999999999999LL);

    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1e-8")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.1e-7")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01e-6")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000000000000000000000000000000001e+30")), 1);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.0000000000000000000000000000000000000000000000000000000000000000000000000001e+68")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("10000000000000000000000000000000000000000000000000000000000000000e-64")), COIN);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000e64")), COIN);

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e-9")), UniValue); //should fail
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("0.000000019")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001000000")), 1LL); //should pass, cut trailing 0
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("19e-9")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.19e-6")), 19); //should pass, leading 0 is present
    BOOST_CHECK_EXCEPTION(AmountFromValue(".19e-6"), UniValue, HasJSON(R"({"code":-3,"message":"Invalid amount"})")); //should fail, no leading 0

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("92233720368.54775808")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e+11")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e11")), UniValue); //overflow error signless
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("93e+9")), UniValue); //overflow error
}

BOOST_AUTO_TEST_CASE(rpc_ban)
{
    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.0:8334")), std::runtime_error); //portnumber for setban not allowed
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    UniValue ar = r.get_array();
    UniValue o1 = ar[0].get_obj();
    UniValue adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/32");
    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 9907731200 true")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    int64_t banned_until{o1.find_value("banned_until").getInt<int64_t>()};
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until, 9907731200); // absolute time check

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    auto now = 10'000s;
    SetMockTime(now);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 200")));
    SetMockTime(now += 2s);
    const int64_t time_remaining_expected{198};
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    banned_until = o1.find_value("banned_until").getInt<int64_t>();
    const int64_t ban_created{o1.find_value("ban_created").getInt<int64_t>()};
    const int64_t ban_duration{o1.find_value("ban_duration").getInt<int64_t>()};
    const int64_t time_remaining{o1.find_value("time_remaining").getInt<int64_t>()};
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until, time_remaining_expected + now.count());
    BOOST_CHECK_EQUAL(ban_duration, banned_until - ban_created);
    BOOST_CHECK_EQUAL(time_remaining, time_remaining_expected);

    // must throw an exception because 127.0.0.1 is in already banned subnet range
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0/24 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/255.255.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.1.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);


    BOOST_CHECK_THROW(r = CallRPC(std::string("setban test add")), std::runtime_error); //invalid IP

    //IPv6 tests
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban FE80:0000:0000:0000:0202:B3FF:FE1E:8329 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "fe80::202:b3ff:fe1e:8329/128");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:db8::/ffff:fffc:0:0:0:0:0:0 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:db8::/30");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128");
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_generatetoaddress)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"1", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a", "9"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 9);

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"1", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU", "9"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 9);
}

BOOST_AUTO_TEST_CASE(rpc_getblockstats_calculate_percentiles_by_weight)
{
    int64_t total_weight = 200;
    std::vector<std::pair<CAmount, int64_t>> feerates;
    feerates.reserve(200);
    CAmount result[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(1 ,1);
    }

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(2 ,1);
    }

    CalculatePercentilesByWeight(result, feerates, total_weight);
    BOOST_CHECK_EQUAL(result[0], 1);
    BOOST_CHECK_EQUAL(result[1], 1);
    BOOST_CHECK_EQUAL(result[2], 1);
    BOOST_CHECK_EQUAL(result[3], 2);
    BOOST_CHECK_EQUAL(result[4], 2);

    // Test with more pairs, and two pairs overlapping 2 percentiles.
    total_weight = 100;
    CAmount result2[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 9);
    feerates.emplace_back(2 , 16); //10th + 25th percentile
    feerates.emplace_back(4 ,50); //50th + 75th percentile
    feerates.emplace_back(5 ,10);
    feerates.emplace_back(9 ,15);  // 90th percentile

    CalculatePercentilesByWeight(result2, feerates, total_weight);

    BOOST_CHECK_EQUAL(result2[0], 2);
    BOOST_CHECK_EQUAL(result2[1], 2);
    BOOST_CHECK_EQUAL(result2[2], 4);
    BOOST_CHECK_EQUAL(result2[3], 4);
    BOOST_CHECK_EQUAL(result2[4], 9);

    // Same test as above, but one of the percentile-overlapping pairs is split in 2.
    total_weight = 100;
    CAmount result3[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 9);
    feerates.emplace_back(2 , 11); // 10th percentile
    feerates.emplace_back(2 , 5); // 25th percentile
    feerates.emplace_back(4 ,50); //50th + 75th percentile
    feerates.emplace_back(5 ,10);
    feerates.emplace_back(9 ,15); // 90th percentile

    CalculatePercentilesByWeight(result3, feerates, total_weight);

    BOOST_CHECK_EQUAL(result3[0], 2);
    BOOST_CHECK_EQUAL(result3[1], 2);
    BOOST_CHECK_EQUAL(result3[2], 4);
    BOOST_CHECK_EQUAL(result3[3], 4);
    BOOST_CHECK_EQUAL(result3[4], 9);

    // Test with one transaction spanning all percentiles.
    total_weight = 104;
    CAmount result4[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 100);
    feerates.emplace_back(2, 1);
    feerates.emplace_back(3, 1);
    feerates.emplace_back(3, 1);
    feerates.emplace_back(999999, 1);

    CalculatePercentilesByWeight(result4, feerates, total_weight);

    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        BOOST_CHECK_EQUAL(result4[i], 1);
    }
}

// Make sure errors are triggered appropriately if parameters have the same names.
BOOST_AUTO_TEST_CASE(check_dup_param_names)
{
    enum ParamType { POSITIONAL, NAMED, NAMED_ONLY };
    auto make_rpc = [](std::vector<std::tuple<std::string, ParamType>> param_names) {
        std::vector<RPCArg> params;
        std::vector<RPCArg> options;
        auto push_options = [&] { if (!options.empty()) params.emplace_back(strprintf("options%i", params.size()), RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", std::move(options)); };
        for (auto& [param_name, param_type] : param_names) {
            if (param_type == POSITIONAL) {
                push_options();
                params.emplace_back(std::move(param_name), RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "description");
            } else {
                options.emplace_back(std::move(param_name), RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "description", RPCArgOptions{.also_positional = param_type == NAMED});
            }
        }
        push_options();
        return RPCHelpMan{"method_name", "description", params, RPCResults{}, RPCExamples{""}};
    };

    // No errors if parameter names are unique.
    make_rpc({{"p1", POSITIONAL}, {"p2", POSITIONAL}});
    make_rpc({{"p1", POSITIONAL}, {"p2", NAMED}});
    make_rpc({{"p1", POSITIONAL}, {"p2", NAMED_ONLY}});
    make_rpc({{"p1", NAMED}, {"p2", POSITIONAL}});
    make_rpc({{"p1", NAMED}, {"p2", NAMED}});
    make_rpc({{"p1", NAMED}, {"p2", NAMED_ONLY}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", POSITIONAL}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", NAMED}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", NAMED_ONLY}});

    // Error if parameters names are duplicates, unless one parameter is
    // positional and the other is named and .also_positional is true.
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p1", POSITIONAL}}), NonFatalCheckError);
    make_rpc({{"p1", POSITIONAL}, {"p1", NAMED}});
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
    make_rpc({{"p1", NAMED}, {"p1", POSITIONAL}});
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED}, {"p1", NAMED}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", POSITIONAL}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", NAMED}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", NAMED_ONLY}}), NonFatalCheckError);

    // Make sure duplicate aliases are detected too.
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p2|p1", NAMED_ONLY}}), NonFatalCheckError);
}

BOOST_AUTO_TEST_CASE(help_example)
{
    // test different argument types
    const RPCArgList& args = {{"foo", "bar"}, {"b", true}, {"n", 1}};
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", args), "> tidecoin-cli -named test foo=bar b=true n=1\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", args), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"foo\":\"bar\",\"b\":true,\"n\":1}}' -H 'content-type: application/json' http://127.0.0.1:8332/\n");

    // test shell escape
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b'ar"}}), "> tidecoin-cli -named test foo='b'''ar'\n");
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b\"ar"}}), "> tidecoin-cli -named test foo='b\"ar'\n");
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b ar"}}), "> tidecoin-cli -named test foo='b ar'\n");

    // test object params
    UniValue obj_value(UniValue::VOBJ);
    obj_value.pushKV("foo", "bar");
    obj_value.pushKV("b", false);
    obj_value.pushKV("n", 1);
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"name", obj_value}}), "> tidecoin-cli -named test name='{\"foo\":\"bar\",\"b\":false,\"n\":1}'\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", {{"name", obj_value}}), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"name\":{\"foo\":\"bar\",\"b\":false,\"n\":1}}}' -H 'content-type: application/json' http://127.0.0.1:8332/\n");

    // test array params
    UniValue arr_value(UniValue::VARR);
    arr_value.push_back("bar");
    arr_value.push_back(false);
    arr_value.push_back(1);
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"name", arr_value}}), "> tidecoin-cli -named test name='[\"bar\",false,1]'\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", {{"name", arr_value}}), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"name\":[\"bar\",false,1]}}' -H 'content-type: application/json' http://127.0.0.1:8332/\n");

    // test types don't matter for shell
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("foo", {{"arg", true}}), HelpExampleCliNamed("foo", {{"arg", "true"}}));

    // test types matter for Rpc
    BOOST_CHECK_NE(HelpExampleRpcNamed("foo", {{"arg", true}}), HelpExampleRpcNamed("foo", {{"arg", "true"}}));
}

static void CheckRpc(const std::vector<RPCArg>& params, const UniValue& args, RPCHelpMan::RPCMethodImpl test_impl)
{
    auto null_result{RPCResult{RPCResult::Type::NONE, "", "None"}};
    const RPCHelpMan rpc{"dummy", "dummy description", params, null_result, RPCExamples{""}, test_impl};
    JSONRPCRequest req;
    req.params = args;

    rpc.HandleRequest(req);
}

BOOST_AUTO_TEST_CASE(rpc_arg_helper)
{
    constexpr bool DEFAULT_BOOL = true;
    constexpr auto DEFAULT_STRING = "default";
    constexpr uint64_t DEFAULT_UINT64_T = 3;

    //! Parameters with which the RPCHelpMan is instantiated
    const std::vector<RPCArg> params{
        // Required arg
        {"req_int", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
        {"req_str", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
        // Default arg
        {"def_uint64_t", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_UINT64_T}, ""},
        {"def_string", RPCArg::Type::STR, RPCArg::Default{DEFAULT_STRING}, ""},
        {"def_bool", RPCArg::Type::BOOL, RPCArg::Default{DEFAULT_BOOL}, ""},
        // Optional arg without default
        {"opt_double", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
        {"opt_string", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""}
    };

    //! Check that `self.Arg` returns the same value as the `request.params` accessors
    RPCHelpMan::RPCMethodImpl check_positional = [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            BOOST_CHECK_EQUAL(self.Arg<int>("req_int"), request.params[0].getInt<int>());
            BOOST_CHECK_EQUAL(self.Arg<std::string>("req_str"), request.params[1].get_str());
            BOOST_CHECK_EQUAL(self.Arg<uint64_t>("def_uint64_t"), request.params[2].isNull() ? DEFAULT_UINT64_T : request.params[2].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(self.Arg<std::string>("def_string"), request.params[3].isNull() ? DEFAULT_STRING : request.params[3].get_str());
            BOOST_CHECK_EQUAL(self.Arg<bool>("def_bool"), request.params[4].isNull() ? DEFAULT_BOOL : request.params[4].get_bool());
            if (!request.params[5].isNull()) {
                BOOST_CHECK_EQUAL(self.MaybeArg<double>("opt_double").value(), request.params[5].get_real());
            } else {
                BOOST_CHECK(!self.MaybeArg<double>("opt_double"));
            }
            if (!request.params[6].isNull()) {
                BOOST_CHECK(self.MaybeArg<std::string>("opt_string"));
                BOOST_CHECK_EQUAL(*self.MaybeArg<std::string>("opt_string"), request.params[6].get_str());
            } else {
                BOOST_CHECK(!self.MaybeArg<std::string>("opt_string"));
            }
            return UniValue{};
        };
    CheckRpc(params, UniValue{JSON(R"([5, "hello", null, null, null, null, null])")}, check_positional);
    CheckRpc(params, UniValue{JSON(R"([5, "hello", 4, "test", true, 1.23, "world"])")}, check_positional);
}

BOOST_FIXTURE_TEST_CASE(historical_snapshot_isolation_and_interruption, TestChain100Setup)
{
    auto& chainstate = m_node.chainman->ActiveChainstate();
    const auto* target = WITH_LOCK(cs_main, return chainstate.m_chain.Tip());
    const auto baseline_path = m_args.GetDataDirNet() / "baseline.dat";
    m_node.rpc_interruption_point = [] {};
    AutoFile baseline_file{fsbridge::fopen(baseline_path, "wb")};
    auto baseline = CreateUTXOSnapshot(m_node, chainstate, std::move(baseline_file), baseline_path, baseline_path);
    mineBlocks(10);
    const auto* tip = WITH_LOCK(cs_main, return chainstate.m_chain.Tip());
    const auto path = m_args.GetDataDirNet() / "rollback.dat";
    const auto check_cleanup = [&] {
        for (const auto& entry : fs::directory_iterator(path.parent_path())) {
            BOOST_CHECK(!fs::PathToString(entry.path().filename()).starts_with("temp_utxo_"));
        }
        BOOST_CHECK(WITH_LOCK(cs_main, return chainstate.m_chain.Tip() == tip));
        BOOST_CHECK(WITH_LOCK(cs_main, return !(tip->nStatus & BLOCK_FAILED_VALID)));
    };
    size_t calls{0};
    m_node.rpc_interruption_point = [&] { ++calls; };
    {
        AutoFile file{fsbridge::fopen(path, "wb")};
        auto result = CreateRolledBackUTXOSnapshot(m_node, chainstate, target, std::move(file), path, path);
        for (const auto* key : {"coins_written", "base_hash", "base_height", "txoutset_hash", "nchaintx"}) {
            BOOST_CHECK_EQUAL(result[key].write(), baseline[key].write());
        }
    }
    check_cleanup();
    BOOST_REQUIRE(calls > 110U);
    const size_t total_calls = calls;
    // Interrupt early copying, later copying, undo processing and final output.
    for (const size_t stop : {size_t{1}, size_t{50}, size_t{115}, total_calls}) {
        calls = 0;
        m_node.rpc_interruption_point = [&] {
            if (++calls == stop) throw std::runtime_error("cancel export");
        };
        AutoFile file{fsbridge::fopen(path, "wb")};
        BOOST_CHECK_EXCEPTION(CreateRolledBackUTXOSnapshot(m_node, chainstate, target, std::move(file), path, path),
                              std::runtime_error, [](const auto& e) { return std::string{e.what()} == "cancel export"; });
        check_cleanup();
    }
    m_node.rpc_interruption_point = [] {};
    // A reorg between RPC target selection and capture must fail, not export a
    // different block at the requested height. A disconnected index models it.
    CBlockIndex stale_target;
    stale_target.nHeight = target->nHeight;
    {
        AutoFile file{fsbridge::fopen(path, "wb")};
        BOOST_CHECK_EXCEPTION(CreateRolledBackUTXOSnapshot(m_node, chainstate, &stale_target, std::move(file), path, path),
                              UniValue, [](const auto& e) { return e["message"].get_str() == "Snapshot target is no longer on the captured chain"; });
    }
    check_cleanup();
    // Recovery: a subsequent export still produces the expected historical set.
    AutoFile file{fsbridge::fopen(path, "wb")};
    auto result = CreateRolledBackUTXOSnapshot(m_node, chainstate, target, std::move(file), path, path);
    BOOST_CHECK_EQUAL(result["txoutset_hash"].get_str(), baseline["txoutset_hash"].get_str());
    check_cleanup();
}

BOOST_AUTO_TEST_SUITE_END()
