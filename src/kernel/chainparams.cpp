// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

using namespace util::hex_literals;

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// https://developercommunity.visualstudio.com/t/Bogus-C7595-error-on-valid-C20-code/10906093
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "spectrum.ieee.org 09/Dec/2020 Photonic Quantum Computer Displays 'Supremacy' Over Supercomputers.";
    const CScript genesisOutputScript = CScript() << "070903b9fdabf894363dea700a33acedb349b8d3d605ab6a8a997bf885581a5cb656758d18b3d17b144aeba442ccdd5538c4d88dd45d28ea8cf3b1e60f73af23a6ac866d56f8c49eabf84ad3e7a90c4b198f7a661cae08869fb07ba0ca2a2dcbbba5619f43e214c088da988eae9a39d6a5992c697cf56b46b6a81d6710b2c84d7134546b3eafc43da6454641a85b8a4a09747f4e284be53f03dfcfcbb1c0b9706100e73644fbc8b359bc23508f1b4350fe5e2da08a33cf0b5186ce83dd1bcc4a6d6240575d4d08d1e15922994f12ad44743e271a76683f66a9273491da8a217dd25a870e37e227577cbd462e97b49c32b2399cc2c9db2ba6955f0143cba62ce9e9b79f844220ad3e382caebd0880d273b3d7590a8ccdf7d26c8a21c64d637d8d5c0dae178513231f532c0b26244d25610cd83931e42c3039e3c15101104e40d53bf4c6f599322e2956e802551803757fde82593892798feaccbdc52b495197f276c4858ae16253bb186872c4c87665bae41b1411b26c6ec636dad53619d183d492d6996cc18cb6fad8cb7ef00889a88ce5438603d8b6e90a1cca4203b4d46b4942b59492af797c44f582730834be341178d5ef6e9f82e1caa440686525bf83c753e4a6beb9254d1db68c15fbb34906871039f90644da1468493bf729211f308403a911943e066a98081d8dd661bd97a6b9e774479d6861afcd048c2a17d70a481d5e38c067b42629bda1aceba8613ebb1827511545465025886b6510b622816f43f24b1d0300dcc2db24ca7cb02aa6e583e5a6c0e8a7bde1110fd50e37d5557e865d9a66ad9c3d19d6f3a277c71abfa572cb7a647954f5c0293bd298984483ab6ed65b2915921aadc0f98600870bea13668d21b1a31d10ec28622bf9c28e23501846c0fa02ce7158aac4b7977d51debf1168cd03b7d49a480c1b385c52d5a079a2be884e45b332003ca198963797a1c45eda0f9a0dce6f03869ae78b937b819d38b7e1120d7fa9a8a96a9fd691d6c6f448a1ebb74862e95d8b7f3cf45d99f2981f4f5622ea05d8fc094ec9a0670a2684622c556964e530c1372b442918856aa79494c199a6912ffa2a893c7e7e1c090892264d6e4b583281eb2dc252c61e4904382c56f2c36f736a755b515aa2b108201bf1502de3228cf258700d8a7bec14f113e8d6be8daf7796237a5cd9adda37ca201cd9c7f3dedc574b595f21c4865244e5dde5c5c5f330fa2e58a988da0e223f0a42e41f9f9dd9908e82a86819ec690c5716"_hex << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.nSubsidyHalvingInterval = 262800; // initial interval
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{"fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf"};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nAuxpowStartHeight = Consensus::AUXPOW_DISABLED;
        consensus.nAuxpowChainId = 8;
        consensus.fStrictChainId = true;
        // Suppress unknown versionbit warnings until auxpow activation height.
        consensus.MinBIP9WarningHeight = consensus.nAuxpowStartHeight;
        consensus.powLimit = uint256{"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 5 * 24 * 60 * 60; // 5 days
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nNewPowDiffHeight = consensus.nAuxpowStartHeight;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
        consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16;   // 16% adjustment up
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 6048; // 75% of 8064
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 8064;

        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000000007e9c0d0d38263"};
        consensus.defaultAssumeValid = uint256{"1b4031baa9b71ea2d01b6676705fe25b07a72db1437d965a5be4e7ad3ccf6c9f"}; // 2463084

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xec;
        pchMessageStart[1] = 0xfa;
        pchMessageStart[2] = 0xce;
        pchMessageStart[3] = 0xa5;
        nDefaultPort = 8755;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 22;
        m_assumed_chain_state_size = 3;

        genesis = CreateGenesisBlock(1609074580, 11033477, 0x2001ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"480ecc7602d8989f32483377ed66381c391dda6215aeef9e80486a7fd3018075"});
        assert(genesis.hashMerkleRoot == uint256{"50a03c5c0b982dccfd03bebc0f6142fa298354743dce82be936e69335d614ff8"});

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed.tidecoin.co");


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,33);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,70);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,65);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,125);

        bech32_hrp = "tbc";
        bech32_pq_hrp = "q";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 2cdba8c47858d34cf0e02dfb8733263a3ed8705b1663ec7c158783d77b93e7ee
            .nTime    = 1621410565,
            .tx_count = 283072,
            .dTxRate  = 0.02080753988235224,
        };
    }
};

/**
 * Testnet: public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.nSubsidyHalvingInterval = 262800;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{"fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf"};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nAuxpowStartHeight = 1000;
        consensus.nAuxpowChainId = 8;
        consensus.fStrictChainId = true;
        consensus.MinBIP9WarningHeight = 1; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256{"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 5 * 24 * 60 * 60; // 5 days
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nNewPowDiffHeight = consensus.nAuxpowStartHeight;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
        consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16;   // 16% adjustment up
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 6048; // 75% of 8064
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 8064;

        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
        consensus.defaultAssumeValid = uint256{"b34a457c601ef8ce3294116e3296078797be7ded1b0d12515395db9ab5e93ab8"}; // 1683528

        pchMessageStart[0] = 0xba;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18755;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 22;
        m_assumed_chain_state_size = 3;

        genesis = CreateGenesisBlock(1609074580, 11033477, 0x2001ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"480ecc7602d8989f32483377ed66381c391dda6215aeef9e80486a7fd3018075"});
        assert(genesis.hashMerkleRoot == uint256{"50a03c5c0b982dccfd03bebc0f6142fa298354743dce82be936e69335d614ff8"});

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("tidetest.ddnsgeek.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,92);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,132);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,127);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,180);

        bech32_hrp = "ttbc";
        bech32_pq_hrp = "tq";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{};
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.nSubsidyHalvingInterval = 20;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.nAuxpowStartHeight = 0;
        consensus.nAuxpowChainId = 8;
        consensus.fStrictChainId = true;
        consensus.MinBIP9WarningHeight = 1;
        consensus.powLimit = uint256{"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"};
        consensus.nPowTargetTimespan = 4 * 60 * 60; // 4 hours
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = true;
        consensus.nNewPowDiffHeight = 0;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
        consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 0; // disabled on regtest
        consensus.nPowMaxAdjustUp = 0;   // disabled on regtest

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 108; // 75% for testchains
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 144; // Faster than normal for regtest (144 instead of 2016)


        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
        consensus.defaultAssumeValid = uint256{"0000000000000000000000000000000000000000000000000000000000000000"};

        pchMessageStart[0] = 0xba;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18778;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateGenesisBlock(1609074580, 0, 0x200f0f0f, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"c19a1b559b1ea55d7c5ee23031c6a06fb917c641ae896587f42a1847bf2a2e8b"});
        assert(genesis.hashMerkleRoot == uint256{"50a03c5c0b982dccfd03bebc0f6142fa298354743dce82be936e69335d614ff8"});

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        // AssumeUTXO data for deterministic regtest test vectors.
        // The height-299 entry is used by feature_assumeutxo.py.
        m_assumeutxo_data = {
            {.height = 110,
             .hash_serialized = AssumeutxoHash{uint256{"6cdd7e279d1552f1bee12232d1ab64465d9d34b8bc952da931419e33b5f2f8e5"}},
             .m_chain_tx_count = 111,
             .blockhash = consteval_ctor(uint256{"28c79d24d42b39e86e9cd981e3b08c940c0d1413225e4eb49d2911ed721a0b99"})},
            {.height = 200,
             .hash_serialized = AssumeutxoHash{uint256{"30e3eb80545e3c4c12ab6528a9f32ddd09644822ce9d1fd3fd0fee04ab0d1af0"}},
             .m_chain_tx_count = 202,
             .blockhash = consteval_ctor(uint256{"2b322de3c65d567ccbd15cb84724fcfbc4f82520bc287bedcb7d1652fe98a754"})},
            {.height = 299,
             .hash_serialized = AssumeutxoHash{uint256{"127bbb92ff31cd9bc4a23f63d15841f2c1b9eac91b43db9a9a10853365f25c9e"}},
             .m_chain_tx_count = 334,
             .blockhash = consteval_ctor(uint256{"919971d2ad79095dc0aaaed1a135062b61d14d4f533104d1b23658cbe8dd359e"})},
        };

        chainTxData = ChainTxData{};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,117);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,186);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,122);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,15);

        bech32_hrp = "rtbc";
        bech32_pq_hrp = "rq";
    }
};

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    }
    return std::nullopt;
}
