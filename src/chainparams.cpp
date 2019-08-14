// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, const CScript& genesisCoinbaseCommitmentScript, uint32_t nTime, uint256 nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    static const std::vector<unsigned char> nonce(32, 0x00);
    unsigned int nHeight = 0;

    CMutableTransaction txNew;
    txNew.nVersion = 2;
    txNew.vin.resize(1);
    txNew.vout.resize(2);

    txNew.vin[0].prevout.SetNull();
    txNew.vin[0].scriptSig = CScript() << nHeight << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vin[0].scriptWitness.stack.resize(1);
    txNew.vin[0].scriptWitness.stack[0] = nonce;

    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    txNew.vout[1].nValue = 0;
    txNew.vout[1].scriptPubKey = genesisCoinbaseCommitmentScript;

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
 * CBlock(hash=00000000cf908c, ver=0x20000000, hashPrevBlock=00000000000000, hashMerkleRoot=996a41, nTime=1565695862, nBits=1d00ffff, nNonce=uint256S("01ef65e1ee"), vtx=1)
 *   CTransaction(hash=56ee35, ver=2, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 0001040d4e657665722047697665205570)
 *     CTxOut(nValue=420000.00000000, scriptPubKey=0014faa1133ed40545e843657512b867b17838fd5218)
 *     CTxOut(nValue=0, CoinbaseCommitment=e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9)
 *   vMerkleTree: 996a41
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint256 nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, const char* outputScript)
{
    const char* pszTimestamp = "Never Give Up";
    const CScript genesisOutputScript = CScript() << OP_0 << ParseHex(outputScript);
    const CScript genesisCoinbaseCommitmentScript = CScript() << OP_RETURN << ParseHex("aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9");
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, genesisCoinbaseCommitmentScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000f1c54590ee18d15ec70e68c8cd4cfbadb1b4f11697eee"); //563378

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        //  0x4C52434E : "LRCN"
        pchMessageStart[0] = 0x4c;  //  'L'
        pchMessageStart[1] = 0x52;  //  'R'
        pchMessageStart[2] = 0x43;  //  'C'
        pchMessageStart[3] = 0x4e;  //  'N'
        nDefaultPort = 9218;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 240;
        m_assumed_chain_state_size = 3;

        genesis = CreateGenesisBlock(1565695862, 
            uint256S("00000000000000000000000000000000000000000000000000000001ef65e1ee"), 
            0x1d00ffff, 0x20000000, GENESIS_BLOCK_SUBSIDY_COIN_COUNT * COIN, 
            "faa1133ed40545e843657512b867b17838fd5218");
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.hashGenesisBlockTx = genesis.vtx[0]->GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000cf908c47b86800595aab94cd8b5d04b953905c39f3e73e2de3ae2098"));
        assert(genesis.hashMerkleRoot == uint256S("0x996a4102400c02ea12a6d65ca2c707089ccea4019847030e0c8ba42c097c039b"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("mainnet.longshao.info"); // Pieter Wuille, only supports x1, x5, x9, and xd

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "lc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, uint256S("0x00000000ed7c3517b90c20cdb22ceb7176a522f652ba2c4c519c6c9ec2ef1c39")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000000000f1c54590ee18d15ec70e68c8cd4cfbadb1b4f11697eee
            /* nTime    */ 1550374134,
            /* nTxCount */ 383732546,
            /* dTxRate  */ 3.685496590998308
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;

        // Reward Address
        vRewardAddress = {
            "lc1qrn97xjynnhc9xvssmyk784luls9hn4xfzsxpk3",   // developer  10%
            "lc1qtfg562txj9xtay7q6a62vd8vlzzndhxdgsem9q",   // flow miner 30% 
            "lc1qlrty5ahr5wjxyv3dkhy6ffxm0pf7geffn89r24",   // layer2     30%
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000002000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00"); //1354312

        //  0x4C52444E : "LRDN"
        pchMessageStart[0] = 0x4c;  //  'L'
        pchMessageStart[1] = 0x52;  //  'R'
        pchMessageStart[2] = 0x44;  //  'D'
        pchMessageStart[3] = 0x4e;  //  'N'
        nDefaultPort = 19218;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 30;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(1565695657, 
            uint256S("00000000000000000000000000000000000000000000000000000000000002a2"), 
            0x1f07ffff, 0x20000000, GENESIS_BLOCK_SUBSIDY_COIN_COUNT * COIN,
            "db2e1536cb0d78bba2b5ad7bb00db43efc1d2d0e");
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.hashGenesisBlockTx = genesis.vtx[0]->GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0007ab882520224dbdec12839253a987c76673f4c3743c81432b13f9fd7d4678"));
        assert(genesis.hashMerkleRoot == uint256S("0xfc0a0f445860e268a2081fffdc59d07d571d253106cd83bfc8bdf9a59c44966e"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet.longshao.info");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tl";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {0, uint256S("0002bdb81bf01a43d3a3789f0c95554de926704aa8ddd7a2761de183dd67027b")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75
            /* nTime    */ 1531929919,
            /* nTxCount */ 19438708,
            /* dTxRate  */ 0.626
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;

        // Reward Address
        vRewardAddress = {
            "tl1qxl4qh8z0qcyxghp48lvcag6ptk36k66n04sx8q",   // developer  10%
            "tl1qvjesntdw7cvej854s0x0hrkl3jzw3kcp5779p0",   // flow miner 30% 
            "tl1qszult87zmc5q93dfd4u5wsrapugx878vjwehc3",   // layer2     30%
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        
        //  0x4C52454E : "LREN"
        pchMessageStart[0] = 0x4c;  //  'L'
        pchMessageStart[1] = 0x52;  //  'R'
        pchMessageStart[2] = 0x45;  //  'E'
        pchMessageStart[3] = 0x4e;  //  'N'
        nDefaultPort = 19318;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);

        genesis = CreateGenesisBlock(1565691010, 
            uint256S("0000000000000000000000000000000000000000000000000000000000000006"), 
            0x207fffff, 0x20000000, GENESIS_BLOCK_SUBSIDY_COIN_COUNT * COIN,
            "22f93fa544fc96895e001a7deb793866d9c73ed2");
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.hashGenesisBlockTx = genesis.vtx[0]->GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x7e303db103a22166b08ec3d836db07c963ddbac438365cabaadd0f6a1e892ec3"));
        assert(genesis.hashMerkleRoot == uint256S("0x57f22ee4629684ea8ae9e2015c46d571c14fe6a414c0d316415f29af50232beb"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("797ea6ae89f48d7a1e2850c088ace38cbdd3f5cf617921c3fc2b5fd67018bf12")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "lcrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;

        // Reward Address
        vRewardAddress = {
            "lcrt1q5myg5la9929d7xjp8tjlluaq2l3q29znqvez0r",   // developer  10%
            "lcrt1qnkvr4qg34thhprt6pcedxqsw0lurt9v8npkfke",   // flow miner 30% 
            "lcrt1qkuggeqxqnvz5c30jmf0pc8ev2w9he75ynaqey0",   // layer2     30%
        };
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
