// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2019 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "core_io.h"
#ifdef ENABLE_MINING
#include "crypto/equihash.h"
#endif
#include "init.h"
#include "main.h"
#include "metrics.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpc/server.h"
#include "txmempool.h"
#include "util.h"
#include "validationinterface.h"
#include "wallet/wallet.h"
#include "asyncrpcqueue.h"
#include "asyncrpcoperation.h"
#include "wallet/asyncrpcoperation_sendmany.h"
#include "timedata.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

#include "rpc/pbaasrpc.h"
#include "coincontrol.h"

#include <librustzcash.h>
#include "transaction_builder.h"

using namespace std;

extern uint32_t ASSETCHAINS_ALGO;
extern int32_t ASSETCHAINS_EQUIHASH, ASSETCHAINS_LWMAPOS;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern uint32_t ASSETCHAINS_STARTING_DIFF;
extern uint64_t ASSETCHAINS_STAKED;
extern int32_t KOMODO_MININGTHREADS;
extern bool VERUS_MINTBLOCKS;
extern uint8_t NOTARY_PUBKEY33[33];
extern uint160 ASSETCHAINS_CHAINID;
extern uint160 VERUS_CHAINID;
extern std::string VERUS_CHAINNAME;
extern int32_t USE_EXTERNAL_PUBKEY;
extern std::string NOTARY_PUBKEY;

#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
extern uint64_t ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_TIMEUNLOCKFROM, ASSETCHAINS_TIMEUNLOCKTO;
extern int64_t ASSETCHAINS_SUPPLY;
extern int64_t ASSETCHAINS_ISSUANCE;
extern uint64_t ASSETCHAINS_REWARD[3], ASSETCHAINS_DECAY[3], ASSETCHAINS_HALVING[3], ASSETCHAINS_ENDSUBSIDY[3], ASSETCHAINS_ERAOPTIONS[3];
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK, ASSETCHAINS_LWMAPOS;
extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA;
extern std::string VERUS_CHAINNAME;


arith_uint256 komodo_PoWtarget(int32_t *percPoSp,arith_uint256 target,int32_t height,int32_t goalperc);

std::set<uint160> ClosedPBaaSChains({});

// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {};

protected:
    virtual void BlockChecked(const CBlock& block, const CValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    };
};

bool GetCurrencyDefinition(const uint160 &chainID, CCurrencyDefinition &chainDef, int32_t *pDefHeight, bool checkMempool, bool notarizationCheck, CUTXORef *pUTXO, std::vector<CNodeData> *pGoodNodes)
{
    static bool isVerusActive = IsVerusActive();
    static bool thisChainLoaded = false;
    std::vector<CNodeData> _goodNodes;
    std::vector<CNodeData> &goodNodes = pGoodNodes ? *pGoodNodes : _goodNodes;

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    uint160 lookupKey = CCrossChainRPCData::GetConditionID(chainID, CCurrencyDefinition::CurrencyDefinitionKey());

    std::vector<std::pair<uint160, int>> addresses = {{lookupKey, CScript::P2IDX}};
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > results;
    CCurrencyDefinition foundDef;

    // TODO: HARDENING - consider converting chain filter to a currency blacklist and/or whitelist check
    if (!ClosedPBaaSChains.count(chainID) && GetAddressUnspent(lookupKey, CScript::P2IDX, unspentOutputs) && unspentOutputs.size())
    {
        for (auto &currencyDefOut : unspentOutputs)
        {
            if ((foundDef = CCurrencyDefinition(currencyDefOut.second.script)).IsValid())
            {
                chainDef = foundDef;
                if (pDefHeight)
                {
                    *pDefHeight = currencyDefOut.second.blockHeight;
                }
                if (pUTXO)
                {
                    *pUTXO = CUTXORef(currencyDefOut.first.txhash, currencyDefOut.first.index);
                }
                if (pGoodNodes)
                {
                    std::vector<CNodeData> nodes;
                    CTransaction nTx;
                    uint256 blockHash;
                    if (!myGetTransaction(currencyDefOut.first.txhash, nTx, blockHash))
                    {
                        LogPrintf("%s: Cannot load currency definition transaction, txid %s\n", __func__, currencyDefOut.first.txhash.GetHex().c_str());
                        continue;
                    }
                    for (int i = currencyDefOut.first.index + 1; i < nTx.vout.size(); i++)
                    {
                        COptCCParams p;
                        CPBaaSNotarization pbn;

                        if (nTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                            p.vData.size() &&
                            (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                            pbn.currencyID == chainID)
                        {
                            goodNodes = pbn.nodes;
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    else if (checkMempool && !ClosedPBaaSChains.count(chainID) && mempool.getAddressIndex(addresses, results) && results.size())
    {
        for (auto &currencyDefOut : results)
        {
            CTransaction tx;

            if (mempool.lookup(currencyDefOut.first.txhash, tx) &&
                (foundDef = CCurrencyDefinition(tx.vout[currencyDefOut.first.index].scriptPubKey)).IsValid())
            {
                chainDef = foundDef;
                if (pDefHeight)
                {
                    *pDefHeight = chainActive.Height() + 1;
                }
                if (pUTXO)
                {
                    *pUTXO = CUTXORef(currencyDefOut.first.txhash, currencyDefOut.first.index);
                }
                if (pGoodNodes)
                {
                    std::vector<CNodeData> nodes;
                    uint256 blockHash;
                    for (int i = currencyDefOut.first.index + 1; i < tx.vout.size(); i++)
                    {
                        COptCCParams p;
                        CPBaaSNotarization pbn;

                        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                            p.vData.size() &&
                            (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                            pbn.currencyID == chainID)
                        {
                            goodNodes = pbn.nodes;
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    if (chainID == ASSETCHAINS_CHAINID && foundDef.IsValid())
    {
        if (pGoodNodes)
        {
            auto extraNodes = GetGoodNodes();
            goodNodes.insert(goodNodes.end(), extraNodes.begin(), extraNodes.end());
        }
        if (!thisChainLoaded)
        {
            thisChainLoaded = true;
            ConnectedChains.ThisChain() = foundDef;
            ConnectedChains.UpdateCachedCurrency(foundDef, pDefHeight ? *pDefHeight : chainActive.Height());
        }
    }
    else if (foundDef.IsValid())
    {
        // add to nodes with last confirmed notarization nodes
        CChainNotarizationData cnd;
        if (notarizationCheck && GetNotarizationData(chainID, cnd) && cnd.IsConfirmed())
        {
            auto extraNodes = cnd.vtx[cnd.lastConfirmed].second.nodes;
            goodNodes.insert(goodNodes.end(), extraNodes.begin(), extraNodes.end());
        }
    }
    else
    {
        if (chainID == ASSETCHAINS_CHAINID && (thisChainLoaded || chainActive.Height() < 1 || isVerusActive))
        {
            chainDef = ConnectedChains.ThisChain();
            if (pDefHeight)
            {
                *pDefHeight = 0;
            }
            if (pUTXO)
            {
                *pUTXO = CUTXORef();
            }
            if (pGoodNodes)
            {
                goodNodes = GetGoodNodes();
            }
            return true;
        }
        else if (!isVerusActive && chainActive.Height() == 0)
        {
            if (ConnectedChains.FirstNotaryChain().IsValid() && (chainID == ConnectedChains.FirstNotaryChain().chainDefinition.GetID()))
            {
                chainDef = ConnectedChains.FirstNotaryChain().chainDefinition;
                if (pDefHeight)
                {
                    *pDefHeight = 0;
                }
                if (pUTXO)
                {
                    *pUTXO = CUTXORef();
                }
                return true;
            }
        }

    }
    return foundDef.IsValid();
}

bool GetCurrencyDefinition(const std::string &name, CCurrencyDefinition &chainDef)
{
    return GetCurrencyDefinition(CCrossChainRPCData::GetID(name), chainDef);
}

CTxDestination ValidateDestination(const std::string &destStr)
{
    CTxDestination destination = DecodeDestination(destStr);
    if (destination.which() == COptCCParams::ADDRTYPE_ID)
    {
        AssertLockHeld(cs_main);
        if (!CIdentity::LookupIdentity(GetDestinationID(destination)).IsValid())
        {
            return CTxDestination();
        }
    }
    return destination;
}

CIdentity ValidateIdentityParameter(const std::string &idStr)
{
    CIdentity retVal;
    CTxDestination destination = DecodeDestination(idStr);
    if (destination.which() == COptCCParams::ADDRTYPE_ID)
    {
        AssertLockHeld(cs_main);
        retVal = CIdentity::LookupIdentity(GetDestinationID(destination));
    }
    return retVal;
}

// returns non-null value, if this is a gateway destination
std::pair<uint160, CTransferDestination> ValidateTransferDestination(const std::string &destStr)
{
    uint160 parent;
    uint160 destID;
    CTxDestination destination;

    AssertLockHeld(cs_main);

    // One case where the transfer destination is valid, but will not be located on chain
    // is when the destination is a gateway. In that case, alternate format destinations
    // can be used. Each format type has its own validation.
    if (std::count(destStr.begin(), destStr.end(), '@') == 1)
    {
        std::string str = CleanName(destStr, parent);
        if (str != "")
        {
            destID = CIdentityID(CIdentity::GetID(str, parent));
            if (CIdentity::LookupIdentity(destID).IsValid())
            {
                return std::make_pair(uint160(), DestinationToTransferDestination(CIdentityID(destID)));
            }
            // we haven't found an ID, so this may be a transfer address, but only if
            // it's parent is a gateway currency and it validates
            auto gatewayPair = ConnectedChains.GetGateway(parent);
            if (gatewayPair.first.IsValid() && gatewayPair.second->ValidateDestination(str));
            {
                return std::make_pair(parent, gatewayPair.second->ToTransferDestination(str));
            }
        }
    }
    else
    {
        destination = DecodeDestination(destStr);
        if (destination.which() == COptCCParams::ADDRTYPE_ID)
        {
            if (!CIdentity::LookupIdentity(GetDestinationID(destination)).IsValid())
            {
                destination = CTxDestination();
            }
        }
    }
    return std::make_pair(uint160(), DestinationToTransferDestination(destination));
}

// set default peer nodes in the current connected chains
bool SetPeerNodes(const UniValue &nodes)
{
    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0)
    {
        printf("%s: Ignoring seednodes due to nodes specified in \"-connect\" parameter\n", __func__);
        LogPrintf("%s: Ignoring seednodes due to nodes specified in \"-connect\" parameter\n", __func__);
        std::vector<std::string> connectNodes = mapMultiArgs["-connect"];
        for (int i = 0; i < connectNodes.size(); i++)
        {
            CNodeData oneNode = CNodeData(connectNodes[i], "");
            if (oneNode.networkAddress != "")
            {
                ConnectedChains.defaultPeerNodes.push_back(oneNode);
            }
        }
    }
    else
    {
        if (!nodes.isArray() || nodes.size() == 0)
        {
            return false;
        }

        LOCK(ConnectedChains.cs_mergemining);
        ConnectedChains.defaultPeerNodes.clear();

        for (int i = 0; i < nodes.size(); i++)
        {
            CNodeData oneNode(nodes[i]);
            if (oneNode.networkAddress != "")
            {
                ConnectedChains.defaultPeerNodes.push_back(oneNode);
            }
        }

        std::vector<std::string> seedNodes = mapMultiArgs["-seednode"];
        for (int i = 0; i < seedNodes.size(); i++)
        {
            CNodeData oneNode = CNodeData(seedNodes[i], "");
            if (oneNode.networkAddress != "")
            {
                ConnectedChains.defaultPeerNodes.push_back(oneNode);
            }
        }
    }

    std::vector<std::string> addNodes = mapMultiArgs["-addnode"];
    for (int i = 0; i < addNodes.size(); i++)
    {
        CNodeData oneNode = CNodeData(addNodes[i], "");
        if (oneNode.networkAddress != "")
        {
            ConnectedChains.defaultPeerNodes.push_back(oneNode);
        }
    }

    // set all command line parameters into mapArgs from chain definition
    vector<string> nodeStrs;

    if (!GetBoolArg("-forcednsseed", false) && !(mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0))
    {
        for (auto node : ConnectedChains.defaultPeerNodes)
        {
            nodeStrs.push_back(node.networkAddress);
        }
    }

    if (!(mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0))
    {
        mapMultiArgs["-seednode"] = nodeStrs;
    }

    for (auto &oneNode : nodeStrs)
    {
        AddOneShot(oneNode);
    }

    if (int port = ConnectedChains.GetThisChainPort())
    {
        mapArgs["-port"] = to_string(port);
    }
    return true;
}

// adds the chain definition for this chain and nodes as well
// this also sets up the notarization chain, if there is one
bool SetThisChain(const UniValue &chainDefinition, CCurrencyDefinition *retDef)
{
    ConnectedChains.ThisChain() = CCurrencyDefinition(chainDefinition);
    if (!ConnectedChains.ThisChain().IsValid())
    {
        return false;
    }
    if (retDef)
    {
        *retDef = ConnectedChains.ThisChain();
    }
    SetPeerNodes(find_value(chainDefinition, "nodes"));

    memset(ASSETCHAINS_SYMBOL, 0, sizeof(ASSETCHAINS_SYMBOL));
    assert(ConnectedChains.ThisChain().name.size() < sizeof(ASSETCHAINS_SYMBOL));
    strcpy(ASSETCHAINS_SYMBOL, ConnectedChains.ThisChain().name.c_str());

    ASSETCHAINS_STARTING_DIFF = ConnectedChains.ThisChain().initialBits;
    //printf("Starting PBaaS chain:\n%s\n", ConnectedChains.ThisChain().ToUniValue().write(1,2).c_str());

    if (!IsVerusActive())
    {
        // we set the notary chain to either Verus or VerusTest
        // TODO: HARDENING - ensure that we don't need to check which name here and do the right thing in all cases
        CCurrencyDefinition notaryChainDef = CCurrencyDefinition(PBAAS_TESTMODE ? "VRSCTEST" : "VRSC", PBAAS_TESTMODE);

        VERUS_CHAINNAME = notaryChainDef.name;
        VERUS_CHAINID = notaryChainDef.GetID();

        ASSETCHAINS_CHAINID = ConnectedChains.ThisChain().GetID();

        ConnectedChains.notarySystems[notaryChainDef.GetID()] = 
            CNotarySystemInfo(0, CRPCChainData(notaryChainDef, PBAAS_HOST, PBAAS_PORT, PBAAS_USERPASS), CPBaaSNotarization());
        ASSETCHAINS_SUPPLY = ConnectedChains.ThisChain().GetTotalPreallocation();
        ASSETCHAINS_ISSUANCE = ConnectedChains.ThisChain().gatewayConverterIssuance;
        ASSETCHAINS_ERAOPTIONS[0] = ConnectedChains.ThisChain().ChainOptions();
    }

    auto numEras = ConnectedChains.ThisChain().rewards.size();
    ASSETCHAINS_LASTERA = numEras - 1;
    mapArgs["-ac_eras"] = to_string(numEras);

    mapArgs["-ac_end"] = "";
    mapArgs["-ac_reward"] = "";
    mapArgs["-ac_halving"] = "";
    mapArgs["-ac_decay"] = "";
    mapArgs["-ac_options"] = "";

    for (int j = 0; j < ASSETCHAINS_MAX_ERAS; j++)
    {
        if (j > ASSETCHAINS_LASTERA)
        {
            ASSETCHAINS_REWARD[j] = ASSETCHAINS_REWARD[j-1];
            ASSETCHAINS_DECAY[j] = ASSETCHAINS_DECAY[j-1];
            ASSETCHAINS_HALVING[j] = ASSETCHAINS_HALVING[j-1];
            ASSETCHAINS_ENDSUBSIDY[j] = 0;
            ASSETCHAINS_ERAOPTIONS[j] = ConnectedChains.ThisChain().options;
        }
        else
        {
            ASSETCHAINS_REWARD[j] = ConnectedChains.ThisChain().rewards[j];
            ASSETCHAINS_DECAY[j] = ConnectedChains.ThisChain().rewardsDecay[j];
            ASSETCHAINS_HALVING[j] = ConnectedChains.ThisChain().halving[j];
            ASSETCHAINS_ENDSUBSIDY[j] = ConnectedChains.ThisChain().eraEnd[j];
            ASSETCHAINS_ERAOPTIONS[j] = ConnectedChains.ThisChain().options;
            if (j == 0)
            {
                mapArgs["-ac_reward"] = to_string(ASSETCHAINS_REWARD[j]);
                mapArgs["-ac_decay"] = to_string(ASSETCHAINS_DECAY[j]);
                mapArgs["-ac_halving"] = to_string(ASSETCHAINS_HALVING[j]);
                mapArgs["-ac_end"] = to_string(ASSETCHAINS_ENDSUBSIDY[j]);
                mapArgs["-ac_options"] = to_string(ASSETCHAINS_ERAOPTIONS[j]);
            }
            else
            {
                mapArgs["-ac_reward"] += "," + to_string(ASSETCHAINS_REWARD[j]);
                mapArgs["-ac_decay"] += "," + to_string(ASSETCHAINS_DECAY[j]);
                mapArgs["-ac_halving"] += "," + to_string(ASSETCHAINS_HALVING[j]);
                mapArgs["-ac_end"] += "," + to_string(ASSETCHAINS_ENDSUBSIDY[j]);
                mapArgs["-ac_options"] += "," + to_string(ASSETCHAINS_ERAOPTIONS[j]);
            }
        }
    }

    PBAAS_STARTBLOCK = ConnectedChains.ThisChain().startBlock;
    mapArgs["-startblock"] = to_string(PBAAS_STARTBLOCK);
    PBAAS_ENDBLOCK = ConnectedChains.ThisChain().endBlock;
    mapArgs["-endblock"] = to_string(PBAAS_ENDBLOCK);
    mapArgs["-ac_supply"] = to_string(ASSETCHAINS_SUPPLY);
    mapArgs["-gatewayconverterissuance"] = to_string(ASSETCHAINS_ISSUANCE);
    return true;
}

void CurrencySystemTypeQuery(const uint160 queryID,
                             std::map<CUTXORef, int> &currenciesFound,
                             std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> &curDefVec,
                             uint32_t startBlock=0,
                             uint32_t endBlock=0)
{
    if (startBlock || endBlock)
    {
        std::vector<CAddressIndexDbEntry> systemAddressIndex;
        if (GetAddressIndex(queryID, CScript::P2IDX, systemAddressIndex, startBlock, endBlock) && systemAddressIndex.size())
        {
            for (auto &oneOut : systemAddressIndex)
            {
                CUTXORef oneRef(oneOut.first.txhash, oneOut.first.index);
                if (!currenciesFound.count(oneRef))
                {
                    currenciesFound.insert(std::make_pair(oneRef, -1));
                }
            }
        }
    }
    else
    {
        std::vector<CAddressUnspentDbEntry> unspentAddressIndex;
        if (GetAddressUnspent(queryID, CScript::P2IDX, unspentAddressIndex) && unspentAddressIndex.size())
        {
            for (auto &oneOut : unspentAddressIndex)
            {
                CCurrencyDefinition curDef(oneOut.second.script);
                if (!curDef.IsValid())
                {
                    LogPrintf("%s: invalid currency definition found in index, txid %s, vout: %d\n", __func__, oneOut.first.txhash.GetHex().c_str(), (int)oneOut.first.index);
                    continue;
                }
                CUTXORef oneRef(oneOut.first.txhash, oneOut.first.index);
                if (!currenciesFound.count(oneRef) || currenciesFound[oneRef] == -1)
                {
                    std::vector<CNodeData> nodes;
                    CTransaction nTx;
                    uint256 blockHash;
                    uint160 curDefID = curDef.GetID();
                    if (!myGetTransaction(oneRef.hash, nTx, blockHash))
                    {
                        LogPrintf("%s: Cannot load currency definition transaction, txid %s\n", __func__, oneOut.first.txhash.GetHex().c_str());
                        continue;
                    }
                    for (int i = oneRef.n + 1; i < nTx.vout.size(); i++)
                    {
                        COptCCParams p;
                        CPBaaSNotarization pbn;

                        if (nTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                            p.vData.size() &&
                            (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                            pbn.currencyID == curDefID)
                        {
                            nodes = pbn.nodes;
                            break;
                        }
                    }
                    currenciesFound.insert(std::make_pair(oneRef, curDefVec.size()));
                    curDefVec.push_back(std::make_pair(std::make_pair(oneRef, nodes),  curDef));
                }
            }
        }
    }
}

void CurrencyNotarizationTypeQuery(CCurrencyDefinition::EQueryOptions launchStateQuery,
                                   std::map<CUTXORef, int> &currenciesFound,
                                   std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> &curDefVec,
                                   uint32_t startBlock=0,
                                   uint32_t endBlock=0)
{
    uint160 queryID;
    bool checkUnspent = false;
    if (launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchPrelaunchKey());
        checkUnspent = true;
    }
    else if (launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_REFUND)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchRefundKey());
    }
    else if (launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_COMPLETE)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchCompleteKey());
    }
    else if (launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_CONFIRM)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchConfirmKey());
    }
    else if (launchStateQuery == CCurrencyDefinition::QUERY_ISCONVERTER)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCoinbaseCurrencyState::IndexConverterKey(ASSETCHAINS_CHAINID));
        checkUnspent = true;
    }

    if (launchStateQuery != CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH && (startBlock || endBlock))
    {
        std::vector<CAddressIndexDbEntry> notarizationAddressIndex;
        std::map<uint160, CPBaaSNotarization> notarizationsFound;

        if (GetAddressIndex(queryID, CScript::P2IDX, notarizationAddressIndex, startBlock, endBlock) && notarizationAddressIndex.size())
        {
            for (auto &oneOut : notarizationAddressIndex)
            {
                CTransaction notarizationTx;
                uint256 blockHash;
                if (!myGetTransaction(oneOut.first.txhash, notarizationTx, blockHash) ||
                    notarizationTx.vout.size() <= oneOut.first.index)
                {
                    LogPrintf("%s: Error reading transaction %s\n", __func__, oneOut.first.txhash.GetHex().c_str());
                    continue;
                }
                CPBaaSNotarization pbn(notarizationTx.vout[oneOut.first.index].scriptPubKey);
                if (!pbn.IsValid())
                {
                    LogPrintf("%s: Invalid notarization on transaction %s, vout: %d\n", __func__, oneOut.first.txhash.GetHex().c_str(), (int)oneOut.first.index);
                    continue;
                }

                CCurrencyDefinition curDef;
                int32_t currencyHeight;
                CUTXORef curDefUTXO;
                std::vector<CNodeData> goodNodes;
                if (!GetCurrencyDefinition(pbn.currencyID, curDef, &currencyHeight, false, true, &curDefUTXO, &goodNodes))
                {
                    LogPrintf("%s: Error getting currency definition %s\n", __func__, EncodeDestination(CIdentityID(pbn.currencyID)).c_str());
                    continue;
                }
                if (!currenciesFound.count(curDefUTXO))
                {
                    currenciesFound[curDefUTXO] = curDefVec.size();
                    curDefVec.push_back(std::make_pair(std::make_pair(curDefUTXO, goodNodes), curDef));
                }
            }
        }
    }
    else
    {
        std::vector<CAddressUnspentDbEntry> unspentAddressIndex;
        if (GetAddressUnspent(queryID, CScript::P2IDX, unspentAddressIndex) && unspentAddressIndex.size())
        {
            for (auto &oneOut : unspentAddressIndex)
            {
                CPBaaSNotarization pbn(oneOut.second.script);
                if (!pbn.IsValid())
                {
                    LogPrintf("%s: Invalid notarization in index for %s, vout: %d\n", __func__, oneOut.first.txhash.GetHex().c_str(), (int)oneOut.first.index);
                    continue;
                }
                CCurrencyDefinition curDef;
                int32_t currencyHeight;
                CUTXORef curDefUTXO;
                std::vector<CNodeData> goodNodes;
                if (!GetCurrencyDefinition(pbn.currencyID, curDef, &currencyHeight, false, true, &curDefUTXO, &goodNodes))
                {
                    LogPrintf("%s: Error getting currency definition %s\n", __func__, EncodeDestination(CIdentityID(pbn.currencyID)).c_str());
                    continue;
                }
                if (!currenciesFound.count(curDefUTXO) &&
                    (!endBlock || currencyHeight < endBlock) &&
                    (!startBlock || curDef.startBlock >= startBlock))
                {
                    currenciesFound[curDefUTXO] = curDefVec.size();
                    curDefVec.push_back(std::make_pair(std::make_pair(curDefUTXO, goodNodes), curDef));
                }
            }
        }
    }
}

// can query and return currency definitions for currencies on this system or from a specific system specified in systemIDQualifier
void GetCurrencyDefinitions(const uint160 &systemIDQualifier,
                            std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> &chains,
                            CCurrencyDefinition::EQueryOptions launchStateQuery,
                            CCurrencyDefinition::EQueryOptions systemTypeQuery,
                            bool isConverter,
                            uint32_t startBlock=0,
                            uint32_t endBlock=0)
{
    CCcontract_info CC;
    CCcontract_info *cp;

    std::map<CUTXORef, int> currenciesFound;
    std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> curDefVec;

    if (systemTypeQuery == CCurrencyDefinition::QUERY_SYSTEMTYPE_LOCAL)
    {
        uint160 queryID = CCrossChainRPCData::GetConditionID(systemIDQualifier, CCurrencyDefinition::CurrencySystemKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }
    else if (systemTypeQuery == CCurrencyDefinition::QUERY_SYSTEMTYPE_IMPORTED)
    {
        uint160 queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::ExternalCurrencyKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }
    else if (systemTypeQuery == CCurrencyDefinition::QUERY_SYSTEMTYPE_PBAAS)
    {
        uint160 queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::PBaaSChainKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }
    else if (systemTypeQuery == CCurrencyDefinition::QUERY_SYSTEMTYPE_GATEWAY)
    {
        uint160 queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencyGatewayKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }

    bool narrowBySystem = systemTypeQuery != CCurrencyDefinition::QUERY_NULL;
    bool narrowByLaunch = launchStateQuery != CCurrencyDefinition::QUERY_NULL;
    if (narrowBySystem && !currenciesFound.size())
    {
        return;
    }

    if (narrowByLaunch)
    {
        std::map<CUTXORef, int> launchStateCurrenciesFound;
        std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> launchStateCurVec;
        static std::set<CCurrencyDefinition::EQueryOptions> validLaunchOptions({CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH,
                                                                                CCurrencyDefinition::QUERY_LAUNCHSTATE_REFUND,
                                                                                CCurrencyDefinition::QUERY_LAUNCHSTATE_CONFIRM,
                                                                                CCurrencyDefinition::QUERY_LAUNCHSTATE_COMPLETE});

        if (!validLaunchOptions.count(launchStateQuery))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid launchStateQuery");
        }

        CurrencyNotarizationTypeQuery(launchStateQuery, launchStateCurrenciesFound, launchStateCurVec, startBlock, endBlock);

        if (launchStateCurrenciesFound.size())
        {
            // remove all that are not in the system type of interest
            if (narrowBySystem)
            {
                std::vector<CUTXORef> toRemove;
                for (auto &oneFound : currenciesFound)
                {
                    if (!launchStateCurrenciesFound.count(oneFound.first))
                    {
                        toRemove.push_back(oneFound.first);
                    }
                    else if (currenciesFound[oneFound.first] == -1)
                    {
                        currenciesFound[oneFound.first] = curDefVec.size();
                        curDefVec.push_back(launchStateCurVec[launchStateCurrenciesFound[oneFound.first]]);
                    }
                }
                if (currenciesFound.size() == toRemove.size())
                {
                    return;
                }
                for (auto &oneUtxo : toRemove)
                {
                    currenciesFound.erase(oneUtxo);
                }
            }
            else
            {
                curDefVec.insert(curDefVec.end(), launchStateCurVec.begin(), launchStateCurVec.end());
                currenciesFound = launchStateCurrenciesFound;
            }
        }
        else
        {
            return;
        }
    }

    bool isNarrowing = narrowBySystem || narrowByLaunch;

    if (isNarrowing && !currenciesFound.size())
    {
        return;
    }

    // two options are is converter as narrowing or just is converter
    // for narrowing, we ignore start and end blocks to determine state now
    if (isConverter)
    {
        if (isNarrowing)
        {
            std::map<CUTXORef, int> converterCurrenciesFound;
            std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> converterCurVec;

            // get converters and return only those already found that are converters
            CurrencyNotarizationTypeQuery(CCurrencyDefinition::QUERY_ISCONVERTER, converterCurrenciesFound, converterCurVec, startBlock, endBlock);
            std::vector<CUTXORef> toRemove;
            for (auto &oneFound : currenciesFound)
            {
                if (!converterCurrenciesFound.count(oneFound.first))
                {
                    toRemove.push_back(oneFound.first);
                }
                else if (currenciesFound[oneFound.first] == -1)
                {
                    currenciesFound[oneFound.first] = curDefVec.size();
                    curDefVec.push_back(converterCurVec[converterCurrenciesFound[oneFound.first]]);
                }
            }
            if (currenciesFound.size() == toRemove.size())
            {
                return;
            }
            for (auto &oneUtxo : toRemove)
            {
                currenciesFound.erase(oneUtxo);
            }
        }
        else
        {
            // the only query is converters
            CurrencyNotarizationTypeQuery(CCurrencyDefinition::QUERY_ISCONVERTER, currenciesFound, curDefVec, startBlock, endBlock);
        }
    }
    else if (!isNarrowing)
    {
        // no qualifiers, so we default to this system currencies and retrieve all currencies in the specified block range
        uint160 queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencySystemKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }

    // now, loop through the found currencies and load the currency definition if not loaded, then store all
    // in the return vector
    for (auto &oneCur : currenciesFound)
    {
        if (oneCur.second == -1)
        {
            CTransaction tx;
            uint256 blkHash;
            if (!myGetTransaction(oneCur.first.hash, tx, blkHash) ||
                tx.vout.size() <= oneCur.first.n)
            {
                continue;
            }
            CCurrencyDefinition oneCurDef(tx.vout[oneCur.first.n].scriptPubKey);
            std::vector<CNodeData> nodes;
            if (oneCurDef.IsValid())
            {
                for (int i = oneCur.first.n + 1; i < tx.vout.size(); i++)
                {
                    COptCCParams p;
                    CPBaaSNotarization pbn;

                    if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                        p.vData.size() &&
                        (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                        pbn.currencyID == oneCurDef.GetID())
                    {
                        nodes = pbn.nodes;
                        break;
                    }
                }
                chains.push_back(std::make_pair(std::make_pair(oneCur.first, nodes),  oneCurDef));
            }
        }
        else
        {
            chains.push_back(curDefVec[oneCur.second]);
        }
    }
}

bool CConnectedChains::GetNotaryCurrencies(const CRPCChainData notaryChain, 
                                           const std::set<uint160> &currencyIDs,
                                           std::map<uint160, std::pair<CCurrencyDefinition,CPBaaSNotarization>> &currencyDefs)
{
    for (auto &curID : currencyIDs)
    {
        CCurrencyDefinition oneDef;
        UniValue params(UniValue::VARR);
        params.push_back(EncodeDestination(CIdentityID(curID)));

        UniValue result;
        try
        {
            result = find_value(RPCCallRoot("getcurrency", params), "result");
        } catch (exception e)
        {
            result = NullUniValue;
        }

        if (!result.isNull())
        {
            oneDef = CCurrencyDefinition(result);
        }

        if (!oneDef.IsValid())
        {
            // no matter what happens, we should be able to get a valid currency state of some sort, if not, fail
            LogPrintf("Unable to get currency definition for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
            printf("Unable to get currency definition for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
            return false;
        }

        {
            CChainNotarizationData cnd;
            UniValue result;
            try
            {
                result = find_value(RPCCallRoot("getnotarizationdata", params), "result");
            } catch (exception e)
            {
                result = NullUniValue;
            }

            if (!result.isNull())
            {
                cnd = CChainNotarizationData(result);
            }

            if (!cnd.IsValid())
            {
                // no matter what happens, we should be able to get a valid currency state of some sort, if not, fail
                LogPrintf("Invalid notarization data for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
                printf("Invalid notarization data for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
                return false;
            }
            LOCK(cs_mergemining);
            currencyDefs[oneDef.GetID()].first = oneDef;
            if (cnd.IsConfirmed())
            {
                currencyDefs[oneDef.GetID()].second = cnd.vtx[cnd.lastConfirmed].second;
                currencyDefs[oneDef.GetID()].second.SetBlockOneNotarization();
            }
        }
    }
    return true;
}

bool CConnectedChains::GetNotaryIDs(const CRPCChainData notaryChain, const std::set<uint160> &idIDs, std::map<uint160, CIdentity> &identities)
{
    for (auto &curID : idIDs)
    {
        CIdentity oneDef;
        UniValue params(UniValue::VARR);
        params.push_back(EncodeDestination(CIdentityID(curID)));

        UniValue result;
        try
        {
            result = find_value(RPCCallRoot("getidentity", params), "result");
        } catch (exception e)
        {
            result = NullUniValue;
        }

        if (!result.isNull())
        {
            oneDef = CIdentity(find_value(result, "identity"));
        }

        if (!oneDef.IsValid())
        {
            // no matter what happens, we should be able to get a valid currency state of some sort, if not, fail
            LogPrintf("Unable to get identity for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
            printf("Unable to get identity for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
            return false;
        }

        {
            identities[oneDef.GetID()] = oneDef;
        }
    }
    // if we have a currency converter, create a new ID as a clone of the main chain ID with revocation and recovery as main chain ID
    if (!ConnectedChains.ThisChain().GatewayConverterID().IsNull())
    {
        CIdentity newConverterIdentity = identities[ASSETCHAINS_CHAINID];
        assert(newConverterIdentity.IsValid());
        newConverterIdentity.parent = newConverterIdentity.GetID();
        newConverterIdentity.name = ConnectedChains.ThisChain().gatewayConverterName;
        newConverterIdentity.contentMap.clear();
        newConverterIdentity.revocationAuthority = newConverterIdentity.recoveryAuthority = ASSETCHAINS_CHAINID;
        identities[ConnectedChains.ThisChain().GatewayConverterID()] = newConverterIdentity;
    }
    return true;
}

bool CConnectedChains::GetLastImport(const uint160 &currencyID, 
                                     CTransaction &lastImport, 
                                     int32_t &outputNum)
{
    std::vector<CAddressUnspentDbEntry> unspentOutputs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> memPoolOutputs;

    LOCK2(cs_main, mempool.cs);

    uint160 importKey = CCrossChainRPCData::GetConditionID(currencyID, CCrossChainImport::CurrencyImportKey());

    if (mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({std::make_pair(importKey, CScript::P2IDX)}), memPoolOutputs) &&
        memPoolOutputs.size())
    {
        // make sure it isn't just a burned transaction to that address, drop out on first match
        COptCCParams p;
        CAddressUnspentDbEntry foundOutput;
        std::set<uint256> spentTxOuts;
        std::set<uint256> txOuts;
        
        for (const auto &oneOut : memPoolOutputs)
        {
            // get last one in spending list
            if (oneOut.first.spending)
            {
                spentTxOuts.insert(oneOut.first.txhash);
            }
        }
        for (auto &oneOut : memPoolOutputs)
        {
            if (!spentTxOuts.count(oneOut.first.txhash))
            {
                lastImport = mempool.mapTx.find(oneOut.first.txhash)->GetTx();
                outputNum = oneOut.first.index;
                return true;
            }
        }
    }

    // get last import from the specified chain
    if (!GetAddressUnspent(importKey, CScript::P2IDX, unspentOutputs))
    {
        return false;
    }

    // make sure it isn't just a burned transaction to that address, drop out on first match
    const std::pair<CAddressUnspentKey, CAddressUnspentValue> *pOutput = NULL;
    COptCCParams p;
    CAddressUnspentDbEntry foundOutput;
    for (const auto &output : unspentOutputs)
    {
        if (output.second.script.IsPayToCryptoCondition(p) && p.IsValid() && 
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.vData.size())
        {
            foundOutput = output;
            pOutput = &foundOutput;
            break;
        }
    }
    if (!pOutput)
    {
        return false;
    }
    uint256 hashBlk;
    CCurrencyDefinition newCur;

    if (!myGetTransaction(pOutput->first.txhash, lastImport, hashBlk))
    {
        return false;
    }

    outputNum = pOutput->first.index;

    return true;
}

bool CConnectedChains::GetLastSourceImport(const uint160 &sourceSystemID, 
                                            CTransaction &lastImport, 
                                            int32_t &outputNum)
{
    std::vector<CAddressUnspentDbEntry> unspentOutputs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> memPoolOutputs;

    LOCK2(cs_main, mempool.cs);

    uint160 importKey = CCrossChainRPCData::GetConditionID(sourceSystemID, CCrossChainImport::CurrencySystemImportKey());

    if (mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({std::make_pair(importKey, CScript::P2IDX)}), memPoolOutputs) &&
        memPoolOutputs.size())
    {
        // make sure it isn't just a burned transaction to that address, drop out on first match
        COptCCParams p;
        CAddressUnspentDbEntry foundOutput;
        std::set<uint256> spentTxOuts;
        std::set<uint256> txOuts;
        
        for (const auto &oneOut : memPoolOutputs)
        {
            // get last one in spending list
            if (oneOut.first.spending)
            {
                spentTxOuts.insert(oneOut.first.txhash);
            }
        }
        for (auto &oneOut : memPoolOutputs)
        {
            if (!spentTxOuts.count(oneOut.first.txhash))
            {
                lastImport = mempool.mapTx.find(oneOut.first.txhash)->GetTx();
                outputNum = oneOut.first.index;
                return true;
            }
        }
    }

    // get last import from the specified chain
    if (!GetAddressUnspent(importKey, CScript::P2IDX, unspentOutputs))
    {
        return false;
    }

    // make sure it isn't just a burned transaction to that address, drop out on first match
    const std::pair<CAddressUnspentKey, CAddressUnspentValue> *pOutput = NULL;
    COptCCParams p;
    CAddressUnspentDbEntry foundOutput;
    for (const auto &output : unspentOutputs)
    {
        if (output.second.script.IsPayToCryptoCondition(p) && p.IsValid() && 
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.vData.size())
        {
            foundOutput = output;
            pOutput = &foundOutput;
            break;
        }
    }
    if (!pOutput)
    {
        return false;
    }
    uint256 hashBlk;
    CCurrencyDefinition newCur;

    if (!myGetTransaction(pOutput->first.txhash, lastImport, hashBlk))
    {
        return false;
    }

    outputNum = pOutput->first.index;

    return true;
}

void CheckPBaaSAPIsValid()
{
    //printf("Solution version running: %d\n\n", CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()));
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()) < CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS)
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "PBaaS not activated on blockchain.");
    }
}

void CheckVerusVaultAPIsValid()
{
    //printf("Solution version running: %d\n\n", CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()));
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()) < CConstVerusSolutionVector::activationHeight.ACTIVATE_VERUSVAULT)
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Verus Vault and VerusID Marketplace not activated on blockchain.");
    }
}

void CheckIdentityAPIsValid()
{
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()) < CConstVerusSolutionVector::activationHeight.ACTIVATE_IDENTITY)
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Identity APIs not activated on blockchain.");
    }
}

// returns an i-address string when given a 20 byte hex representation
std::string ConvertAlternateRepresentations(const std::string &paramStr)
{
    // to enable easy conversion from a hex value representation of a currency, which is used in PBaaS folders and
    // conf file names to ensure case insensitive support for unique folders and file names, the prefix "hex:" is allowed
    // on currency names, or even IDs.
    if (paramStr.length() == 44 && paramStr.substr(0, 4) == "hex:")
    {
        std::string hexVal = paramStr.substr(4, 40);
        if (IsHex(hexVal))
        {
            CIdentityID idID;
            idID.SetHex(hexVal);
            return EncodeDestination(idID);
        }
    }
    return paramStr;
}

uint160 ValidateCurrencyName(std::string currencyStr, bool ensureCurrencyValid=false, CCurrencyDefinition *pCurrencyDef=NULL)
{
    std::string extraName;
    uint160 retVal;
    currencyStr = TrimSpaces(currencyStr);
    if (!currencyStr.size())
    {
        return retVal;
    }
    ParseSubNames(currencyStr, extraName, true);
    if (currencyStr.back() == '@')
    {
        return retVal;
    }
    CTxDestination currencyDest = DecodeDestination(currencyStr);
    if (currencyDest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        currencyDest = DecodeDestination(currencyStr + "@");
    }
    uint160 currencyID = GetDestinationID(currencyDest);
    if (currencyDest.which() != COptCCParams::ADDRTYPE_INVALID)
    {
        if (currencyID == ConnectedChains.ThisChain().GetID() && (chainActive.Height() < 1 || _IsVerusActive()))
        {
            if (pCurrencyDef)
            {
                *pCurrencyDef = ConnectedChains.ThisChain();
            }
            return ConnectedChains.ThisChain().GetID();
        }
        // make sure there is such a currency defined on this chain
        if (ensureCurrencyValid)
        {
            CCurrencyDefinition currencyDef;
            if (!GetCurrencyDefinition(currencyID, currencyDef) || !currencyDef.IsValid())
            {
                return retVal;
            }
            retVal = currencyDef.GetID();
            if (pCurrencyDef)
            {
                *pCurrencyDef = currencyDef;
            }
        }
        else
        {
            retVal = currencyID;
        }
    }
    return retVal;
}

uint160 GetChainIDFromParam(const UniValue &param, CCurrencyDefinition *pCurrencyDef=NULL)
{
    return ValidateCurrencyName(ConvertAlternateRepresentations(uni_get_str(param)), true, pCurrencyDef);
}

UniValue getcurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getcurrency \"currencyname\"\n"
            "\nReturns a complete definition for any given chain if it is registered on the blockchain. If the chain requested\n"
            "\nis NULL, chain definition of the current chain is returned.\n"

            "\nArguments\n"
            "1. \"currencyname\"            (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"
            "\nResult:\n"
            "  {\n"
            "    \"version\" : n,                           (int) version of this chain definition\n"
            "    \"name\" : \"string\",                     (string) name or symbol of the chain, same as passed\n"
            "    \"fullyqualifiedname\" : \"string\",       (string) name or symbol of the chain with all parent namespaces, separated by \".\"\n"
            "    \"currencyid\" : \"i-address\",            (string) string that represents the currency ID, same as the ID behind the currency\n"
            "    \"currencyidhex\" : \"hex\",               (string) hex representation of currency ID, getcurrency API supports \"hex:currencyidhex\"\n"
            "    \"parent\" : \"i-address\",                (string) parent blockchain ID\n"
            "    \"systemid\" : \"i-address\",              (string) system on which this currency is considered to run\n"
            "    \"launchsystemid\" : \"i-address\",        (string) system from which this currency was launched\n"
            "    \"notarizationprotocol\" : n               (int) protocol number that determines variations in cross-chain or bridged notarizations\n"
            "    \"proofprotocol\" : n                      (int) protocol number that determines variations in cross-chain or bridged proofs\n"
            "    \"startblock\" : n,                        (int) block # on this chain, which must be notarized into block one of the chain\n"
            "    \"endblock\" : n,                          (int) block # after which, this chain's useful life is considered to be over\n"
            "    \"currencies\" : \"[\"i-address\", ...]\", (stringarray) currencies that can be converted to this currency at launch or makeup a liquidity basket\n"
            "    \"weights\" : \"[n, ...]\",                (numberarray) relative currency weights (only returned for a liquidity basket)\n"
            "    \"conversions\" : \"[n, ...]\",            (numberarray) pre-launch conversion rates for non-fractional currencies\n"
            "    \"minpreconversion\" : \"[n, ...]\",       (numberarray) minimum amounts required in pre-conversions for currency to launch\n"
            "    \"currencies\" : \"[\"i-address\", ...]\", (stringarray) currencies that can be converted to this currency at launch or makeup a liquidity basket\n"
            "    \"currencynames\" : \"{\"i-address\":\"fullname\",...}\", (obj) i-addresses mapped to fully qualified names of all sub-currencies\n"
            "    \"initialsupply\" : n,                     (number) initial currency supply for fractional currencies before preallocation or issuance\n"
            "    \"prelaunchcarveout\" : n,                 (number) pre-launch percentage of proceeds for fractional currency sent to launching ID\n"
            "    \"preallocations\" : \"[{\"i-address\":n}, ...]\", (objarray) VerusIDs and amounts for pre-allocation at launch\n"
            "    \"initialcontributions\" : \"[n, ...]\",   (numberarray) amounts of pre-conversions reserved for launching ID\n"
            "    \"idregistrationfees\" : n,                (number) base cost of IDs for this currency namespace in this currency\n"
            "    \"idreferrallevels\" : n,                  (int) levels of ID referrals (only for native PBaaS chains and IDs)\n"
            "    \"idimportfees\" : n,                      (number) fees required to import an ID to this system (only for native PBaaS chains and IDs)\n"
            "    \"eras\" : \"[obj, ...]\",                 (objarray) different chain phases of rewards and convertibility\n"
            "    {\n"
            "      \"reward\" : \"[n, ...]\",               (int) reward start for each era in native coin\n"
            "      \"decay\" : \"[n, ...]\",                (int) exponential or linear decay of rewards during each era\n"
            "      \"halving\" : \"[n, ...]\",              (int) blocks between halvings during each era\n"
            "      \"eraend\" : \"[n, ...]\",               (int) block marking the end of each era\n"
            "      \"eraoptions\" : \"[n, ...]\",           (int) options (reserved)\n"
            "    }\n"
            "    \"nodes\"      : \"[obj, ..]\",    (objectarray, optional) up to 8 nodes that can be used to connect to the blockchain"
            "      [{\n"
            "         \"nodeidentity\" : \"txid\", (string,  optional) internet, TOR, or other supported address for node\n"
            "         \"paymentaddress\" : n,     (int,     optional) rewards payment address\n"
            "       }, .. ]\n"
            "    \"lastconfirmedcurrencystate\" : {\n"
            "     }\n"
            "    \"besttxid\" : \"txid\"\n"
            "     }\n"
            "    \"confirmednotarization\" : {\n"
            "     }\n"
            "    \"confirmedtxid\" : \"txid\"\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrency", "\"currencyname\"")
            + HelpExampleRpc("getcurrency", "\"currencyname\"")
        );
    }

    LOCK2(cs_main, mempool.cs);
    CheckPBaaSAPIsValid();

    UniValue ret(UniValue::VOBJ);
    uint32_t height = chainActive.Height();

    CCurrencyDefinition chainDef;
    int32_t defHeight = 0;
    CUTXORef defUTXO;
    std::vector<CNodeData> goodNodes;

    uint160 chainID = ValidateCurrencyName(uni_get_str(params[0]));

    if (!GetCurrencyDefinition(chainID, chainDef, &defHeight, false, true, &defUTXO, &goodNodes))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency or currency not found");
    }

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency name or ID");
    }

    if (chainDef.IsValid())
    {
        ret = chainDef.ToUniValue();
        ret.pushKV("currencyidhex", chainDef.GetID().GetHex());
        ret.pushKV("fullyqualifiedname", ConnectedChains.GetFriendlyCurrencyName(chainID));

        if (chainDef.currencies.size())
        {
            UniValue curNames(UniValue::VOBJ);
            for (auto &oneCurID : chainDef.currencies)
            {
                curNames.pushKV(EncodeDestination(CIdentityID(oneCurID)), ConnectedChains.GetFriendlyCurrencyName(oneCurID));
            }
            ret.pushKV("currencynames", curNames);
        }

        if (defUTXO.IsValid())
        {
            ret.push_back(Pair("definitiontxid", defUTXO.hash.GetHex()));
            ret.push_back(Pair("definitiontxout", (int)defUTXO.n));
        }

        UniValue lastStateUni = ConnectedChains.GetCurrencyState(chainDef, height + 1, defHeight).ToUniValue();

        if (chainDef.IsToken() && chainDef.systemID == ASSETCHAINS_CHAINID)
        {
            ret.push_back(Pair("bestheight", chainActive.Height()));
            ret.push_back(Pair("lastconfirmedheight", chainActive.Height()));
            ret.push_back(Pair("bestcurrencystate", lastStateUni));
            ret.push_back(Pair("lastconfirmedcurrencystate", lastStateUni));
        }
        else
        {
            CChainNotarizationData cnd;
            if (GetNotarizationData(chainDef.systemID, cnd) && cnd.IsConfirmed() &&
                cnd.vtx[cnd.lastConfirmed].second.currencyStates.count(chainID))
            {
                ret.push_back(Pair("bestheight", (int64_t)cnd.vtx[cnd.lastConfirmed].second.notarizationHeight));
                if (cnd.vtx[cnd.lastConfirmed].second.IsPreLaunch() && cnd.vtx[cnd.lastConfirmed].second.IsLaunchConfirmed())
                {
                    ret.push_back(Pair("lastconfirmedheight", 0));
                }
                else
                {
                    ret.push_back(Pair("lastconfirmedheight", (int64_t)cnd.vtx[cnd.lastConfirmed].second.notarizationHeight));
                }
                ret.push_back(Pair("bestcurrencystate", lastStateUni));
                ret.push_back(Pair("lastconfirmedcurrencystate", lastStateUni));
            }
            else
            {
                GetNotarizationData(chainID, cnd);

                int32_t confirmedHeight = -1, bestHeight = -1;

                std::set<std::string> nodeAddressSet;
                if (goodNodes.size())
                {
                    UniValue nodeArr(UniValue::VARR);
                    for (auto &oneNode : goodNodes)
                    {
                        if (!nodeAddressSet.count(oneNode.networkAddress))
                        {
                            nodeAddressSet.insert(oneNode.networkAddress);
                            nodeArr.push_back(oneNode.ToUniValue());
                        }
                    }
                    ret.push_back(Pair("nodes", nodeArr));
                }

                if (cnd.forks.size())
                {
                    confirmedHeight = cnd.vtx.size() && cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed].second.notarizationHeight : -1;
                    bestHeight = cnd.vtx.size() && cnd.bestChain != -1 ? cnd.vtx[cnd.forks[cnd.bestChain].back()].second.notarizationHeight : -1;
                }

                if (chainID == ASSETCHAINS_CHAINID)
                {
                    int64_t curHeight = chainActive.Height();
                    ret.push_back(Pair("lastconfirmedheight", curHeight));
                    ret.push_back(Pair("lastconfirmedcurrencystate", lastStateUni));
                    ret.push_back(Pair("bestheight", curHeight));
                }
                else
                {
                    if (!chainDef.IsToken())
                    {
                        ret.push_back(Pair("lastconfirmedheight", confirmedHeight == -1 ? 0 : confirmedHeight));
                        if (confirmedHeight != -1)
                        {
                            ret.push_back(Pair("lastconfirmedtxid", cnd.vtx[cnd.lastConfirmed].first.hash.GetHex().c_str()));
                            ret.push_back(Pair("lastconfirmedcurrencystate", cnd.vtx[cnd.lastConfirmed].second.currencyState.ToUniValue()));
                        }
                    }
                    ret.push_back(Pair("bestheight", bestHeight == -1 ? 0 : bestHeight));
                    if (bestHeight != -1)
                    {
                        ret.push_back(Pair("besttxid", cnd.vtx[cnd.forks[cnd.bestChain].back()].first.hash.GetHex().c_str()));
                        ret.push_back(Pair("bestcurrencystate", cnd.vtx[cnd.forks[cnd.bestChain].back()].second.currencyState.ToUniValue()));
                    }
                }
            }
        }
        return ret;
    }
    else
    {
        return NullUniValue;
    }
}

UniValue getreservedeposits(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getreservedeposits \"currencyname\"\n"
            "\nReturns all deposits under control of the specified currency or chain. If the currency is of an external system\n"
            "or chain, all deposits will be under the control of that system or chain only, not its independent currencies.\n"

            "\nArguments\n"
            "1. \"currencyname\"       (string, optional) full name or i-ID of controlling currency\n"

            "\nResult:\n"
            "  {\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getreservedeposits", "\"currencyname\"")
            + HelpExampleRpc("getreservedeposits", "\"currencyname\"")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    CCurrencyDefinition chainDef;

    uint160 chainID = ValidateCurrencyName(uni_get_str(params[0]), true, &chainDef);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency or currency not found " + uni_get_str(params[0]));
    }

    int32_t defHeight;
    std::vector<CInputDescriptor> reserveDeposits;

    {
        LOCK(mempool.cs);
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);

        if (!ConnectedChains.GetReserveDeposits(chainID, view, reserveDeposits))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Error getting reserve deposits for on-chain currency");
        }
    }

    CCurrencyValueMap totalReserveDeposits;
    for (auto &oneDeposit : reserveDeposits)
    {
        CReserveDeposit rd;
        COptCCParams p;
        if (oneDeposit.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_RESERVE_DEPOSIT &&
            p.vData.size() &&
            (rd = CReserveDeposit(p.vData[0])).IsValid())
        {
            rd.reserveValues.valueMap[ASSETCHAINS_CHAINID] = oneDeposit.nValue;
            totalReserveDeposits += rd.reserveValues;
        }
    }

    UniValue ret(UniValue::VOBJ);

    if (totalReserveDeposits.valueMap.size())
    {
        for (auto &oneBalance : totalReserveDeposits.valueMap)
        {
            ret.push_back(make_pair(EncodeDestination(CIdentityID(oneBalance.first)), ValueFromAmount(oneBalance.second)));
        }
    }
    return ret;
}

UniValue getpendingtransfers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getpendingtransfers \"chainname\"\n"
            "\nReturns all pending transfers for a particular chain that have not yet been aggregated into an export\n"

            "\nArguments\n"
            "1. \"chainname\"                     (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"

            "\nResult:\n"
            "  {\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getpendingtransfers", "\"chainname\"")
            + HelpExampleRpc("getpendingtransfers", "\"chainname\"")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    CCurrencyDefinition chainDef;
    int32_t defHeight;

    if (GetCurrencyDefinition(chainID, chainDef, &defHeight))
    {
        // look for new exports
        multimap<uint160, ChainTransferData> inputDescriptors;

        if (GetUnspentChainTransfers(inputDescriptors, chainID))
        {
            UniValue ret(UniValue::VARR);

            for (auto &desc : inputDescriptors)
            {
                UniValue oneExport(UniValue::VOBJ);
                uint32_t inpHeight = std::get<0>(desc.second);
                CInputDescriptor inpDesc = std::get<1>(desc.second);

                oneExport.push_back(Pair("currencyid", EncodeDestination(CIdentityID(desc.first))));
                oneExport.push_back(Pair("height", (int64_t)inpHeight));
                oneExport.push_back(Pair("txid", inpDesc.txIn.prevout.hash.GetHex()));
                oneExport.push_back(Pair("n", (int32_t)inpDesc.txIn.prevout.n));
                oneExport.push_back(Pair("valueout", inpDesc.nValue));
                oneExport.push_back(Pair("reservetransfer", std::get<2>(desc.second).ToUniValue()));
                ret.push_back(oneExport);
            }
            if (ret.size())
            {
                return ret;
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unrecognized currency name or ID");
    }
    
    return NullUniValue;
}

UniValue getexports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "getexports \"chainname\" (heightstart) (heightend)\n"
            "\nReturns pending export transfers to the specified currency from start height to end height if specified\n"

            "\nArguments\n"
            "\"chainname\"                      (string, required)  name/ID of the currency to look for. no parameter returns current chain\n"
            "\"heightstart\"                    (int, optional)     default=0 only return exports at or above this height\n"
            "\"heightend\"                      (int, optional)     dedfault=maxheight only return exports below or at this height\n"

            "\nResult:\n"
            "  [{\n"
            "     \"height\": n,"
            "     \"txid\": \"hexid\","
            "     \"txoutnum\": n,"
            "     \"partialtransactionproof\": \"hexstr\","             // proof's are relative to the heightend, if specified. if not, they are invalid
            "     \"transfers\": [{transfer1}, {transfer2},...]"
            "  }, ...]\n"

            "\nExamples:\n"
            + HelpExampleCli("getexports", "\"chainname\" (heightstart) (heightend)")
            + HelpExampleRpc("getexports", "\"chainname\" (heightstart) (heightend)")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK2(cs_main, mempool.cs);

    uint160 currencyID;
    CCurrencyDefinition curDef;
    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;

    if ((currencyID = ValidateCurrencyName(uni_get_str(params[0]), true, &curDef)).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    uint32_t fromHeight = 0, toHeight = INT32_MAX;
    uint32_t proofHeight = 0;
    uint32_t nHeight = chainActive.Height();

    if (params.size() > 1)
    {
        fromHeight = uni_get_int64(params[1]);
    }
    if (params.size() > 2)
    {
        toHeight = uni_get_int64(params[2]);
        proofHeight = toHeight != 0 && (toHeight < nHeight) ? toHeight : nHeight;
        toHeight = proofHeight;
    }

    if ((curDef.IsGateway() && curDef.gatewayID == currencyID) ||
        (curDef.systemID == currencyID))
    {
        ConnectedChains.GetSystemExports(currencyID, exports, fromHeight, toHeight, true);
    }
    else
    {
        ConnectedChains.GetCurrencyExports(currencyID, exports, fromHeight, toHeight);
    }

    UniValue retVal(UniValue::VARR);

    for (auto &oneExport : exports)
    {
        UniValue oneObj(UniValue::VOBJ);
        CTransaction tx;
        uint256 blkHash;
        if (!myGetTransaction(oneExport.first.first.txIn.prevout.hash, tx, blkHash) || blkHash.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid export transaction");
        }
        auto indexIt = mapBlockIndex.find(blkHash);
        if (indexIt == mapBlockIndex.end())
        {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "transaction for export not found in main block index");
        }
        oneObj.push_back(Pair("height", indexIt->second->GetHeight()));
        oneObj.push_back(Pair("txid", oneExport.first.first.txIn.prevout.hash.GetHex()));
        oneObj.push_back(Pair("txoutnum", (int64_t)oneExport.first.first.txIn.prevout.n));
        CCrossChainExport ccx(oneExport.first.first.scriptPubKey);
        oneObj.push_back(Pair("exportinfo", ccx.ToUniValue()));
        if (oneExport.first.second.IsValid())
        {
            oneObj.push_back(Pair("partialtransactionproof", oneExport.first.second.ToUniValue()));
        }

        UniValue transferArr(UniValue::VARR);
        for (auto &oneTransfer : oneExport.second)
        {
            /* // check serialization discrepancies
            if (oneTransfer.IsCurrencyExport() && oneTransfer.destination.TypeNoFlags() == oneTransfer.destination.DEST_REGISTERCURRENCY)
            {
                CCurrencyDefinition exportDef = CCurrencyDefinition(oneTransfer.destination.destination);
                CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(exportDef.GetID());
                auto exportDefVec = ::AsVector(exportDef);
                auto onChainDefVec = ::AsVector(curDef);
                auto translatedDefVec = ::AsVector(CCurrencyDefinition(exportDef.ToUniValue()));
                if (exportDefVec != onChainDefVec || onChainDefVec != translatedDefVec)
                {
                    printf("Exported currency:\n%s\nOn-chain currency:\n%s\nSerialized export:\n%s\nSerialized on-chain:\n%s\nSerialized translated:\n%s\n", 
                        exportDef.ToUniValue().write(1,2).c_str(),
                        curDef.ToUniValue().write(1,2).c_str(),
                        HexBytes(&(exportDefVec[0]), exportDefVec.size()).c_str(),
                        HexBytes(&(onChainDefVec[0]), onChainDefVec.size()).c_str(),
                        HexBytes(&(translatedDefVec[0]), translatedDefVec.size()).c_str());
                }
                auto transferVec = ::AsVector(oneTransfer);
                printf("ReserveTransfer:\n%s\nSerialized:\n%s\n", oneTransfer.ToUniValue().write(1,2).c_str(), HexBytes(&(transferVec[0]), transferVec.size()).c_str());
            } //*/
            transferArr.push_back(oneTransfer.ToUniValue());
        }
        oneObj.push_back(Pair("transfers", transferArr));

        retVal.push_back(oneObj);
    }

    return retVal;
}

UniValue submitimports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "submitimports '{\"sourcesystemid\":\"systemid\", \"notarizationtxid\":\"txid\", \"notarizationtxoutnum\":n,\n"
            "\"exports\":[{\"txid\":\"hexid\", \"txoutnum\":n, \"partialtransactionproof\":\"hexstr\", \n"
            "\"transfers\": [{transfer1}, {transfer2},...]}, ...]}'\n\n"
            "\nAccepts a set of exports from another system to post to the " + VERUS_CHAINNAME + " network.\n"

            "\nArguments\n"
            "  {\n"
            "    \"sourcesystemid\":\"systemid\"        ()\n"
            "    \"notarizationtxid\":\"txid\"          ()\n"
            "    \"notarizationtxoutnum\":n             ()\n"
            "    \"exports\": [{\n"
            "       \"height\": n,\n"                                   // height on the other system of this export
            "       \"txid\": \"hexid\",\n"                             // export txid on the other system
            "       \"txoutnum\": n,\n"                                 // export tx out num on the other system
            "       \"partialtransactionproof\": \"hexstr\",\n"         // transaction proof, relative to the specified notarization
            "       \"transfers\": [{transfer1}, {transfer2},...]\n"    // all reserve transfers for this export
            "    }, ...]\n"
            "  }\n"

            "\nResult:\n"
            "  [{\n"                                                    // list of transactions and the specific cross chain outputs created
            "     \"currency\": \"currencyid\"\n"                       // destination currency
            "     \"txid\": \"hexid\",\n"                               // import txid
            "     \"txoutnum\": n\n"                                    // txoutnum on transaction
            "  }, ...]\n"

            "\nExamples:\n"
            + HelpExampleCli("submitimports", "{\"sourcesystemid\":\"systemid\", \"notarizationtxid\":\"txid\", \"notarizationtxoutnum\":n, \"exports\":[{\"height\":n, \"txid\":\"hexid\", \"txoutnum\":n, \"partialtransactionproof\":\"hexstr\", \"transfers\": [{transfer1}, {transfer2},...]}, ...]}")
            + HelpExampleRpc("submitimports", "{\"sourcesystemid\":\"systemid\", \"notarizationtxid\":\"txid\", \"notarizationtxoutnum\":n, \"exports\":[{\"height\":n, \"txid\":\"hexid\", \"txoutnum\":n, \"partialtransactionproof\":\"hexstr\", \"transfers\": [{transfer1}, {transfer2},...]}, ...]}")
        );
    }

    CheckPBaaSAPIsValid();

    if (!params[0].isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. see help.");
    }

    LOCK(cs_main);

    CCurrencyDefinition curDef;
    uint160 sourceSystemID = ValidateCurrencyName(uni_get_str(find_value(params[0], "sourcesystemid")), true, &curDef);

    sourceSystemID = curDef.IsGateway() ? curDef.gatewayID : curDef.systemID;

    // source system must be a different system and an actual system
    if (sourceSystemID.IsNull() ||
        curDef.GetID() != sourceSystemID ||
        sourceSystemID == ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid chain name or chain ID");
    }

    uint256 notarizationTxId = uint256S(uni_get_str(find_value(params[0], "notarizationtxid")));
    int notarizationTxOutNum = uni_get_int(find_value(params[0], "notarizationtxoutnum"));
    CTransaction notarizationTx;
    uint256 blkHash;
    COptCCParams p;
    CPBaaSNotarization lastConfirmed;

    {
        LOCK2(smartTransactionCS, mempool.cs);

        if (!(!notarizationTxId.IsNull() &&
            myGetTransaction(notarizationTxId, notarizationTx, blkHash) &&
            !blkHash.IsNull() &&
            notarizationTxOutNum >= 0 &&
            notarizationTx.vout.size() > notarizationTxOutNum &&
            notarizationTx.vout[notarizationTxOutNum].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            (p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
            p.vData.size() &&
            (lastConfirmed = CPBaaSNotarization(p.vData[0])).IsValid()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid notarization transaction id or transaction");
        }
    }

    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;
    UniValue exportsUni = find_value(params[0], "exports");
    if (!exportsUni.isArray() ||
        !exportsUni.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "parameters must include valid exports to import");
    }

    for (int i = 0; i < exportsUni.size(); i++)
    {
        // create one import at a time
        uint256 exportTxId = uint256S(uni_get_str(find_value(exportsUni[i], "txid")));
        int32_t exportTxOutNum = uni_get_int(find_value(exportsUni[i], "txoutnum"));
        CPartialTransactionProof txProof = CPartialTransactionProof(find_value(exportsUni[i], "partialtransactionproof"));
        UniValue transferArrUni = find_value(exportsUni[i], "transfers");
        if (exportTxId.IsNull() || 
            exportTxOutNum == -1 ||
            !transferArrUni.isArray())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid export from " + uni_get_str(params[0]));
        }

        CTransaction exportTx;
        uint256 blkHash;
        auto proofRootIt = lastConfirmed.proofRoots.find(sourceSystemID);
        if (!(txProof.IsValid() &&
            !txProof.GetPartialTransaction(exportTx).IsNull() &&
            exportTxId == txProof.TransactionHash() &&
            proofRootIt != lastConfirmed.proofRoots.end() &&
            proofRootIt->second.stateRoot == txProof.CheckPartialTransaction(exportTx) &&
            exportTx.vout.size() > exportTxOutNum))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid export 1 from " + uni_get_str(params[0]));
        }

        std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> oneExport =
            std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[exportTxOutNum].scriptPubKey, 
                                            exportTx.vout[exportTxOutNum].nValue, 
                                            CTxIn(exportTxId, exportTxOutNum)),
                                            txProof),
                            std::vector<CReserveTransfer>());

        for (int j = 0; j < transferArrUni.size(); j++)
        {
            oneExport.second.push_back(CReserveTransfer(transferArrUni[j]));
            if (!oneExport.second.back().IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid reserve transfers from export of " + uni_get_str(params[0]));
            }
        }
        exports.push_back(oneExport);
    }

    std::map<uint160, std::vector<std::pair<int, CTransaction>>> newImports;
    ConnectedChains.CreateLatestImports(curDef, CUTXORef(notarizationTxId, notarizationTxOutNum), exports, newImports);

    UniValue retVal(UniValue::VARR);
    for (auto &oneExportCurrency : newImports)
    {
        for (auto &oneExport : oneExportCurrency.second)
        {
            retVal.push_back(Pair("currencyid", EncodeDestination(CIdentityID(oneExportCurrency.first))));
            retVal.push_back(Pair("txid", oneExport.second.GetHash().GetHex()));
            retVal.push_back(Pair("txoutnum", oneExport.first));
        }
    }
    return retVal;
}

UniValue getlastimportfrom(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getlastimportfrom \"systemname\"\n"
            "\nReturns the last import from a specific originating system.\n"

            "\nArguments\n"
            "1. \"systemname\"                      (string, optional) name or ID of the system to retrieve the last import from\n"

            "\nResult:\n"
            "  {\n"
            "     \"lastimport\" :                  (object) last import from the indicated system on this chain\n"
            "       {\n"
            "       }\n"
            "     \"lastconfirmednotarization\" :   (object) last confirmed notarization of the indicated system on this chain\n"
            "       {\n"
            "       }\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getlastimportfrom", "\"systemname\"")
            + HelpExampleRpc("getlastimportfrom", "\"systemname\"")
        );
    }
    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    uint160 chainID;
    CCurrencyDefinition chainDef;
    int32_t defHeight;

    if ((chainID = ValidateCurrencyName(uni_get_str(params[0]), true, &chainDef)).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    if ((chainDef.IsToken() && !chainDef.IsGateway()) || chainID == ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getlastimportfrom retrieves the last import from an external, not local system");
    }

    CChainNotarizationData cnd;
    if (!GetNotarizationData(chainID, cnd) || !cnd.IsConfirmed())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot locate confirmed notarization data for system or chain");
    }

    std::vector<CAddressUnspentDbEntry> unspentOutputs;
    CCrossChainImport lastCCI;
    bool found = false;
    CAddressUnspentDbEntry foundEntry;

    if (GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(chainID, CCrossChainImport::CurrencySystemImportKey())), CScript::P2IDX, unspentOutputs) &&
        unspentOutputs.size())
    {
        for (auto &txidx : unspentOutputs)
        {
            COptCCParams p;
            if (txidx.second.script.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (lastCCI = CCrossChainImport(p.vData[0])).IsValid())
            {
                found = true;
                foundEntry = txidx;
                break;
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No import thread found for currency");
    }

    UniValue retVal(UniValue::VOBJ);
    if (found)
    {
        retVal.pushKV("lastimport", lastCCI.ToUniValue());
        retVal.pushKV("lastimportutxo", CUTXORef(foundEntry.first.txhash, foundEntry.first.index).ToUniValue());
    }
    retVal.pushKV("lastconfirmednotarization", cnd.vtx[cnd.lastConfirmed].second.ToUniValue());
    retVal.pushKV("lastconfirmedutxo", cnd.vtx[cnd.lastConfirmed].first.ToUniValue());
    return retVal;
}

UniValue getimports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getimports \"chainname\" (startheight) (endheight)\n"
            "\nReturns all imports into a specific currency, optionally that were imported between a specific block range.\n"

            "\nArguments\n"
            "1. \"chainname\"                     (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"

            "\nResult:\n"
            "  {\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getimports", "\"chainname\"")
            + HelpExampleRpc("getimports", "\"chainname\"")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    uint160 chainID;
    CCurrencyDefinition chainDef;
    int32_t defHeight;

    if ((chainID = ValidateCurrencyName(uni_get_str(params[0]), true, &chainDef)).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    uint32_t fromHeight = 0, toHeight = INT32_MAX;
    uint32_t proofHeight = 0;
    uint32_t nHeight = chainActive.Height();

    if (params.size() > 1)
    {
        fromHeight = uni_get_int64(params[1]);
    }
    if (params.size() > 2)
    {
        toHeight = uni_get_int64(params[2]);
        proofHeight = toHeight < nHeight ? toHeight : nHeight;
        toHeight = proofHeight;
    }

    if (GetCurrencyDefinition(chainID, chainDef, &defHeight))
    {
        // which transaction are we in this block?
        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
        uint160 searchKey = CCrossChainRPCData::GetConditionID(chainID, CCrossChainImport::CurrencyImportKey());
        CBlockIndex *pIndex;
        CChainNotarizationData cnd;

        // get all import transactions including and since this one up to the confirmed height
        if (GetAddressIndex(searchKey, CScript::P2IDX, addressIndex, fromHeight, toHeight))
        {
            UniValue ret(UniValue::VARR);

            for (auto &idx : addressIndex)
            {
                uint256 blkHash;
                CTransaction importTx;
                if (!idx.first.spending && myGetTransaction(idx.first.txhash, importTx, blkHash))
                {
                    CCrossChainExport ccx;
                    CCrossChainImport cci;
                    int32_t sysCCIOut;
                    CPBaaSNotarization importNotarization;
                    int32_t importNotOut;
                    int32_t evidenceOutStart, evidenceOutEnd;
                    std::vector<CReserveTransfer> reserveTransfers;
                    uint32_t importHeight = 0;

                    auto importBlockIdxIt = mapBlockIndex.find(blkHash);
                    if (importBlockIdxIt != mapBlockIndex.end() && chainActive.Contains(importBlockIdxIt->second))
                    {
                        importHeight = importBlockIdxIt->second->GetHeight();
                    }
                    else
                    {
                        continue;
                    }

                    /* UniValue scrOut(UniValue::VOBJ);
                    ScriptPubKeyToUniv(importTx.vout[idx.first.index].scriptPubKey, scrOut, false);
                    printf("%s: scriptOut: %s\n", __func__, scrOut.write(1,2).c_str()); */

                    CCrossChainImport sysCCI;
                    if ((cci = CCrossChainImport(importTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
                        cci.GetImportInfo(importTx, importHeight, idx.first.index, ccx, sysCCI, sysCCIOut, importNotarization, importNotOut, evidenceOutStart, evidenceOutEnd, reserveTransfers))
                    {
                        UniValue oneImportUni(UniValue::VOBJ);

                        oneImportUni.push_back(Pair("importheight", (int64_t)importHeight));
                        oneImportUni.push_back(Pair("importtxid", idx.first.txhash.GetHex()));
                        oneImportUni.push_back(Pair("importvout", (int64_t)idx.first.index));
                        oneImportUni.push_back(Pair("import", cci.ToUniValue()));
                        if (sysCCIOut != -1)
                        {
                            oneImportUni.push_back(Pair("sysimport", sysCCI.ToUniValue()));
                        }
                        oneImportUni.push_back(Pair("importnotarization", importNotarization.ToUniValue()));

                        UniValue transferArr(UniValue::VARR);
                        for (auto &oneTransfer : reserveTransfers)
                        {
                            transferArr.push_back(oneTransfer.ToUniValue());
                        }
                        oneImportUni.push_back(Pair("transfers", transferArr));
                        ret.push_back(oneImportUni);
                    }
                }
            }
            if (ret.size())
            {
                return ret;
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unrecognized currency name or ID");
    }
    return NullUniValue;
}

UniValue listcurrencies(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
    {
        throw runtime_error(
            "listcurrencies ({query object}) startblock endblock\n"
            "\nReturns a complete definition for any given chain if it is registered on the blockchain. If the chain requested\n"
            "\nis NULL, chain definition of the current chain is returned.\n"

            "\nArguments\n"
            "{                                    (json, optional) specify valid query conditions\n"
            "   \"launchstate\" :                   (\"prelaunch\" | \"launched\" | \"refund\" | \"complete\") (optional) return only currencies in that state\n"
            "   \"systemtype\" :                    (\"local\" | \"imported\" | \"gateway\" | \"pbaas\")\n"
            "   \"fromsystem\" :                    (\"systemnameeorid\") default is the local chain, but if currency is from another system, specify here\n"
            "   \"converter\": bool                 (bool, optional) default false, only return fractional currency converters\n"
            "}\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"version\" : n,                           (int) version of this chain definition\n"
            "    \"name\" : \"string\",                     (string) name or symbol of the chain, same as passed\n"
            "    \"fullyqualifiedname\" : \"string\",       (string) name or symbol of the chain with all parent namespaces, separated by \".\"\n"
            "    \"currencyid\" : \"i-address\",            (string) string that represents the currency ID, same as the ID behind the currency\n"
            "    \"currencyidhex\" : \"hex\",               (string) hex representation of currency ID, getcurrency API supports \"hex:currencyidhex\"\n"
            "    \"parent\" : \"i-address\",                (string) parent blockchain ID\n"
            "    \"systemid\" : \"i-address\",              (string) system on which this currency is considered to run\n"
            "    \"launchsystemid\" : \"i-address\",        (string) system from which this currency was launched\n"
            "    \"notarizationprotocol\" : n               (int) protocol number that determines variations in cross-chain or bridged notarizations\n"
            "    \"proofprotocol\" : n                      (int) protocol number that determines variations in cross-chain or bridged proofs\n"
            "    \"startblock\" : n,                        (int) block # on this chain, which must be notarized into block one of the chain\n"
            "    \"endblock\" : n,                          (int) block # after which, this chain's useful life is considered to be over\n"
            "    \"currencies\" : \"[\"i-address\", ...]\", (stringarray) currencies that can be converted to this currency at launch or makeup a liquidity basket\n"
            "    \"weights\" : \"[n, ...]\",                (numberarray) relative currency weights (only returned for a liquidity basket)\n"
            "    \"conversions\" : \"[n, ...]\",            (numberarray) pre-launch conversion rates for non-fractional currencies\n"
            "    \"minpreconversion\" : \"[n, ...]\",       (numberarray) minimum amounts required in pre-conversions for currency to launch\n"
            "    \"currencies\" : \"[\"i-address\", ...]\", (stringarray) currencies that can be converted to this currency at launch or makeup a liquidity basket\n"
            "    \"currencynames\" : \"{\"i-address\":\"fullname\",...}\", (obj) i-addresses mapped to fully qualified names of all sub-currencies\n"
            "    \"initialsupply\" : n,                     (number) initial currency supply for fractional currencies before preallocation or issuance\n"
            "    \"prelaunchcarveout\" : n,                 (number) pre-launch percentage of proceeds for fractional currency sent to launching ID\n"
            "    \"preallocations\" : \"[{\"i-address\":n}, ...]\", (objarray) VerusIDs and amounts for pre-allocation at launch\n"
            "    \"initialcontributions\" : \"[n, ...]\",   (numberarray) amounts of pre-conversions reserved for launching ID\n"
            "    \"idregistrationfees\" : n,                (number) base cost of IDs for this currency namespace in this currency\n"
            "    \"idreferrallevels\" : n,                  (int) levels of ID referrals (only for native PBaaS chains and IDs)\n"
            "    \"idimportfees\" : n,                      (number) fees required to import an ID to this system (only for native PBaaS chains and IDs)\n"
            "    \"eras\" : \"[obj, ...]\",                 (objarray) different chain phases of rewards and convertibility\n"
            "    {\n"
            "      \"reward\" : \"[n, ...]\",               (int) reward start for each era in native coin\n"
            "      \"decay\" : \"[n, ...]\",                (int) exponential or linear decay of rewards during each era\n"
            "      \"halving\" : \"[n, ...]\",              (int) blocks between halvings during each era\n"
            "      \"eraend\" : \"[n, ...]\",               (int) block marking the end of each era\n"
            "      \"eraoptions\" : \"[n, ...]\",           (int) options (reserved)\n"
            "    }\n"
            "    \"nodes\"      : \"[obj, ..]\",    (objectarray, optional) up to 8 nodes that can be used to connect to the blockchain"
            "      [{\n"
            "         \"nodeidentity\" : \"txid\", (string,  optional) internet, TOR, or other supported address for node\n"
            "         \"paymentaddress\" : n,     (int,     optional) rewards payment address\n"
            "       }, .. ]\n"
            "    \"lastconfirmedcurrencystate\" : {\n"
            "     }\n"
            "    \"besttxid\" : \"txid\"\n"
            "     }\n"
            "    \"confirmednotarization\" : {\n"
            "     }\n"
            "    \"confirmedtxid\" : \"txid\"\n"
            "  }, ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listcurrencies", "true")
            + HelpExampleRpc("listcurrencies", "true")
        );
    }

    CheckPBaaSAPIsValid();

    UniValue ret(UniValue::VARR);

    uint160 querySystem;
    static std::map<std::string, CCurrencyDefinition::EQueryOptions> launchStates(
        {{"prelaunch", CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH},
         {"launched", CCurrencyDefinition::QUERY_LAUNCHSTATE_CONFIRM},
         {"refund", CCurrencyDefinition::QUERY_LAUNCHSTATE_REFUND},
         {"complete", CCurrencyDefinition::QUERY_LAUNCHSTATE_COMPLETE}}
    );
    static std::map<std::string, CCurrencyDefinition::EQueryOptions> systemTypes(
        {{"local", CCurrencyDefinition::QUERY_SYSTEMTYPE_LOCAL},
         {"imported", CCurrencyDefinition::QUERY_SYSTEMTYPE_IMPORTED},
         {"gateway", CCurrencyDefinition::QUERY_SYSTEMTYPE_GATEWAY},
         {"pbaas", CCurrencyDefinition::QUERY_SYSTEMTYPE_PBAAS}}
    );

    CCurrencyDefinition::EQueryOptions launchStateQuery = CCurrencyDefinition::QUERY_NULL;
    CCurrencyDefinition::EQueryOptions systemTypeQuery = CCurrencyDefinition::QUERY_NULL;
    bool isConverter = false;
    uint32_t startBlock = 0;
    uint32_t endBlock = 0;
    uint160 fromSystemID = ASSETCHAINS_CHAINID;
    if (params.size())
    {
        if (!params[0].isObject())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid query object parameter");
        }
        int numKeys = params[0].getKeys().size();
        std::string launchState = uni_get_str(find_value(params[0], "launchstate"));
        std::string systemType = uni_get_str(find_value(params[0], "systemtype"));
        std::string fromSystemIDStr = uni_get_str(find_value(params[0], "fromsystem"));
        if (fromSystemIDStr.size())
        {
            fromSystemID = ValidateCurrencyName(fromSystemIDStr, true);
            if (fromSystemID.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain or gateway specified in fromsystem not found");
            }
            systemType = "local";
        }

        UniValue isConverterUni = find_value(params[0], "converter");
        if (!isConverterUni.isNull())
        {
            numKeys--;
        }
        isConverter = uni_get_bool(isConverterUni);
        if (launchStates.count(launchState))
        {
            launchStateQuery = launchStates[launchState];
            numKeys--;
        }
        if (systemTypes.count(systemType))
        {
            systemTypeQuery = systemTypes[systemType];
            numKeys--;
        }
        if (numKeys)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid query object parameter, use \"listidentities help\"");
        }
        if (params.size() > 1)
        {
            startBlock = uni_get_int64(params[1]);
        }
        if (params.size() > 2)
        {
            endBlock = uni_get_int64(params[2]);
        }
    }

    std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> chains;
    {
        LOCK2(cs_main, mempool.cs);
        GetCurrencyDefinitions(fromSystemID, chains, launchStateQuery, systemTypeQuery, isConverter, startBlock, endBlock);
    }

    for (auto oneDef : chains)
    {
        LOCK2(cs_main, mempool.cs);
        CCurrencyDefinition &def = oneDef.second;

        UniValue oneChain(UniValue::VOBJ);
        UniValue oneDefUni = def.ToUniValue();
        oneDefUni.pushKV("currencyidhex", def.GetID().GetHex());
        oneDefUni.pushKV("fullyqualifiedname", ConnectedChains.GetFriendlyCurrencyName(def.GetID()));

        if (oneDef.first.first.IsValid())
        {
            oneDefUni.push_back(Pair("definitiontxid", oneDef.first.first.hash.GetHex()));
            oneDefUni.push_back(Pair("definitiontxout", (int)oneDef.first.first.n));
        }

        if (oneDef.first.second.size())
        {
            UniValue nodesUni(UniValue::VARR);
            for (auto node : oneDef.first.second)
            {
                nodesUni.push_back(node.ToUniValue());
            }
            oneDefUni.push_back(Pair("nodes", nodesUni));
        }

        oneChain.push_back(Pair("currencydefinition", oneDefUni));

        CChainNotarizationData cnd;
        GetNotarizationData(def.GetID(), cnd);

        int32_t confirmedHeight = -1, bestHeight = -1;
        confirmedHeight = cnd.vtx.size() && cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed].second.notarizationHeight : -1;
        bestHeight = cnd.vtx.size() && cnd.bestChain != -1 ? cnd.vtx[cnd.forks[cnd.bestChain].back()].second.notarizationHeight : -1;

        if (!def.IsToken())
        {
            oneChain.push_back(Pair("lastconfirmedheight", confirmedHeight == -1 ? 0 : confirmedHeight));
            if (confirmedHeight != -1)
            {
                oneChain.push_back(Pair("lastconfirmedtxid", cnd.vtx[cnd.lastConfirmed].first.hash.GetHex().c_str()));
                oneChain.push_back(Pair("lastconfirmedtxout", (uint64_t)cnd.vtx[cnd.lastConfirmed].first.n));
                oneChain.push_back(Pair("lastconfirmednotarization", cnd.vtx[cnd.lastConfirmed].second.ToUniValue()));
            }
        }
        oneChain.push_back(Pair("bestheight", bestHeight == -1 ? 0 : bestHeight));
        if (bestHeight != -1)
        {
            oneChain.push_back(Pair("besttxid", cnd.vtx[cnd.forks[cnd.bestChain].back()].first.hash.GetHex().c_str()));
            oneChain.push_back(Pair("besttxout", (uint64_t)cnd.vtx[cnd.forks[cnd.bestChain].back()].first.n));
            oneChain.push_back(Pair("bestcurrencystate", cnd.vtx[cnd.forks[cnd.bestChain].back()].second.currencyState.ToUniValue()));
        }
        ret.push_back(oneChain);
    }
    return ret;
}

// returns all chain transfer outputs, both spent and unspent between a specific start and end block with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that system are returned
bool GetChainTransfers(multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, uint160 chainFilter, int start, int end, uint32_t flags)
{
    if (!flags)
    {
        flags = CReserveTransfer::VALID;
    }
    bool nofilter = chainFilter.IsNull();

    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    LOCK2(cs_main, mempool.cs);

    if (!GetAddressIndex(CReserveTransfer::ReserveTransferKey(), 
                         CScript::P2IDX, 
                         addressIndex, 
                         start, 
                         end))
    {
        return false;
    }
    else
    {
        for (auto it = addressIndex.begin(); it != addressIndex.end(); it++)
        {
            CTransaction ntx;
            uint256 blkHash;

            if (it->first.spending)
            {
                continue;
            }

            if (myGetTransaction(it->first.txhash, ntx, blkHash))
            {
                COptCCParams p, m;
                CReserveTransfer rt;
                if (ntx.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.evalCode == EVAL_RESERVE_TRANSFER &&
                    p.vData.size() > 1 && (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                    (m = COptCCParams(p.vData[1])).IsValid() &&
                    (nofilter || ((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID) == chainFilter) &&
                    (rt.flags & flags) == flags)
                {
                    inputDescriptors.insert(make_pair(((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID),
                                                make_pair(CInputDescriptor(ntx.vout[it->first.index].scriptPubKey, ntx.vout[it->first.index].nValue, CTxIn(COutPoint(it->first.txhash, it->first.index))), 
                                                            rt)));
                }

                /*
                uint256 hashBlk;
                UniValue univTx(UniValue::VOBJ);
                TxToUniv(ntx, hashBlk, univTx);
                printf("tx: %s\n", univTx.write(1,2).c_str());
                */
            }
            else
            {
                LogPrintf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                return false;
            }
        }
        return true;
    }
}

// returns all chain transfer outputs, both spent and unspent between a specific start and end block with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that system are returned
bool GetChainTransfersUnspentBy(std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, uint160 chainFilter, uint32_t start, uint32_t end, uint32_t unspentBy, uint32_t flags)
{
    if (!flags)
    {
        flags = CReserveTransfer::VALID;
    }
    bool nofilter = chainFilter.IsNull();

    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    LOCK2(cs_main, mempool.cs);

    if (!GetAddressIndex(CReserveTransfer::ReserveTransferKey(), 
                         CScript::P2IDX, 
                         addressIndex, 
                         start, 
                         end))
    {
        return false;
    }
    else
    {
        // This call does not include outputs that were mined in as spent at the
        // end height requested
        for (auto it = addressIndex.begin(); it != addressIndex.end(); it++)
        {
            CTransaction ntx;
            uint256 blkHash;

            if (it->first.spending)
            {
                continue;
            }

            // no matter where we are getting the reserve transfers from, if they are otherwise spent
            // in the block prior, they are not considered unspent by the "end" block, meaning they 
            CSpentIndexValue spentInfo;
            CSpentIndexKey spentKey(it->first.txhash, it->first.index);

            if (GetSpentIndex(spentKey, spentInfo) &&
                !spentInfo.IsNull() &&
                spentInfo.blockHeight < unspentBy)
            {
                continue;
            }

            if (myGetTransaction(it->first.txhash, ntx, blkHash))
            {
                COptCCParams p, m;
                CReserveTransfer rt;
                if (ntx.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.evalCode == EVAL_RESERVE_TRANSFER &&
                    p.vData.size() > 1 && (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                    (m = COptCCParams(p.vData[1])).IsValid() &&
                    (nofilter || ((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID) == chainFilter) &&
                    (rt.flags & flags) == flags)
                {
                    inputDescriptors.insert(std::make_pair(((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID),
                                                std::make_pair(CInputDescriptor(ntx.vout[it->first.index].scriptPubKey, ntx.vout[it->first.index].nValue, CTxIn(COutPoint(it->first.txhash, it->first.index))), 
                                                               rt)));
                }

                /*
                uint256 hashBlk;
                UniValue univTx(UniValue::VOBJ);
                TxToUniv(ntx, hashBlk, univTx);
                printf("tx: %s\n", univTx.write(1,2).c_str());
                */
            }
            else
            {
                LogPrintf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                return false;
            }
        }
        return true;
    }
}

// returns all unspent chain transfer outputs with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that chain are returned
bool GetUnspentChainTransfers(std::multimap<uint160, ChainTransferData> &inputDescriptors, uint160 chainFilter)
{
    bool nofilter = chainFilter.IsNull();

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    LOCK(cs_main);

    if (!GetAddressUnspent(CReserveTransfer::ReserveTransferKey(), CScript::P2IDX, unspentOutputs))
    {
        return false;
    }
    else
    {
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    // if this is a transfer output, optionally to this chain, add it to the input vector
                    // chain filter was applied in index search
                    COptCCParams p;
                    COptCCParams m;
                    CReserveTransfer rt;
                    uint160 destCID;
                    if (coins.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) && 
                        p.evalCode == EVAL_RESERVE_TRANSFER &&
                        p.vData.size() && 
                        p.version >= p.VERSION_V3 &&
                        (m = COptCCParams(p.vData.back())).IsValid() &&
                        (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                        !(destCID = ((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID)).IsNull() &&
                        (nofilter || destCID == chainFilter))
                    {
                        inputDescriptors.insert(make_pair(destCID,
                                                          ChainTransferData(coins.nHeight,
                                                                            CInputDescriptor(coins.vout[it->first.index].scriptPubKey, 
                                                                                            coins.vout[it->first.index].nValue, 
                                                                                            CTxIn(COutPoint(it->first.txhash, it->first.index))),
                                                                            rt)));
                    }
                }
            }
            else
            {
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
            }
        }
        return true;
    }
}

bool GetNotarizationData(const uint160 &currencyID, CChainNotarizationData &notarizationData, vector<pair<CTransaction, uint256>> *optionalTxOut)
{
    notarizationData = CChainNotarizationData(std::vector<std::pair<CUTXORef, CPBaaSNotarization>>());

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentFinalizations;
    CCurrencyDefinition chainDef = ConnectedChains.GetCachedCurrency(currencyID);
    if (!chainDef.IsValid())
    {
        LogPrint("notarization", "Cannot retrieve currency %s, may need to reindex\n", EncodeDestination(CIdentityID(currencyID)).c_str());
        return false;
    }

    // if we are being asked for a notarization of the current chain, we make one
    uint32_t height = chainActive.Height();
    if ((IsVerusActive() || height == 0) && currencyID == ASSETCHAINS_CHAINID)
    {
        CIdentityID proposer = VERUS_NOTARYID.IsNull() ? (VERUS_DEFAULTID.IsNull() ? VERUS_NODEID : VERUS_DEFAULTID) : VERUS_NOTARYID;

        std::map<uint160, CProofRoot> proofRoots;
        proofRoots[ASSETCHAINS_CHAINID] = CProofRoot::GetProofRoot(height);
        //printf("%s: returning proof root: %s\n", __func__, proofRoots[ASSETCHAINS_CHAINID].ToUniValue().write(1,2).c_str());

        CPBaaSNotarization bestNotarization(currencyID,
                                            ConnectedChains.GetCurrencyState(height),
                                            height,
                                            CUTXORef(),
                                            0,
                                            std::vector<CNodeData>(),
                                            std::map<uint160, CCoinbaseCurrencyState>(),
                                            DestinationToTransferDestination(proposer),
                                            proofRoots,
                                            CPBaaSNotarization::VERSION_CURRENT,
                                            CPBaaSNotarization::FLAG_LAUNCH_CONFIRMED);
        notarizationData.vtx.push_back(std::make_pair(CUTXORef(), bestNotarization));
        notarizationData.lastConfirmed = 0;
        notarizationData.forks.push_back(std::vector<int>({0}));
        notarizationData.bestChain = 0;
        return true;
    }

    // look for unspent, confirmed finalizations first
    uint160 finalizeNotarizationKey = CCrossChainRPCData::GetConditionID(currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey());
    uint160 confirmedNotarizationKey = CCrossChainRPCData::GetConditionID(finalizeNotarizationKey, CObjectFinalization::ObjectFinalizationConfirmedKey());

    if (GetAddressUnspent(confirmedNotarizationKey, CScript::P2IDX, unspentFinalizations) &&
        unspentFinalizations.size())
    {
        // get the latest, confirmed notarization
        auto bestIt = unspentFinalizations.begin();
        for (auto oneIt = bestIt; oneIt != unspentFinalizations.end(); oneIt++)
        {
            if (oneIt->second.blockHeight > bestIt->second.blockHeight)
            {
                bestIt = oneIt;
            }
        }

        CTransaction nTx;
        uint256 blkHash;
        COptCCParams p;
        if (!bestIt->second.script.IsPayToCryptoCondition(p) || 
            !p.IsValid() ||
            !(p.evalCode == EVAL_FINALIZE_NOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION) ||
            !p.vData.size())
        {
            LogPrintf("Invalid finalization or notarization on transaction %s, output %ld may need to reindex\n", bestIt->first.txhash.GetHex().c_str(), bestIt->first.index);
            printf("Invalid finalization or notarization on transaction %s, output %ld may need to reindex\n", bestIt->first.txhash.GetHex().c_str(), bestIt->first.index);
            return false;
        }

        CUTXORef txInfo(bestIt->first.txhash, bestIt->first.index);

        // if this is actually a finalization, get the notarization it is for
        if (p.evalCode == EVAL_FINALIZE_NOTARIZATION)
        {
            CObjectFinalization finalization(p.vData[0]);
            if (!finalization.output.hash.IsNull())
            {
                txInfo.hash = finalization.output.hash;
            }
            txInfo.n = finalization.output.n;

            if (myGetTransaction(txInfo.hash, nTx, blkHash) && nTx.vout.size() > txInfo.n)
            {
                CPBaaSNotarization thisNotarization(nTx.vout[txInfo.n].scriptPubKey);
                if (!thisNotarization.IsValid())
                {
                    LogPrintf("Invalid notarization on transaction %s, output %u may need to reindex\n", txInfo.hash.GetHex().c_str(), txInfo.n);
                    printf("Invalid finalization on transaction %s, output %u may need to reindex\n", txInfo.hash.GetHex().c_str(), txInfo.n);
                    return false;
                }
                notarizationData.vtx.push_back(std::make_pair(txInfo, thisNotarization));
                notarizationData.forks = std::vector<std::vector<int>>({{0}});
                notarizationData.bestChain = 0;
                notarizationData.lastConfirmed = 0;
                if (optionalTxOut)
                {
                    optionalTxOut->push_back(make_pair(nTx, blkHash));
                }
            }
        }
        else
        {
            // straightforward, get the notarization and return
            CPBaaSNotarization thisNotarization(p.vData[0]);
            if (!thisNotarization.IsValid())
            {
                LogPrintf("Invalid notarization on index entry for %s, output %u may need to reindex\n", txInfo.hash.GetHex().c_str(), txInfo.n);
                printf("Invalid finalization on index entry for %s, output %u may need to reindex\n", txInfo.hash.GetHex().c_str(), txInfo.n);
                return false;
            }
            notarizationData.vtx.push_back(std::make_pair(txInfo, thisNotarization));
            notarizationData.forks = std::vector<std::vector<int>>({{0}});
            notarizationData.bestChain = 0;
            notarizationData.lastConfirmed = 0;
            if (optionalTxOut)
            {
                if (myGetTransaction(txInfo.hash, nTx, blkHash) && nTx.vout.size() > txInfo.n)
                {
                    CPBaaSNotarization thisNotarization(nTx.vout[txInfo.n].scriptPubKey);
                    if (!thisNotarization.IsValid())
                    {
                        LogPrintf("Invalid notarization on transaction %s, output %u\n", txInfo.hash.GetHex().c_str(), txInfo.n);
                        printf("Invalid finalization on transaction %s, output %u\n", txInfo.hash.GetHex().c_str(), txInfo.n);
                        return false;
                    }
                    optionalTxOut->push_back(make_pair(nTx, blkHash));
                }
                else
                {
                    LogPrintf("Cannot retrieve transaction %s, may need to reindex\n", txInfo.hash.GetHex().c_str());
                    printf("Cannot retrieve transaction %s, may need to reindex\n", txInfo.hash.GetHex().c_str());
                    return false;
                }
            }
            // if this is a token, we're done, otherwise, get pending below as well
            if (chainDef.IsToken())
            {
                return true;
            }
        }
    }

    if (!notarizationData.vtx.size())
    {
        LogPrintf("%s: failure to find confirmed notarization starting point for currency %s\n", __func__, chainDef.ToUniValue().write(1,2).c_str());
        return false;
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> pendingFinalizations;

    // now, add all pending notarizations, if present, and sort them out
    if (GetAddressUnspent(CCrossChainRPCData::GetConditionID(finalizeNotarizationKey, CObjectFinalization::ObjectFinalizationPendingKey()), 
                          CScript::P2IDX,
                          pendingFinalizations) &&
        pendingFinalizations.size())
    {
        // all pending finalizations must be later than the last confirmed transaction and
        // refer to a previous valid / confirmable, not necessarily confirmed, notarization
        multimap<uint32_t, pair<CUTXORef, CPBaaSNotarization>> sorted;
        multimap<uint32_t, pair<CTransaction, uint256>> sortedTxs;
        std::multimap<CUTXORef, std::pair<CUTXORef, CPBaaSNotarization>> notarizationReferences;
        std::map<CUTXORef, std::pair<CTransaction, uint256>> referencedTxes;

        CTransaction nTx;
        uint256  blkHash;
        COptCCParams p;
        CObjectFinalization f;
        CPBaaSNotarization n;
        BlockMap::iterator blockIt;
        for (auto it = pendingFinalizations.begin(); it != pendingFinalizations.end(); it++)
        {
            if (!(it->second.script.IsPayToCryptoCondition(p) && 
                  p.IsValid() && 
                  p.evalCode == EVAL_FINALIZE_NOTARIZATION && 
                  p.vData.size() &&
                  (f = CObjectFinalization(p.vData[0])).IsValid() &&
                  myGetTransaction(f.output.hash.IsNull() ? it->first.txhash : f.output.hash, nTx, blkHash) &&
                  nTx.vout.size() > f.output.n &&
                  nTx.vout[f.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                  p.IsValid() &&
                  (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                  p.vData.size() &&
                  (n = CPBaaSNotarization(p.vData[0])).IsValid() &&
                  !blkHash.IsNull() &&
                  (blockIt = mapBlockIndex.find(blkHash)) != mapBlockIndex.end() &&
                  chainActive.Contains(blockIt->second)))
            {
                LogPrintf("%s: invalid, indexed finalization on transaction %s, output %d\n", __func__, it->first.txhash.GetHex().c_str(), (int)it->first.index);
                continue;
            }

            // if the notarization is a mirror, it's prior notarization is on the alternate chain
            CUTXORef priorRef = n.prevNotarization;
            if (p.evalCode == EVAL_ACCEPTEDNOTARIZATION && n.IsMirror())
            {
                // we should have another finalization of our prior following the
                // pending finalization
                CTransaction finalizationTx;
                if (f.output.hash.IsNull())
                {
                    finalizationTx = nTx;
                }

                CObjectFinalization priorOF;
                if (!(myGetTransaction(it->first.txhash, finalizationTx, blkHash) &&
                        (it->first.index + 1) < finalizationTx.vout.size() &&
                        finalizationTx.vout[it->first.index + 1].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                        p.vData.size() &&
                        (priorOF = CObjectFinalization(p.vData[0])).IsValid()))
                {
                    LogPrintf("%s: invalid index for finalization %s, output %d\n", __func__, it->first.txhash.GetHex().c_str(), (int)it->first.index);
                    continue;
                }
                // we should have a finalization right after on the same TX, pointing to the prior notarization that we care about
                priorRef = priorOF.output;
            }

            // if finalization is on same transaction as notarization, set it
            if (f.output.hash.IsNull())
            {
                f.output.hash = it->first.txhash;
            }

            notarizationReferences.insert(std::make_pair(priorRef, std::make_pair(f.output, n)));
            if (optionalTxOut)
            {
                referencedTxes.insert(std::make_pair(f.output, std::make_pair(nTx, blkHash)));
            }
        }

        // now that we have all pending notarizations (not finalizations) in a sorted list, keep all those which
        // directly or indirectly refer to the last confirmed notarization
        // all others should be pruned
        bool somethingAdded = true;
        while (somethingAdded && notarizationReferences.size())
        {
            somethingAdded = false;
            int numForks = notarizationData.forks.size();
            int forkNum;
            for (forkNum = 0; forkNum < numForks; forkNum++)
            {
                CUTXORef searchRef = notarizationData.vtx[notarizationData.forks[forkNum].back()].first;

                std::multimap<CUTXORef, std::pair<CUTXORef, CPBaaSNotarization>>::iterator pendingIt;

                bool newFork = false;

                for (pendingIt = notarizationReferences.lower_bound(searchRef);
                     pendingIt != notarizationReferences.end() && pendingIt->first == searchRef; 
                     pendingIt++)
                {
                    notarizationData.vtx.push_back(pendingIt->second);
                    if (optionalTxOut)
                    {
                        optionalTxOut->push_back(referencedTxes[pendingIt->second.first]);
                    }
                    if (newFork)
                    {
                        notarizationData.forks.push_back(notarizationData.forks[forkNum]);
                        notarizationData.forks.back().back() = notarizationData.vtx.size() - 1;
                    }
                    else
                    {
                        notarizationData.forks[forkNum].push_back(notarizationData.vtx.size() - 1);
                        newFork = true;
                        somethingAdded = true;
                    }
                }
                notarizationReferences.erase(searchRef);
            }
        }

        // now, we should have all forks in vectors
        // they should all have roots that point to the same confirmed or initial notarization, which should be enforced by chain rules
        // the best chain should simply be the tip with most power
        notarizationData.bestChain = 0;
        CChainPower best;
        for (int i = 0; i < notarizationData.forks.size(); i++)
        {
            if (notarizationData.vtx[notarizationData.forks[i].back()].second.proofRoots.count(currencyID))
            {
                CChainPower curPower = 
                    CChainPower::ExpandCompactPower(notarizationData.vtx[notarizationData.forks[i].back()].second.proofRoots[currencyID].compactPower, i);
                if (curPower > best)
                {
                    best = curPower;
                    notarizationData.bestChain = i;
                }
            }
            else if (notarizationData.vtx[notarizationData.forks[i].back()].second.IsLaunchCleared() &&
                     notarizationData.vtx[notarizationData.forks[i].back()].second.IsPreLaunch() &&
                     notarizationData.vtx[notarizationData.forks[i].back()].second.IsLaunchConfirmed())
            {
                notarizationData.bestChain = i;
            }
            else
            {
                printf("%s: invalid notarization expecting proofroot for %s:\n%s\n",
                    __func__,
                    EncodeDestination(CIdentityID(currencyID)).c_str(),
                    notarizationData.vtx[notarizationData.forks[i].back()].second.ToUniValue().write(1,2).c_str());
                LogPrintf("%s: invalid notarization on transaction %s, output %u\n", __func__, 
                           notarizationData.vtx[notarizationData.forks[i].back()].first.hash.GetHex().c_str(), 
                           notarizationData.vtx[notarizationData.forks[i].back()].first.n);
                //assert(false);
            }
        }
    }

    return notarizationData.vtx.size() != 0;
}

UniValue getnotarizationdata(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getnotarizationdata \"currencyid\"\n"
            "\nReturns the latest PBaaS notarization data for the specifed currencyid.\n"

            "\nArguments\n"
            "1. \"currencyid\"                  (string, required) the hex-encoded ID or string name  search for notarizations on\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                 (numeric) The notarization protocol version\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getnotarizationdata", "\"currencyid\"")
            + HelpExampleRpc("getnotarizationdata", "\"currencyid\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint160 chainID;
    CChainNotarizationData nData;
    
    LOCK2(cs_main, mempool.cs);

    chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currencyid");
    }

    if (GetNotarizationData(chainID, nData))
    {
        return nData.ToUniValue();
    }
    else
    {
        return NullUniValue;
    }
}

UniValue getlaunchinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "getlaunchinfo \"currencyid\"\n"
            "\nReturns the launch notarization data and partial transaction proof of the \n"
            "launch notarization for the specifed currencyid.\n"

            "\nArguments\n"
            "1. \"currencyid\"                  (string, required) the hex-encoded ID or string name  search for notarizations on\n"

            "\nResult:\n"
            "{\n"
            "  \"currencydefinition\" : {},     (json) Full currency definition\n"
            "  \"txid\" : \"hexstr\",           (hexstr) transaction ID\n"
            "  \"voutnum\" : \"n\",             (number) vout index of the launch notarization\n"
            "  \"transactionproof\" : {},       (json) Partial transaction proof of the launch transaction and output\n"
            "  \"launchnotarization\" : {},     (json) Final CPBaaSNotarization clearing launch or refund\n"
            "  \"notarynotarization\" : {},     (json) Current notarization of this chain\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getlaunchinfo", "\"currencyid\"")
            + HelpExampleRpc("getlaunchinfo", "\"currencyid\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint160 chainID;
    LOCK(cs_main);

    CCurrencyDefinition curDef;
    chainID = ValidateCurrencyName(uni_get_str(params[0]), true, &curDef);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currencyid or name");
    }

    std::pair<CInputDescriptor, CPartialTransactionProof> notarizationTx;
    CPBaaSNotarization launchNotarization, notaryNotarization;
    if (!ConnectedChains.GetLaunchNotarization(curDef, notarizationTx, launchNotarization, notaryNotarization) ||
        !notaryNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Valid notarization not found");
    }

    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;
    ConnectedChains.GetSystemExports(curDef.systemID, exports, 0, notarizationTx.second.GetBlockHeight(), true);

    std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> foundExport;
    bool isExportFound = false;
    if (exports.size())
    {
        for (auto &oneExport : exports)
        {
            CCrossChainExport oneCCX(oneExport.first.first.scriptPubKey);
            if (oneCCX.IsValid() &&
                oneCCX.destCurrencyID == chainID)
            {
                foundExport = oneExport;
                isExportFound = true;
                break;
            }
        }
    }
    if (!isExportFound)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No valid export found");
    }

    UniValue retVal(UniValue::VOBJ);
    retVal.pushKV("currencydefinition", curDef.ToUniValue());
    retVal.pushKV("notarizationtxid", notarizationTx.first.txIn.prevout.hash.GetHex());
    retVal.pushKV("notarizationvoutnum", (int64_t)notarizationTx.first.txIn.prevout.n);
    retVal.pushKV("notarizationproof", notarizationTx.second.ToUniValue());
    retVal.pushKV("exporttxid", foundExport.first.first.txIn.prevout.hash.GetHex());
    retVal.pushKV("exportvoutnum", (int64_t)foundExport.first.first.txIn.prevout.n);
    retVal.pushKV("exportproof", foundExport.first.second.ToUniValue());
    if (foundExport.second.size())
    {
        UniValue exportTransfers(UniValue::VARR);
        for (auto &oneTransfer : foundExport.second)
        {
            exportTransfers.push_back(oneTransfer.ToUniValue());
        }
        retVal.pushKV("exporttransfers", exportTransfers);
    }
    retVal.pushKV("launchnotarization", launchNotarization.ToUniValue());
    retVal.pushKV("notarynotarization", notaryNotarization.ToUniValue());
    return retVal;
}

UniValue getbestproofroot(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || params[0].getKeys().size() < 2)
    {
        throw runtime_error(
            "getbestproofroot '{\"proofroots\":[\"version\":n,\"type\":n,\"systemid\":\"currencyidorname\",\"height\":n,"
            "                   \"stateroot\":\"hex\",\"blockhash\":\"hex\",\"power\":\"hex\"],\"lastconfirmed\":n}'\n"
            "\nDetermines and returns the index of the best (most recent, valid, qualified) proof root in the list of proof roots,\n"
            "and the most recent, valid proof root.\n"

            "\nArguments\n"
            "{\n"
            "  \"proofroots\":                  (array, required/may be empty) ordered array of proof roots, indexed on return\n"
            "  [\n"
            "    {\n"
            "      \"version\":n                (int, required) version of this proof root data structure\n"
            "      \"type\":n                   (int, required) type of proof root (chain or system specific)\n"
            "      \"systemid\":\"hexstr\"      (hexstr, required) system the proof root is for\n"
            "      \"height\":n                 (uint32_t, required) height of this proof root\n"
            "      \"stateroot\":\"hexstr\"     (hexstr, required) Merkle or merkle-style tree root for the specified block/sequence\n"
            "      \"blockhash\":\"hexstr\"     (hexstr, required) hash identifier for the specified block/sequence\n"
            "      \"power\":\"hexstr\"         (hexstr, required) work, stake, or combination of the two for most-work/most-power rule\n"
            "    }\n"
            "  .\n"
            "  .\n"
            "  .\n"
            "  ]\n"
            "  \"currencies\":[\"id1\"]         (array, optional) currencies to query for currency states\n"
            "  \"lastconfirmed\":n              (int, required) index into the proof root array indicating the last confirmed root"
            "}\n"

            "\nResult:\n"
            "\"bestindex\"                      (int) index of best proof root not confirmed that is provided, confirmed index, or -1"
            "\"latestproofroot\"                (object) latest valid proof root of chain"
            "\"laststableproofroot\"            (object) either tip-BLOCK_MATURITY or last notarized/witnessed tip"
            "\"lastconfirmedproofroot\"         (object) last proof root of chain that has been confirmed"
            "\"currencystates\"                 (int) currency states of target currency and published bridges"

            "\nExamples:\n"
            + HelpExampleCli("getbestproofroot", "\"{\"proofroots\":[\"version\":n,\"type\":n,\"systemid\":\"currencyidorname\",\"height\":n,\"stateroot\":\"hex\",\"blockhash\":\"hex\",\"power\":\"hex\"],\"lastconfirmed\":n}\"")
            + HelpExampleRpc("getbestproofroot", "\"{\"proofroots\":[\"version\":n,\"type\":n,\"systemid\":\"currencyidorname\",\"height\":n,\"stateroot\":\"hex\",\"blockhash\":\"hex\",\"power\":\"hex\"],\"lastconfirmed\":n}\"")
        );
    }

    CheckPBaaSAPIsValid();

    std::vector<std::string> paramKeys = params[0].getKeys();
    UniValue currenciesUni;
    if (paramKeys.size() > 3 ||
        (paramKeys.size() == 3) && !(currenciesUni = find_value(params[0], "currencies")).isArray())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "too many members in object or invalid currencies array");
    }

    int lastConfirmed = uni_get_int(find_value(params[0], "lastconfirmed"), -1);
    if (lastConfirmed < 0)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid lastconfirmed");
    }

    std::map<uint32_t, std::pair<int32_t, CProofRoot>> proofRootMap;
    UniValue uniProofRoots = find_value(params[0], "proofroots");
    if (!uniProofRoots.isArray())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid proof root array parameter");
    }

    CProofRoot lastConfirmedRoot, lastConfirmedRootClaim;
    
    if (uniProofRoots.size() > lastConfirmed)
    {
        lastConfirmedRootClaim = CProofRoot(uniProofRoots[lastConfirmed]);
    }
    
    if (!lastConfirmedRootClaim.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid last confirmed proof root");
    }

    LOCK(cs_main);

    UniValue retVal(UniValue::VOBJ);

    // no notarization can be considered confirmed by another chain or system, if it has not already been first confirmed
    // by the first notary of this one. any confirmed proof root must map to a confirmed notarization on this chain that is
    // correct and at least before the last confirmed one on this chain
    std::vector<std::pair<CTransaction, uint256>> notaryTxVec;
    CChainNotarizationData notaryCND;
    if (ConnectedChains.FirstNotaryChain().IsValid())
    {
        if (GetNotarizationData(ConnectedChains.FirstNotaryChain().GetID(), notaryCND, &notaryTxVec) &&
            notaryCND.IsConfirmed() &&
            notaryCND.vtx[notaryCND.lastConfirmed].second.proofRoots.count(ASSETCHAINS_CHAINID))
        {
            lastConfirmedRoot = notaryCND.vtx[notaryCND.lastConfirmed].second.proofRoots[ASSETCHAINS_CHAINID];
        }
        else
        {
            // if we have a valid first notary, then we should have a valid confirmed notarization, or something is wrong
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid notarization for confirmed proof of current chain");
        }
    }

    for (int i = 0; i < uniProofRoots.size(); i++)
    {
        CProofRoot oneRoot(uniProofRoots[i]);
        if (!oneRoot.IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid proof root in array");
        }
        if (oneRoot.systemID != ASSETCHAINS_CHAINID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("incorrect systemid in proof root for %s", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID))));
        }
        // if we have no notary chain, we could have an invalid last confirmed
        proofRootMap.insert(std::make_pair(oneRoot.rootHeight, std::make_pair(i, oneRoot)));
    }

    uint32_t nHeight = chainActive.Height();

    std::map<uint32_t, int32_t> validRoots;       // height, index (only return the first valid at each height)

    for (auto it = proofRootMap.rbegin(); it != proofRootMap.rend(); it ++)
    {
        // ignore potential dups
        if (validRoots.count(it->second.second.rootHeight))
        {
            continue;
        }
        if (it->second.second == it->second.second.GetProofRoot(it->second.second.rootHeight))
        {
            validRoots.insert(std::make_pair(it->second.second.rootHeight, it->second.first));
        }
    }

    if (lastConfirmedRoot.IsValid() &&
        (!validRoots.count(lastConfirmedRootClaim.rootHeight) || lastConfirmedRootClaim.rootHeight > lastConfirmedRoot.rootHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("incorrect claim of confirmed proof root for height %u, %s", lastConfirmedRoot.rootHeight, EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID))));
    }

    if (validRoots.size())
    {
        UniValue validArr(UniValue::VARR);
        for (auto &oneRoot : validRoots)
        {
            validArr.push_back(oneRoot.second);
        }
        retVal.pushKV("validindexes", validArr);
        retVal.pushKV("bestindex", validRoots.rbegin()->second);
    }

    // get the latest proof root and currency states
    retVal.pushKV("latestproofroot", CProofRoot::GetProofRoot(nHeight).ToUniValue());
    if (lastConfirmedRoot.IsValid() && validRoots.count(lastConfirmedRoot.rootHeight))
    {
        retVal.pushKV("lastconfirmedproofroot", lastConfirmedRoot.ToUniValue());
        retVal.pushKV("laststableproofroot", lastConfirmedRoot.ToUniValue());
        retVal.pushKV("lastconfirmedindex", validRoots[lastConfirmedRoot.rootHeight]);
    }
    else if (lastConfirmedRoot.IsValid())
    {
        retVal.pushKV("laststableproofroot", lastConfirmedRoot.ToUniValue());
    }
    else
    {
        retVal.pushKV("laststableproofroot", CProofRoot::GetProofRoot((nHeight - COINBASE_MATURITY) > 0 ? (nHeight - COINBASE_MATURITY) : 1).ToUniValue());
    }

    std::set<uint160> currenciesSet({ASSETCHAINS_CHAINID});
    CCurrencyDefinition targetCur;
    uint160 targetCurID;
    UniValue currencyStatesUni(UniValue::VARR);
    UniValue confirmedCurrencyStatesUni(UniValue::VARR);
    if ((targetCurID = ValidateCurrencyName(EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)), true, &targetCur)).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("invalid currency state request for %s", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID))));
    }
    currencyStatesUni.push_back(ConnectedChains.GetCurrencyState(targetCur, nHeight).ToUniValue());

    for (int i = 0; i < currenciesUni.size(); i++)
    {
        if ((targetCurID = ValidateCurrencyName(uni_get_str(currenciesUni[i]), true, &targetCur)).IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("invalid currency state request for %s", uni_get_str(currenciesUni[i])));
        }
        if (!currenciesSet.count(targetCurID))
        {
            currencyStatesUni.push_back(ConnectedChains.GetCurrencyState(targetCur, nHeight).ToUniValue());
            if (lastConfirmedRoot.IsValid())
            {
                confirmedCurrencyStatesUni.push_back(ConnectedChains.GetCurrencyState(targetCur, lastConfirmedRoot.rootHeight).ToUniValue());
            }
        }
    }
    retVal.pushKV("currencystates", lastConfirmedRoot.IsValid() ? confirmedCurrencyStatesUni : currencyStatesUni);
    retVal.pushKV("latestcurrencystates", currencyStatesUni);

    return retVal;
}

UniValue submitacceptednotarization(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
    {
        throw runtime_error(
            "submitacceptednotarization \"{earnednotarization}\" \"{notaryevidence}\"\n"
            "\nFinishes an almost complete notarization transaction based on the notary chain and the current wallet or pubkey.\n"
            "If successful in submitting the transaction based on all rules, a transaction ID is returned, otherwise, NULL.\n"

            "\nArguments\n"
            "\"earnednotarization\"             (object, required) notarization earned on the other system, which is the basis for this\n"
            "\"notaryevidence\"                 (object, required) evidence and notary signatures validating the notarization\n"

            "\nResult:\n"
            "txid                               (hexstring) transaction ID of submitted transaction\n"

            "\nExamples:\n"
            + HelpExampleCli("submitacceptednotarization", "\"{earnednotarization}\" \"{notaryevidence}\"")
            + HelpExampleRpc("submitacceptednotarization", "\"{earnednotarization}\" \"{notaryevidence}\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint32_t nHeight = chainActive.Height();

    // decode the transaction and ensure that it is formatted as expected
    CPBaaSNotarization pbn;
    CNotaryEvidence evidence;
    CCurrencyDefinition chainDef;
    int32_t chainDefHeight;

    /* CPBaaSNotarization checkPbn(params[0]);
    printf("%s: checknotarization before:\n%s\n", __func__, checkPbn.ToUniValue().write(1,2).c_str());
    checkPbn.SetMirror();
    printf("%s: checknotarization mirrored:\n%s\n", __func__, checkPbn.ToUniValue().write(1,2).c_str());
    checkPbn.SetMirror(false);
    printf("%s: checknotarization after:\n%s\n", __func__, checkPbn.ToUniValue().write(1,2).c_str()); */

    TransactionBuilder tb(Params().GetConsensus(), nHeight, pwalletMain);

    {
        LOCK2(cs_main, mempool.cs);
        if (!(pbn = CPBaaSNotarization(params[0])).IsValid() ||
            !pbn.SetMirror() ||
            !GetCurrencyDefinition(pbn.currencyID, chainDef, &chainDefHeight) ||
            chainDef.systemID == ASSETCHAINS_CHAINID ||
            !(chainDef.IsPBaaSChain() || chainDef.IsGateway()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid earned notarization");
        }

        if (!(evidence = CNotaryEvidence(params[1])).IsValid() ||
            !evidence.GetNotarySignatures().size() ||
            evidence.systemID != pbn.currencyID)
        {
            printf("%s: invalid evidence %s\n", __func__, evidence.ToUniValue().write(1,2).c_str());
            throw JSONRPCError(RPC_INVALID_PARAMETER, "insufficient notarization evidence");
        }

        // flip back to normal earned notarization as before
        pbn.SetMirror(false);

        // printf("%s: evidence: %s\n", __func__, evidence.ToUniValue().write(1,2).c_str());

        // now, make a new notarization based on this earned notarization, mirrored, so it reflects a notarization on this chain, 
        // but can be verified with the cross-chain signatures and evidence

        CValidationState state;
        if (!pbn.CreateAcceptedNotarization(chainDef, pbn, evidence, state, tb))
        {
            //printf("%s: unable to create accepted notarization: %s\n", __func__, state.GetRejectReason().c_str());
            throw JSONRPCError(RPC_INVALID_PARAMETER, state.GetRejectReason());
        }
    }

    // get the new notarization transaction
    tb.SetFee(0);
    std::vector<TransactionBuilderResult> buildResultVec;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        buildResultVec.push_back(tb.Build());
    }
    auto buildResult = buildResultVec[0];
    CTransaction newTx;
    if (buildResult.IsTx())
    {
        newTx = buildResult.GetTxOrThrow();
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, buildResult.GetError());
    }

    bool relayTx;
    {
        LOCK(cs_main);
        LOCK2(smartTransactionCS, mempool.cs);
        std::list<CTransaction> removed;
        mempool.removeConflicts(newTx, removed);

        // add to mem pool and relay
        relayTx = myAddtomempool(newTx);
    }

    // add to mem pool and relay
    if (relayTx)
    {
        RelayTransaction(newTx);
        return newTx.GetHash().GetHex();
    }
    return NullUniValue;
}

// this must be called after all initial contributions are updated in the currency definition.
CCoinbaseCurrencyState GetInitialCurrencyState(const CCurrencyDefinition &chainDef)
{
    bool isFractional = chainDef.IsFractional();
    CCurrencyState cState;
    uint160 cID = chainDef.GetID();

    // calculate contributions and conversions
    const std::vector<CAmount> reserveFees(chainDef.currencies.size());
    std::vector<int64_t> conversions = chainDef.conversions;

    CAmount nativeFees = 0;
    if (isFractional)
    {
        cState = CCurrencyState(cID,
                                chainDef.currencies,
                                chainDef.weights,
                                std::vector<int64_t>(chainDef.currencies.size(), 0),
                                chainDef.initialFractionalSupply,
                                0,
                                chainDef.initialFractionalSupply,
                                CCurrencyState::FLAG_FRACTIONAL);
        conversions = cState.PricesInReserve();
    }
    else
    {
        cState.currencies = chainDef.currencies;
        cState.reserves = conversions;
        CAmount PreconvertedNative = cState.ReserveToNative(CCurrencyValueMap(chainDef.currencies, chainDef.preconverted));
        cState = CCurrencyState(cID,
                                chainDef.currencies, 
                                std::vector<int32_t>(0), 
                                conversions,
                                0, 
                                PreconvertedNative,
                                PreconvertedNative);
    }

    CCoinbaseCurrencyState retVal(cState, 
                                  0, 
                                  0, 
                                  0,
                                  std::vector<int64_t>(chainDef.currencies.size()), 
                                  std::vector<int64_t>(chainDef.currencies.size()), 
                                  std::vector<int64_t>(chainDef.currencies.size()), 
                                  conversions,
                                  std::vector<int64_t>(chainDef.currencies.size()), 
                                  reserveFees,
                                  reserveFees,
                                  0,
                                  std::vector<int32_t>(chainDef.currencies.size()));

    return retVal;
}

std::vector<CAddressUnspentDbEntry> GetFractionalNotarizationsForReserve(const uint160 &currencyID)
{
    std::vector<CAddressUnspentDbEntry> fractionalNotarizations;
    CIndexID indexKey = CCoinbaseCurrencyState::IndexConverterKey(currencyID);
    if (!GetAddressUnspent(indexKey, CScript::P2IDX, fractionalNotarizations))
    {
        LogPrintf("%s: Error reading unspent index\n", __func__);
    }
    return fractionalNotarizations;
}

UniValue getcurrencyconverters(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > CCurrencyState::MAX_RESERVE_CURRENCIES)
    {
        throw runtime_error(
            "getcurrencyconverters \"currency1\" \"currency2\" ...\n"
            "\nRetrieves all currencies that have at least 1000 VRSC in reserve, are >10% VRSC reserve ratio, and have all listed currencies as reserves\n"
            "\nArguments\n"
            "       \"currencyname\"               : \"string\" ...  (string(s), one or more) all selected currencies are returned with their current state"

            "\nResult:\n"
            "       \"[{currency1}, {currency2}]\" : \"array of objects\" (string) All currencies and the last notarization, which are valid converters.\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrencyconverters", "'[\"currency1\",\"currency2\",...]'")
            + HelpExampleRpc("getcurrencyconverters", "'[\"currency1\",\"currency2\",...]'")
        );
    }

    CheckPBaaSAPIsValid();

    std::map<uint160, CCurrencyDefinition> reserves;

    for (int i = 0; i < params.size(); i++)
    {
        std::string oneName = uni_get_str(params[i]);
        CCurrencyDefinition oneCurrency;
        uint160 oneCurrencyID;
        if (!oneName.size() ||
            (oneCurrencyID = ValidateCurrencyName(oneName, true, &oneCurrency)).IsNull() ||
            reserves.count(oneCurrencyID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Each reserve currency specified must be a valid, unique currency");
        }
        reserves[oneCurrencyID] = oneCurrency;
    }

    // get all currencies that contain all specified reserves in our fractionalsFound set
    // use latest notarizations of the currencies to do so
    std::vector<CAddressUnspentDbEntry> activeFractionals;
    std::set<int32_t> toRemove;
    auto resIt = reserves.begin();
    if (reserves.size() &&
        (activeFractionals = GetFractionalNotarizationsForReserve(resIt->first)).size())
    {
        resIt++;
        for (int i = 0; i < activeFractionals.size(); i++)
        {
            CPBaaSNotarization pbn(activeFractionals[i].second.script);
            if (!pbn.IsValid())
            {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Cannot read currency notarization in transaction " + activeFractionals[i].first.txhash.GetHex());
            }
            auto curMap = pbn.currencyState.GetReserveMap();
            for (auto it = resIt; it != reserves.end(); it++)
            {
                if (!curMap.count(it->first))
                {
                    toRemove.insert(i);
                    break;
                }
            }
        }
        for (auto oneIdx = toRemove.rbegin(); oneIdx != toRemove.rend(); oneIdx++)
        {
            activeFractionals.erase(activeFractionals.begin() + *oneIdx);
        }
    }

    UniValue ret(UniValue::VARR);
    for (int i = 0; i < activeFractionals.size(); i++)
    {
        CPBaaSNotarization pbn(activeFractionals[i].second.script);
        CCurrencyDefinition oneCur;
        if (!GetCurrencyDefinition(pbn.currencyID, oneCur))
        {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Cannot get currency definition for currency " + EncodeDestination(CIdentityID(pbn.currencyID)));
        }
        UniValue oneCurrency(UniValue::VOBJ);
        oneCurrency.push_back(Pair(oneCur.name, oneCur.ToUniValue()));
        oneCurrency.push_back(Pair("lastnotarization", pbn.ToUniValue()));
        ret.push_back(oneCurrency);
    }
    return ret;
}

UniValue estimateconversion(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "estimateconversion '{\"currency\":\"name\",\"convertto\":\"name\",\"amount\":n}'\n"
            "\nThis estimates conversion from one currency to another, taking into account pending conversions, fees and slippage.\n"

            "\nArguments\n"
            "1. {\n"
            "      \"currency\": \"name\"       (string, required)  Name of the source currency to send in this output, defaults to\n"
            "                                                       native of chain\n"
            "      \"amount\":amount            (numeric, required) The numeric amount of currency, denominated in source currency\n"
            "      \"convertto\":\"name\",      (string, optional)  Valid currency to convert to, either a reserve of a fractional, or fractional\n"
            "      \"preconvert\":\"false\",    (bool,  optional)   Convert to currency at market price (default=false), only works if\n"
            "                                                       transaction is mined before start of currency\n"
            "      \"via\":\"name\",            (string, optional)  If source and destination currency are reserves, via is a common fractional\n"
            "                                                       to convert through\n"
            "   }\n"

            "\nResult:\n"
            "   {\n"
            "      \"estimatereceived\": (value),                   Estimated amount of converted currency after conversion\n"
            "      \"estimatedslippage\": (value),                  Estimated percent slippage from conversion\n"
            "      \"transactionsperblock100\": (value),            Transactions per block over last 100 blocks\n"
            "      \"transactionsperblock10\": (value),             Transactions per block over last 10 blocks\n"
            "   }\n"

            "\nExamples:\n"
            + HelpExampleCli("estimateconversion", "'{\"currency\":\"name\",\"convertto\":\"name\",\"amount\":n}'")
            + HelpExampleRpc("estimateconversion", "'{\"currency\":\"name\",\"convertto\":\"name\",\"amount\":n}'")
        );
    }

    CheckPBaaSAPIsValid();

    bool isVerusActive = IsVerusActive();
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();
    uint160 thisChainID = thisChain.GetID();
    bool toFractional = false;
    bool reserveToReserve = false;

    auto currencyStr = TrimSpaces(uni_get_str(find_value(params[0], "currency")));
    CAmount sourceAmount = AmountFromValue(find_value(params[0], "amount"));
    auto convertToStr = TrimSpaces(uni_get_str(find_value(params[0], "convertto")));
    auto viaStr = TrimSpaces(uni_get_str(find_value(params[0], "via")));
    bool preConvert = uni_get_bool(find_value(params[0], "preconvert"));

    LOCK(cs_main);

    uint32_t nHeight = chainActive.Height();

    CCurrencyDefinition sourceCurrencyDef;
    uint160 sourceCurrencyID;
    if (currencyStr != "")
    {
        sourceCurrencyID = ValidateCurrencyName(currencyStr, true, &sourceCurrencyDef);
        if (sourceCurrencyID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
        }
    }
    else
    {
        sourceCurrencyDef = thisChain;
        sourceCurrencyID = sourceCurrencyDef.GetID();
        currencyStr = thisChain.name;
    }

    CCurrencyDefinition convertToCurrencyDef;
    uint160 convertToCurrencyID;

    if (convertToStr == "")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify a \"convertto\" currency for conversion estimation");
    }
    else 
    {
        convertToCurrencyID = ValidateCurrencyName(convertToStr, true, &convertToCurrencyDef);
        if (convertToCurrencyID == sourceCurrencyID)
        {
            convertToCurrencyID.SetNull();
            convertToCurrencyDef = CCurrencyDefinition();
        }
        else if (convertToCurrencyID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid \"convertto\" currency " + convertToStr + " specified");
        }
    }

    CCurrencyDefinition secondCurrencyDef;
    uint160 secondCurrencyID;
    if (viaStr != "")
    {
        secondCurrencyID = ValidateCurrencyName(viaStr, true, &secondCurrencyDef);
        std::map<uint160, int32_t> viaIdxMap = secondCurrencyDef.GetCurrenciesMap();
        if (secondCurrencyID.IsNull() ||
            sourceCurrencyID.IsNull() ||
            convertToCurrencyID.IsNull() ||
            secondCurrencyID == sourceCurrencyID || 
            secondCurrencyID == convertToCurrencyID ||
            sourceCurrencyID == convertToCurrencyID ||
            !viaIdxMap.count(sourceCurrencyID) ||
            !viaIdxMap.count(convertToCurrencyID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "To specify a fractional currency converter, \"currency\" and \"convertto\" must both be reserves of \"via\"");
        }
        if (preConvert)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot combine reserve to reserve conversion with preconversion");
        }
        CCurrencyDefinition tempDef = convertToCurrencyDef;
        convertToCurrencyDef = secondCurrencyDef;
        secondCurrencyDef = tempDef;
        convertToCurrencyID = convertToCurrencyDef.GetID();
        secondCurrencyID = secondCurrencyDef.GetID();
    }

    // if this is reserve to reserve "via" another currency, ensure that both "from" and "to" are reserves of the "via" currency
    CReserveTransfer checkTransfer;
    CCurrencyDefinition *pFractionalCurrency;
    if (secondCurrencyDef.IsValid())
    {
        std::map<uint160, int32_t> checkMap = convertToCurrencyDef.GetCurrenciesMap();
        if (!checkMap.count(sourceCurrencyID) || !checkMap.count(secondCurrencyID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "If \"via\" is specified, it must be a fractional currency with reserves of both source and \"convertto\" currency");
        }
        reserveToReserve = true;
        pFractionalCurrency = &convertToCurrencyDef;
    }
    else
    {
        // figure out if fractional to reserve, reserve to fractional, or error
        toFractional = convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID);

        if (toFractional)
        {
            pFractionalCurrency = &convertToCurrencyDef;
        }
        else if (!sourceCurrencyDef.GetCurrenciesMap().count(convertToCurrencyID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Source currency cannot be converted to destination");
        }
        else
        {
            pFractionalCurrency = &sourceCurrencyDef;
        }
    }

    if (!pFractionalCurrency->IsFractional() && (!preConvert || pFractionalCurrency->startBlock >= nHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, pFractionalCurrency->name + " must be a fractional currency or prior to start block to estimate a conversion price");
    }

    // now, get last notarization and all pending conversion transactions, calculate new conversions, including the new one to estimate and
    // return results
    CPBaaSNotarization notarization;
    uint160 fractionalCurrencyID = pFractionalCurrency->GetID();

    CUTXORef lastUnspentUTXO;
    CTransaction lastUnspentTx;

    if (pFractionalCurrency->systemID == ASSETCHAINS_CHAINID)
    {
        notarization.GetLastUnspentNotarization(fractionalCurrencyID, 
                                                lastUnspentUTXO.hash,
                                                *((int32_t *)&lastUnspentUTXO.n),
                                                &lastUnspentTx);
    }
    else
    {
        if (preConvert && !(pFractionalCurrency->IsGatewayConverter() && pFractionalCurrency->launchSystemID == ASSETCHAINS_CHAINID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Can only preconvert to currencies launching on the current chain");
        }
        CChainNotarizationData cnd;
        if (!GetNotarizationData(fractionalCurrencyID, cnd))
        {
            notarization = cnd.vtx[cnd.forks[cnd.bestChain].back()].second;
        }
    }

    if (!notarization.IsValid())
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Cannot find valid notarization for " + pFractionalCurrency->name);
    }

    UniValue retVal(UniValue::VOBJ);
    if (preConvert)
    {
        // estimate preconversion
        
    }
    else
    {
        // estimate normal fractional conversion
        // get all pending chain transfers, virtually process all the should be processed in order, put this
        // one into the export that it should go into, and calculate the final price of transfers in that export
    }
    return NullUniValue;
}

bool find_utxos(const CTxDestination &fromtaddr_, std::vector<COutput> &t_inputs_) 
{
    std::set<CTxDestination> destinations;

    bool wildCardPKH = false;
    bool wildCardID = false;
    bool isFromSpecificID = fromtaddr_.which() == COptCCParams::ADDRTYPE_ID && !GetDestinationID(fromtaddr_).IsNull();

    // if no specific address type, wildcard outputs to all transparent addresses and IDs are valid to consider
    if (fromtaddr_.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        wildCardPKH = true;
        wildCardID = true;
    }
    // wildcard for all transparent addresses, except IDs is null PKH
    else if (fromtaddr_.which() == COptCCParams::ADDRTYPE_PKH && GetDestinationID(fromtaddr_).IsNull())
    {
        wildCardPKH = true;
    }
    // wildcard for all ID transparent outputs is null ID
    else if (fromtaddr_.which() == COptCCParams::ADDRTYPE_ID && GetDestinationID(fromtaddr_).IsNull())
    {
        wildCardID = true;
    }
    else
    {
        destinations.insert(fromtaddr_);
    }

    vector<COutput> vecOutputs;

    pwalletMain->AvailableReserveCoins(vecOutputs,
                                       false,
                                       NULL,
                                       true,
                                       true,
                                       wildCardPKH || wildCardID ? nullptr : &fromtaddr_,
                                       nullptr,
                                       false);

    for (COutput& out : vecOutputs) 
    {
        CTxDestination dest;

        if (!isFromSpecificID && !out.fSpendable) {
            continue;
        }

        if (out.nDepth < 0) {
            continue;
        }

        std::vector<CTxDestination> addresses;
        int nRequired;
        bool canSign, canSpend;
        CTxDestination address;
        txnouttype txType;
        if (!ExtractDestinations(out.tx->vout[out.i].scriptPubKey, txType, addresses, nRequired, pwalletMain, &canSign, &canSpend))
        {
            continue;
        }

        if (isFromSpecificID)
        {
            // if we have more address destinations than just this address and have specified from a single ID only,
            // the condition must be such that the ID itself can spend, even if this wallet cannot due to a multisig
            // ID. if the ID cannot spend, even given a valid multisig ID, then to select this as a source without
            // an explicit, multisig match would cause potentially unwanted sourcing of funds. a spend just to this ID
            // is fine.

            COptCCParams p, m;
            // if we can't spend and can only sign,
            // ensure that this output is spendable by just this ID as a 1 of n and 1 of n at the master
            // smart transaction level as well
            if (!canSpend &&
                (!canSign ||
                 !(out.tx->vout[out.i].scriptPubKey.IsPayToCryptoCondition(p) &&
                   p.IsValid() &&
                   (p.version < COptCCParams::VERSION_V3 ||
                    (p.vData.size() &&
                     (m = COptCCParams(p.vData.back())).IsValid() &&
                     (m.m == 1 || m.m == 0))) &&
                   p.m == 1)))
            {
                continue;
            }
            else
            {
                out.fSpendable = true;      // this may not really be spendable, but set it if its the correct ID source and can sign
            }
        }
        else
        {
            if (!out.fSpendable)
            {
                continue;
            }
        }

        bool keep = false;
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        for (auto &address : addresses)
        {
            if (isFromSpecificID)
            {
                if (address == fromtaddr_)
                {
                    keep = true;
                }
            }
            else if (wildCardID || wildCardPKH)
            {
                if (wildCardPKH)
                {
                    keep = (address.which() == COptCCParams::ADDRTYPE_PKH || address.which() == COptCCParams::ADDRTYPE_PK) &&
                            pwalletMain->HaveKey(GetDestinationID(address));
                }
                if (!keep && wildCardID)
                {
                    keep = address.which() == COptCCParams::ADDRTYPE_ID  &&
                           pwalletMain->GetIdentity(CIdentityID(GetDestinationID(address)), keyAndIdentity) &&
                           keyAndIdentity.first.CanSign();
                }
            }
            else
            {
                keep = destinations.count(address);
            }
            if (keep)
            {
                break;
            }
        }

        if (!keep)
        {
            continue;
        }

        t_inputs_.push_back(out);
    }

    // sort in ascending order, so smaller utxos appear first
    std::sort(t_inputs_.begin(), t_inputs_.end(), [](COutput i, COutput j) -> bool {
        return ( i.tx->vout[i.i].nValue < j.tx->vout[j.i].nValue );
    });

    return t_inputs_.size() > 0;
}

std::vector<SaplingNoteEntry> find_unspent_notes(const libzcash::PaymentAddress &fromaddress_)
{
    std::vector<SaplingNoteEntry> retVal;

    std::vector<SproutNoteEntry> sproutEntries;
    std::vector<SaplingNoteEntry> saplingEntries;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetFilteredNotes(sproutEntries, saplingEntries, EncodePaymentAddress(fromaddress_));
    }

    sproutEntries.clear();

    for (auto entry : saplingEntries) {
        retVal.push_back(entry);
        std::string data(entry.memo.begin(), entry.memo.end());
        LogPrint("zrpcunsafe", "found unspent Sapling note (txid=%s, vShieldedSpend=%d, amount=%s, memo=%s)\n",
            entry.op.hash.ToString().substr(0, 10),
            entry.op.n,
            ValueFromAmount(entry.note.value()).write(),
            HexStr(data).substr(0, 10));
    }

    if (retVal.empty()) {
        return retVal;
    }

    // sort in descending order, so big notes appear first
    std::sort(retVal.begin(), retVal.end(),
        [](SaplingNoteEntry i, SaplingNoteEntry j) -> bool {
            return i.note.value() > j.note.value();
        });

    return retVal;
}

CAmount CalculateFractionalPrice(CAmount smallNumerator, CAmount smallDenominator, bool roundup)
{
    static arith_uint256 bigZero(0);
    static arith_uint256 BigSatoshi(SATOSHIDEN);
    static arith_uint256 BigSatoshiSquared = BigSatoshi * BigSatoshi;

    arith_uint256 denominator = smallDenominator * BigSatoshi;
    arith_uint256 numerator = smallNumerator * BigSatoshiSquared;
    arith_uint256 bigAnswer = numerator / denominator;
    int64_t remainder = (numerator - (bigAnswer * denominator)).GetLow64();
    CAmount answer = bigAnswer.GetLow64();
    if (remainder && roundup)
    {
        answer++;
    }
    return answer;
}

bool GetOpRetChainOffer(const CTransaction &postedTx,
                        CTransaction &offerTx,
                        CTransaction &inputToOfferTx,
                        uint32_t height,
                        bool getUnexpired,
                        bool getExpired,
                        uint256 &offerBlockHash)
{
    std::vector<CBaseChainObject *> opRetArray;
    CPartialTransactionProof offerTxProof;
    bool isPartial = false, incompleteTx = false;
    COptCCParams p;
    CSpentIndexKey spentKey = CSpentIndexKey(postedTx.GetHash(), 1);
    CSpentIndexValue spentValue;
    CTransaction opRetTx;
    uint256 opRetBlockHash;

    if (postedTx.vout.size() > 1 &&
        postedTx.vout[0].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        (p.evalCode == EVAL_IDENTITY_COMMITMENT || p.evalCode == EVAL_IDENTITY_PRIMARY) &&
        postedTx.vout[0].nValue >= DEFAULT_TRANSACTION_FEE &&
        ((postedTx.vout.back().scriptPubKey.IsOpReturn() &&
          (opRetArray = RetrieveOpRetArray((opRetTx = postedTx).vout.back().scriptPubKey)).size() == 1) ||
         (GetSpentIndex(spentKey, spentValue) &&
          myGetTransaction(spentValue.txid, opRetTx, opRetBlockHash)  &&
          (opRetArray = RetrieveOpRetArray(opRetTx.vout.back().scriptPubKey)).size() == 1)) &&
        opRetArray[0]->objectType == CHAINOBJ_TRANSACTION_PROOF &&
        (offerTxProof = ((CChainObject<CPartialTransactionProof> *)(opRetArray[0]))->object).IsValid() &&
        !offerTxProof.GetPartialTransaction(offerTx, &isPartial).IsNull() &&
        !isPartial &&
        offerTx.vout.size() == 1 &&
        offerTx.vin.size() == 1 &&
        offerTx.vShieldedSpend.size() == 0 &&
        ((spentKey = CSpentIndexKey(offerTx.vin[0].prevout.hash, offerTx.vin[0].prevout.n), !GetSpentIndex(spentKey, spentValue))) &&
        ((getExpired && offerTx.nExpiryHeight <= height) || (getUnexpired && offerTx.nExpiryHeight > height)) &&
        myGetTransaction(offerTx.vin[0].prevout.hash, inputToOfferTx, offerBlockHash))
    {
        return true;
    }
    else if (getExpired &&
             !(offerTxProof.IsValid() && !isPartial && offerTx.nExpiryHeight > height) &&
             p.IsValid() &&
             p.evalCode == EVAL_IDENTITY_COMMITMENT &&
             postedTx.vout[0].nValue >= DEFAULT_TRANSACTION_FEE &&
             p.vData.size() > 1 &&
             COptCCParams(p.vData.back()).vKeys.size() > 1 &&
             myGetTransaction(postedTx.GetHash(), inputToOfferTx, offerBlockHash) &&
             !offerBlockHash.IsNull() &&
             mapBlockIndex.count(offerBlockHash) &&
             (mapBlockIndex[offerBlockHash]->GetHeight() + DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA) < height)
    {
        CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height);
        mtx.vin.push_back(CTxIn(postedTx.GetHash(), 0));
        mtx.vout.push_back(postedTx.vout[0]);
        mtx.nExpiryHeight = std::min(height - 1, (uint32_t)0);
        offerTx = mtx;
        return true;
    }
    
    return false;
}

bool GetOpRetChainOffer(const CTransaction &postedTx,
                        CTransaction &offerTx,
                        CTransaction &inputToOfferTx,
                        uint32_t height)
{
    bool getUnexpired = true;
    bool getExpired = false;
    uint256 offerBlockHash;
    return GetOpRetChainOffer(postedTx, offerTx, inputToOfferTx, height, getUnexpired, getExpired, offerBlockHash);
}

struct OfferInfo
{
public:
    CTransaction offerTx;
    CTransaction inputToOfferTx;
    uint256 blockHash;
};

// returns a map with the first boolean being the "unexpired" state. if 0, the offer is expired
bool GetMyOffers(std::map<std::pair<bool, uint256>, OfferInfo> &myOffers, uint32_t height, bool getUnexpired, bool getExpired)
{
    bool retVal = false;
    LOCK(pwalletMain->cs_wallet);
    for (auto &txPair : pwalletMain->mapWallet)
    {
        OfferInfo oneOfferInfo;
        if (txPair.second.IsInMainChain() &&
            txPair.second.vout.size() > 0 &&
            !pwalletMain->IsSpent(txPair.second.GetHash(), 0) &&
            GetOpRetChainOffer(txPair.second, oneOfferInfo.offerTx, oneOfferInfo.inputToOfferTx, height, getUnexpired, getExpired, oneOfferInfo.blockHash))
        {
            CSpentIndexKey spentKey = CSpentIndexKey(oneOfferInfo.inputToOfferTx.GetHash(), oneOfferInfo.offerTx.vin[0].prevout.n);
            CSpentIndexValue spentValue;
            if (!GetSpentIndex(spentKey, spentValue))
            {
                bool isExpired = (oneOfferInfo.offerTx.nExpiryHeight <= height);
                myOffers.insert(std::make_pair(std::make_pair(!isExpired, txPair.first), oneOfferInfo));
            }
            retVal = true;
        }
    }
    return retVal;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
void SigningErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.push_back(Pair("txid", txin.prevout.hash.ToString()));
    entry.push_back(Pair("vout", (uint64_t)txin.prevout.n));
    entry.push_back(Pair("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    entry.push_back(Pair("sequence", (uint64_t)txin.nSequence));
    entry.push_back(Pair("error", strMessage));
    vErrorsRet.push_back(entry);
}

UniValue makeoffer(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
    {
        throw runtime_error(
            "makeoffer fromaddress '{\"changeaddress\":\"transparentoriaddress\", \"expiryheight\":blockheight, \"offer\":{\"currency\":\"anycurrency\", \"amount\":...} | {\"identity\":\"idnameoriaddress\",...}', \"for\":{\"address\":..., \"currency\":\"anycurrency\", \"amount\":...} | {\"name\":\"identityforswap\",\"parent\":\"parentid\",\"primaryaddresses\":[\"R-address(s)\"],\"minimumsignatures\":1,...}}' (returntx) (feeamount)\n"
            "\nThis sends a transaction which provides a completely decentralized, fully on-chain an atomic swap offer for\n"
            "\"decentralized swapping of any blockchain asset, including any/multi currencies, NFTs, identities, contractual\n"
            "\"agreements and rights transfers, or to be used as bids for an on-chain auction of any blockchain asset(s).\n"
            "\"Sources and destination of funds for swaps can be any valid transparent address capable of holding or controlling\n"
            "the specific asset.\n"

            "\nArguments\n"
            "1. \"fromaddress\"             (string, required) The VerusID, or wildcard address to send funds from. \"*\", \"R*\", or \"i*\" are valid wildcards\n"
            "2. {\n"
            "     \"changeaddress\"         (string, required) Change destination when constructing transactions\n"
            "     \"expiryheight\"          (number, optional) Block height at which this offer expires. Defaults to 20 blocks (avg 1/minute)\n"
            "     \"offer\"                 (object, required) Funds description or identity name, \"address\" in this object should be an address of the person making an offer for change\n"
            "     \"for\"                   (object, required) Funds description or full identity description\n"
            "   }\n"
            "3. \"returntx\"                (bool, optional) default = false, if true, returns a transaction waiting for taker completion instead of posting\n"
            "4. \"feeamount\"               (value, optional) default = 0.0001\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"transactionid\", The hex transaction id on success\n"
            "  \"hex\" : \"serializedtx\"   If hex is requested, hex serialization of partial transaction instead of txid is returned on success\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("makeoffer", "fromaddress '{\"changeaddress\":\"transparentoriaddress\", \"expiryheight\":blockheight, \"offer\":{\"currency\":\"anycurrency\", \"amount\":...} | {\"identity\":\"idnameoriaddress\",...}', \"for\":{\"address\":..., \"currency\":\"anycurrency\", \"amount\":...} | {\"name\":\"identityforswap\",\"parent\":\"parentid\",\"primaryaddresses\":[\"R-address(s)\"],\"minimumsignatures\":1,...}}' (returntx) (feeamount)")
            + HelpExampleRpc("makeoffer", "fromaddress '{\"changeaddress\":\"transparentoriaddress\", \"expiryheight\":blockheight, \"offer\":{\"currency\":\"anycurrency\", \"amount\":...} | {\"identity\":\"idnameoriaddress\",...}', \"for\":{\"address\":..., \"currency\":\"anycurrency\", \"amount\":...} | {\"name\":\"identityforswap\",\"parent\":\"parentid\",\"primaryaddresses\":[\"R-address(s)\"],\"minimumsignatures\":1,...}}' (returntx) (feeamount)")
        );
    }

    CheckVerusVaultAPIsValid();

    std::string sourceAddress = uni_get_str(params[0]);
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = sourceAddress == "*";
    bool wildCardRAddress = sourceAddress == "R*";
    bool wildCardiAddress = sourceAddress == "i*";
    bool wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;

    std::vector<CRecipient> outputs;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 sourceOvk;
    bool hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddressSource);
    // if we have a z-address as a source, re-encode it to a string, which is used
    // by the async operation, to ensure that we don't need to lookup IDs in that operation
    if (hasZSource)
    {
        sourceAddress = EncodePaymentAddress(zaddressSource);
        // We don't need to lock on the wallet as spending key related methods are thread-safe
        if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
        }

        auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
        auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
        expsk = sk.expsk;
        sourceOvk = expsk.full_viewing_key().ovk;
    }

    if (!(hasZSource ||
          wildCardAddress ||
          (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
    }

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    if (!params[1].isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. Second parameter must be object. See help.");
    }

    bool returnHex = false;
    if (params.size() > 2)
    {
        returnHex = uni_get_bool(params[2], returnHex);
    }

    CAmount feeAmount = DEFAULT_TRANSACTION_FEE;
    if (params.size() > 3)
    {
        feeAmount = AmountFromValue(params[3]);
    }

    UniValue offerValue = find_value(params[1], "offer");
    UniValue forValue = find_value(params[1], "for");
    if (!offerValue.isObject() || !forValue.isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Both \"offer\" and \"for\" must be valid objects in the first parameter object");
    }

    uint32_t height = chainActive.Height();

    CMutableTransaction offerTx = CreateNewContextualCMutableTransaction(Params().consensus, height + 1);
    uint32_t expiryHeight = uni_get_int(find_value(params[1], "expiryheight"));
    if (expiryHeight > offerTx.nExpiryHeight && expiryHeight < TX_EXPIRY_HEIGHT_THRESHOLD)
    {
        offerTx.nExpiryHeight = expiryHeight;
    }

    CInputDescriptor offerIn;
    std::vector<CInputDescriptor> postedOfferIns;
    CTxDestination changeDestination;
    CTxDestination fundsDestination;
    uint160 offerID;
    uint160 offerCurrencyID;
    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;
    uint160 newIDID;
    uint160 newCurrencyID;
    CTransaction preTx;

    bool hasZDest = false;
    libzcash::PaymentAddress zaddressDest;
    libzcash::SaplingPaymentAddress *saplingAddress;
    void *saplingOutputCtx = nullptr;

    auto changeAddressStr = TrimSpaces(uni_get_str(find_value(params[1], "changeaddress")));
    if (changeAddressStr.empty() || (changeDestination = ValidateDestination(changeAddressStr)).which() == COptCCParams::ADDRTYPE_INVALID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changeaddress must be valid");
    }

    if (find_value(forValue, "name").isNull())
    {
        if (!find_value(forValue, "identity").isNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "To buy an identity, define the identity by the \"for\" object as you would when registering, with \"name\", \"primaryaddresses\", etc. Do not use an \"identity\" tag");
        }

        auto currencyStr = TrimSpaces(uni_get_str(find_value(forValue, "currency")));
        CAmount destinationAmount = AmountFromValue(find_value(forValue, "amount"));
        auto memoStr = TrimSpaces(uni_get_str(find_value(forValue, "memo")));

        CCurrencyDefinition sourceCurrencyDef;
        if (currencyStr.empty())
        {
            sourceCurrencyDef = ConnectedChains.ThisChain();
            newCurrencyID = sourceCurrencyDef.GetID();
            currencyStr = EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID()));
        }
        else
        {
            newCurrencyID = ValidateCurrencyName(currencyStr, true, &sourceCurrencyDef);
            if (newCurrencyID.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
            }
        }

        auto destStr = TrimSpaces(uni_get_str(find_value(forValue, "address")));

        fundsDestination = ValidateDestination(destStr);
        CTransferDestination dest;

        if (fundsDestination.which() == COptCCParams::ADDRTYPE_INVALID)
        {
            // make the funds output that defines what we are willing to accept for the input we are offering
            hasZDest = pwalletMain->GetAndValidateSaplingZAddress(destStr, zaddressDest);
            if (hasZDest)
            {
                saplingAddress = boost::get<libzcash::SaplingPaymentAddress>(&zaddressDest);
            }
            else
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Specified \"for\" destination address must be valid");
            }
            if (saplingAddress == nullptr)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only sapling addresses may be used as a private \"for\" destination");
            }
        }
    }
    else
    {
        uint160 parentID = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(forValue, "parent")))));
        if (parentID.IsNull() && (parentID = ValidateCurrencyName(uni_get_str(find_value(forValue, "parent")), true)).IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "To ensure reference to the correct identity, parent must be a valid, non-null value.");
        }

        CIdentity forID(forValue);
        if (!forID.IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "New ID definition of the ID for which offer is being made must be valid.");
        }

        std::string nameStr = CleanName(uni_get_str(find_value(forValue, "name")), parentID);
        newIDID = CIdentity::GetID(nameStr, parentID);
        if (newIDID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " specification is not valid -- " + (nameStr.empty() ? "must have valid name" : "maybe needs parent?"));
        }

        if (!(oldID = CIdentity::LookupIdentity(newIDID, 0, &idHeight, &idTxIn)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " (" +EncodeDestination(CIdentityID(newIDID)) + "), not found ");
        }
    }

    try
    {
        std:vector<COutput> vCoins;

        // first, construct the "offer" input, which will either be funds or an ID from this wallet
        if (find_value(offerValue, "identity").isNull())
        {
            auto currencyStr = TrimSpaces(uni_get_str(find_value(offerValue, "currency")));
            CAmount sourceAmount = AmountFromValue(find_value(offerValue, "amount"));

            if (!sourceAmount)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "A currency offer must include a valid amount");
            }

            CCurrencyDefinition sourceCurrencyDef;
            uint160 sourceCurrencyID;
            if (currencyStr != "")
            {
                sourceCurrencyID = ValidateCurrencyName(currencyStr, true, &sourceCurrencyDef);
                if (sourceCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
                }
            }
            else
            {
                sourceCurrencyDef = ConnectedChains.ThisChain();
                sourceCurrencyID = sourceCurrencyDef.GetID();
                currencyStr = EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID()));
            }

            offerCurrencyID = sourceCurrencyID;
            CRecipient oneOutput;

            if (sourceCurrencyID == ASSETCHAINS_CHAINID)
            {
                oneOutput.nAmount = sourceAmount;
                oneOutput.scriptPubKey = GetScriptForDestination(changeDestination);
            }
            else
            {
                oneOutput.nAmount = 0;

                std::vector<CTxDestination> dests = std::vector<CTxDestination>({changeDestination});
                CTokenOutput to(sourceCurrencyID, sourceAmount);

                oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &to));
            }

            bool success = false;
            std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
            std::vector<SaplingNoteEntry> saplingNotes;
            CCurrencyValueMap reserveValueOut;
            CAmount nativeValueOut;
            CAmount totalOriginationFees = feeAmount;
            if (!returnHex)
            {
                totalOriginationFees += feeAmount;
                // if we're posting, and it is not a native currency offer, add an extra fee
                // to enable closing the offer
                if (sourceCurrencyID != ASSETCHAINS_CHAINID)
                {
                    // add one more fee to enable auto-cancellation when offering non-native currencies
                    totalOriginationFees += feeAmount;
                }
            }

            // first make an input transaction to split the offer funds into an exact input and change, if needed
            if (sourceCurrencyID == ASSETCHAINS_CHAINID)
            {
                if (hasZSource)
                {
                    saplingNotes = find_unspent_notes(zaddressSource);
                    CAmount totalFound = 0;
                    int i;
                    for (i = 0; i < saplingNotes.size(); i++)
                    {
                        totalFound += saplingNotes[i].note.value();
                        if (totalFound >= (oneOutput.nAmount + totalOriginationFees))
                        {
                            break;
                        }
                    }
                    // remove all but the notes we'll use
                    if (i < saplingNotes.size())
                    {
                        saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
                        success = true;
                    }
                }
                else
                {
                    success = find_utxos(from_taddress, vCoins) &&
                            pwalletMain->SelectCoinsMinConf(oneOutput.nAmount + totalOriginationFees, 0, 0, vCoins, setCoinsRet, nativeValueOut);
                }
            }
            else if (hasZSource)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot source non-native currencies from a private address");
            }
            else
            {
                success = find_utxos(from_taddress, vCoins);
                success = success && pwalletMain->SelectReserveCoinsMinConf(oneOutput.scriptPubKey.ReserveOutValue(),
                                                                            totalOriginationFees,
                                                                            0,
                                                                            1,
                                                                            vCoins,
                                                                            setCoinsRet,
                                                                            reserveValueOut,
                                                                            nativeValueOut);
            }
            if (!success)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient funds for offer");
            }
 
            // we need one output to create the proper index entry
            CKeyID offerIDKey = COnChainOffer::OnChainCurrencyOfferKey(offerCurrencyID);
            CKeyID forIDKey = newIDID.IsNull() ? 
                COnChainOffer::OnChainOfferForCurrencyKey(newCurrencyID) :
                COnChainOffer::OnChainOfferForIdentityKey(newIDID);

            // use the transaction builder to properly make change of native and reserves
            TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

            CCommitmentHash ch;
            std::vector<CTxDestination> dests({changeDestination});
            std::vector<CTxDestination> masterKeyDest({forIDKey, offerIDKey});
            if (sourceCurrencyID == ASSETCHAINS_CHAINID)
            {
                CCommitmentHash commitment = CCommitmentHash(uint256());
                tb.AddTransparentOutput(MakeMofNCCScript(
                    CConditionObj<CCommitmentHash>(EVAL_IDENTITY_COMMITMENT, dests, 1, &commitment), returnHex ? nullptr : &masterKeyDest),
                    oneOutput.nAmount);
            }
            else
            {
                CCommitmentHash commitment = CCommitmentHash(uint256(), CTokenOutput(oneOutput.scriptPubKey.ReserveOutValue()));
                tb.AddTransparentOutput(MakeMofNCCScript(
                    CConditionObj<CCommitmentHash>(EVAL_IDENTITY_COMMITMENT, dests, 1, &commitment), returnHex ? nullptr : &masterKeyDest), 
                    returnHex ? oneOutput.nAmount : oneOutput.nAmount + feeAmount);
            }

            // aggregate all inputs into one output with only the offer coins and offer indexes
            if (saplingNotes.size())
            {
                std::vector<SaplingOutPoint> notes;
                for (auto &oneNoteInfo : saplingNotes)
                {
                    notes.push_back(oneNoteInfo.op);
                }
                // Fetch Sapling anchor and witnesses
                uint256 anchor;
                std::vector<boost::optional<SaplingWitness>> witnesses;
                {
                    LOCK2(cs_main, pwalletMain->cs_wallet);
                    pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
                }

                // Add Sapling spends
                for (size_t i = 0; i < saplingNotes.size(); i++)
                {
                    tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());
                }
            }
            else
            {
                for (auto &oneInput : setCoinsRet)
                {
                    tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                            oneInput.first->vout[oneInput.second].scriptPubKey,
                                            oneInput.first->vout[oneInput.second].nValue);
                }
            }
            tb.SendChangeTo(changeDestination);
            tb.SetFee(feeAmount);
            TransactionBuilderResult preResult = tb.Build();
            preTx = preResult.GetTxOrThrow();

            LOCK2(smartTransactionCS, mempool.cs);

            bool relayTx;
            CValidationState state;
            {
                LOCK2(smartTransactionCS, mempool.cs);
                relayTx = myAddtomempool(preTx, &state);
            }

            // add to mem pool and relay
            if (!relayTx)
            {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to prepare offer tx: " + state.GetRejectReason());
            }
            else
            {
                RelayTransaction(preTx);
            }

            offerIn = CInputDescriptor(preTx.vout[0].scriptPubKey, preTx.vout[0].nValue, CTxIn(preTx.GetHash(), 0));
            offerTx.vin.push_back(offerIn.txIn);

            if (!returnHex)
            {
                postedOfferIns.push_back(CInputDescriptor(preTx.vout[1].scriptPubKey, preTx.vout[1].nValue, CTxIn(preTx.GetHash(), 1)));
            }
        }
        else
        {
            CTxDestination idDest = DecodeDestination(uni_get_str(find_value(offerValue, "identity")));
            if (idDest.which() != COptCCParams::ADDRTYPE_ID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity parameter must be valid friendly name or i-address: \"" + uni_get_str(params[0]) + "\"");
            }
            CIdentityID idID = CIdentityID(GetDestinationID(idDest));
            // we must have the offer value ID in our wallet to offer it
            std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
            if (!pwalletMain->GetIdentity(idID, keyAndIdentity) && keyAndIdentity.first.CanSign())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "To offer an identity, this wallet must have signing authority over the identity offered");
            }

            offerID = idID;

            uint32_t idHeight;
            CTxIn idTxIn;
            CIdentity sourceIdentity = CIdentity::LookupIdentity(idID, 0, &idHeight, &idTxIn);
            if (!sourceIdentity.IsValid() && !idTxIn.prevout.hash.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot find identity to offer");
            }

            CTransaction idTx;
            uint256 blockHash;
            if (!myGetTransaction(idTxIn.prevout.hash, idTx, blockHash))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot find identity to offer");
            }

            if (returnHex)
            {
                offerIn.txIn = idTxIn;
                offerIn.nValue = idTx.vout[idTxIn.prevout.n].nValue;
                offerIn.scriptPubKey = idTx.vout[idTxIn.prevout.n].scriptPubKey;
                offerTx.vin.push_back(offerIn.txIn);
            }
            else
            {
                bool success;
                std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
                CCurrencyValueMap reserveValueOut;
                CAmount nativeValueOut;
                CAmount totalOriginationFees = feeAmount * 2;

                success = find_utxos(from_taddress, vCoins) &&
                            pwalletMain->SelectCoinsMinConf(totalOriginationFees, 0, 0, vCoins, setCoinsRet, nativeValueOut);

                // first make an input transaction to split the offer funds into an exact input and change, if needed
                if (!success)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient funds for posting offer for identity on chain");
                }
    
                // we need one output to create the proper index entry
                CKeyID offerIDKey = COnChainOffer::OnChainIdentityOfferKey(offerID);
                CKeyID forIDKey = newIDID.IsNull() ? 
                    COnChainOffer::OnChainOfferForCurrencyKey(newCurrencyID) :
                    COnChainOffer::OnChainOfferForIdentityKey(newIDID);

                // use the transaction builder to properly make change of native and reserves
                TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

                CCommitmentHash ch;
                std::vector<CTxDestination> dests({changeDestination});
                std::vector<CTxDestination> indexDests({forIDKey, offerIDKey});

                tb.AddTransparentInput(COutPoint(idTxIn.prevout.hash, idTxIn.prevout.n), idTx.vout[idTxIn.prevout.n].scriptPubKey, idTx.vout[idTxIn.prevout.n].nValue);
                sourceIdentity.UpgradeVersion(height + 1);
                tb.AddTransparentOutput(sourceIdentity.IdentityUpdateOutputScript(height + 1, &indexDests), feeAmount);

                // aggregate all inputs into one output with only the offer coins and offer indexes
                for (auto &oneInput : setCoinsRet)
                {
                    tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                            oneInput.first->vout[oneInput.second].scriptPubKey,
                                            oneInput.first->vout[oneInput.second].nValue);
                }
                tb.SendChangeTo(changeDestination);
                tb.SetFee(feeAmount);
                TransactionBuilderResult preResult = tb.Build();
                preTx = preResult.GetTxOrThrow();

                bool relayTx;
                CValidationState state;
                {
                    LOCK2(smartTransactionCS, mempool.cs);
                    relayTx = myAddtomempool(preTx, &state);
                }

                if (!relayTx)
                {
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to prepare offer tx for identity: " + state.GetRejectReason());
                }
                else
                {
                    RelayTransaction(preTx);
                }

                offerIn = CInputDescriptor(preTx.vout[0].scriptPubKey, preTx.vout[0].nValue, CTxIn(preTx.GetHash(), 0));
                offerTx.vin.push_back(offerIn.txIn);

                postedOfferIns.push_back(CInputDescriptor(preTx.vout[1].scriptPubKey, preTx.vout[1].nValue, CTxIn(preTx.GetHash(), 1)));
            }
        }

        CRecipient requestOutput;

        // now we have made and added the offer input, make the output of what we want to exchange directed to us
        // then, sign the transaction, put it in an opreturn, and make the transaction that contains it
        if (find_value(forValue, "name").isNull())
        {
            auto currencyStr = TrimSpaces(uni_get_str(find_value(forValue, "currency")));
            CAmount destinationAmount = AmountFromValue(find_value(forValue, "amount"));
            auto memoStr = TrimSpaces(uni_get_str(find_value(forValue, "memo")));

            if (hasZDest && newCurrencyID != ASSETCHAINS_CHAINID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot send non-native currency when sending proceeds to a private z-address");
            }
            if (!hasZDest && !memoStr.empty())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot include memo when sending proceeds to a transparent address or ID");
            }
            if (hasZDest)
            {
                requestOutput.nAmount = DEFAULT_TRANSACTION_FEE;
                requestOutput.scriptPubKey = GetScriptForDestination(changeDestination);

                // if memo starts with "#", convert it from a string to a hex value
                if (memoStr.size() > 1 && memoStr[0] == '#')
                {
                    // make a hex string out of the chars without the "#"
                    memoStr = HexBytes((const unsigned char *)&(memoStr[1]), memoStr.size());
                }

                if (memoStr.size() && !IsHex(memoStr)) 
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected memo data in hexadecimal format or as a non-zero length text string, starting with \"#\".");
                }

                std::array<unsigned char, ZC_MEMO_SIZE> hexMemo;

                if (memoStr.length() > ZC_MEMO_SIZE*2) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,  strprintf("Size of memo is larger than maximum allowed %d", ZC_MEMO_SIZE));
                }
                else if (memoStr.length() > 0)
                {
                    hexMemo = AsyncRPCOperation_sendmany::get_memo_from_hex_string(memoStr);
                }

                // make the z-output
                uint256 ovk;
                HDSeed seed;
                if (!pwalletMain->GetHDSeed(seed)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "wallet seed unavailable for z-address output");
                }
                ovk = ovkForShieldingFromTaddr(seed);

                saplingOutputCtx = librustzcash_sapling_proving_ctx_init();
                auto note = libzcash::SaplingNote(*saplingAddress, destinationAmount);
                OutputDescriptionInfo output(ovk, note, hexMemo);
                offerTx.valueBalance -= destinationAmount;

                auto cm = output.note.cm();
                if (!cm) {
                    librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "failed attempt to create private output");
                }

                libzcash::SaplingNotePlaintext notePlaintext(output.note, output.memo);

                auto res = notePlaintext.encrypt(output.note.pk_d);
                if (!res) {
                    librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "failed to encrypt note with memo");
                }
                auto enc = res.get();
                auto encryptor = enc.second;

                OutputDescription odesc;
                if (!librustzcash_sapling_output_proof(
                        saplingOutputCtx,
                        encryptor.get_esk().begin(),
                        output.note.d.data(),
                        output.note.pk_d.begin(),
                        output.note.r.begin(),
                        output.note.value(),
                        odesc.cv.begin(),
                        odesc.zkproof.begin())) {
                    librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "output proof failed");
                }

                odesc.cm = *cm;
                odesc.ephemeralKey = encryptor.get_epk();
                odesc.encCiphertext = enc.first;

                libzcash::SaplingOutgoingPlaintext outPlaintext(output.note.pk_d, encryptor.get_esk());
                odesc.outCiphertext = outPlaintext.encrypt(
                    output.ovk,
                    odesc.cv,
                    odesc.cm,
                    encryptor);
                offerTx.vShieldedOutput.push_back(odesc);
            }
            else
            {
                // make transparent output and complete transaction
                if (newCurrencyID == ASSETCHAINS_CHAINID)
                {
                    requestOutput.nAmount = destinationAmount;
                    requestOutput.scriptPubKey = GetScriptForDestination(fundsDestination);
                }
                else
                {
                    requestOutput.nAmount = newCurrencyID == ASSETCHAINS_CHAINID ? destinationAmount : 0;

                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({fundsDestination});
                    CTokenOutput to(newCurrencyID, destinationAmount);

                    requestOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &to));
                }
            }
            offerTx.vout.push_back(CTxOut(requestOutput.nAmount, requestOutput.scriptPubKey));
        }
        else
        {
            // create the desired ID output, which the asset this exchange is making an offer for
            // to take the offer, a party in control of the identity defined by the output
            // must provide them on input to turn this into a valid transaction

            uint160 parentID = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(forValue, "parent")))));

            if (parentID.IsNull() && (parentID = ValidateCurrencyName(uni_get_str(find_value(forValue, "parent")), true)).IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "To ensure reference to the correct identity, parent must be a correct, non-null value.");
            }
            std::string nameStr = CleanName(uni_get_str(find_value(forValue, "name")), parentID);
            newIDID = CIdentity::GetID(nameStr, parentID);
            if (newIDID.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " specification is not valid -- " + (nameStr.empty() ? "must have valid name" : "maybe needs parent?"));
            }

            CTxIn idTxIn;
            CIdentity oldID;
            uint32_t idHeight;

            if (!(oldID = CIdentity::LookupIdentity(newIDID, 0, &idHeight, &idTxIn)).IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " (" +EncodeDestination(CIdentityID(newIDID)) + "), not found ");
            }

            oldID.revocationAuthority = oldID.GetID();
            oldID.recoveryAuthority = oldID.GetID();
            oldID.privateAddresses.clear();
            oldID.primaryAddresses.clear();
            oldID.minSigs = 1;

            uint256 blkHash;
            CTransaction oldIdTx;
            if (!myGetTransaction(idTxIn.prevout.hash, oldIdTx, blkHash))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + ", transaction not found ");
            }

            auto uniOldID = UniObjectToMap(oldID.ToUniValue());

            // overwrite old elements
            for (auto &oneEl : UniObjectToMap(forValue))
            {
                uniOldID[oneEl.first] = oneEl.second;
            }

            uint32_t solVersion = CConstVerusSolutionVector::GetVersionByHeight(height + 1);

            if (solVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
            {
                uniOldID["version"] = solVersion < CActivationHeight::ACTIVATE_PBAAS ? (int64_t)CIdentity::VERSION_VAULT : (int64_t)CIdentity::VERSION_PBAAS;
                if (oldID.nVersion < CIdentity::VERSION_VAULT)
                {
                    uniOldID["systemid"] = EncodeDestination(CIdentityID(parentID.IsNull() ? oldID.GetID() : parentID));
                }
            }

            UniValue newUniID = MapToUniObject(uniOldID);
            CIdentity newID(newUniID);

            if (!newID.IsValid(true))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
            }

            // make sure we have a revocation and recovery authority defined
            CIdentity revocationAuth = newID.revocationAuthority == newIDID ? newID : newID.LookupIdentity(newID.revocationAuthority);
            CIdentity recoveryAuth = newID.recoveryAuthority == newIDID ? newID : newID.LookupIdentity(newID.recoveryAuthority);

            if (!revocationAuth.IsValid() || !recoveryAuth.IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid revocation or recovery authority specified");
            }

            if (!recoveryAuth.IsValidUnrevoked() || !revocationAuth.IsValidUnrevoked())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or revoked recovery, or revocation identity.");
            }

            if (oldID.IsLocked() != newID.IsLocked())
            {
                bool newLocked = newID.IsLocked();
                uint32_t unlockAfter = newID.unlockAfter;
                newID.flags = (newID.flags & ~newID.FLAG_LOCKED) | (newID.IsRevoked() ? 0 : (oldID.flags & oldID.FLAG_LOCKED));
                newID.unlockAfter = oldID.unlockAfter;

                if (!newLocked)
                {
                    newID.Unlock(height + 1, offerTx.nExpiryHeight);
                }
                else
                {
                    newID.Lock(unlockAfter);
                }
            }

            newID.UpgradeVersion(height + 1);
            offerTx.vout.push_back(CTxOut(0, newID.IdentityUpdateOutputScript(height + 1)));
        }

        // now, the offer tx is complete, and we need to sign its input with SIGHASH_SINGLE
        auto consensusBranchId = CurrentEpochBranchId(height, Params().consensus);

        if (offerTx.vShieldedOutput.size())
        {
            // has for SIGHASH_SINGLE | SIGHASH_ANYONECANPAY binding signature for
            // Sapling outputs. Final transaction must only include Sapling outputs, which
            // have a binding signature bound to the single input along with its output and a zero
            // amount. the zero amount allows us to generate and validate this hash without
            // the output script of the prior transaction output, which is bound and verified by the
            // hash signed on that input already
            uint256 dataToBeSigned;
            CScript scriptCode;
            try {
                dataToBeSigned = SignatureHash(scriptCode, offerTx, 0, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, 0, consensusBranchId);
            } catch (std::logic_error ex) {
                librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not construct signature hash");
            }

            librustzcash_sapling_binding_sig(
                saplingOutputCtx,
                offerTx.valueBalance,
                dataToBeSigned.begin(),
                offerTx.bindingSig.data());

            librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
        }

        CTransaction txNewConst(offerTx);
        SignatureData sigdata;

        bool signSuccess = ProduceSignature(
            TransactionSignatureCreator(pwalletMain, &txNewConst, 0, offerIn.nValue, offerIn.scriptPubKey, height + 1, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY), offerIn.scriptPubKey, sigdata, consensusBranchId);

        if (signSuccess || sigdata.scriptSig.size())
        {
            UpdateTransaction(offerTx, 0, sigdata);
        }
        else
        {
            UniValue jsonTx(UniValue::VOBJ);
            extern void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry);
            TxToUniv(txNewConst, uint256(), jsonTx);
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to sign for script:\n " + jsonTx.write(1,2) + "\n");
        }

        UniValue retVal(UniValue::VOBJ);

        // if we're not just returning the hex tx, create a transaction from the postedOfferIns funds
        if (!signSuccess || returnHex)
        {
            if (signSuccess)
            {
                retVal.pushKV("signstatus", "complete");
            }
            else
            {
                retVal.pushKV("signstatus", "incomplete");
            }
            retVal.pushKV("hex", EncodeHexTx(offerTx));
            if (!returnHex)
            {
                retVal.pushKV("listingtransactionid", preTx.GetHash().GetHex());
            }
        }
        else
        {
            if (!postedOfferIns.size())
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to make offer transaction on chain, try with returnhex as false");
            }
            TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);
            for (auto &oneIn : postedOfferIns)
            {
                tb.AddTransparentInput(COutPoint(oneIn.txIn.prevout.hash, oneIn.txIn.prevout.n), oneIn.scriptPubKey, oneIn.nValue);
            }

            // now, make the opret to contain this transaction
            CCrossChainProof opRetProof;
            opRetProof << CPartialTransactionProof(CMMRProof(), offerTx);
            tb.AddOpRet(StoreOpRetArray(opRetProof.chainObjects));
            tb.SendChangeTo(changeDestination);
            tb.SetFee(feeAmount);

            TransactionBuilderResult result = tb.Build();
            CTransaction offerPostTx = result.GetTxOrThrow();

            bool relayTx;
            CValidationState state;
            {
                LOCK2(smartTransactionCS, mempool.cs);
                relayTx = myAddtomempool(offerPostTx, &state);
            }

            if (!relayTx)
            {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Failed to add offer transaction to mempool");
            }
            else
            {
                retVal.pushKV("txid", preTx.GetHash().GetHex());
                retVal.pushKV("oprettxid", offerPostTx.GetHash().GetHex());
                RelayTransaction(offerPostTx);
            }
        }

        return retVal;
    }
    catch(const std::exception& e)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot create offer: " + std::string(e.what()));
    }
    return NullUniValue;
}

UniValue takeoffer(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
    {
        throw runtime_error(
            "takeoffer fromaddress '{\"txid\":\"txid\" | \"tx\":\"hextx\", \"changeaddress\":\"transparentoriaddress\", \"deliver\":\"fullidnameoriaddresstodeliver\" | {\"currency\":\"currencynameorid\",\"amount\":n}, \"accept\":{\"address\":\"addressorid\",\"currency\":\"currencynameorid\",\"amount\":n} | {identitydefinition}}' (returntx) (feeamount)\n"
            "\nIf the current wallet can afford the swap, this accepts a swap offer on the blockchain, creates a transaction\n"
            "to execute it, and posts the transaction to the blockchain.\n"

            "\nArguments\n"
            "\"fromaddress\"            (string, required) The Sapling, VerusID, or wildcard address to send funds from, including fees for ID swaps.\n"
            "                                              \"*\", \"R*\", or \"i*\" are valid wildcards\n"
            "{\n"
                "\"txid\"               (string, required) The transaction ID for the offer to accept\n"
                "\"tx\"                 (string, required) The hex transaction to complete in order to accept the offer\n"
                "\"deliver\"            (object, required) One of \"fullidnameoriaddresstotrade\" or {\"currency\":\"currencynameorid\", \"amount\":value}\n"
                "\"accept\"             (object, required) One of {\"address\":\"addressorid\",\"currency\":\"currencynameorid\",\"amount\"} or {identitydefinition}\n"
                "\"feeamount\"          (number, optional) Specific fee amount requested instead of default miner's fee\n"
            "}\n"

            "\nResult:\n"
            "   \"txid\" : \"transactionid\" (string) The transaction id if (returntx) is false\n"
            "   \"hextx\" : \"hex\"         (string) The hexadecimal, serialized transaction if (returntx) is true\n"

            "\nExamples:\n"
            + HelpExampleCli("takeoffer", "fromaddress '{\"txid\":\"txid\" | \"tx\":\"hextx\", \"deliver\":\"fullidnameoriaddresstodeliver\" | {\"currency\":\"currencynameorid\",\"amount\":...}, \"accept\":{\"address\":\"addressorid\",\"currency\":\"currencynameorid\",\"amount\"} | {identitydefinition}}' (returntx) (feeamount)")
            + HelpExampleRpc("takeoffer", "fromaddress {\"txid\":\"txid\" | \"tx\":\"hextx\", \"deliver\":\"fullidnameoriaddresstodeliver\" | {\"currency\":\"currencynameorid\",\"amount\":...}, \"accept\":{\"address\":\"addressorid\",\"currency\":\"currencynameorid\",\"amount\"} | {identitydefinition}} (returntx) (feeamount)")
        );
    }

    CheckVerusVaultAPIsValid();

    bool returnHex = params.size() > 2 ? uni_get_bool(params[2]) : false;
    CAmount feeAmount = params.size() > 3 ? AmountFromValue(params[3]) : DEFAULT_TRANSACTION_FEE;

    std::string fundsSource = uni_get_str(params[0]);
    if (fundsSource.empty())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "First parameter json object must include a currency funding \"source\", which may be an ID, transparent address, private address, or wildcards (*, R*, i*)");
    }

    CTxDestination sourceDest, changeAddress;

    bool wildCardTransparentAddress = fundsSource == "*";
    bool wildCardRAddress = fundsSource == "R*";
    bool wildCardiAddress = fundsSource == "i*";
    bool wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;

    std::vector<CRecipient> outputs;

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    std::vector<SpendDescriptionInfo> saplingSpends;
    void *saplingSpendCtx = nullptr;

    uint256 sourceOvk;
    bool hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(fundsSource, zaddressSource);
    // if we have a z-address as a source, re-encode it to a string, which is used
    // by the async operation, to ensure that we don't need to lookup IDs in that operation
    if (hasZSource)
    {
        // TODO: enable z-source for funds
        throw JSONRPCError(RPC_INVALID_PARAMETER, "z-address for payment, not yet implemented");
        fundsSource = EncodePaymentAddress(zaddressSource);
        // We don't need to lock on the wallet as spending key related methods are thread-safe
        if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
        }

        auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
        auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
        expsk = sk.expsk;
        sourceOvk = expsk.full_viewing_key().ovk;
    }

    if (!(hasZSource ||
          wildCardAddress ||
          (sourceDest = DecodeDestination(fundsSource)).which() != COptCCParams::ADDRTYPE_INVALID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
    }

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    // now, we either have a z-address source, wild card, or single transparent source
    const UniValue &takeOfferUni = params[1];
    std::string txIdStringToTake = uni_get_str(find_value(takeOfferUni, "txid"));
    std::string txStringToTake = uni_get_str(find_value(takeOfferUni, "tx"));
    std::string changeAddressStr = uni_get_str(find_value(takeOfferUni, "changeaddress"));

    {
        LOCK(cs_main);
        if ((changeAddress = ValidateDestination(changeAddressStr)).which() == COptCCParams::ADDRTYPE_INVALID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "\"changeaddress\" must be specified as a transparent address or identity");
        }
    }

    uint256 txIdToTake;
    CTransaction txToTake, inputTxToOffer;
    uint32_t height;
    uint32_t consensusBranchId;

    {
        LOCK2(cs_main, mempool.cs);
        height = chainActive.Height();
        consensusBranchId = CurrentEpochBranchId(height + 1, Params().GetConsensus());

        if (!txIdStringToTake.empty())
        {
            txIdToTake.SetHex(txIdStringToTake);
            if (txIdToTake.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txid specified");
            }
            uint256 blockHash;
            CTransaction postedTx;
            if (!myGetTransaction(txIdToTake, postedTx, blockHash))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction " + txIdToTake.GetHex() + " not found");
            }

            // get the actual transaction from the op return
            if (!GetOpRetChainOffer(postedTx, txToTake, inputTxToOffer, height))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to retrieve valid offer");
            }
        }
        else if (!txStringToTake.empty())
        {
            uint256 blockHash;
            if (!(DecodeHexTx(txToTake, txStringToTake) &&
                  txToTake.vout.size() == 1 &&
                  txToTake.vin.size() == 1 &&
                  txToTake.vShieldedSpend.size() == 0 &&
                  txToTake.nExpiryHeight > (height + 3) &&
                  myGetTransaction(txToTake.vin[0].prevout.hash, inputTxToOffer, blockHash)))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer transaction supplied is not valid or expired");
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must either provide a transaction in \"tx\" or a transaction id in \"txid\" to specify the offer");
        }
    }

    UniValue deliver = find_value(takeOfferUni, "deliver");
    UniValue accept = find_value(takeOfferUni, "accept");

    CIdentityID idIDToDeliver;
    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
    CTxIn idInput;
    CTxOut oldIdOutput;
    CTxDestination acceptToAddress;

    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndRevocation;
    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndRecovery;

    CIdentity acceptedIdentity;
    CCurrencyValueMap acceptedCurrency, currencyToDeliver;
    CAmount subsidizedFees = 0;

    if (accept.isNull() || !accept.isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity or currency to accept must be a valid json object");
    }

    if ((acceptedIdentity = CIdentity(accept)).IsValid())
    {
        uint160 parentID = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(accept, "parent")))));
        if (parentID.IsNull() && (parentID = ValidateCurrencyName(uni_get_str(find_value(accept, "parent")), true)).IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "To ensure acceptance of the correct identity, parent must be a correct, non-null value.");
        }

        CTxIn idTxIn;
        CIdentity oldID;
        uint32_t idHeight;

        if (!(oldID = CIdentity::LookupIdentity(acceptedIdentity.GetID(), 0, &idHeight, &idTxIn)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + acceptedIdentity.GetID().GetHex() + ", not found ");
        }

        oldID.revocationAuthority = oldID.GetID();
        oldID.recoveryAuthority = oldID.GetID();
        oldID.privateAddresses.clear();
        oldID.primaryAddresses.clear();
        oldID.minSigs = 1;

        auto uniOldID = UniObjectToMap(oldID.ToUniValue());

        // overwrite old elements
        for (auto &oneEl : UniObjectToMap(accept))
        {
            uniOldID[oneEl.first] = oneEl.second;
        }

        uint32_t solVersion = CConstVerusSolutionVector::GetVersionByHeight(height + 1);

        if (solVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
        {
            uniOldID["version"] = solVersion < CActivationHeight::ACTIVATE_PBAAS ? (int64_t)CIdentity::VERSION_VAULT : (int64_t)CIdentity::VERSION_PBAAS;
            if (oldID.nVersion < CIdentity::VERSION_VAULT)
            {
                uniOldID["systemid"] = EncodeDestination(CIdentityID(parentID.IsNull() ? oldID.GetID() : parentID));
            }
        }

        UniValue newUniID = MapToUniObject(uniOldID);
        acceptedIdentity = CIdentity(newUniID);
        acceptedIdentity.UpgradeVersion(height + 1);
    }
    else
    {
        std::string acceptCurrencyStr = uni_get_str(find_value(accept, "currency"));
        std::string acceptToDestStr = uni_get_str(find_value(accept, "address"));
        uint160 currencyID = ValidateCurrencyName(acceptCurrencyStr, true);
        if (acceptCurrencyStr.empty())
        {
            currencyID = ASSETCHAINS_CHAINID;
        }
        CAmount currencyAmount;
        if (currencyID.IsNull() || (currencyAmount = AmountFromValue(find_value(accept, "amount"))) <= 0)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "One of identity or currency to accept must be valid");
        }
        acceptedCurrency.valueMap[currencyID] = currencyAmount;

        LOCK(cs_main);
        if ((acceptToAddress = ValidateDestination(acceptToDestStr)).which() == COptCCParams::ADDRTYPE_INVALID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. To accept an offer of currency, the accept address must be a transparent address or identity. See help.");
        }
    }

    // for use later
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    CMutableTransaction mtx(txToTake);

    int firstFundingInput = 0;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        LOCK(mempool.cs);

        if (deliver.isStr())
        {
            CIdentity revocationIdentity, recoveryIdentity;

            // this needs to be a valid ID in our wallet
            CTxDestination identityDest = DecodeDestination(uni_get_str(deliver));
            if (identityDest.which() != COptCCParams::ADDRTYPE_ID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "If a VerusID is specified to deliver when taking the offer, it must be a valid ID name or i-address on this chain");
            }
            bool idInWallet = pwalletMain->GetIdentity(GetDestinationID(identityDest), keyAndIdentity);

            if (!idInWallet || !(*(CIdentity *)(&keyAndIdentity.second) = CIdentity::LookupIdentity(GetDestinationID(identityDest), 0, nullptr, &idInput)).IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No authority over VerusID or ID not found");
            }

            uint256 blkHash;
            CTransaction oldIdTx;
            if (!myGetTransaction(idInput.prevout.hash, oldIdTx, blkHash))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + keyAndIdentity.second.name + " (" + EncodeDestination(CIdentityID(keyAndIdentity.second.GetID())) + "), transaction not found ");
            }
            oldIdOutput = oldIdTx.vout[idInput.prevout.n];

            if (!keyAndIdentity.first.CanSign())
            {
                // we need either signing authority, revocation, recovery, or any combination to be able to create a delivery transaction
                if (keyAndIdentity.second.revocationAuthority == idIDToDeliver && keyAndIdentity.second.recoveryAuthority == idIDToDeliver)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "No authority over VerusID specified for delivery");
                }
                // if recovery is different, get it and see if we have signing authority on that
                if (keyAndIdentity.second.revocationAuthority != idIDToDeliver)
                {
                    if (!pwalletMain->GetIdentity(keyAndIdentity.second.revocationAuthority, keyAndRevocation))
                    {
                        if (!(keyAndRevocation.second = CIdentityMapValue(CIdentity::LookupIdentity(keyAndIdentity.second.revocationAuthority))).IsValid())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Revocation authority not found for ID specified");
                        }
                    }
                }
                else
                {
                    keyAndRevocation = keyAndIdentity;
                }
                
                // if recovery is different, get it and see if we have signing authority on that
                if (keyAndIdentity.second.recoveryAuthority != idIDToDeliver)
                {
                    if (keyAndIdentity.second.recoveryAuthority == keyAndIdentity.second.revocationAuthority)
                    {
                        keyAndRecovery = keyAndRevocation;
                    }
                    else if (!pwalletMain->GetIdentity(keyAndIdentity.second.recoveryAuthority, keyAndRecovery))
                    {
                        if (!(keyAndRecovery.second = CIdentityMapValue(CIdentity::LookupIdentity(keyAndIdentity.second.recoveryAuthority))).IsValid())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Recovery authority not found for ID specified");
                        }
                    }
                }
                else
                {
                    keyAndRecovery = keyAndIdentity;
                }
            }
            // if we can't sign for any authority on the ID, don't make a transaction
            if (!keyAndIdentity.first.CanSign() && !keyAndRevocation.first.CanSign() && !keyAndRecovery.first.CanSign())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "This wallet has no authority to sign for any part of delivering the ID specified");
            }
            currencyToDeliver.valueMap[ASSETCHAINS_CHAINID] = feeAmount;
        }
        else if (deliver.isObject())
        {
            // determine the currency we are offering to deliver
            auto currencyStr = TrimSpaces(uni_get_str(find_value(deliver, "currency")));
            CAmount destinationAmount = AmountFromValue(find_value(deliver, "amount"));
            uint160 curID;
            if (!currencyStr.empty())
            {
                curID = ValidateCurrencyName(currencyStr, true);
                if (curID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency specified for delivery not found");
                }
            }
            else
            {
                curID = ASSETCHAINS_CHAINID;
            }
            
            currencyToDeliver.valueMap[curID] = destinationAmount;
            currencyToDeliver.valueMap[ASSETCHAINS_CHAINID] += feeAmount;
        }

        // now, ensure that our expected output and the input provided in the offer are the same
        COptCCParams p;
        CIdentity offeredIdentity;
        CCurrencyValueMap offeredCurrency;
        if (inputTxToOffer.vout[txToTake.vin[0].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_IDENTITY_PRIMARY &&
            p.vData.size() &&
            (offeredIdentity = CIdentity(p.vData[0])).IsValid())
        {
            if (offeredIdentity.GetID() != acceptedIdentity.GetID())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity offered: " + EncodeDestination(CIdentityID(offeredIdentity.GetID())) + ", is not the same as accepted: " + EncodeDestination(CIdentityID(acceptedIdentity.GetID())));
            }
        }
        else if (inputTxToOffer.vout[txToTake.vin[0].prevout.n].scriptPubKey.IsSpendableOutputType())
        {
            if (inputTxToOffer.vout[txToTake.vin[0].prevout.n].nValue > 0)
            {
                offeredCurrency.valueMap[ASSETCHAINS_CHAINID] = inputTxToOffer.vout[txToTake.vin[0].prevout.n].nValue;
            }
            offeredCurrency += inputTxToOffer.vout[txToTake.vin[0].prevout.n].scriptPubKey.ReserveOutValue();
            if (offeredCurrency < acceptedCurrency)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency offered: " + offeredCurrency.ToUniValue().write() + ", is less than accepted: " + acceptedCurrency.ToUniValue().write());
            }
        }

        CAmount additionalFees = feeAmount;

        // add the output
        if (acceptedIdentity.IsValid())
        {
            mtx.vout.push_back(CTxOut(0, acceptedIdentity.IdentityUpdateOutputScript(height + 1)));
        }
        else if ((acceptedCurrency = acceptedCurrency.CanonicalMap()).valueMap.size())
        {
            // if our accepted currency is native, no reserve output
            CAmount nativeOut = acceptedCurrency.valueMap.count(ASSETCHAINS_CHAINID) ? acceptedCurrency.valueMap[ASSETCHAINS_CHAINID] : 0;

            if (acceptedCurrency.valueMap.size() == 1 && nativeOut)
            {
                mtx.vout.push_back(CTxOut(nativeOut, GetScriptForDestination(acceptToAddress)));
            }
            else
            {
                acceptedCurrency.valueMap.erase(ASSETCHAINS_CHAINID);
                std::vector<CTxDestination> dest({acceptToAddress});
                CTokenOutput to(acceptedCurrency);
                mtx.vout.push_back(CTxOut(nativeOut, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dest, 1, &to))));
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify valid identity or currency for exchange");
        }

        // if the identity has been initialized, we are delivering an identity in this transaction, input our identity to the
        // transaction, and add an output for our return
        std:vector<COutput> vCoins;
        std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
        CAmount nativeValueOut;
        CCurrencyValueMap reserveValueOut;
        std::vector<SaplingNoteEntry> saplingNotes;

        firstFundingInput = mtx.vin.size();

        if (keyAndIdentity.second.IsValid())
        {
            bool success = true;
            mtx.vin.push_back(idInput);
            // one ID input to fund the transaction
            if (additionalFees)
            {
                if (hasZSource)
                {
                    saplingNotes = find_unspent_notes(zaddressSource);
                    CAmount totalFound = 0;
                    int i;
                    for (i = 0; i < saplingNotes.size(); i++)
                    {
                        totalFound += saplingNotes[i].note.value();
                        if (totalFound >= additionalFees)
                        {
                            break;
                        }
                    }
                    // remove all but the notes we'll use
                    if (i < saplingNotes.size())
                    {
                        saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
                        success = true;
                    }
                    else
                    {
                        success = false;
                    }
                }
                else
                {
                    success = find_utxos(from_taddress, vCoins) &&
                                pwalletMain->SelectCoinsMinConf(additionalFees, 0, 0, vCoins, setCoinsRet, nativeValueOut);
                }
            }
            if (!success)
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to fund delivery of identity");
            }
        }
        else if (currencyToDeliver.valueMap.size())
        {
            COptCCParams p;
            CCurrencyValueMap currencyRequested;
            if (txToTake.vout[0].scriptPubKey.IsSpendableOutputType(p) || (p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT))
            {
                if (txToTake.vout[0].nValue - txToTake.valueBalance > 0)
                {
                    currencyRequested.valueMap[ASSETCHAINS_CHAINID] = txToTake.vout[0].nValue - txToTake.valueBalance;
                }
                currencyRequested += txToTake.vout[0].scriptPubKey.ReserveOutValue();
                if (currencyToDeliver < currencyRequested)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency being delivered: " + currencyToDeliver.ToUniValue().write() + ", is less than requested: " + currencyRequested.ToUniValue().write());
                }
                currencyToDeliver = currencyRequested;
            }
            else
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Invalid currency request from offer transaction");
            }

            // find enough currency from source to fund the acceptance
            CAmount nativeValue = (currencyToDeliver.valueMap[ASSETCHAINS_CHAINID] + additionalFees);
            currencyToDeliver.valueMap.erase(ASSETCHAINS_CHAINID);

            bool success = false;
            if (hasZSource)
            {
                if (currencyToDeliver.CanonicalMap().valueMap.size() != 0)
                {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Private address source cannot be used for non-native currency delivery");
                }
                saplingNotes = find_unspent_notes(zaddressSource);
                CAmount totalFound = 0;
                int i;
                for (i = 0; i < saplingNotes.size(); i++)
                {
                    totalFound += saplingNotes[i].note.value();
                    if (totalFound >= additionalFees)
                    {
                        break;
                    }
                }
                // remove all but the notes we'll use
                if (i < saplingNotes.size())
                {
                    saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
                    success = true;
                }
            }
            else
            {
                success = find_utxos(from_taddress, vCoins) &&
                        pwalletMain->SelectReserveCoinsMinConf(currencyToDeliver,
                                                                nativeValue,
                                                                0,
                                                                1,
                                                                vCoins,
                                                                setCoinsRet,
                                                                reserveValueOut,
                                                                nativeValueOut);
            }
            
            if (!success)
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to fund currency delivery");
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No identity or currency to deliver");
        }

        if (saplingNotes.size())
        {
            if (txToTake.vShieldedOutput.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Paying for an offer, which pays to a z-address with a z-address source is not yet implemented");
            }

            std::vector<SaplingOutPoint> notes;
            for (size_t i = 0; i < saplingNotes.size(); i++)
            {
                notes.push_back(saplingNotes[i].op);
            }

            // Fetch Sapling anchor and witnesses
            uint256 anchor;
            std::vector<boost::optional<SaplingWitness>> witnesses;
            {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
            }

            saplingSpendCtx = librustzcash_sapling_proving_ctx_init();

            // Add Sapling spends
            for (size_t i = 0; i < saplingNotes.size(); i++)
            {
                SpendDescriptionInfo spend(expsk, saplingNotes[i].note, anchor, boost::get(witnesses[i]));
                //tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());

                auto cm = spend.note.cm();
                auto nf = spend.note.nullifier(
                    spend.expsk.full_viewing_key(), spend.witness.position());
                if (!cm || !nf) {
                    librustzcash_sapling_proving_ctx_free(saplingSpendCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Spend is invalid");
                }

                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss << spend.witness.path();
                std::vector<unsigned char> witness(ss.begin(), ss.end());

                SpendDescription sdesc;
                if (!librustzcash_sapling_spend_proof(
                        saplingSpendCtx,
                        spend.expsk.full_viewing_key().ak.begin(),
                        spend.expsk.nsk.begin(),
                        spend.note.d.data(),
                        spend.note.r.begin(),
                        spend.alpha.begin(),
                        spend.note.value(),
                        spend.anchor.begin(),
                        witness.data(),
                        sdesc.cv.begin(),
                        sdesc.rk.begin(),
                        sdesc.zkproof.data())) {
                    librustzcash_sapling_proving_ctx_free(saplingSpendCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Spend proof failed");
                }

                sdesc.anchor = spend.anchor;
                sdesc.nullifier = *nf;
                mtx.vShieldedSpend.push_back(sdesc);
            }
        }
        else
        {
            // put all transparent inputs and spends on the transaction, sign and return or post
            for (auto &oneInput : setCoinsRet)
            {
                mtx.vin.push_back(CTxIn(oneInput.first->GetHash(), oneInput.second));
            }
        }

        // Fetch previous transactions (inputs):
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view
        for (auto &txin : mtx.vin)
        {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.AccessCoins(prevHash); // this can fail
        }
        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    CReserveTransactionDescriptor rtxd(mtx, view, height + 1);
    if (!rtxd.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Created invalid transaction");
    }
    CCurrencyValueMap reserveChange = rtxd.ReserveFees();
    CAmount nativeChange = rtxd.NativeFees() - feeAmount;
    if (nativeChange < DEFAULT_TRANSACTION_FEE)
    {
        nativeChange = 0;
    }
    if (reserveChange.valueMap.size())
    {
        std::vector<CTxDestination> dest({changeAddress});
        CTokenOutput to(reserveChange);
        mtx.vout.push_back(CTxOut(nativeChange, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dest, 1, &to))));
    }
    else if (nativeChange)
    {
        mtx.vout.push_back(CTxOut(nativeChange, GetScriptForDestination(changeAddress)));
    }

    CTransaction txConst(mtx);
    UniValue vErrors(UniValue::VARR);

    // Sign what we can

    // first Sapling spends, if we have them
    if (saplingSpends.size())
    {
        uint256 dataToBeSigned;
        CScript scriptCode;
        try {
            dataToBeSigned = SignatureHash(scriptCode, mtx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId);
        } catch (std::logic_error ex) {
            librustzcash_sapling_proving_ctx_free(saplingSpendCtx);
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not construct signature hash");
        }

        // Create Sapling spendAuth and binding signatures
        for (size_t i = 0; i < saplingSpends.size(); i++) {
            librustzcash_sapling_spend_sig(
                saplingSpends[i].expsk.ask.begin(),
                saplingSpends[i].alpha.begin(),
                dataToBeSigned.begin(),
                mtx.vShieldedSpend[i].spendAuthSig.data());
        }
        librustzcash_sapling_binding_sig(
            saplingSpendCtx,
            mtx.valueBalance,
            dataToBeSigned.begin(),
            mtx.bindingSig.data());

        librustzcash_sapling_proving_ctx_free(saplingSpendCtx);
    }

    for (int i = firstFundingInput; i < mtx.vin.size(); i++)
    {
        CTxIn& txin = mtx.vin[i];
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (coins == NULL || !coins->IsAvailable(txin.prevout.n)) {
            SigningErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = CCoinsViewCache::GetSpendFor(coins, txin);
        const CAmount& amount = coins->vout[txin.prevout.n].nValue;

        SignatureData sigdata;
        ProduceSignature(MutableTransactionSignatureCreator(pwalletMain, &mtx, i, amount, prevPubKey), prevPubKey, sigdata, consensusBranchId);

        TransactionSignatureChecker checker(&txConst, i, amount);
        sigdata = CombineSignatures(prevPubKey, checker, sigdata, DataFromTransaction(txConst, i), consensusBranchId);

        UpdateTransaction(mtx, i, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, checker, consensusBranchId, &serror)) {
            SigningErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }
    bool fComplete = vErrors.empty();
    UniValue retVal(UniValue::VOBJ);

    if (fComplete && !returnHex)
    {
        CValidationState state;
        CTransaction finalTx = mtx;
        LOCK(cs_main);

        bool relayTx;
        {
            LOCK2(smartTransactionCS, mempool.cs);
            relayTx = myAddtomempool(finalTx, &state);
        }

        if (!relayTx)
        {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Could not commit transaction - rejected");
        }
        else
        {
            //printf("%s: success adding %s to mempool\n", __func__, newImportTx.GetHash().GetHex().c_str());
            RelayTransaction(finalTx);
        }
        retVal.pushKV("txid", finalTx.GetHash().GetHex());
    }
    else
    {
        // if this is an ID swap, spend ID to transaction and take funds or pay requird funds and take ID
        // if this is a funds swap, pay required funds and take required funds
        retVal.pushKV("tx", EncodeHexTx(mtx));
        if (!vErrors.empty())
        {
            retVal.pushKV("errors", vErrors);
        }
    }

    return retVal;
}

UniValue IdOfferInfo(const CIdentity &identityOffer)
{
    UniValue retVal(UniValue::VOBJ);
    retVal.pushKV("name", identityOffer.name);
    retVal.pushKV("identityid", EncodeDestination(CIdentityID(identityOffer.GetID())));
    retVal.pushKV("systemid", EncodeDestination(CIdentityID(identityOffer.systemID)));
    retVal.pushKV("original", identityOffer.systemID == ASSETCHAINS_CHAINID);
    return retVal;
}

UniValue getoffers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "getoffers \"currencyorid\" (iscurrency) (withtx)\n"
            "\nReturns all open offers for a specific currency or ID\n"

            "\nArguments\n"
            "1. \"currencyorid\"        (string, required) The currency or ID to check for offers, both sale and purchase\n"
            "2. \"iscurrency\"          (bool, optional)   default=false, if false, this looks for ID offers, if true, currencies\n"
            "3. \"withtx\"              (bool, optional)   default=false, if true, this returns serialized hex of the exchange transaction for signing\n"

            "\nResult:\n"
            "all available offers for or in the indicated currency or ID are displayed\n"

            "\nExamples:\n"
            + HelpExampleCli("getoffers", "\"currencyorid\" (iscurrency)")
            + HelpExampleRpc("getoffers", "\"currencyorid\" (iscurrency)")
        );
    }

    CheckVerusVaultAPIsValid();

    bool isCurrency = false;
    if (params.size() > 1)
    {
        isCurrency = uni_get_bool(params[1]);
    }

    bool withTx = false;
    if (params.size() > 2)
    {
        withTx = uni_get_bool(params[2]);
    }

    uint160 lookupID, lookupForID;

    CCurrencyDefinition currencyDef;
    uint160 currencyOrIdID;
    CIdentity identity;
    std::string currencyOrIDStr(uni_get_str(params[0]));

    LOCK(cs_main);

    if (isCurrency)
    {
        lookupID = ValidateCurrencyName(currencyOrIDStr, true, &currencyDef);
        if (lookupID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency specified as source is not valid");
        }
        lookupForID = COnChainOffer::OnChainOfferForCurrencyKey(lookupID);
        lookupID = COnChainOffer::OnChainCurrencyOfferKey(lookupID);
        currencyOrIdID = currencyDef.GetID();
    }
    else
    {
        CTxDestination idDest = DecodeDestination(currencyOrIDStr);
        if (idDest.which() != COptCCParams::ADDRTYPE_ID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity specified as source is not valid");
        }
        lookupID = GetDestinationID(idDest);
        if (!(identity = CIdentity::LookupIdentity(lookupID)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Source identity not found");
        }
        lookupForID = COnChainOffer::OnChainOfferForIdentityKey(lookupID);
        lookupID = COnChainOffer::OnChainIdentityOfferKey(lookupID);
        currencyOrIdID = identity.GetID();
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputOffers;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;

    uint32_t height = chainActive.Height();

    // bool is "iscurrency" for the offer in a buy and for the request for payment in a sell

    // offers to buy with IDs
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniBuyWithIDs;
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniSellToIDs;

    std::multimap<std::pair<uint160, CAmount>, UniValue> uniBuyWithCurrency;
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniSellToCurrency;

    //printf("%s: looking up keys: %s, %s\n", __func__, EncodeDestination(CKeyID(lookupID)).c_str(), EncodeDestination(CKeyID(lookupForID)).c_str());

    if (!GetAddressUnspent(lookupID, CScript::P2PKH, unspentOutputOffers) || !GetAddressUnspent(lookupForID, CScript::P2PKH, unspentOutputs))
    {
        return false;
    }
    else
    {
        UniValue retVal(UniValue::VOBJ);
        unspentOutputs.insert(unspentOutputs.end(), unspentOutputOffers.begin(), unspentOutputOffers.end());

        for (auto &oneOffer : unspentOutputs)
        {
            CTransaction postedTx, offerTx, inputToOfferTx;
            uint256 blockHash;
            CPartialTransactionProof offerTxProof;
            COptCCParams p;
            if (myGetTransaction(oneOffer.first.txhash, postedTx, blockHash))
            {
                if (GetOpRetChainOffer(postedTx, offerTx, inputToOfferTx, height))
                {
                    // find out what the transaction is requesting for payment
                    CCurrencyValueMap offerToPay, wePay;
                    CIdentity offerToTransfer, weTransfer;

                    std::pair<bool, CAmount> exchangeForurrencyOrID;
                    bool isBuy = true;

                    std::pair<CTxOut, CTxOut> offerOuts(std::make_pair(inputToOfferTx.vout[offerTx.vin[0].prevout.n], offerTx.vout[0]));
                    if (offerTx.vShieldedOutput.size() != 0)
                    {
                        offerOuts.second.nValue -= offerTx.valueBalance;
                    }

                    if (offerOuts.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        p.evalCode == EVAL_IDENTITY_PRIMARY &&
                        p.vData.size())
                    {
                        if (!(weTransfer = CIdentity(p.vData[0])).IsValid())
                        {
                            continue;
                        }
                        // if this is not what we are looking for, then it must be a request to trade for what we are looking for
                        if (isCurrency || weTransfer.GetID() != currencyOrIdID)
                        {
                            // make sure the offer is offering what we are looking for
                            if (isCurrency)
                            {
                                // verify it is the currency we are looking for
                                p = COptCCParams();
                                if (!(offerOuts.first.scriptPubKey.IsSpendableOutputType(p) &&
                                     ((currencyOrIdID == ASSETCHAINS_CHAINID && offerOuts.first.nValue > 0) ||
                                      ((currencyOrIdID != ASSETCHAINS_CHAINID && 
                                       (offerToPay = offerOuts.first.ReserveOutValue()).valueMap.count(currencyOrIdID) &&
                                        offerToPay.valueMap[currencyOrIdID] > 0)))))
                                {
                                    continue;
                                }
                                if (offerOuts.first.nValue > 0)
                                {
                                    offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                                }
                            }
                            else
                            {
                                // verify it is the ID we are looking for
                                if (!(offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                      p.IsValid() &&
                                      p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                      p.vData.size() &&
                                      (offerToTransfer = CIdentity(p.vData[0])).IsValid() &&
                                      offerToTransfer.GetID() == currencyOrIdID))
                                {
                                    continue;
                                }
                            }
                            UniValue offerJSON(UniValue::VOBJ);
                            offerJSON.pushKV("offer", offerToTransfer.IsValid() ? IdOfferInfo(offerToTransfer) : offerToPay.ToUniValue());
                            offerJSON.pushKV("accept", IdOfferInfo(weTransfer));
                            offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                            if (withTx)
                            {
                                offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                            }
                            offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                            if (offerToPay.valueMap.begin() != offerToPay.valueMap.end() && offerToPay.valueMap.begin()->first == currencyOrIdID)
                            {
                                uniSellToIDs.insert(std::make_pair(std::make_pair(weTransfer.GetID(), offerToPay.valueMap.begin()->second), offerJSON));
                            }
                            else // offer to transfer is our query ID
                            {
                                uniSellToIDs.insert(std::make_pair(std::make_pair(weTransfer.GetID(), offerOuts.second.nValue > 0 ? offerOuts.second.nValue : 0), offerJSON));
                            }
                        }
                        else // this is an offer to buy the referenced ID for either currency or another ID, which is in the first output
                        {
                            if (offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                p.vData.size() &&
                                (offerToTransfer = CIdentity(p.vData[0])).IsValid())
                            {
                                UniValue offerJSON(UniValue::VOBJ);
                                offerJSON.pushKV("offer", offerToTransfer.IsValid() ? IdOfferInfo(offerToTransfer) : offerToPay.ToUniValue());
                                offerJSON.pushKV("accept", weTransfer.IsValid() ? IdOfferInfo(weTransfer) : wePay.ToUniValue());
                                offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                                if (withTx)
                                {
                                    offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                                }
                                offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                                uniBuyWithIDs.insert(std::make_pair(std::make_pair(offerToTransfer.GetID(), offerOuts.second.nValue > 0 ? offerOuts.second.nValue : 0), offerJSON));
                            }
                            else
                            {
                                // verify that there is a non-zero offer
                                p = COptCCParams();
                                if (!(offerOuts.first.scriptPubKey.IsSpendableOutputType(p) &&
                                     (offerOuts.first.nValue > 0 ||
                                      ((offerToPay = offerOuts.first.ReserveOutValue()) > CCurrencyValueMap()))))
                                {
                                    continue;
                                }
                                uint160 currencyID = offerOuts.first.nValue > 0 ? ASSETCHAINS_CHAINID : offerToPay.valueMap.begin()->first;
                                CAmount offerAmount = offerOuts.first.nValue > 0 ? offerOuts.first.nValue : offerToPay.valueMap.begin()->second;
                                if (offerOuts.first.nValue > 0)
                                {
                                    offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                                }
                                UniValue offerJSON(UniValue::VOBJ);
                                offerJSON.pushKV("offer", offerToTransfer.IsValid() ? IdOfferInfo(offerToTransfer) : offerToPay.ToUniValue());
                                offerJSON.pushKV("accept", weTransfer.IsValid() ? IdOfferInfo(weTransfer) : wePay.ToUniValue());
                                offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                                if (withTx)
                                {
                                    offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                                }
                                offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                                uniBuyWithCurrency.insert(std::make_pair(std::make_pair(currencyID, offerAmount), offerJSON));
                            }
                        }
                    }
                    else if (offerOuts.second.scriptPubKey.IsSpendableOutputType(p))
                    {
                        // see if it is a buy with the currency we are querying for
                        wePay = offerOuts.second.ReserveOutValue();
                        if (offerOuts.second.nValue > 0)
                        {
                            wePay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.second.nValue;
                        }

                        if (isCurrency && wePay.valueMap.count(currencyOrIdID) && wePay.valueMap[currencyOrIdID] > 0)
                        {
                            // if so, then it is a buy with whatever the input is
                            if (offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                p.vData.size() &&
                                (offerToTransfer = CIdentity(p.vData[0])).IsValid())
                            {
                                UniValue offerJSON(UniValue::VOBJ);
                                offerJSON.pushKV("offer", IdOfferInfo(offerToTransfer));
                                offerJSON.pushKV("accept", wePay.ToUniValue());
                                offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                                if (withTx)
                                {
                                    offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                                }
                                offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                                uniBuyWithIDs.insert(std::make_pair(std::make_pair(offerToTransfer.GetID(), wePay.valueMap.begin()->second), offerJSON));
                            }
                            else
                            {
                                // verify that there is a non-zero offer
                                offerToPay = offerOuts.first.ReserveOutValue();
                                if (offerOuts.first.nValue > 0)
                                {
                                    offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                                }

                                p = COptCCParams();
                                if (!(offerOuts.first.scriptPubKey.IsSpendableOutputType(p) && offerToPay > CCurrencyValueMap()))
                                {
                                    continue;
                                }
                                
                                bool nativeOffer = offerOuts.first.nValue > 0 && offerToPay.CanonicalMap().valueMap.size() == 1;
                                uint160 currencyID = nativeOffer ? ASSETCHAINS_CHAINID : offerToPay.valueMap.begin()->first;
                                CAmount offerAmount = nativeOffer ? offerOuts.first.nValue : offerToPay.valueMap.begin()->second;

                                UniValue offerJSON(UniValue::VOBJ);
                                offerJSON.pushKV("offer", offerToPay.ToUniValue());
                                offerJSON.pushKV("accept", wePay.ToUniValue());
                                offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                                if (withTx)
                                {
                                    offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                                }
                                offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                                uniBuyWithCurrency.insert(std::make_pair(std::make_pair(currencyID, CalculateFractionalPrice(offerAmount, wePay.valueMap[currencyOrIdID], true)), offerJSON));
                            }
                        }
                        else if (isCurrency &&
                                 offerOuts.first.scriptPubKey.IsSpendableOutputType(p) &&
                                 ((currencyOrIdID == ASSETCHAINS_CHAINID && offerOuts.first.nValue > 0) ||
                                 ((currencyOrIdID != ASSETCHAINS_CHAINID && 
                                 (offerToPay = offerOuts.first.ReserveOutValue()).valueMap.count(currencyOrIdID) &&
                                 offerToPay.valueMap[currencyOrIdID] > 0))))
                        {
                            if (offerOuts.first.nValue > 0)
                            {
                                offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                            }

                            // offer to sell currency we are querying for the output's currency
                            bool nativePay = offerOuts.second.nValue > 0 && wePay.CanonicalMap().valueMap.size() == 1;
                            uint160 currencyID = nativePay ? ASSETCHAINS_CHAINID : wePay.valueMap.begin()->first;
                            CAmount payAmount = nativePay ? offerOuts.second.nValue : wePay.valueMap.begin()->second;
                            UniValue offerJSON(UniValue::VOBJ);
                            offerJSON.pushKV("offer", offerToPay.ToUniValue());
                            offerJSON.pushKV("accept", wePay.ToUniValue());
                            offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                            if (withTx)
                            {
                                offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                            }
                            offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                            uniSellToCurrency.insert(std::make_pair(std::make_pair(currencyID, CalculateFractionalPrice(payAmount, offerToPay.valueMap[currencyOrIdID], false)), offerJSON));
                        }
                        else if (!isCurrency &&
                                 offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                 p.IsValid() &&
                                 p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                 p.vData.size() &&
                                 (offerToTransfer = CIdentity(p.vData[0])).IsValid() &&
                                 offerToTransfer.GetID() == currencyOrIdID)
                        {
                            bool nativePay = offerOuts.second.nValue > 0 && wePay.CanonicalMap().valueMap.size() == 1;
                            uint160 currencyID = nativePay ? ASSETCHAINS_CHAINID : wePay.valueMap.begin()->first;
                            CAmount payAmount = nativePay ? offerOuts.second.nValue : wePay.valueMap.begin()->second;

                            // offer to sell identity we are querying for the output's currency
                            UniValue offerJSON(UniValue::VOBJ);
                            offerJSON.pushKV("offer", IdOfferInfo(offerToTransfer));
                            offerJSON.pushKV("accept", wePay.ToUniValue());
                            offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                            if (withTx)
                            {
                                offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                            }
                            offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                            uniSellToCurrency.insert(std::make_pair(std::make_pair(currencyID, payAmount), offerJSON));
                        }
                    }
                }
            }
            else
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot retrieve transaction " + oneOffer.first.txhash.GetHex() + ", the local index is likely corrupted and either requires reindex, bootstrap, or resync");
            }
        }
        if (isCurrency)
        {
            // for uniSellToIDs (same as offers in this currency for IDs), we will want to order by highest price to lowest price,
            // as the query was only for things that could be traded or purchased from the currency. the long tail is likely
            // less interesting. we do not end up with buy with IDs on a currency only query
            UniValue oneCategory(UniValue::VARR);
            for (auto rIT = uniSellToIDs.rbegin(); rIT != uniSellToIDs.rend(); rIT++)
            {
                UniValue oneOffer(UniValue::VOBJ);
                oneOffer.pushKV("identityid", EncodeDestination(CIdentityID(rIT->first.first)));
                oneOffer.pushKV("price", ValueFromAmount(rIT->first.second));
                oneOffer.pushKV("offer", rIT->second);
                oneCategory.push_back(oneOffer);
            }

            if (oneCategory.size())
            {
                retVal.pushKV("currency_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_for_ids", oneCategory);
                oneCategory = UniValue(UniValue::VARR);
            }

            // buying currency with IDs is basically selling the ID for this currency
            for (auto rIT = uniBuyWithIDs.rbegin(); rIT != uniBuyWithIDs.rend(); rIT++)
            {
                UniValue oneOffer(UniValue::VOBJ);
                oneOffer.pushKV("identityid", EncodeDestination(CIdentityID(rIT->first.first)));
                oneOffer.pushKV("price", ValueFromAmount(rIT->first.second));
                oneOffer.pushKV("offer", rIT->second);
                oneCategory.push_back(oneOffer);
            }

            if (oneCategory.size())
            {
                retVal.pushKV("ids_for_currency_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                oneCategory = UniValue(UniValue::VARR);
            }

            // we should order these by currency, showing both sellTo and buyWith in each currency together
            auto rSellIT = uniSellToCurrency.rbegin();
            auto rBuyIT = uniBuyWithCurrency.rbegin();
            uint160 lastCurrencyID;
            bool isBuyLast = false;

            while (rSellIT != uniSellToCurrency.rend() || rBuyIT != uniBuyWithCurrency.rend())
            {
                for (;
                    rSellIT != uniSellToCurrency.rend() &&
                        (rBuyIT == uniBuyWithCurrency.rend() || (rSellIT->first.first.GetHex() >= rBuyIT->first.first.GetHex()));
                    rSellIT++)
                {
                    uint160 newLast = rSellIT->first.first;
                    if (lastCurrencyID != newLast)
                    {
                        if (oneCategory.size())
                        {
                            retVal.pushKV("currency_" + EncodeDestination(CIdentityID(lastCurrencyID)) + "_offers_in_currency_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                            oneCategory = UniValue(UniValue::VARR);
                        }
                        lastCurrencyID = newLast;
                    }
                    UniValue oneOffer(UniValue::VOBJ);
                    oneOffer.pushKV("currencyid", EncodeDestination(CIdentityID(rSellIT->first.first)));
                    oneOffer.pushKV("price", ValueFromAmount(rSellIT->first.second));
                    oneOffer.pushKV("offer", rSellIT->second);
                    oneCategory.push_back(oneOffer);
                    isBuyLast = false;
                }

                for (;
                    rBuyIT != uniBuyWithCurrency.rend() &&
                        (rSellIT == uniSellToCurrency.rend() || (rBuyIT->first.first.GetHex() >= lastCurrencyID.GetHex()));
                    rBuyIT++)
                {
                    uint160 newLast = rBuyIT->first.first;
                    if (lastCurrencyID != newLast)
                    {
                        if (oneCategory.size())
                        {
                            retVal.pushKV("currency_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_offers_in_currency_" + EncodeDestination(CIdentityID(lastCurrencyID)), oneCategory);
                            oneCategory = UniValue(UniValue::VARR);
                        }
                        lastCurrencyID = newLast;
                    }
                    UniValue oneOffer(UniValue::VOBJ);
                    oneOffer.pushKV("currencyid", EncodeDestination(CIdentityID(rBuyIT->first.first)));
                    oneOffer.pushKV("price", ValueFromAmount(rBuyIT->first.second));
                    oneOffer.pushKV("offer", rBuyIT->second);
                    oneCategory.push_back(oneOffer);
                    isBuyLast = true;
                }
            }
            if (oneCategory.size())
            {
                if (isBuyLast)
                {
                    retVal.pushKV("currency_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_offers_in_currency_" + EncodeDestination(CIdentityID(lastCurrencyID)), oneCategory);
                }
                else
                {
                    retVal.pushKV("currency_" + EncodeDestination(CIdentityID(lastCurrencyID)) + "_offers_in_currency_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                }
            }
        }
        else
        {
            // for uniSellToIDs (same as offer to trade ID in question for other ID(s)) - offered in exchange for IDs
            // for uniBuyWithIDs (same as offer to trade other IDs for the ID in question) - IDs offered in exchange for

            // for uniSellToCurrency, offer(s) to sell for a specific currency at a specific price, list low to high in each currecny
            // uniBuyWithCurrency, offers to buy with a specific currency for a specific price, list high to low

            // for uniSellToIDs (same as this ID on offer for other IDs)
            UniValue oneCategory(UniValue::VARR);
            for (auto rIT = uniSellToIDs.rbegin(); rIT != uniSellToIDs.rend(); rIT++)
            {
                UniValue oneOffer(UniValue::VOBJ);
                oneOffer.pushKV("identityid", EncodeDestination(CIdentityID(rIT->first.first)));
                oneOffer.pushKV("price", ValueFromAmount(rIT->first.second));
                oneOffer.pushKV("offer", rIT->second);
                oneCategory.push_back(oneOffer);
            }

            if (oneCategory.size())
            {
                retVal.pushKV("id_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_for_ids", oneCategory);
                oneCategory = UniValue(UniValue::VARR);
            }

            for (auto rIT = uniBuyWithIDs.rbegin(); rIT != uniBuyWithIDs.rend(); rIT++)
            {
                UniValue oneOffer(UniValue::VOBJ);
                oneOffer.pushKV("identityid", EncodeDestination(CIdentityID(rIT->first.first)));
                oneOffer.pushKV("price", ValueFromAmount(rIT->first.second));
                oneOffer.pushKV("offer", rIT->second);
                oneCategory.push_back(oneOffer);
            }

            if (oneCategory.size())
            {
                retVal.pushKV("ids_for_id_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                oneCategory = UniValue(UniValue::VARR);
            }

            // we should order these by currency, showing both sellTo and buyWith in each currency together
            auto rSellIT = uniSellToCurrency.rbegin();
            auto rBuyIT = uniBuyWithCurrency.rbegin();
            uint160 lastCurrencyID;
            bool isBuyLast = false;

            while (rSellIT != uniSellToCurrency.rend() || rBuyIT != uniBuyWithCurrency.rend())
            {

                for (;
                    rSellIT != uniSellToCurrency.rend() &&
                        (rBuyIT == uniBuyWithCurrency.rend() || (rSellIT->first.first.GetHex() >= rBuyIT->first.first.GetHex()));
                    rSellIT++)
                {
                    uint160 newLast = rSellIT->first.first;
                    if (lastCurrencyID != newLast)
                    {
                        if (oneCategory.size())
                        {
                            retVal.pushKV("id_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_for_currency_" + EncodeDestination(CIdentityID(lastCurrencyID)), oneCategory);
                            oneCategory = UniValue(UniValue::VARR);
                        }
                        lastCurrencyID = newLast;
                    }
                    UniValue oneOffer(UniValue::VOBJ);
                    oneOffer.pushKV("currencyid", EncodeDestination(CIdentityID(rSellIT->first.first)));
                    oneOffer.pushKV("price", ValueFromAmount(rSellIT->first.second));
                    oneOffer.pushKV("offer", rSellIT->second);
                    oneCategory.push_back(oneOffer);
                    isBuyLast = false;
                }

                for (;
                    rBuyIT != uniBuyWithCurrency.rend() &&
                        (rSellIT == uniSellToCurrency.rend() || (rBuyIT->first.first.GetHex() >= lastCurrencyID.GetHex()));
                    rBuyIT++)
                {
                    uint160 newLast = rBuyIT->first.first;
                    if (lastCurrencyID != newLast)
                    {
                        if (oneCategory.size())
                        {
                            retVal.pushKV("currency_" + EncodeDestination(CIdentityID(lastCurrencyID)) + "_for_id_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                            oneCategory = UniValue(UniValue::VARR);
                        }
                        lastCurrencyID = newLast;
                    }
                    UniValue oneOffer(UniValue::VOBJ);
                    oneOffer.pushKV("currencyid", EncodeDestination(CIdentityID(rBuyIT->first.first)));
                    oneOffer.pushKV("price", ValueFromAmount(rBuyIT->first.second));
                    oneOffer.pushKV("offer", rBuyIT->second);
                    oneCategory.push_back(oneOffer);
                    isBuyLast = true;
                }
            }
            if (oneCategory.size())
            {
                if (isBuyLast)
                {
                    retVal.pushKV("currency_" + EncodeDestination(CIdentityID(lastCurrencyID)) + "_for_id_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                }
                else
                {
                    retVal.pushKV("id_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_for_currency_" + EncodeDestination(CIdentityID(lastCurrencyID)), oneCategory);
                }
            }
        }
        return retVal;
    }
    return NullUniValue;
}

// close an offer by spending its source
bool CloseOneOffer(const OfferInfo &oneOffer, TransactionBuilder &tb, const CTxDestination &_dest, uint32_t height, const libzcash::PaymentAddress &zdest=libzcash::PaymentAddress());
bool CloseOneOffer(const OfferInfo &oneOffer, TransactionBuilder &tb, const CTxDestination &_dest, uint32_t height, const PaymentAddress &zdest)
{
    CTxDestination dest = _dest;
    // we just need to be able to spend the output to another input/output
    CScript outScript(oneOffer.inputToOfferTx.vout[oneOffer.offerTx.vin[0].prevout.n].scriptPubKey);
    CAmount value = oneOffer.inputToOfferTx.vout[oneOffer.offerTx.vin[0].prevout.n].nValue;
    tb.AddTransparentInput(COutPoint(oneOffer.offerTx.vin[0].prevout.hash, oneOffer.offerTx.vin[0].prevout.n), outScript, value);
    COptCCParams p;
    if (outScript.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        (p.evalCode == EVAL_IDENTITY_PRIMARY || p.evalCode == EVAL_IDENTITY_COMMITMENT) &&
        p.vData.size())
    {
        const libzcash::SaplingPaymentAddress *pSaplingAddress = boost::get<libzcash::SaplingPaymentAddress>(&zdest);
        bool hasZDest = pSaplingAddress != nullptr;
        bool hasTDest = dest.which() != COptCCParams::ADDRTYPE_INVALID;
        bool hasTokens = false;

        value -= std::min(DEFAULT_TRANSACTION_FEE, value);

        uint256 ovk;
        if (hasZDest)
        {
            HDSeed seed;
            if (!pwalletMain->GetHDSeed(seed)) {
                LogPrintf("%s: Wallet seed unavailable for z-address output\n", __func__);
                return false;
            }
            ovk = ovkForShieldingFromTaddr(seed);
            tb.SendChangeTo(*pSaplingAddress, ovk);
        }
        if (p.evalCode == EVAL_IDENTITY_PRIMARY)
        {
            CIdentity offeredIdentity(p.vData[0]);
            if (!offeredIdentity.IsValid())
            {
                LogPrintf("%s: Invalid identity\n", __func__);
                return false;
            }
            if (!hasTDest)
            {
                dest = CIdentityID(offeredIdentity.GetID());
                hasTDest = true;
            }
            offeredIdentity.UpgradeVersion(height);
            value -= std::min(DEFAULT_TRANSACTION_FEE, value);
            tb.AddTransparentOutput(offeredIdentity.IdentityUpdateOutputScript(height + 1), value);
        }
        else if (p.evalCode == EVAL_IDENTITY_COMMITMENT)
        {
            if (!hasTDest)
            {
                if (p.vKeys.size() > 1)
                {
                    LogPrintf("%s: No transparent destination specified and cannot determine from commitment\n", __func__);
                    return false;
                }
                dest = p.vKeys[0];
                hasTDest = true;
            }
            CCommitmentHash ch(p.vData[0]);
            if (ch.IsValid() && ch.reserveValues.valueMap.size())
            {
                hasTokens = true;
                if (hasZDest)
                {
                    tb.AddSaplingOutput(ovk, *pSaplingAddress, value);
                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, {dest}, 1, (CTokenOutput *)&ch)), 0);
                }
                else if (dest.which() != COptCCParams::ADDRTYPE_INVALID)
                {
                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, {dest}, 1, (CTokenOutput *)&ch)), value);
                }
                else
                {
                    LogPrintf("%s: Must close offers with valid, transparent funds destination when offer funds include non-native currency\n", __func__);
                    return false;
                }
            }
            else
            {
                if (hasZDest)
                {
                    tb.AddSaplingOutput(ovk, *pSaplingAddress, value);
                }
                else
                {
                    tb.AddTransparentOutput(dest, value);
                }
            }
        }
        if (hasTokens || !hasZDest)
        {
            tb.SendChangeTo(dest);
        }
    }
    return true;
}

UniValue closeoffers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
    {
        throw runtime_error(
            "closeoffers ('[\"offer1_txid\", \"offer2_txid\", ...]') (transparentorprivatefundsdestination) (privatefundsdestination)\n"
            "\nCloses all offers listed, if they are still valid and belong to this wallet.\n"
            "Always closes expired offers, even if no parameters are given\n\n"

            "\nArguments\n"
            "  [\"offer1_txid\", \"offer2_txid\", ...]      (array, optional) array of hex tx ids of offers to close\n"
            "  transparentorprivatefundsdestination         (transparent or private address, optional) destination for closing funds\n"
            "  privatefundsdestination                      (private address, optional) destination for native funds only\n"

            "\nResult\n"
            "  null return\n"
        );
    }
    CheckVerusVaultAPIsValid();

    UniValue retVal;
    std::set<uint256> txIds;

    if (params.size() > 0)
    {
        if (!params[0].isArray())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "First parameter must be an array of transaction IDs that are offers from this wallet to close. It may be null '[]'");
        }
        for (int i = 0; i < params[0].size(); i++)
        {
            uint256 oneTxId;
            oneTxId.SetHex(uni_get_str(params[0][i]));
            if (oneTxId.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txid specified, txids must be hex strings with no prefix");
            }
            txIds.insert(oneTxId);
        }
    }

    libzcash::PaymentAddress zaddressDest;
    CTxDestination transparentDest;
    std::string destStr;

    if (params.size() > 1)
    {
        destStr = uni_get_str(params[1]);
        if (destStr.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Closing open offers requires a transparent and/or private address to send funds to when closing");
        }
        transparentDest = ValidateDestination(destStr);
    }

    bool hasTDest = transparentDest.which() != COptCCParams::ADDRTYPE_INVALID;
    bool hasZDest = !hasTDest && pwalletMain->GetAndValidateSaplingZAddress(destStr, zaddressDest);

    if (hasTDest)
    {
        if (params.size() > 2)
        {
            if (hasZDest)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Third parameter must be a private address and only one private address may be specified");
            }
            std::string zDestStr = uni_get_str(params[2]);

            if (!(hasZDest = pwalletMain->GetAndValidateSaplingZAddress(zDestStr, zaddressDest)))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Third parameter must be a valid private address");
            }
        }
    }

    std::map<std::pair<bool, uint256>, OfferInfo> myOffers;
    uint32_t height;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        LOCK(mempool.cs);
        height = chainActive.Height();
        GetMyOffers(myOffers, height, txIds.size() != 0, true);
    }

    for (auto &oneOffer : myOffers)
    {
        TransactionBuilder tb(Params().GetConsensus(), height + 1, pwalletMain);
        CTransaction oneTx;
        {
            LOCK(pwalletMain->cs_wallet);
            // if this is true, it is unexpired
            if (oneOffer.first.first && !txIds.count(oneOffer.first.second))
            {
                continue;
            }
            if (!CloseOneOffer(oneOffer.second, tb, transparentDest, height, zaddressDest))
            {
                continue;
            }
            TransactionBuilderResult buildResult = tb.Build();
            oneTx = buildResult.GetTxOrThrow();
        }
        LOCK(cs_main);

        bool relayTx;
        CValidationState state;
        {
            LOCK2(smartTransactionCS, mempool.cs);
            relayTx = myAddtomempool(oneTx, &state);
        }

        if (!relayTx)
        {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Close offer transaction rejected: " + state.GetRejectReason());
        }
        else
        {
            RelayTransaction(oneTx);
        }
    }
    return retVal;
}

UniValue listopenoffers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
    {
        throw runtime_error(
            "listopenoffers (unexpired) (expired)'\n"
            "\nShows offers outstanding in this wallet\n"

            "\nArguments\n"
            "  unexpired                (bool, optional) default=true, list those offers in the wallet which are not expired\n"
            "  expired                  (bool, optional) default=true, list those offers in the wallet which are expired\n"

            "\nResult\n"
            "  all open offers\n"
        );
    }
    CheckVerusVaultAPIsValid();

    UniValue retVal;
    std::set<uint256> txIds;

    bool listUnexpired = true; 
    bool listExpired = true; 
    if (params.size() > 0)
    {
        listUnexpired = uni_get_bool(params[0]);
    }
    if (params.size() > 1)
    {
        listExpired = uni_get_bool(params[1]);
    }

    std::map<std::pair<bool, uint256>, OfferInfo> myOffers;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);

    uint32_t height = chainActive.Height();

    if (GetMyOffers(myOffers, height, listUnexpired, listExpired))
    {
        retVal = UniValue(UniValue::VARR);
        for (auto &oneOffer : myOffers)
        {
            UniValue oneOfferUni(UniValue::VOBJ);
            if (!oneOffer.first.first)
            {
                oneOfferUni.pushKV("expired", true);
            }
            else
            {
                oneOfferUni.pushKV("expires", (int64_t)oneOffer.second.offerTx.nExpiryHeight);
            }
            
            oneOfferUni.pushKV("txid", oneOffer.first.second.GetHex());
            UniValue scriptPubKeyUni(UniValue::VOBJ);
            ScriptPubKeyToUniv(oneOffer.second.inputToOfferTx.vout[oneOffer.second.offerTx.vin[0].prevout.n].scriptPubKey, scriptPubKeyUni, false);
            scriptPubKeyUni.pushKV("nativeout", ValueFromAmount(oneOffer.second.inputToOfferTx.vout[oneOffer.second.offerTx.vin[0].prevout.n].nValue));
            oneOfferUni.pushKV("offer", scriptPubKeyUni);
            scriptPubKeyUni = UniValue(UniValue::VOBJ);
            ScriptPubKeyToUniv(oneOffer.second.offerTx.vout[0].scriptPubKey, scriptPubKeyUni, false);
            scriptPubKeyUni.pushKV("nativeout", ValueFromAmount(oneOffer.second.offerTx.vout[0].nValue));
            oneOfferUni.pushKV("for", scriptPubKeyUni);
            retVal.push_back(oneOfferUni);
        }
    }
    return retVal;
}

bool IsValidExportCurrency(const CCurrencyDefinition &systemDest, const uint160 &exportCurrencyID, uint32_t height);

UniValue sendcurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
    {
        throw runtime_error(
            "sendcurrency \"fromaddress\" '[{\"address\":... ,\"amount\":...},...]' (minconfs) (feeamount)\n"
            "\nThis sends one or many Verus outputs to one or many addresses on the same or another chain.\n"
            "Funds are sourced automatically from the current wallet, which must be present, as in sendtoaddress.\n"
            "If \"fromaddress\" is specified, all funds will be taken from that address, otherwise funds may come\n"
            "from any source set of UTXOs controlled by the wallet.\n"

            "\nArguments\n"
            "1. \"fromaddress\"             (string, required) The Sapling, VerusID, or wildcard address to send funds from. \"*\", \"R*\", or \"i*\" are valid wildcards\n"
            "2. \"outputs\"                 (array, required) An array of json objects representing currencies, amounts, and destinations to send.\n"
            "    [{\n"
            "      \"currency\": \"name\"   (string, required) Name of the source currency to send in this output, defaults to native of chain\n"
            "      \"amount\":amount        (numeric, required) The numeric amount of currency, denominated in source currency\n"
            "      \"convertto\":\"name\",  (string, optional) Valid currency to convert to, either a reserve of a fractional, or fractional\n"
            "      \"exportto\":\"name\",   (string, optional) Valid chain or system name or ID to export to\n"
            "      \"exportid\":\"false\",  (bool, optional) if cross-chain export, export the full ID to the destination chain (will cost to export)\n"
            "      \"exportcurrency\":\"false\", (bool, optional) if cross-chain export, export the currency definition (will cost to export)\n"
            "      \"feecurrency\":\"name\", (string, optional) Valid currency that should be pulled from the current wallet and used to pay fee\n"
            "      \"via\":\"name\",        (string, optional) If source and destination currency are reserves, via is a common fractional to convert through\n"
            "      \"address\":\"dest\"     (string, required) The address and optionally chain/system after the \"@\" as a system specific destination\n"
            "      \"refundto\":\"dest\"    (string, optional) For pre-conversions, this is where refunds will go, defaults to fromaddress\n"
            "      \"memo\":memo            (string, optional) If destination is a zaddr (not supported on testnet), a string message (not hexadecimal) to include.\n"
            "      \"preconvert\":\"false\", (bool,  optional) convert to currency at market price (default=false), only works if transaction is mined before start of currency\n"
            "      \"burn\":\"false\",      (bool,  optional) destroy the currency and subtract it from the supply. Currency must be a token.\n"
            "      \"mintnew\":\"false\",   (bool,  optional) if the transaction is sent from the currency ID of a centralized currency, this creates new currency to send\n"
            "    }, ... ]\n"
            "3. \"minconf\"                 (numeric, optional, default=1) only use funds confirmed at least this many times.\n"
            "4. \"feeamount\"               (number, optional) specific fee amount requested instead of default miner's fee\n"

            "\nResult:\n"
            "   \"txid\" : \"transactionid\" (string) The transaction id if (returntx) is false\n"
            "   \"hextx\" : \"hex\"         (string) The hexadecimal, serialized transaction if (returntx) is true\n"

            "\nExamples:\n"
            + HelpExampleCli("sendcurrency", "\"*\" '[{\"currency\":\"btc\",\"address\":\"RRehdmUV7oEAqoZnzEGBH34XysnWaBatct\" ,\"amount\":500.0},...]'")
            + HelpExampleRpc("sendcurrency", "\"bob@\", [{\"currency\":\"btc\", \"address\":\"alice@quad\", \"amount\":500.0},...]")
        );
    }

    std::string sourceAddress = uni_get_str(params[0]);
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = sourceAddress == "*";
    bool wildCardRAddress = sourceAddress == "R*";
    bool wildCardiAddress = sourceAddress == "i*";
    bool wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;

    bool isVerusActive = IsVerusActive();
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();
    uint160 thisChainID = thisChain.GetID();
    bool toFractional = false;
    bool fromFractional = false;

    std::vector<CRecipient> outputs;
    std::set<libzcash::PaymentAddress> zaddrDestSet;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);

    libzcash::PaymentAddress zaddress;
    bool hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddress);
    // if we have a z-address as a source, re-encode it to a string, which is used
    // by the async operation, to ensure that we don't need to lookup IDs in that operation
    if (hasZSource)
    {
        zaddrDestSet.insert(zaddress);
        sourceAddress = EncodePaymentAddress(zaddress);
    }

    if (!(hasZSource ||
          wildCardAddress ||
          (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
    }

    if (!params[1].isArray() || !params[1].size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. Second parameter must be array of outputs. See help.");
    }

    int minConfs = 0;
    if (params.size() > 2)
    {
        minConfs = uni_get_int(params[2]);
    }

    uint32_t height = chainActive.Height();

    if (sourceDest.which() == COptCCParams::ADDRTYPE_ID && !GetDestinationID(sourceDest).IsNull())
    {
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        if (!pwalletMain->GetIdentity(GetDestinationID(sourceDest), keyAndIdentity) ||
            !keyAndIdentity.second.IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity or identity not in wallet");
        }
        if (keyAndIdentity.second.IsLocked(height + 1))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot send currency from a locked identity");
        }
    }

    CAmount feeAmount = DEFAULT_TRANSACTION_FEE;
    if (params.size() > 3)
    {
        feeAmount = AmountFromValue(params[3]);
    }

    const UniValue &uniOutputs = params[1];

    TransactionBuilder tb(Params().GetConsensus(), height + 1, pwalletMain);
    std::vector<SendManyRecipient> tOutputs;
    std::vector<SendManyRecipient> zOutputs;

    try
    {
        for (int i = 0; i < uniOutputs.size(); i++)
        {        
            auto currencyStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "currency")));
            CAmount sourceAmount = AmountFromValue(find_value(uniOutputs[i], "amount"));
            auto convertToStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "convertto")));
            auto exportToStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "exportto")));
            auto feeCurrencyStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "feecurrency")));
            auto viaStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "via")));
            auto destStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "address")));
            auto exportId = uni_get_bool(find_value(uniOutputs[i], "exportid"));
            auto exportCurrency = uni_get_bool(find_value(uniOutputs[i], "exportcurrency"));
            auto refundToStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "refundto")));
            auto memoStr = uni_get_str(find_value(uniOutputs[i], "memo"));
            bool preConvert = uni_get_bool(find_value(uniOutputs[i], "preconvert"));
            bool burnCurrency = uni_get_bool(find_value(uniOutputs[i], "burn")) || uni_get_bool(find_value(uniOutputs[i], "burnweight"));
            bool burnWeight = uni_get_bool(find_value(uniOutputs[i], "burnweight"));
            bool mintNew = uni_get_bool(find_value(uniOutputs[i], "mintnew"));

            if (currencyStr.size() ||
                convertToStr.size() ||
                exportToStr.size() ||
                feeCurrencyStr.size() ||
                viaStr.size() ||
                refundToStr.size() ||
                preConvert ||
                mintNew ||
                exportId ||
                exportCurrency ||
                burnCurrency)
            {
                CheckPBaaSAPIsValid();
            }

            CCurrencyDefinition sourceCurrencyDef;
            uint160 sourceCurrencyID;
            if (currencyStr != "")
            {
                sourceCurrencyID = ValidateCurrencyName(currencyStr, true, &sourceCurrencyDef);
                if (sourceCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
                }
            }
            else
            {
                sourceCurrencyDef = thisChain;
                sourceCurrencyID = sourceCurrencyDef.GetID();
                currencyStr = thisChain.name;
            }

            if (hasZSource && sourceCurrencyID != ASSETCHAINS_CHAINID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only native " + thisChain.name + " currency can be sourced from a z-address.");
            }

            libzcash::PaymentAddress zaddressDest;
            bool hasZDest = pwalletMain->GetAndValidateSaplingZAddress(destStr, zaddressDest);
            if (hasZDest &&
                (convertToStr.size() ||
                 viaStr.size() ||
                 exportToStr.size() ||
                 burnCurrency ||
                 mintNew ||
                 preConvert ||
                 sourceCurrencyID != ASSETCHAINS_CHAINID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert, preconvert, mint, cross-chain send, burn or send non-native currency when sending to a z-address.");
            }

            // re-encode destination, in case it is specified as the private address of an ID
            if (hasZDest)
            {
                // no duplicate z-address destinations
                if (zaddrDestSet.count(zaddressDest))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot duplicate private address source or destination");
                }
                zaddrDestSet.insert(zaddressDest);
                destStr = EncodePaymentAddress(zaddressDest);
            }

            CCurrencyDefinition convertToCurrencyDef;
            uint160 convertToCurrencyID;
            if (convertToStr != "")
            {
                convertToCurrencyID = ValidateCurrencyName(convertToStr, true, &convertToCurrencyDef);
                if (convertToCurrencyID == sourceCurrencyID)
                {
                    convertToCurrencyID.SetNull();
                    convertToCurrencyDef = CCurrencyDefinition();
                }
                else
                {
                    if (convertToCurrencyID.IsNull())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "If currency conversion is requested, destination currency must be valid.");
                    }
                    if (burnCurrency)
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert and burn currency in a single operation. First convert, then burn.");
                    }
                }
            }

            CCurrencyDefinition secondCurrencyDef;
            uint160 secondCurrencyID;
            bool isVia = false;
            bool isConversion = false;

            if (viaStr != "")
            {
                secondCurrencyID = ValidateCurrencyName(viaStr, true, &secondCurrencyDef);
                std::map<uint160, int32_t> viaIdxMap = secondCurrencyDef.GetCurrenciesMap();
                if (secondCurrencyID.IsNull() ||
                    sourceCurrencyID.IsNull() ||
                    !secondCurrencyDef.IsFractional() ||
                    (!convertToCurrencyID.IsNull() &&
                     !burnCurrency &&
                     (secondCurrencyID == sourceCurrencyID || 
                      secondCurrencyID == convertToCurrencyID ||
                      sourceCurrencyID == convertToCurrencyID ||
                      !viaIdxMap.count(convertToCurrencyID))) ||
                    !(viaIdxMap.count(sourceCurrencyID) ||
                      sourceCurrencyID == secondCurrencyID ||
                      convertToStr.empty()))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "To specify a fractional currency converter, \"currency\" and \"convertto\" must both be reserves of \"via\"");
                }
                if (mintNew || preConvert)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot combine reserve to reserve conversion with minting or preconversion");
                }
                if (convertToCurrencyID.IsNull())
                {
                    convertToCurrencyDef = secondCurrencyDef;
                    convertToCurrencyID = convertToCurrencyDef.GetID();
                    secondCurrencyDef = CCurrencyDefinition();
                    secondCurrencyID = uint160();
                }
                else
                {
                    CCurrencyDefinition tempDef = convertToCurrencyDef;
                    convertToCurrencyDef = secondCurrencyDef;
                    secondCurrencyDef = tempDef;
                    convertToCurrencyID = convertToCurrencyDef.GetID();
                    secondCurrencyID = secondCurrencyDef.GetID();
                    isConversion = true;
                }
                isVia = true;
            }
            else if (!convertToCurrencyID.IsNull())
            {
                isConversion = true;
            }

            // send a reserve transfer preconvert
            uint32_t flags = CReserveTransfer::VALID;
            if (burnCurrency)
            {
                if (convertToCurrencyDef.IsValid() && convertToCurrencyDef.IsFractional())
                {
                    if (mintNew || isConversion ||
                        !(convertToCurrencyID == sourceCurrencyID || convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID)))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot mint and burn currency in a single operation.");
                    }
                    if (convertToCurrencyID != sourceCurrencyID)
                    {
                        if (burnWeight)
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Change weight while burning reserves not implemented.");
                        }
                    }
                    flags |= burnWeight ? CReserveTransfer::BURN_CHANGE_WEIGHT : CReserveTransfer::BURN_CHANGE_PRICE;
                }
                else
                {
                    if (mintNew || isConversion ||
                        !convertToCurrencyID.IsNull() ||
                        !(sourceCurrencyDef.IsFractional() || sourceCurrencyDef.IsToken()))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert and burn currency in a single operation. First convert, then burn.");
                    }
                    flags |= burnWeight ? CReserveTransfer::BURN_CHANGE_WEIGHT : CReserveTransfer::BURN_CHANGE_PRICE;
                    convertToCurrencyID = sourceCurrencyID;
                    convertToCurrencyDef = sourceCurrencyDef;
                }
            }

            std::string systemDestStr;
            uint160 destSystemID = thisChainID;
            CCurrencyDefinition destSystemDef;
            std::vector<std::string> subNames;

            CCurrencyDefinition exportToCurrencyDef;
            uint160 exportToCurrencyID;

            toFractional = isConversion &&
                           convertToCurrencyDef.IsValid() &&
                           convertToCurrencyDef.IsFractional() &&
                           convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID);
            fromFractional = isConversion &&
                             !toFractional &&
                             sourceCurrencyDef.IsFractional() && !convertToCurrencyID.IsNull() && sourceCurrencyDef.GetCurrenciesMap().count(convertToCurrencyID);
            if (toFractional || preConvert)
            {
                destSystemID = convertToCurrencyDef.systemID;
            }
            else if (fromFractional)
            {
                destSystemID = sourceCurrencyDef.systemID;
            }
            else if (!hasZDest)
            {
                // check for explicit system name specified
                subNames = ParseSubNames(destStr, systemDestStr, true);
                if (systemDestStr != "")
                {
                    destSystemID = ValidateCurrencyName(systemDestStr, true, &destSystemDef);
                    if (destSystemID.IsNull() || destSystemDef.IsToken() || destSystemDef.systemID != destSystemDef.GetID())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "If destination system is specified, destination system or chain must be registered.");
                    }
                    if (exportToStr == "")
                    {
                        exportToStr = systemDestStr;
                        exportToCurrencyID = destSystemID;
                        exportToCurrencyDef = destSystemDef;
                    }
                }
            }
            else
            {
                // things you can't do with a z-destination yet
                if (exportToStr.size() ||
                    isConversion ||
                    burnCurrency ||
                    preConvert ||
                    mintNew)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid operations for z-address destination");
                }
            }

            if (!destSystemDef.IsValid() && !destSystemID.IsNull())
            {
                destSystemDef = ConnectedChains.GetCachedCurrency(destSystemID);
            }

            // see if we should send this currency off-chain. if our target is a fractional currency and can convert but lives on another system, 
            // we will not implicitly send it off chain for conversion, even if via is specified. "exportto" requests an explicit system
            // export/import before the operation.
            CCurrencyDefinition exportSystemDef;
            if (exportToStr != "")
            {
                uint160 explicitExportID = ValidateCurrencyName(exportToStr, true, &exportToCurrencyDef);
                if (!exportToCurrencyDef.IsValid() || (!exportToCurrencyID.IsNull() && exportToCurrencyID != explicitExportID))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate or invalid export system/currency destinations that do not match");
                }
                // if we have a converter currency on the same chain as the explicit export, the converter is
                // our actual export currency
                if (convertToCurrencyDef.systemID == exportToCurrencyDef.SystemOrGatewayID())
                {
                    exportToCurrencyDef = convertToCurrencyDef;
                    exportToCurrencyID = convertToCurrencyID;
                }
                else
                {
                    exportToCurrencyID = explicitExportID;
                }

                if (exportToCurrencyDef.SystemOrGatewayID() == ASSETCHAINS_CHAINID)
                {
                    exportToStr = "";
                    exportToCurrencyID.SetNull();
                }
            }

            if (!exportToCurrencyID.IsNull())
            {
                if (exportToCurrencyID == exportToCurrencyDef.systemID || 
                    (exportToCurrencyDef.IsGateway() && exportToCurrencyID == exportToCurrencyDef.GetID()))
                {
                    exportSystemDef = exportToCurrencyDef;
                }
                else
                {
                    exportSystemDef = ConnectedChains.GetCachedCurrency(exportToCurrencyDef.systemID);
                    if (!exportSystemDef.IsValid() ||
                        (exportSystemDef.systemID != exportSystemDef.GetID() && 
                         !(exportSystemDef.IsGateway() && exportSystemDef.systemID == thisChainID && exportSystemDef.gatewayID == exportSystemDef.GetID())))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid export system definition");
                    }
                }
            }

            // if we have no explicit destination system and non-null export, make export
            // our destination system
            if (destSystemID == ASSETCHAINS_CHAINID &&
                !(convertToCurrencyDef.IsValid() && convertToCurrencyDef.systemID == ASSETCHAINS_CHAINID) &&
                !exportToCurrencyID.IsNull())
            {
                destSystemID = exportSystemDef.GetID();
                destSystemDef = exportSystemDef;
            }

            // this only applies to the first step, if
            // first step is on-chain convert, then second is off chain, this will be false
            bool sendOffChain = (destSystemID != ASSETCHAINS_CHAINID) || (!exportToCurrencyID.IsNull() && exportToCurrencyID != ASSETCHAINS_CHAINID);
            bool convertBeforeOffChain = sendOffChain && (destSystemID == ASSETCHAINS_CHAINID);

            uint160 feeCurrencyID;
            CCurrencyDefinition feeCurrencyDef;
            if (feeCurrencyStr != "")
            {
                feeCurrencyID = ValidateCurrencyName(feeCurrencyStr, true, &feeCurrencyDef);
                if (!feeCurrencyID.IsNull())
                {
                    CCurrencyValueMap validFeeCurrencies;
                    if (!destSystemDef.launchSystemID.IsNull() && destSystemDef.IsMultiCurrency())
                    {
                        validFeeCurrencies.valueMap[destSystemDef.launchSystemID] = 1;
                    }

                    CCurrencyDefinition tmpConverterDef;
                    if (!preConvert)
                    {
                        validFeeCurrencies.valueMap[destSystemID] = 1;
                        if (feeCurrencyID != destSystemID && convertToCurrencyID.IsNull())
                        {
                            tmpConverterDef = 
                                exportToCurrencyDef.IsFractional() ?
                                exportToCurrencyDef :
                                (exportToCurrencyDef.GatewayConverterID().IsNull() &&
                                exportToCurrencyID == thisChain.launchSystemID && !thisChain.GatewayConverterID().IsNull() ?
                                    ConnectedChains.GetCachedCurrency(thisChain.GatewayConverterID()) :
                                    CCurrencyDefinition());
                        }
                        else
                        {
                            tmpConverterDef = convertToCurrencyDef;
                        }
                    }

                    if (tmpConverterDef.IsValid() &&
                        (tmpConverterDef.systemID == ASSETCHAINS_CHAINID || tmpConverterDef.systemID == destSystemID))
                    {
                        validFeeCurrencies.valueMap[tmpConverterDef.GetID()] = 1;
                        for (auto &oneCur : tmpConverterDef.currencies)
                        {
                            validFeeCurrencies.valueMap[oneCur] = 1;
                        }
                    }
                    if (!validFeeCurrencies.valueMap.count(feeCurrencyID))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency specified");
                    }
                }
                else
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency specified");
                }
            }
            else
            {
                feeCurrencyDef = ConnectedChains.ThisChain();
                feeCurrencyID = thisChainID;
            }

            // if we are already converting or processing through some currency, that can only be done on its native system
            // and may imply an export off-chain. before creating an off-chain export, we need an explicit "exportto" command that matches. 
            // we may also have an "exportafter" command, which enables funding a second leg to up to one more system

            // ensure that any initial export is explicit
            if (sendOffChain && !exportToCurrencyID.IsNull() &&
                !exportToCurrencyDef.IsGateway() &&
                !(exportToCurrencyDef.systemID == destSystemID || (convertBeforeOffChain && destSystemID == ASSETCHAINS_CHAINID)))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Conflicting target system for send -- \"exportto\" must be consistent with any other cross-chain currency targets");
            }
            else if (!exportToCurrencyID.IsNull() &&
                     exportToCurrencyID != thisChainID &&
                     !preConvert)
            {
                if (mintNew)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cross-system mint operations not supported");
                }

                if (isConversion &&
                    !((convertToCurrencyDef.systemID == ASSETCHAINS_CHAINID &&
                       convertToCurrencyID != exportToCurrencyID &&
                       (exportToCurrencyDef.IsGateway() || exportToCurrencyDef.IsPBaaSChain()) &&
                       convertToCurrencyDef.IsFractional() &&
                       convertToCurrencyDef.GetCurrenciesMap().count(exportToCurrencyDef.systemID)) ||
                      (convertToCurrencyID == exportToCurrencyID &&
                       exportToCurrencyDef.systemID == destSystemID)))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid export syntax. Fractional converter must be from current chain before \"exportto\" a system currency or if on the alternate system, then it must be the same destination as \"exportto\".");
                }

                // if fee currency is the export system destination
                // don't see if we should route through a converter
                if (feeCurrencyID == destSystemID)
                {
                    // if we also have an explicit conversion, we must verify that we can either do that on this chain
                    // first and then pass through or pass to the converter currency on the other system
                    if (!convertToCurrencyID.IsNull())
                    {
                        if (convertToCurrencyDef.systemID != destSystemID &&
                            (convertToCurrencyDef.systemID != ASSETCHAINS_CHAINID ||
                             !convertToCurrencyDef.IsFractional()))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency " + 
                                                                    EncodeDestination(CIdentityID(convertToCurrencyID)) +
                                                                    " is not capable of converting " +
                                                                    EncodeDestination(CIdentityID(feeCurrencyID)) +
                                                                    " to " +
                                                                    EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
                        }
                    }
                }
                else if (convertToCurrencyID.IsNull())
                {
                    convertToCurrencyID = 
                        exportToCurrencyDef.IsFractional() ?
                        exportToCurrencyID :
                        (exportToCurrencyDef.GatewayConverterID().IsNull() &&
                         exportToCurrencyID == thisChain.launchSystemID && !thisChain.GatewayConverterID().IsNull() ?
                            thisChain.GatewayConverterID() :
                            (exportToCurrencyDef.GatewayConverterID().IsNull() ? uint160() : exportToCurrencyDef.GatewayConverterID()));
                    if (convertToCurrencyID.IsNull() && (convertToCurrencyID = ConnectedChains.ThisChain().GatewayConverterID()).IsNull())
                    {
                        convertToCurrencyID = exportToCurrencyID;
                        convertToCurrencyDef = exportToCurrencyDef;
                    }
                    else
                    {
                        // get gateway converter and set as fee converter/exportto currency
                        convertToCurrencyDef = ConnectedChains.GetCachedCurrency(convertToCurrencyID);
                    }
                    if (!convertToCurrencyDef.IsValid())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "No available fee converter.");
                    }
                    if (convertToCurrencyID != exportToCurrencyID && convertToCurrencyDef.systemID == exportToCurrencyID)
                    {
                        exportToCurrencyID = convertToCurrencyID;
                        exportToCurrencyDef = convertToCurrencyDef;
                    }
                    bool toCurrencyIsFractional = convertToCurrencyDef.IsFractional();
                    if (!convertToCurrencyDef.IsValid() ||
                        (!((convertToCurrencyDef.IsPBaaSChain() && (feeCurrencyID == destSystemDef.launchSystemID || 
                            feeCurrencyID == destSystemID))) &&
                         !(toCurrencyIsFractional && convertToCurrencyDef.GetCurrenciesMap().count(feeCurrencyID) || 
                            convertToCurrencyDef.GetID() == feeCurrencyID)))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency for system destination.");
                    }
                    // if we are inserting a converter on the current chain, before the destination, adjust
                    if (convertToCurrencyDef.systemID == ASSETCHAINS_CHAINID)
                    {
                        convertBeforeOffChain = true;
                        destSystemID = thisChainID;
                        destSystemDef = thisChain;
                    }
                }
            }

            if (mintNew && 
                (!(sourceCurrencyDef.IsToken() &&
                   GetDestinationID(sourceDest) == sourceCurrencyID &&
                   sourceCurrencyDef.proofProtocol == sourceCurrencyDef.PROOF_CHAINID &&
                   destSystemID == thisChainID &&
                   !preConvert &&
                   convertToCurrencyID.IsNull())))
            {
                // attempt to mint currency that isn't under the source ID's control
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only the ID of a mintable currency can mint such a currency. Minting cannot be combined with conversion.");
            }

            if (hasZDest)
            {
                // if memo starts with "#", convert it from a string to a hex value
                if (memoStr.size() > 1 && memoStr[0] == '#')
                {
                    // make a hex string out of the chars without the "#"
                    memoStr = HexBytes((const unsigned char *)&(memoStr[1]), memoStr.size());
                }

                if (memoStr.size() && !IsHex(memoStr)) 
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected memo data in hexadecimal format or as a non-zero length string, starting with \"#\".");
                }

                if (memoStr.length() > ZC_MEMO_SIZE*2) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,  strprintf("Invalid parameter, size of memo is larger than maximum allowed %d", ZC_MEMO_SIZE ));
                }

                zOutputs.push_back(SendManyRecipient(destStr, sourceAmount, memoStr, CScript()));
            }
            else
            {
                if (memoStr.size() > 0)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo is only an option for z-address destinations.");
                }

                CTxDestination destination = ValidateDestination(destStr);

                CTxDestination refundDestination = refundToStr.empty() ? CTxDestination() : DecodeDestination(refundToStr);

                if (refundDestination.which() == COptCCParams::ADDRTYPE_ID &&
                    GetDestinationID(refundDestination) != GetDestinationID(destination))
                {
                    if (!CIdentity::LookupIdentity(GetDestinationID(refundDestination)).IsValid())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "When refunding to an ID, the ID must be valid.");
                    }
                }

                CTransferDestination dest;
                if (destination.which() == COptCCParams::ADDRTYPE_INVALID)
                {
                    if (destSystemDef.IsGateway())
                    {
                        // if we expect an ETH address, only accept that
                        if (exportSystemDef.proofProtocol == exportSystemDef.PROOF_ETHNOTARIZATION)
                        {
                            uint160 ethDestination = dest.DecodeEthDestination(destStr);
                            if (ethDestination.IsNull())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid Ethereum destination (null)");
                            }
                            dest = CTransferDestination(CTransferDestination::DEST_ETH, ::AsVector(ethDestination));
                            if (refundDestination.which() != COptCCParams::ADDRTYPE_INVALID)
                            {
                                dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                            }
                        }
                        else
                        {
                            std::vector<unsigned char> rawDestBytes;
                            for (int i = 0; i < subNames.size(); i++)
                            {
                                if (i)
                                {
                                    rawDestBytes.push_back('.');
                                }
                                rawDestBytes.insert(rawDestBytes.end(), subNames[i].begin(), subNames[i].end());
                            }
                            if (!rawDestBytes.size())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Specified destination must be valid");
                            }
                            dest = CTransferDestination(CTransferDestination::FLAG_DEST_GATEWAY + CTransferDestination::DEST_RAW, rawDestBytes, destSystemID);
                        }
                    }
                    else if (exportSystemDef.IsValid() && exportSystemDef.proofProtocol == exportSystemDef.PROOF_ETHNOTARIZATION)
                    {
                        uint160 ethDestination = dest.DecodeEthDestination(destStr);
                        if (ethDestination.IsNull())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid Ethereum destination (null)");
                        }
                        dest = CTransferDestination(CTransferDestination::DEST_ETH, ::AsVector(ethDestination));
                        dest.type |= dest.FLAG_DEST_GATEWAY;
                        dest.gatewayID = exportSystemDef.GetID();

                        if (refundDestination.which() != COptCCParams::ADDRTYPE_INVALID)
                        {
                            dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                        }
                    }
                    else
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Specified destination must be valid.");
                    }
                }

                bool refundValid = refundDestination.which() != COptCCParams::ADDRTYPE_INVALID;
                if (!refundValid)
                {
                    refundDestination = destination;
                }

                // make one output
                CRecipient oneOutput;

                if (preConvert)
                {
                    flags |= CReserveTransfer::PRECONVERT;
                }
                if (isConversion && !burnCurrency && !convertToCurrencyID.IsNull())
                {
                    flags |= CReserveTransfer::CONVERT;
                }
                else if (mintNew)
                {
                    flags |= CReserveTransfer::MINT_CURRENCY;
                    convertToCurrencyID = sourceCurrencyID;
                    convertToCurrencyDef = sourceCurrencyDef;
                }
                if (isVia && isConversion)
                {
                    flags |= CReserveTransfer::RESERVE_TO_RESERVE;
                }

                // are we a system/chain transfer with or without conversion?
                if (destSystemID != thisChainID || (!exportToCurrencyID.IsNull() && exportToCurrencyID != thisChainID))
                {
                    // possible cases:
                    // 1. sending currency to another chain, paying with native currencies and no converter
                    // 2. sending currency with or without conversion, paying with fees converted via converter on source or dest system
                    // 3. preconvert on launch of new system
                    //
                    // converting with fees via a converter on the source chain first converts fees and optionally more,
                    // then uses case 1 above

                    if (exportCurrency)
                    {
                        // validate no conflicts with currency export and create a destination of the currency
                        if (mintNew ||
                            isConversion ||
                            preConvert ||
                            exportId ||
                            sourceCurrencyID == ASSETCHAINS_CHAINID)
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot mint or convert currency when exporting a currency definition cross-chain");
                        }
                        // confirm that we can export the intended currency
                        if (IsValidExportCurrency(exportToCurrencyDef, sourceCurrencyID, height + 1))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency ( " + ConnectedChains.GetFriendlyCurrencyName(sourceCurrencyID) + ") already exported to destination system");
                        }
                        if (destSystemID != ASSETCHAINS_CHAINID ? !destSystemDef.IsMultiCurrency() : !exportToCurrencyDef.IsMultiCurrency())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export currency to single currency system");
                        }
                        dest = CTransferDestination(CTransferDestination::DEST_REGISTERCURRENCY, ::AsVector(sourceCurrencyDef));
                    }

                    // if we should export the ID, make a full ID destination
                    if (!dest.IsValid())
                    {
                        dest = DestinationToTransferDestination(destination);                    
                    }
                    if (dest.TypeNoFlags() == dest.DEST_ID)
                    {
                        if (exportId)
                        {
                            // get and export the ID
                            CIdentity destIdentity = CIdentity::LookupIdentity(GetDestinationID(destination));
                            if (!destIdentity.IsValid())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot find identity to export (" + EncodeDestination(destination) + ")");
                            }
                            dest = CTransferDestination(CTransferDestination::DEST_FULLID, ::AsVector(destIdentity));
                        }
                    }

                    // check for potentially unknown currencies being sent across
                    // for now, we can only send currencies that were involved in the launch
                    std::set<uint160> validCurrencies;
                    std::set<uint160> validIDs;
                    CChainNotarizationData cnd;
                    CCurrencyDefinition nonVerusChainDef = IsVerusActive() ?
                        (destSystemID != thisChainID ? destSystemDef : exportToCurrencyDef) :
                        (ConnectedChains.ThisChain());
                    uint160 offChainID = IsVerusActive() ? nonVerusChainDef.GetID() : VERUS_CHAINID;
                    const CCurrencyDefinition &offChainDef = (destSystemID != thisChainID ? destSystemDef : exportToCurrencyDef);

                    if (!offChainDef.IsValidTransferDestinationType(dest.TypeNoFlags()))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Invalid destination address for export system " + offChainDef.name + " (" + dest.ToUniValue().write() + ")");
                    }

                    if (!GetNotarizationData(offChainID, cnd) || !cnd.IsConfirmed())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Cannot retrieve notarization data for export system " + nonVerusChainDef.name + " (" + EncodeDestination(CIdentityID(offChainID)) + ")");
                    }

                    if (!preConvert && cnd.vtx[cnd.lastConfirmed].second.IsPreLaunch() && !cnd.vtx[cnd.lastConfirmed].second.IsLaunchCleared())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Cannot send non-preconvert transfers to import system " + nonVerusChainDef.name + " (" + EncodeDestination(CIdentityID(offChainID)) + ") until after launch");
                    }

                    // TODO: HARDENING - ensure this gets into enforcement/protocol - check the target currency, if not system, for prelaunch & launch confirmed

                    if (cnd.vtx[cnd.lastConfirmed].second.IsRefunding())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Cannot send to import system " + nonVerusChainDef.name + " (" + EncodeDestination(CIdentityID(offChainID)) + ") that is in a refunding state");
                    }

                    validCurrencies = ValidExportCurrencies(offChainDef, height + 1);

                    if (exportCurrency)
                    {
                        CCurrencyValueMap canExport, cannotExport;

                        if (ConnectedChains.CurrencyExportStatus(
                            CCurrencyValueMap(std::vector<uint160>({sourceCurrencyID}), std::vector<int64_t>({1})),
                            ASSETCHAINS_CHAINID,
                            offChainID,
                            canExport,
                            cannotExport) &&
                            canExport.valueMap.size() &&
                            !cannotExport.valueMap.size())
                        {
                            if (validCurrencies.count(sourceCurrencyID))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unnecessary to export currency to system. Currency is already exported to destination network.");
                            }
                        }
                        else
                        {
                            if (!CCurrencyDefinition::IsValidDefinitionImport(thisChain, offChainDef, sourceCurrencyDef.parent, height))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export currency to import system");
                            }
                        }
                    }
                    else if (!validCurrencies.count(sourceCurrencyID))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency " + sourceCurrencyDef.name + " (" + EncodeDestination(CIdentityID(sourceCurrencyID)) + ") cannot be sent to specified system");
                    }

                    if (!convertToCurrencyID.IsNull() && !validCurrencies.count(convertToCurrencyID) && convertToCurrencyDef.systemID != ASSETCHAINS_CHAINID)
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency " + sourceCurrencyDef.name + " (" + EncodeDestination(CIdentityID(sourceCurrencyID)) + ") cannot be currency destination on specified system");
                    }

                    std::set<uint160> validFeeCurrencies;
                    validFeeCurrencies.insert(offChainID);
                    if (IsVerusActive() && offChainDef.IsPBaaSChain() && offChainDef.launchSystemID == ASSETCHAINS_CHAINID)
                    {
                        validFeeCurrencies.insert(ASSETCHAINS_CHAINID);
                    }

                    // calculate the price of the fee currency in the source and destination currencies
                    int64_t reversePriceInFeeCur = SATOSHIDEN;

                    CCcontract_info CC;
                    CCcontract_info *cp;
                    cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                    CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                    if (preConvert)
                    {
                        if (convertToCurrencyID.IsNull())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot preconvert to unspecified or invalid currency.");
                        }
                        auto validConversionCurrencies = convertToCurrencyDef.GetCurrenciesMap();
                        if (!validConversionCurrencies.count(sourceCurrencyID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ".");
                        }
                        if (convertToCurrencyDef.launchSystemID == ASSETCHAINS_CHAINID &&
                            convertToCurrencyDef.startBlock <= (height + 1))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too late to convert " + sourceCurrencyDef.name + " to " + convertToStr + ", as pre-launch is over.");
                        }

                        CReserveTransfer rt = CReserveTransfer(flags, 
                                                               sourceCurrencyID, 
                                                               sourceAmount,
                                                               ASSETCHAINS_CHAINID,
                                                               0,
                                                               convertToCurrencyID,
                                                               dest);
                        rt.nFees = rt.CalculateTransferFee();

                        std::vector<CTxDestination> dests = refundValid ? std::vector<CTxDestination>({pk.GetID(), refundDestination}) :
                                                                          std::vector<CTxDestination>({pk.GetID()});

                        oneOutput.nAmount = sourceCurrencyID == thisChainID ? sourceAmount + rt.CalculateTransferFee() : rt.CalculateTransferFee();
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt));
                    }
                    // through a converter before or after conversion for actual conversion and/or fee conversion
                    else if (isConversion || (destSystemID != exportToCurrencyID && !convertToCurrencyID.IsNull()))
                    {
                        // if we have pricing for converting fees, we add all convertible currencies to valid fee currencies
                        CPBaaSNotarization lastConfirmedNotarization = cnd.vtx[cnd.lastConfirmed].second;
                        CCurrencyValueMap feeConversionPrices;
                        CCoinbaseCurrencyState feePriceState;

                        bool sameChainConversion = convertToCurrencyDef.systemID == ASSETCHAINS_CHAINID;

                        uint160 converterID = convertToCurrencyID;
                        CCurrencyDefinition converterDef = convertToCurrencyDef;

                        if (!isVia && sourceCurrencyDef.IsFractional() && sourceCurrencyDef.GetCurrenciesMap().count(convertToCurrencyID))
                        {
                            flags |= CReserveTransfer::IMPORT_TO_SOURCE;
                            converterID = sourceCurrencyID;
                            converterDef = sourceCurrencyDef;
                        }

                        if (sameChainConversion)
                        {
                            // get the latest notarization for the converter on this chain
                            CChainNotarizationData localCND;

                            if (!GetNotarizationData(converterID, localCND) || !localCND.IsConfirmed())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid converter or converter not ready " + EncodeDestination(CIdentityID(converterID)));
                            }
                            
                            feePriceState = localCND.vtx[localCND.lastConfirmed].second.currencyState;
                        }
                        else if (lastConfirmedNotarization.currencyStates.count(converterID))
                        {
                            feePriceState = lastConfirmedNotarization.currencyStates[converterID];
                            if (!feePriceState.IsValid())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency state for currency " + EncodeDestination(CIdentityID(converterID)));
                            }
                        }

                        if (feePriceState.IsValid())
                        {
                            if (sameChainConversion)
                            {
                                feeConversionPrices = feePriceState.TargetConversionPricesReverse(offChainID, true);

                                if (!feeConversionPrices.valueMap.count(offChainID))
                                {
                                    feeConversionPrices.valueMap[offChainID] = SATOSHIDEN;
                                }
                            }
                            else
                            {
                                // get all currencies that may be converted through the converter to valid fees
                                validFeeCurrencies = BaseBridgeCurrencies(offChainDef, height + 1, true);
                                feeConversionPrices = feePriceState.TargetConversionPricesReverse(offChainID, true);

                                // TODO: HARDENING - confirm rules such that no currency could slip through here and have a 1:1
                                // conversion that could be exploited in some way
                                for (auto &oneCur : validFeeCurrencies)
                                {
                                    // if we have a valid currency with no conversion, consider the conversion to be 1
                                    if (!feeConversionPrices.valueMap.count(oneCur))
                                    {
                                        feeConversionPrices.valueMap[oneCur] = SATOSHIDEN;
                                    }
                                }
                            }
                        }        
                        else
                        {
                            for (auto &oneCur : validFeeCurrencies)
                            {
                                feeConversionPrices.valueMap[oneCur] = SATOSHIDEN;
                            }
                        }                

                        if (!feeConversionPrices.valueMap.count(feeCurrencyID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency for cross-chain transaction 1 " + ConnectedChains.GetFriendlyCurrencyName(feeCurrencyID));
                        }

                        // determine required fees
                        CAmount requiredFees;
                        if (feeConversionPrices.valueMap.count(feeCurrencyID))
                        {
                            reversePriceInFeeCur = feeConversionPrices.valueMap[feeCurrencyID];
                        }
                        if (exportCurrency)
                        {
                            // get source price for export and dest price for import to ensure we have enough fee currency
                            requiredFees = 
                                CCurrencyState::ReserveToNativeRaw(offChainDef.GetCurrencyImportFee(sourceCurrencyDef.ChainOptions() & sourceCurrencyDef.OPTION_NFT_TOKEN),
                                                                   reversePriceInFeeCur);
                            flags |= CReserveTransfer::CURRENCY_EXPORT;
                        }
                        else if (exportId)
                        {
                            requiredFees = CCurrencyState::ReserveToNativeRaw(offChainDef.IDImportFee(), reversePriceInFeeCur);
                        }
                        else
                        {
                            requiredFees = CCurrencyState::ReserveToNativeRaw(offChainDef.GetTransactionImportFee() << 1, reversePriceInFeeCur);
                        }

                        if (sameChainConversion)
                        {
                            // if same chain first, we need to ensure that we have enough fees on the other side or it will get
                            // refunded and fall short. add 20% buffer.
                            requiredFees += CCurrencyDefinition::CalculateRatioOfValue(requiredFees, SATOSHIDEN / 5);

                            // if we're converting and then sending, we don't need an initial fee, so all
                            // fees go into the final destination

                            // if we are sending a full ID, revert back to just ID and set the full ID bit to enable
                            // sending the full ID in the next leg without overhead in the first
                            if (dest.TypeNoFlags() == dest.DEST_FULLID)
                            {
                                dest = CTransferDestination(CTransferDestination::DEST_ID, ::AsVector(CIdentityID(GetDestinationID(destination))));
                                flags |= CReserveTransfer::IDENTITY_EXPORT;
                            }
                            else if (dest.TypeNoFlags() != dest.DEST_ID)
                            {
                                exportId = false;
                            }

                            if (dest.TypeNoFlags() == dest.DEST_REGISTERCURRENCY)
                            {
                                dest = destination.which() == COptCCParams::ADDRTYPE_INVALID ?
                                    DestinationToTransferDestination(CIdentityID(CCurrencyDefinition(dest.destination).GetID())) :
                                    DestinationToTransferDestination(destination);                    
                            }

                            dest.type |= dest.FLAG_DEST_GATEWAY;
                            dest.gatewayID = exportSystemDef.GetID();
                            CChainNotarizationData cnd;
                            if (!GetNotarizationData(converterID, cnd) ||
                                !cnd.IsConfirmed())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot get notarization/pricing information for " + exportToCurrencyDef.name);
                            }
                            auto currencyMap = cnd.vtx[cnd.lastConfirmed].second.currencyState.GetReserveMap();
                            if (!currencyMap.count(destSystemID) || !currencyMap.count(ASSETCHAINS_CHAINID) || (!currencyMap.count(feeCurrencyID) && feeCurrencyID != convertToCurrencyID))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Local converter convert " + feeCurrencyDef.name + " to " + destSystemDef.name + ".");
                            }

                            dest.fees = requiredFees;
                            requiredFees = 0;           // clear them, as they are used below as well when sending directly across
                            reversePriceInFeeCur = feePriceState.TargetConversionPricesReverse(ASSETCHAINS_CHAINID, true).valueMap[feeCurrencyID];

                            printf("%s: setting transfer fees in currency %s to %ld\n", __func__, EncodeDestination(CIdentityID(feeCurrencyID)).c_str(), dest.fees);
                            flags &= ~CReserveTransfer::CROSS_SYSTEM;
                        }
                        else
                        {
                            flags |= CReserveTransfer::CROSS_SYSTEM;
                        }

                        auto reserveMap = converterDef.GetCurrenciesMap();
                        if (feeCurrencyID != destSystemID &&
                            !(converterDef.IsFractional() && (feeCurrencyID == converterID || reserveMap.count(feeCurrencyID))))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert fees " + EncodeDestination(CIdentityID(feeCurrencyID)) + " to " + destSystemDef.name + ". 3");
                        }

                        // converting from reserve to a fractional of that reserve
                        auto fees = requiredFees + CCurrencyState::ReserveToNativeRaw(CReserveTransfer::CalculateTransferFee(dest, flags), reversePriceInFeeCur);
                        CReserveTransfer rt = CReserveTransfer(flags,
                                                               sourceCurrencyID, 
                                                               sourceAmount, 
                                                               feeCurrencyID,
                                                               fees, 
                                                               convertToCurrencyID, 
                                                               dest,
                                                               secondCurrencyID,
                                                               destSystemID);

                        std::vector<CTxDestination> dests = refundValid ? std::vector<CTxDestination>({pk.GetID(), refundDestination}) :
                                                                          std::vector<CTxDestination>({pk.GetID()});

                        oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt));
                    }
                    else // direct to another system paying with acceptable fee currency
                    {
                        if (!validFeeCurrencies.count(feeCurrencyID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency for cross-chain transaction 2" + ConnectedChains.GetFriendlyCurrencyName(feeCurrencyID));
                        }

                        // determine required fees
                        CAmount requiredFees;
                        if (exportCurrency)
                        {
                            // get source price for export and dest price for import to ensure we have enough fee currency
                            requiredFees = CCurrencyState::ReserveToNativeRaw(offChainDef.GetCurrencyImportFee(sourceCurrencyDef.ChainOptions() & sourceCurrencyDef.OPTION_NFT_TOKEN), reversePriceInFeeCur);
                            flags |= CReserveTransfer::CURRENCY_EXPORT;
                        }
                        else if (exportId)
                        {
                            requiredFees = CCurrencyState::ReserveToNativeRaw(offChainDef.IDImportFee(), reversePriceInFeeCur);
                        }
                        else
                        {
                            requiredFees = CCurrencyState::ReserveToNativeRaw(offChainDef.GetTransactionImportFee(), reversePriceInFeeCur);
                        }

                        flags |= CReserveTransfer::CROSS_SYSTEM;
                        auto fees = requiredFees + CCurrencyState::ReserveToNativeRaw(CReserveTransfer::CalculateTransferFee(dest, flags), reversePriceInFeeCur);
                        CReserveTransfer rt = CReserveTransfer(flags,
                                                               sourceCurrencyID, 
                                                               sourceAmount, 
                                                               feeCurrencyID,
                                                               fees, 
                                                               exportToCurrencyID, 
                                                               dest,
                                                               secondCurrencyID,
                                                               destSystemID);

                        std::vector<CTxDestination> dests = refundValid ? std::vector<CTxDestination>({pk.GetID(), refundDestination}) :
                                                                          std::vector<CTxDestination>({pk.GetID()});

                        oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt));
                    }
                }
                else if (exportCurrency)
                {
                    // invalid to export currency except off-chain
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export " + sourceCurrencyDef.name + " without specifying \"exportto\"");
                }
                // a currency conversion without transfer?
                else if (!convertToCurrencyID.IsNull())
                {
                    if (convertToCurrencyDef.IsToken() && preConvert)
                    {
                        if (convertToCurrencyDef.startBlock <= (height + 1))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too late to convert " + sourceCurrencyDef.name + " to " + convertToStr + ", as pre-launch is over.");
                        }

                        CCurrencyValueMap validConversionCurrencies = CCurrencyValueMap(convertToCurrencyDef.currencies, 
                                                                                        std::vector<CAmount>(convertToCurrencyDef.currencies.size(), 1));
                        if (!convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". 1");
                        }

                        CCcontract_info CC;
                        CCcontract_info *cp;
                        cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                        CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                        std::vector<CTxDestination> dests = refundValid ? std::vector<CTxDestination>({pk.GetID(), refundDestination}) :
                                                                          std::vector<CTxDestination>({pk.GetID()});

                        auto dest = DestinationToTransferDestination(destination);
                        auto fees = CReserveTransfer::CalculateTransferFee(dest, flags);
                        CReserveTransfer rt = CReserveTransfer(flags, 
                                                               sourceCurrencyID, 
                                                               sourceAmount,
                                                               feeCurrencyID,
                                                               fees,
                                                               convertToCurrencyID,
                                                               dest);
                        rt.nFees = rt.CalculateTransferFee();
                        oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt));
                    }
                    else if (!preConvert && (mintNew || burnCurrency || toFractional || fromFractional))
                    {
                        // the following cases end up here:
                        //   1. we are minting or burning currency
                        //   2. we are converting from a fractional currency to its reserve or back
                        //   3. we are converting from one reserve of a fractional currency to another reserve of the same fractional

                        CCcontract_info CC;
                        CCcontract_info *cp;
                        cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                        CPubKey pk = CPubKey(ParseHex(CC.CChexstr));
                        if (mintNew || burnCurrency)
                        {
                            // we only allow minting/burning of tokens right now
                            // TODO: support centralized minting of native AND fractional currency
                            // minting of fractional currency should emit coins without changing price by
                            // adjusting reserve ratio
                            if (!convertToCurrencyDef.IsToken() || convertToCurrencyDef.systemID != ASSETCHAINS_CHAINID || convertToCurrencyDef.IsGateway())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot mint or burn currency " + convertToCurrencyDef.name);
                            }
                            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                            if (burnCurrency && sourceCurrencyID == convertToCurrencyID)
                            {
                                flags |= CReserveTransfer::IMPORT_TO_SOURCE;
                            }

                            CReserveTransfer rt = CReserveTransfer(flags, 
                                                                   burnCurrency ? sourceCurrencyID : thisChainID, 
                                                                   sourceAmount,
                                                                   ASSETCHAINS_CHAINID,
                                                                   0,
                                                                   convertToCurrencyID,
                                                                   DestinationToTransferDestination(destination));
                            rt.nFees = rt.CalculateTransferFee();
                            oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                            oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt));
                        }
                        else
                        {
                            flags |= CReserveTransfer::CONVERT;

                            // determine the currency that is the fractional currency, whether that is the source
                            // or destination
                            CCurrencyDefinition *pFractionalCurrency = &sourceCurrencyDef;

                            // determine the reserve currency of the destination that we are relevant to,
                            // again, whether source or destination
                            CCurrencyDefinition *pReserveCurrency = &convertToCurrencyDef;

                            // is our destination currency, the conversion destination?
                            if (toFractional)
                            {
                                pReserveCurrency = pFractionalCurrency;
                                pFractionalCurrency = &convertToCurrencyDef;
                            }
                            else
                            {
                                flags |= CReserveTransfer::IMPORT_TO_SOURCE;
                            }
                            if (!secondCurrencyID.IsNull())
                            {
                                flags |= CReserveTransfer::RESERVE_TO_RESERVE;
                            }

                            if (pFractionalCurrency->launchSystemID == ASSETCHAINS_CHAINID && pFractionalCurrency->startBlock > (height + 1))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + " except through preconvert before the startblock has passed.");
                            }

                            auto reserveMap = pFractionalCurrency->GetCurrenciesMap();
                            auto reserveIndexIt = reserveMap.find(pReserveCurrency->GetID());
                            if (reserveIndexIt == reserveMap.end())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". Must have reserve<->fractional relationship.");
                            }

                            /*
                            In order to accept fees in any currency, we need to pin ourselves to an easily accessible, objective price of the
                            fee currency in native currency of the target system. In order to support an objective and hard line of meeting
                            fee requirements, we define the exchange rate of a currency to verify required import fees for any operation to 
                            be determined by the last confirmed notarization of the importing currency state, if it is fractional, as of the 
                            last export transaction to that currency from this system. An export transaction also includes a predicted 
                            notarization, which is not typically finalized, except for the launch notarization, but always includes the last
                            known state based on notarization.
                            Enabling this will also enable us to generate transactions which require Verus to be posted at all, but once
                            posted, use tokens, which are convenient and already in the transaction to pay for all remaining fees on this
                            system or others.
                            Until then, we use the same standard prices and defaults for all currencies.
                            CChainNotarizationData cnd;
                            if (!GetNotarizationData(pFractionalCurrency->GetID(), EVAL_ACCEPTEDNOTARIZATION, cnd))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to get reserve currency data for " + pFractionalCurrency->name + ".");
                            }
                            */

                            CChainNotarizationData cnd;
                            if (!GetNotarizationData(pFractionalCurrency->GetID(), cnd) ||
                                !cnd.IsConfirmed())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot get notarization/pricing information for " + exportToCurrencyDef.name);
                            }
                            CCoinbaseCurrencyState &feePriceState = cnd.vtx[cnd.lastConfirmed].second.currencyState;
                            if (feeCurrencyID.IsNull())
                            {
                                feeCurrencyID = ASSETCHAINS_CHAINID;
                            }
                            CAmount reversePriceInFeeCur = feePriceState.TargetConversionPricesReverse(ASSETCHAINS_CHAINID, true).valueMap[feeCurrencyID];

                            // converting from reserve to a fractional of that reserve
                            auto dest = DestinationToTransferDestination(destination);
                            CAmount fees = CCurrencyState::ReserveToNativeRaw(CReserveTransfer::CalculateTransferFee(dest, flags), reversePriceInFeeCur);

                            CReserveTransfer rt = CReserveTransfer(flags,
                                                                   sourceCurrencyID, 
                                                                   sourceAmount, 
                                                                   feeCurrencyID,
                                                                   fees, 
                                                                   convertToCurrencyID, 
                                                                   dest,
                                                                   secondCurrencyID);

                            std::vector<CTxDestination> dests = refundValid ? std::vector<CTxDestination>({pk.GetID(), refundDestination}) :
                                                                            std::vector<CTxDestination>({pk.GetID()});

                            oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                            oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt));
                        }
                    }
                    else
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". 4");
                    }
                }
                // or a normal native or reserve output?
                else
                {
                    if (sourceCurrencyID == thisChainID)
                    {
                        oneOutput.nAmount = sourceAmount;
                        oneOutput.scriptPubKey = GetScriptForDestination(destination);
                    }
                    else
                    {
                        oneOutput.nAmount = 0;

                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({destination});
                        CTokenOutput to(sourceCurrencyID, sourceAmount);

                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &to));
                    }
                }
                if (!oneOutput.scriptPubKey.size())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Failure to make currency output");
                }
                tOutputs.push_back(SendManyRecipient(destStr, oneOutput.nAmount, "", oneOutput.scriptPubKey));
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters.");
    }

    // Create operation and add to global queue
    if (hasZSource && minConfs ==0)
    {
        minConfs = 1;
    }
    CMutableTransaction contextualTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height + 1);
    std::shared_ptr<AsyncRPCQueue> q = getAsyncRPCQueue();
    std::shared_ptr<AsyncRPCOperation> operation(new AsyncRPCOperation_sendmany(tb, 
                                                                                contextualTx, 
                                                                                sourceAddress, 
                                                                                tOutputs, 
                                                                                zOutputs,
                                                                                minConfs, 
                                                                                feeAmount, 
                                                                                uniOutputs,
                                                                                true) );
    q->addOperation(operation);
    AsyncRPCOperationId operationId = operation->getId();
    return operationId;
}

UniValue refundfailedlaunch(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "refundfailedlaunch \"currencyid\"\n"
            "\nRefunds any funds sent to the chain if they are eligible for refund.\n"
            "This attempts to refund all transactions for all contributors.\n"

            "\nArguments\n"
            "\"currencyid\"         (iaddress or full chain name, required)   the chain to refund contributions to\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("refundfailedlaunch", "\"currencyid\"")
            + HelpExampleRpc("refundfailedlaunch", "\"currencyid\"")
        );
    }
    CheckPBaaSAPIsValid();

    uint160 chainID;

    {
        LOCK(cs_main);
        chainID = GetChainIDFromParam(params[0]);
    }
    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid PBaaS name or currencyid");
    }

    if (chainID == ConnectedChains.ThisChain().GetID() || chainID == ConnectedChains.FirstNotaryChain().chainDefinition.GetID())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot refund the specified chain");
    }

    CTransaction lastImportTx;
    std::vector<CTransaction> refundTxes;
    std::string failReason;

    //if (!RefundFailedLaunch(chainID, lastImportTx, refundTxes, failReason))
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, failReason);
    }

    uint32_t consensusBranchId = CurrentEpochBranchId(chainActive.LastTip()->GetHeight(), Params().GetConsensus());

    UniValue ret(UniValue::VARR);

    CCoinsViewCache view(pcoinsTip);

    // sign and commit the transactions
    for (auto tx : refundTxes)
    {
        LOCK2(cs_main, mempool.cs);

        CMutableTransaction newTx(tx);

        // sign the transaction and submit
        bool signSuccess;
        for (int i = 0; i < tx.vin.size(); i++)
        {
            SignatureData sigdata;
            CAmount value;
            CScript outputScript;

            if (tx.vin[i].prevout.hash == lastImportTx.GetHash())
            {
                value = lastImportTx.vout[tx.vin[i].prevout.n].nValue;
                outputScript = lastImportTx.vout[tx.vin[i].prevout.n].scriptPubKey;
            }
            else
            {
                CCoinsViewCache view(pcoinsTip);
                CCoins coins;
                if (!view.GetCoins(tx.vin[i].prevout.hash, coins))
                {
                    fprintf(stderr,"refundfailedlaunch: cannot get input coins from tx: %s, output: %d\n", tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    LogPrintf("refundfailedlaunch: cannot get input coins from tx: %s, output: %d\n", tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    break;
                }
                value = coins.vout[tx.vin[i].prevout.n].nValue;
                outputScript = coins.vout[tx.vin[i].prevout.n].scriptPubKey;
            }

            signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &tx, i, value, SIGHASH_ALL), outputScript, sigdata, consensusBranchId);

            if (!signSuccess)
            {
                fprintf(stderr,"refundfailedlaunch: failure to sign refund transaction\n");
                LogPrintf("refundfailedlaunch: failure to sign refund transaction\n");
                break;
            } else {
                UpdateTransaction(newTx, i, sigdata);
            }
        }

        if (signSuccess)
        {
            // push to local node and sync with wallets
            CValidationState state;
            bool fMissingInputs;
            CTransaction signedTx(newTx);
            if (!AcceptToMemoryPool(mempool, state, signedTx, false, &fMissingInputs)) {
                if (state.IsInvalid()) {
                    fprintf(stderr,"refundfailedlaunch: rejected by memory pool for %s\n", state.GetRejectReason().c_str());
                    LogPrintf("refundfailedlaunch: rejected by memory pool for %s\n", state.GetRejectReason().c_str());
                } else {
                    if (fMissingInputs) {
                        fprintf(stderr,"refundfailedlaunch: missing inputs\n");
                        LogPrintf("refundfailedlaunch: missing inputs\n");
                    }
                    else
                    {
                        fprintf(stderr,"refundfailedlaunch: rejected by memory pool for\n");
                        LogPrintf("refundfailedlaunch: rejected by memory pool for\n");
                    }
                }
                break;
            }
            else
            {
                RelayTransaction(signedTx);
                ret.push_back(signedTx.GetHash().GetHex());
            }
        }
    }
    return ret;
}

UniValue getinitialcurrencystate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getinitialcurrencystate \"name\"\n"
            "\nReturns the total amount of preconversions that have been confirmed on the blockchain for the specified PBaaS chain.\n"
            "This should be used to get information about chains that are not this chain, but are being launched by it.\n"

            "\nArguments\n"
            "   \"name\"                    (string, required) name or chain ID of the chain to get the export transactions for\n"

            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"flags\" : n,\n"
            "           \"initialratio\" : n,\n"
            "           \"initialsupply\" : n,\n"
            "           \"emitted\" : n,\n"
            "           \"supply\" : n,\n"
            "           \"reserve\" : n,\n"
            "           \"currentratio\" : n,\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getinitialcurrencystate", "name")
            + HelpExampleRpc("getinitialcurrencystate", "name")
        );
    }
    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    CCurrencyDefinition chainDef;
    int32_t definitionHeight;
    if (!GetCurrencyDefinition(chainID, chainDef, &definitionHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Chain " + params[0].get_str() + " not found");
    }
    return ConnectedChains.GetCurrencyState(chainDef.GetID(), chainDef.startBlock - 1).ToUniValue();
}

UniValue getcurrencystate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "getcurrencystate \"currencynameorid\" (\"n\") (\"connectedsystemid\")\n"
            "\nReturns the currency state(s) on the blockchain for any specified currency, either with all changes on this chain or relative to another system.\n"

            "\nArguments\n"
            "   \"currencynameorid\"                  (string)                  name or i-address of currency in question"
            "   \"n\" or \"m,n\" or \"m,n,o\"         (int or string, optional) height or inclusive range with optional step at which to get the currency state\n"
            "                                                                   If not specified, the latest currency state and height is returned\n"
            "   (\"connectedchainid\")                (string)                  optional\n"

            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"height\": n,\n"
            "           \"blocktime\": n,\n"
            "           \"currencystate\": {\n"
            "               \"flags\" : n,\n"
            "               \"initialratio\" : n,\n"
            "               \"initialsupply\" : n,\n"
            "               \"emitted\" : n,\n"
            "               \"supply\" : n,\n"
            "               \"reserve\" : n,\n"
            "               \"currentratio\" : n,\n"
            "           \"}\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrencystate", "\"currencynameorid\" (\"n\") (\"connectedchainid\")")
            + HelpExampleRpc("getcurrencystate", "\"currencynameorid\" (\"n\") (\"connectedchainid\")")
        );
    }
    CheckPBaaSAPIsValid();

    CCurrencyDefinition currencyToCheck;

    std::string currencyStr = uni_get_str(params[0]);
    if (currencyStr.empty() || ValidateCurrencyName(currencyStr, true, &currencyToCheck).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency specified");
    }
    uint160 currencyID = currencyToCheck.GetID();

    LOCK(cs_main);

    uint64_t lStart;
    uint64_t startEnd[3] = {0};

    lStart = startEnd[1] = startEnd[0] = chainActive.LastTip() ? chainActive.LastTip()->GetHeight() : 1;

    if (params.size() > 1)
    {
        if (params[1].isStr())
        {
            Split(params[1].get_str(), startEnd, startEnd[0], 3);
        }
        else if (uni_get_int(params[1], -1) != -1)
        {
            lStart = startEnd[1] = startEnd[0] = uni_get_int(params[0], lStart);
        }
    }

    if (startEnd[0] > startEnd[1])
    {
        startEnd[0] = startEnd[1];
    }

    if (startEnd[1] > lStart)
    {
        startEnd[1] = lStart;
    }

    if (startEnd[1] < startEnd[0])
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range for currency state");
    }

    if (startEnd[2] == 0)
    {
        startEnd[2] = 1;
    }

    if (startEnd[2] > INT_MAX)
    {
        startEnd[2] = INT_MAX;
    }

    uint32_t start = startEnd[0], end = startEnd[1], step = startEnd[2];

    UniValue ret(UniValue::VARR);

    for (int i = start; i <= end; i += step)
    {
        LOCK(cs_main);
        CCoinbaseCurrencyState currencyState = ConnectedChains.GetCurrencyState(currencyID, i);
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("height", i));
        entry.push_back(Pair("blocktime", (uint64_t)chainActive.LastTip()->nTime));
        CAmount price;
        entry.push_back(Pair("currencystate", currencyState.ToUniValue()));
        ret.push_back(entry);
    }
    return ret;
}

UniValue getsaplingtree(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
    {
        throw runtime_error(
            "getsaplingtree \"n\"\n"
            "\nReturns the entries for a light wallet Sapling tree state.\n"

            "\nArguments\n"
            "   \"n\" or \"m,n\" or \"m,n,o\"         (int or string, optional) height or inclusive range with optional step at which to get the Sapling tree state\n"
            "                                                                   If not specified, the latest currency state and height is returned\n"
            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"network\": \"VRSC\",\n"
            "           \"height\": n,\n"
            "           \"hash\": \"hex\"\n"
            "           \"time\": n,\n"
            "           \"tree\": \"hex\"\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getsaplingtree", "name")
            + HelpExampleRpc("getsaplingtree", "name")
        );
    }

    uint64_t lStart;
    uint64_t startEnd[3] = {0};

    lStart = startEnd[1] = startEnd[0] = chainActive.LastTip() ? chainActive.LastTip()->GetHeight() : 1;

    if (params.size() == 1)
    {
        if (uni_get_int(params[0], -1) == -1 && params[0].isStr())
        {
            Split(params[0].get_str(), startEnd, startEnd[0], 3);
        }
    }

    if (startEnd[0] > startEnd[1])
    {
        startEnd[0] = startEnd[1];
    }

    if (startEnd[1] > lStart)
    {
        startEnd[1] = lStart;
    }

    if (startEnd[1] < startEnd[0])
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range for currency state");
    }

    if (startEnd[2] == 0)
    {
        startEnd[2] = 1;
    }

    if (startEnd[2] > INT_MAX)
    {
        startEnd[2] = INT_MAX;
    }

    uint32_t start = startEnd[0], end = startEnd[1], step = startEnd[2];

    UniValue ret(UniValue::VARR);

    LOCK(cs_main);
    CCoinsViewCache view(pcoinsTip);
    SaplingMerkleTree tree;

    std::string networkIDName = EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID));

    for (int i = start; i <= end; i += step)
    {
        CBlockIndex &blkIndex = *(chainActive[i]);
        if (view.GetSaplingAnchorAt(blkIndex.hashFinalSaplingRoot, tree))
        {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("network", networkIDName));
            entry.push_back(Pair("height", blkIndex.GetHeight()));
            entry.push_back(Pair("hash", blkIndex.GetBlockHash().GetHex()));
            entry.push_back(Pair("time", (uint64_t)chainActive.LastTip()->nTime));
            std::vector<unsigned char> treeBytes = ::AsVector(tree);
            entry.push_back(Pair("tree", HexBytes(treeBytes.data(), treeBytes.size())));
            ret.push_back(entry);
        }
    }
    return ret;
}

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);

CCurrencyDefinition ValidateNewUnivalueCurrencyDefinition(const UniValue &uniObj, uint32_t height, const uint160 systemID, std::map<uint160, std::string> &requiredDefinitions, bool checkMempool)
{
    CCurrencyDefinition newCurrency(uniObj);
    if (find_value(uniObj, "launchsystemid").isNull() && newCurrency.GetID() != ASSETCHAINS_CHAINID && newCurrency.parent != ASSETCHAINS_CHAINID)
    {
        newCurrency.launchSystemID = systemID;
    }

    if (!newCurrency.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency definition. see help.");
    }

    CCurrencyDefinition checkDef;
    int32_t defHeight;
    if (GetCurrencyDefinition(newCurrency.GetID(), checkDef, &defHeight, checkMempool) &&
        defHeight < height &&
        !(newCurrency.GetID() == ASSETCHAINS_CHAINID &&
         !defHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, newCurrency.name + " chain already defined. see help.");
    }

    bool currentChainDefinition = newCurrency.GetID() == ASSETCHAINS_CHAINID && _IsVerusActive();
    if (currentChainDefinition)
    {
        newCurrency = checkDef;
    }

    if (newCurrency.parent.IsNull() && !currentChainDefinition)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, newCurrency.name + " invalid chain name.");
    }

    for (auto &oneID : newCurrency.preAllocation)
    {
        if (!(newCurrency.IsPBaaSChain() && oneID.first.IsNull()) && !CIdentity::LookupIdentity(CIdentityID(oneID.first)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "attempting to pre-allocate currency to a non-existent ID.");
        }
    }

    // a new currency definition must spend an ID that currently has no active currency, which sets a semaphore that "blocks"
    // that ID from having more than one at once. Before submitting the transaction, it must be properly signed by the primary authority. 
    // This also has the effect of piggybacking on the ID protocol's deconfliction between mined blocks to avoid name conflicts, 
    // as the ID can only have its bit set or unset by one transaction at any time and only as part of a transaction that changes the
    // the state of a potentially active currency.

    if (newCurrency.IsToken() || newCurrency.IsGateway())
    {
        if (newCurrency.rewards.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "currency cannot be both a token and also specify a mining and staking rewards schedule.");
        }

        if ((newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETH && !newCurrency.IsGateway()) ||
            newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETHNFT)
        {
            if (newCurrency.IsPBaaSChain() ||
                !newCurrency.IsToken() ||
                newCurrency.IsFractional())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "mapped currency must be a token with no initial supply and cannot be otherwise functional");
            }
            if (newCurrency.proofProtocol != newCurrency.PROOF_ETHNOTARIZATION)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Ethereum mapped currency must have \"proofprotocol\":%d", (int)newCurrency.PROOF_ETHNOTARIZATION));
            }
            bool nonZeroSupply = (newCurrency.conversions.size() && !newCurrency.maxPreconvert.size()) || newCurrency.GetTotalPreallocation();
            for (auto oneVal : newCurrency.maxPreconvert)
            {
                if (oneVal)
                {
                    nonZeroSupply = true;
                }
            }
            if (nonZeroSupply)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Mapped currency definition requires zero initial supply and no possible conversions");
            }
            CCurrencyDefinition systemCurrency = ConnectedChains.GetCachedCurrency(newCurrency.systemID);
            if (systemCurrency.IsValid() &&
                (!systemCurrency.IsGateway() ||
                 systemCurrency.launchSystemID != ASSETCHAINS_CHAINID ||
                 systemCurrency.proofProtocol != systemCurrency.PROOF_ETHNOTARIZATION))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Ethereum protocol networks are the only mapped currency type currently supported");
            }
        }
        else
        {
            // if this is a token or gateway definition, set systemID
            newCurrency.systemID = systemID;
        }
    }
    else
    {
        // it is a PBaaS chain, and it is its own system, responsible for its own communication and currency control
        newCurrency.systemID = newCurrency.GetID();
    }

    if (currentChainDefinition)
    {
        return newCurrency;
    }

    // refunding a currency after its launch is aborted, or shutting it down after the endblock has passed must be completed
    // to fully decommission a blockchain and clear the active blockchain bit from an ID

    //if (!newCurrency.startBlock || newCurrency.startBlock < (chainActive.Height() + PBAAS_MINSTARTBLOCKDELTA))
    //{
    //    newCurrency.startBlock = chainActive.Height() + (PBAAS_MINSTARTBLOCKDELTA + 5);    // give a little time to send the tx
    //}

    if (!newCurrency.startBlock || newCurrency.startBlock < (chainActive.Height() + 10))
    {
        newCurrency.startBlock = chainActive.Height() + DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA;  // give a little time to send the tx
    }

    if (newCurrency.endBlock && newCurrency.endBlock < (newCurrency.startBlock + CCurrencyDefinition::MIN_CURRENCY_LIFE))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "If endblock (" + to_string(newCurrency.endBlock) + 
                                               ") is specified, it must be at least " + to_string(CCurrencyDefinition::MIN_CURRENCY_LIFE) + 
                                               " blocks after startblock (" + to_string(newCurrency.startBlock) + ")\n");
    }

    if (!newCurrency.IsToken())
    {
        // if we have no emission parameters, this is not a PBaaS blockchain, it is a controlled or bridged token.
        // controlled tokens can be centrally or algorithmically controlled.
        if (!newCurrency.IsGateway() && newCurrency.rewards.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "A currency must either be based on a token protocol or must specify blockchain rewards, even if 0\n");
        }

        if (newCurrency.IsFractional())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Fractional currencies must be tokens.\n");
        }

        // we need to also be able to set PBaaS converter and gateway
        if (!newCurrency.IsGateway())
        {
            newCurrency.options |= newCurrency.OPTION_PBAAS;
        }
    }

    UniValue currencyNames = find_value(uniObj, "currencies");
    std::set<uint160> currencySet;

    for (int i = 0; i < currencyNames.size(); i++)
    {
        std::string oneCurName = uni_get_str(currencyNames[i]);
        if (!oneCurName.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid (null) currency name");
        }
        uint160 oneCurID = ValidateCurrencyName(oneCurName, true);
        if (oneCurID.IsNull())
        {
            if ((oneCurID = ValidateCurrencyName(oneCurName)).IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency " + oneCurName + " in \"currencies\" 1");
            }
            if (requiredDefinitions.count(oneCurID))
            {
                oneCurName = requiredDefinitions[oneCurID];
            }
            else
            {
                printf("%s: currency not found: name(%s), ID(%s)\nstored names and IDs:\n", __func__, oneCurName.c_str(), EncodeDestination(CIdentityID(oneCurID)).c_str());
                for (auto &onePair : requiredDefinitions)
                {
                    printf("ID(%s), name(%s)\n", EncodeDestination(CIdentityID(onePair.first)).c_str(), onePair.second.c_str());
                }
            }
            // if the new currency is a PBaaS or gateway converter, and this is the PBaaS chain or gateway,
            // it will be created in this tx as well
            if (newCurrency.IsGatewayConverter() && oneCurID == newCurrency.parent)
            {
                currencySet.insert(oneCurID);
                continue;
            }
            if (!(newCurrency.IsGatewayConverter() && systemID == ASSETCHAINS_CHAINID && newCurrency.parent != ASSETCHAINS_CHAINID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency " + oneCurName + " in \"currencies\"");
            }

            uint160 parent;
            std::string cleanName = CleanName(oneCurName + "@", parent);
            if (cleanName.empty())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot decode currency name " + oneCurName + " in \"currencies\"");
            }

            // the parent of the currency cannot require a new definition
            if (oneCurID != newCurrency.parent)
            {
                if (parent != newCurrency.parent || cleanName == "")
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to auto-create currency " + oneCurName + " in \"currencies\"");
                }
                requiredDefinitions[oneCurID] = oneCurName;
            }
        }
        else
        {
            requiredDefinitions.erase(oneCurID);
        }
        currencySet.insert(oneCurID);
    }

    if (currencyNames.size() != currencySet.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate currency specified in \"currencies\"");
    }

    // if this is a fractional reserve currency, ensure that all reserves are currently active 
    // with at least as long of a life as this currency and that at least one of the currencies
    // is VRSC or VRSCTEST.
    std::vector<CCurrencyDefinition> reserveCurrencies;
    bool hasCoreReserve = false;
    if (newCurrency.IsFractional())
    {
        if (newCurrency.currencies.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Fractional reserve currencies must specify at least one reserve currency\n");
        }

        if (newCurrency.contributions.size() != newCurrency.currencies.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "All reserves must have non-zero initial contributions for each reserve for fractional currency " + newCurrency.name);
        }

        newCurrency.preconverted = newCurrency.contributions;

        for (auto &currency : newCurrency.currencies)
        {
            currencySet.insert(currency);
            if (currency == ASSETCHAINS_CHAINID)
            {
                hasCoreReserve = true;
                continue;
            }

            if (newCurrency.systemID == currency)
            {
                continue;
            }

            if (newCurrency.parent == currency)
            {
                continue;
            }

            reserveCurrencies.push_back(CCurrencyDefinition());

            bool currencyIsRegistered = false;
            if (!requiredDefinitions.count(currency))
            {
                if (!GetCurrencyDefinition(currency, reserveCurrencies.back()) || 
                    (reserveCurrencies.back().launchSystemID == ASSETCHAINS_CHAINID && reserveCurrencies.back().startBlock >= height))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "All reserve currencies of a fractional currency must be valid and past the start block " + EncodeDestination(CIdentityID(currency)));
                }
                if (reserveCurrencies.back().endBlock && (!newCurrency.endBlock || reserveCurrencies.back().endBlock < newCurrency.endBlock))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Reserve currency " + EncodeDestination(CIdentityID(currency)) + " ends its life before the fractional currency's endblock");
                }
            }
        }
        if (!hasCoreReserve)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Fractional currency requires a reserve of " + std::string(ASSETCHAINS_SYMBOL) + " in addition to any other reserves");
        }
    }
    return newCurrency;
}

UniValue definecurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 14)
    {
        throw runtime_error(
            "definecurrency '{\"name\": \"coinortokenname\", ..., \"nodes\":[{\"networkaddress\":\"identity\"},..]}'\\\n"
            "                '({\"name\": \"fractionalgatewayname\", ..., })' ({\"name\": \"reserveonename\", ..., }) ...\n"
            "\nThis defines a blockchain currency, either as an independent blockchain, or as a token on this blockchain. It also spends\n"
            "the identity after which this currency is named and sets a bit indicating that it has a currently active blockchain in its name.\n"
            "\nTo create a currency of any kind, the identity it is named after must be minted on the blockchain on which the currency is created.\n"
            "Once a currency is activated for an identity name, the same symbol may not be reused for another currency or blockchain, even\n"
            "if the identity is transferred, revoked or recovered, unless there is an endblock specified and the currency or blockchain has\n"
            "deactivated as of that end block.\n"
            "\nAll funds to start the currency and for initial conversion amounts must be available to spend from the identity with the same\n"
            "name and ID as the currency being defined.\n"
            "\nArguments\n"
            "      {\n"
            "         \"options\" : n,                  (int,    optional) bits (in hexadecimal):\n"
            "                                                             1 = FRACTIONAL\n"
            "                                                             2 = IDRESTRICTED\n"
            "                                                             4 = IDSTAKING\n"
            "                                                             8 = IDREFERRALS\n"
            "                                                             0x10 = IDREFERRALSREQUIRED\n"
            "                                                             0x20 = TOKEN\n"
            "                                                             0x40 = RESERVED\n"
            "                                                             0x100 = IS_PBAAS_CHAIN\n"
            "\n"
            "         \"name\" : \"xxxx\",              (string, required) name of existing identity with no active or pending blockchain\n"
            "         \"idregistrationfees\" : \"xx.xx\", (value, required) price of an identity in native currency\n"
            "         \"idreferrallevels\" : n,         (int, required) how many levels ID referrals go back in reward\n"

            "         \"notaries\" : \"[identity,..]\", (list, optional) list of identities that are assigned as chain notaries\n"
            "         \"minnotariesconfirm\" : n,       (int, optional) unique notary signatures required to confirm an auto-notarization\n"
            "         \"notarizationreward\" : \"xx.xx\", (value,  required) default VRSC notarization reward total for first billing period\n"
            "         \"billingperiod\" : n,            (int,    optional) number of blocks in each billing period\n"
            "         \"proofprotocol\" : n,            (int,    optional) if 2, currency can be minted by whoever controls the ID\n"

            "         \"startblock\"    : n,            (int,    optional) VRSC block must be notarized into block 1 of PBaaS chain, default curheight + 100\n"
            "         \"endblock\"      : n,            (int,    optional) chain is considered inactive after this block height, and a new one may be started\n"

            "         \"currencies\"    : \"[\"VRSC\",..]\", (list, optional) reserve currencies backing this chain in equal amounts\n"
            "         \"conversions\"   : \"[\"xx.xx\",..]\", (list, optional) if present, must be same size as currencies. pre-launch conversion ratio overrides\n"
            "         \"minpreconversion\" : \"[\"xx.xx\",..]\", (list, optional) must be same size as currencies. minimum in each currency to launch\n"
            "         \"maxpreconversion\" : \"[\"xx.xx\",..]\", (list, optional) maximum in each currency allowed\n"

            "         \"initialcontributions\" : \"[\"xx.xx\",..]\", (list, optional) initial contribution in each currency\n"
            "         \"prelaunchdiscount\" : \"xx.xx\" (value, optional) for fractional reserve currencies less than 100%, discount on final price at launch\n"
            "         \"initialsupply\" : \"xx.xx\"    (value, required for fractional) supply after conversion of contributions, before preallocation\n"
            "         \"prelaunchcarveout\" : \"0.xx\", (value, optional) identities and % of pre-converted amounts from each reserve currency\n"
            "         \"preallocations\" : \"[{\"identity\":xx.xx}..]\", (list, optional)  list of identities and amounts from pre-allocation\n"
            "         \"gatewayconvertername\" : \"name\", (string, optional) if this is a PBaaS chain, this names a co-launched gateway converter currency\n"

            "         \"eras\"          : \"objarray\", (array, optional) data specific to each era, maximum 3\n"
            "         {\n"
            "            \"reward\"     : n,           (int64,  required) native initial block rewards in each period\n"
            "            \"decay\"      : n,           (int64,  optional) reward decay for each era\n"
            "            \"halving\"    : n,           (int,    optional) halving period for each era\n"
            "            \"eraend\"     : n,           (int,    optional) ending block of each era\n"
            "         }\n"
            "         \"nodes\"         : \"[obj, ..]\", (objectarray, optional) up to 5 nodes that can be used to connect to the blockchain"
            "         [{\n"
            "            \"networkaddress\" : \"ip:port\", (string,  optional) internet, TOR, or other supported address for node\n"
            "            \"nodeidentity\" : \"name@\",  (string, optional) published node identity\n"
            "         }, .. ]\n"
            "      }\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"transactionid\", (string) The transaction id\n"
            "  \"tx\"   : \"json\",          (json)   The transaction decoded as a transaction\n"
            "  \"hex\"  : \"data\"           (string) Raw data for signed transaction\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("definecurrency", "jsondefinition")
            + HelpExampleRpc("definecurrency", "jsondefinition")
        );
    }

    CheckPBaaSAPIsValid();
    bool isVerusActive = IsVerusActive();

    uint160 thisChainID = ConnectedChains.ThisChain().GetID();

    if (!params[0].isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "JSON object required. see help.");
    }

    if (!pwalletMain)
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "must have active wallet to define PBaaS chain");
    }

    UniValue valStr(UniValue::VSTR);
    if (!valStr.read(params[0].write()))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid characters in blockchain definition");
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);
    uint32_t height = chainActive.Height();

    std::map<uint160, std::string> requiredCurrencyDefinitions;
    CCurrencyDefinition newChain(ValidateNewUnivalueCurrencyDefinition(params[0], height, ASSETCHAINS_CHAINID, requiredCurrencyDefinitions));

    if (requiredCurrencyDefinitions.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "currency definition has invalid or undefined currency references");
    }

    CCurrencyDefinition parentCurrency;

    if (!newChain.parent.IsNull())
    {
        parentCurrency = ConnectedChains.GetCachedCurrency(newChain.parent);
    }
    else
    {
        parentCurrency = ConnectedChains.ThisChain();
    }

    bool invalidUnlessNFT = false;
    if (newChain.parent != thisChainID &&
        !(isVerusActive && newChain.GetID() == ASSETCHAINS_CHAINID && newChain.parent.IsNull()) &&
        !(parentCurrency.IsGateway() && !parentCurrency.IsNameController() && parentCurrency.launchSystemID == ASSETCHAINS_CHAINID))
    {
        invalidUnlessNFT = true;
        if (!newChain.IsNFTToken() )
        {
            // parent chain must be current chain or be VRSC or VRSCTEST registered by the owner of the associated ID
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Attempting to define a currency relative to a parent that is not a valid gateway or the current chain.");
        }
    }

    uint160 newChainID = newChain.GetID();

    CIdentity launchIdentity;
    uint32_t idHeight = 0;
    CTxIn idTxIn;
    bool canSign = false, canSpend = false;

    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
    if (pwalletMain->GetIdentity(newChainID, keyAndIdentity))
    {
        canSign = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SIGN;
        canSpend = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SPEND;
        launchIdentity = static_cast<CIdentity>(keyAndIdentity.second);
    }

    if (!canSign)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot sign for ID " + newChain.name);
    }

    if (!(launchIdentity = CIdentity::LookupIdentity(newChainID, 0, &idHeight, &idTxIn)).IsValidUnrevoked() || launchIdentity.HasActiveCurrency())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID " + newChain.name + " not found, is revoked, or already has an active currency defined");
    }

    if (launchIdentity.systemID != ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot launch any currency or tokenized ID control unless the root identity is rooted on this system");
    }

    CTransaction idTx;
    uint256 blockHash;
    if (!GetTransaction(idTxIn.prevout.hash, idTx, blockHash, true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot load ID transaction for " + VERUS_CHAINNAME);
    }
    TransactionBuilder tb = TransactionBuilder(Params().GetConsensus(), height + 1, pwalletMain);
    tb.AddTransparentInput(idTxIn.prevout, idTx.vout[idTxIn.prevout.n].scriptPubKey, idTx.vout[idTxIn.prevout.n].nValue);

    // if this is a PBaaS chain definition, and we have a gateway converter currency to also start,
    // validate and start the converter currency as well
    CCurrencyDefinition newGatewayConverter;
    std::map<uint160, std::map<std::string, UniValue>> newReserveDefinitions;
    std::map<uint160, CCurrencyDefinition> newReserveCurrencies;
    std::vector<CNodeData> startupNodes;
    if (newChain.IsPBaaSChain() || newChain.IsGateway())
    {
        UniValue launchNodesUni = find_value(params[0], "nodes");
        if (launchNodesUni.isArray() && launchNodesUni.size())
        {
            for (int i = 0; i < launchNodesUni.size(); i++)
            {
                std::string networkAddress;
                std::string nodeIdentity;
                CNodeData oneNode;
                if (launchNodesUni[i].isObject() &&
                    (oneNode = CNodeData(launchNodesUni[i])).IsValid())
                {
                    startupNodes.push_back(oneNode);
                }
            }
        }
        if (startupNodes.size() > CCurrencyDefinition::MAX_STARTUP_NODES)
        {
            startupNodes.resize(CCurrencyDefinition::MAX_STARTUP_NODES);
        }
        if (!startupNodes.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify valid, initial launch nodes for a PBaaS chain");
        }

        if (!newChain.gatewayConverterName.empty())
        {
            // create a set of default, necessary parameters
            // then apply the parameters passed, which will simplify the
            // specification with defaults
            std::map<std::string, UniValue> gatewayConverterMap;
            gatewayConverterMap.insert(std::make_pair("options", CCurrencyDefinition::OPTION_FRACTIONAL +
                                                                 CCurrencyDefinition::OPTION_TOKEN +
                                                                 CCurrencyDefinition::OPTION_GATEWAY_CONVERTER));
            gatewayConverterMap.insert(std::make_pair("parent", EncodeDestination(CIdentityID(newChainID))));
            gatewayConverterMap.insert(std::make_pair("name", newChain.gatewayConverterName));
            gatewayConverterMap.insert(std::make_pair("launchsystemid", EncodeDestination(CIdentityID(thisChainID))));
            gatewayConverterMap.insert(std::make_pair("gateway", EncodeDestination(CIdentityID(newChain.GetID()))));

            // if this is a gateway, the converter runs on the launching chain by default
            // if PBaaS chain, on the new system
            if (newChain.IsGateway())
            {
                gatewayConverterMap.insert(std::make_pair("systemid", EncodeDestination(CIdentityID(thisChainID))));
            }
            else
            {
                gatewayConverterMap.insert(std::make_pair("systemid", EncodeDestination(CIdentityID(newChainID))));
            }

            UniValue currenciesUni(UniValue::VARR);
            currenciesUni.push_back(EncodeDestination(CIdentityID(thisChainID)));
            currenciesUni.push_back(EncodeDestination(CIdentityID(newChainID)));
            gatewayConverterMap.insert(std::make_pair("currencies", currenciesUni));

            if (params.size() > 1)
            {
                auto curKeys = params[1].getKeys();
                auto curValues = params[1].getValues();
                for (int i = 0; i < curKeys.size(); i++)
                {
                    gatewayConverterMap[curKeys[i]] = curValues[i];
                }
            }

            // set start block and gateway converter issuance
            if (newChain.IsGateway())
            {
                CEthGateway gatewayCheck;
                if (newChain.GetID() != gatewayCheck.GatewayID())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Ethereum is the only gateway supported at this time");
                }

                if (uni_get_int(gatewayConverterMap["startblock"]) < (int32_t)(height + DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA))
                {
                    gatewayConverterMap["startblock"] = (int32_t)(height + DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA);
                }
                // gateways start already running
                newChain.startBlock = 0;
            }
            else
            {
                gatewayConverterMap["startblock"] = newChain.startBlock;
            }

            gatewayConverterMap["gatewayconverterissuance"] = ValueFromAmount(newChain.gatewayConverterIssuance);

            UniValue newCurUni(UniValue::VOBJ);
            for (auto oneProp : gatewayConverterMap)
            {
                newCurUni.pushKV(oneProp.first, oneProp.second);
            }

            uint32_t converterOptions = uni_get_int64(gatewayConverterMap["options"]);
            converterOptions &= ~(CCurrencyDefinition::OPTION_GATEWAY + CCurrencyDefinition::OPTION_PBAAS);
            converterOptions |= CCurrencyDefinition::OPTION_FRACTIONAL +
                                CCurrencyDefinition::OPTION_TOKEN +
                                CCurrencyDefinition::OPTION_GATEWAY_CONVERTER;
            gatewayConverterMap["options"] = (int64_t)converterOptions;

            //printf("%s: gatewayConverter definition:\n%s\n", __func__, newCurUni.write(1,2).c_str());

            // set the parent and system of the new gateway converter to the new currency
            std::map<uint160, std::string> autoCurrencyNames;
            newGatewayConverter = ValidateNewUnivalueCurrencyDefinition(newCurUni, height, newChain.systemID, autoCurrencyNames);

            if (autoCurrencyNames.size())
            {
                if (!newChain.IsGateway())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Only a gateway definition may also define currencies to use as bridge converter reserves");
                }

                // any required currency definitions will include their text name and have a parent of the gateway
                // to qualify for auto-definition. we also need to parse the remaining parameters
                // and verify that they are only needed definitions

                for (auto &oneCurrencyName : autoCurrencyNames)
                {
                    // for each name, we will create a definition that has a systemID of the current system and parent of the gateway
                    std::map<std::string, UniValue> oneCurEntry;
                    oneCurEntry["name"] = oneCurrencyName.second;
                    oneCurEntry["parent"] = EncodeDestination(CIdentityID(newChainID));
                    oneCurEntry["systemid"] = EncodeDestination(CIdentityID(newChainID));
                    oneCurEntry["launchsystemid"] = EncodeDestination(CIdentityID(newChainID));
                    oneCurEntry["nativecurrencyid"] = DestinationToTransferDestination(CIdentityID(oneCurrencyName.first)).ToUniValue();
                    oneCurEntry["options"] = CCurrencyDefinition::OPTION_TOKEN;
                    oneCurEntry["proofprotocol"] = newChain.proofProtocol;
                    oneCurEntry["notarizationprotocol"] = CCurrencyDefinition::NOTARIZATION_AUTO;
                    
                    newReserveDefinitions[oneCurrencyName.first] = oneCurEntry;
                }

                if (params.size() > 2)
                {
                    for (int paramIdx = 2; paramIdx < params.size(); paramIdx++)
                    {
                        uint160 reserveParentID;
                        std::string checkName = CleanName(uni_get_str(find_value(params[paramIdx], "name")), reserveParentID);
                        if (reserveParentID != newChainID && reserveParentID != ASSETCHAINS_CHAINID)
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Only reserves on the gateway may be defined as additional currency definition parameters");
                        }
                        reserveParentID = newChainID;
                        uint160 autoReserveID = CIdentity::GetID(checkName, reserveParentID);
                        if (!newReserveDefinitions.count(autoReserveID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency " + checkName + " is not a required reserve definition");
                        }
                        auto curKeys = params[paramIdx].getKeys();
                        auto curValues = params[paramIdx].getValues();
                        for (int i = 0; i < curKeys.size(); i++)
                        {
                            newReserveDefinitions[autoReserveID][curKeys[i]] = curValues[i];
                        }
                    }
                }
                // now, loop through all new currency definitions and define them
                // disallow: pre-allocation, prelaunch discount, future start block, fractional currency, any form of launch
                for (auto &oneDefinition : newReserveDefinitions)
                {
                    UniValue oneDefUni(UniValue::VOBJ);
                    for (auto &oneProp : oneDefinition.second)
                    {
                        oneDefUni.pushKV(oneProp.first, oneProp.second);
                    }
                    CCurrencyDefinition newReserveDef(oneDefUni);
                    if (!(newReserveDef.IsValid() &&
                          newReserveDef.IsToken() &&
                          !newReserveDef.IsFractional() &&
                          newReserveDef.systemID == newChainID &&
                          newReserveDef.parent == newChainID &&
                          newReserveDef.nativeCurrencyID.IsValid() &&
                          newReserveDef.launchSystemID == newChainID &&
                          newReserveDef.startBlock == 0 &&
                          newReserveDef.endBlock == 0 &&
                          newReserveDef.proofProtocol == newChain.proofProtocol))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid auto-reserve currency definition");
                    }
                    if (newChain.IsGateway())
                    {
                        newReserveDef.gatewayID = newChainID;
                    }
                    newReserveCurrencies[oneDefinition.first] = newReserveDef;
                }
            }
            else if (params.size() > 2)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters. Please see help.");
            }

            // check that basics are correct, fractional that includes correct currencies, etc.
            if (newGatewayConverter.parent != newChainID ||
                !newGatewayConverter.IsFractional() ||
                !newGatewayConverter.IsToken())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "A gateway currency must have the PBaaS chain as parent and be a fractional token");
            }

            auto currencyMap = newGatewayConverter.GetCurrenciesMap();
            if (!currencyMap.count(ASSETCHAINS_CHAINID) ||
                !currencyMap.count(newChainID) ||
                newGatewayConverter.weights[currencyMap[ASSETCHAINS_CHAINID]] < (SATOSHIDEN / 10) ||
                newGatewayConverter.weights[currencyMap[newChainID]] < (SATOSHIDEN / 10))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "A gateway currency must be a fractional token that includes both the launch coin and PBaaS native coin at 10% or greater ratio each");
            }
        }
        else if (params.size() > 1)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters. Please see help.");
        }
    }
    else if (!newChain.gatewayConverterName.empty() || params.size() > 1)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "A second currency definition is only supported as a converter currency for a PBaaS chain or gateway");
    }

    // now, we have one or two currencies. if we have two, it is because the first is a PBaaS chain, and the second
    // is its gateway currency. We will create an ID and currency launch definition for the new currency. The ID will
    // be controlled by the same primary addresses and have the same revocation and recovery IDs as the primary ID.
    //
    // Create the outputs:
    // 1. Updated identity with active currency
    // 2. Currency definition
    // 3. Notarization thread
    // 4. Export thread - working to deprecate
    // 4. Import thread (if PBaaS, this is for imports from the PBaaS chain)
    // 5. Initial contribution exports
    // (optional for PBaaS chain or gateway):
    // 6. Converter currency ID with active currency
    // 7. Converter currency definition for start on the new PBaaS chain, pre-launching from current chain
    // 3. Converter notarization thread
    // 4. Converter export thread - working to deprecate
    // 8. Converter import thread (for imports to gateway currency from PBaaS chain for this chain as well)
    // ensure that the appropriate identity is an input to the transaction,
    // and fund the transaction

    // first, we need the identity output with currency activated
    launchIdentity.UpgradeVersion(height);
    launchIdentity.ActivateCurrency();
    if (newChain.IsNFTToken())
    {
        launchIdentity.ActivateTokenizedControl();
    }
    tb.AddTransparentOutput(launchIdentity.IdentityUpdateOutputScript(height + 1), 0);

    // now, create the currency definition output
    CCcontract_info CC;
    CCcontract_info *cp;
    cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
    CPubKey pk(ParseHex(CC.CChexstr));

    std::vector<CTxDestination> dests({pk});

    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &newChain)), 
                                         CCurrencyDefinition::DEFAULT_OUTPUT_VALUE);

    CAmount mainImportFee = ConnectedChains.ThisChain().LaunchFeeImportShare(newChain.options);
    CCurrencyValueMap mainImportFees(std::vector<uint160>({thisChainID}), std::vector<CAmount>({mainImportFee}));
    CAmount converterImportFee = 0;
    CAmount newReserveImportFees = 0;
    CCurrencyValueMap converterImportFees;

    CCoinbaseCurrencyState newCurrencyState;
    uint32_t lastImportHeight = newChain.IsPBaaSChain() || newChain.IsGateway() ? 1 : height;

    // if it's a mapped currency, we don't need to add anything but the definition with no launch period
    bool isMappedCurrency = newChain.IsToken() && !newChain.IsGateway() && !newChain.IsPBaaSChain() && !newChain.IsGatewayConverter() &&
                           newChain.nativeCurrencyID.IsValid() && parentCurrency.IsGateway() && newChain.systemID != ASSETCHAINS_CHAINID;

    // create import and export outputs
    cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
    pk = CPubKey(ParseHex(CC.CChexstr));

    if (newChain.proofProtocol == newChain.PROOF_PBAASMMR ||
        newChain.proofProtocol == newChain.PROOF_ETHNOTARIZATION ||
        newChain.proofProtocol == newChain.PROOF_CHAINID)
    {
        dests = std::vector<CTxDestination>({pk.GetID()});
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid notarization protocol specified");
    }

    CCrossChainImport cci = CCrossChainImport(newChain.SystemOrGatewayID(),
                                            lastImportHeight,
                                            newChainID,
                                            CCurrencyValueMap(),
                                            CCurrencyValueMap());
    cci.SetSameChain(newChain.systemID == ASSETCHAINS_CHAINID);
    cci.SetDefinitionImport(true);
    if (newChainID == ASSETCHAINS_CHAINID || newChain.IsGateway())
    {
        cci.SetPostLaunch();
        cci.SetInitialLaunchImport();
    }
    cci.exportTxOutNum = tb.mtx.vout.size() + 2;
    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci)), 0);

    // get initial currency state at this height
    newCurrencyState = ConnectedChains.GetCurrencyState(newChain, chainActive.Height());

    newCurrencyState.SetPrelaunch();

    CPBaaSNotarization pbn = CPBaaSNotarization(newChainID, 
                                                newCurrencyState,
                                                height,
                                                CUTXORef(),
                                                0);

    pbn.SetSameChain();
    pbn.SetDefinitionNotarization();
    pbn.nodes = startupNodes;

    if (newCurrencyState.GetID() == ASSETCHAINS_CHAINID || newChain.IsGateway() || isMappedCurrency)
    {
        newChain.startBlock = 1;
        newCurrencyState.SetPrelaunch(false);
        newCurrencyState.SetLaunchConfirmed();
        newCurrencyState.SetLaunchCompleteMarker();
        pbn.currencyState = newCurrencyState;
        pbn.SetPreLaunch(false);
        pbn.SetLaunchCleared();
        pbn.SetLaunchConfirmed();
        pbn.SetLaunchComplete();
    }
    else
    {
        pbn.SetPreLaunch();
    }

    // make the first chain notarization output
    cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
    CTxDestination notarizationDest;

    if (newChain.notarizationProtocol == newChain.NOTARIZATION_AUTO || newChain.notarizationProtocol == newChain.NOTARIZATION_NOTARY_CONFIRM)
    {
        notarizationDest = CPubKey(ParseHex(CC.CChexstr));
    }
    else if (newChain.notarizationProtocol == newChain.NOTARIZATION_NOTARY_CHAINID)
    {
        notarizationDest = CIdentityID(newChainID);
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "None or notarization protocol specified");
    }

    dests = std::vector<CTxDestination>({notarizationDest});

    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &pbn)), 
                                        CPBaaSNotarization::MIN_NOTARIZATION_OUTPUT);

    // export thread
    cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

    CCrossChainExport ccx = CCrossChainExport(thisChainID,
                                            0,
                                            height,
                                            (newChain.IsPBaaSChain() || newChain.IsGateway() || newChain.IsGatewayConverter()) ?
                                                newChain.SystemOrGatewayID() :
                                                ASSETCHAINS_CHAINID,
                                            newChainID,
                                            0,
                                            mainImportFees,
                                            mainImportFees,
                                            uint256());
    ccx.SetChainDefinition();
    if (newCurrencyState.GetID() == ASSETCHAINS_CHAINID || newChain.IsGateway() || isMappedCurrency)
    {
        ccx.SetPreLaunch(false);
        ccx.SetPostLaunch();
    }
    else
    {
        ccx.SetPreLaunch();
    }
    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx)), 0);

    // make the outputs for initial contributions
    if (newChain.contributions.size() && newChain.contributions.size() == newChain.currencies.size())
    {
        for (int i = 0; i < newChain.currencies.size(); i++)
        {
            if (newChain.contributions[i] > 0)
            {
                CAmount contribution = newChain.contributions[i] + 
                                        CReserveTransactionDescriptor::CalculateAdditionalConversionFee(newChain.contributions[i]);
                CAmount fee = CReserveTransfer::DEFAULT_PER_STEP_FEE << 1;

                CReserveTransfer rt = CReserveTransfer(CReserveTransfer::VALID + CReserveTransfer::PRECONVERT,
                                                    newChain.currencies[i],
                                                    contribution,
                                                    ASSETCHAINS_CHAINID,
                                                    fee,
                                                    newChainID,
                                                    DestinationToTransferDestination(CIdentityID(newChainID)));

                cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                CPubKey pk(ParseHex(CC.CChexstr));

                dests = std::vector<CTxDestination>({pk.GetID()});

                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt)), 
                                                    newChain.currencies[i] == thisChainID ? contribution + fee : fee);
            }
        }
    }

    CAmount totalLaunchFee = ConnectedChains.ThisChain().GetCurrencyRegistrationFee(newChain.options);
    CAmount notaryFeeShare = 0;

    // now, setup the gateway converter currency, if appropriate
    if ((newChain.IsPBaaSChain() || newChain.IsGateway()))
    {
        if (newGatewayConverter.IsValid())
        {
            cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);

            // create any new reserve currencies needed that are mapped to the gateway
            // for now, there is only an import fee for these currencies, since they do not launch
            for (auto oneNewReserve : newReserveCurrencies)
            {
                // define one currency
                // and add one import currency fee for each new reserve
                newReserveImportFees += ConnectedChains.ThisChain().currencyImportFee;
                std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &oneNewReserve.second)), 
                                                    CCurrencyDefinition::DEFAULT_OUTPUT_VALUE);
            }

            if (newChain.IsGateway() &&
                newChain.notaries.size() &&
                (newChain.notarizationProtocol == newChain.NOTARIZATION_AUTO ||
                 newChain.notarizationProtocol == newChain.NOTARIZATION_NOTARY_CONFIRM))
            {
                // notaries all get an even share of 10% of a currency launch fee to use for notarizing
                notaryFeeShare = ConnectedChains.ThisChain().GetCurrencyRegistrationFee(newChain.options) / 100;
                totalLaunchFee -= notaryFeeShare;
                CAmount oneNotaryShare = notaryFeeShare / newChain.notaries.size();
                CAmount notaryModExtra = notaryFeeShare % newChain.notaries.size();
                for (auto &oneNotary : newChain.notaries)
                {
                    tb.AddTransparentOutput(CIdentityID(oneNotary), notaryModExtra ? notaryModExtra--, oneNotaryShare + 1 : oneNotaryShare);
                }
            }

            newGatewayConverter.gatewayConverterIssuance = newChain.gatewayConverterIssuance;

            cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
            std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &newGatewayConverter)), 
                                                CCurrencyDefinition::DEFAULT_OUTPUT_VALUE);

            // get initial currency state at this height
            CCoinbaseCurrencyState gatewayCurrencyState = ConnectedChains.GetCurrencyState(newGatewayConverter, chainActive.Height());
            int currencyIndex = gatewayCurrencyState.GetReserveMap()[newChainID];

            gatewayCurrencyState.reserveIn[currencyIndex] += newChain.gatewayConverterIssuance;

            uint160 gatewayCurrencyID = newGatewayConverter.GetID();

            CPBaaSNotarization gatewayPbn = CPBaaSNotarization(gatewayCurrencyID, 
                                                            gatewayCurrencyState,
                                                            height,
                                                            CUTXORef(),
                                                            0);

            // launch notarizations are on this chain
            gatewayPbn.SetSameChain();
            gatewayPbn.SetPreLaunch();
            gatewayPbn.SetDefinitionNotarization();

            // create import and export outputs
            cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
            pk = CPubKey(ParseHex(CC.CChexstr));

            if (newGatewayConverter.proofProtocol == newGatewayConverter.PROOF_PBAASMMR ||
                newGatewayConverter.proofProtocol == newGatewayConverter.PROOF_CHAINID ||
                newGatewayConverter.proofProtocol == newGatewayConverter.PROOF_ETHNOTARIZATION)
            {
                dests = std::vector<CTxDestination>({pk.GetID()});
            }
            else
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "None or invalid notarization protocol specified");
            }

            // if this is a token on this chain, the transfer that is output here is burned through the export 
            // and merges with the import thread. we multiply new input times 2, to cover both the import thread output 
            // and the reserve transfer outputs.
            CCrossChainImport gatewayCci = CCrossChainImport(newGatewayConverter.systemID, lastImportHeight, gatewayCurrencyID, CCurrencyValueMap(), CCurrencyValueMap());
            gatewayCci.SetSameChain(newGatewayConverter.systemID == ASSETCHAINS_CHAINID);
            gatewayCci.SetDefinitionImport(true);

            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &gatewayCci)), 0);

            // make the first chain notarization output
            cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
            CTxDestination notarizationDest;

            if (newGatewayConverter.notarizationProtocol == newGatewayConverter.NOTARIZATION_AUTO || 
                newGatewayConverter.notarizationProtocol == newGatewayConverter.NOTARIZATION_NOTARY_CONFIRM)
            {
                notarizationDest = CPubKey(ParseHex(CC.CChexstr));
            }
            else if (newGatewayConverter.notarizationProtocol == newGatewayConverter.NOTARIZATION_NOTARY_CHAINID)
            {
                notarizationDest = CIdentityID(gatewayCurrencyID);
            }
            else
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "None or notarization protocol specified");
            }

            dests = std::vector<CTxDestination>({notarizationDest});

            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &gatewayPbn)), 
                                                CPBaaSNotarization::MIN_NOTARIZATION_OUTPUT);

            converterImportFee = ConnectedChains.ThisChain().LaunchFeeImportShare(newGatewayConverter.options);
            converterImportFees.valueMap[thisChainID] += converterImportFee;

            // export thread
            cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            CCrossChainExport gatewayCcx = CCrossChainExport(thisChainID, 0, height, newGatewayConverter.systemID, gatewayCurrencyID, 0, converterImportFees, converterImportFees, uint256());
            gatewayCcx.SetPreLaunch();
            gatewayCcx.SetChainDefinition();

            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &gatewayCcx)), 0);

            // make the outputs for initial contributions
            if (newGatewayConverter.contributions.size() && newGatewayConverter.contributions.size() == newGatewayConverter.currencies.size())
            {
                for (int i = 0; i < newGatewayConverter.currencies.size(); i++)
                {
                    if (newGatewayConverter.contributions[i] > 0)
                    {
                        CAmount contribution = newGatewayConverter.contributions[i] + 
                                                CReserveTransactionDescriptor::CalculateAdditionalConversionFee(newGatewayConverter.contributions[i]);
                        CAmount fee = CReserveTransfer::DEFAULT_PER_STEP_FEE << 1;

                        CReserveTransfer rt = CReserveTransfer(CReserveTransfer::VALID + CReserveTransfer::PRECONVERT,
                                                            newGatewayConverter.currencies[i],
                                                            contribution,
                                                            ASSETCHAINS_CHAINID,
                                                            fee,
                                                            gatewayCurrencyID,
                                                            DestinationToTransferDestination(CIdentityID(gatewayCurrencyID)));

                        cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                        CPubKey pk(ParseHex(CC.CChexstr));

                        dests = std::vector<CTxDestination>({pk.GetID()});

                        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt)), 
                                                            newGatewayConverter.currencies[i] == thisChainID ? contribution + fee : fee);
                    }
                }
            }
        }
    }

    // figure all launch fees, including export and import
    if (converterImportFee)
    {
        totalLaunchFee += ConnectedChains.ThisChain().GetCurrencyRegistrationFee(newGatewayConverter.options);
    }
    totalLaunchFee += newReserveImportFees;

    CAmount totalLaunchExportFee = totalLaunchFee - (mainImportFee + converterImportFee);
    if (newCurrencyState.IsValid() && newCurrencyState.GetID() != ASSETCHAINS_CHAINID && !isMappedCurrency)
    {
        cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);
        pk = CPubKey(ParseHex(CC.CChexstr));
        dests = std::vector<CTxDestination>({pk});

        CReserveDeposit launchDeposit = CReserveDeposit(newChainID, CCurrencyValueMap());
        if (mainImportFee)
        {
            launchDeposit.reserveValues.valueMap[ASSETCHAINS_CHAINID] = mainImportFee;
        }
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &launchDeposit)), 
                                            mainImportFee);
    }
    tb.SetFee(totalLaunchExportFee);
    tb.SendChangeTo(launchIdentity.GetID());

    if (newGatewayConverter.IsValid())
    {
        uint160 gatewayDepositCurrencyID = newGatewayConverter.systemID == thisChainID ? 
                                           newGatewayConverter.GetID() :
                                           newGatewayConverter.systemID;
        CReserveDeposit launchDeposit = CReserveDeposit(gatewayDepositCurrencyID, CCurrencyValueMap());
        if (converterImportFee)
        {
            launchDeposit.reserveValues.valueMap[ASSETCHAINS_CHAINID] = converterImportFee;
        }
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &launchDeposit)), 
                                            converterImportFee);
    }

    // create the transaction
    CReserveTransactionDescriptor rtxd;
    {
        LOCK(mempool.cs);
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);
        rtxd = CReserveTransactionDescriptor(tb.mtx, view, height + 1);
    }

    // get a native currency input capable of paying a fee, and make our notary ID the change address
    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
    std::vector<COutput> vCoins;
    CCurrencyValueMap totalReservesNeeded = rtxd.ReserveOutputMap();
    CCurrencyValueMap totalCurrenciesNeeded = totalReservesNeeded;
    totalCurrenciesNeeded.valueMap[ASSETCHAINS_CHAINID] = rtxd.nativeOut + totalLaunchExportFee;
    CTxDestination fromID(CIdentityID(launchIdentity.GetID()));
    pwalletMain->AvailableReserveCoins(vCoins,
                                       false,
                                       nullptr,
                                       true,
                                       true,
                                       &fromID,
                                       &totalCurrenciesNeeded, 
                                       false);

    for (COutput &out : vCoins) 
    {
        std::vector<CTxDestination> addresses;
        int nRequired;
        bool canSign, canSpend;
        CTxDestination address;
        txnouttype txType;
        if (!ExtractDestinations(out.tx->vout[out.i].scriptPubKey, txType, addresses, nRequired, pwalletMain, &canSign, &canSpend))
        {
            continue;
        }

        // if we have more address destinations than just this address and have specified from a single ID only,
        // the condition must be such that the ID itself can spend, even if this wallet cannot due to a multisig
        // ID. if the ID cannot spend, even given a valid multisig ID, then to select this as a source without
        // an explicit, multisig match would cause potentially unwanted sourcing of funds. a spend just to this ID
        // is fine.

        COptCCParams p, m;
        // if we can't spend and can only sign,
        // ensure that this output is spendable by just this ID as a 1 of n and 1 of n at the master
        // smart transaction level as well
        if (!canSpend &&
            (!canSign ||
                !(out.tx->vout[out.i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                (p.version < COptCCParams::VERSION_V3 ||
                (p.vData.size() &&
                    (m = COptCCParams(p.vData.back())).IsValid() &&
                    (m.m == 1 || m.m == 0))) &&
                p.m == 1)))
        {
            continue;
        }
        else
        {
            out.fSpendable = true;      // this may not really be spendable, but set it if its the correct ID source and can sign
        }
    }

    CCurrencyValueMap reservesUsed;
    CAmount nativeUsed;
    if (!pwalletMain->SelectReserveCoinsMinConf(rtxd.ReserveOutputMap(),
                                                rtxd.nativeOut + totalLaunchExportFee,
                                                0,
                                                1,
                                                vCoins,
                                                setCoinsRet,
                                                reservesUsed,
                                                nativeUsed))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Insufficient funds held by " + launchIdentity.name + " identity.");
    }

    for (auto &oneInput : setCoinsRet)
    {
        tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second), 
                                                oneInput.first->vout[oneInput.second].scriptPubKey,
                                                oneInput.first->vout[oneInput.second].nValue);
    }

    auto builtTxResult = tb.Build(true);

    CTransaction retTx;
    bool partialSig = !builtTxResult.IsTx() && IsHex(builtTxResult.GetError()) && DecodeHexTx(retTx, builtTxResult.GetError());

    if (!builtTxResult.IsTx() && !partialSig)
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, newChain.name + ": " + builtTxResult.GetError());
    }
    else if (!partialSig)
    {
        retTx = builtTxResult.GetTxOrThrow();
    }

    UniValue uvret(UniValue::VOBJ);
    UniValue txJSon(UniValue::VOBJ);
    TxToJSON(retTx, uint256(), txJSon);
    uvret.push_back(Pair("tx",  txJSon));

    string strHex = EncodeHexTx(retTx);
    uvret.push_back(Pair("hex", strHex));

    return uvret;
}

UniValue registernamecommitment(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() < 2 || params.size() > 5))
    {
        throw runtime_error(
            "registernamecommitment \"name\" \"controladdress\" (\"referralidentity\") (\"parentnameorid\") (\"sourceoffunds\")\n"
            "\nRegisters a name commitment, which is required as a source for the name to be used when registering an identity. The name commitment hides the name itself\n"
            "while ensuring that the miner who mines in the registration cannot front-run the name unless they have also registered a name commitment for the same name or\n"
            "are willing to forfeit the offer of payment for the chance that a commitment made now will allow them to register the name in the future.\n"

            "\nArguments\n"
            "\"name\"                           (string, required)  the unique name to commit to. creating a name commitment is not a registration, and if one is\n"
            "                                                       created for a name that exists, it may succeed, but will never be able to be used.\n"
            "\"controladdress\"                 (address, required) address that will control this commitment\n"
            "\"referralidentity\"               (identity, optional)friendly name or identity address that is provided as a referral mechanism and to lower network cost of the ID\n"
            "\"parentnameorid-pbaasonly\"       (currency, optional)friendly name or currency i-address, which will be the parent of this ID and dictate issuance rules & pricing\n"
            "\"sourceoffunds\"                  (addressorid, optional) optional address to use for source of funds. if not specified, transparent wildcard \"*\" is used\n\n"

            "\nResult: obj\n"
            "{\n"
            "    \"txid\" : \"hexid\"\n"
            "    \"namereservation\" :\n"
            "    {\n"
            "        \"name\"    : \"namestr\",     (string) the unique name in this commitment\n"
            "        \"salt\"    : \"hexstr\",      (hex)    salt used to hide the commitment\n"
            "        \"referral\": \"identityaddress\", (base58) address of the referring identity if there is one\n"
            "        \"parent\"  : \"namestr\",     (string) name of the parent if not Verus or Verus test\n"
            "        \"nameid\"  : \"address\",     (base58) identity address for this identity if it is created\n"
            "    }\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("registernamecommitment", "\"name\"")
            + HelpExampleRpc("registernamecommitment", "\"name\"")
        );
    }

    CheckIdentityAPIsValid();

    // create the transaction with native coin as input
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint32_t height = chainActive.Height();
    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_PBAAS;

    CCurrencyDefinition parentCurrency = ConnectedChains.ThisChain();
    uint160 parentID = parentCurrency.GetID();

    if (params.size() > 3 && !uni_get_str(params[3]).empty())
    {
        if (!isPBaaS)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot issue identities from specified parent currencies until after PBaaS activates");
        }
        parentID = ValidateCurrencyName(uni_get_str(params[3]), true, &parentCurrency);

        if (!parentCurrency.IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parent currency");
        }
    }

    std::string sourceAddress;
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = false;
    bool wildCardRAddress = false;
    bool wildCardiAddress = false;
    bool wildCardAddress = false;

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 sourceOvk;
    bool hasZSource = false;

    if (params.size() > 4)
    {
        sourceAddress = uni_get_str(params[4]);

        wildCardTransparentAddress = sourceAddress == "*";
        wildCardRAddress = sourceAddress == "R*";
        wildCardiAddress = sourceAddress == "i*";
        wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;
        hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddressSource);

        // if we have a z-address as a source, re-encode it to a string, which is used
        // by the async operation, to ensure that we don't need to lookup IDs in that operation
        if (hasZSource)
        {
            sourceAddress = EncodePaymentAddress(zaddressSource);
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
            }

            auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
            auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
            expsk = sk.expsk;
            sourceOvk = expsk.full_viewing_key().ovk;
        }

        if (!(hasZSource ||
            wildCardAddress ||
            (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
        }
    }

    // if we are registering an identity through a gateway, we can and should redirect fee payment through its
    // fee converter currency

    // TODO: PBAAS - enable PBaaS chains to issue IDs through their gateway converter IDs as gateways can

    CCurrencyDefinition issuingCurrency = parentCurrency;
    uint160 issuerID = parentID;
    if (!parentCurrency.IsNameController() && parentCurrency.launchSystemID == ASSETCHAINS_CHAINID && !parentCurrency.GatewayConverterID().IsNull())
    {
        issuingCurrency = ConnectedChains.GetCachedCurrency(parentCurrency.GatewayConverterID());
        if (!issuingCurrency.IsValid() || issuingCurrency.systemID != ASSETCHAINS_CHAINID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid issuing currency for this network");
        }
    }
    else if (parentCurrency.systemID != ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parent currency for this network");
    }

    std::string name = CleanName(uni_get_str(params[0]), parentID, true, true);
    if (parentID != parentCurrency.GetID())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid implied parent currency");
    }

    uint160 idID = GetDestinationID(DecodeDestination(name + "@"));
    if (idID == ASSETCHAINS_CHAINID && IsVerusActive())
    {
        name = VERUS_CHAINNAME;
        parentID.SetNull();
    }

    // if either we have an invalid name or an implied parent, that is not valid
    if (!(idID == VERUS_CHAINID && IsVerusActive() && parentID.IsNull()) &&
         (name == "" || parentID != parentCurrency.GetID() || name != uni_get_str(params[0])))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid name for commitment. Names must not have leading or trailing spaces and must not include any of the following characters between parentheses (\\/:*?\"<>|@)");
    }

    CTxDestination dest = DecodeDestination(uni_get_str(params[1]));
    if (dest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid control address for commitment");
    }

    CIdentityID referrer;
    if (params.size() > 2 && !uni_get_str(params[2]).empty())
    {
        CTxDestination referDest = DecodeDestination(uni_get_str(params[2]));
        if (referDest.which() != COptCCParams::ADDRTYPE_ID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid referral identity for commitment, must be a currently registered friendly name or i-address");
        }
        referrer = CIdentityID(GetDestinationID(referDest));
        CIdentity referrerIdentity = CIdentity::LookupIdentity(referrer);
        if (!referrerIdentity.IsValidUnrevoked())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Referral identity for commitment must be a currently valid, unrevoked friendly name or i-address");
        }
        if (referrerIdentity.parent != parentID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Referrals must be from an identity of the same parent");
        }
    }

    CNameReservation nameRes;
    CAdvancedNameReservation advNameRes;

    if (isPBaaS && !parentID.IsNull())
    {
        advNameRes = CAdvancedNameReservation(name, parentID, referrer, GetRandHash());
    }
    else
    {
        nameRes = CNameReservation(name, referrer, GetRandHash());
    }

    if (CIdentity::LookupIdentity(CIdentity::GetID(name, parentID)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity already exists.");
    }

    if (params.size() <= 4)
    {
        wildCardTransparentAddress = true;
    }

    bool success = false;
    std::vector<CRecipient> newInputs;
    CTxDestination changeDest;

    std::vector<CTxDestination> dests({dest});
    int requiredSigs = 1;

    if (parentCurrency.IDRequiresPermission())
    {
        dests.push_back(CIdentityID(parentID));
        requiredSigs = 2;
    }
    else if (parentCurrency.IDReferralRequired())
    {
        dests.push_back(CIdentityID(referrer));
        requiredSigs = 2;
    }

    CCommitmentHash commitment(advNameRes.IsValid() ? advNameRes.GetCommitment() : nameRes.GetCommitment());
    CConditionObj<CCommitmentHash> condObj(EVAL_IDENTITY_COMMITMENT, dests, requiredSigs, &commitment);
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{MakeMofNCCScript(condObj, &dest), CCommitmentHash::DEFAULT_OUTPUT_AMOUNT, false}});

    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
    std::vector<SaplingNoteEntry> saplingNotes;
    CCurrencyValueMap reserveValueOut;
    CAmount nativeValueOut;
    std::vector<COutput> vCoins;

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    CCurrencyValueMap reservesOut;
    for (int i = 0; i < outputs.size(); i++)
    {
        CRecipient &oneOut = outputs[i];

        CCurrencyValueMap oneOutReserves;
        oneOutReserves += oneOut.scriptPubKey.ReserveOutValue();
        if (oneOut.nAmount)
        {
            oneOutReserves.valueMap[ASSETCHAINS_CHAINID] = oneOut.nAmount;
        }
        else
        {
            oneOutReserves.valueMap.erase(ASSETCHAINS_CHAINID);
        }
        reservesOut += oneOutReserves;
    }

    reservesOut = reservesOut.CanonicalMap();

    // use the transaction builder to properly make change of native and reserves
    TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

    // make sure we have enough
    CAmount nativeNeeded = CCommitmentHash::DEFAULT_OUTPUT_AMOUNT + DEFAULT_TRANSACTION_FEE;

    for (auto &oneOut : outputs)
    {
        tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nAmount);
    }

    if (hasZSource)
    {
        saplingNotes = find_unspent_notes(zaddressSource);
        CAmount totalFound = 0;
        int i;
        for (i = 0; i < saplingNotes.size(); i++)
        {
            totalFound += saplingNotes[i].note.value();
            if (totalFound >= nativeNeeded)
            {
                break;
            }
        }
        // remove all but the notes we'll use
        if (i < saplingNotes.size())
        {
            saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
            success = true;
        }
    }
    else
    {
        success = find_utxos(from_taddress, vCoins) &&
                pwalletMain->SelectCoinsMinConf(nativeNeeded, 0, 0, vCoins, setCoinsRet, nativeValueOut);
    }

    if (!success)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient funds for identity registration");
    }

    // aggregate all inputs into one output with only the offer coins and offer indexes
    if (saplingNotes.size())
    {
        std::vector<SaplingOutPoint> notes;
        for (auto &oneNoteInfo : saplingNotes)
        {
            notes.push_back(oneNoteInfo.op);
        }

        // Fetch Sapling anchor and witnesses
        uint256 anchor;
        std::vector<boost::optional<SaplingWitness>> witnesses;
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
        }

        // Add Sapling spends
        for (size_t i = 0; i < saplingNotes.size(); i++)
        {
            tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());
        }
    }
    else
    {
        for (auto &oneInput : setCoinsRet)
        {
            tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                    oneInput.first->vout[oneInput.second].scriptPubKey,
                                    oneInput.first->vout[oneInput.second].nValue);
        }
    }

    if (hasZSource)
    {
        tb.SendChangeTo(*boost::get<libzcash::SaplingPaymentAddress>(&zaddressSource), sourceOvk);
    }
    else if (sourceDest.which() != COptCCParams::ADDRTYPE_INVALID && !GetDestinationID(sourceDest).IsNull())
    {
        tb.SendChangeTo(sourceDest);
        changeDest = sourceDest;
    }
    else
    {
        tb.SendChangeTo(dest);
        changeDest = dest;
    }

    TransactionBuilderResult preResult = tb.Build();
    CTransaction commitTx = preResult.GetTxOrThrow();

    // add to mem pool and relay
    LOCK(cs_main);

    bool relayTx;
    CValidationState state;
    {
        LOCK2(smartTransactionCS, mempool.cs);
        relayTx = myAddtomempool(commitTx, &state);
    }

    if (!relayTx)
    {
        throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to prepare offer tx: " + state.GetRejectReason());
    }
    else
    {
        RelayTransaction(commitTx);
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("txid", commitTx.GetHash().GetHex()));
    ret.push_back(Pair("namereservation", advNameRes.IsValid() ? advNameRes.ToUniValue() : nameRes.ToUniValue()));
    return ret;
}

UniValue registeridentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 5)
    {
        throw runtime_error(
            "registeridentity \"jsonidregistration\" (returntx) feeoffer sourceoffunds\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"txid\" : \"hexid\",          (hex)    the transaction ID of the name commitment for this ID name\n"
            "    \"namereservation\" :\n"
            "    {\n"
            "        \"name\": \"namestr\",     (string) the unique name in this commitment\n"
            "        \"salt\": \"hexstr\",      (hex)    salt used to hide the commitment\n"
            "        \"referrer\": \"identityID\", (name@ or address) must be a valid ID to use as a referrer to receive a discount\n"
            "    },\n"
            "    \"identity\" :\n"
            "    {\n"
            "        \"name\": \"namestr\",     (string) the unique name for this identity\n"
            "        ...\n"
            "    }\n"
            "}\n"
            "returntx                           (bool, optional) default=false if true, return a transaction for additional signatures rather than committing it\n"
            "feeoffer                           (amount, optional) amount to offer miner/staker for the registration fee, if missing, uses standard price\n"
            "sourceoffunds                      (addressorid, optional) optional address to use for source of funds. if not specified, transparent wildcard \"*\" is used\n\n"

            "\nResult:\n"
            "   transactionid                   (hexstr)\n"

            "\nExamples:\n"
            + HelpExampleCli("registeridentity", "jsonidregistration")
            + HelpExampleRpc("registeridentity", "jsonidregistration")
        );
    }

    CheckIdentityAPIsValid();

    // all names have a parent of the current chain
    uint160 parent = ConnectedChains.ThisChain().GetID();

    uint256 txid = uint256S(uni_get_str(find_value(params[0], "txid")));

    UniValue nameResUni = find_value(params[0], "namereservation");

    // lookup commitment to be sure that we can register this identity
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint32_t height = chainActive.Height();
    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(height + 1) >= CActivationHeight::ACTIVATE_PBAAS;

    CNameReservation reservation;
    CAdvancedNameReservation advReservation;
    if (!find_value(nameResUni, "version").isNull() && !find_value(nameResUni, "parent").isNull())
    {
        if (!isPBaaS)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Advanced identity reservations are only valid after PBaaS activates");
        }
        advReservation = CAdvancedNameReservation(nameResUni);
    }
    else
    {
        reservation = CNameReservation(nameResUni);
    }

    UniValue rawID = find_value(params[0], "identity");

    if (uni_get_int(find_value(rawID,"version")) == 0)
    {
        rawID.pushKV("version", 
                     CConstVerusSolutionVector::GetVersionByHeight(height + 1) >= CActivationHeight::ACTIVATE_VERUSVAULT ? 
                        CIdentity::VERSION_VAULT :
                        CIdentity::VERSION_VERUSID);
    }

    if (uni_get_int(find_value(rawID,"minimumsignatures")) == 0)
    {
        rawID.pushKV("minimumsignatures", (int32_t)1);
    }

    CCurrencyDefinition parentCurrency = ConnectedChains.GetCachedCurrency(advReservation.IsValid() ? advReservation.parent : parent);
    if (!parentCurrency.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parent currency or currency not found");
    }

    CCurrencyDefinition issuingCurrency = parentCurrency;
    parent = parentCurrency.GetID();
    uint160 issuerID = issuingCurrency.GetID();

    CIdentity newID(rawID);
    if (!newID.IsValid(true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity");
    }

    uint32_t solVersion = CConstVerusSolutionVector::GetVersionByHeight(height + 1);

    if (solVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
    {
        newID.SetVersion(solVersion < CActivationHeight::ACTIVATE_PBAAS ? CIdentity::VERSION_VAULT : CIdentity::VERSION_PBAAS);
    }
    else
    {
        newID.SetVersion(CIdentity::VERSION_VERUSID);
    }

    if (IsVerusActive())
    {
        CIdentity checkIdentity(newID);
        checkIdentity.parent.SetNull();
        if (checkIdentity.GetID() == ASSETCHAINS_CHAINID)
        {
            newID.parent.SetNull();
            parent.SetNull();
        }
    }
    else
    {
        newID.parent = parent;
    }

    newID.systemID = ASSETCHAINS_CHAINID;

    uint160 newIDID = newID.GetID();

    if (find_value(rawID, "revocationauthority").isNull())
    {
        newID.revocationAuthority = newID.GetID();
    }
    if (find_value(rawID, "recoveryauthority").isNull())
    {
        newID.recoveryAuthority = newID.GetID();
    }

    bool returnTx = params.size() > 1 ? uni_get_bool(params[1]) : false;

    // get the primary currency to price in and apply any conversion rates
    uint160 parentID = parentCurrency.GetID();
    issuerID = issuingCurrency.GetID();
    uint160 feePricingCurrency = issuerID;
    int64_t idReferralFee = issuingCurrency.IDReferralAmount();
    int64_t idFullRegistrationFee = issuingCurrency.IDFullRegistrationAmount();
    int64_t idReferredRegistrationFee = issuingCurrency.IDReferredRegistrationAmount();
    CCurrencyValueMap burnAmount;
    CCoinbaseCurrencyState pricingState;

    // set currency and price, as well as burn requirement
    // determine if we may use a gateway converter to issue

    if (isPBaaS)
    {
        if (!issuingCurrency.IsNameController() && !issuingCurrency.GatewayConverterID().IsNull())
        {
            issuingCurrency = ConnectedChains.GetCachedCurrency(issuingCurrency.GatewayConverterID());
            if (!(issuingCurrency.IsValid() &&
                 issuingCurrency.IsFractional() &&
                 issuingCurrency.IsGatewayConverter() &&
                 issuingCurrency.gatewayID == parentID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid converter for gateway to register identity");
            }
            issuerID = issuingCurrency.GetID();
        }
        else if (issuingCurrency.IsGatewayConverter())
        {
            if (issuingCurrency.gatewayID.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid gateway converter for identity registration");
            }
            CCurrencyDefinition gatewayCurrency = ConnectedChains.GetCachedCurrency(issuingCurrency.gatewayID);
            if (gatewayCurrency.GetID() != issuingCurrency.systemID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid gateway converter system for identity registration");
            }
        }
        if (!issuingCurrency.IsValid() || issuingCurrency.systemID != ASSETCHAINS_CHAINID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid issuing currency to register identity");
        }

        if (issuingCurrency.IsFractional())
        {
            feePricingCurrency = issuingCurrency.FeePricingCurrency();
            if (!(pricingState = ConnectedChains.GetCurrencyState(issuerID, height)).IsValid() ||
                !pricingState.IsLaunchConfirmed())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency state for gateway converter to register identity");
            }
            if (feePricingCurrency != issuerID)
            {
                int32_t reserveIndex = pricingState.GetReserveMap()[feePricingCurrency];
                idReferralFee = pricingState.ReserveToNative(idReferralFee, reserveIndex);
                idFullRegistrationFee = pricingState.ReserveToNative(idFullRegistrationFee, reserveIndex);
                idReferredRegistrationFee = pricingState.ReserveToNative(idReferredRegistrationFee, reserveIndex);
            }
        }
        // aside from fractional currencies, centralized or native currencies can issue IDs
        else if (!(issuingCurrency.GetID() == ASSETCHAINS_CHAINID || issuingCurrency.proofProtocol == issuingCurrency.PROOF_CHAINID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parent currency for identity registration on this chain");
        }
    }

    CAmount feeOffer = 0;
    CIdentityID referralID = advReservation.IsValid() ? advReservation.referral : reservation.referral;
    CAmount minFeeOffer = referralID.IsNull() ? idFullRegistrationFee : idReferredRegistrationFee;

    if (params.size() > 2)
    {
        feeOffer = AmountFromValue(params[2]);
    }
    if (feeOffer == 0)
    {
        feeOffer = minFeeOffer;
    }

    if (feeOffer < minFeeOffer)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee offer must be at least " + ValueFromAmount(minFeeOffer).write());
    }

    std::string sourceAddress;
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = false;
    bool wildCardRAddress = false;
    bool wildCardiAddress = false;
    bool wildCardAddress = false;

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 sourceOvk;
    bool hasZSource = false;

    if (params.size() > 3)
    {
        sourceAddress = uni_get_str(params[3]);

        wildCardTransparentAddress = sourceAddress == "*";
        wildCardRAddress = sourceAddress == "R*";
        wildCardiAddress = sourceAddress == "i*";
        wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;
        hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddressSource);

        // if we have a z-address as a source, re-encode it to a string, which is used
        // by the async operation, to ensure that we don't need to lookup IDs in that operation
        if (hasZSource)
        {
            sourceAddress = EncodePaymentAddress(zaddressSource);
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
            }

            auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
            auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
            expsk = sk.expsk;
            sourceOvk = expsk.full_viewing_key().ovk;
        }

        if (!(hasZSource ||
            wildCardAddress ||
            (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
        }
    }

    // this is only used to actually create errors and is normally not
    // a parameter used for anything except testing
    enum {
        ERRTEST_NONE = 0,
        ERRTEST_UNDERPAYFEE = 1,
        ERRTEST_UNDERPAYREFERRAL = 2,
        ERRTEST_SKIPREFERRAL = 3,
        ERRTEST_WRONGREFERRAL = 4,
        ERRTEST_LAST = 4
    };
    int errorTest = ERRTEST_NONE;
    if (params.size() > 4)
    {
        errorTest = uni_get_int(params[4]);
        if (errorTest < ERRTEST_NONE || errorTest > ERRTEST_LAST)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Optional test parameter out of range");
        }
    }

    uint160 impliedParent, resParent;
    if (advReservation.IsValid())
    {
        resParent = advReservation.parent;
        impliedParent = newID.parent;
        if (txid.IsNull() || 
            CleanName(advReservation.name, resParent) != CleanName(newID.name, impliedParent) || 
            resParent != impliedParent)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity description or mismatched advanced reservation. Is " + CleanName(newID.name, impliedParent) + " should be " + CleanName(advReservation.name, resParent) + ".");
        }
    }
    else
    {
        if (txid.IsNull() || 
            CleanName(reservation.name, resParent) != CleanName(newID.name, impliedParent) || 
            resParent != impliedParent)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity description or mismatched reservation.");
        }
    }

    uint256 hashBlk;
    CTransaction txOut;
    CCommitmentHash ch;
    int commitmentOutput;

    uint32_t commitmentHeight;

    // make sure we have a revocation and recovery authority defined
    CIdentity revocationAuth = newID.revocationAuthority == newIDID ? newID : newID.LookupIdentity(newID.revocationAuthority);
    CIdentity recoveryAuth = newID.recoveryAuthority == newIDID ? newID : newID.LookupIdentity(newID.recoveryAuthority);

    if (!recoveryAuth.IsValidUnrevoked() || !revocationAuth.IsValidUnrevoked())
    {
        if (newIDID == ASSETCHAINS_CHAINID)
        {
            revocationAuth = newID;
            recoveryAuth = newID;
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or revoked recovery, or revocation identity.");
        }
    }

    CTxDestination commitmentOutDest;

    // must be present and in a mined block
    {
        {
            LOCK(mempool.cs);
            if (!myGetTransaction(txid, txOut, hashBlk) || hashBlk.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or unconfirmed commitment transaction id");
            }
        }

        auto indexIt = mapBlockIndex.find(hashBlk);
        if (indexIt == mapBlockIndex.end() || indexIt->second->GetHeight() > chainActive.Height() || chainActive[indexIt->second->GetHeight()]->GetBlockHash() != indexIt->second->GetBlockHash())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or unconfirmed commitment");
        }

        commitmentHeight = indexIt->second->GetHeight();

        for (int i = 0; i < txOut.vout.size(); i++)
        {
            COptCCParams p;
            if (txOut.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT && p.vData.size())
            {
                commitmentOutput = i;
                ::FromVector(p.vData[0], ch);
                std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
                for (auto &oneKey : p.vKeys)
                {
                    if (oneKey.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        std::pair<CIdentityMapKey, CIdentityMapValue> checkKeyAndIdentity;
                        if (pwalletMain->GetIdentity(GetDestinationID(oneKey), checkKeyAndIdentity))
                        {
                            if (checkKeyAndIdentity.first.CanSign())
                            {
                                keyAndIdentity = checkKeyAndIdentity;
                                if (keyAndIdentity.first.CanSpend())
                                {
                                    commitmentOutDest = oneKey;
                                    break;
                                }
                            }
                        }
                    }
                    else if (oneKey.which() == COptCCParams::ADDRTYPE_PKH || oneKey.which() == COptCCParams::ADDRTYPE_PK)
                    {
                        if (pwalletMain->HaveKey(GetDestinationID(oneKey)))
                        {
                            commitmentOutDest = oneKey;
                            break;
                        }
                    }
                    else if (oneKey.which() == COptCCParams::ADDRTYPE_SH)
                    {
                        if (pwalletMain->HaveCScript(GetDestinationID(oneKey)))
                        {
                            commitmentOutDest = oneKey;
                            break;
                        }
                    }
                }
                if (commitmentOutDest.which() == COptCCParams::ADDRTYPE_INVALID && keyAndIdentity.second.IsValid() && keyAndIdentity.first.CanSign())
                {
                    commitmentOutDest = keyAndIdentity.first.idID;
                }
                break;
            }
        }
        if (ch.hash.IsNull() || commitmentOutDest.which() == COptCCParams::ADDRTYPE_INVALID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid commitment hash");
        }
    }

    if (ch.hash != (advReservation.IsValid() ? advReservation.GetCommitment().hash : reservation.GetCommitment().hash))
    {
        uint256 gotHash = ch.hash;
        uint256 expectedHash = (advReservation.IsValid() ? advReservation.GetCommitment().hash : reservation.GetCommitment().hash);
        
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid commitment salt or referral ID, got hash: " + gotHash.GetHex() + ", expected: " + expectedHash.GetHex());
    }

    // until PBaaS, the parent is generally the current chains, and it is invalid to specify a parent
    if (newID.parent != parent)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid to specify alternate parent when creating an identity. Parent is determined by the current blockchain.");
    }

    CIdentity dupID = newID.LookupIdentity(newID.GetID());
    if (dupID.IsValid())
    {
        throw JSONRPCError(RPC_VERIFY_ALREADY_IN_CHAIN, "Identity already exists.");
    }

    // create the identity definition transaction
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(height + 1), 0, false}});
    int32_t registrationPaymentOut = -1;

    int64_t expectedFee = referralID.IsNull() ? feeOffer : feeOffer - idReferralFee;

    if (issuingCurrency.proofProtocol == issuingCurrency.PROOF_CHAINID)
    {
        if (issuerID == ASSETCHAINS_CHAINID)
        {
            // make an output to the currency ID of the amount less referrers
            registrationPaymentOut = outputs.size();
            outputs.push_back({CIdentity::TransparentOutput(issuerID), expectedFee, false});
        }
        else
        {
            // make an output to the currency ID of the amount less referrers
            CTokenOutput to(CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({expectedFee})));
            registrationPaymentOut = outputs.size();
            outputs.push_back({MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({CIdentityID(issuerID)}), 1, &to)), 0, false});
        }
    }
    else if (issuingCurrency.IsFractional())
    {
        // make a burn output of this currency for the amount
        CReserveTransfer rt(CReserveTransfer::VALID + CReserveTransfer::BURN_CHANGE_PRICE,
                            CCurrencyValueMap(std::vector<uint160>({issuerID}),
                            std::vector<int64_t>({expectedFee})),
                            ASSETCHAINS_CHAINID,
                            ConnectedChains.ThisChain().GetTransactionTransferFee(),
                            issuerID,
                            DestinationToTransferDestination(CIdentityID(issuerID)));
        registrationPaymentOut = outputs.size();

        CCcontract_info CC;
        CCcontract_info *cp;
        cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
        CPubKey pk(ParseHex(CC.CChexstr));

        std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

        outputs.push_back({MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt)), ConnectedChains.ThisChain().GetTransactionTransferFee(), false});
    }

    // wrong referral refers to the source identity instead of specified referral address
    if (errorTest == ERRTEST_WRONGREFERRAL)
    {
        referralID = GetDestinationID(sourceDest);
    }

    // add referrals if any
    if (errorTest != ERRTEST_SKIPREFERRAL &&
        !newID.parent.IsNull() &&
        (parentCurrency.IDReferrals() || (newID.parent == ASSETCHAINS_CHAINID && IsVerusActive())) &&
        !referralID.IsNull())
    {
        uint32_t referralHeight;
        CTxIn referralTxIn;
        CTransaction referralIdTx;
        auto referralIdentity = newID.LookupIdentity(referralID, commitmentHeight - 1);

        if (referralIdentity.IsValidUnrevoked() &&
            referralIdentity.systemID == ASSETCHAINS_CHAINID &&
            newID.systemID == ASSETCHAINS_CHAINID &&
            (referralIdentity.parent == newID.parent || ((referralID != ASSETCHAINS_CHAINID || !ConnectedChains.ThisChain().parent.IsNull()) && referralID == newID.parent)))
        {
            if (!newID.LookupFirstIdentity(referralID, &referralHeight, &referralTxIn, &referralIdTx).IsValid())
            {
                throw JSONRPCError(RPC_DATABASE_ERROR, "Database or blockchain data error, \"" + referralIdentity.name + "\" seems valid, but first instance is not found in index");
            }

            if (errorTest == ERRTEST_UNDERPAYREFERRAL)
            {
                idReferralFee >>= 1;
            }

            // create outputs for this referral and up to n identities back in the referral chain
            if (issuerID == ASSETCHAINS_CHAINID)
            {
                outputs.push_back({newID.TransparentOutput(referralIdentity.GetID()), idReferralFee, false});
            }
            else
            {
                // make an output to the currency ID of the amount less referrers
                CTokenOutput to(CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({idReferralFee})));
                outputs.push_back({MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({referralIdentity.GetID()}), 1, &to)), 0, false});
            }
            feeOffer -= idReferralFee;
            if (referralHeight != 1 && referralID != newID.parent)
            {
                int afterId = referralTxIn.prevout.n + 
                               ((parentCurrency.IsPBaaSChain() && parentCurrency.proofProtocol != parentCurrency.PROOF_CHAINID) ? 1 : 2);
                for (int i = afterId; i < (referralIdTx.vout.size() - 1) && (i - afterId) < (parentCurrency.idReferralLevels - 1); i++)
                {
                    CTxDestination nextID;
                    COptCCParams p, master;

                    if (referralIdTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && 
                        p.IsValid() && 
                        ((p.evalCode == EVAL_NONE && issuingCurrency.GetID() == ASSETCHAINS_CHAINID) ||
                         (p.evalCode == EVAL_RESERVE_OUTPUT && issuingCurrency.GetID() != ASSETCHAINS_CHAINID)) && 
                        p.vKeys.size() == 1 && 
                        (p.vData.size() == 1 ||
                        (p.vData.size() == 2 && 
                        p.vKeys[0].which() == COptCCParams::ADDRTYPE_ID &&
                        (master = COptCCParams(p.vData[1])).IsValid() &&
                        master.evalCode == EVAL_NONE)))
                    {
                        if (issuingCurrency.GetID() == ASSETCHAINS_CHAINID)
                        {
                            outputs.push_back({newID.TransparentOutput(CIdentityID(GetDestinationID(p.vKeys[0]))), idReferralFee, false});
                        }
                        else
                        {
                            // make an output to the currency ID of the amount less referrers
                            CTokenOutput to(CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({idReferralFee})));
                            outputs.push_back({MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({CIdentityID(GetDestinationID(p.vKeys[0]))}), 1, &to)), 0, false});
                        }
                        feeOffer -= idReferralFee;
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or revoked referral identity at time of commitment");
        }
    }

    if (errorTest == ERRTEST_UNDERPAYFEE)
    {
        feeOffer >>= 1;
    }

    CScript reservationOutScript;
    if (advReservation.IsValid())
    {
        reservationOutScript = MakeMofNCCScript(CConditionObj<CAdvancedNameReservation>(EVAL_IDENTITY_ADVANCEDRESERVATION, std::vector<CTxDestination>({CIdentityID(newID.GetID())}), 1, &advReservation));
    }
    else
    {
        reservationOutScript = MakeMofNCCScript(CConditionObj<CNameReservation>(EVAL_IDENTITY_RESERVATION, std::vector<CTxDestination>({CIdentityID(newID.GetID())}), 1, &reservation));
    }
    outputs.push_back({reservationOutScript, CNameReservation::DEFAULT_OUTPUT_AMOUNT, false});

    // make one dummy output, which CreateTransaction will leave as last, and we will remove to add its output to the fee
    // this serves to keep the change output after our real reservation output

    // use the transaction builder to properly make change of native and reserves
    TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

    CCurrencyValueMap reservesOut;

    // if we have registration payments, fixup the output amount based on referrals adjustment
    if (registrationPaymentOut >= 0)
    {
        if (issuingCurrency.proofProtocol == issuingCurrency.PROOF_CHAINID)
        {
            if (issuerID == ASSETCHAINS_CHAINID)
            {
                // make an output to the currency ID of the amount less referrers
                outputs[registrationPaymentOut].nAmount = feeOffer;
            }
            else
            {
                // make an output to the currency ID of the amount less referrers
                CTokenOutput to(CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({feeOffer})));
                outputs[registrationPaymentOut].scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, 
                                                                                                            std::vector<CTxDestination>({CIdentityID(issuerID)}),
                                                                                                            1,
                                                                                                            &to));
            }
        }
        else
        {
            // make a burn output of this currency for the amount
            CReserveTransfer rt(CReserveTransfer::VALID + CReserveTransfer::BURN_CHANGE_PRICE,
                                CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({feeOffer})),
                                ASSETCHAINS_CHAINID,
                                ConnectedChains.ThisChain().GetTransactionTransferFee(),
                                issuerID,
                                DestinationToTransferDestination(CIdentityID(issuerID)));

            CCcontract_info CC;
            CCcontract_info *cp;
            cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
            CPubKey pk(ParseHex(CC.CChexstr));

            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

            outputs[registrationPaymentOut].scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER,
                                                                            dests,
                                                                            1,
                                                                            &rt));
        }

        // the fee for a non-native registration is the import fee, as the fee offer was paid to the issuing currency
        tb.SetFee(ConnectedChains.ThisChain().IDImportFee());
        reservesOut.valueMap[ASSETCHAINS_CHAINID] += ConnectedChains.ThisChain().IDImportFee();
    }
    else
    {
        tb.SetFee(feeOffer);
        reservesOut.valueMap[ASSETCHAINS_CHAINID] += feeOffer;
    }

    if (params.size() <= 3)
    {
        wildCardTransparentAddress = true;
    }

    bool success = false;
    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
    std::vector<SaplingNoteEntry> saplingNotes;
    CCurrencyValueMap reserveValueOut;
    CAmount nativeValueOut;
    std::vector<COutput> vCoins;

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    for (int i = 0; i < outputs.size(); i++)
    {
        CRecipient &oneOut = outputs[i];
        tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nAmount);

        CCurrencyValueMap oneOutReserves;
        oneOutReserves += oneOut.scriptPubKey.ReserveOutValue();
        if (oneOut.nAmount)
        {
            oneOutReserves.valueMap[ASSETCHAINS_CHAINID] = oneOut.nAmount;
        }
        else
        {
            oneOutReserves.valueMap.erase(ASSETCHAINS_CHAINID);
        }
        reservesOut += oneOutReserves;
    }

    tb.AddTransparentInput(COutPoint(txid, commitmentOutput), txOut.vout[commitmentOutput].scriptPubKey, txOut.vout[commitmentOutput].nValue);

    reservesOut -= txOut.vout[commitmentOutput].scriptPubKey.ReserveOutValue();
    if (txOut.vout[commitmentOutput].nValue)
    {
        reservesOut = reservesOut.SubtractToZero(
                            CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}),
                                              std::vector<int64_t>({txOut.vout[commitmentOutput].nValue}))).CanonicalMap();
    }
    else
    {
        reservesOut = reservesOut.CanonicalMap();
    }

    reservesOut.valueMap[ASSETCHAINS_CHAINID] += DEFAULT_TRANSACTION_FEE;

    if (reservesOut.valueMap.size() == 1 && reservesOut.valueMap.count(ASSETCHAINS_CHAINID))
    {
        CAmount nativeNeeded = reservesOut.valueMap.begin()->second;

        if (hasZSource)
        {
            saplingNotes = find_unspent_notes(zaddressSource);
            CAmount totalFound = 0;
            int i;
            for (i = 0; i < saplingNotes.size(); i++)
            {
                totalFound += saplingNotes[i].note.value();
                if (totalFound >= nativeNeeded)
                {
                    break;
                }
            }
            // remove all but the notes we'll use
            if (i < saplingNotes.size())
            {
                saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
                success = true;
            }
        }
        else
        {
            success = find_utxos(from_taddress, vCoins) &&
                    pwalletMain->SelectCoinsMinConf(nativeNeeded, 0, 0, vCoins, setCoinsRet, nativeValueOut);
        }
    }
    else if (hasZSource)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot source non-native currencies from a private address");
    }
    else
    {
        CAmount nativeNeeded = reservesOut.valueMap.count(ASSETCHAINS_CHAINID) ? reservesOut.valueMap[ASSETCHAINS_CHAINID] : 0;
        reservesOut.valueMap.erase(ASSETCHAINS_CHAINID);

        success = find_utxos(from_taddress, vCoins);
        success = success && pwalletMain->SelectReserveCoinsMinConf(reservesOut,
                                                                    nativeNeeded,
                                                                    0,
                                                                    1,
                                                                    vCoins,
                                                                    setCoinsRet,
                                                                    reserveValueOut,
                                                                    nativeValueOut);
    }
    if (!success)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient funds for identity registration");
    }

    // aggregate all inputs into one output with only the offer coins and offer indexes
    if (saplingNotes.size())
    {
        std::vector<SaplingOutPoint> notes;
        for (auto &oneNoteInfo : saplingNotes)
        {
            notes.push_back(oneNoteInfo.op);
        }
        // Fetch Sapling anchor and witnesses
        uint256 anchor;
        std::vector<boost::optional<SaplingWitness>> witnesses;
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
        }

        // Add Sapling spends
        for (size_t i = 0; i < saplingNotes.size(); i++)
        {
            tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());
        }
    }
    else
    {
        for (auto &oneInput : setCoinsRet)
        {
            tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                    oneInput.first->vout[oneInput.second].scriptPubKey,
                                    oneInput.first->vout[oneInput.second].nValue);
        }
    }

    if (hasZSource)
    {
        tb.SendChangeTo(*boost::get<libzcash::SaplingPaymentAddress>(&zaddressSource), sourceOvk);
    }
    else if (sourceDest.which() != COptCCParams::ADDRTYPE_INVALID && !GetDestinationID(sourceDest).IsNull())
    {
        tb.SendChangeTo(sourceDest);
    }
    else
    {
        tb.SendChangeTo(commitmentOutDest);
    }

    TransactionBuilderResult preResult = tb.Build(true);
    CTransaction commitTx = preResult.GetTxOrThrow();

    if (returnTx)
    {
        return EncodeHexTx(commitTx);
    }
    else
    {
        // add to mem pool and relay
        LOCK(cs_main);

        bool relayTx;
        CValidationState state;
        {
            LOCK2(smartTransactionCS, mempool.cs);
            relayTx = myAddtomempool(commitTx, &state);
        }

        // add to mem pool and relay
        if (!relayTx)
        {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to commit identity registration transaction: " + state.GetRejectReason());
        }
        else
        {
            RelayTransaction(commitTx);
        }
    }

    // including definitions and claims thread
    return UniValue(commitTx.GetHash().GetHex());
}

std::map<std::string, UniValue> UniObjectToMap(const UniValue &obj)
{
    std::map<std::string, UniValue> retVal;
    if (obj.isObject())
    {
        std::vector<std::string> keys = obj.getKeys();
        std::vector<UniValue> values = obj.getValues();
        for (int i = 0; i < keys.size(); i++)
        {
            retVal.insert(std::make_pair(keys[i], values[i]));
        }
    }
    return retVal;
}

UniValue MapToUniObject(const std::map<std::string, UniValue> &uniMap)
{
    UniValue retVal(UniValue::VOBJ);
    for (auto &oneEl : uniMap)
    {
        retVal.pushKV(oneEl.first, oneEl.second);
    }
    return retVal;
}

UniValue updateidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "updateidentity \"jsonidentity\" (returntx) (tokenupdate)\n"
            "\n\n"

            "\nArguments\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"
            "       \"tokenupdate\"                     (bool,   optional) defaults to false, if true, the tokenized ID control token, if one exists, will be used to update\n"
            "                                                              which enables changing the revocation or recovery IDs, even if the wallet holding the token does not\n"
            "                                                              control either.\n"

            "\nResult:\n"
            "   hex string of either the txid if returnhex is false or the hex serialized transaction if returntx is true\n"

            "\nExamples:\n"
            + HelpExampleCli("updateidentity", "\'{\"name\" : \"myname\"}\'")
            + HelpExampleRpc("updateidentity", "\'{\"name\" : \"myname\"}\'")
        );
    }

    CheckIdentityAPIsValid();

    bool returnTx = false;
    bool tokenizedIDControl = false;

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    if (params.size() > 2)
    {
        tokenizedIDControl = uni_get_bool(params[2], false);
    }

    uint160 parentID = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(params[0], "parent")))));
    if (parentID.IsNull())
    {
        parentID = ValidateCurrencyName(uni_get_str(find_value(params[0], "parent")), true);
    }
    std::string nameStr = CleanName(uni_get_str(find_value(params[0], "name")), parentID);
    uint160 newIDID = CIdentity::GetID(nameStr, parentID);

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint32_t nHeight = chainActive.Height();

    if (!(oldID = CIdentity::LookupIdentity(newIDID, 0, &idHeight, &idTxIn)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " (" +EncodeDestination(CIdentityID(newIDID)) + "), not found ");
    }
    uint256 blkHash;
    CTransaction oldIdTx;
    if (!myGetTransaction(idTxIn.prevout.hash, oldIdTx, blkHash))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + ", transaction not found ");
    }

    auto uniOldID = UniObjectToMap(oldID.ToUniValue());

    // overwrite old elements
    for (auto &oneEl : UniObjectToMap(params[0]))
    {
        uniOldID[oneEl.first] = oneEl.second;
    }

    uint32_t solVersion = CConstVerusSolutionVector::GetVersionByHeight(nHeight + 1);

    if (solVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
    {
        uniOldID["version"] = solVersion < CActivationHeight::ACTIVATE_PBAAS ? (int64_t)CIdentity::VERSION_VAULT : (int64_t)CIdentity::VERSION_PBAAS;
        if (oldID.nVersion < CIdentity::VERSION_VAULT)
        {
            uniOldID["systemid"] = EncodeDestination(CIdentityID(parentID.IsNull() ? oldID.GetID() : parentID));
        }
    }

    UniValue newUniID = MapToUniObject(uniOldID);
    CIdentity newID(newUniID);

    newID.flags |= (oldID.flags & (oldID.FLAG_ACTIVECURRENCY + oldID.FLAG_TOKENIZED_CONTROL));

    if (!newID.IsValid(true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    // make sure we have a revocation and recovery authority defined
    CIdentity revocationAuth = newID.revocationAuthority == newIDID ? newID : newID.LookupIdentity(newID.revocationAuthority);
    CIdentity recoveryAuth = newID.recoveryAuthority == newIDID ? newID : newID.LookupIdentity(newID.recoveryAuthority);

    if (tokenizedIDControl)
    {
        if (!oldID.HasTokenizedControl())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Can only used ID control token for ID that has tokenized ID control on this chain");
        }
        if (PBAAS_TESTMODE && (IsVerusActive() || ConnectedChains.ThisChain().name == "Gravity") && chainActive.Height() < TESTNET_FORK_HEIGHT)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Tokenized ID control has not yet activated on testnet");
        }
    }

    if (!revocationAuth.IsValid() || !recoveryAuth.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid revocation or recovery authority");
    }

    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight + 1);

    if (oldID.IsLocked() != newID.IsLocked())
    {
        bool newLocked = newID.IsLocked();
        uint32_t unlockAfter = newID.unlockAfter;
        newID.flags = (newID.flags & ~newID.FLAG_LOCKED) | (newID.IsRevoked() ? 0 : (oldID.flags & oldID.FLAG_LOCKED));
        newID.unlockAfter = oldID.unlockAfter;

        if (!newLocked)
        {
            newID.Unlock(nHeight + 1, txNew.nExpiryHeight);
            if (unlockAfter > newID.unlockAfter)
            {
                newID.unlockAfter = unlockAfter;
            }
        }
        else
        {
            newID.Lock(unlockAfter);
        }
    }

    // if we are supposed to get our authority from the token, make sure it is present and prepare to spend it
    std::vector<COutput> controlTokenOuts;
    CCurrencyValueMap tokenCurrencyControlMap(std::vector<uint160>({newIDID}), std::vector<int64_t>({1}));

    if (tokenizedIDControl)
    {
        COptCCParams tcP;
        CCurrencyValueMap reserveMap;

        pwalletMain->AvailableReserveCoins(controlTokenOuts, true, nullptr, false, false, nullptr, &tokenCurrencyControlMap, false);
        if (controlTokenOuts.size() == 1 && controlTokenOuts[0].fSpendable)
        {
            reserveMap = controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue();
            if (!reserveMap.valueMap.count(newIDID) || reserveMap.valueMap[newIDID] != 1)
            {
                LogPrint("tokenizedidcontrol", "%s: controlTokenOuts.size(): %d, controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue(): %s, reserveMap: %s, reserveMap.valueMap[idID]: %ld\n", __func__, (int)controlTokenOuts.size(), controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue().ToUniValue().write().c_str(), reserveMap.ToUniValue().write().c_str(), reserveMap.valueMap[newIDID]);
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot locate spendable tokenized ID control currency in wallet - if present, may require rescan");
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No spendable tokenized ID control currency for update in wallet");
        }
    }

    // create the identity definition transaction
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(nHeight + 1), 0, false}});
    CWalletTx wtx;

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    int nNumChangeOutputs = 0;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason, nullptr, false))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to create update transaction: " + failReason);
    }
    CMutableTransaction mtx(wtx);

    // add the spend of the last ID transaction output
    mtx.vin.push_back(idTxIn);

    // if we are using tokenized ID control, add the input and output to the transaction before signing
    if (tokenizedIDControl)
    {
        mtx.vin.push_back(CTxIn(controlTokenOuts[0].tx->GetHash(), controlTokenOuts[0].i));
        // just in case a change output was inserted, we loop to find the first output with zero out
        // and put the spend just after
        for (auto it = mtx.vout.begin(); it != mtx.vout.end(); it++)
        {
            if (!it->nValue)
            {
                it++;
                mtx.vout.insert(it, CTxOut(controlTokenOuts[0].tx->vout[controlTokenOuts[0].i]));
                break;
            }
        }
    }

    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (tokenizedIDControl && LogAcceptCategory("tokenizedidcontrol"))
    {
        UniValue jsonTx(UniValue::VOBJ);
        TxToUniv(wtx, uint256(), jsonTx);
        LogPrintf("%s: updateidtx:\n%s\n", __func__, jsonTx.write(1,2).c_str());
    }

    // now sign
    CCoinsViewCache view(pcoinsTip);
    for (int i = 0; i < wtx.vin.size(); i++)
    {
        bool signSuccess;
        SignatureData sigdata;

        CCoins coins;
        if (!(view.GetCoins(wtx.vin[i].prevout.hash, coins) && coins.IsAvailable(wtx.vin[i].prevout.n)))
        {
            break;
        }

        CAmount value = coins.vout[wtx.vin[i].prevout.n].nValue;

        signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &wtx, i, value, coins.vout[wtx.vin[i].prevout.n].scriptPubKey), coins.vout[wtx.vin[i].prevout.n].scriptPubKey, sigdata, CurrentEpochBranchId(nHeight, Params().GetConsensus()));

        if (!signSuccess && !returnTx)
        {
            LogPrintf("%s: failure to sign identity update tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            printf("%s: failure to sign identity update tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to sign transaction");
        } else if (sigdata.scriptSig.size()) {
            UpdateTransaction(mtx, i, sigdata);
        }
    }
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (returnTx)
    {
        return EncodeHexTx(wtx);
    }
    else if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }
    return wtx.GetHash().GetHex();
}

UniValue setidentitytimelock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        throw runtime_error(
            "setidentitytimelock \"id@\" '{\"unlockatblock\":absoluteblockheight || \"setunlockdelay\":numberofblocksdelayafterunlock}' (returntx)\n"
            "\nEnables timelocking and unlocking of funds access for an on-chain VerusID. This does not affect the lock status of VerusIDs on other chains,\n"
            "including VerusIDs with the same identity as this one, which has been exported to another chain.\n"
            "\nUse \"setunlockdelay\" to set a time unlock delay on an identity, which means that once the identity has been unlocked,\n"
            "numberofblocksdelayafterunlock must then pass before the identity will be able to spend funds on this blockchain. Services\n"
            "which support VerusID authentication and recognize this setting may also choose to prevent funds transfers when an ID is locked.\n"
            "\nUse \"unlockatblock\" to either unlock, by passing the current block, which will still require waiting for the specified unlock\n"
            "delay, or to set a future unlock height that immediately begins counting down. Unlike an unlock delay, which only starts counting\n"
            "down when the ID is unlocked, an \"unlockatblock\" time lock is absolute and will automatically unlock when the specified\n"
            "block passes.\n"

            "\nArguments - either \"unlockatblock\" or \"setunlockdelay\" must be specified and not both\n"
            "{\n"
            "  \"unlockatblock\"                (number, optional) unlock at an absolute block height, countdown starts when mined into a block\n"
            "  \"setunlockdelay\"               (number, optional) delay this many blocks after unlock request to unlock, can only be\n"
            "                                                      circumvented by revoke/recover\n"
            "}\n"

            "\nResult:\n"
            "   Hex string of either the txid if returnhex is false or the hex serialized transaction if returntx is true.\n"
            "   If returntx is true, the transaction will not have been submitted and must be sent with \"sendrawtransaction\"\n"
            "   after any necessary signatures are applied in the case of multisig.\n"

            "\nExamples:\n"
            + HelpExampleCli("setidentitytimelock", "\"id@\" '{\"unlockatblock\":absoluteblockheight || \"setunlockdelay\":numberofblocksdelayafterunlock}' (returntx)")
            + HelpExampleRpc("setidentitytimelock", "\"id@\" '{\"unlockatblock\":absoluteblockheight || \"setunlockdelay\":numberofblocksdelayafterunlock}' (returntx)")
        );
    }

    CheckIdentityAPIsValid();

    bool returnTx = false;
    if (params.size() > 2)
    {
        returnTx = uni_get_bool(params[2], false);
    }

    std::string idString = uni_get_str(params[0]);
    CIdentity oldIdentity = ValidateIdentityParameter(idString);
    if (!oldIdentity.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity, " + idString + " not found ");
    }

    UniValue unlockDelayUni = find_value(params[1], "setunlockdelay");
    UniValue absoluteUnlockUni = find_value(params[1], "unlockatblock");

    if ((!unlockDelayUni.isNull() && !absoluteUnlockUni.isNull()) || (unlockDelayUni.isNull() && absoluteUnlockUni.isNull()))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Either \"setunlockdelay\" or \"unlockatblock\" must have a non-zero value and not both");
    }

    uint32_t unlockDelay = uni_get_int64(unlockDelayUni);
    uint32_t absoluteUnlock = uni_get_int64(absoluteUnlockUni);

    {
        LOCK(cs_main);
        uint32_t nextHeight = chainActive.Height() + 1;
        CMutableTransaction txNew = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nextHeight);

        if (unlockDelayUni.isNull())
        {
            oldIdentity.Unlock(nextHeight, txNew.nExpiryHeight);
            oldIdentity.unlockAfter = absoluteUnlock;
        }
        else
        {
            oldIdentity.Lock(unlockDelay);
        }
    }

    UniValue newParams(UniValue::VARR);

    newParams.push_back(oldIdentity.ToUniValue());
    if (params.size() > 2)
    {
        newParams.push_back(params[2]);
    }
    return updateidentity(newParams, fHelp);
}

UniValue revokeidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "revokeidentity \"nameorID\" (returntx) (tokenrevoke)\n"
            "\n\n"

            "\nArguments\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"
            "       \"tokenrevoke\"                     (bool,   optional) defaults to false, if true, the tokenized ID control token, if one exists, will be used to revoke\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("revokeidentity", "\"nameorID\"")
            + HelpExampleRpc("revokeidentity", "\"nameorID\"")
        );
    }

    CheckIdentityAPIsValid();

    // get identity
    bool returnTx = false;
    bool tokenizedIDControl = false;

    CTxDestination idDest = DecodeDestination(uni_get_str(params[0]));

    if (idDest.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    CIdentityID idID(GetDestinationID(idDest));

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    if (params.size() > 2)
    {
        tokenizedIDControl = uni_get_bool(params[2], false);
    }

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!(oldID = CIdentity::LookupIdentity(idID, 0, &idHeight, &idTxIn)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found " + EncodeDestination(idID));
    }

    // if we are supposed to get our authority from the token, make sure it is present and prepare to spend it
    std::vector<COutput> controlTokenOuts;
    CCurrencyValueMap tokenCurrencyControlMap(std::vector<uint160>({idID}), std::vector<int64_t>({1}));

    if (tokenizedIDControl)
    {
        if (PBAAS_TESTMODE && (IsVerusActive() || ConnectedChains.ThisChain().name == "Gravity") && chainActive.Height() < TESTNET_FORK_HEIGHT)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Tokenized ID control has not yet activated on testnet");
        }
        COptCCParams tcP;
        CCurrencyValueMap reserveMap;
        pwalletMain->AvailableReserveCoins(controlTokenOuts, true, nullptr, false, false, nullptr, &tokenCurrencyControlMap, false);
        if (controlTokenOuts.size() == 1 && controlTokenOuts[0].fSpendable)
        {
            reserveMap = controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue();
            if (!reserveMap.valueMap.count(idID) || reserveMap.valueMap[idID] != 1)
            {
                LogPrint("tokenizedidcontrol", "%s: controlTokenOuts.size(): %d, controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue(): %s, reserveMap: %s, reserveMap.valueMap[idID]: %ld\n", __func__, (int)controlTokenOuts.size(), controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue().ToUniValue().write().c_str(), reserveMap.ToUniValue().write().c_str(), reserveMap.valueMap[idID]);
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot locate spendable tokenized ID control currency in wallet - if present, may require rescan");
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No spendable tokenized ID control currency for revoke in wallet");
        }
    }

    CIdentity newID(oldID);
    newID.UpgradeVersion(chainActive.Height() + 1);
    newID.Revoke();

    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(chainActive.Height()), 0, false}});
    CWalletTx wtx;

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason, nullptr, false))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to create update transaction: " + failReason);
    }
    CMutableTransaction mtx(wtx);

    // add the spend of the last ID transaction output
    mtx.vin.push_back(idTxIn);

    // if we are using tokenized ID control, add the input and output to the transaction before signing
    if (tokenizedIDControl)
    {
        mtx.vin.push_back(CTxIn(controlTokenOuts[0].tx->GetHash(), controlTokenOuts[0].i));
        // just in case a change output was inserted, we loop to find the first output with zero out
        // and put the spend just after
        for (auto it = mtx.vout.begin(); it != mtx.vout.end(); it++)
        {
            if (!it->nValue)
            {
                it++;
                mtx.vout.insert(it, CTxOut(controlTokenOuts[0].tx->vout[controlTokenOuts[0].i]));
                break;
            }
        }
    }

    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);
    if (tokenizedIDControl && LogAcceptCategory("tokenizedidcontrol"))
    {
        UniValue jsonTx(UniValue::VOBJ);
        TxToUniv(wtx, uint256(), jsonTx);
        LogPrintf("%s: revokeidtx:\n%s\n", __func__, jsonTx.write(1,2).c_str());
    }

    // now sign
    CCoinsViewCache view(pcoinsTip);
    for (int i = 0; i < wtx.vin.size(); i++)
    {
        bool signSuccess;
        SignatureData sigdata;

        CCoins coins;
        if (!(view.GetCoins(wtx.vin[i].prevout.hash, coins) && coins.IsAvailable(wtx.vin[i].prevout.n)))
        {
            break;
        }

        CAmount value = coins.vout[wtx.vin[i].prevout.n].nValue;

        signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &wtx, i, value, coins.vout[wtx.vin[i].prevout.n].scriptPubKey), coins.vout[wtx.vin[i].prevout.n].scriptPubKey, sigdata, CurrentEpochBranchId(chainActive.Height(), Params().GetConsensus()));

        if (!signSuccess && !returnTx)
        {
            LogPrintf("%s: failure to sign identity revocation tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            printf("%s: failure to sign identity revocation tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to sign transaction");
        } else if (sigdata.scriptSig.size()) {
            UpdateTransaction(mtx, i, sigdata);
        }
    }
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (returnTx)
    {
        return EncodeHexTx(wtx);
    }
    else if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }
    return wtx.GetHash().GetHex();
}

UniValue recoveridentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "recoveridentity \"jsonidentity\" (returntx) (tokenrecover)\n"
            "\n\n"

            "\nArguments\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"
            "       \"tokenrecover\"                    (bool,   optional) defaults to false, if true, the tokenized ID control token, if one exists, will be used to recover\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("recoveridentity", "\'{\"name\" : \"myname\"}\'")
            + HelpExampleRpc("recoveridentity", "\'{\"name\" : \"myname\"}\'")
        );
    }
    CheckIdentityAPIsValid();

    // get identity
    bool returnTx = false;
    bool tokenizedIDControl = false;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint32_t nHeight = chainActive.Height();

    UniValue newUniIdentity = params[0];
    if (uni_get_int(find_value(newUniIdentity,"version")) == 0)
    {
        newUniIdentity.pushKV("version", 
                              CConstVerusSolutionVector::GetVersionByHeight(nHeight + 1) >= CActivationHeight::ACTIVATE_VERUSVAULT ? 
                                CIdentity::VERSION_VAULT :
                                CIdentity::VERSION_VERUSID);
    }

    if (uni_get_int(find_value(newUniIdentity,"minimumsignatures")) == 0)
    {
        newUniIdentity.pushKV("minimumsignatures", (int32_t)1);
    }

    CIdentity newID(newUniIdentity);
    uint160 newIDID = newID.GetID();

    if (!newID.IsValid(true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    if (params.size() > 2)
    {
        tokenizedIDControl = uni_get_bool(params[2], false);
    }

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    if (!(oldID = CIdentity::LookupIdentity(newIDID, 0, &idHeight, &idTxIn)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found " + newID.ToUniValue().write());
    }

    if (!oldID.IsRevoked())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity must be revoked in order to recover : " + newID.name);
    }

    // if we are supposed to get our authority from the token, make sure it is present and prepare to spend it
    std::vector<COutput> controlTokenOuts;
    CCurrencyValueMap tokenCurrencyControlMap(std::vector<uint160>({newIDID}), std::vector<int64_t>({1}));

    if (tokenizedIDControl)
    {
        if (PBAAS_TESTMODE && (IsVerusActive() || ConnectedChains.ThisChain().name == "Gravity") && chainActive.Height() < TESTNET_FORK_HEIGHT)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Tokenized ID control has not yet activated on testnet");
        }

        COptCCParams tcP;

        CCurrencyValueMap reserveMap;
        pwalletMain->AvailableReserveCoins(controlTokenOuts, true, nullptr, false, false, nullptr, &tokenCurrencyControlMap, false);
        if (controlTokenOuts.size() == 1 && controlTokenOuts[0].fSpendable)
        {
            reserveMap = controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue();
            if (!reserveMap.valueMap.count(newIDID) || reserveMap.valueMap[newIDID] != 1)
            {
                LogPrint("tokenizedidcontrol", "%s: controlTokenOuts.size(): %d, controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue(): %s, reserveMap: %s, reserveMap.valueMap[idID]: %ld\n", __func__, (int)controlTokenOuts.size(), controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue().ToUniValue().write().c_str(), reserveMap.ToUniValue().write().c_str(), reserveMap.valueMap[newIDID]);
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot locate spendable tokenized ID control currency in wallet - if present, may require rescan");
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No spendable tokenized ID control currency for recover in wallet");
        }
    }

    newID.flags |= (oldID.flags & (oldID.FLAG_ACTIVECURRENCY + oldID.FLAG_TOKENIZED_CONTROL));
    newID.flags &= ~CIdentity::FLAG_REVOKED;
    newID.systemID = oldID.systemID;
    newID.UpgradeVersion(nHeight + 1);

    // create the identity definition transaction
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(nHeight + 1), 0, false}});
    CWalletTx wtx;

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason, nullptr, false))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to create update transaction: " + failReason);
    }
    CMutableTransaction mtx(wtx);

    // add the spend of the last ID transaction output
    mtx.vin.push_back(idTxIn);

    // if we are using tokenized ID control, add the input and output to the transaction before signing
    if (tokenizedIDControl)
    {
        mtx.vin.push_back(CTxIn(controlTokenOuts[0].tx->GetHash(), controlTokenOuts[0].i));
        // just in case a change output was inserted, we loop to find the first output with zero out
        // and put the spend just after
        for (auto it = mtx.vout.begin(); it != mtx.vout.end(); it++)
        {
            if (!it->nValue)
            {
                it++;
                mtx.vout.insert(it, CTxOut(controlTokenOuts[0].tx->vout[controlTokenOuts[0].i]));
                break;
            }
        }
    }

    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (tokenizedIDControl && LogAcceptCategory("tokenizedidcontrol"))
    {
        UniValue jsonTx(UniValue::VOBJ);
        TxToUniv(wtx, uint256(), jsonTx);
        LogPrintf("%s: recoveridtx:\n%s\n", __func__, jsonTx.write(1,2).c_str());
    }

    // now sign
    CCoinsViewCache view(pcoinsTip);
    for (int i = 0; i < wtx.vin.size(); i++)
    {
        bool signSuccess;
        SignatureData sigdata;

        CCoins coins;
        if (!(view.GetCoins(wtx.vin[i].prevout.hash, coins) && coins.IsAvailable(wtx.vin[i].prevout.n)))
        {
            break;
        }

        CAmount value = coins.vout[wtx.vin[i].prevout.n].nValue;

        signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &wtx, i, value, coins.vout[wtx.vin[i].prevout.n].scriptPubKey), coins.vout[wtx.vin[i].prevout.n].scriptPubKey, sigdata, CurrentEpochBranchId(chainActive.Height(), Params().GetConsensus()));

        if (!signSuccess && !returnTx)
        {
            LogPrintf("%s: failure to sign identity recovery tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            printf("%s: failure to sign identity recovery tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to sign transaction");
        } else if (sigdata.scriptSig.size()) {
            UpdateTransaction(mtx, i, sigdata);
        }
    }
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (returnTx)
    {
        return EncodeHexTx(wtx);
    }
    else if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }
    return wtx.GetHash().GetHex();
}

UniValue getidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
    {
        throw runtime_error(
            "getidentity \"name@ || iid\" (height) (txproof) (txproofheight)\n"
            "\n\n"

            "\nArguments\n"
            "    \"name@ || iid\"                       (string, required) name followed by \"@\" or i-address of an identity\n"
            "    \"height\"                             (number, optional) default=current height, return identity as of this height\n"
            "    \"txproof\"                            (bool, optional) default=false, if true, returns proof of ID\n"
            "    \"txproofheight\"                      (number, optional) default=\"height\", height from which to generate a proof\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentity", "\"name@\"")
            + HelpExampleRpc("getidentity", "\"name@\"")
        );
    }

    CheckIdentityAPIsValid();

    CTxDestination idID = DecodeDestination(uni_get_str(params[0]));
    if (idID.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity parameter must be valid friendly name or identity address: \"" + uni_get_str(params[0]) + "\"");
    }

    LOCK(cs_main);

    uint32_t lteHeight = chainActive.Height();
    if (params.size() > 1)
    {
        uint32_t tmpHeight = uni_get_int64(params[1]);
        if (tmpHeight > 0 && lteHeight > tmpHeight)
        {
            lteHeight = tmpHeight;
        }
    }
    bool txProof = params.size() > 2 ? uni_get_bool(params[2]) : false;
    uint32_t txProofHeight = params.size() > 3 ? uni_get_int64(params[1]) : 0;
    if (txProofHeight < lteHeight)
    {
        txProofHeight = lteHeight;
    }

    CTxIn idTxIn;
    uint32_t height;

    CIdentity identity;
    bool canSign = false, canSpend = false;

    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_wallet);
        uint256 txID;
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        if (pwalletMain->GetIdentity(GetDestinationID(idID), keyAndIdentity, lteHeight))
        {
            canSign = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SIGN;
            canSpend = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SPEND;
            identity = static_cast<CIdentity>(keyAndIdentity.second);
        }
    }

    uint160 identityID = GetDestinationID(idID);
    identity = CIdentity::LookupIdentity(CIdentityID(identityID), lteHeight, &height, &idTxIn);

    if (!identity.IsValid() && identityID == VERUS_CHAINID)
    {
        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
        std::vector<std::pair<uint160, uint256>> contentmap;
        identity = CIdentity(CIdentity::VERSION_VAULT, 
                             CIdentity::FLAG_ACTIVECURRENCY,
                             primary, 
                             1, 
                             ConnectedChains.ThisChain().parent,
                             VERUS_CHAINNAME,
                             contentmap,
                             ConnectedChains.ThisChain().GetID(),
                             ConnectedChains.ThisChain().GetID(),
                             std::vector<libzcash::SaplingPaymentAddress>());
    }

    UniValue ret(UniValue::VOBJ);

    uint160 parent;
    if (identity.IsValid() && identity.name == CleanName(identity.name, parent, true))
    {
        ret.push_back(Pair("identity", identity.ToUniValue()));
        ret.push_back(Pair("status", identity.IsRevoked() ? "revoked" : "active"));
        ret.push_back(Pair("canspendfor", canSpend));
        ret.push_back(Pair("cansignfor", canSign));
        ret.push_back(Pair("blockheight", (int64_t)height));
        ret.push_back(Pair("txid", idTxIn.prevout.hash.GetHex()));
        ret.push_back(Pair("vout", (int32_t)idTxIn.prevout.n));

        if (txProof &&
            !idTxIn.prevout.hash.IsNull() &&
            height > 0 &&
            height <= chainActive.Height())
        {
            CTransaction idTx;
            uint256 blkHash;
            CBlockIndex *pIndex;
            LOCK(mempool.cs);
            if (!myGetTransaction(idTxIn.prevout.hash, idTx, blkHash) ||
                blkHash.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Identity transacton not found or not indexed / committed");
            }
            auto blkMapIt = mapBlockIndex.find(blkHash);
            if (blkMapIt == mapBlockIndex.end()  ||
                !chainActive.Contains(pIndex = blkMapIt->second))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Identity transacton not indexed / committed");
            }
            CPartialTransactionProof idProof = CPartialTransactionProof(idTx, 
                                                                        std::vector<int>(), 
                                                                        std::vector<int>({(int)idTxIn.prevout.n}), 
                                                                        pIndex, 
                                                                        txProofHeight);
            if (idProof.IsValid())
            {
                ret.push_back(Pair("proof", idProof.ToUniValue()));
            }
        }

        return ret;
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Identity not found");
    }
}

UniValue IdentityPairToUni(const std::pair<CIdentityMapKey, CIdentityMapValue> &identity)
{
    UniValue oneID(UniValue::VOBJ);

    if (identity.first.IsValid() && identity.second.IsValid())
    {
        oneID.push_back(Pair("identity", identity.second.ToUniValue()));
        oneID.push_back(Pair("blockheight", (int64_t)identity.first.blockHeight));
        oneID.push_back(Pair("txid", identity.second.txid.GetHex()));
        if (identity.second.IsRevoked())
        {
            oneID.push_back(Pair("status", "revoked"));
            oneID.push_back(Pair("canspendfor", bool(0)));
            oneID.push_back(Pair("cansignfor", bool(0)));
        }
        else
        {
            oneID.push_back(Pair("status", "active"));
            oneID.push_back(Pair("canspendfor", bool(identity.first.flags & identity.first.CAN_SPEND)));
            oneID.push_back(Pair("cansignfor", bool(identity.first.flags & identity.first.CAN_SIGN)));
        }
    }
    return oneID;
}

UniValue listidentities(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
    {
        throw runtime_error(
            "listidentities (includecanspend) (includecansign) (includewatchonly)\n"
            "\n\n"

            "\nArguments\n"
            "    \"includecanspend\"    (bool, optional, default=true)    Include identities for which we can spend/authorize\n"
            "    \"includecansign\"     (bool, optional, default=true)    Include identities that we can only sign for but not spend\n"
            "    \"includewatchonly\"   (bool, optional, default=false)   Include identities that we can neither sign nor spend, but are either watched or are co-signers with us\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("listidentities", "\'{\"name\" : \"myname\"}\'")
            + HelpExampleRpc("listidentities", "\'{\"name\" : \"myname\"}\'")
        );
    }

    CheckIdentityAPIsValid();

    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> mine, imsigner, notmine;
    CIdentity oneIdentity;
    uint32_t oneIdentityHeight;

    bool includeCanSpend = params.size() > 0 ? uni_get_bool(params[0], true) : true;
    bool includeCanSign = params.size() > 1 ? uni_get_bool(params[1], true) : true;
    bool includeWatchOnly = params.size() > 2 ? uni_get_bool(params[2], false) : false;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (pwalletMain->GetIdentities(mine, imsigner, notmine))
    {
        UniValue ret(UniValue::VARR);
        if (includeCanSpend)
        {
            for (auto identity : mine)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent, true))
                {
                    oneIdentity = CIdentity::LookupIdentity(identity.first.idID, 0, &oneIdentityHeight);

                    if (!oneIdentity.IsValid())
                    {
                        if (identity.first.idID != VERUS_CHAINID)
                        {
                            continue;
                        }
                        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
                        std::vector<std::pair<uint160, uint256>> contentmap;
                        oneIdentity = CIdentity(CIdentity::VERSION_VAULT, 
                                                CIdentity::FLAG_ACTIVECURRENCY,
                                                primary, 
                                                1, 
                                                ConnectedChains.ThisChain().parent,
                                                VERUS_CHAINNAME,
                                                contentmap,
                                                ConnectedChains.ThisChain().GetID(),
                                                ConnectedChains.ThisChain().GetID(),
                                                std::vector<libzcash::SaplingPaymentAddress>());
                    }
                    (*(CIdentity *)&identity.second) = oneIdentity;
                    // TODO: confirm that missing block order is fine for this API
                    identity.first.blockHeight = oneIdentityHeight;
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        if (includeCanSign)
        {
            for (auto identity : imsigner)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent, true))
                {
                    oneIdentity = CIdentity::LookupIdentity(identity.first.idID, 0, &oneIdentityHeight);

                    if (!oneIdentity.IsValid())
                    {
                        if (identity.first.idID != VERUS_CHAINID)
                        {
                            continue;
                        }
                        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
                        std::vector<std::pair<uint160, uint256>> contentmap;
                        oneIdentity = CIdentity(CIdentity::VERSION_VAULT, 
                                                CIdentity::FLAG_ACTIVECURRENCY,
                                                primary, 
                                                1, 
                                                ConnectedChains.ThisChain().parent,
                                                VERUS_CHAINNAME,
                                                contentmap,
                                                ConnectedChains.ThisChain().GetID(),
                                                ConnectedChains.ThisChain().GetID(),
                                                std::vector<libzcash::SaplingPaymentAddress>());
                    }
                    (*(CIdentity *)&identity.second) = oneIdentity;
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        if (includeWatchOnly)
        {
            for (auto identity : notmine)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent, true))
                {
                    oneIdentity = CIdentity::LookupIdentity(identity.first.idID, 0, &oneIdentityHeight);

                    if (!oneIdentity.IsValid())
                    {
                        if (identity.first.idID != VERUS_CHAINID)
                        {
                            continue;
                        }
                        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
                        std::vector<std::pair<uint160, uint256>> contentmap;
                        oneIdentity = CIdentity(CIdentity::VERSION_VAULT, 
                                                CIdentity::FLAG_ACTIVECURRENCY,
                                                primary, 
                                                1, 
                                                ConnectedChains.ThisChain().parent,
                                                VERUS_CHAINNAME,
                                                contentmap,
                                                ConnectedChains.ThisChain().GetID(),
                                                ConnectedChains.ThisChain().GetID(),
                                                std::vector<libzcash::SaplingPaymentAddress>());
                    }
                    (*(CIdentity *)&identity.second) = oneIdentity;
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        return ret;
    }
    else
    {
        return NullUniValue;
    }
}

UniValue getidentitieswithaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getidentitieswithaddress '{\"address\":\"validprimaryaddress\",\"fromheight\":height, \"toheight\":height, \"unspent\":false}'\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"address\":\"validaddress\"   (string, required) returns all identities that contain the specified address in its primary addresses\n"
            "    \"fromheight\":n               (number, optional, default=0) Search for qualified identities modified from this height forward only\n"
            "    \"toheight\":n                 (number, optional, default=0) Search for qualified identities only up until this height (0 == no limit)\n"
            "    \"unspent\":bool               (bool, optional, default=false) if true, this will only return active ID UTXOs as of the current block height\n"
            "}\n"

            "\nResult:\n"
            "[                                  (array) array of matching identities\n"
            "  {identityobject},                (object) identity with additional member \"txout\" with txhash and output index\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentitieswithaddress", "\'{\"address\":\"validprimaryaddress\",\"fromheight\":height, \"toheight\":height, \"unspent\":false}\'")
            + HelpExampleRpc("getidentitieswithaddress", "\'{\"address\":\"validprimaryaddress\",\"fromheight\":height, \"toheight\":height, \"unspent\":false}\'")
        );
    }

    CheckIdentityAPIsValid();
    if (!fIdIndex)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "getidentitieswithaddress requires -idindex=1 when starting the daemon\n");
    }
    UniValue retVal(UniValue::VARR);

    std::string addressString = uni_get_str(find_value(params[0], "address"));
    CTxDestination addressDest = DecodeDestination(addressString);
    if (addressDest.which() != COptCCParams::ADDRTYPE_PKH && addressDest.which() != COptCCParams::ADDRTYPE_PK)
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no valid PKH or PK address\n");
    }
    uint32_t fromHeight = uni_get_int64(find_value(params[0], "fromheight"));
    uint32_t toHeight = uni_get_int64(find_value(params[0], "toheight"));

    if (uni_get_bool(find_value(params[0], "unspent")))
    {
        std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> identities;
        if (CIdentity::GetActiveIdentitiesByPrimaryAddress(addressDest, identities))
        {
            for (auto &oneIdentity : identities)
            {
                if ((!fromHeight || oneIdentity.second.first.second.blockHeight >= fromHeight) &&
                    (!toHeight || oneIdentity.second.first.second.blockHeight <= toHeight))
                {
                    UniValue idUni = oneIdentity.second.second.ToUniValue();
                    idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                    retVal.push_back(idUni);
                }
            }
        }
    }
    else
    {
        std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> identities;
        if (CIdentity::GetIdentityOutsByPrimaryAddress(addressDest, identities, fromHeight, toHeight))
        {
            for (auto &oneIdentity : identities)
            {
                UniValue idUni = oneIdentity.second.second.ToUniValue();
                idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                retVal.push_back(idUni);
            }
        }
    }
    return retVal;
}
 
UniValue getidentitieswithrevocation(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getidentitieswithrevocation '{\"identityid\":\"idori-address\", \"fromheight\":height, \"toheight\":height, \"unspent\":false}'\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"identityid\":\"idori-address\" (string, required) returns all identities where this ID or i-address is the revocation authority\n"
            "    \"fromheight\":n               (number, optional, default=0) Search for qualified identities modified from this height forward only\n"
            "    \"toheight\":n                 (number, optional, default=0) Search for qualified identities only up until this height (0 == no limit)\n"
            "    \"unspent\":bool               (bool, optional, default=false) if true, this will only return active ID UTXOs as of the current block height\n"
            "}\n"

            "\nResult:\n"
            "[                                  (array) array of matching identities\n"
            "  {identityobject},                (object) identity with additional member \"txout\" with txhash and output index\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentitieswithrevocation", "\'{\"identityid\":\"idori-address\",\"fromheight\":height,\"toheight\":height,\"unspent\":false}\'")
            + HelpExampleRpc("getidentitieswithrevocation", "\'{\"identityid\":\"idori-address\",\"fromheight\":height,\"toheight\":height,\"unspent\":false}\'")
        );
    }

    CheckIdentityAPIsValid();
    if (!fIdIndex)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "getidentitieswithrevocation requires -idindex=1 when starting the daemon\n");
    }
    UniValue retVal(UniValue::VARR);

    std::string addressString = uni_get_str(find_value(params[0], "identityid"));
    CTxDestination addressDest = DecodeDestination(addressString);
    if (addressDest.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no valid ID address\n");
    }

    CIdentityID idID = GetDestinationID(addressDest);

    uint32_t fromHeight = uni_get_int64(find_value(params[0], "fromheight"));
    uint32_t toHeight = uni_get_int64(find_value(params[0], "toheight"));

    if (uni_get_bool(find_value(params[0], "unspent")))
    {
        std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> identities;
        if (CIdentity::GetActiveIdentitiesWithRevocationID(idID, identities))
        {
            for (auto &oneIdentity : identities)
            {
                if ((!fromHeight || oneIdentity.second.first.second.blockHeight >= fromHeight) &&
                    (!toHeight || oneIdentity.second.first.second.blockHeight <= toHeight))
                {
                    UniValue idUni = oneIdentity.second.second.ToUniValue();
                    idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                    retVal.push_back(idUni);
                }
            }
        }
    }
    else
    {
        std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> identities;
        if (CIdentity::GetIdentityOutsWithRevocationID(idID, identities, fromHeight, toHeight))
        {
            for (auto &oneIdentity : identities)
            {
                UniValue idUni = oneIdentity.second.second.ToUniValue();
                idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                retVal.push_back(idUni);
            }
        }
    }
    return retVal;
}

UniValue getidentitieswithrecovery(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getidentitieswithrecovery '{\"identityid\":\"idori-address\", \"fromheight\":height, \"toheight\":height, \"unspent\":false}'\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"identityid\":\"idori-address\" (string, required) returns all identities where this ID or i-address is the recovery authority\n"
            "    \"fromheight\":n               (number, optional, default=0) Search for qualified identities modified from this height forward only\n"
            "    \"toheight\":n                 (number, optional, default=0) Search for qualified identities only up until this height (0 == no limit)\n"
            "    \"unspent\":bool               (bool, optional, default=false) if true, this will only return active ID UTXOs as of the current block height\n"
            "}\n"

            "\nResult:\n"
            "[                                  (array) array of matching identities\n"
            "  {identityobject},                (object) identity with additional member \"txout\" with txhash and output index\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentitieswithrecovery", "\'{\"identityid\":\"idori-address\",\"fromheight\":height,\"toheight\":height,\"unspent\":false}\'")
            + HelpExampleRpc("getidentitieswithrecovery", "\'{\"identityid\":\"idori-address\",\"fromheight\":height,\"toheight\":height,\"unspent\":false}\'")
        );
    }

    CheckIdentityAPIsValid();
    if (!fIdIndex)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "getidentitieswithrecovery requires -idindex=1 when starting the daemon\n");
    }
    UniValue retVal(UniValue::VARR);

    std::string addressString = uni_get_str(find_value(params[0], "identityid"));
    CTxDestination addressDest = DecodeDestination(addressString);
    if (addressDest.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no valid ID address\n");
    }

    CIdentityID idID = GetDestinationID(addressDest);

    uint32_t fromHeight = uni_get_int64(find_value(params[0], "fromheight"));
    uint32_t toHeight = uni_get_int64(find_value(params[0], "toheight"));

    if (uni_get_bool(find_value(params[0], "unspent")))
    {
        std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> identities;
        if (CIdentity::GetActiveIdentitiesWithRecoveryID(idID, identities))
        {
            for (auto &oneIdentity : identities)
            {
                if ((!fromHeight || oneIdentity.second.first.second.blockHeight >= fromHeight) &&
                    (!toHeight || oneIdentity.second.first.second.blockHeight <= toHeight))
                {
                    UniValue idUni = oneIdentity.second.second.ToUniValue();
                    idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                    retVal.push_back(idUni);
                }
            }
        }
    }
    else
    {
        std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> identities;
        if (CIdentity::GetIdentityOutsWithRecoveryID(idID, identities, fromHeight, toHeight))
        {
            for (auto &oneIdentity : identities)
            {
                UniValue idUni = oneIdentity.second.second.ToUniValue();
                idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                retVal.push_back(idUni);
            }
        }
    }
    return retVal;
}

UniValue addmergedblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
    {
        throw runtime_error(
            "addmergedblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAdds a fully prepared block and its header to the current merge mining queue of this daemon.\n"
            "Parameters determine the action to take if adding this block would exceed the available merge mining slots.\n"
            "Default action to take if adding would exceed available space is to replace the choice with the least ROI if this block provides more.\n"

            "\nArguments\n"
            "1. \"hexdata\"                     (string, required) the hex-encoded, complete, unsolved block data to add. nTime, and nSolution are replaced.\n"
            "2. \"name\"                        (string, required) chain name symbol\n"
            "3. \"rpchost\"                     (string, required) host address for RPC connection\n"
            "4. \"rpcport\"                     (int,    required) port address for RPC connection\n"
            "5. \"userpass\"                    (string, required) credentials for login to RPC\n"

            "\nResult:\n"
            "\"deserialize-invalid\" - block could not be deserialized and was rejected as invalid\n"
            "\"blocksfull\"          - block did not exceed others in estimated ROI, and there was no room for an additional merge mined block\n"

            "\nExamples:\n"
            + HelpExampleCli("addmergedblock", "\"hexdata\" \'{\"currencyid\" : \"hexstring\", \"rpchost\" : \"127.0.0.1\", \"rpcport\" : portnum}\'")
            + HelpExampleRpc("addmergedblock", "\"hexdata\" \'{\"currencyid\" : \"hexstring\", \"rpchost\" : \"127.0.0.1\", \"rpcport\" : portnum, \"estimatedroi\" : (verusreward/hashrate)}\'")
        );
    }

    CheckPBaaSAPIsValid();

    // check to see if we should replace any existing block or add a new one. if so, add this to the merge mine vector
    string name = params[1].get_str();
    if (name == "")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "must provide chain name to merge mine");
    }

    string rpchost = params[2].get_str();
    int32_t rpcport = params[3].get_int();
    string rpcuserpass = params[4].get_str();

    if (rpchost == "" || rpcport == 0 || rpcuserpass == "")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "must provide valid RPC connection parameters to merge mine");
    }

    CCurrencyDefinition chainDef;
    uint160 chainID = ValidateCurrencyName(name, true, &chainDef);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain for merge mining");
    }

    // confirm data from blockchain
    CRPCChainData chainData;
    if (ConnectedChains.GetChainInfo(chainID, chainData))
    {
        chainDef = chainData.chainDefinition;
    }

    if (!chainDef.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain not found");
    }

    CBlock blk;

    if (!DecodeHexBlk(blk, params[0].get_str()))
        return "deserialize-invalid";

    CPBaaSMergeMinedChainData blkData = CPBaaSMergeMinedChainData(chainDef, rpchost, rpcport, rpcuserpass, blk);
    return ConnectedChains.AddMergedBlock(blkData) ? NullUniValue : "blocksfull";
}

UniValue submitmergedblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "submitmergedblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAttempts to submit one more more new blocks to one or more networks.\n"
            "Each merged block submission may be valid for Verus and/or up to 8 merge mined chains.\n"
            "The submitted block consists of a valid block for this chain, along with embedded headers of up to 8 other chains.\n"
            "If the hash for this header meets targets of other chains that have been added with 'addmergedblock', this API will\n"
            "submit those blocks to the specified URL endpoints with an RPC 'submitblock' request."
            "\nAttempts to submit one more more new blocks to one or more networks.\n"
            "The 'jsonparametersobject' parameter is currently ignored.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"    (string, required) the hex-encoded block data to submit\n"
            "2. \"jsonparametersobject\"     (string, optional) object of optional parameters\n"
            "    {\n"
            "      \"workid\" : \"id\"    (string, optional) if the server provided a workid, it MUST be included with submissions\n"
            "    }\n"
            "\nResult:\n"
            "\"duplicate\" - node already has valid copy of block\n"
            "\"duplicate-invalid\" - node already has block, but it is invalid\n"
            "\"duplicate-inconclusive\" - node already has block but has not validated it\n"
            "\"inconclusive\" - node has not validated the block, it may not be on the node's current best chain\n"
            "\"rejected\" - block was rejected as invalid\n"
            "For more information on submitblock parameters and results, see: https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki#block-submission\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );

    CheckPBaaSAPIsValid();

    CBlock block;
    //LogPrintStr("Hex block submission: " + params[0].get_str());
    if (!DecodeHexBlk(block, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex)
            {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                // Otherwise, we might only have the header - process the block before returning
                fBlockPresent = true;
            }
        }
    }

    CValidationState state;
    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    //printf("submitblock, height=%d, coinbase sequence: %d, scriptSig: %s\n", chainActive.LastTip()->GetHeight()+1, block.vtx[0].vin[0].nSequence, block.vtx[0].vin[0].scriptSig.ToString().c_str());
    bool fAccepted = ProcessNewBlock(1, chainActive.LastTip()->GetHeight()+1, state, Params(), NULL, &block, true, NULL);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (fAccepted)
    {
        if (!sc.found)
            return "inconclusive";
        state = sc.state;
    }
    return BIP22ValidationResult(state);
}

UniValue getmergedblocktemplate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getblocktemplate ( \"jsonrequestobject\" )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments:\n"
            "1. \"jsonrequestobject\"       (string, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\" or omitted\n"
            "       \"capabilities\":[       (array, optional) A list of strings\n"
            "           \"support\"           (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "         ]\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                     (numeric) The block version\n"
            "  \"previousblockhash\" : \"xxxx\",    (string) The hash of current highest block\n"
            "  \"finalsaplingroothash\" : \"xxxx\", (string) The hash of the final sapling root\n"
            "  \"transactions\" : [                 (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",          (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"hash\" : \"xxxx\",          (string) hash/id encoded in little-endian hexadecimal\n"
            "         \"depends\" : [              (array) array of numbers \n"
            "             n                        (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                   (numeric) difference in value between transaction inputs and outputs (in Satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,               (numeric) total number of SigOps, as counted for purposes of block limits; if key is not present, sigop count is unknown and clients MUST NOT assume there aren't any\n"
            "         \"required\" : true|false     (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
//            "  \"coinbaseaux\" : {                  (json object) data that should be included in the coinbase's scriptSig content\n"
//            "      \"flags\" : \"flags\"            (string) \n"
//            "  },\n"
//            "  \"coinbasevalue\" : n,               (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in Satoshis)\n"
            "  \"coinbasetxn\" : { ... },           (json object) information for coinbase transaction\n"
            "  \"target\" : \"xxxx\",               (string) The hash target\n"
            "  \"mintime\" : xxx,                   (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                      (array of string) list of ways the block template may be changed \n"
            "     \"value\"                         (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",   (string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxx\",                 (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getblocktemplate", "")
            + HelpExampleRpc("getblocktemplate", "")
         );

    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    // Wallet or miner address is required because we support coinbasetxn
    if (GetArg("-mineraddress", "").empty()) {
#ifdef ENABLE_WALLET
        if (!pwalletMain) {
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Wallet disabled and -mineraddress not set");
        }
#else
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "verusd compiled without wallet and -mineraddress not set");
#endif
    }

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    // TODO: Re-enable coinbasevalue once a specification has been written
    bool coinbasetxn = true;
    if (params.size() > 0)
    {
        const UniValue& oparam = params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            BlockMap::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end()) {
                CBlockIndex *pindex = mi->second;
                if (pindex)
                {
                    if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                        return "duplicate";
                    if (pindex->nStatus & BLOCK_FAILED_MASK)
                        return "duplicate-invalid";
                }
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = chainActive.LastTip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    bool fvNodesEmpty;
    {
        LOCK(cs_vNodes);
        fvNodesEmpty = vNodes.empty();
    }
    if (Params().MiningRequiresPeers() && (IsNotInSync() || fvNodesEmpty))
    {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Cannot get a block template while no peers are connected or chain not in sync!");
    }

    //if (IsInitialBlockDownload())
     //   throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Zcash is downloading blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        boost::system_time checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.LastTip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = boost::get_system_time() + boost::posix_time::minutes(1);

            boost::unique_lock<boost::mutex> lock(csBestBlock);
            while (chainActive.LastTip()->GetBlockHash() == hashWatchedChain && IsRPCRunning())
            {
                if (!cvBlockChange.timed_wait(lock, checktxtime))
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += boost::posix_time::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CBlockTemplate* pblocktemplate;
    if (pindexPrev != chainActive.LastTip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlockWithKey, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainActive.LastTip();
        nStart = GetTime();

        // Create new block
        if(pblocktemplate)
        {
            delete pblocktemplate;
            pblocktemplate = NULL;
        }
#ifdef ENABLE_WALLET
        CReserveKey reservekey(pwalletMain);
        pblocktemplate = CreateNewBlockWithKey(reservekey,chainActive.LastTip()->GetHeight()+1);
#else
        pblocktemplate = CreateNewBlockWithKey();
#endif
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory or no available utxo for staking");

        // Need to update only after we know CreateNewBlockWithKey succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Update nTime
    UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
    pblock->nNonce = uint256();

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue txCoinbase = NullUniValue;
    UniValue transactions(UniValue::VARR);
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    BOOST_FOREACH (const CTransaction& tx, pblock->vtx) {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() && !coinbasetxn)
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.push_back(Pair("data", EncodeHexTx(tx)));

        entry.push_back(Pair("hash", txHash.GetHex()));

        UniValue deps(UniValue::VARR);
        BOOST_FOREACH (const CTxIn &in, tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.push_back(Pair("depends", deps));

        int index_in_template = i - 1;
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template]));
        entry.push_back(Pair("sigops", pblocktemplate->vTxSigOps[index_in_template]));

        if (tx.IsCoinBase()) {
            // Show founders' reward if it is required
            //if (pblock->vtx[0].vout.size() > 1) {
                // Correct this if GetBlockTemplate changes the order
            //    entry.push_back(Pair("foundersreward", (int64_t)tx.vout[1].nValue));
            //}
            CAmount nReward = GetBlockSubsidy(chainActive.LastTip()->GetHeight()+1, Params().GetConsensus());
            entry.push_back(Pair("coinbasevalue", nReward));
            entry.push_back(Pair("required", true));
            txCoinbase = entry;
        } else
            transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    static UniValue aMutable(UniValue::VARR);
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("capabilities", aCaps));
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("finalsaplingroothash", pblock->hashFinalSaplingRoot.GetHex()));
    result.push_back(Pair("transactions", transactions));
    if (coinbasetxn) {
        assert(txCoinbase.isObject());
        result.push_back(Pair("coinbasetxn", txCoinbase));
    } else {
        result.push_back(Pair("coinbaseaux", aux));
        result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    }
    result.push_back(Pair("longpollid", chainActive.LastTip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast)));
    if ( ASSETCHAINS_STAKED != 0 )
    {
        arith_uint256 POWtarget; int32_t PoSperc;
        POWtarget = komodo_PoWtarget(&PoSperc,hashTarget,(int32_t)(pindexPrev->GetHeight()+1),ASSETCHAINS_STAKED);
        result.push_back(Pair("target", POWtarget.GetHex()));
        result.push_back(Pair("PoSperc", (int64_t)PoSperc));
        result.push_back(Pair("ac_staked", (int64_t)ASSETCHAINS_STAKED));
        result.push_back(Pair("origtarget", hashTarget.GetHex()));
    } else result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
    result.push_back(Pair("curtime", pblock->GetBlockTime()));
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->GetHeight()+1)));

    //fprintf(stderr,"return complete template\n");
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "identity",     "registernamecommitment",       &registernamecommitment, true  },
    { "identity",     "registeridentity",             &registeridentity,       true  },
    { "identity",     "updateidentity",               &updateidentity,         true  },
    { "identity",     "revokeidentity",               &revokeidentity,         true  },
    { "identity",     "setidentitytimelock",          &setidentitytimelock,    true  },
    { "identity",     "recoveridentity",              &recoveridentity,        true  },
    { "identity",     "getidentity",                  &getidentity,            true  },
    { "identity",     "listidentities",               &listidentities,         true  },
    { "identity",     "getidentitieswithaddress",     &getidentitieswithaddress, true  },
    { "identity",     "getidentitieswithrevocation",  &getidentitieswithrevocation, true  },
    { "identity",     "getidentitieswithrecovery",    &getidentitieswithrecovery, true  },
    { "marketplace",  "makeoffer",                    &makeoffer,              true  },
    { "marketplace",  "takeoffer",                    &takeoffer,              true  },
    { "marketplace",  "getoffers",                    &getoffers,              true  },
    { "marketplace",  "listopenoffers",               &listopenoffers,         true  },
    { "marketplace",  "closeoffers",                  &closeoffers,            true  },
    { "multichain",   "definecurrency",               &definecurrency,         true  },
    { "multichain",   "listcurrencies",               &listcurrencies,         true  },
    { "multichain",   "getcurrencyconverters",        &getcurrencyconverters,  true  },
    { "multichain",   "getcurrency",                  &getcurrency,            true  },
    { "multichain",   "getreservedeposits",           &getreservedeposits,     true  },
    { "multichain",   "getnotarizationdata",          &getnotarizationdata,    true  },
    { "multichain",   "getlaunchinfo",                &getlaunchinfo,          true  },
    { "multichain",   "getbestproofroot",             &getbestproofroot,       true  },
    { "multichain",   "submitacceptednotarization",   &submitacceptednotarization, true },
    { "multichain",   "submitimports",                &submitimports,          true },
    { "multichain",   "getinitialcurrencystate",      &getinitialcurrencystate, true  },
    { "multichain",   "getcurrencystate",             &getcurrencystate,       true  },
    { "multichain",   "getsaplingtree",               &getsaplingtree,         true  },
    { "multichain",   "sendcurrency",                 &sendcurrency,           true  },
    { "multichain",   "getpendingtransfers",          &getpendingtransfers,    true  },
    { "multichain",   "getexports",                   &getexports,             true  },
    { "multichain",   "getlastimportfrom",            &getlastimportfrom,      true  },
    { "multichain",   "getimports",                   &getimports,             true  },
    { "multichain",   "refundfailedlaunch",           &refundfailedlaunch,     true  },
    { "multichain",   "refundfailedlaunch",           &refundfailedlaunch,     true  },
    { "multichain",   "getmergedblocktemplate",       &getmergedblocktemplate, true  },
    { "multichain",   "addmergedblock",               &addmergedblock,         true  }
};

void RegisterPBaaSRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
