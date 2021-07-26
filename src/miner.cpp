// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "miner.h"
#ifdef ENABLE_MINING
#include "pow/tromp/equi_miner.h"
#endif

#include "amount.h"
#include "chainparams.h"
#include "cc/StakeGuard.h"
#include "importcoin.h"
#include "consensus/consensus.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#ifdef ENABLE_MINING
#include "crypto/equihash.h"
#include "crypto/verus_hash.h"
#endif
#include "hash.h"
#include "key_io.h"
#include "main.h"
#include "metrics.h"
#include "net.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "random.h"
#include "timedata.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include "zcash/Address.hpp"
#include "transaction_builder.h"

#include "sodium.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#ifdef ENABLE_MINING
#include <functional>
#endif
#include <mutex>

#include "pbaas/pbaas.h"
#include "pbaas/notarization.h"
#include "pbaas/identity.h"
#include "rpc/pbaasrpc.h"
#include "transaction_builder.h"

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;
    
    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
    
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

void UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    pblock->nTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // Updating time can change work required on testnet:
    if (consensusParams.nPowAllowMinDifficultyBlocksAfterHeight != boost::none) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }
}

#include "komodo_defs.h"

extern CCriticalSection cs_metrics;
extern int32_t KOMODO_MININGTHREADS,KOMODO_LONGESTCHAIN,IS_KOMODO_NOTARY,USE_EXTERNAL_PUBKEY,KOMODO_CHOSEN_ONE,ASSETCHAIN_INIT,KOMODO_INITDONE,KOMODO_ON_DEMAND,KOMODO_INITDONE,KOMODO_PASSPORT_INITDONE;
extern uint64_t ASSETCHAINS_COMMISSION, ASSETCHAINS_STAKED;
extern bool VERUS_MINTBLOCKS;
extern uint64_t ASSETCHAINS_REWARD[ASSETCHAINS_MAX_ERAS], ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_NONCEMASK[];
extern const char *ASSETCHAINS_ALGORITHMS[];
extern int32_t VERUS_MIN_STAKEAGE, ASSETCHAINS_EQUIHASH, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA, ASSETCHAINS_LWMAPOS, ASSETCHAINS_NONCESHIFT[], ASSETCHAINS_HASHESPERROUND[];
extern uint32_t ASSETCHAINS_ALGO;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern uint160 ASSETCHAINS_CHAINID;
extern uint160 VERUS_CHAINID;
extern std::string VERUS_CHAINNAME;
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK;
extern string PBAAS_HOST, PBAAS_USERPASS, ASSETCHAINS_RPCHOST, ASSETCHAINS_RPCCREDENTIALS;;
extern int32_t PBAAS_PORT;
extern uint16_t ASSETCHAINS_RPCPORT;
extern std::string NOTARY_PUBKEY,ASSETCHAINS_OVERRIDE_PUBKEY;
void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len);

extern uint8_t NOTARY_PUBKEY33[33],ASSETCHAINS_OVERRIDE_PUBKEY33[33];
uint32_t Mining_start, Mining_height;
int32_t My_notaryid = -1;
int32_t komodo_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp);
int32_t komodo_pax_opreturn(int32_t height,uint8_t *opret,int32_t maxsize);
int32_t komodo_baseid(char *origbase);
int32_t komodo_validate_interest(const CTransaction &tx,int32_t txheight,uint32_t nTime,int32_t dispflag);
int64_t komodo_block_unlocktime(uint32_t nHeight);
uint64_t komodo_commission(const CBlock *block);
int32_t komodo_staked(CMutableTransaction &txNew,uint32_t nBits,uint32_t *blocktimep,uint32_t *txtimep,uint256 *utxotxidp,int32_t *utxovoutp,uint64_t *utxovaluep,uint8_t *utxosig);
int32_t verus_staked(CBlock *pBlock, CMutableTransaction &txNew, uint32_t &nBits, arith_uint256 &hashResult, std::vector<unsigned char> &utxosig, CTxDestination &rewardDest);
int32_t komodo_notaryvin(CMutableTransaction &txNew,uint8_t *notarypub33);

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int &nExtraNonce, bool buildMerkle, uint32_t *pSaveBits)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;

    if (pSaveBits)
    {
        *pSaveBits = pblock->nBits;
    }

    int32_t nHeight = pindexPrev->GetHeight() + 1;

    int solutionVersion = CConstVerusSolutionVector::activationHeight.ActiveVersion(nHeight);

    if (solutionVersion >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS_HEADER)
    {
        // coinbase should already be finalized in the new version
        if (buildMerkle)
        {
            pblock->hashMerkleRoot = pblock->BuildMerkleTree();
            pblock->SetPrevMMRRoot(ChainMerkleMountainView(chainActive.GetMMR(), pindexPrev->GetHeight()).GetRoot());
            BlockMMRange mmRange(pblock->BuildBlockMMRTree());
            BlockMMView mmView(mmRange);
            pblock->SetBlockMMRRoot(mmView.GetRoot());
            pblock->AddUpdatePBaaSHeader();
        }

        UpdateTime(pblock, Params().GetConsensus(), pindexPrev);

        // POS blocks have already had their solution space filled, and there is no actual extra nonce, extradata is used
        // for POS proof, so don't modify it
        if (solutionVersion >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS && !pblock->IsVerusPOSBlock())
        {
            pblock->AddUpdatePBaaSHeader();

            uint8_t dummy;
            // clear extra data to allow adding more PBaaS headers
            pblock->SetExtraData(&dummy, 0);

            // combine blocks and set compact difficulty if necessary
            uint32_t savebits;
            if ((savebits = ConnectedChains.CombineBlocks(*pblock)) && pSaveBits)
            {
                arith_uint256 ours, merged;
                ours.SetCompact(pblock->nBits);
                merged.SetCompact(savebits);
                if (merged > ours)
                {
                    *pSaveBits = savebits;
                }
            }

            // extra nonce is kept in the header, not in the coinbase any longer
            // this allows instant spend transactions to use coinbase funds for
            // inputs by ensuring that once final, the coinbase transaction hash
            // will not continue to change
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
            s << nExtraNonce;
            std::vector<unsigned char> vENonce(s.begin(), s.end());

            assert(pblock->ExtraDataLen() >= vENonce.size());
            pblock->SetExtraData(vENonce.data(), vENonce.size());
        }
    }
    else
    {
        // finalize input of coinbase
        CMutableTransaction txcb(pblock->vtx[0]);
        txcb.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
        assert(txcb.vin[0].scriptSig.size() <= 100);
        pblock->vtx[0] = txcb;
        if (buildMerkle)
        {
            pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        }

        UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
    }
}

extern CWallet *pwalletMain;

CPubKey GetSolutionPubKey(const std::vector<std::vector<unsigned char>> &vSolutions, txnouttype txType)
{
    CPubKey pk;

    if (txType == TX_PUBKEY)
    {
        pk = CPubKey(vSolutions[0]);
    }
    else if(txType == TX_PUBKEYHASH)
    {
        // we need to have this in our wallet to get the public key
        LOCK(pwalletMain->cs_wallet);
        pwalletMain->GetPubKey(CKeyID(uint160(vSolutions[0])), pk);
    }
    else if (txType == TX_CRYPTOCONDITION)
    {
        if (vSolutions[0].size() == 33)
        {
            pk = CPubKey(vSolutions[0]);
        }
        else if (vSolutions[0].size() == 34 && vSolutions[0][0] == COptCCParams::ADDRTYPE_PK)
        {
            pk = CPubKey(std::vector<unsigned char>(vSolutions[0].begin() + 1, vSolutions[0].end()));
        }
        else if (vSolutions[0].size() == 20)
        {
            LOCK(pwalletMain->cs_wallet);
            pwalletMain->GetPubKey(CKeyID(uint160(vSolutions[0])), pk);
        }
        else if (vSolutions[0].size() == 21 && vSolutions[0][0] == COptCCParams::ADDRTYPE_ID)
        {
            // destination is an identity, see if we can get its first public key
            std::pair<CIdentityMapKey, CIdentityMapValue> identity;

            if (pwalletMain->GetIdentity(CIdentityID(uint160(std::vector<unsigned char>(vSolutions[0].begin() + 1, vSolutions[0].end()))), identity) && 
                identity.second.IsValidUnrevoked() && 
                identity.second.primaryAddresses.size())
            {
                CPubKey pkTmp = boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), identity.second.primaryAddresses[0]);
                if (pkTmp.IsValid())
                {
                    pk = pkTmp;
                }
                else
                {
                    LOCK(pwalletMain->cs_wallet);
                    pwalletMain->GetPubKey(CKeyID(GetDestinationID(identity.second.primaryAddresses[0])), pk);
                }
            }
        }
    }
    return pk;
}

CPubKey GetScriptPublicKey(const CScript &scriptPubKey)
{
    txnouttype typeRet;
    std::vector<std::vector<unsigned char>> vSolutions;
    if (Solver(scriptPubKey, typeRet, vSolutions))
    {
        return GetSolutionPubKey(vSolutions, typeRet);
    }
    return CPubKey();
}

// call a chain that we consider a notary chain, meaning we call its daemon, not the other way around,
// retrieve new exports that we have not imported, and process them. Also, send any exports that are now
// provable with the available notarization on the specified chain.
void ProcessNewImports(const uint160 &sourceChainID, CPBaaSNotarization &lastConfirmed, CUTXORef &lastConfirmedUTXO, uint32_t nHeight)
{
    if (CConstVerusSolutionVector::GetVersionByHeight(nHeight) < CActivationHeight::ACTIVATE_PBAAS || 
        CConstVerusSolutionVector::activationHeight.IsActivationHeight(CActivationHeight::ACTIVATE_PBAAS, nHeight))
    {
        return;
    }

    uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, Params().GetConsensus());

    // get any pending imports from the source chain. if the source chain is this chain, we don't need notarization
    CCurrencyDefinition thisChain = ConnectedChains.ThisChain();
    uint160 thisChainID = thisChain.GetID();
    CCurrencyDefinition sourceChain = ConnectedChains.GetCachedCurrency(sourceChainID);
    if (!sourceChain.IsValid())
    {
        printf("Unrecognized source chain %s\n", EncodeDestination(CIdentityID(sourceChainID)).c_str());
        return;
    }

    // printf("%s: processing imports for %s\n", __func__, sourceChain.name.c_str());

    bool isSameChain = thisChain.GetID() == sourceChainID;

    CChainNotarizationData cnd;
    if (!(GetNotarizationData(sourceChainID, cnd) && cnd.IsConfirmed()))
    {
        printf("Cannot get notarization data for currency %s\n", sourceChain.name.c_str());
        return;
    }

    lastConfirmedUTXO = cnd.vtx[cnd.lastConfirmed].first;
    lastConfirmed = cnd.vtx[cnd.lastConfirmed].second;

    CTransaction lastImportTx;

    // we need to find the last unspent import transaction
    std::vector<CAddressUnspentDbEntry> unspentOutputs;

    bool found = false;
    CAddressUnspentDbEntry foundEntry;
    CCrossChainImport lastCCI;
    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;

    {
        LOCK(cs_main);

        if (!isSameChain &&
            lastConfirmed.proofRoots.count(sourceChainID) &&
            GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(sourceChainID, CCrossChainImport::CurrencySystemImportKey())), CScript::P2IDX, unspentOutputs))
        {
            // if one spends the prior one, get the one that is not spent
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

            if (found && 
                lastCCI.sourceSystemHeight < lastConfirmed.notarizationHeight)
            {
                UniValue params(UniValue::VARR);

                params.push_back(EncodeDestination(CIdentityID(thisChainID)));
                params.push_back((int64_t)lastCCI.sourceSystemHeight);
                params.push_back((int64_t)lastConfirmed.proofRoots[sourceChainID].rootHeight);

                UniValue result = NullUniValue;
                try
                {
                    if (sourceChainID == thisChain.GetID())
                    {
                        UniValue getexports(const UniValue& params, bool fHelp);
                        result = getexports(params, false);
                    }
                    else
                    {
                        result = find_value(RPCCallRoot("getexports", params), "result");
                    }
                } catch (exception e)
                {
                    printf("Could not get latest export from external chain %s for %s\n", EncodeDestination(CIdentityID(sourceChainID)).c_str(), uni_get_str(params[0]).c_str());
                    return;
                }

                // now, we should have a list of exports to import in order
                if (!result.isArray() || !result.size())
                {
                    return;
                }
                bool foundCurrent = false;
                for (int i = 0; i < result.size(); i++)
                {
                    uint256 exportTxId = uint256S(uni_get_str(find_value(result[i], "txid")));
                    if (!foundCurrent && !lastCCI.exportTxId.IsNull())
                    {
                        // when we find our export, take the next
                        if (exportTxId == lastCCI.exportTxId)
                        {
                            foundCurrent = true;
                        }
                        continue;
                    }

                    // create one import at a time
                    uint32_t notarizationHeight = uni_get_int64(find_value(result[i], "height"));
                    int32_t exportTxOutNum = uni_get_int(find_value(result[i], "txoutnum"));
                    CPartialTransactionProof txProof = CPartialTransactionProof(find_value(result[i], "partialtransactionproof"));
                    UniValue transferArrUni = find_value(result[i], "transfers");
                    if (!notarizationHeight || 
                        exportTxId.IsNull() || 
                        exportTxOutNum == -1 ||
                        !transferArrUni.isArray())
                    {
                        printf("Invalid export from %s\n", uni_get_str(params[0]).c_str());
                        return;
                    }

                    CTransaction exportTx;
                    uint256 blkHash;
                    auto proofRootIt = lastConfirmed.proofRoots.find(sourceChainID);
                    if (!isSameChain &&
                        !(txProof.IsValid() &&
                          !txProof.GetPartialTransaction(exportTx).IsNull() &&
                          txProof.TransactionHash() == exportTxId &&
                          proofRootIt != lastConfirmed.proofRoots.end() &&
                          proofRootIt->second.stateRoot == txProof.CheckPartialTransaction(exportTx) &&
                          exportTx.vout.size() > exportTxOutNum))
                    {
                        /* printf("%s: proofRoot: %s, checkPartialRoot: %s, proofheight: %u, ischainproof: %s, blockhash: %s\n", 
                            __func__,
                            proofRootIt->second.ToUniValue().write(1,2).c_str(),
                            txProof.CheckPartialTransaction(exportTx).GetHex().c_str(),
                            txProof.GetProofHeight(),
                            txProof.IsChainProof() ? "true" : "false",
                            txProof.GetBlockHash().GetHex().c_str()); */
                        printf("Invalid export for %s\n", uni_get_str(params[0]).c_str());
                        return;
                    }
                    else if (isSameChain &&
                            !(myGetTransaction(exportTxId, exportTx, blkHash) &&
                            exportTx.vout.size() > exportTxOutNum))
                    {
                        printf("Invalid export msg2 from %s\n", uni_get_str(params[0]).c_str());
                        return;
                    }
                    if (!foundCurrent)
                    {
                        CCrossChainExport ccx(exportTx.vout[exportTxOutNum].scriptPubKey);
                        if (!ccx.IsValid())
                        {
                            printf("Invalid export msg3 from %s\n", uni_get_str(params[0]).c_str());
                            return;
                        }
                        if (ccx.IsChainDefinition())
                        {
                            continue;
                        }
                    }
                    std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> oneExport =
                        std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[exportTxOutNum].scriptPubKey, 
                                                        exportTx.vout[exportTxOutNum].nValue, 
                                                        CTxIn(exportTxId, exportTxOutNum)),
                                                        txProof),
                                        std::vector<CReserveTransfer>());
                    for (int j = 0; j < transferArrUni.size(); j++)
                    {
                        //printf("%s: onetransfer: %s\n", __func__, transferArrUni[j].write(1,2).c_str());
                        oneExport.second.push_back(CReserveTransfer(transferArrUni[j]));
                        if (!oneExport.second.back().IsValid())
                        {
                            printf("Invalid reserve transfers in export from %s\n", sourceChain.name.c_str());
                            return;
                        }
                    }
                    exports.push_back(oneExport);
                }
            }
            std::map<uint160, std::vector<std::pair<int, CTransaction>>> newImports;
            ConnectedChains.CreateLatestImports(sourceChain, lastConfirmedUTXO, exports, newImports);
        }
        else if (isSameChain)
        {
            ConnectedChains.ProcessLocalImports();
            return;
        }
        else
        {
            LogPrint("crosschain", "Could not get prior import for currency %s\n", sourceChain.name.c_str());
            return;
        }
    }
}

bool CheckNotaryConnection(const CRPCChainData &notarySystem)
{
    // ensure we have connection parameters, or we fail
    if (notarySystem.rpcHost == "" || notarySystem.rpcUserPass == "" || !notarySystem.rpcPort)
    {
        return false;
    }
    return true;
}

bool CallNotary(const CRPCChainData &notarySystem, std::string command, const UniValue &params, UniValue &result, UniValue &error)
{
    // ensure we have connection parameters, or we fail
    if (!CheckNotaryConnection(notarySystem))
    {
        return false;
    }

    try
    {
        UniValue rpcResult = RPCCall(command, params, notarySystem.rpcUserPass, notarySystem.rpcPort, notarySystem.rpcHost);
        result = find_value(rpcResult, "result");
        error = find_value(rpcResult, "error");
    } catch (std::exception e)
    {
        error = strprintf("Failed to connect to %s chain, error: %s\n", notarySystem.chainDefinition.name.c_str(), e.what());
    }
    return error.isNull();
}

// get initial currency state from the notary system specified
bool GetBlockOneLaunchNotarization(const CRPCChainData &notarySystem, 
                                   const uint160 &currencyID,
                                   CCurrencyDefinition &curDef,
                                   CPBaaSNotarization &launchNotarization,
                                   CPBaaSNotarization &notaryNotarization,
                                   std::pair<CUTXORef, CPartialTransactionProof> &notarizationOutputProof,
                                   std::pair<CUTXORef, CPartialTransactionProof> &exportOutputProof,
                                   std::vector<CReserveTransfer> &exportTransfers)
{
    UniValue result, error;
    bool retVal = false;

    UniValue params(UniValue::VARR);
    params.push_back(EncodeDestination(CIdentityID(currencyID)));

    // VRSC and VRSCTEST do not start with a notary chain
    if (!IsVerusActive() && ConnectedChains.IsNotaryAvailable())
    {
        // we are starting a PBaaS chain. We only assume that our chain definition and the first notary chain, if there is one, are setup
        // in ConnectedChains. All other currencies and identities necessary to start have not been populated and must be in block 1 by
        // getting the information from the notary chain.
        if (CallNotary(notarySystem, "getlaunchinfo", params, result, error))
        {
            CCurrencyDefinition currency(find_value(result, "currencydefinition"));
            CPBaaSNotarization notarization(find_value(result, "launchnotarization"));
            notaryNotarization = CPBaaSNotarization(find_value(result, "notarynotarization"));
            CPartialTransactionProof notarizationProof(find_value(result, "notarizationproof"));
            CUTXORef notarizationUtxo(uint256S(uni_get_str(find_value(result, "notarizationtxid"))), uni_get_int(find_value(result, "notarizationvoutnum")));

            CPartialTransactionProof exportProof(find_value(result, "exportproof"));
            UniValue exportTransfersUni = find_value(result, "exportransfers");

            bool reject = false;
            if (exportTransfersUni.isArray() && exportTransfersUni.size())
            {
                for (int i = 0; i < exportTransfersUni.size(); i++)
                {
                    CReserveTransfer oneTransfer(exportTransfersUni[i]);
                    if (!oneTransfer.IsValid())
                    {
                        reject = true;
                    }
                    else
                    {
                        exportTransfers.push_back(oneTransfer);
                    }
                }
            }
            CUTXORef exportUtxo(uint256S(uni_get_str(find_value(result, "exporttxid"))), uni_get_int(find_value(result, "exportvoutnum")));

            if (reject ||
                !currency.IsValid() ||
                !notarization.IsValid() ||
                !notarizationProof.IsValid() ||
                !notaryNotarization.IsValid())
            {
                LogPrintf("%s: invalid launch notarization for currency %s\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
                printf("%s: invalid launch notarization for currency %s\ncurrencydefinition: %s\nnotarization: %s\ntransactionproof: %s\n", 
                    __func__, 
                    EncodeDestination(CIdentityID(currencyID)).c_str(),
                    currency.ToUniValue().write(1,2).c_str(),
                    notarization.ToUniValue().write(1,2).c_str(),
                    notarizationProof.ToUniValue().write(1,2).c_str());
            }
            else
            {
                //printf("%s: proofroot: %s\n", __func__, latestProofRoot.ToUniValue().write(1,2).c_str());
                curDef = currency;
                launchNotarization = notarization;
                launchNotarization.proofRoots = notaryNotarization.proofRoots;
                notaryNotarization.proofRoots[ASSETCHAINS_CHAINID] = CProofRoot::GetProofRoot(0);
                notaryNotarization.currencyStates[ASSETCHAINS_CHAINID] = launchNotarization.currencyState;
                notarizationOutputProof = std::make_pair(notarizationUtxo, notarizationProof);
                exportOutputProof = std::make_pair(exportUtxo, exportProof);
                retVal = true;
            }
        }
        else
        {
            LogPrintf("%s: error calling notary chain %s\n", __func__, error.write(1,2).c_str());
            printf("%s: error calling notary chain %s\n", __func__, error.write(1,2).c_str());
        }
    }
    return retVal;
}

bool DecodeOneExport(const UniValue obj, CCrossChainExport &ccx,
                     std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> &oneExport)
{
    uint32_t exportHeight = uni_get_int64(find_value(obj, "height"));
    uint256 txId = uint256S(uni_get_str(find_value(obj, "txid")));
    uint32_t outNum = uni_get_int(find_value(obj, "txoutnum"));
    ccx = CCrossChainExport(find_value(obj, "exportinfo"));
    if (!ccx.IsValid())
    {
        LogPrintf("%s: invalid launch export from notary chain\n", __func__);
        printf("%s: invalid launch export from notary chain\n", __func__);
        return false;
    }
    CPartialTransactionProof partialTxProof(find_value(obj, "partialtransactionproof"));
    CTransaction exportTx;
    COptCCParams p;
    CScript outputScript;
    CAmount outputValue;

    if (!partialTxProof.IsValid() ||
        partialTxProof.GetPartialTransaction(exportTx).IsNull() ||
        partialTxProof.TransactionHash() != txId ||
        exportTx.vout.size() <= outNum ||
        !exportTx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) ||
        !p.IsValid() ||
        !p.evalCode == EVAL_CROSSCHAIN_EXPORT ||
        (outputValue = exportTx.vout[outNum].nValue) == -1)
    {
        //UniValue jsonTxOut(UniValue::VOBJ);
        //TxToUniv(exportTx, uint256(), jsonTxOut);
        //printf("%s: proofTxRoot:%s\npartialTx: %s\n", __func__, 
        //                                            partialTxProof.GetPartialTransaction(exportTx).GetHex().c_str(),
        //                                            jsonTxOut.write(1,2).c_str());
        LogPrintf("%s: invalid partial transaction proof from notary chain\n", __func__);
        printf("%s: invalid partial transaction proof from notary chain\n", __func__);
        return false;
    }

    UniValue transfers = find_value(obj, "transfers");
    std::vector<CReserveTransfer> reserveTransfers;
    if (transfers.isArray() && transfers.size())
    {
        for (int i = 0; i < transfers.size(); i++)
        {
            CReserveTransfer rt(transfers[i]);
            if (rt.IsValid())
            {
                reserveTransfers.push_back(rt);
            }
        }
    }

    oneExport.first.first = CInputDescriptor(outputScript, outputValue, CTxIn(txId, outNum));
    oneExport.first.second = partialTxProof;
    oneExport.second = reserveTransfers;
    return true;
}

// get initial currency state from the notary system specified
bool GetBlockOneImports(const CRPCChainData &notarySystem, const CPBaaSNotarization &launchNotarization, std::map<uint160, std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>>> &exports)
{
    UniValue result, error;

    UniValue params(UniValue::VARR);
    params.push_back(EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
    params.push_back((int)0);
    if (launchNotarization.proofRoots.count(ConnectedChains.ThisChain().launchSystemID))
    {
        params.push_back((int64_t)launchNotarization.proofRoots.find(ConnectedChains.ThisChain().launchSystemID)->second.rootHeight);
    }

    // VRSC and VRSCTEST do not start with a notary chain
    if (!IsVerusActive() && ConnectedChains.IsNotaryAvailable())
    {
        // we are starting a PBaaS chain. We only assume that our chain definition and the first notary chain, if there is one, are setup
        // in ConnectedChains. All other currencies and identities necessary to start have not been populated and must be in block 1 by
        // getting the information from the notary chain.
        if (CallNotary(notarySystem, "getexports", params, result, error) &&
            result.isArray() &&
            result.size())
        {
            // we now have an array of exports that we should import into this system
            // load up to the last launch export on each currency
            for (int i = 0; i < result.size(); i++)
            {
                CCrossChainExport ccx;
                std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> oneExport;
                if (DecodeOneExport(result[i], ccx, oneExport))
                {
                    exports[ccx.destCurrencyID].push_back(oneExport);
                }
                else
                {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
    return false;
}

// This is called with either the initial currency, or the gateway converter currency
// to setup an import/export thread, transfer the initial issuance of native currency
// into the converter, and notarize the state of each currency.
// All outputs to do those things are added to the outputs vector.
bool AddOneCurrencyImport(const CCurrencyDefinition &newCurrency, 
                          const CPBaaSNotarization &lastNotarization,
                          const std::pair<CUTXORef, CPartialTransactionProof> *pLaunchProof,
                          const std::pair<CUTXORef, CPartialTransactionProof> *pFirstExport,
                          const std::vector<CReserveTransfer> &_exportTransfers,
                          CCurrencyValueMap &gatewayDeposits,
                          std::vector<CTxOut> &outputs,
                          CCurrencyValueMap &additionalFees)
{
    uint160 newCurID = newCurrency.GetID();
    CPBaaSNotarization newNotarization = lastNotarization;
    newNotarization.prevNotarization = CUTXORef();
    newNotarization.SetBlockOneNotarization();

    // each currency will get:
    // * one currency definition output
    // * notarization of latest currency state

    CCcontract_info CC;
    CCcontract_info *cp;

    // make a currency definition
    cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
    std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
    outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &newCurrency))));

    // import / export capable currencies include the main currency, fractional currencies on any system, 
    // gateway currencies. the launch system, and non-token currencies. they also get an import / export thread
    if (ConnectedChains.ThisChain().launchSystemID == newCurID ||
        (newCurrency.systemID == ASSETCHAINS_CHAINID &&
        (newCurrency.IsFractional() ||
        newCurrency.systemID == newCurID ||
        (newCurrency.IsGateway() && newCurrency.GetID() == newCurrency.gatewayID))))
    {
        uint160 firstNotaryID = ConnectedChains.FirstNotaryChain().chainDefinition.GetID();

        // first, put evidence of the notarization pre-import
        int notarizationIdx = -1;
        if (pLaunchProof)
        {
            // add notarization before other outputs
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            // now, we need to put the launch notarization evidence, followed by the import outputs
            CNotaryEvidence evidence = CNotaryEvidence(ConnectedChains.FirstNotaryChain().chainDefinition.GetID(),
                                                       pLaunchProof->first,
                                                       true,
                                                       std::map<CIdentityID, CIdentitySignature>(),
                                                       std::vector<CPartialTransactionProof>({pLaunchProof->second}),
                                                       CNotaryEvidence::TYPE_PARTIAL_TXPROOF);
            notarizationIdx = outputs.size();
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence))));
        }

        // create the import thread output
        cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
        if (newCurrency.proofProtocol == newCurrency.PROOF_CHAINID)
        {
            dests = std::vector<CTxDestination>({CIdentityID(newCurID)});
        }
        else
        {
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
        }

        if ((newCurrency.systemID == ASSETCHAINS_CHAINID) && firstNotaryID == newCurrency.launchSystemID)
        {
            uint256 transferHash;
            std::vector<CTxOut> importOutputs;
            CCurrencyValueMap importedCurrency, gatewayDepositsUsed, spentCurrencyOut;

            CPBaaSNotarization tempLastNotarization = lastNotarization;
            tempLastNotarization.currencyState.SetLaunchCompleteMarker(false);

            std::vector<CReserveTransfer> exportTransfers(_exportTransfers);
            if (!tempLastNotarization.NextNotarizationInfo(ConnectedChains.FirstNotaryChain().chainDefinition,
                                                           newCurrency,
                                                           0,
                                                           1,
                                                           exportTransfers,
                                                           transferHash,
                                                           newNotarization,
                                                           importOutputs,
                                                           importedCurrency,
                                                           gatewayDepositsUsed,
                                                           spentCurrencyOut))
            {
                LogPrintf("%s: invalid import for currency %s on system %s\n", __func__,
                                                                            newCurrency.name.c_str(), 
                                                                            EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)).c_str());
                return false;
            }

            // if fees are not converted, we will pay out original fees,
            // less liquidity fees, which go into the currency reserves
            bool feesConverted;
            CCurrencyValueMap liquidityFees;
            CCurrencyValueMap originalFees = 
                newNotarization.currencyState.CalculateConvertedFees(
                    newNotarization.currencyState.viaConversionPrice,
                    newNotarization.currencyState.viaConversionPrice,
                    ASSETCHAINS_CHAINID,
                    feesConverted,
                    liquidityFees,
                    additionalFees);
            
            if (!feesConverted)
            {
                additionalFees += (originalFees - liquidityFees);
            }

            newNotarization.SetBlockOneNotarization();

            // display import outputs
            CMutableTransaction debugTxOut;
            debugTxOut.vout = outputs;
            debugTxOut.vout.insert(debugTxOut.vout.end(), importOutputs.begin(), importOutputs.end());
            UniValue jsonTxOut(UniValue::VOBJ);
            TxToUniv(debugTxOut, uint256(), jsonTxOut);
            printf("%s: launch outputs: %s\nlast notarization: %s\nnew notarization: %s\n", __func__, 
                                                                                            jsonTxOut.write(1,2).c_str(),
                                                                                            lastNotarization.ToUniValue().write(1,2).c_str(),
                                                                                            newNotarization.ToUniValue().write(1,2).c_str());

            newNotarization.prevNotarization = CUTXORef();
            newNotarization.prevHeight = 0;

            // get the first export for launch from the notary chain
            CTransaction firstExportTx;
            if (!pFirstExport || !(pFirstExport->second.IsValid() && !pFirstExport->second.GetPartialTransaction(firstExportTx).IsNull()))
            {
                LogPrintf("%s: invalid first export for PBaaS or converter launch\n");
                return false;
            }

            // get the export for this import
            CCrossChainExport ccx(firstExportTx.vout[pFirstExport->first.n].scriptPubKey);
            if (!ccx.IsValid())
            {
                LogPrintf("%s: invalid export output for PBaaS or converter launch\n");
                return false;
            }

            // create an import based on launch conditions that covers all pre-allocations and uses the initial notarization.
            // generate outputs, then fill in numOutputs
            CCrossChainImport cci = CCrossChainImport(newCurrency.launchSystemID,
                                                      newNotarization.notarizationHeight,
                                                      newCurID,
                                                      ccx.totalAmounts,
                                                      CCurrencyValueMap(),
                                                      0,
                                                      ccx.hashReserveTransfers,
                                                      pFirstExport->first.hash,
                                                      pFirstExport->first.n);
            cci.SetSameChain(newCurrency.launchSystemID == ASSETCHAINS_CHAINID);
            cci.SetPostLaunch();
            cci.SetInitialLaunchImport();

            // anything we had before plus anything imported and minus all spent currency out should
            // be all reserve deposits remaining under control of this currency

            /* printf("%s: ccx.totalAmounts: %s\ngatewayDepositsUsed: %s\nadditionalFees: %s\noriginalFees: %s\n",
                __func__,
                ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
                gatewayDepositsUsed.ToUniValue().write(1,2).c_str(),
                additionalFees.ToUniValue().write(1,2).c_str(),
                originalFees.ToUniValue().write(1,2).c_str()); */

            // to determine left over reserves for deposit, consider imported and emitted as the same
            gatewayDeposits = CCurrencyValueMap(lastNotarization.currencyState.currencies, lastNotarization.currencyState.reserveIn);
            if (!newCurrency.IsFractional())
            {
                gatewayDeposits += originalFees;
            }

            gatewayDeposits.valueMap[newCurID] += gatewayDepositsUsed.valueMap[newCurID] + newNotarization.currencyState.primaryCurrencyOut;

            printf("importedcurrency %s\nspentcurrencyout %s\ngatewaydeposits %s\n", 
                importedCurrency.ToUniValue().write(1,2).c_str(),
                spentCurrencyOut.ToUniValue().write(1,2).c_str(),
                gatewayDeposits.ToUniValue().write(1,2).c_str());

            gatewayDeposits = (gatewayDeposits - spentCurrencyOut).CanonicalMap();

            printf("newNotarization.currencyState %s\nnewgatewaydeposits %s\n", 
                newNotarization.currencyState.ToUniValue().write(1,2).c_str(),
                gatewayDeposits.ToUniValue().write(1,2).c_str());

            // add the reserve deposit output with all deposits for this currency for the new chain
            if (gatewayDeposits.valueMap.size())
            {
                CCcontract_info *depositCp;
                CCcontract_info depositCC;

                // create the import thread output
                depositCp = CCinit(&depositCC, EVAL_RESERVE_DEPOSIT);
                std::vector<CTxDestination> depositDests({CPubKey(ParseHex(depositCC.CChexstr))});
                // put deposits under control of the launch system, where the imports using them will be coming from
                CReserveDeposit rd(newCurrency.IsPBaaSChain() ? newCurrency.launchSystemID : newCurID, gatewayDeposits);
                CAmount nativeOut = gatewayDeposits.valueMap.count(ASSETCHAINS_CHAINID) ? gatewayDeposits.valueMap[ASSETCHAINS_CHAINID] : 0;
                outputs.push_back(CTxOut(nativeOut, MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, depositDests, 1, &rd))));
            }

            if (newCurrency.notaries.size())
            {
                // notaries all get an even share of 10% of the launch fee in the launch currency to use for notarizing
                // they may also get pre-allocations
                uint160 notaryNativeID = ConnectedChains.FirstNotaryChain().chainDefinition.GetID();
                CAmount notaryFeeShare = ConnectedChains.FirstNotaryChain().chainDefinition.currencyRegistrationFee / 10;
                additionalFees -= CCurrencyValueMap(std::vector<uint160>({notaryNativeID}), std::vector<int64_t>({notaryFeeShare}));
                CAmount oneNotaryShare = notaryFeeShare / newCurrency.notaries.size();
                CAmount notaryModExtra = notaryFeeShare % newCurrency.notaries.size();
                for (auto &oneNotary : newCurrency.notaries)
                {
                    CTokenOutput to(notaryNativeID, oneNotaryShare);
                    if (notaryModExtra)
                    {
                        to.reserveValues.valueMap[notaryNativeID]++;
                        notaryModExtra--;
                    }
                    outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, 
                                                    std::vector<CTxDestination>({CIdentityID(oneNotary)}), 
                                                    1, 
                                                    &to))));
                }
            }

            cci.numOutputs = importOutputs.size();

            // now add the import itself
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci))));

            // add notarization before other outputs
            cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);
            if (newCurID == ASSETCHAINS_CHAINID &&
                newCurrency.notarizationProtocol == newCurrency.NOTARIZATION_NOTARY_CHAINID)
            {
                dests = std::vector<CTxDestination>({CIdentityID(newCurID)});
            }
            else
            {
                dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            }
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &newNotarization))));

            // add export before other outputs
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            // now, we need to put the export evidence, followed by the import outputs
            CNotaryEvidence evidence = CNotaryEvidence(cci.sourceSystemID,
                                                       CUTXORef(uint256(), notarizationIdx),
                                                       true,
                                                       std::map<CIdentityID, CIdentitySignature>(),
                                                       std::vector<CPartialTransactionProof>({pFirstExport->second}),
                                                       CNotaryEvidence::TYPE_PARTIAL_TXPROOF);
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence))));

            outputs.insert(outputs.end(), importOutputs.begin(), importOutputs.end());
        }
        else
        {
            // begin with an empty import for this currency
            // create an import based on launch conditions that covers all pre-allocations and uses the initial notarization

            // if the currency is new and owned by this chain, its registration requires the fee, paid in its launch chain currency
            // otherwise, it is being imported from another chain and requires an import fee
            CCurrencyValueMap registrationFees;
            CAmount registrationAmount = 0;
            if (newCurrency.systemID == ASSETCHAINS_CHAINID)
            {
                if (newCurrency.launchSystemID != ASSETCHAINS_CHAINID)
                {
                    registrationFees = CCurrencyValueMap(std::vector<uint160>({newCurrency.launchSystemID}),
                                        std::vector<int64_t>({ConnectedChains.FirstNotaryChain().chainDefinition.currencyRegistrationFee}));
                }
                else
                {
                    registrationAmount = ConnectedChains.ThisChain().currencyRegistrationFee;
                }
            }
            else
            {
                registrationAmount = 0;
            }

            CCrossChainImport cci = CCrossChainImport(ConnectedChains.ThisChain().launchSystemID,
                                                      1,
                                                      newCurID,
                                                      CCurrencyValueMap());
            cci.SetDefinitionImport(true);
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci))));

            // add notarization before other outputs
            cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);
            if (newCurID == ASSETCHAINS_CHAINID &&
                newCurrency.notarizationProtocol == newCurrency.NOTARIZATION_NOTARY_CHAINID)
            {
                dests = std::vector<CTxDestination>({CIdentityID(newCurID)});
            }
            else
            {
                dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            }
            // this currency is not launching now
            newNotarization.SetLaunchConfirmed();
            newNotarization.SetLaunchComplete();
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &newNotarization))));

            CReserveTransactionDescriptor rtxd;
            CCoinbaseCurrencyState importState = newNotarization.currencyState;
            importState.RevertReservesAndSupply();
            CCurrencyValueMap importedCurrency;
            CCurrencyValueMap gatewayDepositsIn;
            CCurrencyValueMap spentCurrencyOut;
            CCoinbaseCurrencyState newCurrencyState;
            if (!rtxd.AddReserveTransferImportOutputs(ConnectedChains.FirstNotaryChain().chainDefinition,
                                                      ConnectedChains.ThisChain(),
                                                      newCurrency,
                                                      importState,
                                                      std::vector<CReserveTransfer>(),
                                                      outputs,
                                                      importedCurrency,
                                                      gatewayDepositsIn,
                                                      spentCurrencyOut,
                                                      &newCurrencyState))
            {
                LogPrintf("Invalid starting currency import for %s\n", ConnectedChains.ThisChain().name.c_str());
                printf("Invalid starting currency import for %s\n", ConnectedChains.ThisChain().name.c_str());
                return false;
            }
        }
        // export thread
        cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
        CCrossChainExport ccx;

        ccx = CCrossChainExport(ASSETCHAINS_CHAINID, 1, 1, newCurrency.systemID, newCurID, 0, CCurrencyValueMap(), CCurrencyValueMap(), uint256());
        outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx))));
    }
    else
    {
        cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);
        if (newCurID == ASSETCHAINS_CHAINID &&
            newCurrency.notarizationProtocol == newCurrency.NOTARIZATION_NOTARY_CHAINID)
        {
            dests = std::vector<CTxDestination>({CIdentityID(newCurID)});
        }
        else
        {
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
        }
        // we notarize our notary chain here, not ourselves
        if (newNotarization.currencyID == ASSETCHAINS_CHAINID)
        {
            if (!newNotarization.SetMirror())
            {
                LogPrintf("Cannot mirror our notarization from notary chain\n");
                printf("Cannot mirror our notarization from notary chain\n");
                return false;
            }
        }
        newNotarization.SetBlockOneNotarization();
        outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &newNotarization))));
    }
    return true;
}

// create all special PBaaS outputs for block 1
bool MakeBlockOneCoinbaseOutputs(std::vector<CTxOut> &outputs,
                                 CPBaaSNotarization &launchNotarization,
                                 CCurrencyValueMap &additionalFees,
                                 const Consensus::Params &consensusParams)
{
    uint160 thisChainID = ConnectedChains.ThisChain().GetID();
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();
    uint160 firstNotaryID = ConnectedChains.FirstNotaryChain().GetID();
    CCoinbaseCurrencyState currencyState;
    std::map<uint160, std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>>> blockOneExportImports;

    std::pair<CUTXORef, CPartialTransactionProof> launchNotarizationProof;
    std::pair<CUTXORef, CPartialTransactionProof> launchExportProof;
    std::vector<CReserveTransfer> launchExportTransfers;
    CPBaaSNotarization notaryNotarization;

    if (!GetBlockOneLaunchNotarization(ConnectedChains.FirstNotaryChain(), 
                                       thisChainID, 
                                       thisChain, 
                                       launchNotarization,
                                       notaryNotarization,
                                       launchNotarizationProof,
                                       launchExportProof,
                                       launchExportTransfers))
    {
        // cannot make block 1 unless we can get the initial currency state from the first notary system
        LogPrintf("Cannot find chain on notary system\n");
        printf("Cannot find chain on notary system\n");
        return false;
    }

    // we need to have a launch decision to be able to mine any blocks, prior to launch being clear,
    // it is not an error. we are just not ready.
    if (!launchNotarization.IsLaunchCleared())
    {
        return false;
    }

    if (!launchNotarization.IsLaunchConfirmed())
    {
        // we must reach minimums in all currencies to launch
        LogPrintf("This chain did not receive the minimum currency contributions and cannot launch. Pre-launch contributions to this chain can be refunded.\n");
        printf("This chain did not receive the minimum currency contributions and cannot launch. Pre-launch contributions to this chain can be refunded.\n");
        return false;
    }

    // get initial imports
    if (!GetBlockOneImports(ConnectedChains.FirstNotaryChain(), launchNotarization, blockOneExportImports))
    {
        // we must reach minimums in all currencies to launch
        LogPrintf("Cannot retrieve initial export imports from notary system\n");
        printf("Cannot retrieve initial export imports from notary system\n");
        return false;
    }

    // get all currencies/IDs that we will need to retrieve from our notary chain
    std::set<uint160> blockOneCurrencies;
    std::set<uint160> blockOneIDs = {ASSETCHAINS_CHAINID};
    std::set<uint160> convertersToCreate;

    CPBaaSNotarization converterNotarization;
    std::pair<CUTXORef, CPartialTransactionProof> converterNotarizationProof;
    std::pair<CUTXORef, CPartialTransactionProof> converterExportProof;
    std::vector<CReserveTransfer> converterExportTransfers;
    uint160 converterCurrencyID = thisChain.GatewayConverterID();
    CCurrencyDefinition converterCurDef;

    // if we have a converter currency, ensure that it also meets requirements for currency launch
    if (!thisChain.gatewayConverterName.empty())
    {
        if (!GetBlockOneLaunchNotarization(ConnectedChains.FirstNotaryChain(), 
                                           converterCurrencyID,
                                           converterCurDef,
                                           converterNotarization,
                                           notaryNotarization,
                                           converterNotarizationProof,
                                           converterExportProof,
                                           converterExportTransfers))
        {
            LogPrintf("Unable to get gateway converter initial state\n");
            printf("Unable to get gateway converter initial state\n");
            return false;
        }

        notaryNotarization.currencyStates[converterCurrencyID] = converterNotarization.currencyState;

        // both currency and primary gateway must have their pre-launch phase complete before we can make a decision
        // about launching
        if (!converterNotarization.IsLaunchCleared())
        {
            return false;
        }

        // we need to have a cleared launch to be able to launch
        if (!converterNotarization.IsLaunchConfirmed())
        {
            LogPrintf("Primary currency met requirements for launch, but gateway currency converter did not\n");
            printf("Primary currency met requirements for launch, but gateway currency converter did not\n");
            return false;
        }

        convertersToCreate.insert(converterCurrencyID);

        for (auto &oneCurrency : converterCurDef.currencies)
        {
            blockOneCurrencies.insert(oneCurrency);
        }
    }

    // Now, add block 1 imports, which provide a foundation of all IDs and currencies needed to launch the
    // new system, including ID and currency outputs for notary chain, all currencies we accept for pre-conversion,
    // native currency of system launching the chain.
    for (auto &oneNotary : ConnectedChains.notarySystems)
    {
        // first, we need to have the native notary currency itself and its notaries, if it has them
        blockOneCurrencies.insert(oneNotary.first);
        blockOneIDs.insert(oneNotary.second.notaryChain.chainDefinition.notaries.begin(), oneNotary.second.notaryChain.chainDefinition.notaries.end());
    }

    for (auto &oneCurrency : thisChain.currencies)
    {
        blockOneCurrencies.insert(oneCurrency);
    }

    for (auto &onePrealloc : thisChain.preAllocation)
    {
        blockOneIDs.insert(onePrealloc.first);
    }

    // get this chain's notaries
    auto &notaryIDs = ConnectedChains.ThisChain().notaries;
    blockOneIDs.insert(notaryIDs.begin(), notaryIDs.end());

    // now retrieve IDs and currencies
    std::map<uint160, std::pair<CCurrencyDefinition,CPBaaSNotarization>> currencyImports;
    std::map<uint160, CIdentity> identityImports;
    if (!ConnectedChains.GetNotaryCurrencies(ConnectedChains.FirstNotaryChain(), blockOneCurrencies, currencyImports) ||
        !ConnectedChains.GetNotaryIDs(ConnectedChains.FirstNotaryChain(), blockOneIDs, identityImports))
    {
        // we must reach minimums in all currencies to launch
        LogPrintf("Cannot retrieve identity and currency definitions needed to create block 1\n");
        printf("Cannot retrieve identity and currency definitions needed to create block 1\n");
        return false;
    }

    if (currencyImports.count(notaryNotarization.currencyID))
    {
        currencyImports[notaryNotarization.currencyID].second = notaryNotarization;
    }

    // add all imported currency and identity outputs, identity revocaton and recovery IDs must be explicitly imported if needed
    for (auto &oneIdentity : identityImports)
    {
        outputs.push_back(CTxOut(0, oneIdentity.second.IdentityUpdateOutputScript(1)));
    }

    // calculate all issued currency on this chain for both the native and converter currencies,
    // which is the only currency that can be considered a gateway deposit at launch. this can
    // be used for native currency fee conversions
    CCurrencyValueMap gatewayDeposits;

    bool success = AddOneCurrencyImport(thisChain, 
                                        launchNotarization,
                                        &launchNotarizationProof,
                                        &launchExportProof,
                                        launchExportTransfers,
                                        gatewayDeposits,
                                        outputs,
                                        additionalFees);

    // now, the converter
    if (success && converterCurDef.IsValid())
    {
        // TODO: add a new ID for the converter currency, controlled by the same primary addresses as the
        // ID for this chain
        CCurrencyValueMap converterDeposits;

        success = AddOneCurrencyImport(converterCurDef, 
                                       converterNotarization,
                                       &converterNotarizationProof,
                                       &converterExportProof,
                                       converterExportTransfers,
                                       converterDeposits,
                                       outputs,
                                       additionalFees);
    }

    if (success)
    {
        currencyImports.erase(ASSETCHAINS_CHAINID);
        currencyImports.erase(converterCurrencyID);
        // now, add the rest of necessary currencies
        for (auto &oneCurrency : currencyImports)
        {
            success = AddOneCurrencyImport(oneCurrency.second.first, 
                                           oneCurrency.second.second,
                                           nullptr,
                                           nullptr,
                                           std::vector<CReserveTransfer>(),
                                           gatewayDeposits,
                                           outputs,
                                           additionalFees);
            if (!success)
            {
                break;
            }
        }
    }
    return success;
}

CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const std::vector<CTxOut> &minerOutputs, bool isStake)
{
    // instead of one scriptPubKeyIn, we take a vector of them along with relative weight. each is assigned a percentage of the block subsidy and
    // mining reward based on its weight relative to the total
    if (!(minerOutputs.size() && ConnectedChains.SetLatestMiningOutputs(minerOutputs) || isStake))
    {
        fprintf(stderr,"%s: Must have valid miner outputs, including script with valid PK, PKH, or Verus ID destination.\n", __func__);
        return NULL;
    }

    CTxDestination firstDestination;

    if (minerOutputs.size())
    {
        int64_t shareCheck = 0;
        CTxDestination checkDest;
        for (auto &output : minerOutputs)
        {
            shareCheck += output.nValue;
            if (shareCheck < 0 || 
                shareCheck > INT_MAX || 
                !ExtractDestination(output.scriptPubKey, checkDest) || 
                (checkDest.which() == COptCCParams::ADDRTYPE_INVALID))
            {
                fprintf(stderr,"Invalid miner outputs share specifications\n");
                return NULL;
            }
        }
        ExtractDestination(minerOutputs[0].scriptPubKey, firstDestination);
    }

    uint32_t blocktime;
    //fprintf(stderr,"create new block\n");
    // Create new block
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
    {
        fprintf(stderr,"pblocktemplate.get() failure\n");
        return NULL;
    }
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    pblock->nSolution.resize(Eh200_9.SolutionWidth);

    pblock->SetVersionByHeight(chainActive.LastTip()->GetHeight() + 1);

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);
    
    // Add dummy coinbase tx placeholder as first transaction
    pblock->vtx.push_back(CTransaction());

    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end
    
    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);

    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    unsigned int nMaxIDSize = nBlockMaxSize / 2;
    unsigned int nCurrentIDSize = 0;
    
    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);
    
    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);
    
    // Collect memory pool transactions into the block
    CAmount nFees = 0;
    CAmount takenFees = 0;

    bool isVerusActive = IsVerusActive();
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();

    std::vector<CAmount> exchangeRate(thisChain.currencies.size());

    // we will attempt to spend any cheats we see
    CTransaction cheatTx;
    boost::optional<CTransaction> cheatSpend;
    uint256 cbHash;

    CBlockIndex* pindexPrev = 0;
    bool loop = true;
    while (loop)
    {
        loop = false;
        int nHeight;
        const Consensus::Params &consensusParams = chainparams.GetConsensus();
        uint32_t consensusBranchId;
        int64_t nMedianTimePast = 0;
        uint32_t proposedTime = 0;

        {
            while (proposedTime == nMedianTimePast)
            {
                if (proposedTime)
                {
                    MilliSleep(20);
                }
                LOCK(cs_main);
                pindexPrev = chainActive.LastTip();
                nHeight = pindexPrev->GetHeight() + 1;
                consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);
                nMedianTimePast = pindexPrev->GetMedianTimePast();
                proposedTime = GetAdjustedTime();

                if (proposedTime == nMedianTimePast)
                {
                    boost::this_thread::interruption_point();
                }
            }
        }

        CCoinbaseCurrencyState currencyState;
        CCoinsViewCache view(pcoinsTip);
        uint32_t expired; uint64_t commission;
        
        SaplingMerkleTree sapling_tree;

        {
            LOCK2(cs_main, mempool.cs);
            if (pindexPrev != chainActive.LastTip())
            {
                // try again
                loop = true;
                continue;
            }
            pblock->nTime = GetAdjustedTime();

            currencyState = ConnectedChains.GetCurrencyState(nHeight);

            if (!(view.GetSaplingAnchorAt(view.GetBestAnchor(SAPLING), sapling_tree)))
            {
                LogPrintf("%s: failed to get Sapling anchor\n", __func__);
                assert(false);
            }
        }

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);
        
        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size() + 1);

        {
            LOCK(cs_main);

            // check if we should add cheat transaction
            CBlockIndex *ppast;
            CTransaction cb;
            int cheatHeight = nHeight - COINBASE_MATURITY < 1 ? 1 : nHeight - COINBASE_MATURITY;
            if (defaultSaplingDest &&
                chainActive.Height() > 100 && 
                (ppast = chainActive[cheatHeight]) && 
                ppast->IsVerusPOSBlock() && 
                cheatList.IsHeightOrGreaterInList(cheatHeight))
            {
                // get the block and see if there is a cheat candidate for the stake tx
                CBlock b;
                if (!(fHavePruned && !(ppast->nStatus & BLOCK_HAVE_DATA) && ppast->nTx > 0) && ReadBlockFromDisk(b, ppast, chainparams.GetConsensus(), 1))
                {
                    CTransaction &stakeTx = b.vtx[b.vtx.size() - 1];

                    if (cheatList.IsCheatInList(stakeTx, &cheatTx))
                    {
                        // make and sign the cheat transaction to spend the coinbase to our address
                        CMutableTransaction mtx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);

                        uint32_t voutNum;
                        // get the first vout with value
                        for (voutNum = 0; voutNum < b.vtx[0].vout.size(); voutNum++)
                        {
                            if (b.vtx[0].vout[voutNum].nValue > 0)
                                break;
                        }

                        // send to the same pub key as the destination of this block reward
                        if (MakeCheatEvidence(mtx, b.vtx[0], voutNum, cheatTx))
                        {
                            LOCK(pwalletMain->cs_wallet);
                            TransactionBuilder tb = TransactionBuilder(consensusParams, nHeight);
                            cb = b.vtx[0];
                            cbHash = cb.GetHash();

                            bool hasInput = false;
                            for (uint32_t i = 0; i < cb.vout.size(); i++)
                            {
                                // add the spends with the cheat
                                if (cb.vout[i].nValue > 0)
                                {
                                    tb.AddTransparentInput(COutPoint(cbHash,i), cb.vout[0].scriptPubKey, cb.vout[0].nValue);
                                    hasInput = true;
                                }
                            }

                            if (hasInput)
                            {
                                // this is a send from a t-address to a sapling address, which we don't have an ovk for.
                                // Instead, generate a common one from the HD seed. This ensures the data is
                                // recoverable, at least for us, while keeping it logically separate from the ZIP 32
                                // Sapling key hierarchy, which the user might not be using.
                                uint256 ovk;
                                HDSeed seed;
                                if (pwalletMain->GetHDSeed(seed)) {
                                    ovk = ovkForShieldingFromTaddr(seed);

                                    // send everything to Sapling address
                                    tb.SendChangeTo(defaultSaplingDest.value(), ovk);

                                    tb.AddOpRet(mtx.vout[mtx.vout.size() - 1].scriptPubKey);

                                    TransactionBuilderResult buildResult(tb.Build());
                                    if (!buildResult.IsError() && buildResult.IsTx())
                                    {
                                        cheatSpend = buildResult.GetTxOrThrow();
                                    }
                                    else
                                    {
                                        LogPrintf("Error building cheat catcher transaction: %s\n", buildResult.GetError().c_str());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (cheatSpend)
            {
                LOCK(mempool.cs);

                cheatTx = cheatSpend.value();
                std::list<CTransaction> removed;
                mempool.removeConflicts(cheatTx, removed);
                printf("Found cheating stake! Adding cheat spend for %.8f at block #%d, coinbase tx\n%s\n",
                    (double)cb.GetValueOut() / (double)COIN, nHeight, cheatSpend.value().vin[0].prevout.hash.GetHex().c_str());

                // add to mem pool and relay
                if (myAddtomempool(cheatTx))
                {
                    RelayTransaction(cheatTx);
                }
            }
        }

        //
        // Now start solving the block
        //

        uint64_t nBlockSize = 1000;             // initial size
        uint64_t nBlockTx = 1;                  // number of transactions - always have a coinbase
        uint32_t autoTxSize = 0;                // extra transaction overhead that we will add while creating the block
        int nBlockSigOps = 100;

        // VerusPoP staking transaction data
        CMutableTransaction txStaked;           // if this is a stake operation, the staking transaction that goes at the end
        uint32_t nStakeTxSize = 0;              // serialized size of the stake transaction

        // if this is not for mining, first determine if we have a right to make a block
        if (isStake)
        {
            uint64_t txfees, utxovalue;
            uint32_t txtime;
            uint256 utxotxid;
            int32_t i, siglen, numsigs, utxovout;
            std::vector<unsigned char> utxosig;

            txStaked = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight);

            if (ASSETCHAINS_LWMAPOS != 0)
            {
                uint32_t nBitsPOS;
                arith_uint256 posHash;

                siglen = verus_staked(pblock, txStaked, nBitsPOS, posHash, utxosig, firstDestination);
                blocktime = GetAdjustedTime();
            }

            if (siglen <= 0)
            {
                return NULL;
            }

            pblock->nTime = blocktime;
            nStakeTxSize = GetSerializeSize(txStaked, SER_NETWORK, PROTOCOL_VERSION);
            nBlockSize += nStakeTxSize;
        }

        ConnectedChains.AggregateChainTransfers(firstDestination, nHeight);

        // Now the coinbase -
        // A PBaaS coinbase must have some additional outputs to enable certain chain state and functions to be properly
        // validated. All but currency state and the first chain definition are either optional or not valid on non-fractional reserve PBaaS blockchains
        // All of these are instant spend outputs that have no maturity wait time and may be spent in the same block.
        //
        // 1. (required) currency state - current state of currency supply and optionally reserve, premine, etc. This is primarily a data output to provide
        //    cross check for coin minting and burning operations, making it efficient to determine up-to-date supply, reserves, and conversions. To provide
        //    an extra level of supply cross-checking and fast data retrieval, this is part of all PBaaS chains' protocol, not just reserves.
        //    This output also includes reserve and native amounts for total conversions, less fees, of any conversions between Verus reserve and the
        //    native currency.
        //
        // 2. (block 1 required) chain definition - in order to confirm the amount of coins converted and issued within the possible range, before chain start,
        //    new PBaaS chains have a zero-amount, unspendable chain definition output.
        //
        // 3. (block 1 optional) initial import utxo - for any chain with conversion or pre-conversion, the first coinbase must include an initial import utxo. 
        //    Pre-conversions are handled on the launch chain before the PBaaS chain starts, so they are an additional output, which begins
        //    as a fixed amount and is spent with as many outputs as necessary to the recipients of the pre-conversion transactions when those pre-conversions
        //    are imported. All pre-converted outputs get their source currency from a thread that starts with this output in block 1.
        //
        // 4. (block 1 optional) initial export utxo - reserve chains, or any chain that will use exports to another chain must have an initial export utxo, any chain
        //    may have one, but currently, they can only be spent with valid exports, which only occur on reserve chains
        //
        // 5. (optional) notarization output - in order to ensure that notarization can occur independent of the availability of fungible
        //    coins on the network, and also that the notarization can provide a spendable finalization output and possible reward
        //
        // In addition, each PBaaS block can be mined with optional, fee-generating transactions. Inporting transactions from the reserve chain or sending
        // exported transactions to the reserve chain are optional fee-generating steps that would be easy to do when running multiple daemons.
        // The types of transactions miners/stakers may facilitate or create for fees are as follows:
        //
        // 1. Earned notarization of Verus chain - spends the notarization instant out. must be present and spend the notarization output if there is a notarization output
        //
        // 2. Imported transactions from the export thread for this PBaaS chain on the Verus blockchain - imported transactions must spend the import utxo
        //    thread, represent the export from the alternate chain which spends the export output from the prior import transaction, carry a notary proof, and
        //    include outputs that map to each of its inputs on the source chain. Outputs can include unconverted reserve outputs only on fractional
        //    reserve chains, pre-converted outputs for any chain with launch conversion, and post launch outputs to be converted on fractional reserve
        //    chains. Each are handled in the following way:
        //      a. Unconverted outputs are left as outputs to the intended destination of Verus reserve token and do not pass through the coinbase
        //      b. Pre-converted outputs require that the import transaction spend the last pre-conversion output starting at block 1 as the source for
        //         pre-converted currency.
        //
        // 3. Zero or more aggregated exports that combine individual cross-chain transactions and reserve transfer outputs for export to the Verus chain. 
        //
        // 4. Conversion distribution transactions for all native and reserve currency conversions, including reserve transfer outputs without conversion as
        //    a second step for reserve transfers that have conversion included. Any remaining pre-converted reserve must always remain in a change output
        //    until it is exhausted
        CTxOut premineOut;

        // size of conversion tx
        std::vector<CInputDescriptor> conversionInputs;

        // if we are a PBaaS chain, first make sure we don't start prematurely, and if
        // we should make an earned notarization, make it and set index to non-zero value
        int32_t notarizationTxIndex = 0;                            // index of notarization if it is added
        int32_t conversionTxIndex = 0;                              // index of conversion transaction if it is added

        // export transactions can be created here by aggregating all pending transfer requests and either getting 10 or more together, or
        // waiting n (10) blocks since the last one. each export must spend the output of the one before it
        std::vector<CMutableTransaction> exportTransactions;

        // all transaction outputs requesting conversion to another currency (PBaaS fractional reserve only)
        // these will be used to calculate conversion price, fees, and generate coinbase conversion output as well as the
        // conversion output transaction
        std::vector<CTxOut> reserveConversionTo;
        std::vector<CTxOut> reserveConversionFrom;

        int64_t pbaasTransparentIn = 0;
        int64_t pbaasTransparentOut = 0;
        //extern int64_t ASSETCHAINS_SUPPLY;
        //printf("%lu premine\n", ASSETCHAINS_SUPPLY);
        int64_t blockSubsidy = GetBlockSubsidy(nHeight, consensusParams);

        uint160 thisChainID = ConnectedChains.ThisChain().GetID();

        uint256 mmrRoot;
        vector<CInputDescriptor> notarizationInputs;

        // used as scratch for making CCs, should be reinitialized each time
        CCcontract_info CC;
        CCcontract_info *cp;
        std::vector<CTxDestination> dests;
        CPubKey pkCC;

        // Create coinbase tx and set up the null input with height
        CMutableTransaction coinbaseTx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);
        coinbaseTx.vin.push_back(CTxIn(uint256(), (uint32_t)-1, CScript() << nHeight << OP_0));

        // we will update amounts and fees later, but convert the guarded output now for validity checking and size estimate
        if (isStake)
        {
            // if there is a specific destination, use it
            CTransaction stakeTx(txStaked);
            CStakeParams p;
            if (ValidateStakeTransaction(stakeTx, p, false))
            {
                if (p.Version() < p.VERSION_EXTENDED_STAKE && !p.pk.IsValid())
                {
                    LogPrintf("CreateNewBlock: invalid public key\n");
                    fprintf(stderr,"CreateNewBlock: invalid public key\n");
                    return NULL;
                }
                CTxDestination guardedOutputDest = (p.Version() < p.VERSION_EXTENDED_STAKE) ? p.pk : p.delegate;
                coinbaseTx.vout.push_back(CTxOut(1, CScript()));
                if (!MakeGuardedOutput(1, guardedOutputDest, stakeTx, coinbaseTx.vout.back()))
                {
                    LogPrintf("CreateNewBlock: failed to make GuardedOutput on staking coinbase\n");
                    fprintf(stderr,"CreateNewBlock: failed to make GuardedOutput on staking coinbase\n");
                    return NULL;
                }
                COptCCParams optP;
                if (!coinbaseTx.vout.back().scriptPubKey.IsPayToCryptoCondition(optP) || !optP.IsValid())
                {
                    MakeGuardedOutput(1, guardedOutputDest, stakeTx, coinbaseTx.vout.back());
                    LogPrintf("%s: created invalid staking coinbase\n", __func__);
                    fprintf(stderr,"%s: created invalid staking coinbase\n", __func__);
                    return NULL;
                }
            }
            else
            {
                LogPrintf("CreateNewBlock: invalid stake transaction\n");
                fprintf(stderr,"CreateNewBlock: invalid stake transaction\n");
                return NULL;
            }
        }
        else
        {
            // default outputs for mining and before stake guard or fee calculation
            // store the relative weight in the amount output to convert later to a relative portion
            // of the reward + fees
            coinbaseTx.vout.insert(coinbaseTx.vout.end(), minerOutputs.begin(), minerOutputs.end());
        }

        CAmount totalEmission = blockSubsidy;
        CCurrencyValueMap additionalFees;

        // if we don't have a connected root PBaaS chain, we can't properly check
        // and notarize the start block, so we have to pass the notarization and cross chain steps
        bool notaryConnected = ConnectedChains.IsNotaryAvailable();
        uint32_t solutionVersion = CConstVerusSolutionVector::GetVersionByHeight(nHeight);

        if (isVerusActive &&
            solutionVersion >= CActivationHeight::ACTIVATE_PBAAS &&
            !notaryConnected)
        {
            // until we have connected to the ETH bridge, after PBaaS has launched, we check each block to see if there is now an
            // ETH bridge defined
            if (ConnectedChains.FirstNotaryChain().IsValid())
            {
                // once PBaaS is active, we attempt to connect to the Ethereum bridge, in case it is active
                notaryConnected = ConnectedChains.IsNotaryAvailable(true);
            }
            else
            {
                notaryConnected = ConnectedChains.ConfigureEthBridge();
            }
        }

        // at block 1 for a PBaaS chain, we validate launch conditions
        if (!isVerusActive && nHeight == 1)
        {
            CPBaaSNotarization launchNotarization;
            if (!ConnectedChains.readyToStart &&
                !ConnectedChains.CheckVerusPBaaSAvailable() &&
                !ConnectedChains.readyToStart)
            {
                return NULL;
            }
            if (!MakeBlockOneCoinbaseOutputs(coinbaseTx.vout, launchNotarization, additionalFees, Params().GetConsensus()))
            {
                // can't mine block 1 if we are not connected to a notary
                printf("%s: cannot create block one coinbase outputs\n", __func__);
                LogPrintf("%s: cannot create block one coinbase outputs\n", __func__);
                return NULL;
            }
            currencyState = launchNotarization.currencyState;
        }

        // if we are a notary, notarize
        if (nHeight > CPBaaSNotarization::MIN_BLOCKS_BEFORE_NOTARY_FINALIZED && !VERUS_NOTARYID.IsNull())
        {
            CValidationState state;
            TransactionBuilder notarizationBuilder = TransactionBuilder(consensusParams, nHeight, pwalletMain);
            bool finalized;
            CTransaction notarizationTx;
            const CRPCChainData &notaryChain = ConnectedChains.FirstNotaryChain();
            if (notaryChain.IsValid() &&
                CPBaaSNotarization::ConfirmOrRejectNotarizations(pwalletMain, ConnectedChains.FirstNotaryChain(), state, notarizationBuilder, finalized))
            {
                if (!notarizationBuilder.mtx.vin.size())
                {
                    bool success = false;
                    CCurrencyValueMap reserveValueOut;
                    CAmount nativeValueOut;
                    // get a native currency input capable of paying a fee, and make our notary ID the change address
                    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
                    {
                        LOCK2(cs_main, pwalletMain->cs_wallet);
                        std::vector<COutput> vCoins;
                        if (IsVerusActive())
                        {
                            pwalletMain->AvailableCoins(vCoins,
                                                        false,
                                                        nullptr,
                                                        false,
                                                        true,
                                                        true,
                                                        true,
                                                        false);
                            success = pwalletMain->SelectCoinsMinConf(CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE, 0, 0, vCoins, setCoinsRet, nativeValueOut);
                            notarizationBuilder.SetFee(CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE);
                        }
                        else
                        {
                            CCurrencyValueMap totalTxFees;
                            totalTxFees.valueMap[ConnectedChains.FirstNotaryChain().chainDefinition.GetID()] = CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE;
                            notarizationBuilder.SetReserveFee(totalTxFees);
                            notarizationBuilder.SetFee(0);
                            pwalletMain->AvailableReserveCoins(vCoins,
                                                               false,
                                                               nullptr,
                                                               true,
                                                               true,
                                                               nullptr,
                                                               &totalTxFees, 
                                                               false);

                            success = pwalletMain->SelectReserveCoinsMinConf(totalTxFees,
                                                                            0,
                                                                            0,
                                                                            1,
                                                                            vCoins,
                                                                            setCoinsRet,
                                                                            reserveValueOut,
                                                                            nativeValueOut);
                        }
                    }
                    for (auto &oneInput : setCoinsRet)
                    {
                        notarizationBuilder.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second), 
                                                                oneInput.first->vout[oneInput.second].scriptPubKey,
                                                                oneInput.first->vout[oneInput.second].nValue);
                    }
                    notarizationBuilder.SendChangeTo(CTxDestination(VERUS_NOTARYID));
                }
                else
                {
                    notarizationBuilder.SetFee(0);
                }

                if (notarizationBuilder.mtx.vin.size())
                {
                    LOCK2(cs_main, mempool.cs);
                    TransactionBuilderResult buildResult = notarizationBuilder.Build();
                    if (buildResult.IsTx())
                    {
                        notarizationTx = buildResult.GetTxOrThrow();

                        UniValue jsonNotaryConfirmations(UniValue::VOBJ);
                        TxToUniv(notarizationTx, uint256(), jsonNotaryConfirmations);
                        //printf("%s: (PII) Submitting notarization confirmations:\n%s\n", __func__, jsonNotaryConfirmations.write(1,2).c_str());
                        LogPrintf("%s: (PII) Submitting notarization confirmations:\n%s\n", __func__, jsonNotaryConfirmations.write(1,2).c_str());

                        // add to mem pool and relay
                        if (myAddtomempool(notarizationTx))
                        {
                            RelayTransaction(notarizationTx);
                        }
                    }
                    else
                    {
                        printf("%s: (PII) error adding notary evidence: %s\n", __func__, buildResult.GetError().c_str());
                        LogPrintf("%s: (PII) error adding notary evidence: %s\n", __func__, buildResult.GetError().c_str());
                    }
                }
            }
        }

        if (notaryConnected)
        {
            // if we should make an earned notarization, do so
            if (nHeight != 1 && !(VERUS_NOTARYID.IsNull() && VERUS_DEFAULTID.IsNull() && VERUS_NODEID.IsNull()))
            {
                CIdentityID proposer = VERUS_NOTARYID.IsNull() ? (VERUS_DEFAULTID.IsNull() ? VERUS_NODEID : VERUS_DEFAULTID) : VERUS_NOTARYID;

                // if we have access to our notary daemon
                // create a notarization if we would qualify to do so. add it to the mempool and next block
                ChainMerkleMountainView mmv = chainActive.GetMMV();
                mmrRoot = mmv.GetRoot();
                int32_t confirmedInput = -1;
                CTxDestination confirmedDest;
                CValidationState state;
                CPBaaSNotarization earnedNotarization;

                if (CPBaaSNotarization::CreateEarnedNotarization(ConnectedChains.FirstNotaryChain(),
                                                                 DestinationToTransferDestination(proposer),
                                                                 state,
                                                                 coinbaseTx.vout,
                                                                 earnedNotarization))
                {
                }
                CPBaaSNotarization lastImportNotarization;
                CUTXORef lastImportNotarizationUTXO;

                CPBaaSNotarization::SubmitFinalizedNotarizations(ConnectedChains.FirstNotaryChain(), state);
                ProcessNewImports(ConnectedChains.FirstNotaryChain().chainDefinition.GetID(), lastImportNotarization, lastImportNotarizationUTXO, nHeight);
            }
        }

        // done calling out, take locks for the rest
        LOCK2(cs_main, mempool.cs);

        totalEmission = GetBlockSubsidy(nHeight, consensusParams);
        blockSubsidy = totalEmission;

        // PBaaS chain's block 1 currency state is done by the time we get here,
        // including pre-allocations, etc.
        if (isVerusActive || nHeight != 1)
        {
            currencyState.UpdateWithEmission(totalEmission);
        }

        // process any imports from the current chain to itself
        ConnectedChains.ProcessLocalImports();

        CFeePool feePool;
        if (!CFeePool::GetCoinbaseFeePool(feePool, nHeight - 1) ||
            (!feePool.IsValid() && CConstVerusSolutionVector::GetVersionByHeight(nHeight - 1) >= CActivationHeight::ACTIVATE_PBAAS))
        {
            // we should be able to get a valid currency state, if not, fail
            LogPrintf("Failure to get fee pool information for blockchain height #%d\n", nHeight - 1);
            printf("Failure to get fee pool information for blockchain height #%d\n", nHeight - 1);
            return NULL;
        }

        if (solutionVersion >= CActivationHeight::ACTIVATE_PBAAS && !feePool.IsValid())
        {
            // first block with a fee pool, so make it valid and empty
            feePool = CFeePool();
        }

        // coinbase should have all necessary outputs
        uint32_t nCoinbaseSize = GetSerializeSize(coinbaseTx, SER_NETWORK, PROTOCOL_VERSION);
        nBlockSize += nCoinbaseSize;

        // now create the priority array, including market order reserve transactions, since they can always execute, leave limits for later
        bool haveReserveTransactions = false;
        uint32_t reserveExchangeLimitSize = 0;
        std::vector<CReserveTransactionDescriptor> limitOrders;

        // now add transactions from the mem pool to the priority heap
        for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
            const CTransaction& tx = mi->GetTx();
            uint256 hash = tx.GetHash();
            
            int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
            ? nMedianTimePast
            : pblock->GetBlockTime();

            if (tx.IsCoinBase() || !IsFinalTx(tx, nHeight, nLockTimeCutoff) || IsExpiredTx(tx, nHeight))
            {
                //fprintf(stderr,"coinbase.%d finaltx.%d expired.%d\n",tx.IsCoinBase(),IsFinalTx(tx, nHeight, nLockTimeCutoff),IsExpiredTx(tx, nHeight));
                continue;
            }

            if ( ASSETCHAINS_SYMBOL[0] == 0 && komodo_validate_interest(tx,nHeight,(uint32_t)pblock->nTime,0) < 0 )
            {
                //fprintf(stderr,"CreateNewBlock: komodo_validate_interest failure nHeight.%d nTime.%u vs locktime.%u\n",nHeight,(uint32_t)pblock->nTime,(uint32_t)tx.nLockTime);
                continue;
            }

            COrphan* porphan = NULL;
            double dPriority = 0;
            CAmount nTotalIn = 0;
            CCurrencyValueMap totalReserveIn;
            bool fMissingInputs = false;
            CReserveTransactionDescriptor rtxd;
            bool isReserve = mempool.IsKnownReserveTransaction(hash, rtxd);

            if (tx.IsCoinImport())
            {
                CAmount nValueIn = GetCoinImportValue(tx);
                nTotalIn += nValueIn;
                dPriority += (double)nValueIn * 1000;  // flat multiplier
            } else {
                if (isReserve)
                {
                    nTotalIn += rtxd.nativeIn;
                    totalReserveIn = rtxd.ReserveInputMap();
                    assert(!totalReserveIn.valueMap.count(ASSETCHAINS_CHAINID));
                    if (rtxd.IsIdentity() && CNameReservation(tx).IsValid())
                    {
                        nCurrentIDSize += GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
                        if (nCurrentIDSize > nMaxIDSize)
                        {
                            continue;
                        }
                    }
                }
                BOOST_FOREACH(const CTxIn& txin, tx.vin)
                {
                    CAmount nValueIn = 0;
                    CCurrencyValueMap reserveValueIn;

                    // Read prev transaction
                    if (!view.HaveCoins(txin.prevout.hash))
                    {
                        // This should never happen; all transactions in the memory
                        // pool should connect to either transactions in the chain
                        // or other transactions in the memory pool.
                        if (!mempool.mapTx.count(txin.prevout.hash))
                        {
                            LogPrintf("ERROR: mempool transaction missing input\n");
                            if (fDebug) assert("mempool transaction missing input" == 0);
                            fMissingInputs = true;
                            if (porphan)
                                vOrphan.pop_back();
                            break;
                        }

                        // Has to wait for dependencies
                        if (!porphan)
                        {
                            // Use list for automatic deletion
                            vOrphan.push_back(COrphan(&tx));
                            porphan = &vOrphan.back();
                        }
                        mapDependers[txin.prevout.hash].push_back(porphan);
                        porphan->setDependsOn.insert(txin.prevout.hash);

                        const CTransaction &otx = mempool.mapTx.find(txin.prevout.hash)->GetTx();
                        // consider reserve outputs and set priority according to their value here as well
                        if (isReserve)
                        {
                            totalReserveIn += otx.vout[txin.prevout.n].ReserveOutValue();
                        }
                        nTotalIn += otx.vout[txin.prevout.n].nValue;
                        continue;
                    }
                    const CCoins* coins = view.AccessCoins(txin.prevout.hash);
                    assert(coins);

                    if (isReserve)
                    {
                        reserveValueIn = coins->vout[txin.prevout.n].ReserveOutValue();
                    }

                    nValueIn = coins->vout[txin.prevout.n].nValue;
                    int nConf = nHeight - coins->nHeight;

                    dPriority += ((double)((reserveValueIn.valueMap.size() ? currencyState.ReserveToNative(reserveValueIn) : 0) + nValueIn)) * nConf;

                    if (!isReserve)
                    {
                        nTotalIn += nValueIn;
                        totalReserveIn += reserveValueIn;
                    }
                }
                nTotalIn += tx.GetShieldedValueIn();
            }

            if (fMissingInputs) continue;
            
            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = tx.ComputePriority(dPriority, nTxSize);
            
            CAmount nDeltaValueIn = nTotalIn + (totalReserveIn.valueMap.size() ? currencyState.ReserveToNative(totalReserveIn) : 0);
            CAmount nFeeValueIn = nDeltaValueIn;
            mempool.ApplyDeltas(hash, dPriority, nDeltaValueIn);

            CAmount nativeEquivalentOut = 0;

            // if there is reserve in, or this is a reserveexchange transaction, calculate fee properly
            if (isReserve && rtxd.ReserveOutputMap().valueMap.size())
            {
                // if this has reserve currency out, convert it to native currency for fee calculation
                nativeEquivalentOut = currencyState.ReserveToNative(rtxd.ReserveOutputMap());
            }

            CFeeRate feeRate(isReserve ? rtxd.AllFeesAsNative(currencyState) + currencyState.ReserveToNative(rtxd.ReserveConversionFeesMap()) + rtxd.nativeConversionFees : 
                                         nFeeValueIn - (tx.GetValueOut() + nativeEquivalentOut), nTxSize);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->feeRate = feeRate;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, feeRate, &(mi->GetTx())));
        }

        //
        // NOW -- REALLY START TO FILL THE BLOCK
        //
        // estimate number of conversions, staking transaction size, and additional coinbase outputs that will be required

        int32_t maxPreLimitOrderBlockSize = nBlockMaxSize - std::min(nBlockMaxSize >> 2, reserveExchangeLimitSize);

        int64_t interest;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        std::vector<int> reservePositions;

        // now loop and fill the block, leaving space for reserve exchange limit transactions
        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            CFeeRate feeRate = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());
            
            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();
            
            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= maxPreLimitOrderBlockSize - autoTxSize) // room for extra autotx
            {
                //fprintf(stderr,"nBlockSize %d + %d nTxSize >= %d maxPreLimitOrderBlockSize\n",(int32_t)nBlockSize,(int32_t)nTxSize,(int32_t)maxPreLimitOrderBlockSize);
                continue;
            }
            
            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS-1)
            {
                //fprintf(stderr,"A nBlockSigOps %d + %d nTxSigOps >= %d MAX_BLOCK_SIGOPS-1\n",(int32_t)nBlockSigOps,(int32_t)nTxSigOps,(int32_t)MAX_BLOCK_SIGOPS);
                continue;
            }
            // Skip free transactions if we're past the minimum block size:
            const uint256& hash = tx.GetHash();
            double dPriorityDelta = 0;
            CAmount nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
            if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (feeRate < ::minRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
            {
                //fprintf(stderr,"fee rate skip\n");
                continue;
            }

            // Prioritise by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }
            
            if (!view.HaveInputs(tx))
            {
                //fprintf(stderr,"dont have inputs\n");
                continue;
            }
            CAmount nTxFees;
            CReserveTransactionDescriptor txDesc;
            bool isReserve = mempool.IsKnownReserveTransaction(hash, txDesc);

            nTxFees = view.GetValueIn(chainActive.LastTip()->GetHeight(),&interest,tx,chainActive.LastTip()->nTime) - tx.GetValueOut();
            
            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS-1)
            {
                //fprintf(stderr,"B nBlockSigOps %d + %d nTxSigOps >= %d MAX_BLOCK_SIGOPS-1\n",(int32_t)nBlockSigOps,(int32_t)nTxSigOps,(int32_t)MAX_BLOCK_SIGOPS);
                continue;
            }

            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            CValidationState state;
            PrecomputedTransactionData txdata(tx);
            if (!ContextualCheckInputs(tx, state, view, nHeight, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, txdata, Params().GetConsensus(), consensusBranchId))
            {
                //fprintf(stderr,"context failure\n");
                continue;
            }

            UpdateCoins(tx, view, nHeight);

            if (isReserve)
            {
                reservePositions.push_back(nBlockTx);
                haveReserveTransactions = true;
                additionalFees += txDesc.ReserveFees();
            }

            BOOST_FOREACH(const OutputDescription &outDescription, tx.vShieldedOutput) {
                sapling_tree.append(outDescription.cm);
            }

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;
            if (fPrintPriority)
            {
                LogPrintf("priority %.1f fee %s txid %s\n",dPriority, feeRate.ToString(), tx.GetHash().ToString());
            }
            
            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        // first calculate and distribute block rewards, including fees in the minerOutputs vector
        CAmount rewardTotalShareAmount = 0;
        CAmount rewardFees = nFees;
        if (additionalFees.valueMap.count(thisChainID))
        {
            rewardFees += additionalFees.valueMap[thisChainID];
            additionalFees.valueMap.erase(thisChainID);
        }

        CAmount verusFees = 0;
        if (VERUS_CHAINID != ASSETCHAINS_CHAINID && additionalFees.valueMap.count(VERUS_CHAINID))
        {
            verusFees += additionalFees.valueMap[VERUS_CHAINID];
            additionalFees.valueMap.erase(VERUS_CHAINID);
        }

        if (additionalFees.valueMap.size())
        {
            printf("%s: burning reserve currency: %s\n", __func__, additionalFees.ToUniValue().write(1,2).c_str());
        }

        if (feePool.IsValid())
        {
            // we support only the current native currency or VRSC on PBaaS chains in the fee pool for now
            feePool.reserveValues.valueMap[thisChainID] += rewardFees;
            if (verusFees)
            {
                feePool.reserveValues.valueMap[VERUS_CHAINID] += verusFees;
            }
            CFeePool oneFeeShare = feePool.OneFeeShare();
            rewardFees = oneFeeShare.reserveValues.valueMap[thisChainID];
            feePool.reserveValues.valueMap[thisChainID] -= rewardFees;

            if (VERUS_CHAINID != ASSETCHAINS_CHAINID && oneFeeShare.reserveValues.valueMap.count(VERUS_CHAINID))
            {
                verusFees = oneFeeShare.reserveValues.valueMap[VERUS_CHAINID];
                feePool.reserveValues.valueMap[VERUS_CHAINID] -= verusFees;
            }

            cp = CCinit(&CC, EVAL_FEE_POOL);
            pkCC = CPubKey(ParseHex(CC.CChexstr));
            coinbaseTx.vout.push_back(CTxOut(0,MakeMofNCCScript(CConditionObj<CFeePool>(EVAL_FEE_POOL,{pkCC.GetID()},1,&feePool))));
        }

        // printf("%s: rewardfees: %ld, verusfees: %ld\n", __func__, rewardFees, verusFees);

        CAmount rewardTotal = blockSubsidy + rewardFees;

        // now that we have the total reward, update the coinbase outputs
        if (isStake)
        {
            // TODO: need to add reserve output to stake coinbase to prevent burning of VRSC
            coinbaseTx.vout[0].nValue = rewardTotal;
        }
        else
        {
            for (auto &outputShare : minerOutputs)
            {
                rewardTotalShareAmount += outputShare.nValue;
            }

            int cbOutIdx;
            CAmount rewardLeft = rewardTotal;
            CAmount verusFeeLeft = verusFees;
            for (cbOutIdx = 0; cbOutIdx < minerOutputs.size(); cbOutIdx++)
            {
                CAmount amount = (arith_uint256(rewardTotal) * arith_uint256(minerOutputs[cbOutIdx].nValue) / arith_uint256(rewardTotalShareAmount)).GetLow64();
                if (rewardLeft <= amount || (cbOutIdx + 1) == minerOutputs.size())
                {
                    amount = rewardLeft;
                }
                rewardLeft -= amount;

                // now make outputs for non-native, VRSC fees
                if (verusFeeLeft)
                {
                    CAmount verusFee = (arith_uint256(verusFees) * arith_uint256(minerOutputs[cbOutIdx].nValue) / arith_uint256(rewardTotalShareAmount)).GetLow64();
                    if (verusFeeLeft <= verusFee || (cbOutIdx + 1) == minerOutputs.size())
                    {
                        verusFee = verusFeeLeft;
                    }
                    CTxDestination minerDestination;
                    if (verusFee >= CFeePool::MIN_SHARE_SIZE && ExtractDestination(coinbaseTx.vout[cbOutIdx].scriptPubKey, minerDestination))
                    {
                        CTokenOutput to = CTokenOutput(VERUS_CHAINID, verusFee);
                        coinbaseTx.vout[cbOutIdx].scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, 
                                                                                  std::vector<CTxDestination>({minerDestination}),
                                                                                  1,
                                                                                  &to));
                    }
                    verusFeeLeft -= verusFee;
                }

                // we had to wait to update this here to ensure it represented a correct distribution ratio
                coinbaseTx.vout[cbOutIdx].nValue = amount;
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        blocktime = std::max(pindexPrev->GetMedianTimePast(), GetAdjustedTime());

        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());

        coinbaseTx.nExpiryHeight = 0;
        coinbaseTx.nLockTime = blocktime;

        // finalize input of coinbase
        coinbaseTx.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(0)) + COINBASE_FLAGS;
        assert(coinbaseTx.vin[0].scriptSig.size() <= 100);

        // coinbase is done
        pblock->vtx[0] = coinbaseTx;
        uint256 cbHash = coinbaseTx.GetHash();

        // display it at block 1 for PBaaS debugging
        /* if (nHeight == 1)
        {
            UniValue jsonTxOut(UniValue::VOBJ);
            TxToUniv(coinbaseTx, uint256(), jsonTxOut);
            printf("%s: new coinbase transaction: %s\n", __func__, jsonTxOut.write(1,2).c_str());
        } */

        // if there is a stake transaction, add it to the very end
        if (isStake)
        {
            UpdateCoins(txStaked, view, nHeight);
            pblock->vtx.push_back(txStaked);
            pblocktemplate->vTxFees.push_back(0);
            int txSigOps = GetLegacySigOpCount(txStaked);
            pblocktemplate->vTxSigOps.push_back(txSigOps);
            // already added to the block size above
            ++nBlockTx;
            nBlockSigOps += txSigOps;
        }

        extern CWallet *pwalletMain;

        pblock->vtx[0] = coinbaseTx;
        pblocktemplate->vTxFees[0] = -nFees;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        // if not Verus stake, setup nonce, otherwise, leave it alone
        if (!isStake || ASSETCHAINS_LWMAPOS == 0)
        {
            // Randomize nonce
            arith_uint256 nonce = UintToArith256(GetRandHash());

            // Clear the top 16 and bottom 16 or 24 bits (for local use as thread flags and counters)
            nonce <<= ASSETCHAINS_NONCESHIFT[ASSETCHAINS_ALGO];
            nonce >>= 16;
            pblock->nNonce = ArithToUint256(nonce);
        }
        
        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->hashFinalSaplingRoot   = sapling_tree.root();

        // all Verus PoS chains need this data in the block at all times
        if ( ASSETCHAINS_LWMAPOS || ASSETCHAINS_SYMBOL[0] == 0 || ASSETCHAINS_STAKED == 0 || KOMODO_MININGTHREADS > 0 )
        {
            UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
        }

        if ( ASSETCHAINS_SYMBOL[0] == 0 && IS_KOMODO_NOTARY != 0 && My_notaryid >= 0 )
        {
            uint32_t r;
            CMutableTransaction txNotary = CreateNewContextualCMutableTransaction(Params().GetConsensus(), chainActive.Height() + 1);
            if ( pblock->nTime < pindexPrev->nTime+60 )
                pblock->nTime = pindexPrev->nTime + 60;

            if ( komodo_notaryvin(txNotary,NOTARY_PUBKEY33) > 0 )
            {
                CAmount txfees = 5000;
                pblock->vtx.push_back(txNotary);
                pblocktemplate->vTxFees.push_back(txfees);
                pblocktemplate->vTxSigOps.push_back(GetLegacySigOpCount(txNotary));
                nFees += txfees;
                pblocktemplate->vTxFees[0] = -nFees;
                //*(uint64_t *)(&pblock->vtx[0].vout[0].nValue) += txfees;
                //fprintf(stderr,"added notaryvin\n");
            }
            else
            {
                fprintf(stderr,"error adding notaryvin, need to create 0.0001 utxos\n");
                return(0);
            }
        }
        else if ( ASSETCHAINS_CC == 0 && pindexPrev != 0 && ASSETCHAINS_STAKED == 0 && (ASSETCHAINS_SYMBOL[0] != 0 || IS_KOMODO_NOTARY == 0 || My_notaryid < 0) )
        {
            CValidationState state;
            //fprintf(stderr,"check validity\n");
            if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) // invokes CC checks
            {
                throw std::runtime_error("CreateNewBlock(): TestBlockValidity failed");
            }
            //fprintf(stderr,"valid\n");
        }
    }
    //fprintf(stderr,"done new block\n");

    // setup the header and buid the Merkle tree
    unsigned int extraNonce;
    IncrementExtraNonce(pblock, pindexPrev, extraNonce, true);

    return pblocktemplate.release();
}

CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& _scriptPubKeyIn, bool isStake)
{
    std::vector<CTxOut> minerOutputs = _scriptPubKeyIn.size() ? std::vector<CTxOut>({CTxOut(1, _scriptPubKeyIn)}) : std::vector<CTxOut>();
    return CreateNewBlock(chainparams, minerOutputs, isStake);
}

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

#ifdef ENABLE_MINING

class MinerAddressScript : public CReserveScript
{
    // CReserveScript requires implementing this function, so that if an
    // internal (not-visible) wallet address is used, the wallet can mark it as
    // important when a block is mined (so it then appears to the user).
    // If -mineraddress is set, the user already knows about and is managing the
    // address, so we don't need to do anything here.
    void KeepScript() {}
};

void GetScriptForMinerAddress(boost::shared_ptr<CReserveScript> &script)
{
    CTxDestination addr = DecodeDestination(GetArg("-mineraddress", ""));
    if (!IsValidDestination(addr)) {
        return;
    }

    boost::shared_ptr<MinerAddressScript> mAddr(new MinerAddressScript());
    script = mAddr;
    script->reserveScript = GetScriptForDestination(addr);
}

#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey, int32_t nHeight, bool isStake)
{
    CPubKey pubkey; 
    CScript scriptPubKey; 
    uint8_t *ptr; 
    int32_t i;
    boost::shared_ptr<CReserveScript> coinbaseScript;
 
    if ( nHeight == 1 && ASSETCHAINS_OVERRIDE_PUBKEY33[0] != 0 )
    {
        scriptPubKey = CScript() << ParseHex(ASSETCHAINS_OVERRIDE_PUBKEY) << OP_CHECKSIG;
    }
    else if ( USE_EXTERNAL_PUBKEY != 0 )
    {
        //fprintf(stderr,"use notary pubkey\n");
        scriptPubKey = CScript() << ParseHex(NOTARY_PUBKEY) << OP_CHECKSIG;
    }
    else if (GetArg("-mineraddress", "").empty() || !(GetScriptForMinerAddress(coinbaseScript), (scriptPubKey = coinbaseScript->reserveScript).size()))
    {
        if (!isStake)
        {
            if (!reservekey.GetReservedKey(pubkey))
            {
                return NULL;
            }
            scriptPubKey = GetScriptForDestination(pubkey);
        }
    }
    return CreateNewBlock(Params(), scriptPubKey, isStake);
}

void komodo_broadcast(const CBlock *pblock,int32_t limit)
{
    int32_t n = 1;
    //fprintf(stderr,"broadcast new block t.%u\n",(uint32_t)time(NULL));
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            if ( pnode->hSocket == INVALID_SOCKET )
                continue;
            if ( (rand() % n) == 0 )
            {
                pnode->PushMessage("block", *pblock);
                if ( n++ > limit )
                    break;
            }
        }
    }
    //fprintf(stderr,"finished broadcast new block t.%u\n",(uint32_t)time(NULL));
}

static bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
#else
static bool ProcessBlockFound(CBlock* pblock)
#endif // ENABLE_WALLET
{
    int32_t height = chainActive.LastTip()->GetHeight()+1;
    //LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s height.%d\n", FormatMoney(pblock->vtx[0].vout[0].nValue), height);

    // Found a solution
    {
        if (pblock->hashPrevBlock != chainActive.LastTip()->GetBlockHash())
        {
            uint256 hash; int32_t i;
            hash = pblock->hashPrevBlock;
            for (i=31; i>=0; i--)
                fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
            fprintf(stderr," <- prev (stale)\n");
            hash = chainActive.LastTip()->GetBlockHash();
            for (i=31; i>=0; i--)
                fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
            fprintf(stderr," <- chainTip (stale)\n");
            
            return error("VerusMiner: generated block is stale");
        }
    }
    
#ifdef ENABLE_WALLET
    // Remove key from key pool
    if ( IS_KOMODO_NOTARY == 0 )
    {
        if (GetArg("-mineraddress", "").empty()) {
            // Remove key from key pool
            reservekey.KeepKey();
        }
    }
    // Track how many getdata requests this block gets
    //if ( 0 )
    {
        //fprintf(stderr,"lock cs_wallet\n");
        LOCK(wallet.cs_wallet);
        wallet.mapRequestCount[pblock->GetHash()] = 0;
    }
#endif
    //fprintf(stderr,"process new block\n");

    // Process this block (almost) the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(1, chainActive.LastTip()->GetHeight()+1, state, Params(), NULL, pblock, true, NULL))
        return error("VerusMiner: ProcessNewBlock, block not accepted");
    
    TrackMinedBlock(pblock->GetHash());
    komodo_broadcast(pblock,16);
    return true;
}

int32_t komodo_baseid(char *origbase);
int32_t komodo_eligiblenotary(uint8_t pubkeys[66][33],int32_t *mids,uint32_t *blocktimes,int32_t *nonzpkeysp,int32_t height);
arith_uint256 komodo_PoWtarget(int32_t *percPoSp,arith_uint256 target,int32_t height,int32_t goalperc);
int32_t FOUND_BLOCK,KOMODO_MAYBEMINED;
extern int32_t KOMODO_LASTMINED,KOMODO_INSYNC;
int32_t roundrobin_delay;
arith_uint256 HASHTarget,HASHTarget_POW;
int32_t komodo_longestchain();

// wait for peers to connect
void waitForPeers(const CChainParams &chainparams)
{
    if (chainparams.MiningRequiresPeers())
    {
        bool fvNodesEmpty;
        {
            boost::this_thread::interruption_point();
            LOCK(cs_vNodes);
            fvNodesEmpty = vNodes.empty();
        }
        int longestchain = komodo_longestchain();
        int lastlongest = 0;
        if (fvNodesEmpty || IsNotInSync() || (longestchain != 0 && longestchain > chainActive.LastTip()->GetHeight()))
        {
            int loops = 0, blockDiff = 0, newDiff = 0;
            
            do {
                if (fvNodesEmpty)
                {
                    MilliSleep(1000 + rand() % 4000);
                    boost::this_thread::interruption_point();
                    LOCK(cs_vNodes);
                    fvNodesEmpty = vNodes.empty();
                    loops = 0;
                    blockDiff = 0;
                    lastlongest = 0;
                }
                else if ((newDiff = IsNotInSync()) > 0)
                {
                    if (blockDiff != newDiff)
                    {
                        blockDiff = newDiff;
                    }
                    else
                    {
                        if (++loops <= 5)
                        {
                            MilliSleep(1000);
                        }
                        else break;
                    }
                    lastlongest = 0;
                }
                else if (!fvNodesEmpty && !IsNotInSync() && longestchain > chainActive.LastTip()->GetHeight())
                {
                    // the only thing may be that we are seeing a long chain that we'll never get
                    // don't wait forever
                    if (lastlongest == 0)
                    {
                        MilliSleep(3000);
                        lastlongest = longestchain;
                    }
                }
            } while (fvNodesEmpty || IsNotInSync());
            MilliSleep(500 + rand() % 1000);
        }
    }
}

#ifdef ENABLE_WALLET
CBlockIndex *get_chainactive(int32_t height)
{
    if ( chainActive.LastTip() != 0 )
    {
        if ( height <= chainActive.LastTip()->GetHeight() )
        {
            LOCK(cs_main);
            return(chainActive[height]);
        }
        // else fprintf(stderr,"get_chainactive height %d > active.%d\n",height,chainActive.Tip()->GetHeight());
    }
    //fprintf(stderr,"get_chainactive null chainActive.Tip() height %d\n",height);
    return(0);
}

/*
 * A separate thread to stake, while the miner threads mine.
 */
void static VerusStaker(CWallet *pwallet)
{
    LogPrintf("Verus staker thread started\n");
    RenameThread("verus-staker");

    const CChainParams& chainparams = Params();
    auto consensusParams = chainparams.GetConsensus();
    bool isNotaryConnected = ConnectedChains.CheckVerusPBaaSAvailable();

    // Each thread has its own key
    CReserveKey reservekey(pwallet);

    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    uint8_t *script; uint64_t total,checktoshis; int32_t i,j;

    while ( (ASSETCHAIN_INIT == 0 || KOMODO_INITDONE == 0) ) //chainActive.Tip()->GetHeight() != 235300 &&
    {
        sleep(1);
        if ( komodo_baseid(ASSETCHAINS_SYMBOL) < 0 )
            break;
    }

    // try a nice clean peer connection to start
    CBlockIndex *pindexPrev, *pindexCur;
    do {
        pindexPrev = chainActive.LastTip();
        MilliSleep(5000 + rand() % 5000);
        waitForPeers(chainparams);
        pindexCur = chainActive.LastTip();
    } while (pindexPrev != pindexCur);

    try {
        static int32_t lastStakingHeight = 0;

        while (true)
        {
            waitForPeers(chainparams);
            CBlockIndex* pindexPrev = chainActive.LastTip();

            // Create new block
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();

            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                Mining_start = (uint32_t)time(NULL);
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();

            // try to stake a block
            CBlockTemplate *ptr = NULL;

            // get height locally for consistent reporting
            int32_t newHeight = Mining_height;

            if (newHeight > VERUS_MIN_STAKEAGE)
                ptr = CreateNewBlockWithKey(reservekey, newHeight, true);

            // TODO - putting this output here tends to help mitigate announcing a staking height earlier than
            // announcing the last block win when we start staking before a block's acceptance has been
            // acknowledged by the mining thread - a better solution may be to put the output on the submission
            // thread.
            if ( ptr == 0 && newHeight != lastStakingHeight )
            {
                printf("Staking height %d for %s\n", newHeight, ASSETCHAINS_SYMBOL);
            }
            lastStakingHeight = newHeight;

            if ( ptr == 0 )
            {
                if (newHeight == 1 && (isNotaryConnected = ConnectedChains.IsNotaryAvailable()))
                {
                    static int outputCounter;
                    if (outputCounter++ % 60 == 0)
                    {
                        printf("%s: waiting for confirmation of launch at or after block %u on %s before mining block 1\n", __func__, 
                                                                                        (uint32_t)ConnectedChains.ThisChain().startBlock, 
                                                                                        ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                        sleep(1);
                    }
                }
                // wait to try another staking block until after the tip moves again
                while ( chainActive.LastTip() == pindexPrev )
                    MilliSleep(250);
                if (newHeight == 1)
                {
                    sleep(10);
                }
                continue;
            }

            unique_ptr<CBlockTemplate> pblocktemplate(ptr);
            if (!pblocktemplate.get())
            {
                if (GetArg("-mineraddress", "").empty()) {
                    LogPrintf("Error in %s staker: Keypool ran out, please call keypoolrefill before restarting the mining thread\n",
                              ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                } else {
                    // Should never reach here, because -mineraddress validity is checked in init.cpp
                    LogPrintf("Error in %s staker: Invalid %s -mineraddress\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], ASSETCHAINS_SYMBOL);
                }
                return;
            }

            CBlock *pblock = &pblocktemplate->block;
            LogPrintf("Staking with %u transactions in block (%u bytes)\n", pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));
            //
            // Search
            //
            int64_t nStart = GetTime();

            if (vNodes.empty() && chainparams.MiningRequiresPeers())
            {
                if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                {
                    fprintf(stderr,"no nodes, attempting reconnect\n");
                    continue;
                }
            }

            if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
            {
                fprintf(stderr,"timeout, retrying\n");
                continue;
            }

            if ( pindexPrev != chainActive.LastTip() )
            {
                printf("Block %d added to chain\n", chainActive.LastTip()->GetHeight());
                MilliSleep(250);
                continue;
            }

            int32_t unlockTime = komodo_block_unlocktime(Mining_height);
            int64_t subsidy = (int64_t)(pblock->vtx[0].vout[0].nValue);

            uint256 hashTarget = ArithToUint256(arith_uint256().SetCompact(pblock->nBits));

            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

            UpdateTime(pblock, consensusParams, pindexPrev);

            if (ProcessBlockFound(pblock, *pwallet, reservekey))
            {
                LogPrintf("Using %s algorithm:\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                LogPrintf("Staked block found  \n  hash: %s  \ntarget: %s\n", pblock->GetHash().GetHex(), hashTarget.GetHex());
                printf("Found block %d \n", newHeight);
                printf("staking reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
                arith_uint256 post;
                post.SetCompact(pblock->GetVerusPOSTarget());

                CTransaction &sTx = pblock->vtx[pblock->vtx.size()-1];
                printf("POS hash: %s  \ntarget:   %s\n", 
                    CTransaction::_GetVerusPOSHash(&(pblock->nNonce), 
                                                     sTx.vin[0].prevout.hash, 
                                                     sTx.vin[0].prevout.n, 
                                                     newHeight, 
                                                     chainActive.GetVerusEntropyHash(newHeight), 
                                                     sTx.vout[0].nValue).GetHex().c_str(), 
                                                     ArithToUint256(post).GetHex().c_str());
                if (unlockTime > newHeight && subsidy >= ASSETCHAINS_TIMELOCKGTE)
                    printf("- timelocked until block %i\n", unlockTime);
                else
                    printf("\n");
            }
            else
            {
                LogPrintf("Found block rejected at staking height: %d\n", Mining_height);
                printf("Found block rejected at staking height: %d\n", Mining_height);
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();

            sleep(3);

            // In regression test mode, stop mining after a block is found.
            if (chainparams.MineBlocksOnDemand()) {
                throw boost::thread_interrupted();
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("VerusStaker terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("VerusStaker runtime error: %s\n", e.what());
        return;
    }
}

typedef bool (*minefunction)(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);
bool mine_verus_v2(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);
bool mine_verus_v2_port(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);

void static BitcoinMiner_noeq(CWallet *pwallet)
#else
void static BitcoinMiner_noeq()
#endif
{
    LogPrintf("%s miner started\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
    RenameThread("verushash-miner");

#ifdef ENABLE_WALLET
    // Each thread has its own key
    CReserveKey reservekey(pwallet);
#endif

    miningTimer.clear();

    const CChainParams& chainparams = Params();
    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    uint8_t *script; uint64_t total,checktoshis; int32_t i,j;

    while ( (ASSETCHAIN_INIT == 0 || KOMODO_INITDONE == 0) ) //chainActive.Tip()->GetHeight() != 235300 &&
    {
        sleep(1);
        if ( komodo_baseid(ASSETCHAINS_SYMBOL) < 0 )
            break;
    }

    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // try a nice clean peer connection to start
    CBlockIndex *pindexPrev, *pindexCur;
    do {
        pindexPrev = chainActive.LastTip();
        MilliSleep(5000 + rand() % 5000);
        waitForPeers(chainparams);
        pindexCur = chainActive.LastTip();
    } while (pindexPrev != pindexCur);

    // make sure that we have checked for PBaaS availability
    ConnectedChains.CheckVerusPBaaSAvailable();

    // this will not stop printing more than once in all cases, but it will allow us to print in all cases
    // and print duplicates rarely without having to synchronize
    static CBlockIndex *lastChainTipPrinted;
    static int32_t lastMiningHeight = 0;

    miningTimer.start();

    try {
        printf("Mining %s with %s\n", ASSETCHAINS_SYMBOL, ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);

        while (true)
        {
            miningTimer.stop();
            waitForPeers(chainparams);

            pindexPrev = chainActive.LastTip();

            // prevent forking on startup before the diff algorithm kicks in,
            // but only for a startup Verus test chain. PBaaS chains have the difficulty inherited from
            // their parent
            if (chainparams.MiningRequiresPeers() && ((IsVerusActive() && pindexPrev->GetHeight() < 50) || pindexPrev != chainActive.LastTip()))
            {
                do {
                    pindexPrev = chainActive.LastTip();
                    MilliSleep(2000 + rand() % 2000);
                } while (pindexPrev != chainActive.LastTip());
            }

            // Create new block
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                if (lastMiningHeight != Mining_height)
                {
                    lastMiningHeight = Mining_height;
                    printf("Mining %s at height %d\n", ASSETCHAINS_SYMBOL, Mining_height);
                }
                Mining_start = (uint32_t)time(NULL);
            }

            miningTimer.start();

#ifdef ENABLE_WALLET
            CBlockTemplate *ptr = CreateNewBlockWithKey(reservekey, Mining_height);
#else
            CBlockTemplate *ptr = CreateNewBlockWithKey();
#endif
            if ( ptr == 0 )
            {
                static uint32_t counter;
                if ( counter++ % 40 == 0 )
                {
                    if (!IsVerusActive() &&
                        ConnectedChains.IsNotaryAvailable() &&
                        !ConnectedChains.readyToStart)
                    {
                        fprintf(stderr,"waiting for confirmation of launch at or after block %u on %s chain to start\n", (uint32_t)ConnectedChains.ThisChain().startBlock,
                                                                                        ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                    }
                    else
                    {
                        fprintf(stderr,"Unable to create valid block... will continue to try\n");
                    }
                }
                MilliSleep(2000);
                continue;
            }

            unique_ptr<CBlockTemplate> pblocktemplate(ptr);
            if (!pblocktemplate.get())
            {
                if (GetArg("-mineraddress", "").empty()) {
                    LogPrintf("Error in %s miner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n",
                              ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                } else {
                    // Should never reach here, because -mineraddress validity is checked in init.cpp
                    LogPrintf("Error in %s miner: Invalid %s -mineraddress\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], ASSETCHAINS_SYMBOL);
                }
                miningTimer.stop();
                miningTimer.clear();
                return;
            }
            CBlock *pblock = &pblocktemplate->block;

            uint32_t savebits;
            bool mergeMining = false;
            savebits = pblock->nBits;

            uint32_t solutionVersion = CConstVerusSolutionVector::Version(pblock->nSolution);
            if (pblock->nVersion != CBlockHeader::VERUS_V2)
            {
                // must not be in sync
                printf("Mining on incorrect block version.\n");
                sleep(2);
                continue;
            }
            bool verusSolutionPBaaS = solutionVersion >= CActivationHeight::ACTIVATE_PBAAS;

            // v2 hash writer with adjustments for the current height
            CVerusHashV2bWriter ss2 = CVerusHashV2bWriter(SER_GETHASH, PROTOCOL_VERSION, solutionVersion);

            if ( ASSETCHAINS_SYMBOL[0] != 0 )
            {
                if ( ASSETCHAINS_REWARD[0] == 0 && !ASSETCHAINS_LASTERA )
                {
                    if ( pblock->vtx.size() == 1 && pblock->vtx[0].vout.size() == 1 && Mining_height > ASSETCHAINS_MINHEIGHT )
                    {
                        static uint32_t counter;
                        if ( counter++ < 10 )
                            fprintf(stderr,"skip generating %s on-demand block, no tx avail\n",ASSETCHAINS_SYMBOL);
                        sleep(10);
                        continue;
                    } else fprintf(stderr,"%s vouts.%d mining.%d vs %d\n",ASSETCHAINS_SYMBOL,(int32_t)pblock->vtx[0].vout.size(),Mining_height,ASSETCHAINS_MINHEIGHT);
                }
            }

            // set our easiest target, if V3+, no need to rebuild the merkle tree
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce, verusSolutionPBaaS ? false : true, &savebits);

            // update PBaaS header
            if (verusSolutionPBaaS)
            {
                if (!IsVerusActive() && ConnectedChains.IsVerusPBaaSAvailable())
                {

                    UniValue params(UniValue::VARR);
                    UniValue error(UniValue::VARR);
                    params.push_back(EncodeHexBlk(*pblock));
                    params.push_back(ASSETCHAINS_SYMBOL);
                    params.push_back(ASSETCHAINS_RPCHOST);
                    params.push_back(ASSETCHAINS_RPCPORT);
                    params.push_back(ASSETCHAINS_RPCCREDENTIALS);
                    try
                    {
                        ConnectedChains.lastSubmissionFailed = false;
                        params = RPCCallRoot("addmergedblock", params);
                        params = find_value(params, "result");
                        error = find_value(params, "error");
                    } catch (std::exception e)
                    {
                        printf("Failed to connect to %s chain\n", ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                        params = UniValue(e.what());
                    }
                    if (mergeMining = (params.isNull() && error.isNull()))
                    {
                        printf("Merge mining %s with %s as the hashing chain\n", ASSETCHAINS_SYMBOL, ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                        LogPrintf("Merge mining with %s as the hashing chain\n", ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                    }
                }
            }

            LogPrintf("Running %s miner with %u transactions in block (%u bytes)\n",ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO],
                       pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));
            //
            // Search
            //
            int64_t nStart = GetTime();

            arith_uint256 hashTarget = arith_uint256().SetCompact(savebits);
            uint256 uintTarget = ArithToUint256(hashTarget);
            arith_uint256 ourTarget;
            ourTarget.SetCompact(pblock->nBits);

            Mining_start = 0;

            if ( pindexPrev != chainActive.LastTip() )
            {
                if (lastChainTipPrinted != chainActive.LastTip())
                {
                    lastChainTipPrinted = chainActive.LastTip();
                    printf("Block %d added to chain\n", lastChainTipPrinted->GetHeight());
                }
                MilliSleep(100);
                continue;
            }

            uint64_t count;
            uint64_t hashesToGo = 0;
            uint64_t totalDone = 0;

            int64_t subsidy = (int64_t)(pblock->vtx[0].vout[0].nValue);
            count = ((ASSETCHAINS_NONCEMASK[ASSETCHAINS_ALGO] >> 3) + 1) / ASSETCHAINS_HASHESPERROUND[ASSETCHAINS_ALGO];
            CVerusHashV2 *vh2 = &ss2.GetState();
            u128 *hashKey;
            verusclhasher &vclh = vh2->vclh;
            minefunction mine_verus;
            mine_verus = IsCPUVerusOptimized() ? &mine_verus_v2 : &mine_verus_v2_port;

            while (true)
            {
                uint256 hashResult = uint256();

                unsigned char *curBuf;

                if (mergeMining)
                {
                    // loop for a few minutes before refreshing the block
                    while (true)
                    {
                        uint256 ourMerkle = pblock->hashMerkleRoot;
                        if ( pindexPrev != chainActive.LastTip() )
                        {
                            if (lastChainTipPrinted != chainActive.LastTip())
                            {
                                lastChainTipPrinted = chainActive.LastTip();
                                printf("Block %d added to chain\n\n", lastChainTipPrinted->GetHeight());
                                arith_uint256 target;
                                target.SetCompact(lastChainTipPrinted->nBits);
                                if (ourMerkle == lastChainTipPrinted->hashMerkleRoot)
                                {
                                    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", lastChainTipPrinted->GetBlockHash().GetHex().c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                                    printf("Found block %d \n", lastChainTipPrinted->GetHeight());
                                    printf("mining reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
                                    printf("  hash: %s\ntarget: %s\n", lastChainTipPrinted->GetBlockHash().GetHex().c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                                }
                            }
                            break;
                        }

                        // if PBaaS is no longer available, we can't count on merge mining
                        if (!ConnectedChains.IsVerusPBaaSAvailable())
                        {
                            break;
                        }

                        if (vNodes.empty() && chainparams.MiningRequiresPeers())
                        {
                            if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                            {
                                fprintf(stderr,"no nodes, attempting reconnect\n");
                                break;
                            }
                        }

                        // update every few minutes, regardless
                        int64_t elapsed = GetTime() - nStart;

                        if ((mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && elapsed > 60) || elapsed > 60 || ConnectedChains.lastSubmissionFailed)
                        {
                            break;
                        }

                        boost::this_thread::interruption_point();
                        MilliSleep(500);
                    }
                    break;
                }
                else
                {
                    // check NONCEMASK at a time
                    for (uint64_t i = 0; i < count; i++)
                    {
                        // this is the actual mining loop, which enables us to drop out and queue a header anytime we earn a block that is good enough for a
                        // merge mined block, but not our own
                        bool blockFound;
                        arith_uint256 arithHash;
                        totalDone = 0;
                        do
                        {
                            // pickup/remove any new/deleted headers
                            if (ConnectedChains.dirty || (pblock->NumPBaaSHeaders() < ConnectedChains.mergeMinedChains.size() + 1))
                            {
                                IncrementExtraNonce(pblock, pindexPrev, nExtraNonce, verusSolutionPBaaS ? false : true, &savebits);

                                hashTarget.SetCompact(savebits);
                                uintTarget = ArithToUint256(hashTarget);
                            }

                            // hashesToGo gets updated with actual number run for metrics
                            hashesToGo = ASSETCHAINS_HASHESPERROUND[ASSETCHAINS_ALGO];
                            uint64_t start = i * hashesToGo + totalDone;
                            hashesToGo -= totalDone;

                            if (verusSolutionPBaaS)
                            {
                                // mine on canonical header for merge mining
                                CPBaaSPreHeader savedHeader(*pblock);

                                pblock->ClearNonCanonicalData();
                                blockFound = (*mine_verus)(*pblock, ss2, hashResult, uintTarget, start, &hashesToGo);
                                savedHeader.SetBlockData(*pblock);
                            }
                            else
                            {
                                blockFound = (*mine_verus)(*pblock, ss2, hashResult, uintTarget, start, &hashesToGo);
                            }

                            arithHash = UintToArith256(hashResult);
                            totalDone += hashesToGo + 1;
                            if (blockFound && IsVerusActive())
                            {
                                ConnectedChains.QueueNewBlockHeader(*pblock);
                                if (arithHash > ourTarget)
                                {
                                    // all blocks qualified with this hash will be submitted
                                    // until we redo the block, we might as well not try again with anything over this hash
                                    hashTarget = arithHash;
                                    uintTarget = ArithToUint256(hashTarget);
                                }
                            }
                        } while (blockFound && arithHash > ourTarget);

                        if (!blockFound || arithHash > ourTarget)
                        {
                            // Check for stop or if block needs to be rebuilt
                            boost::this_thread::interruption_point();
                            if ( pindexPrev != chainActive.LastTip() )
                            {
                                if (lastChainTipPrinted != chainActive.LastTip())
                                {
                                    lastChainTipPrinted = chainActive.LastTip();
                                    printf("Block %d added to chain\n", lastChainTipPrinted->GetHeight());
                                }
                                break;
                            }
                            else if ((i + 1) < count)
                            {
                                // if we'll not drop through, update hashcount
                                {
                                    miningTimer += totalDone;
                                    totalDone = 0;
                                }
                            }
                        }
                        else
                        {
                            // Check for stop or if block needs to be rebuilt
                            boost::this_thread::interruption_point();

                            if (pblock->nSolution.size() != 1344)
                            {
                                LogPrintf("ERROR: Block solution is not 1344 bytes as it should be");
                                break;
                            }

                            SetThreadPriority(THREAD_PRIORITY_NORMAL);

                            int32_t unlockTime = komodo_block_unlocktime(Mining_height);

#ifdef VERUSHASHDEBUG
                            std::string validateStr = hashResult.GetHex();
                            std::string hashStr = pblock->GetHash().GetHex();
                            uint256 *bhalf1 = (uint256 *)vh2->CurBuffer();
                            uint256 *bhalf2 = bhalf1 + 1;
#else
                            std::string hashStr = hashResult.GetHex();
#endif

                            LogPrintf("Using %s algorithm:\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                            LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hashStr, ArithToUint256(ourTarget).GetHex());
                            printf("Found block %d \n", Mining_height );
                            printf("mining reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
#ifdef VERUSHASHDEBUG
                            printf("  hash: %s\n   val: %s  \ntarget: %s\n\n", hashStr.c_str(), validateStr.c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                            printf("intermediate %lx\n", intermediate);
                            printf("Curbuf: %s%s\n", bhalf1->GetHex().c_str(), bhalf2->GetHex().c_str());
                            bhalf1 = (uint256 *)verusclhasher_key.get();
                            bhalf2 = bhalf1 + ((vh2->vclh.keyMask + 1) >> 5);
                            printf("   Key: %s%s\n", bhalf1->GetHex().c_str(), bhalf2->GetHex().c_str());
#else
                            printf("  hash: %s\ntarget: %s", hashStr.c_str(), ArithToUint256(ourTarget).GetHex().c_str());
#endif
                            if (unlockTime > Mining_height && subsidy >= ASSETCHAINS_TIMELOCKGTE)
                                printf(" - timelocked until block %i\n", unlockTime);
                            else
                                printf("\n");
#ifdef ENABLE_WALLET
                            ProcessBlockFound(pblock, *pwallet, reservekey);
#else
                            ProcessBlockFound(pblock);
#endif
                            SetThreadPriority(THREAD_PRIORITY_LOWEST);
                            break;
                        }
                    }

                    {
                        miningTimer += totalDone;
                    }
                }
                

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point();

                if (vNodes.empty() && chainparams.MiningRequiresPeers())
                {
                    if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                    {
                        fprintf(stderr,"no nodes, attempting reconnect\n");
                        break;
                    }
                }

                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                {
                    fprintf(stderr,"timeout, retrying\n");
                    break;
                }

                if ( pindexPrev != chainActive.LastTip() )
                {
                    if (lastChainTipPrinted != chainActive.LastTip())
                    {
                        lastChainTipPrinted = chainActive.LastTip();
                        printf("Block %d added to chain\n\n", lastChainTipPrinted->GetHeight());
                    }
                    break;
                }

                // totalDone now has the number of hashes actually done since starting on one nonce mask worth
                uint64_t hashesPerNonceMask = ASSETCHAINS_NONCEMASK[ASSETCHAINS_ALGO] >> 3;
                if (!(totalDone < hashesPerNonceMask))
                {
#ifdef _WIN32
                    printf("%llu mega hashes complete - working\n", (hashesPerNonceMask + 1) / 1048576);
#else
                    printf("%lu mega hashes complete - working\n", (hashesPerNonceMask + 1) / 1048576);
#endif
                }
                break;

            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        miningTimer.stop();
        miningTimer.clear();
        LogPrintf("%s miner terminated\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
        throw;
    }
    catch (const std::runtime_error &e)
    {
        miningTimer.stop();
        miningTimer.clear();
        LogPrintf("%s miner runtime error: %s\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], e.what());
        return;
    }
    miningTimer.stop();
    miningTimer.clear();
}

#ifdef ENABLE_WALLET
    void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
#else
    void GenerateBitcoins(bool fGenerate, int nThreads)
#endif
    {
        static CCriticalSection cs_startmining;

        LOCK(cs_startmining);
        if (!AreParamsInitialized())
        {
            return;
        }

        VERUS_MINTBLOCKS = (VERUS_MINTBLOCKS && ASSETCHAINS_LWMAPOS != 0);

        if (fGenerate == true || VERUS_MINTBLOCKS)
        {
            mapArgs["-gen"] = "1";

            if (VERUS_DEFAULT_ZADDR.size() > 0)
            {
                if (defaultSaplingDest == boost::none)
                {
                    LogPrintf("ERROR: -defaultzaddr parameter is invalid Sapling payment address\n");
                    fprintf(stderr, "-defaultzaddr parameter is invalid Sapling payment address\n");
                }
                else
                {
                    LogPrintf("StakeGuard searching for double stakes on %s\n", VERUS_DEFAULT_ZADDR.c_str());
                    fprintf(stderr, "StakeGuard searching for double stakes on %s\n", VERUS_DEFAULT_ZADDR.c_str());
                }
            }
        }

        static boost::thread_group* minerThreads = NULL;

        if (nThreads < 0)
            nThreads = GetNumCores();

        if (minerThreads != NULL)
        {
            minerThreads->interrupt_all();
            minerThreads->join_all();
            delete minerThreads;
            minerThreads = NULL;
        }

        //fprintf(stderr,"nThreads.%d fGenerate.%d\n",(int32_t)nThreads,fGenerate);
        if ( nThreads == 0 && ASSETCHAINS_STAKED )
            nThreads = 1;

        if (!fGenerate)
            return;

        minerThreads = new boost::thread_group();

        // add the PBaaS thread when mining or staking
        minerThreads->create_thread(boost::bind(&CConnectedChains::SubmissionThreadStub));

#ifdef ENABLE_WALLET
        if (VERUS_MINTBLOCKS && pwallet != NULL)
        {
            minerThreads->create_thread(boost::bind(&VerusStaker, pwallet));
        }
#endif

        for (int i = 0; i < nThreads; i++) {
#ifdef ENABLE_WALLET
            minerThreads->create_thread(boost::bind(&BitcoinMiner_noeq, pwallet));
#else
            minerThreads->create_thread(&BitcoinMiner_noeq);
#endif
        }
    }
    
#endif // ENABLE_MINING
