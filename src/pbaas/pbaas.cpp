/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS initialization, notarization, and cross-chain token
 * transactions and enabling liquid or non-liquid tokens across the
 * Verus ecosystem.
 * 
 */

#include "base58.h"
#include "main.h"
#include "rpc/pbaasrpc.h"
#include "timedata.h"
#include "transaction_builder.h"

CConnectedChains ConnectedChains;

bool IsVerusActive()
{
    std::string normalName = boost::to_lower_copy(std::string(ASSETCHAINS_SYMBOL));
    return normalName == "vrsc" || normalName == "vrsctest";
}

bool IsVerusMainnetActive()
{
    return (strcmp(ASSETCHAINS_SYMBOL, "VRSC") == 0);
}

// this adds an opret to a mutable transaction and returns the voutnum if it could be added
int32_t AddOpRetOutput(CMutableTransaction &mtx, const CScript &opRetScript)
{
    if (opRetScript.IsOpReturn() && opRetScript.size() <= MAX_OP_RETURN_RELAY)
    {
        CTxOut vOut = CTxOut();
        vOut.scriptPubKey = opRetScript;
        vOut.nValue = 0;
        mtx.vout.push_back(vOut);
        return mtx.vout.size() - 1;
    }
    else
    {
        return -1;
    }
}

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
uint256 GetChainObjectHash(const CBaseChainObject &bo)
{
    union {
        const CBaseChainObject *retPtr;
        const CChainObject<CBlockHeaderAndProof> *pNewHeader;
        const CChainObject<CPartialTransactionProof> *pNewTx;
        const CChainObject<CBlockHeaderProof> *pNewHeaderRef;
        const CChainObject<CPriorBlocksCommitment> *pPriors;
        const CChainObject<uint256> *pNewProofRoot;
        const CChainObject<CReserveTransfer> *pExport;
        const CChainObject<CCrossChainProof> *pCrossChainProof;
        const CChainObject<CCompositeChainObject> *pCompositeChainObject;
    };

    retPtr = &bo;

    switch(bo.objectType)
    {
        case CHAINOBJ_HEADER:
            return pNewHeader->GetHash();

        case CHAINOBJ_TRANSACTION_PROOF:
            return pNewTx->GetHash();

        case CHAINOBJ_HEADER_REF:
            return pNewHeaderRef->GetHash();

        case CHAINOBJ_PRIORBLOCKS:
            return pPriors->GetHash();

        case CHAINOBJ_PROOF_ROOT:
            return pNewProofRoot->object;

        case CHAINOBJ_RESERVETRANSFER:
            return pExport->GetHash();

        case CHAINOBJ_CROSSCHAINPROOF:
            return pCrossChainProof->GetHash();

        case CHAINOBJ_COMPOSITEOBJECT:
            return pCrossChainProof->GetHash();

    }
    return uint256();
}

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsCrossChainExportInput(const CScript &scriptSig)
{
    return true;
}

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsCrossChainImportInput(const CScript &scriptSig)
{
    return true;
}

// Validate notary evidence
bool ValidateNotaryEvidence(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsNotaryEvidenceInput(const CScript &scriptSig)
{
    return true;
}

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveOutputInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveTransferInput(const CScript &scriptSig)
{
    return true;
}

CReserveDeposit GetSpendingReserveDeposit(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx, uint32_t *pHeight)
{
    CTransaction _sourceTx;
    CTransaction &sourceTx(pSourceTx ? *pSourceTx : _sourceTx);

    // if not fulfilled, ensure that no part of the primary identity is modified
    CReserveDeposit oldReserveDeposit;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        if (pHeight)
        {
            auto bIt = mapBlockIndex.find(blkHash);
            if (bIt == mapBlockIndex.end() || !bIt->second)
            {
                *pHeight = chainActive.Height();
            }
            else
            {
                *pHeight = bIt->second->GetHeight();
            }
        }
        COptCCParams p;
        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() && 
            p.evalCode == EVAL_RESERVE_DEPOSIT && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldReserveDeposit = CReserveDeposit(p.vData[0]);
        }
    }
    return oldReserveDeposit;
}

bool ValidateReserveDeposit(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // reserve deposits can only spend to the following:
    // 1. If the reserve deposit is controlled by an alternate system or gateway currency, it can be
    //    spent by an import that includes a sys import from the alternate system/gateway. The total
    //    input of all inputs to the tx from the deposit controller is considered and all but the amount
    //    specified in gateway imports of the import must come out as change back to the reserve deposit.
    // 2. If the reserve deposit is controlled by the currency of an import, exactly the amount spent by
    //    the import may be released in total and not sent back to change.

    // first, get the prior reserve deposit and determine the controlling currency
    CTransaction sourceTx;
    uint32_t sourceHeight;
    CReserveDeposit sourceRD = GetSpendingReserveDeposit(tx, nIn, &sourceTx, &sourceHeight);
    if (!sourceRD.IsValid())
    {
        return eval->Error(std::string(__func__) + ": attempting to spend invalid reserve deposit output " + tx.vin[nIn].ToString());
    }

    // now, ensure that the spender transaction includes an import output of this specific currency or
    // where this currency is a system gateway source
    CCrossChainImport authorizingImport;
    CCrossChainImport mainImport;

    // looking for an import output to the controlling currency
    int i;
    for (i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.vData.size() &&
            (authorizingImport = CCrossChainImport(p.vData[0])).IsValid() &&
            (authorizingImport.importCurrencyID == sourceRD.controllingCurrencyID))
        {
            break;
        }
    }

    if (i >= tx.vout.size())
    {
        LogPrint("reservedeposits", "%s: non import transaction %s attempting to spend reserve deposit %s\n", __func__, EncodeHexTx(tx).c_str(), tx.vin[nIn].ToString().c_str());
        return eval->Error(std::string(__func__) + ": non import transaction attempting to spend reserve deposit");
    }

    // if we found a valid output, determine if the output is direct or system source
    bool gatewaySource = false;
    if (gatewaySource = authorizingImport.IsSourceSystemImport())
    {
        COptCCParams p;
        i--;        // set i to the actual import
        if (!(i >= 0 &
              tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
              p.IsValid() &&
              p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
              p.vData.size() &&
              (mainImport = CCrossChainImport(p.vData[0])).IsValid()))
        {
            LogPrint("reservedeposits", "%s: malformed import transaction %s attempting to spend reserve deposit %s\n", __func__, EncodeHexTx(tx).c_str(), tx.vin[nIn].ToString().c_str());
            return eval->Error(std::string(__func__) + ": malformed import transaction attempting to spend reserve deposit");
        }
    }
    else
    {
        mainImport = authorizingImport;
    }

    CCrossChainExport ccxSource;
    CPBaaSNotarization importNotarization;
    int32_t sysCCIOut, importNotarizationOut, evidenceOutStart, evidenceOutEnd;
    std::vector<CReserveTransfer> reserveTransfers;

    if (mainImport.GetImportInfo(tx,
                                 chainActive.Height(),
                                 i,
                                 ccxSource,
                                 authorizingImport,
                                 sysCCIOut,
                                 importNotarization,
                                 importNotarizationOut,
                                 evidenceOutStart,
                                 evidenceOutEnd,
                                 reserveTransfers))
    {
        // TODO: HARDENING - confirm that all checks are complete
        // now, check all inputs of the transaction, and if we are the first in the array spent from
        // deposits controlled by this currency, be sure that all input is accounted for by valid reserves out
        // and/or gateway deposits, and/or change

        LOCK(mempool.cs);

        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);

        uint32_t nHeight = chainActive.Height();

        CCurrencyValueMap totalDeposits;

        for (int i = 0; i < tx.vin.size(); i++)
        {
            if (tx.vin[i].prevout.hash.IsNull())
            {
                continue;
            }
            const CCoins *pCoins = view.AccessCoins(tx.vin[i].prevout.hash);

            COptCCParams p;

            // if we can't find the output we are spending, we fail
            if (pCoins->vout.size() <= tx.vin[i].prevout.n)
            {
                return eval->Error(std::string(__func__) + ": cannot get output being spent by input (" + tx.vin[i].ToString() + ") from current view");
            }

            CReserveDeposit oneBeingSpent;

            if (pCoins->vout[tx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_RESERVE_DEPOSIT)
            {
                if (!(p.vData.size() &&
                      (oneBeingSpent = CReserveDeposit(p.vData[0])).IsValid()))
                {
                    return eval->Error(std::string(__func__) + ": reserve deposit being spent by input (" + tx.vin[i].ToString() + ") is invalid in view");
                }
            }

            if (oneBeingSpent.IsValid() &&
                oneBeingSpent.controllingCurrencyID == sourceRD.controllingCurrencyID)
            {
                // if we are not first, this will have to have passed by the first input to have gotten here
                if (i < nIn)
                {
                    return true;
                }
                else
                {
                    totalDeposits += oneBeingSpent.reserveValues;
                }
            }
        }

        // now, determine how much is used and how much change is left
        CCoinbaseCurrencyState checkState = importNotarization.currencyState;
        CCoinbaseCurrencyState newCurState;

        checkState.RevertReservesAndSupply();
        CReserveTransactionDescriptor rtxd;

        CCurrencyDefinition sourceSysDef = ConnectedChains.GetCachedCurrency(ccxSource.sourceSystemID);
        CCurrencyDefinition destSysDef = ConnectedChains.GetCachedCurrency(ccxSource.destSystemID);
        CCurrencyDefinition destCurDef = ConnectedChains.GetCachedCurrency(ccxSource.destCurrencyID);

        if (!(sourceSysDef.IsValid() && destSysDef.IsValid() && destCurDef.IsValid()))
        {
            return eval->Error(std::string(__func__) + ": invalid currencies in export: " + ccxSource.ToUniValue().write(1,2));
        }

        std::vector<CTxOut> vOutputs;
        CCurrencyValueMap importedCurrency, gatewayCurrencyUsed, spentCurrencyOut;

        if (!rtxd.AddReserveTransferImportOutputs(sourceSysDef,
                                                  destSysDef,
                                                  destCurDef,
                                                  checkState,
                                                  reserveTransfers,
                                                  nHeight,
                                                  vOutputs,
                                                  importedCurrency,
                                                  gatewayCurrencyUsed,
                                                  spentCurrencyOut,
                                                  &newCurState))
        {
            return eval->Error(std::string(__func__) + ": invalid import transaction");
        }

        // get outputs total amount to this reserve deposit
        CCurrencyValueMap reserveDepositChange;
        for (int i = 0; i < tx.vout.size(); i++)
        {
            COptCCParams p;
            CReserveDeposit rd;
            if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_RESERVE_DEPOSIT &&
                p.vData.size() &&
                (rd = CReserveDeposit(p.vData[0])).IsValid() &&
                rd.controllingCurrencyID == sourceRD.controllingCurrencyID)
            {
                reserveDepositChange += rd.reserveValues;
            }
        }

        if (gatewaySource)
        {
            if (totalDeposits != (gatewayCurrencyUsed + reserveDepositChange))
            {
                LogPrintf("%s: invalid use of gateway reserve deposits for currency: %s\n", __func__, destCurDef.GetID().GetHex().c_str());
                // TODO: HARDENING - uncomment the following line and return false, when it is confirmed that
                // this passes in all intended cases.
                //return false;
            }
        }
        else
        {
            CCurrencyValueMap currenciesIn(newCurState.currencies, newCurState.reserveIn);
            if (newCurState.primaryCurrencyOut)
            {
                currenciesIn.valueMap[newCurState.GetID()] = newCurState.primaryCurrencyOut;
            }
            if ((totalDeposits + currenciesIn) != (reserveDepositChange + spentCurrencyOut))
            {
                LogPrintf("%s: invalid use of reserve deposits for currency: %s\n", __func__, destCurDef.GetID().GetHex().c_str());
                // TODO: HARDENING - uncomment the following line and return false, when it is confirmed that
                // this passes in all intended cases.
                //return false;
            }
        }

        return true;
    }

    return eval->Error(std::string(__func__) + ": invalid reserve deposit spend");
}
bool IsReserveDepositInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateCurrencyState(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsCurrencyStateInput(const CScript &scriptSig)
{
    return true;
}

// used to convert a fractional reserve currency into its reserve and back 
bool ValidateReserveExchange(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveExchangeInput(const CScript &scriptSig)
{
    return true;
}


/*
 * Verifies that the input objects match the hashes and returns the transaction.
 * 
 * If the opRetTx has the op ret, this calculates based on the actual transaction and
 * validates the hashes. If the opRetTx does not have the opRet itself, this validates
 * by ensuring that all objects are present on this chain, composing the opRet, and
 * ensuring that the transaction then hashes to the correct txid.
 * 
 */
bool ValidateOpretProof(CScript &opRet, COpRetProof &orProof)
{
    // enumerate through the objects and validate that they are objects of the expected type that hash
    // to the value expected. return true if so
    return true;
}

int8_t ObjTypeCode(const CBlockHeaderProof &obj)
{
    return CHAINOBJ_HEADER;
}

int8_t ObjTypeCode(const uint256 &obj)
{
    return CHAINOBJ_PROOF_ROOT;
}

int8_t ObjTypeCode(const CPartialTransactionProof &obj)
{
    return CHAINOBJ_TRANSACTION_PROOF;
}

int8_t ObjTypeCode(const CBlockHeaderAndProof &obj)
{
    return CHAINOBJ_HEADER_REF;
}

int8_t ObjTypeCode(const CPriorBlocksCommitment &obj)
{
    return CHAINOBJ_PRIORBLOCKS;
}

int8_t ObjTypeCode(const CReserveTransfer &obj)
{
    return CHAINOBJ_RESERVETRANSFER;
}

int8_t ObjTypeCode(const CCrossChainProof &obj)
{
    return CHAINOBJ_CROSSCHAINPROOF;
}

int8_t ObjTypeCode(const CCompositeChainObject &obj)
{
    return CHAINOBJ_COMPOSITEOBJECT;
}

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(const std::vector<CBaseChainObject *> &objPtrs)
{
    CScript vData;
    CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
    s << (int32_t)OPRETTYPE_OBJECTARR;
    bool error = false;

    for (auto pobj : objPtrs)
    {
        try
        {
            if (!DehydrateChainObject(s, pobj))
            {
                error = true;
                break;
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            error = true;
            break;
        }
    }

    //std::vector<unsigned char> schars(s.begin(), s.begin() + 200);
    //printf("stream vector chars: %s\n", HexBytes(&schars[0], schars.size()).c_str());

    std::vector<unsigned char> vch(s.begin(), s.end());
    return error ? CScript() : CScript() << OP_RETURN << vch;
}

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora)
{
    for (auto pobj : ora)
    {
        switch(pobj->objectType)
        {
            case CHAINOBJ_HEADER:
            {
                delete (CChainObject<CBlockHeaderAndProof> *)pobj;
                break;
            }

            case CHAINOBJ_TRANSACTION_PROOF:
            {
                delete (CChainObject<CPartialTransactionProof> *)pobj;
                break;
            }

            case CHAINOBJ_PROOF_ROOT:
            {
                delete (CChainObject<uint256> *)pobj;
                break;
            }

            case CHAINOBJ_HEADER_REF:
            {
                delete (CChainObject<CBlockHeaderProof> *)pobj;
                break;
            }

            case CHAINOBJ_PRIORBLOCKS:
            {
                delete (CChainObject<CPriorBlocksCommitment> *)pobj;
                break;
            }

            case CHAINOBJ_RESERVETRANSFER:
            {
                delete (CChainObject<CReserveTransfer> *)pobj;
                break;
            }

            case CHAINOBJ_CROSSCHAINPROOF:
            {
                delete (CChainObject<CCrossChainProof> *)pobj;
                break;
            }

            case CHAINOBJ_COMPOSITEOBJECT:
            {
                delete (CChainObject<CCompositeChainObject> *)pobj;
                break;
            }

            case CHAINOBJ_NOTARYSIGNATURE:
            {
                delete (CChainObject<CNotaryEvidence> *)pobj;
                break;
            }

            default:
            {
                printf("ERROR: invalid object type (%u), likely corrupt pointer %p\n", pobj->objectType, pobj);
                printf("generate code that won't be optimized away %s\n", CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}), std::vector<CAmount>({200000000})).ToUniValue().write(1,2).c_str());
                printf("This is here to generate enough code for a good break point system chain name: %s\n", ConnectedChains.ThisChain().name.c_str());
                
                delete pobj;
            }
        }
    }
    ora.clear();
}

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript)
{
    std::vector<unsigned char> vch;
    std::vector<CBaseChainObject *> vRet;
    if (opRetScript.IsOpReturn() && GetOpReturnData(opRetScript, vch) && vch.size() > 0)
    {
        CDataStream s = CDataStream(vch, SER_NETWORK, PROTOCOL_VERSION);

        int32_t opRetType;

        try
        {
            s >> opRetType;
            if (opRetType == OPRETTYPE_OBJECTARR)
            {
                CBaseChainObject *pobj;
                while (!s.empty() && (pobj = RehydrateChainObject(s)))
                {
                    vRet.push_back(pobj);
                }
                if (!s.empty())
                {
                    printf("failed to load all objects in opret");
                    DeleteOpRetObjects(vRet);
                    vRet.clear();
                }
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            DeleteOpRetObjects(vRet);
            vRet.clear();
        }
    }
    return vRet;
}

CCrossChainExport::CCrossChainExport(const CScript &script)
{
    COptCCParams p;
    if (script.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_CROSSCHAIN_EXPORT)
    {
        FromVector(p.vData[0], *this);
    }
}

CCrossChainExport::CCrossChainExport(const UniValue &obj) :
    nVersion(CCrossChainExport::VERSION_CURRENT),
    sourceHeightStart(0),
    sourceHeightEnd(0),
    firstInput(0),
    numInputs(0)
{
    nVersion = uni_get_int(find_value(obj, "version"));
    flags = uni_get_int(find_value(obj, "flags"));
    if (!this->IsSupplemental())
    {
        sourceHeightStart = uni_get_int64(find_value(obj, "sourceheightstart"));
        sourceHeightEnd = uni_get_int64(find_value(obj, "sourceheightend"));
        sourceSystemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "sourcesystemid"))));
        destSystemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "destinationsystemid"))));
        destCurrencyID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "destinationcurrencyid"))));
        firstInput = uni_get_int(find_value(obj, "firstinput"));
        numInputs = uni_get_int(find_value(obj, "numinputs"));
        totalAmounts = CCurrencyValueMap(find_value(obj, "totalamounts"));
        totalFees = CCurrencyValueMap(find_value(obj, "totalfees"));
        hashReserveTransfers = uint256S(uni_get_str(find_value(obj, "hashtransfers")));
        totalBurned = CCurrencyValueMap(find_value(obj, "totalburned"));
        exporter = DestinationToTransferDestination(DecodeDestination(uni_get_str(find_value(obj, "rewardaddress"))));
    }

    UniValue transfers = find_value(obj, "transfers");
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
}

CCrossChainImport::CCrossChainImport(const UniValue &obj) :
    nVersion(CCrossChainImport::VERSION_CURRENT),
    flags(0),
    sourceSystemHeight(0),
    exportTxOutNum(-1),
    numOutputs(0)
{
    nVersion = uni_get_int(find_value(obj, "version"));
    flags = uni_get_int(find_value(obj, "flags"));

    sourceSystemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "sourcesystemid"))));
    sourceSystemHeight = uni_get_int64(find_value(obj, "sourceheight"));
    importCurrencyID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "importcurrencyid"))));
    importValue = CCurrencyValueMap(find_value(obj, "valuein"));
    totalReserveOutMap = CCurrencyValueMap(find_value(obj, "tokensout"));
    numOutputs = uni_get_int64(find_value(obj, "numoutputs"));
    hashReserveTransfers = uint256S(uni_get_str(find_value(obj, "hashtransfers")));
    exportTxId = uint256S(uni_get_str(find_value(obj, "exporttxid")));
    exportTxOutNum = uni_get_int(find_value(obj, "exporttxout"), -1);
}

CCrossChainExport::CCrossChainExport(const CTransaction &tx, int32_t *pCCXOutputNum)
{
    int32_t _ccxOutputNum = 0;
    int32_t &ccxOutputNum = pCCXOutputNum ? *pCCXOutputNum : _ccxOutputNum;
    
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_EXPORT)
        {
            FromVector(p.vData[0], *this);
            ccxOutputNum = i;
            break;
        }
    }
}

CCurrencyDefinition::CCurrencyDefinition(const CScript &scriptPubKey)
{
    nVersion = PBAAS_VERSION_INVALID;
    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
    {
        if (p.evalCode == EVAL_CURRENCY_DEFINITION)
        {
            FromVector(p.vData[0], *this);
        }
    }
}

std::vector<CCurrencyDefinition> CCurrencyDefinition::GetCurrencyDefinitions(const CTransaction &tx)
{
    std::vector<CCurrencyDefinition> retVal;
    for (auto &out : tx.vout)
    {
        CCurrencyDefinition oneCur = CCurrencyDefinition(out.scriptPubKey);
        if (oneCur.IsValid())
        {
            retVal.push_back(oneCur);
        }
    }
    return retVal;
}

#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
extern uint64_t ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_TIMEUNLOCKFROM, ASSETCHAINS_TIMEUNLOCKTO;
extern int64_t ASSETCHAINS_SUPPLY, ASSETCHAINS_REWARD[3], ASSETCHAINS_DECAY[3], ASSETCHAINS_HALVING[3], ASSETCHAINS_ENDSUBSIDY[3], ASSETCHAINS_ERAOPTIONS[3];
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK, ASSETCHAINS_LWMAPOS;
extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA;
extern std::string VERUS_CHAINNAME;
extern uint160 VERUS_CHAINID;

// ensures that the currency definition is valid and that there are no other definitions of the same name
// that have been confirmed.
bool ValidateCurrencyDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    return eval->Error("cannot spend currency definition output in current protocol");
}

bool PrecheckCurrencyDefinition(const CTransaction &spendingTx, int32_t outNum, CValidationState &state, uint32_t height)
{
    if (IsVerusMainnetActive() &&
        CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return true;
    }

    // ensure that the currency definition follows all rules of currency definition, meaning:
    // 1) it is defined by an identity that controls the currency for the first time
    // 2) it is imported by another system that controls the currency for the first time
    // 3) it is defined in block 1 as part of a PBaaS chain launch, where it was required
    //
    // Further conditions, such as valid start block, or flag combinations apply, and as a special case,
    // if the currency is the ETH bridge and this is the Verus (or Rinkeby wrt VerusTest) blockchain, 
    // it will assert itself as the notary chain of this network and use the gateway config information
    // to locate the RPC of the Alan (Monty Python's gatekeeper) bridge.
    //

    // first, let's figure out what kind of currency definition this is
    // valid definitions:
    // 1. Currency defined on this system by an ID on this system
    // 2. Imported currency controlled by or launched from another system defined on block 1's coinbase
    // 3. Imported currency from another system on an import from a system, which controls the imported currency
    bool isBlockOneDefinition = spendingTx.IsCoinBase() && height == 1;
    bool isImportDefinition = false;

    CIdentity oldIdentity;
    CCrossChainImport cci, sysCCI;
    CPBaaSNotarization pbn;
    int sysCCIOut = -1, notarizationOut = -1, eOutStart = -1, eOutEnd = -1;
    CCrossChainExport ccx;
    std::vector<CReserveTransfer> transfers;
    CTransaction idTx;
    uint256 blkHash;

    CCurrencyDefinition newCurrency;
    COptCCParams currencyOptParams;
    if (!(spendingTx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(currencyOptParams) &&
         currencyOptParams.IsValid() &&
         currencyOptParams.evalCode == EVAL_CURRENCY_DEFINITION &&
         currencyOptParams.vData.size() > 1 &&
         (newCurrency = CCurrencyDefinition(currencyOptParams.vData[0])).IsValid()))
    {
        return state.Error("Invalid currency definition in output");
    }

    if (!isBlockOneDefinition)
    {
        // if this is an imported currency definition,
        // just be sure that it is part of an import and can be imported from the source
        // if so, it is fine
        for (int i = 0; i < spendingTx.vout.size(); i++)
        {
            const CTxOut &oneOut = spendingTx.vout[i];
            COptCCParams p;
            if (i != outNum &&
                oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() > 1 &&
                (cci = CCrossChainImport(p.vData[0])).IsValid())
            {
                if (cci.sourceSystemID != ASSETCHAINS_CHAINID &&
                    cci.GetImportInfo(spendingTx, height, i, ccx, sysCCI, sysCCIOut, pbn, notarizationOut, eOutStart, eOutEnd, transfers) &&
                    outNum <= eOutEnd && 
                    outNum >= eOutEnd)
                {
                    // TODO: HARDENING ensure that this currency is valid as an import from the source 
                    // system to this chain.
                    //
                    isImportDefinition = true;
                    break;
                }
            }
        }

        // in this case, it must either spend an identity or be on an import transaction
        // that has a reserve transfer which imports the currency
        if (!isImportDefinition)
        {
            LOCK(mempool.cs);
            for (auto &input : spendingTx.vin)
            {
                COptCCParams p;
                // first time through may be null
                if ((!input.prevout.hash.IsNull() && input.prevout.hash == idTx.GetHash()) || myGetTransaction(input.prevout.hash, idTx, blkHash))
                {
                    if (idTx.vout[input.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        p.evalCode == EVAL_IDENTITY_PRIMARY &&
                        p.vData.size() > 1 &&
                        (oldIdentity = CIdentity(p.vData[0])).IsValid())
                    {
                        break;
                    }
                }
            }
        }
    }

    COptCCParams p;

    if (!(isBlockOneDefinition || isImportDefinition))
    {
        if (!oldIdentity.IsValid())
        {
            return state.Error("No valid identity found for currency definition");
        }
        
        if (oldIdentity.HasActiveCurrency())
        {
            return state.Error("Identity already has used its one-time ability to define a currency");
        }
    }

    return true;
}

bool PrecheckReserveTransfer(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // do a basic sanity check that this reserve transfer's values are consistent
    COptCCParams p;
    CReserveTransfer rt;

    if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_RESERVE_TRANSFER &&
        p.vData.size() &&
        (rt = CReserveTransfer(p.vData[0])).IsValid() &&
        rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID] == tx.vout[outNum].nValue)
    {
        uint160 systemDestID, importCurrencyID;
        CCurrencyDefinition systemDest, importCurrencyDef;
        CPBaaSNotarization startingNotarization;

        if (rt.IsImportToSource())
        {
            importCurrencyID = rt.FirstCurrency();
        }
        else
        {
            importCurrencyID = rt.destCurrencyID;
        }

        importCurrencyDef = ConnectedChains.GetCachedCurrency(importCurrencyID);

        if (!importCurrencyDef.IsValid())
        {
            // the only case this is ok is if we are part of a currency definition and this is to a new currency
            // if that is the case, importCurrencyDef will always be invalid
            if (!importCurrencyDef.IsValid())
            {
                std::vector<CCurrencyDefinition> newCurrencies = CCurrencyDefinition::GetCurrencyDefinitions(tx);
                if (newCurrencies.size())
                {
                    for (auto oneCurrency : newCurrencies)
                    {
                        if (oneCurrency.GetID() == importCurrencyID)
                        {
                            CPBaaSNotarization oneNotarization;
                            CCurrencyDefinition tempCurDef;
                            importCurrencyDef = oneCurrency;
                            systemDestID = importCurrencyDef.IsGateway() ? importCurrencyDef.gatewayID : importCurrencyDef.systemID;
                            // we need to get the first notarization and possibly systemDest currency here as well
                            for (auto oneOut : tx.vout)
                            {
                                if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                                    p.IsValid())
                                {
                                    if ((p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                                        p.vData.size() &&
                                        (oneNotarization = CPBaaSNotarization(p.vData[0])).IsValid() &&
                                        oneNotarization.currencyID == importCurrencyID)
                                    {
                                        startingNotarization = oneNotarization;
                                    }
                                    else if ((p.evalCode == EVAL_CURRENCY_DEFINITION) &&
                                             p.vData.size() &&
                                             (tempCurDef = CCurrencyDefinition(p.vData[0])).IsValid() &&
                                             tempCurDef.GetID() == systemDestID)
                                    {
                                        systemDest = tempCurDef;
                                    }
                                }
                                if (oneNotarization.IsValid() &&
                                    systemDest.IsValid())
                                {
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }

        CChainNotarizationData cnd;
        if (!(importCurrencyDef.IsValid() &&
             (startingNotarization.IsValid() ||
              (GetNotarizationData(importCurrencyDef.GetID(), cnd) &&
               cnd.IsConfirmed() &&
               (startingNotarization = cnd.vtx[cnd.lastConfirmed].second).IsValid()))))
        {
            // the only case this is ok is if we are part of a currency definition and this is to a new currency
            // if that is the case, importCurrencyDef will always be invalid
            if (!importCurrencyDef.IsValid())
            {
                LogPrintf("%s: Invalid currency in reserve transfer %s\n", __func__, rt.ToUniValue().write(1,2).c_str());
                return state.Error("Invalid currency in reserve transfer " + rt.ToUniValue().write(1,2));
            }
            else
            {
                LogPrintf("%s: Valid notarization required and not found for import currency of reserve transfer %s\n", __func__, rt.ToUniValue().write(1,2).c_str());
                return state.Error("Valid notarization required and not found for import currency of reserve transfer " + rt.ToUniValue().write(1,2));
            }
        }

        if (!systemDest.IsValid())
        {
            systemDestID = importCurrencyDef.IsGateway() ? importCurrencyDef.gatewayID : importCurrencyDef.systemID;
            systemDest = systemDestID == importCurrencyID ? importCurrencyDef : ConnectedChains.GetCachedCurrency(systemDestID);
        }

        if (!systemDest.IsValid())
        {
            LogPrintf("%s: Invalid currency system in reserve transfer %s\n", __func__, rt.ToUniValue().write(1,2).c_str());
            return state.Error("Invalid currency system in reserve transfer " + rt.ToUniValue().write(1,2));
        }

        CReserveTransactionDescriptor rtxd;
        CCoinbaseCurrencyState dummyState;
        CPBaaSNotarization nextNotarization;
        std::vector<CTxOut> vOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsIn, spentCurrencyOut;
        CCurrencyValueMap newPreConversionReservesIn = rt.TotalCurrencyOut();

        if (importCurrencyDef.IsFractional() &&
            !(startingNotarization.IsLaunchCleared() && !startingNotarization.currencyState.IsLaunchCompleteMarker()))
        {
            // normalize prices on the way in to prevent overflows on first pass
            std::vector<int64_t> newReservesVector = newPreConversionReservesIn.AsCurrencyVector(startingNotarization.currencyState.currencies);
            dummyState.reserves = dummyState.AddVectors(dummyState.reserves, newReservesVector);
            startingNotarization.currencyState.conversionPrice = dummyState.PricesInReserve();
        }

        if (rtxd.AddReserveTransferImportOutputs(ConnectedChains.ThisChain(), 
                                                 systemDest, 
                                                 importCurrencyDef, 
                                                 startingNotarization.currencyState,
                                                 std::vector<CReserveTransfer>({rt}), 
                                                 height,
                                                 vOutputs,
                                                 importedCurrency, 
                                                 gatewayDepositsIn, 
                                                 spentCurrencyOut,
                                                 &dummyState))
        {
            return true;
        }
    }
    LogPrintf("%s: Invalid reserve transfer %s\n", __func__, rt.ToUniValue().write(1,2).c_str());
    return false;
}

CCurrencyValueMap CCrossChainExport::CalculateExportFee(const CCurrencyValueMap &fees, int numIn)
{
    CCurrencyValueMap retVal;
    int maxFeeCalc = numIn;

    if (maxFeeCalc > MAX_FEE_INPUTS)
    {
        maxFeeCalc = MAX_FEE_INPUTS;
    }
    static const arith_uint256 satoshis(100000000);

    arith_uint256 ratio(50000000 + ((25000000 / maxFeeCalc) * (numIn - 1)));

    for (auto &feePair : fees.valueMap)
    {
        retVal.valueMap[feePair.first] = (((arith_uint256(feePair.second) * ratio)) / satoshis).GetLow64();
    }
    return retVal.CanonicalMap();
}

CAmount CCrossChainExport::CalculateExportFeeRaw(CAmount fee, int numIn)
{
    int maxFeeCalc = std::min((int)MAX_FEE_INPUTS, std::max(1, numIn));
    static const arith_uint256 satoshis(100000000);

    arith_uint256 ratio(50000000 + ((25000000 / MAX_FEE_INPUTS) * (maxFeeCalc - 1)));

    return (((arith_uint256(fee) * ratio)) / satoshis).GetLow64();
}

CAmount CCrossChainExport::ExportReward(int64_t exportFee)
{
    int64_t individualExportFee = ((arith_uint256(exportFee) * 10000000) / SATOSHIDEN).GetLow64();
    if (individualExportFee < MIN_FEES_BEFORE_FEEPOOL)
    {
        individualExportFee = exportFee > MIN_FEES_BEFORE_FEEPOOL ? MIN_FEES_BEFORE_FEEPOOL : exportFee;
    }
    return individualExportFee;
}

CCurrencyValueMap CCrossChainExport::CalculateExportFee() const
{
    return CalculateExportFee(totalFees, numInputs);
}

CCurrencyValueMap CCrossChainExport::CalculateImportFee() const
{
    CCurrencyValueMap retVal;

    for (auto &feePair : CalculateExportFee().valueMap)
    {
        CAmount feeAmount = feePair.second;
        auto it = totalFees.valueMap.find(feePair.first);
        retVal.valueMap[feePair.first] = (it != totalFees.valueMap.end() ? it->second : 0) - feeAmount;
    }
    return retVal;
}

bool CEthGateway::ValidateDestination(const std::string &destination) const
{
    // just returns true if it looks like a non-NULL ETH address
    return (destination.substr(0,2) == "0x" && 
            destination.length() == 42 && 
            IsHex(destination.substr(2,40)) && 
            !uint160(ParseHex(destination.substr(2,64))).IsNull());
}

CTransferDestination CEthGateway::ToTransferDestination(const std::string &destination) const
{
    // just returns true if it looks like a non-NULL ETH address
    uint160 retVal;
    if (destination.substr(0,2) == "0x" && 
            destination.length() == 42 && 
            IsHex(destination.substr(2,40)) && 
            !(retVal = uint160(ParseHex(destination.substr(2,64)))).IsNull())
    {
        return CTransferDestination(CTransferDestination::FLAG_DEST_GATEWAY + CTransferDestination::DEST_RAW,
                                    std::vector<unsigned char>(retVal.begin(), retVal.end()));
    }
    return CTransferDestination();
}

// hard coded ETH gateway currency, "veth" for Verus chain. should be updated to work with PBaaS chains
std::set<uint160> CEthGateway::FeeCurrencies() const
{
    std::set<uint160> retVal;
    retVal.insert(CCrossChainRPCData::GetID("veth@"));
    return retVal;
}

uint160 CEthGateway::GatewayID() const
{
    return CCrossChainRPCData::GetID("veth@");
}

bool CConnectedChains::RemoveMergedBlock(uint160 chainID)
{
    bool retval = false;
    LOCK(cs_mergemining);

    //printf("RemoveMergedBlock ID: %s\n", chainID.GetHex().c_str());

    auto chainIt = mergeMinedChains.find(chainID);
    if (chainIt != mergeMinedChains.end())
    {
        arith_uint256 target;
        target.SetCompact(chainIt->second.block.nBits);
        std::multimap<arith_uint256, CPBaaSMergeMinedChainData *>::iterator removeIt;
        std::multimap<arith_uint256, CPBaaSMergeMinedChainData *>::iterator nextIt = mergeMinedTargets.begin();
        for (removeIt = nextIt; removeIt != mergeMinedTargets.end(); removeIt = nextIt)
        {
            nextIt++;
            // make sure we don't just match by target
            if (removeIt->second->GetID() == chainID)
            {
                mergeMinedTargets.erase(removeIt);
            }
        }
        mergeMinedChains.erase(chainID);
        dirty = retval = true;

        // if we get to 0, give the thread a kick to stop waiting for mining
        //if (!mergeMinedChains.size())
        //{
        //    sem_submitthread.post();
        //}
    }
    return retval;
}

// remove merge mined chains added and not updated since a specific time
void CConnectedChains::PruneOldChains(uint32_t pruneBefore)
{
    vector<uint160> toRemove;

    LOCK(cs_mergemining);
    for (auto blkData : mergeMinedChains)
    {
        if (blkData.second.block.nTime < pruneBefore)
        {
            toRemove.push_back(blkData.first);
        }
    }

    for (auto id : toRemove)
    {
        //printf("Pruning chainID: %s\n", id.GetHex().c_str());
        RemoveMergedBlock(id);
    }
}

// adds or updates merge mined blocks
// returns false if failed to add
bool CConnectedChains::AddMergedBlock(CPBaaSMergeMinedChainData &blkData)
{
    // determine if we should replace one or add to the merge mine vector
    {
        LOCK(cs_mergemining);

        arith_uint256 target;
        uint160 cID = blkData.GetID();
        auto it = mergeMinedChains.find(cID);
        if (it != mergeMinedChains.end())
        {
            RemoveMergedBlock(cID);             // remove it if already there
        }
        target.SetCompact(blkData.block.nBits);

        mergeMinedChains.insert(make_pair(cID, blkData));
        mergeMinedTargets.insert(make_pair(target, &(mergeMinedChains[cID])));
        dirty = true;
    }
    return true;
}

bool CInputDescriptor::operator<(const CInputDescriptor &op) const
{
    arith_uint256 left = UintToArith256(txIn.prevout.hash);
    arith_uint256 right = UintToArith256(op.txIn.prevout.hash);
    return left < right ? true : left > right ? false : txIn.prevout.n < op.txIn.prevout.n ? true : false;
}


bool CConnectedChains::GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData)
{
    {
        LOCK(cs_mergemining);
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            rpcChainData = (CRPCChainData)chainIt->second;
            return true;
        }
        return false;
    }
}

// this returns a pointer to the data without copy and assumes the lock is held
CPBaaSMergeMinedChainData *CConnectedChains::GetChainInfo(uint160 chainID)
{
    {
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            return &chainIt->second;
        }
        return NULL;
    }
}

void CConnectedChains::QueueNewBlockHeader(CBlockHeader &bh)
{
    //printf("QueueNewBlockHeader %s\n", bh.GetHash().GetHex().c_str());
    {
        LOCK(cs_mergemining);

        qualifiedHeaders[UintToArith256(bh.GetHash())] = bh;
    }
    sem_submitthread.post();
}

void CConnectedChains::CheckImports()
{
    sem_submitthread.post();
}

// get the latest block header and submit one block at a time, returning after there are no more
// matching blocks to be found
vector<pair<string, UniValue>> CConnectedChains::SubmitQualifiedBlocks()
{
    std::set<uint160> inHeader;
    bool submissionFound;
    CPBaaSMergeMinedChainData chainData;
    vector<pair<string, UniValue>>  results;

    CBlockHeader bh;
    arith_uint256 lastHash;
    CPBaaSBlockHeader pbh;

    do
    {
        submissionFound = false;
        {
            LOCK(cs_mergemining);
            // attempt to submit with the lowest hash answers first to increase the likelihood of submitting
            // common, merge mined headers for notarization, drop out on any submission
            for (auto headerIt = qualifiedHeaders.begin(); !submissionFound && headerIt != qualifiedHeaders.end(); headerIt = qualifiedHeaders.begin())
            {
                // add the PBaaS chain ids from this header to a set for search
                for (uint32_t i = 0; headerIt->second.GetPBaaSHeader(pbh, i); i++)
                {
                    inHeader.insert(pbh.chainID);
                }

                uint160 chainID;
                // now look through all targets that are equal to or above the hash of this header
                for (auto chainIt = mergeMinedTargets.lower_bound(headerIt->first); !submissionFound && chainIt != mergeMinedTargets.end(); chainIt++)
                {
                    chainID = chainIt->second->GetID();
                    if (inHeader.count(chainID))
                    {
                        // first, check that the winning header matches the block that is there
                        CPBaaSPreHeader preHeader(chainIt->second->block);
                        preHeader.SetBlockData(headerIt->second);

                        // check if the block header matches the block's specific data, only then can we create a submission from this block
                        if (headerIt->second.CheckNonCanonicalData(chainID))
                        {
                            // save block as is, remove the block from merged headers, replace header, and submit
                            chainData = *chainIt->second;

                            *(CBlockHeader *)&chainData.block = headerIt->second;

                            submissionFound = true;
                        }
                        //else // not an error condition. code is here for debugging
                        //{
                        //    printf("Mismatch in non-canonical data for chain %s\n", chainIt->second->chainDefinition.name.c_str());
                        //}
                    }
                    //else // not an error condition. code is here for debugging
                    //{
                    //    printf("Not found in header %s\n", chainIt->second->chainDefinition.name.c_str());
                    //}
                }

                // if this header matched no block, discard and move to the next, otherwise, we'll drop through
                if (submissionFound)
                {
                    // once it is going to be submitted, remove block from this chain until a new one is added again
                    RemoveMergedBlock(chainID);
                    break;
                }
                else
                {
                    qualifiedHeaders.erase(headerIt);
                }
            }
        }
        if (submissionFound)
        {
            // submit one block and loop again. this approach allows multiple threads
            // to collectively empty the submission queue, mitigating the impact of
            // any one stalled daemon
            UniValue submitParams(UniValue::VARR);
            submitParams.push_back(EncodeHexBlk(chainData.block));
            UniValue result, error;
            try
            {
                result = RPCCall("submitblock", submitParams, chainData.rpcUserPass, chainData.rpcPort, chainData.rpcHost);
                result = find_value(result, "result");
                error = find_value(result, "error");
            }
            catch (exception e)
            {
                result = UniValue(e.what());
            }
            results.push_back(make_pair(chainData.chainDefinition.name, result));
            if (result.isStr() || !error.isNull())
            {
                printf("Error submitting block to %s chain: %s\n", chainData.chainDefinition.name.c_str(), result.isStr() ? result.get_str().c_str() : error.get_str().c_str());
            }
            else
            {
                printf("Successfully submitted block to %s chain\n", chainData.chainDefinition.name.c_str());
            }
        }
    } while (submissionFound);
    return results;
}

// add all merge mined chain PBaaS headers into the blockheader and return the easiest nBits target in the header
uint32_t CConnectedChains::CombineBlocks(CBlockHeader &bh)
{
    vector<uint160> inHeader;
    vector<UniValue> toCombine;
    arith_uint256 blkHash = UintToArith256(bh.GetHash());
    arith_uint256 target(0);
    
    CPBaaSBlockHeader pbh;

    {
        LOCK(cs_mergemining);

        CPBaaSSolutionDescriptor descr = CVerusSolutionVector::solutionTools.GetDescriptor(bh.nSolution);

        for (uint32_t i = 0; i < descr.numPBaaSHeaders; i++)
        {
            if (bh.GetPBaaSHeader(pbh, i))
            {
                inHeader.push_back(pbh.chainID);
            }
        }

        // loop through the existing PBaaS chain ids in the header
        // remove any that are not either this Chain ID or in our local collection and then add all that are present
        for (uint32_t i = 0; i < inHeader.size(); i++)
        {
            auto it = mergeMinedChains.find(inHeader[i]);
            if (inHeader[i] != ASSETCHAINS_CHAINID && (it == mergeMinedChains.end()))
            {
                bh.DeletePBaaSHeader(i);
            }
        }

        for (auto chain : mergeMinedChains)
        {
            // get the native PBaaS header for each chain and put it into the
            // header we are given
            // it must have itself in as a PBaaS header
            uint160 cid = chain.second.GetID();
            if (chain.second.block.GetPBaaSHeader(pbh, cid) != -1)
            {
                if (!bh.AddUpdatePBaaSHeader(pbh))
                {
                    LogPrintf("Failure to add PBaaS block header for %s chain\n", chain.second.chainDefinition.name.c_str());
                    break;
                }
                else
                {
                    arith_uint256 t;
                    t.SetCompact(chain.second.block.nBits);
                    if (t > target)
                    {
                        target = t;
                    }
                }
            }
            else
            {
                LogPrintf("Merge mined block for %s does not contain PBaaS information\n", chain.second.chainDefinition.name.c_str());
            }
        }
        dirty = false;
    }

    return target.GetCompact();
}

bool CConnectedChains::IsVerusPBaaSAvailable()
{
    uint160 parent = VERUS_CHAINID;
    return IsNotaryAvailable() && 
           ((_IsVerusActive() && FirstNotaryChain().chainDefinition.GetID() == CIdentity::GetID("veth", parent)) ||
            FirstNotaryChain().chainDefinition.GetID() == VERUS_CHAINID);
}

extern string PBAAS_HOST, PBAAS_USERPASS;
extern int32_t PBAAS_PORT;
bool CConnectedChains::CheckVerusPBaaSAvailable(UniValue &chainInfoUni, UniValue &chainDefUni)
{
    if (chainInfoUni.isObject() && chainDefUni.isObject())
    {
        // TODO: HARDENING - ensure we confirm the correct PBaaS version
        // and ensure that the chainDef is correct as well

        UniValue uniVer = find_value(chainInfoUni, "VRSCversion");
        if (uniVer.isStr())
        {
            LOCK(cs_mergemining);
            CCurrencyDefinition chainDef(chainDefUni);
            if (chainDef.IsValid())
            {
                /*printf("%s: \n%s\nfirstnotary: %s\ngetid: %s\n", __func__, 
                    chainDef.ToUniValue().write(1,2).c_str(), 
                    EncodeDestination(CIdentityID(notarySystems.begin()->first)).c_str(), 
                    EncodeDestination(CIdentityID(chainDef.GetID())).c_str());
                */
                if (notarySystems.count(chainDef.GetID()))
                {
                    notarySystems[chainDef.GetID()].height = uni_get_int64(find_value(chainInfoUni, "blocks"));
                    notarySystems[chainDef.GetID()].notaryChain = CRPCChainData(chainDef, PBAAS_HOST, PBAAS_PORT, PBAAS_USERPASS);
                    notarySystems[chainDef.GetID()].notaryChain.SetLastConnection(GetTime());
                }
            }
        }
    }
    return IsVerusPBaaSAvailable();
}

uint32_t CConnectedChains::NotaryChainHeight()
{
    LOCK(cs_mergemining);
    return notarySystems.size() ? notarySystems.begin()->second.height : 0;
}

bool CConnectedChains::CheckVerusPBaaSAvailable()
{
    if (FirstNotaryChain().IsValid())
    {
        // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
        // tolerate only 15 second timeout
        UniValue chainInfo, chainDef;
        try
        {
            UniValue params(UniValue::VARR);
            chainInfo = find_value(RPCCallRoot("getinfo", params), "result");
            if (!chainInfo.isNull())
            {
                params.push_back(EncodeDestination(CIdentityID(FirstNotaryChain().chainDefinition.GetID())));
                chainDef = find_value(RPCCallRoot("getcurrency", params), "result");

                if (!chainDef.isNull() && CheckVerusPBaaSAvailable(chainInfo, chainDef))
                {
                    // if we have not passed block 1 yet, store the best known update of our current state
                    if ((!chainActive.LastTip() || !chainActive.LastTip()->GetHeight()))
                    {
                        bool success = false;
                        params = UniValue(UniValue::VARR);
                        params.push_back(EncodeDestination(CIdentityID(thisChain.GetID())));
                        chainDef = find_value(RPCCallRoot("getcurrency", params), "result");
                        if (!chainDef.isNull())
                        {
                            CCoinbaseCurrencyState checkState(find_value(chainDef, "lastconfirmedcurrencystate"));
                            CCurrencyDefinition currencyDef(chainDef);
                            if (currencyDef.IsValid() && checkState.IsValid() && (checkState.IsLaunchConfirmed()))
                            {
                                thisChain = currencyDef;
                                if (NotaryChainHeight() >= thisChain.startBlock)
                                {
                                    readyToStart = true;    // this only gates mining of block one, to be sure we have the latest definition
                                }
                                success = true;
                            }
                        }
                        return success;
                    }
                    return true;
                }
            }
        } catch (exception e)
        {
            LogPrintf("%s: Error communicating with %s chain\n", __func__, VERUS_CHAINNAME);
        }
    }
    return false;
}

bool CConnectedChains::IsNotaryAvailable(bool callToCheck)
{
    if (!callToCheck)
    {
        // if we aren't checking, we consider unavailable no contact in the last two minutes
        return (GetTime() - FirstNotaryChain().LastConnectionTime() < (120000));
    }
    return !(FirstNotaryChain().rpcHost.empty() || FirstNotaryChain().rpcPort == 0 || FirstNotaryChain().rpcUserPass.empty()) &&
           CheckVerusPBaaSAvailable();
}

bool CConnectedChains::ConfigureEthBridge()
{
    // first time through, we initialize the VETH gateway config file
    if (!_IsVerusActive())
    {
        return false;
    }
    if (IsNotaryAvailable())
    {
        return true;
    }
    LOCK(cs_main);
    if (FirstNotaryChain().IsValid())
    {
        return IsNotaryAvailable(true);
    }

    CRPCChainData vethNotaryChain;
    uint160 gatewayParent = ASSETCHAINS_CHAINID;
    static uint160 gatewayID;
    if (gatewayID.IsNull())
    {
        gatewayID = CIdentity::GetID("veth", gatewayParent);
    }
    vethNotaryChain.chainDefinition = ConnectedChains.GetCachedCurrency(gatewayID);
    if (vethNotaryChain.chainDefinition.IsValid())
    {
        map<string, string> settings;
        map<string, vector<string>> settingsmulti;

        // create config file for our notary chain if one does not exist already
        if (ReadConfigFile("veth", settings, settingsmulti))
        {
            // the Ethereum bridge, "VETH", serves as the root currency to VRSC and for Rinkeby to VRSCTEST
            vethNotaryChain.rpcUserPass = PBAAS_USERPASS = settingsmulti.find("-rpcuser")->second[0] + ":" + settingsmulti.find("-rpcpassword")->second[0];
            vethNotaryChain.rpcPort = PBAAS_PORT = atoi(settingsmulti.find("-rpcport")->second[0]);
            PBAAS_HOST = settingsmulti.find("-rpchost")->second[0];
            if (!PBAAS_HOST.size())
            {
                PBAAS_HOST = "127.0.0.1";
            }
            vethNotaryChain.rpcHost = PBAAS_HOST;
            CNotarySystemInfo notarySystem;
            CChainNotarizationData cnd;
            if (!GetNotarizationData(gatewayID, cnd))
            {
                LogPrintf("%s: Failed to get notarization data for notary chain %s\n", __func__, vethNotaryChain.chainDefinition.name.c_str());
                return false;
            }

            notarySystems.insert(std::make_pair(gatewayID, 
                                                CNotarySystemInfo(cnd.IsConfirmed() ? cnd.vtx[cnd.lastConfirmed].second.notarizationHeight : 0, 
                                                    vethNotaryChain,
                                                    cnd.vtx.size() ? cnd.vtx[cnd.forks[cnd.bestChain].back()].second : CPBaaSNotarization(),
                                                    CNotarySystemInfo::TYPE_ETH,
                                                    CNotarySystemInfo::VERSION_CURRENT)));
            return IsNotaryAvailable(true);
        }
    }
    return false;
}

int CConnectedChains::GetThisChainPort() const
{
    int port;
    string host;
    for (auto node : defaultPeerNodes)
    {
        SplitHostPort(node.networkAddress, port, host);
        if (port)
        {
            return port;
        }
    }
    return 0;
}

CCoinbaseCurrencyState CConnectedChains::AddPrelaunchConversions(CCurrencyDefinition &curDef,
                                                                 const CCoinbaseCurrencyState &_currencyState,
                                                                 int32_t fromHeight,
                                                                 int32_t height,
                                                                 int32_t curDefHeight)
{
    CCoinbaseCurrencyState currencyState = _currencyState;
    bool firstUpdate = fromHeight <= curDefHeight;
    if (firstUpdate)
    {
        if (curDef.IsFractional())
        {
            currencyState.supply = curDef.initialFractionalSupply;
            currencyState.reserves = std::vector<int64_t>(currencyState.reserves.size(), 0);
            currencyState.reserveIn = currencyState.reserves;
            if (curDef.IsPBaaSConverter() && curDef.gatewayConverterIssuance)
            {
                currencyState.reserves[curDef.GetCurrenciesMap()[curDef.systemID]] = curDef.gatewayConverterIssuance;
            }
            currencyState.weights = curDef.weights;
        }
        else
        {
            // supply is determined by purchases * current conversion rate
            currencyState.supply = curDef.gatewayConverterIssuance + curDef.GetTotalPreallocation();
        }
    }

    // get chain transfers that should apply before the start block
    // until there is a post-start block notarization, we always consider the
    // currency state to be up to just before the start block
    std::multimap<uint160, ChainTransferData> unspentTransfers;
    std::map<uint160, int32_t> currencyIndexes = currencyState.GetReserveMap();

    if (GetUnspentChainTransfers(unspentTransfers, curDef.GetID()) &&
        unspentTransfers.size())
    {
        std::vector<CReserveTransfer> transfers;
        for (auto &oneTransfer : unspentTransfers)
        {
            if (std::get<0>(oneTransfer.second) < curDef.startBlock)
            {
                transfers.push_back(std::get<2>(oneTransfer.second));
            }
        }
        uint256 transferHash;
        CPBaaSNotarization newNotarization;
        std::vector<CTxOut> importOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsUsed, spentCurrencyOut;
        CPBaaSNotarization workingNotarization = CPBaaSNotarization(currencyState.GetID(),
                                                                    currencyState,
                                                                    fromHeight,
                                                                    CUTXORef(),
                                                                    curDefHeight);
        workingNotarization.SetPreLaunch();
        if (workingNotarization.NextNotarizationInfo(ConnectedChains.ThisChain(),
                                                     curDef,
                                                     fromHeight,
                                                     std::min(height, curDef.startBlock - 1),
                                                     transfers,
                                                     transferHash,
                                                     newNotarization,
                                                     importOutputs,
                                                     importedCurrency,
                                                     gatewayDepositsUsed,
                                                     spentCurrencyOut))
        {
            return newNotarization.currencyState;
        }
    }
    return currencyState;
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(CCurrencyDefinition &curDef, int32_t height, int32_t curDefHeight)
{
    uint160 chainID = curDef.GetID();
    CCoinbaseCurrencyState currencyState;
    std::vector<CAddressIndexDbEntry> notarizationIndex;

    if (chainID == ASSETCHAINS_CHAINID)
    {
        currencyState = GetInitialCurrencyState(thisChain);
        currencyState.SetLaunchConfirmed();
    }
    // if this is a token on this chain, it will be simply notarized
    else if (curDef.systemID == ASSETCHAINS_CHAINID || (curDef.launchSystemID == ASSETCHAINS_CHAINID && curDef.startBlock > height))
    {
        // get the last notarization in the height range for this currency, which is valid by definition for a token
        CPBaaSNotarization notarization;
        notarization.GetLastNotarization(chainID, curDefHeight, height);
        currencyState = notarization.currencyState;
        if (!currencyState.IsValid())
        {
            if (notarization.IsValid() && notarization.currencyStates.count(chainID))
            {
                currencyState = notarization.currencyStates[chainID];
            }
            else
            {
                currencyState = GetInitialCurrencyState(curDef);
                currencyState.SetPrelaunch();
            }
        }
        if (currencyState.IsValid() && (curDef.launchSystemID == ASSETCHAINS_CHAINID && notarization.notarizationHeight < (curDef.startBlock - 1)))
        {
            // pre-launch
            currencyState.SetPrelaunch(true);
            currencyState = AddPrelaunchConversions(curDef, 
                                                    currencyState, 
                                                    notarization.IsValid() && !notarization.IsDefinitionNotarization() ? 
                                                        notarization.notarizationHeight + 1 : curDefHeight, 
                                                    std::min(height, curDef.startBlock - 1), 
                                                    curDefHeight);
        }
    }
    else
    {
        // we need to get the currency state of a currency not on this chain, so we first get the chain's notarization and see if
        // it is there. if not, look for the latest confirmed notarization and return that
        CChainNotarizationData cnd;
        if (GetNotarizationData(curDef.systemID, cnd) && cnd.IsConfirmed() && cnd.vtx[cnd.lastConfirmed].second.currencyStates.count(chainID))
        {
            return cnd.vtx[cnd.lastConfirmed].second.currencyStates[chainID];
        }
        if (GetNotarizationData(chainID, cnd))
        {
            int32_t transfersFrom = curDefHeight;
            if (cnd.lastConfirmed != -1)
            {
                transfersFrom = cnd.vtx[cnd.lastConfirmed].second.notarizationHeight;
                currencyState = cnd.vtx[cnd.lastConfirmed].second.currencyState;
            }
            int32_t transfersUntil = cnd.lastConfirmed == -1 ? curDef.startBlock - 1 :
                                       (cnd.vtx[cnd.lastConfirmed].second.notarizationHeight < curDef.startBlock ?
                                        (height < curDef.startBlock ? height : curDef.startBlock - 1) :
                                        cnd.vtx[cnd.lastConfirmed].second.notarizationHeight);
            if (transfersUntil < curDef.startBlock)
            {
                if (currencyState.reserveIn.size() != curDef.currencies.size())
                {
                    currencyState.reserveIn = std::vector<int64_t>(curDef.currencies.size());
                }
                if (curDef.conversions.size() != curDef.currencies.size())
                {
                    curDef.conversions = std::vector<int64_t>(curDef.currencies.size());
                }
                if (currencyState.conversionPrice.size() != curDef.currencies.size())
                {
                    currencyState.conversionPrice = std::vector<int64_t>(curDef.currencies.size());
                }
                if (currencyState.fees.size() != curDef.currencies.size())
                {
                    currencyState.fees = std::vector<int64_t>(curDef.currencies.size());
                }
                if (currencyState.conversionFees.size() != curDef.currencies.size())
                {
                    currencyState.conversionFees = std::vector<int64_t>(curDef.currencies.size());
                }
                if (currencyState.priorWeights.size() != curDef.currencies.size())
                {
                    currencyState.priorWeights.resize(curDef.currencies.size());
                }
                // get chain transfers that should apply before the start block
                // until there is a post-start block notarization, we always consider the
                // currency state to be up to just before the start block
                std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> unspentTransfers;
                if (GetChainTransfers(unspentTransfers, chainID, transfersFrom, transfersUntil))
                {
                    // at this point, all pre-allocation, minted, and pre-converted currency are included
                    // in the currency state before final notarization
                    std::map<uint160, int32_t> currencyIndexes = currencyState.GetReserveMap();
                    if (curDef.IsFractional())
                    {
                        currencyState.supply = curDef.initialFractionalSupply;
                    }
                    else
                    {
                        // supply is determined by purchases * current conversion rate
                        currencyState.supply = curDef.GetTotalPreallocation();
                    }

                    for (auto &transfer : unspentTransfers)
                    {
                        if (transfer.second.second.IsPreConversion())
                        {
                            CAmount conversionFee = CReserveTransactionDescriptor::CalculateConversionFee(transfer.second.second.FirstValue());

                            currencyState.reserveIn[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue();
                            curDef.preconverted[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue();
                            if (curDef.IsFractional())
                            {
                                currencyState.reserves[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue() - conversionFee;
                            }
                            else
                            {
                                currencyState.supply += CCurrencyState::ReserveToNativeRaw(transfer.second.second.FirstValue() - conversionFee, currencyState.PriceInReserve(currencyIndexes[transfer.second.second.FirstCurrency()]));
                            }

                            currencyState.conversionFees[currencyIndexes[transfer.second.second.FirstCurrency()]] += conversionFee;
                            currencyState.fees[currencyIndexes[transfer.second.second.FirstCurrency()]] += conversionFee;
                            currencyState.fees[currencyIndexes[transfer.second.second.feeCurrencyID]] += transfer.second.second.nFees;
                        }
                    }
                    currencyState.supply += currencyState.emitted;
                    for (int i = 0; i < curDef.conversions.size(); i++)
                    {
                        currencyState.conversionPrice[i] = curDef.conversions[i] = currencyState.PriceInReserve(i);
                    }
                }
            }
            else
            {
                std::pair<CUTXORef, CPBaaSNotarization> notPair = cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed] : cnd.vtx[cnd.forks[cnd.bestChain][0]];
                currencyState = notPair.second.currencyState;
            }
        }
    }
    return currencyState;
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(const uint160 &currencyID, int32_t height)
{
    int32_t curDefHeight;
    CCurrencyDefinition curDef;
    if (GetCurrencyDefinition(currencyID, curDef, &curDefHeight, true))
    {
        return GetCurrencyState(curDef, height, curDefHeight);
    }
    else
    {
        LogPrintf("%s: currency %s:%s not found\n", __func__, currencyID.GetHex().c_str(), EncodeDestination(CIdentityID(currencyID)).c_str());
        printf("%s: currency %s:%s not found\n", __func__, currencyID.GetHex().c_str(), EncodeDestination(CIdentityID(currencyID)).c_str());
    }
    return CCoinbaseCurrencyState();
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(int32_t height)
{
    return GetCurrencyState(thisChain.GetID(), height);
}

bool CConnectedChains::SetLatestMiningOutputs(const std::vector<CTxOut> &minerOutputs)
{
    LOCK(cs_mergemining);
    latestMiningOutputs = minerOutputs;
    return true;
}

CCurrencyDefinition CConnectedChains::GetCachedCurrency(const uint160 &currencyID)
{
    CCurrencyDefinition currencyDef;
    int32_t defHeight;
    auto it = currencyDefCache.find(currencyID);
    if ((it != currencyDefCache.end() && !(currencyDef = it->second).IsValid()) ||
        (it == currencyDefCache.end() && !GetCurrencyDefinition(currencyID, currencyDef, &defHeight, true)))
    {
        LogPrint("notarization", "%s: definition for transfer currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
        return currencyDef;
    }
    if (it == currencyDefCache.end())
    {
        currencyDefCache[currencyID] = currencyDef;
    }
    return currencyDefCache[currencyID];
}

CCurrencyDefinition CConnectedChains::UpdateCachedCurrency(const uint160 &currencyID, uint32_t height)
{
    // due to the main lock being taken on the thread that waits for transaction checks,
    // low level functions like this must be called either from a thread that holds LOCK(cs_main),
    // or script validation, where it is held either by this thread or one waiting for it.
    // in the long run, the daemon synchonrization model should be improved
    CCurrencyDefinition currencyDef = GetCachedCurrency(currencyID);
    CCoinbaseCurrencyState curState = GetCurrencyState(currencyDef, height);
    currencyDefCache[currencyID] = currencyDef;
    return currencyDef;
}


// returns all unspent chain exports for a specific chain/currency
bool CConnectedChains::GetUnspentSystemExports(const CCoinsViewCache &view, 
                                               const uint160 systemID, 
                                               std::vector<pair<int, CInputDescriptor>> &exportOutputs)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> exportUTXOs;

    std::vector<pair<int, CInputDescriptor>> exportOuts;

    LOCK2(cs_main, mempool.cs);

    uint160 exportIndexKey = CCrossChainRPCData::GetConditionID(systemID, CCrossChainExport::SystemExportKey());

    if (mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{exportIndexKey, CScript::P2IDX}}), exportUTXOs) &&
        exportUTXOs.size())
    {
        std::map<COutPoint, CInputDescriptor> memPoolOuts;
        for (auto &oneExport : exportUTXOs)
        {
            if (oneExport.first.spending)
            {
                memPoolOuts.erase(COutPoint(oneExport.first.txhash, oneExport.first.index));
            }
            else
            {
                const CTransaction oneTx = mempool.mapTx.find(oneExport.first.txhash)->GetTx();
                memPoolOuts.insert(std::make_pair(COutPoint(oneExport.first.txhash, oneExport.first.index),
                                                CInputDescriptor(oneTx.vout[oneExport.first.index].scriptPubKey, oneExport.second.amount, 
                                                            CTxIn(oneExport.first.txhash, oneExport.first.index))));
            }
        }

        for (auto &oneUTXO : memPoolOuts)
        {
            exportOuts.push_back(std::make_pair(0, oneUTXO.second));
        }
    }
    if (!exportOuts.size() &&
        !GetAddressUnspent(exportIndexKey, CScript::P2IDX, unspentOutputs))
    {
        return false;
    }
    else
    {
        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            exportOuts.push_back(std::make_pair(it->second.blockHeight, CInputDescriptor(it->second.script, it->second.satoshis, 
                                                            CTxIn(it->first.txhash, it->first.index))));
        }
    }
    exportOutputs.insert(exportOutputs.end(), exportOuts.begin(), exportOuts.end());
    return exportOuts.size() != 0;
}

// returns all unspent chain exports for a specific chain/currency
bool CConnectedChains::GetUnspentCurrencyExports(const CCoinsViewCache &view, 
                                                 const uint160 currencyID, 
                                                 std::vector<pair<int, CInputDescriptor>> &exportOutputs)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> exportUTXOs;

    std::vector<pair<int, CInputDescriptor>> exportOuts;

    LOCK2(cs_main, mempool.cs);

    uint160 exportIndexKey = CCrossChainRPCData::GetConditionID(currencyID, CCrossChainExport::CurrencyExportKey());

    if (mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{exportIndexKey, CScript::P2IDX}}), exportUTXOs) &&
        exportUTXOs.size())
    {
        // we need to remove those that are spent
        std::map<COutPoint, CInputDescriptor> memPoolOuts;
        for (auto &oneExport : exportUTXOs)
        {
            if (oneExport.first.spending)
            {
                memPoolOuts.erase(COutPoint(oneExport.first.txhash, oneExport.first.index));
            }
            else
            {
                const CTransaction oneTx = mempool.mapTx.find(oneExport.first.txhash)->GetTx();
                memPoolOuts.insert(std::make_pair(COutPoint(oneExport.first.txhash, oneExport.first.index),
                                                CInputDescriptor(oneTx.vout[oneExport.first.index].scriptPubKey, oneExport.second.amount, 
                                                            CTxIn(oneExport.first.txhash, oneExport.first.index))));
            }
        }

        for (auto &oneUTXO : memPoolOuts)
        {
            exportOuts.push_back(std::make_pair(0, oneUTXO.second));
        }
    }
    if (!exportOuts.size() &&
        !GetAddressUnspent(exportIndexKey, CScript::P2IDX, unspentOutputs))
    {
        return false;
    }
    else
    {
        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            exportOuts.push_back(std::make_pair(it->second.blockHeight, CInputDescriptor(it->second.script, it->second.satoshis, 
                                                            CTxIn(it->first.txhash, it->first.index))));
        }
    }
    exportOutputs.insert(exportOutputs.end(), exportOuts.begin(), exportOuts.end());
    return exportOuts.size() != 0;
}

bool CConnectedChains::GetPendingCurrencyExports(const uint160 currencyID,
                                                 uint32_t fromHeight,
                                                 std::vector<pair<int, CInputDescriptor>> &exportOutputs)
{
    CCurrencyDefinition chainDef;
    int32_t defHeight;
    exportOutputs.clear();

    if (GetCurrencyDefinition(currencyID, chainDef, &defHeight))
    {
        // which transaction are we in this block?
        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

        CChainNotarizationData cnd;
        if (GetNotarizationData(currencyID, cnd))
        {
            uint160 exportKey = CCrossChainRPCData::GetConditionID(currencyID, CCrossChainExport::CurrencyExportKey());

            // get all export transactions including and since this one up to the confirmed cross-notarization
            if (GetAddressIndex(exportKey, CScript::P2IDX, addressIndex, fromHeight))
            {
                for (auto &idx : addressIndex)
                {
                    uint256 blkHash;
                    CTransaction exportTx;
                    if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
                    {
                        std::vector<CBaseChainObject *> opretTransfers;
                        CCrossChainExport ccx;
                        if ((ccx = CCrossChainExport(exportTx.vout[idx.first.index].scriptPubKey)).IsValid())
                        {
                            exportOutputs.push_back(std::make_pair(idx.first.blockHeight, 
                                                                               CInputDescriptor(exportTx.vout[idx.first.index].scriptPubKey, 
                                                                                                exportTx.vout[idx.first.index].nValue,
                                                                                                CTxIn(idx.first.txhash, idx.first.index))));
                        }
                    }
                }
            }
        }
        return true;
    }
    else
    {
        LogPrintf("%s: unrecognized system name or ID\n", __func__);
        return false;
    }
}

CPartialTransactionProof::CPartialTransactionProof(const CTransaction tx, const std::vector<int32_t> &inputNums, const std::vector<int32_t> &outputNums, const CBlockIndex *pIndex, uint32_t proofAtHeight)
{
    // get map and MMR for transaction
    CTransactionMap txMap(tx);
    TransactionMMView txView(txMap.transactionMMR);
    uint256 txRoot = txView.GetRoot();

    std::vector<CTransactionComponentProof> txProofVec;
    txProofVec.push_back(CTransactionComponentProof(txView, txMap, tx, CTransactionHeader::TX_HEADER, 0));
    for (auto oneInNum : inputNums)
    {
        txProofVec.push_back(CTransactionComponentProof(txView, txMap, tx, CTransactionHeader::TX_PREVOUTSEQ, oneInNum));
    }

    for (auto oneOutNum : outputNums)
    {
        txProofVec.push_back(CTransactionComponentProof(txView, txMap, tx, CTransactionHeader::TX_OUTPUT, oneOutNum));
    }

    // now, both the header and stake output are dependent on the transaction MMR root being provable up
    // through the block MMR, and since we don't cache the new MMR proof for transactions yet, we need the block to create the proof.
    // when we switch to the new MMR in place of a merkle tree, we can keep that in the wallet as well
    CBlock block;
    if (!ReadBlockFromDisk(block, pIndex, Params().GetConsensus(), false))
    {
        LogPrintf("%s: ERROR: could not read block number %u from disk\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    BlockMMRange blockMMR(block.GetBlockMMRTree());
    BlockMMView blockView(blockMMR);

    int txIndexPos;
    for (txIndexPos = 0; txIndexPos < blockMMR.size(); txIndexPos++)
    {
        uint256 txRootHashFromMMR = blockMMR[txIndexPos].hash;
        if (txRootHashFromMMR == txRoot)
        {
            //printf("tx with root %s found in block\n", txRootHashFromMMR.GetHex().c_str());
            break;
        }
    }

    if (txIndexPos == blockMMR.size())
    {
        LogPrintf("%s: ERROR: could not find transaction root in block %u\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    // prove the tx up to the MMR root, which also contains the block hash
    CMMRProof txRootProof;
    if (!blockView.GetProof(txRootProof, txIndexPos))
    {
        LogPrintf("%s: ERROR: could not create proof of source transaction in block %u\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    ChainMerkleMountainView mmv = chainActive.GetMMV();
    mmv.resize(proofAtHeight + 1);
    chainActive.GetMerkleProof(mmv, txRootProof, pIndex->GetHeight());
    *this = CPartialTransactionProof(txRootProof, txProofVec);

    /*printf("%s: MMR root at height %u: %s\n", __func__, proofAtHeight, mmv.GetRoot().GetHex().c_str());
    CTransaction outTx;
    if (CheckPartialTransaction(outTx) != mmv.GetRoot())
    {
        printf("%s: invalid proof result: %s\n", __func__, CheckPartialTransaction(outTx).GetHex().c_str());
    }
    CPartialTransactionProof checkProof(ToUniValue());
    if (checkProof.CheckPartialTransaction(outTx) != mmv.GetRoot())
    {
        printf("%s: invalid proof after univalue: %s\n", __func__, checkProof.CheckPartialTransaction(outTx).GetHex().c_str());
    }*/
}

// given exports on this chain, provide the proofs of those export outputs with the MMR root at height "height"
// proofs are added in place
bool CConnectedChains::GetExportProofs(uint32_t height,
                                       std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports)
{
    // fill in proofs of the export outputs for each export at the specified height
    CBlock proofBlock;

    for (auto &oneExport : exports)
    {
        uint256 blockHash;
        CTransaction exportTx;
        if (!myGetTransaction(oneExport.first.first.txIn.prevout.hash, exportTx, blockHash))
        {
            LogPrintf("%s: unable to retrieve export %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        CCrossChainExport ccx(exportTx.vout[oneExport.first.first.txIn.prevout.n].scriptPubKey);
        if (!ccx.IsValid())
        {
            LogPrintf("%s: invalid export on %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        if (blockHash.IsNull())
        {
            LogPrintf("%s: cannot get proof for unconfirmed export %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        auto blockIt = mapBlockIndex.find(blockHash);
        if (blockIt == mapBlockIndex.end() || !chainActive.Contains(blockIt->second))
        {
            LogPrintf("%s: cannot validate block of export tx %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        std::vector<int32_t> inputsToProve;
        oneExport.first.second = CPartialTransactionProof(exportTx,
                                                          inputsToProve,
                                                          std::vector<int32_t>({(int32_t)oneExport.first.first.txIn.prevout.n}), 
                                                          blockIt->second, 
                                                          height);
    }
    return true;
}

bool CConnectedChains::GetReserveDeposits(const uint160 &currencyID, const CCoinsViewCache &view, std::vector<CInputDescriptor> &reserveDeposits)
{
    std::vector<CAddressUnspentDbEntry> confirmedUTXOs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> unconfirmedUTXOs;

    CCoins coin;

    uint160 depositIndexKey = CReserveDeposit::ReserveDepositIndexKey(currencyID);
    if (!GetAddressUnspent(depositIndexKey, CScript::P2IDX, confirmedUTXOs) ||
        !mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{depositIndexKey, CScript::P2IDX}}), unconfirmedUTXOs))
    {
        LogPrintf("%s: Cannot read address indexes\n", __func__);
        return false;
    }
    for (auto &oneConfirmed : confirmedUTXOs)
    {
        if (!mempool.mapNextTx.count(COutPoint(oneConfirmed.first.txhash, oneConfirmed.first.index)) &&
            view.GetCoins(oneConfirmed.first.txhash, coin) &&
            coin.IsAvailable(oneConfirmed.first.index))
        {
            reserveDeposits.push_back(CInputDescriptor(oneConfirmed.second.script, oneConfirmed.second.satoshis, 
                                                        CTxIn(oneConfirmed.first.txhash, oneConfirmed.first.index)));
        }
    }

    // we need to remove those that are spent
    std::map<COutPoint, CInputDescriptor> memPoolOuts;
    for (auto &oneUnconfirmed : unconfirmedUTXOs)
    {
        COptCCParams p;
        if (!oneUnconfirmed.first.spending &&
            !mempool.mapNextTx.count(COutPoint(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index)) &&
            view.GetCoins(oneUnconfirmed.first.txhash, coin) && 
            coin.IsAvailable(oneUnconfirmed.first.index))
        {
            const CTransaction oneTx = mempool.mapTx.find(oneUnconfirmed.first.txhash)->GetTx();
            reserveDeposits.push_back(CInputDescriptor(oneTx.vout[oneUnconfirmed.first.index].scriptPubKey, oneUnconfirmed.second.amount, 
                                                        CTxIn(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index)));
        }
    }
    return true;
}

// given a set of provable exports to this chain from either this chain or another chain or system, 
// create a set of import transactions
bool CConnectedChains::CreateLatestImports(const CCurrencyDefinition &sourceSystemDef,                      // transactions imported from system
                                           const CUTXORef &confirmedSourceNotarization,                     // relevant notarization of exporting system
                                           const std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                           std::map<uint160, std::vector<std::pair<int, CTransaction>>> &newImports)
{
    // each export is from the source system, but may be to any currency exposed on this system, so each import
    // made combines the potential currency sources of the source system and the importing currency
    LOCK2(cs_main, mempool.cs);

    if (!exports.size())
    {
        return false;
    }

    // determine if we are refunding or not, which must be handled correctly when refunding a
    // PBaaS launch. In that case, the refunds must be read as if they are to another chain,
    // and written as same chain

    CCoinsView dummy;
    CCoinsViewCache view(&dummy);
    CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
    view.SetBackend(viewMemPool);

    uint32_t nHeight = chainActive.Height();
    uint160 sourceSystemID = sourceSystemDef.GetID();
    bool useProofs = sourceSystemID != thisChain.GetID();

    CPBaaSNotarization proofNotarization;
    if (useProofs)
    {
        CTransaction proofNotarizationTx;
        uint256 blkHash;
        COptCCParams p;
        if (confirmedSourceNotarization.hash.IsNull() ||
            !myGetTransaction(confirmedSourceNotarization.hash, proofNotarizationTx, blkHash) ||
            confirmedSourceNotarization.n >= proofNotarizationTx.vout.size() || 
            !proofNotarizationTx.vout[confirmedSourceNotarization.n].scriptPubKey.IsPayToCryptoCondition(p) ||
            !p.IsValid() ||
            (p.evalCode != EVAL_ACCEPTEDNOTARIZATION && p.evalCode != EVAL_EARNEDNOTARIZATION) ||
            !p.vData.size() ||
            !(proofNotarization = CPBaaSNotarization(p.vData[0])).IsValid() ||
            !proofNotarization.proofRoots.count(sourceSystemID))
        {
            LogPrintf("%s: invalid notarization for export proof\n", __func__);
            return false;
        }
    }

    // now, if we are creating an import for an external export, spend and output the import thread for that external system to make it
    // easy to find the last import for any external system and confirm that we are also not skipping any exports
    CTransaction lastSourceImportTx;
    int32_t sourceOutputNum = -1;
    CCrossChainImport lastSourceCCI;
    uint256 lastSourceImportTxID;

    for (auto &oneIT : exports)
    {
        uint256 blkHash;
        CTransaction exportTx;

        if (useProofs)
        {
            if (!oneIT.first.second.IsValid())
            {
                LogPrintf("%s: invalid proof for export tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }

            if (proofNotarization.proofRoots[sourceSystemID].stateRoot != oneIT.first.second.CheckPartialTransaction(exportTx))
            {
                LogPrintf("%s: export tx %s fails verification\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }

            if (exportTx.vout.size() <= oneIT.first.first.txIn.prevout.n)
            {
                LogPrintf("%s: invalid proof for export tx output %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }
        }
        else
        {
            if (!myGetTransaction(oneIT.first.first.txIn.prevout.hash, exportTx, blkHash))
            {
                LogPrintf("%s: unable to retrieve export tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }
        }

        const CCrossChainExport ccx(exportTx.vout[oneIT.first.first.txIn.prevout.n].scriptPubKey);
        if (!ccx.IsValid())
        {
            LogPrintf("%s: invalid export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }

        CChainNotarizationData cnd;
        CPBaaSNotarization priorChainNotarization;
        CCurrencyDefinition refundingPBaaSChain;
        bool isRefundingSeparateChain = false;
        if (GetNotarizationData(ccx.destCurrencyID, cnd) &&
            cnd.IsValid() &&
            cnd.IsConfirmed() &&
            (priorChainNotarization = cnd.vtx[cnd.lastConfirmed].second).IsValid() &&
            priorChainNotarization.currencyState.IsValid())
        {
            // if this is a refund from an alternate chain, we accept it to this chain if we are the launch chain
            if (priorChainNotarization.currencyState.IsRefunding() &&
                GetCurrencyDefinition(ccx.destCurrencyID, refundingPBaaSChain) &&
                refundingPBaaSChain.launchSystemID == ASSETCHAINS_CHAINID &&
                refundingPBaaSChain.systemID != ASSETCHAINS_CHAINID)
            {
                isRefundingSeparateChain = true;
            }
        }

        if (isRefundingSeparateChain)
        {
            printf("%s: processing refund from PBaaS chain currency %s\n", __func__, refundingPBaaSChain.name.c_str());
        }

        // get reserve deposits for destination currency of export. these will be available whether the source is same chain
        // or an external chain/gateway
        std::vector<CInputDescriptor> localDeposits;
        std::vector<CInputDescriptor> crossChainDeposits;

        if (ccx.sourceSystemID != ccx.destCurrencyID)
        {
            if (!ConnectedChains.GetReserveDeposits(ccx.destCurrencyID, view, localDeposits))
            {
                LogPrintf("%s: cannot get reserve deposits for export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }
        }

        // DEBUG OUTPUT
        /* for (auto &oneDepositIn : localDeposits)
        {
            UniValue scrUni(UniValue::VOBJ);
            ScriptPubKeyToUniv(oneDepositIn.scriptPubKey, scrUni, false);
            printf("%s: one deposit hash: %s, vout: %u, scriptdecode: %s, amount: %s\n",
                __func__,
                oneDepositIn.txIn.prevout.hash.GetHex().c_str(), 
                oneDepositIn.txIn.prevout.n,
                scrUni.write(1,2).c_str(),
                ValueFromAmount(oneDepositIn.nValue).write().c_str());
        } // DEBUG OUTPUT END */

        // if importing from another system/chain, get reserve deposits of source system to make available to import as well
        if (isRefundingSeparateChain || useProofs)
        {
            if (!ConnectedChains.GetReserveDeposits(isRefundingSeparateChain ? refundingPBaaSChain.systemID : sourceSystemID, view, crossChainDeposits))
            {
                LogPrintf("%s: cannot get reserve deposits for cross-system export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }

            // DEBUG OUTPUT
            /* for (auto &oneDepositIn : crossChainDeposits)
            {
                UniValue scrUni(UniValue::VOBJ);
                ScriptPubKeyToUniv(oneDepositIn.scriptPubKey, scrUni, false);
                printf("%s: one crosschain deposit hash: %s, vout: %u, scriptdecode: %s, amount: %s\n",
                    __func__,
                    oneDepositIn.txIn.prevout.hash.GetHex().c_str(), 
                    oneDepositIn.txIn.prevout.n,
                    scrUni.write(1,2).c_str(),
                    ValueFromAmount(oneDepositIn.nValue).write().c_str());
            } // DEBUG OUTPUT END */
        }

        // now, we have all reserve deposits for both local destination and importing currency, we can use both, 
        // but must keep track of them separately, first, get last import for the current export
        CTransaction lastImportTx;
        int32_t outputNum;
        CCrossChainImport lastCCI;
        uint256 lastImportTxID;

        auto lastImportIt = newImports.find(ccx.destCurrencyID);
        if (lastImportIt != newImports.end())
        {
            lastImportTx = lastImportIt->second.back().second;
            outputNum = lastImportIt->second.back().first;
            lastCCI = CCrossChainImport(lastImportTx.vout[outputNum].scriptPubKey);
            lastImportTxID = lastImportTx.GetHash();
        }
        else if (nHeight && !GetLastImport(ccx.destCurrencyID, lastImportTx, outputNum))
        {
            LogPrintf("%s: cannot find last import for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            return false;
        }
        else if (nHeight)
        {
            lastCCI = CCrossChainImport(lastImportTx.vout[outputNum].scriptPubKey);
            lastImportTxID = lastImportTx.GetHash();
        }
        
        CCurrencyDefinition destCur = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID);
        if (!lastCCI.IsValid() || !destCur.IsValid())
        {
            LogPrintf("%s: invalid destination currency for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            return false;
        }

        // now, we have:
        // 1. last import output + potentially additional reserve transfer storage outputs to spend from prior import
        // 2. reserve transfers for next import
        // 3. proof notarization if export is from off chain
        // 4. reserve deposits for destination currency on this chain. which will matter if it holds reserves
        // 5. reserve deposits for source system, which will matter if we have sent currencies to it that will be used
        // 6. destination currency definition

        // either:
        // 1) it is a gateway on our current chain, and we are creating imports for the system represented by the gateway from this system
        //    or we are importing into this system from the gateway system
        // 2) we are creating an import for a fractional currency on this chain, or
        // 3) destination is a PBaaS currency, which is either the native currency, if we are the PBaaS chain or a token on our current chain.
        //    We are creating imports for this system, which is the PBaaS chain, to receive exports from our notary chain, which is its parent, 
        //    or we are creating imports to receive exports from the PBaaS chain.
        if (!(isRefundingSeparateChain && sourceSystemID == ASSETCHAINS_CHAINID) &&
            !((destCur.IsGateway() && destCur.systemID == ASSETCHAINS_CHAINID) && 
                (sourceSystemID == ASSETCHAINS_CHAINID || sourceSystemID == ccx.destCurrencyID)) &&
            !(sourceSystemID == destCur.systemID && destCur.systemID == ASSETCHAINS_CHAINID) &&
            !(destCur.IsPBaaSChain() &&
                (sourceSystemID == ccx.destCurrencyID ||
                  (ccx.destCurrencyID == ASSETCHAINS_CHAINID))) &&
            !(sourceSystemID != ccx.destSystemID))
        {
            LogPrintf("%s: invalid currency for export/import %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            return false;
        }

        // if we are importing from another system, find the last import from that system and consider this another one
        if (useProofs)
        {
            if (sourceOutputNum == -1 && nHeight && !GetLastSourceImport(ccx.sourceSystemID, lastSourceImportTx, sourceOutputNum))
            {
                LogPrintf("%s: cannot find last source system import for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), sourceOutputNum);
                return false;
            }
            else if (nHeight)
            {
                lastSourceCCI = CCrossChainImport(lastSourceImportTx.vout[sourceOutputNum].scriptPubKey);
                lastSourceImportTxID = lastSourceImportTx.GetHash();
            }
        }

        CPBaaSNotarization lastNotarization;
        CInputDescriptor lastNotarizationOut;
        std::vector<CReserveTransfer> lastReserveTransfers;
        CCrossChainExport lastCCX;
        CCrossChainImport lastSysCCI;
        int32_t sysCCIOutNum = -1, evidenceOutNumStart = -1, evidenceOutNumEnd = -1;

        int32_t notarizationOutNum;
        CValidationState state;

        uint160 destCurID = destCur.GetID();

        // if not the initial import in the thread, it should have a valid prior notarization as well
        // the notarization of the initial import may be superceded by pre-launch exports
        if (nHeight && lastCCI.IsPostLaunch())
        {
            if (!lastCCI.GetImportInfo(lastImportTx,
                                       nHeight,
                                       outputNum,
                                       lastCCX,
                                       lastSysCCI,
                                       sysCCIOutNum,
                                       lastNotarization,
                                       notarizationOutNum,
                                       evidenceOutNumStart,
                                       evidenceOutNumEnd,
                                       lastReserveTransfers,
                                       state))
            {
                LogPrintf("%s: currency: %s, %u - %s\n", __func__, destCur.name.c_str(), state.GetRejectCode(), state.GetRejectReason().c_str());
                return false;
            }

            lastNotarizationOut = CInputDescriptor(lastImportTx.vout[notarizationOutNum].scriptPubKey,
                                                   lastImportTx.vout[notarizationOutNum].nValue,
                                                   CTxIn(lastImportTxID, notarizationOutNum));

            // verify that the current export from the source system spends the prior export from the source system

            // TODO: HARDENING - if firstInput is -1, this will not check the in order,
            // firstInput should be > 0 at all times

            if (useProofs &&
                !(ccx.IsChainDefinition() ||
                  lastSourceCCI.exportTxId.IsNull() ||
                  (ccx.firstInput > 0 &&
                   exportTx.vin[ccx.firstInput - 1].prevout.hash == lastSourceCCI.exportTxId &&
                   exportTx.vin[ccx.firstInput - 1].prevout.n == lastSourceCCI.exportTxOutNum)))
            {
                printf("%s: out of order export for cci:\n%s\n, expected: (%s, %d) found: (%s, %u)\n", 
                    __func__,
                    lastSourceCCI.ToUniValue().write(1,2).c_str(),
                    lastSourceCCI.exportTxId.GetHex().c_str(), 
                    lastSourceCCI.exportTxOutNum, 
                    exportTx.vin[ccx.firstInput - 1].prevout.hash.GetHex().c_str(), 
                    exportTx.vin[ccx.firstInput - 1].prevout.n);
                LogPrintf("%s: out of order export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), sourceOutputNum);
                return false;
            }
            else if (useProofs)
            {
                // make sure we have the latest, confirmed proof roots to prove this import
                lastNotarization.proofRoots[sourceSystemID] = proofNotarization.proofRoots[sourceSystemID];
            }
        }
        else if (nHeight)
        {
            // the first import ever cannot be on a chain that is already running and is not the same chain
            // as the first export processed. it is either launched from the launch chain, which is running
            // or as a new chain, started from a different launch chain.
            if (useProofs)
            {
                LogPrintf("%s: invalid first import for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                return false;
            }

            // first import, but not first block, so not PBaaS launch - last import has no evidence to spend
            CChainNotarizationData cnd;
            std::vector<std::pair<CTransaction, uint256>> notarizationTxes;
            if (!GetNotarizationData(ccx.destCurrencyID, cnd, &notarizationTxes) || !cnd.IsConfirmed())
            {
                LogPrintf("%s: cannot get notarization for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                return false;
            }

            lastNotarization = cnd.vtx[cnd.lastConfirmed].second;
            if (!lastNotarization.IsValid())
            {
                LogPrintf("%s: invalid notarization for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                return false;
            }
            lastNotarizationOut = CInputDescriptor(notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].scriptPubKey,
                                                   notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].nValue,
                                                   CTxIn(cnd.vtx[cnd.lastConfirmed].first));
        }
        else // height is 0 - this is first block of PBaaS chain
        {
            if (!(proofNotarization.currencyID == ccx.destCurrencyID || proofNotarization.currencyStates.count(ccx.destCurrencyID)))
            {
                // last notarization is coming from the launch chain at height 0
                lastNotarization = CPBaaSNotarization(ccx.destCurrencyID,
                                                      proofNotarization.currencyID == 
                                                        ccx.destCurrencyID ? proofNotarization.currencyState : 
                                                                             proofNotarization.currencyStates[ccx.destCurrencyID],
                                                      0,
                                                      CUTXORef(),
                                                      0);
                lastNotarizationOut = CInputDescriptor(CScript(), 0, CTxIn());
            }
        }

        CPBaaSNotarization newNotarization;
        uint256 transferHash;
        std::vector<CReserveTransfer> exportTransfers = oneIT.second;
        std::vector<CTxOut> newOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsUsed, spentCurrencyOut;

        // if we are transitioning from export to import, allow the function to set launch clear on the currency
        if (lastNotarization.currencyState.IsLaunchClear() && !lastCCI.IsInitialLaunchImport())
        {
            lastNotarization.SetPreLaunch();
            lastNotarization.currencyState.SetLaunchCompleteMarker(false);
            lastNotarization.currencyState.SetLaunchClear(false);
            lastNotarization.currencyState.SetPrelaunch(true);
        }
        else if (lastCCI.IsInitialLaunchImport())
        {
            lastNotarization.SetPreLaunch(false);
            lastNotarization.currencyState.SetPrelaunch(false);
            lastNotarization.currencyState.SetLaunchClear(false);
        }

        uint32_t nextHeight = std::max(ccx.sourceHeightEnd, lastNotarization.notarizationHeight);
        if (ccx.IsPostlaunch() || lastNotarization.IsLaunchComplete())
        {
            lastNotarization.currencyState.SetLaunchCompleteMarker();
        }

        if (!lastNotarization.NextNotarizationInfo(sourceSystemDef,
                                                   destCur,
                                                   ccx.sourceHeightStart,
                                                   std::max(ccx.sourceHeightEnd, lastNotarization.notarizationHeight),
                                                   exportTransfers,
                                                   transferHash,
                                                   newNotarization,
                                                   newOutputs,
                                                   importedCurrency,
                                                   gatewayDepositsUsed,
                                                   spentCurrencyOut))
        {
            LogPrintf("%s: invalid export for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
            return false;
        }

        // after the last clear launch export is imported, we have completed launch
        if (ccx.IsClearLaunch())
        {
            newNotarization.SetLaunchComplete();
        }

        newNotarization.prevNotarization = CUTXORef(lastNotarizationOut.txIn.prevout.hash, lastNotarizationOut.txIn.prevout.n);

        CCurrencyValueMap incomingCurrency = importedCurrency + gatewayDepositsUsed;
        CCurrencyValueMap newLocalReserveDeposits;
        CCurrencyValueMap newLocalDepositsRequired;
        CAmount newPrimaryCurrency = newNotarization.currencyState.primaryCurrencyOut;
        if (newPrimaryCurrency > 0)
        {
            incomingCurrency.valueMap[destCurID] += newPrimaryCurrency;
        }
        newLocalReserveDeposits = incomingCurrency.SubtractToZero(spentCurrencyOut);
        newLocalDepositsRequired += (((incomingCurrency - spentCurrencyOut) - newLocalReserveDeposits).CanonicalMap() * -1);
        if (newPrimaryCurrency < 0)
        {
            // we need to come up with this currency, as it will be burned
            incomingCurrency.valueMap[destCurID] += newPrimaryCurrency;
            newLocalDepositsRequired.valueMap[destCurID] -= newPrimaryCurrency;
        }

        /*printf("%s: newNotarization:\n%s\n", __func__, newNotarization.ToUniValue().write(1,2).c_str());
        printf("%s: ccx.totalAmounts: %s\ngatewayDepositsUsed: %s\nimportedCurrency: %s\nspentCurrencyOut: %s\n",
            __func__,
            ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
            gatewayDepositsUsed.ToUniValue().write(1,2).c_str(),
            importedCurrency.ToUniValue().write(1,2).c_str(),
            spentCurrencyOut.ToUniValue().write(1,2).c_str());

        printf("%s: incomingCurrency: %s\ncurrencyChange: %s\nnewLocalDepositsRequired: %s\n",
            __func__,
            incomingCurrency.ToUniValue().write(1,2).c_str(),
            newLocalReserveDeposits.ToUniValue().write(1,2).c_str(),
            newLocalDepositsRequired.ToUniValue().write(1,2).c_str());
        //*/

        // create the import
        CCrossChainImport cci = CCrossChainImport(sourceSystemID,
                                                  ccx.sourceHeightEnd,
                                                  destCurID,
                                                  ccx.totalAmounts,
                                                  lastCCI.totalReserveOutMap,
                                                  newOutputs.size(),
                                                  transferHash, 
                                                  oneIT.first.first.txIn.prevout.hash, 
                                                  oneIT.first.first.txIn.prevout.n,
                                                  CCrossChainImport::FLAG_POSTLAUNCH + (lastCCI.IsDefinitionImport() ? CCrossChainImport::FLAG_INITIALLAUNCHIMPORT : 0));
        cci.SetSameChain(!useProofs);

        TransactionBuilder tb = TransactionBuilder(Params().GetConsensus(), nHeight + 1);

        CCcontract_info CC;
        CCcontract_info *cp;

        // now add the import itself
        cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
        std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci)), 0);

        // get the source system import as well
        CCrossChainImport sysCCI;
        if (useProofs)
        {
            // we need a new import for the source system
            sysCCI = cci;
            sysCCI.importCurrencyID = sysCCI.sourceSystemID;
            sysCCI.flags |= sysCCI.FLAG_SOURCESYSTEM;
            // for exports to the native chain, the system export thread is merged with currency export, so no need to go to next
            if (cci.importCurrencyID != ASSETCHAINS_CHAINID)
            {
                sysCCI.exportTxOutNum++;                        // source thread output is +1 from the input
            }
            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &sysCCI)), 0);
        }

        // add notarization first, so it will be just after the import
        cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &newNotarization)), 0);

        // add the export evidence, null for same chain or reference specific notarization + (proof + reserve transfers) if sourced from external chain
        // add evidence first, then notarization, then import, add reserve deposits after that, if necessary

        if (useProofs)
        {
            // if we need to put the partial transaction proof and follow it with reserve transfers, do it
            CNotaryEvidence evidence = CNotaryEvidence(destCurID,
                                                       CUTXORef(confirmedSourceNotarization.hash, confirmedSourceNotarization.n),
                                                       true,
                                                       std::map<CIdentityID, CIdentitySignature>(),
                                                       std::vector<CPartialTransactionProof>({oneIT.first.second}),
                                                       CNotaryEvidence::TYPE_PARTIAL_TXPROOF);

            // add notarization first, so it will be after the import
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence)), 0);

            // supplemental export evidence is posted as a supplemental export
            cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            // now add all reserve transfers in supplemental outputs
            // ensure that the output doesn't exceed script size limit
            auto transferIT = exportTransfers.begin();
            while (transferIT != exportTransfers.end())
            {
                int transferCount = exportTransfers.end() - transferIT;
                if (transferCount > 25)
                {
                    transferCount = 25;
                }

                CCrossChainExport rtSupplement = ccx;
                rtSupplement.flags = ccx.FLAG_EVIDENCEONLY + ccx.FLAG_SUPPLEMENTAL;
                rtSupplement.reserveTransfers.assign(transferIT, transferIT + transferCount);
                CScript supScript = MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &rtSupplement));
                while (GetSerializeSize(CTxOut(0, supScript), SER_NETWORK, PROTOCOL_VERSION) > supScript.MAX_SCRIPT_ELEMENT_SIZE)
                {
                    transferCount--;
                    rtSupplement.reserveTransfers.assign(transferIT, transferIT + transferCount);
                    supScript = MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &rtSupplement));
                }
                tb.AddTransparentOutput(supScript, 0);
                transferIT += transferCount;
            }
        }

        // add all importing and conversion outputs
        for (auto oneOut : newOutputs)
        {
            tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
        }

        // now, we need to spend previous import, notarization, and evidence or export finalization from export

        // spend evidence or export finalization if necessary
        // if we use proofs, spend the prior, unless we have no prior proofs to spend
        if (lastCCI.IsValid() && !lastImportTxID.IsNull())
        {
            // spend last import
            tb.AddTransparentInput(COutPoint(lastImportTxID, outputNum), lastImportTx.vout[outputNum].scriptPubKey, lastImportTx.vout[outputNum].nValue);

            // if we should add a source import input
            if (useProofs)
            {
                tb.AddTransparentInput(COutPoint(lastSourceImportTxID, sourceOutputNum), 
                                       lastSourceImportTx.vout[sourceOutputNum].scriptPubKey, lastSourceImportTx.vout[sourceOutputNum].nValue);
            }

            if (!lastNotarizationOut.txIn.prevout.hash.IsNull())
            {
                // and its notarization
                tb.AddTransparentInput(lastNotarizationOut.txIn.prevout, lastNotarizationOut.scriptPubKey, lastNotarizationOut.nValue);
            }

            if (!lastCCI.IsDefinitionImport() && lastCCI.sourceSystemID != ASSETCHAINS_CHAINID && evidenceOutNumStart >= 0)
            {
                for (int i = evidenceOutNumStart; i <= evidenceOutNumEnd; i++)
                {
                    tb.AddTransparentInput(COutPoint(lastImportTxID, i), lastImportTx.vout[i].scriptPubKey, lastImportTx.vout[i].nValue);
                }
            }
            if (!useProofs)
            {
                // if same chain and export has a finalization, spend it on import
                CObjectFinalization of;
                COptCCParams p;
                if (exportTx.vout.size() > (oneIT.first.first.txIn.prevout.n + 1) &&
                    exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_FINALIZE_EXPORT &&
                    p.vData.size() &&
                    (of = CObjectFinalization(p.vData[0])).IsValid())
                {
                    tb.AddTransparentInput(COutPoint(oneIT.first.first.txIn.prevout.hash, oneIT.first.first.txIn.prevout.n + 1), 
                                                        exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].scriptPubKey, 
                                                        exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].nValue);
                }
            }
        }

        // now, get all reserve deposits and change for both gateway reserve deposits and local reserve deposits
        CCurrencyValueMap gatewayChange;

        // add gateway deposit inputs and make a change output for those to the source system's deposits, if necessary
        std::vector<CInputDescriptor> depositsToUse;
        cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

        if (gatewayDepositsUsed.valueMap.size())
        {
            CCurrencyValueMap totalDepositsInput;

            // find all deposits intersecting with target currencies
            for (auto &oneDeposit : crossChainDeposits)
            {
                CCurrencyValueMap oneDepositVal = oneDeposit.scriptPubKey.ReserveOutValue();
                if (oneDeposit.nValue)
                {
                    oneDepositVal.valueMap[ASSETCHAINS_CHAINID] = oneDeposit.nValue;
                }
                if (gatewayDepositsUsed.Intersects(oneDepositVal))
                {
                    totalDepositsInput += oneDepositVal;
                    depositsToUse.push_back(oneDeposit);
                }
            }

            gatewayChange = totalDepositsInput - gatewayDepositsUsed;

            /*printf("%s: gatewayDepositsUsed: %s\n", __func__, gatewayDepositsUsed.ToUniValue().write(1,2).c_str());
            printf("%s: gatewayChange: %s\n", __func__, gatewayChange.ToUniValue().write(1,2).c_str());
            //*/

            // we should always be able to fulfill
            // gateway despoit requirements, or this is an error
            if (gatewayChange.HasNegative())
            {
                LogPrintf("%s: insufficient funds for gateway reserve deposits from system %s\n", __func__, EncodeDestination(CIdentityID(ccx.sourceSystemID)).c_str());
                return false;
            }
        }

        // the amount being imported is under the control of the exporting system and
        // will either be minted by the import from that system or spent on this chain from its reserve deposits
        // any remaining unmet output requirements must be met by local chain deposits as a result of conversions
        // conversion outputs may only be of the destination currency itself, or in the case of a fractional currency, 
        // the currency or its reserves.
        //
        // if this is a local import, local requirements are any spent currency besides
        //
        // change will all accrue to reserve deposits
        //

        // if this import is from another system, we will need local imports or gateway deposits to
        // cover the imported currency amount. if it is from this system, the reserve deposits are already
        // present from the export, which is also on this chain
        CCurrencyValueMap checkImportedCurrency;
        CCurrencyValueMap checkRequiredDeposits;
        if (cci.sourceSystemID != ASSETCHAINS_CHAINID &&
            (!newNotarization.currencyState.IsLaunchConfirmed() || newNotarization.currencyState.IsLaunchCompleteMarker()))
        {
            if (!ConnectedChains.CurrencyImportStatus(cci.importValue,
                                                      cci.sourceSystemID,
                                                      destCur.systemID,
                                                      checkImportedCurrency,
                                                      checkRequiredDeposits))
            {
                return false;
            }
        }

        /*printf("%s: newNotarization.currencyState: %s\n", __func__, newNotarization.currencyState.ToUniValue().write(1,2).c_str());
        printf("%s: cci: %s\n", __func__, cci.ToUniValue().write(1,2).c_str());
        printf("%s: spentcurrencyout: %s\n", __func__, spentCurrencyOut.ToUniValue().write(1,2).c_str());
        printf("%s: newcurrencyin: %s\n", __func__, incomingCurrency.ToUniValue().write(1,2).c_str());
        printf("%s: importedCurrency: %s\n", __func__, importedCurrency.ToUniValue().write(1,2).c_str());
        printf("%s: localdepositrequirements: %s\n", __func__, newLocalDepositsRequired.ToUniValue().write(1,2).c_str());
        printf("%s: checkImportedCurrency: %s\n", __func__, checkImportedCurrency.ToUniValue().write(1,2).c_str());
        printf("%s: checkRequiredDeposits: %s\n", __func__, checkRequiredDeposits.ToUniValue().write(1,2).c_str());
        //*/

        // add local reserve deposit inputs and determine change
        if (newLocalDepositsRequired.valueMap.size() ||
            localDeposits.size() ||
            incomingCurrency.valueMap.size())
        {
            CCurrencyValueMap totalDepositsInput;

            // find all deposits intersecting with target currencies
            for (auto &oneDeposit : localDeposits)
            {
                CCurrencyValueMap oneDepositVal = oneDeposit.scriptPubKey.ReserveOutValue();
                if (oneDeposit.nValue)
                {
                    oneDepositVal.valueMap[ASSETCHAINS_CHAINID] = oneDeposit.nValue;
                }
                if (newLocalDepositsRequired.Intersects(oneDepositVal))
                {
                    totalDepositsInput += oneDepositVal;
                    depositsToUse.push_back(oneDeposit);
                }
            }

            newLocalReserveDeposits = ((totalDepositsInput + incomingCurrency) - spentCurrencyOut).CanonicalMap();

            /* printf("%s: totalDepositsInput: %s\nincomingPlusDepositsMinusSpent: %s\n", 
                __func__, 
                totalDepositsInput.ToUniValue().write(1,2).c_str(),
                newLocalReserveDeposits.ToUniValue().write(1,2).c_str()); //*/

            // we should always be able to fulfill
            // local deposit requirements, or this is an error
            if (newLocalReserveDeposits.HasNegative())
            {
                LogPrintf("%s: insufficient funds for local reserve deposits for currency %s, have:\n%s, need:\n%s\n", 
                          __func__, 
                          EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(),
                          (totalDepositsInput + incomingCurrency).ToUniValue().write(1,2).c_str(),
                          spentCurrencyOut.ToUniValue().write(1,2).c_str());
                return false;
            }
        }

        // add local deposit inputs
        for (auto oneOut : depositsToUse)
        {
            tb.AddTransparentInput(oneOut.txIn.prevout, oneOut.scriptPubKey, oneOut.nValue);
        }

        /*for (auto &oneIn : tb.mtx.vin)
        {
            UniValue scriptObj(UniValue::VOBJ);
            printf("%s: oneInput - hash: %s, n: %d\n", __func__, oneIn.prevout.hash.GetHex().c_str(), oneIn.prevout.n);
        }
        //*/

        // we will keep reserve deposit change to single currency outputs to ensure aggregation of like currencies and
        // prevent fragmentation edge cases
        for (auto &oneChangeVal : gatewayChange.valueMap)
        {
            // dust rules don't apply
            if (oneChangeVal.second)
            {
                CReserveDeposit rd = CReserveDeposit(isRefundingSeparateChain ? refundingPBaaSChain.systemID : sourceSystemID, CCurrencyValueMap());;
                CAmount nativeOutput = 0;
                rd.reserveValues.valueMap[oneChangeVal.first] = oneChangeVal.second;
                if (oneChangeVal.first == ASSETCHAINS_CHAINID)
                {
                    nativeOutput = oneChangeVal.second;
                }
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd)), nativeOutput);
            }
        }

        // we will keep reserve deposit change to single currency outputs to ensure aggregation of like currencies and
        // prevent fragmentation edge cases
        for (auto &oneChangeVal : newLocalReserveDeposits.valueMap)
        {
            // dust rules don't apply
            if (oneChangeVal.second)
            {
                CReserveDeposit rd = CReserveDeposit(ccx.destCurrencyID, CCurrencyValueMap());;
                CAmount nativeOutput = 0;
                rd.reserveValues.valueMap[oneChangeVal.first] = oneChangeVal.second;
                if (oneChangeVal.first == ASSETCHAINS_CHAINID)
                {
                    nativeOutput = oneChangeVal.second;
                }
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd)), nativeOutput);
            }
        }

        CCurrencyValueMap reserveInMap = CCurrencyValueMap(newNotarization.currencyState.currencies, 
                                                           newNotarization.currencyState.reserveIn).CanonicalMap();

        // ins and outs are correct. now calculate the fee correctly here and set the transaction builder accordingly
        // to prevent an automatic change output. we could just let it go and have a setting to stop creation of a change output,
        // but this is a nice doublecheck requirement
        /*printf("%s: reserveInMap:\n%s\nspentCurrencyOut:\n%s\nccx.totalAmounts:\n%s\nccx.totalFees:\n%s\n",
                __func__,
                reserveInMap.ToUniValue().write(1,2).c_str(),
                spentCurrencyOut.ToUniValue().write(1,2).c_str(),
                ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
                ccx.totalFees.ToUniValue().write(1,2).c_str()); //*/

        // pay the fee out to the miner
        CReserveTransactionDescriptor rtxd(tb.mtx, view, nHeight + 1);
        tb.SetFee(rtxd.nativeIn - rtxd.nativeOut);
        CCurrencyValueMap reserveFees = rtxd.ReserveFees();
        if (reserveFees > CCurrencyValueMap())
        {
            tb.SetReserveFee(reserveFees);
        }

        // if we've got launch currency as the fee, it means we are mining block 1
        // send it to our current miner or notary address
        if (!ccx.IsSameChain() && ccx.IsClearLaunch())
        {
            CTxDestination addr;
            extern std::string NOTARY_PUBKEY;
            if (mapArgs.count("-mineraddress"))
            {
                addr = DecodeDestination(mapArgs["-mineraddress"]);
            }
            else if (!VERUS_NOTARYID.IsNull())
            {
                addr = VERUS_NOTARYID;
            }
            else if (!VERUS_DEFAULTID.IsNull())
            {
                addr = VERUS_DEFAULTID;
            }
            else if (!VERUS_NODEID.IsNull())
            {
                addr = CIdentityID(VERUS_NODEID);
            }
            else if (!NOTARY_PUBKEY.empty())
            {
                CPubKey pkey;
                std::vector<unsigned char> hexKey = ParseHex(NOTARY_PUBKEY);
                pkey.Set(hexKey.begin(), hexKey.end());
                addr = pkey.GetID();
            }
            tb.SendChangeTo(addr);
        }

        TransactionBuilderResult result = tb.Build();
        if (result.IsError())
        {
            /*UniValue jsonTx(UniValue::VOBJ);
            uint256 hashBlk;
            TxToUniv(tb.mtx, hashBlk, jsonTx);
            printf("%s\n", jsonTx.write(1,2).c_str()); //*/
            printf("%s: cannot build import transaction for currency %s: %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(), result.GetError().c_str());
            LogPrintf("%s: cannot build import transaction for currency %s: %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(), result.GetError().c_str());
            return false;
        }

        CTransaction newImportTx;

        try
        {
            newImportTx = result.GetTxOrThrow();
        }
        catch(const std::exception& e)
        {
            LogPrintf("%s: failure to build transaction for export to %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str());
            return false;
        }

        {
            std::set<uint256> txesToShow;
            for (auto &oneIn : newImportTx.vin)
            {
                if (!view.HaveCoins(oneIn.prevout.hash))
                {
                    printf("%s: cannot find input in view %s\n", __func__, oneIn.prevout.hash.GetHex().c_str());
                }
                else
                {
                    txesToShow.insert(oneIn.prevout.hash);
                }
            }

            /*// DEBUG output only
            for (auto &oneTxId : txesToShow)
            {
                CTransaction inputTx;
                uint256 inputBlkHash;
                if (myGetTransaction(oneTxId, inputTx, inputBlkHash))
                {
                    UniValue uni(UniValue::VOBJ);
                    TxToUniv(inputTx, inputBlkHash, uni);
                    printf("%s: inputTx:\n%s\n", __func__, uni.write(1,2).c_str());
                }
                else
                {
                    printf("%s: unable to retrieve input transaction: %s\n", __func__, oneTxId.GetHex().c_str());
                }
            } //*/

            // put our transaction in place of any others
            //std::list<CTransaction> removed;
            //mempool.removeConflicts(newImportTx, removed);

            // add to mem pool and relay
            if (!myAddtomempool(newImportTx, &state))
            {
                LogPrintf("%s: %s\n", __func__, state.GetRejectReason().c_str());
                if (state.GetRejectReason() == "bad-txns-inputs-missing" || state.GetRejectReason() == "bad-txns-inputs-duplicate")
                {
                    for (auto &oneIn : newImportTx.vin)
                    {
                        printf("{\"vin\":{\"%s\":%d}\n", oneIn.prevout.hash.GetHex().c_str(), oneIn.prevout.n);
                    }
                }
                return false;
            }
            else
            {
                //printf("%s: success adding %s to mempool\n", __func__, newImportTx.GetHash().GetHex().c_str());
                RelayTransaction(newImportTx);
            }

            if (!mempool.mapTx.count(newImportTx.GetHash()))
            {
                printf("%s: cannot find tx in mempool %s\n", __func__, newImportTx.GetHash().GetHex().c_str());
            }
            UpdateCoins(newImportTx, view, nHeight + 1);
            if (!view.HaveCoins(newImportTx.GetHash()))
            {
                printf("%s: cannot find tx in view %s\n", __func__, newImportTx.GetHash().GetHex().c_str());
            }
        }
        newImports[ccx.destCurrencyID].push_back(std::make_pair(0, newImportTx));
        if (useProofs)
        {
            /* UniValue uni(UniValue::VOBJ);
            TxToUniv(newImportTx, uint256(), uni);
            printf("%s: newImportTx:\n%s\n", __func__, uni.write(1,2).c_str()); */

            lastSourceImportTx = newImportTx;
            lastSourceCCI = sysCCI;
            lastSourceImportTxID = newImportTx.GetHash();
            sourceOutputNum = 1;
        }
    }
    return true;
}


// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// export proofs are all returned as null
bool CConnectedChains::GetSystemExports(const uint160 &systemID,
                                        std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                        uint32_t fromHeight,
                                        uint32_t toHeight,
                                        bool withProofs)
{
    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(systemID, CCrossChainExport::SystemExportKey()), 
                        CScript::P2IDX, 
                        addressIndex, 
                        fromHeight,
                        toHeight))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction exportTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
            {
                std::vector<CBaseChainObject *> opretTransfers;
                CCrossChainExport ccx;
                int exportOutputNum = idx.first.index;
                std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> coLaunchExports;
                if ((ccx = CCrossChainExport(exportTx.vout[exportOutputNum].scriptPubKey)).IsValid())
                {
                    // we are explicitly a system thread only export, so we need to attempt to
                    // read the export before us
                    if (ccx.IsSystemThreadExport())
                    {
                        if (!(exportOutputNum > 0 &&
                             (ccx = CCrossChainExport(exportTx.vout[--exportOutputNum].scriptPubKey)).IsValid() &&
                             ccx.destSystemID == systemID))
                        {
                            LogPrintf("%s: corrupt index state for transaction %s, output %d\n", __func__, idx.first.txhash.GetHex().c_str(), exportOutputNum);
                            return false;
                        }
                    }
                    else if (ccx.destSystemID == ccx.destCurrencyID &&
                             ccx.IsChainDefinition())
                    {
                        // if this includes a launch export for a currency that has a converter on the new chain co-launched,
                        // return the initial converter export information from this transaction as well
                        // we should find both the chain definition and an export to the converter currency on this transaction
                        uint160 coLaunchedID;
                        COptCCParams p;
                        for (int i = 0; i < exportTx.vout.size(); i++)
                        {
                            CCrossChainExport checkExport;

                            if (exportTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                                p.vData.size() &&
                                (checkExport = CCrossChainExport(p.vData[0])).IsValid() &&
                                checkExport.IsChainDefinition() &&
                                checkExport.destCurrencyID != checkExport.destSystemID &&
                                checkExport.destSystemID == systemID)
                            {
                                coLaunchExports.push_back(
                                    std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[i].scriptPubKey, 
                                                                                    exportTx.vout[i].nValue,
                                                                                    CTxIn(idx.first.txhash, i)), 
                                                                    CPartialTransactionProof()),
                                                    std::vector<CReserveTransfer>()));
                            }
                        }
                    }
                }
                
                if (ccx.IsValid())
                {
                    std::vector<CReserveTransfer> exportTransfers;
                    CPartialTransactionProof exportProof;

                    // get the export transfers from the source
                    if (ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                    {
                        for (int i = ccx.firstInput; i < ccx.firstInput + ccx.numInputs; i++)
                        {
                            CTransaction oneTxIn;
                            uint256 txInBlockHash;
                            if (!myGetTransaction(exportTx.vin[i].prevout.hash, oneTxIn, txInBlockHash))
                            {
                                LogPrintf("%s: cannot access transaction %s\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str());
                                return false;
                            }
                            COptCCParams oneInP;
                            if (!(oneTxIn.vout[exportTx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(oneInP) &&
                                oneInP.IsValid() &&
                                oneInP.evalCode == EVAL_RESERVE_TRANSFER &&
                                oneInP.vData.size()))
                            {
                                LogPrintf("%s: invalid reserve transfer input %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                            exportTransfers.push_back(CReserveTransfer(oneInP.vData[0]));
                            if (!exportTransfers.back().IsValid())
                            {
                                LogPrintf("%s: invalid reserve transfer input 1 %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                        }
                        // if we should make a partial transaction proof, do it
                        if (withProofs &&
                            ccx.destSystemID != ASSETCHAINS_CHAINID)
                        {
                            std::vector<int> inputsToProve;
                            if (!ccx.IsChainDefinition() && ccx.firstInput > 0)
                            {
                                inputsToProve.push_back(ccx.firstInput - 1);
                            }
                            std::vector<int> outputsToProve({exportOutputNum});
                            auto it = mapBlockIndex.find(blkHash);
                            if (it == mapBlockIndex.end())
                            {
                                LogPrintf("%s: possible corruption, cannot locate block %s for export tx\n", __func__, blkHash.GetHex().c_str());
                                return false;
                            }
                            // prove all co-launch exports
                            for (auto &oneCoLaunch : coLaunchExports)
                            {
                                assert(oneCoLaunch.first.first.txIn.prevout.hash == exportTx.GetHash());
                                oneCoLaunch.first.second = CPartialTransactionProof(exportTx,
                                                                                    std::vector<int>(),
                                                                                    std::vector<int>({(int)oneCoLaunch.first.first.txIn.prevout.n}), 
                                                                                    it->second,
                                                                                    toHeight);
                                //printf("%s: co-launch proof: %s\n", __func__, oneCoLaunch.first.second.ToUniValue().write(1,2).c_str());
                            }
                            exportProof = CPartialTransactionProof(exportTx, inputsToProve, outputsToProve, it->second, toHeight);
                            //CPartialTransactionProof checkSerProof(exportProof.ToUniValue());
                            //printf("%s: toheight: %u, txhash: %s\nserialized export proof: %s\n", __func__, toHeight, checkSerProof.TransactionHash().GetHex().c_str(), checkSerProof.ToUniValue().write(1,2).c_str());
                        }
                    }
                    else
                    {
                        LogPrintf("%s: invalid export from incorrect system on this chain in tx %s\n", __func__, idx.first.txhash.GetHex().c_str());
                        return false;
                    }

                    exports.push_back(std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[exportOutputNum].scriptPubKey, 
                                                                                     exportTx.vout[exportOutputNum].nValue,
                                                                                     CTxIn(idx.first.txhash, exportOutputNum)), 
                                                                    exportProof),
                                                     exportTransfers));
                    exports.insert(exports.end(), coLaunchExports.begin(), coLaunchExports.end());
                }
            }
        }
        return true;
    }
    return false;
}

// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// export proofs are all returned as null
bool CConnectedChains::GetLaunchNotarization(const CCurrencyDefinition &curDef,
                                             std::pair<CInputDescriptor, CPartialTransactionProof> &notarizationRef,
                                             CPBaaSNotarization &launchNotarization,
                                             CPBaaSNotarization &notaryNotarization)
{
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    uint160 currencyID = curDef.GetID();
    bool retVal = false;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::LaunchNotarizationKey()), 
                        CScript::P2IDX, 
                        addressIndex))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction notarizationTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, notarizationTx, blkHash))
            {
                CChainNotarizationData cnd;
                if ((launchNotarization = CPBaaSNotarization(notarizationTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
                     GetNotarizationData(ASSETCHAINS_CHAINID, cnd) &&
                     cnd.IsConfirmed() &&
                     (notaryNotarization = cnd.vtx[cnd.lastConfirmed].second).IsValid())
                {
                    auto blockIt = mapBlockIndex.find(blkHash);
                    if (blockIt != mapBlockIndex.end() &&
                        chainActive.Contains(blockIt->second))
                    {
                        notarizationRef.first = CInputDescriptor(notarizationTx.vout[idx.first.index].scriptPubKey,
                                                                 notarizationTx.vout[idx.first.index].nValue,
                                                                 CTxIn(idx.first.txhash, idx.first.index));
                        notarizationRef.second = CPartialTransactionProof(notarizationTx,
                                                                          std::vector<int>(),
                                                                          std::vector<int>({(int)idx.first.index}),
                                                                          blockIt->second,
                                                                          blockIt->second->GetHeight());
                        notaryNotarization.proofRoots[ASSETCHAINS_CHAINID] = CProofRoot::GetProofRoot(blockIt->second->GetHeight());
                        retVal = true;
                    }
                }
            }
        }
    }
    return retVal;
}

// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// proofs are returned as null
bool CConnectedChains::GetCurrencyExports(const uint160 &currencyID,
                                          std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                          uint32_t fromHeight,
                                          uint32_t toHeight)
{
    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CCrossChainExport::CurrencyExportKey()), 
                        CScript::P2IDX, 
                        addressIndex, 
                        fromHeight,
                        toHeight))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction exportTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
            {
                std::vector<CBaseChainObject *> opretTransfers;
                CCrossChainExport ccx;
                if ((ccx = CCrossChainExport(exportTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
                    !ccx.IsSystemThreadExport())
                {
                    std::vector<CReserveTransfer> exportTransfers;
                    CPartialTransactionProof exportProof;

                    // get the export transfers from the source
                    if (ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                    {
                        for (int i = ccx.firstInput; i < (ccx.firstInput + ccx.numInputs); i++)
                        {
                            CTransaction oneTxIn;
                            uint256 txInBlockHash;
                            if (!myGetTransaction(exportTx.vin[i].prevout.hash, oneTxIn, txInBlockHash))
                            {
                                LogPrintf("%s: cannot access transasction %s\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str());
                                return false;
                            }
                            COptCCParams oneInP;
                            if (!(oneTxIn.vout[exportTx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(oneInP) &&
                                oneInP.IsValid() &&
                                oneInP.evalCode == EVAL_RESERVE_TRANSFER &&
                                oneInP.vData.size()))
                            {
                                LogPrintf("%s: invalid reserve transfer input %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                            exportTransfers.push_back(CReserveTransfer(oneInP.vData[0]));
                            if (!exportTransfers.back().IsValid())
                            {
                                LogPrintf("%s: invalid reserve transfer input 1 %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                        }
                    }
                    else
                    {
                        LogPrintf("%s: invalid export from incorrect system on this chain in tx %s\n", __func__, idx.first.txhash.GetHex().c_str());
                        return false;
                    }

                    exports.push_back(std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[idx.first.index].scriptPubKey, 
                                                                                     exportTx.vout[idx.first.index].nValue,
                                                                                     CTxIn(idx.first.txhash, idx.first.index)), 
                                                                    exportProof),
                                                     exportTransfers));
                }
                else
                {
                    LogPrintf("%s: invalid export index for txid: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
                    return false;
                }
            }
        }
        return true;
    }
    return false;
}

bool CConnectedChains::GetPendingSystemExports(const uint160 systemID,
                                               uint32_t fromHeight,
                                               multimap<uint160, pair<int, CInputDescriptor>> &exportOutputs)
{
    CCurrencyDefinition chainDef;
    int32_t defHeight;
    exportOutputs.clear();

    if (GetCurrencyDefinition(systemID, chainDef, &defHeight))
    {
        // which transaction are we in this block?
        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

        CChainNotarizationData cnd;
        if (GetNotarizationData(systemID, cnd))
        {
            uint160 exportKey;
            if (chainDef.IsGateway())
            {
                exportKey = CCrossChainRPCData::GetConditionID(chainDef.gatewayID, CCrossChainExport::SystemExportKey());
            }
            else
            {
                exportKey = CCrossChainRPCData::GetConditionID(systemID, CCrossChainExport::SystemExportKey());
            }

            // get all export transactions including and since this one up to the confirmed cross-notarization
            if (GetAddressIndex(exportKey, CScript::P2IDX, addressIndex, fromHeight))
            {
                for (auto &idx : addressIndex)
                {
                    uint256 blkHash;
                    CTransaction exportTx;
                    if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
                    {
                        std::vector<CBaseChainObject *> opretTransfers;
                        CCrossChainExport ccx;
                        if ((ccx = CCrossChainExport(exportTx.vout[idx.first.index].scriptPubKey)).IsValid())
                        {
                            exportOutputs.insert(std::make_pair(ccx.destCurrencyID, 
                                                                std::make_pair(idx.first.blockHeight, 
                                                                               CInputDescriptor(exportTx.vout[idx.first.index].scriptPubKey, 
                                                                                                exportTx.vout[idx.first.index].nValue,
                                                                                                CTxIn(idx.first.txhash, idx.first.index)))));
                        }
                    }
                }
            }
        }
        return true;
    }
    else
    {
        LogPrintf("%s: unrecognized system name or ID\n", __func__);
        return false;
    }
}

bool CConnectedChains::CurrencyExportStatus(const CCurrencyValueMap &totalExports,
                                            const uint160 &sourceSystemID,
                                            const uint160 &destSystemID,
                                            CCurrencyValueMap &newReserveDeposits,
                                            CCurrencyValueMap &exportBurn)
{
    /* printf("%s: num transfers %ld, totalExports: %s\nnewNotarization: %s\n",
        __func__,
        exportTransfers.size(),
        totalExports.ToUniValue().write(1,2).c_str(),
        newNotarization.ToUniValue().write(1,2).c_str()); */

    // if we are exporting off of this system to a gateway or PBaaS chain, don't allow 3rd party 
    // or unregistered currencies to export. if same to same chain, all exports are ok.
    if (destSystemID != sourceSystemID)
    {
        for (auto &oneCur : totalExports.valueMap)
        {
            if (oneCur.first == sourceSystemID)
            {
                newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                continue;
            }

            CCurrencyDefinition oneCurDef;
            uint160 oneCurID;

            if (oneCur.first != oneCurID)
            {
                oneCurDef = ConnectedChains.GetCachedCurrency(oneCur.first);
                if (!oneCurDef.IsValid())
                {
                    printf("%s: Invalid currency for export or corrupt chain state\n", __func__);
                    LogPrintf("%s: Invalid currency for export or corrupt chain state\n", __func__);
                    return false;
                }
                oneCurID = oneCur.first;
            }

            // if we are exporting a gateway or PBaaS currency back to its system, we do not store it in reserve deposits
            if ((oneCurDef.IsGateway() && oneCurDef.systemID == sourceSystemID && oneCurDef.gatewayID == destSystemID) ||
                (oneCurDef.systemID != sourceSystemID && oneCurDef.systemID == destSystemID))
            {
                // we need to burn this currency here, since it will be sent back to where it was originally minted for us to keep
                // track of on this system
                exportBurn.valueMap[oneCur.first] += oneCur.second;

                // TODO: if we're exporting to a gateway or other chain, ensure that our export currency is registered for import
                //
            }
            else if (oneCurDef.systemID == sourceSystemID)
            {
                // exporting from one currency on this system to another currency on this system, store reserve deposits
                newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
            }
            else if (destSystemID != oneCurDef.systemID)
            {
                printf("%s: Cannot export from one external currency system or PBaaS chain to another external system\n", __func__);
                LogPrintf("%s: Cannot export from one external currency system or PBaaS chain to another external system\n", __func__);
                return false;
            }
        }
    }
    else
    {
        // when we export from this system to a specific currency on this system,
        // we record the reserve deposits for the destination currency to ensure they are available for imports
        // which take them as inputs.
        newReserveDeposits = totalExports;
    }
    return true;
}

bool CConnectedChains::CurrencyImportStatus(const CCurrencyValueMap &totalImports,
                                            const uint160 &sourceSystemID,
                                            const uint160 &destSystemID,
                                            CCurrencyValueMap &mintNew,
                                            CCurrencyValueMap &reserveDepositsRequired)
{
    return CurrencyExportStatus(totalImports, sourceSystemID, destSystemID, mintNew, reserveDepositsRequired);
}

bool CConnectedChains::CreateNextExport(const CCurrencyDefinition &_curDef,
                                        const std::vector<ChainTransferData> &_txInputs,
                                        const std::vector<CInputDescriptor> &priorExports,
                                        const CTxDestination &feeOutput,
                                        uint32_t sinceHeight,
                                        uint32_t curHeight, // the height of the next block
                                        int32_t inputStartNum,
                                        int32_t &inputsConsumed,
                                        std::vector<CTxOut> &exportOutputs,
                                        std::vector<CReserveTransfer> &exportTransfers,
                                        const CPBaaSNotarization &lastNotarization,
                                        const CUTXORef &lastNotarizationUTXO,
                                        CPBaaSNotarization &newNotarization,
                                        int &newNotarizationOutNum,
                                        bool createOnlyIfRequired,
                                        const ChainTransferData *addInputTx)
{
    // Accepts all reserve transfer inputs to a particular currency destination. 
    // Generates a new export transactions and any required notarizations. 
    // Observes anti-front-running rules.

    // This assumes that:
    // 1) _txInputs has all currencies since last export on this system with accurate block numbers
    // 2) _txInputs is sorted
    // 3) the last export transaction is added as input outside of this call

    AssertLockHeld(cs_main);

    newNotarization = lastNotarization;
    newNotarization.prevNotarization = lastNotarizationUTXO;
    inputsConsumed = 0;

    uint160 destSystemID = _curDef.IsGateway() ? _curDef.gatewayID : _curDef.systemID;
    uint160 currencyID = _curDef.GetID();
    bool crossSystem = destSystemID != ASSETCHAINS_CHAINID;
    bool isPreLaunch = _curDef.launchSystemID == ASSETCHAINS_CHAINID &&
                       _curDef.startBlock > sinceHeight &&
                       !lastNotarization.IsLaunchCleared();
    bool isClearLaunchExport = isPreLaunch && curHeight >= _curDef.startBlock && !lastNotarization.IsLaunchCleared();

    if (!isClearLaunchExport && !_txInputs.size() && !addInputTx)
    {
        // no error, just nothing to do
        return true;
    }

    // The aggregation rules require that:
    // 1. Either there are MIN_INPUTS of reservetransfer or MIN_BLOCKS before an 
    //    aggregation can be made as an export transaction.
    // 2. We will include as many reserveTransfers as we can, block by block until the 
    //    first block that allows us to meet MIN_INPUTS on this export.
    // 3. One additional *conversion* input may be added in the export transaction as
    //    a "what if", for the estimation API.
    //
    // If the addInputTx is included, this function will add it to the export transaction created.

    // determine inputs to include in next export
    // early out if createOnlyIfRequired is true
    std::vector<ChainTransferData> txInputs;
    if (!isClearLaunchExport &&
        sinceHeight - curHeight < CCrossChainExport::MIN_BLOCKS && 
        _txInputs.size() < CCrossChainExport::MIN_INPUTS &&
        createOnlyIfRequired)
    {
        return true;
    }

    uint32_t addHeight = sinceHeight;
    for (int inputNum = 0; inputNum < _txInputs.size(); inputNum++)
    {
        uint32_t nextHeight = std::get<0>(_txInputs[inputNum]);
        if (addHeight != nextHeight)
        {
            // if this is a launch export, we create one at the boundary
            if (isClearLaunchExport && nextHeight >= _curDef.startBlock)
            {
                addHeight = _curDef.startBlock - 1;
                break;
            }
            // if we have skipped to the next block, and we have enough to make an export, we cannot take any more
            // except the optional one to add
            if (inputNum >= CCrossChainExport::MIN_INPUTS)
            {
                break;
            }
            addHeight = nextHeight;
        }
        txInputs.push_back(_txInputs[inputNum]);
    }

    // if we made an export before getting to the end, it doesn't clear launch
    // if we either early outed, due to height or landed right on the correct height, determine launch state
    // a clear launch export may have no inputs yet still be created with a clear launch notarization
    if (isClearLaunchExport)
    {
        addHeight = _curDef.startBlock - 1;
    }

    // all we expect to add are in txInputs now
    inputsConsumed = txInputs.size();

    // check to see if we need to add the optional input, not counted as "consumed"
    if (addInputTx)
    {
        uint32_t rtHeight = std::get<0>(*addInputTx);
        CReserveTransfer reserveTransfer = std::get<2>(*addInputTx);
        // ensure that any pre-conversions or conversions are all valid, based on mined height and
        if (reserveTransfer.IsPreConversion())
        {
            printf("%s: Invalid optional pre-conversion\n", __func__);
            LogPrintf("%s: Invalid optional pre-conversion\n", __func__);
        }
        else if (reserveTransfer.IsConversion() && rtHeight < _curDef.startBlock)
        {
            printf("%s: Invalid optional conversion added before start block\n", __func__);
            LogPrintf("%s: Invalid optional conversion added before start block\n", __func__);
        }
        else
        {
            txInputs.push_back(*addInputTx);
        }
    }

    // if we are not the clear launch export and have no inputs, including the optional one, we are done
    if (!isClearLaunchExport && txInputs.size() == 0)
    {
        return true;
    }

    // currency from reserve transfers will be stored appropriately for export as follows:
    // 1) Currency with this systemID can be exported to another chain, but it will be held on this
    //    chain in a reserve deposit output. The one exception to this rule is when a gateway currency
    //    that is using this systemID is being exported to itself as the other system. In that case, 
    //    it is sent out and assumed burned from this system, just as it is created/minted when sent
    //    in from the gateway as the source system.
    //
    // 2) Currency being sent to the system of its origin is not tracked.
    //
    // 3) Currency from a system that is not this one being sent to a 3rd system is not allowed.
    //
    // get all the new reserve deposits. the only time we will merge old reserve deposit
    // outputs with current reserve deposit outputs is if there is overlap in currencies. the reserve
    // deposits for this new batch will be output together, and the currencies that are not present
    // in the new batch will be left in separate outputs, one per currency. this should enable old 
    // currencies to get aggregated but still left behind and not carried forward when they drop out 
    // of use.
    CCurrencyDefinition destSystem = ConnectedChains.GetCachedCurrency(destSystemID);

    if (!destSystem.IsValid())
    {
        printf("%s: Invalid data for export system or corrupt chain state\n", __func__);
        LogPrintf("%s: Invalid data for export system or corrupt chain state\n", __func__);
        return false;
    }

    for (int i = 0; i < txInputs.size(); i++)
    {
        exportTransfers.push_back(std::get<2>(txInputs[i]));
    }

    uint256 transferHash;
    CCurrencyValueMap importedCurrency;
    CCurrencyValueMap gatewayDepositsUsed;
    CCurrencyValueMap spentCurrencyOut;
    std::vector<CTxOut> checkOutputs;

    CPBaaSNotarization intermediateNotarization = newNotarization;
    CCrossChainExport lastExport;
    bool isPostLaunch = false;
    if ((!isPreLaunch && !isClearLaunchExport) &&
        priorExports.size() &&
        (lastExport = CCrossChainExport(priorExports[0].scriptPubKey)).IsValid() &&
        (lastExport.IsClearLaunch() ||
         intermediateNotarization.IsLaunchComplete() ||
         (destSystemID != ASSETCHAINS_CHAINID && !isPreLaunch)))
    {
        // now, all exports are post launch
        isPostLaunch = true;
        intermediateNotarization.currencyState.SetLaunchCompleteMarker();
    }

    bool forcedRefunding = false;

    // now, if we are clearing launch, determine if we should refund or launch and set notarization appropriately
    if (isClearLaunchExport)
    {
        // if we are connected to another currency, make sure it will also start before we fonfirm that we can
        CCurrencyDefinition coLaunchCurrency;
        CCoinbaseCurrencyState coLaunchState;
        if (_curDef.IsPBaaSConverter())
        {
            // PBaaS or gateway converters have a parent which is the PBaaS chain or gateway
            coLaunchCurrency = _curDef.parent == _curDef.systemID ? destSystem : ConnectedChains.GetCachedCurrency(_curDef.parent);
            if (coLaunchCurrency.IsValid() && coLaunchCurrency.IsGateway())
            {
                // if we are launching a converter for a gateway to an external system,
                // we can accept pre-launch participation from that system in currencies that it controls.
                // all accounting for such participation on a new gateway launch will be done on the external
                // system and included in cross-chain notarizations. the last cross-chain notarization to be confirmed
                // by the start block is the one that is considered final for accounting. all reservesin from
                // that notarization are considered in the actual reserves. all notarizations not finalized at that time
                // are not included and will be refunded, less the network fees.
                CChainNotarizationData cnd;
                if (GetNotarizationData(coLaunchCurrency.GetID(), cnd) &&
                    cnd.IsValid() &&
                    cnd.IsConfirmed() &&
                    cnd.vtx[cnd.lastConfirmed].second.currencyStates.count(currencyID))
                {
                    // only currencies defined by the gateway system can come from the gateway
                    // system for pre-launch
                    CCoinbaseCurrencyState &gatewayState = cnd.vtx[cnd.lastConfirmed].second.currencyStates[currencyID];
                    std::map<uint160, int32_t> curIdxMap = intermediateNotarization.currencyState.GetReserveMap();

                    // combine gateway currencies that come from the gateway with currencies from this chain
                    for (int i = 0; i < gatewayState.currencies.size(); i++)
                    {
                        auto &oneCurID = gatewayState.currencies[i];
                        if (oneCurID == ASSETCHAINS_CHAINID)
                        {
                            continue;
                        }
                        CCurrencyDefinition oneReserve = ConnectedChains.GetCachedCurrency(oneCurID);
                        if (!oneReserve.IsValid())
                        {
                            printf("%s: Unable to retrieve reserve currency definition for %s - likely corruption\n", __func__, EncodeDestination(CIdentityID(oneCurID)).c_str());
                            LogPrintf("%s: Unable to retrieve reserve currency definition for %s - likely corruption\n", __func__, EncodeDestination(CIdentityID(oneCurID)).c_str());
                            return false;
                        }
                        if (oneReserve.parent == currencyID)
                        {
                            intermediateNotarization.currencyState.reserveIn[i] = gatewayState.reserveIn.size() > i ? gatewayState.reserveIn[i] : 0;
                            intermediateNotarization.currencyState.reserves[i] = gatewayState.reserves.size() > i ? gatewayState.reserves[i] : 0;
                        }
                    }
                }
            }
            else
            {
                coLaunchState = GetCurrencyState(coLaunchCurrency, addHeight);
            }
        }
        else if (_curDef.IsPBaaSChain() && !_curDef.gatewayConverterName.empty())
        {
            coLaunchCurrency = GetCachedCurrency(_curDef.GatewayConverterID());
            if (!coLaunchCurrency.IsValid())
            {
                printf("%s: Invalid co-launch currency - likely corruption\n", __func__);
                LogPrintf("%s: Invalid co-launch currency - likely corruption\n", __func__);
                return false;
            }
            coLaunchState = GetCurrencyState(coLaunchCurrency, addHeight);
        }

        // check our currency and any co-launch currency to determine our eligibility, as ALL
        // co-launch currencies must launch for one to launch
        if (coLaunchCurrency.IsValid() &&
             CCurrencyValueMap(coLaunchCurrency.currencies, coLaunchState.reserveIn) < 
                CCurrencyValueMap(coLaunchCurrency.currencies, coLaunchCurrency.minPreconvert))
        {
            forcedRefunding = true;
        }
    }

    if (!intermediateNotarization.NextNotarizationInfo(ConnectedChains.ThisChain(),
                                                        _curDef,
                                                        sinceHeight,
                                                        addHeight,
                                                        exportTransfers,
                                                        transferHash,
                                                        newNotarization,
                                                        checkOutputs,
                                                        importedCurrency,
                                                        gatewayDepositsUsed,
                                                        spentCurrencyOut,
                                                        forcedRefunding))
    {
        printf("%s: cannot create notarization\n", __func__);
        LogPrintf("%s: cannot create notarization\n", __func__);
        return false;
    }

    //printf("%s: num transfers %ld\n", __func__, exportTransfers.size());

    // if we are refunding, redirect the export back to the launch chain
    if (newNotarization.currencyState.IsRefunding())
    {
        destSystemID = _curDef.launchSystemID;
        crossSystem = destSystemID != ASSETCHAINS_CHAINID;
        destSystem = ConnectedChains.GetCachedCurrency(destSystemID);
        if (!destSystem.IsValid())
        {
            printf("%s: Invalid data for export system or corrupt chain state\n", __func__);
            LogPrintf("%s: Invalid data for export system or corrupt chain state\n", __func__);
            return false;
        }
    }

    newNotarization.prevNotarization = lastNotarizationUTXO;

    CCurrencyValueMap totalExports;
    CCurrencyValueMap newReserveDeposits;
    CCurrencyValueMap exportBurn;

    for (int i = 0; i < exportTransfers.size(); i++)
    {
        totalExports += exportTransfers[i].TotalCurrencyOut();
    }

    /* printf("%s: num transfers %ld, totalExports: %s\nnewNotarization: %s\n",
        __func__,
        exportTransfers.size(),
        totalExports.ToUniValue().write(1,2).c_str(),
        newNotarization.ToUniValue().write(1,2).c_str()); */

    // if we are exporting off of this system to a gateway or PBaaS chain, don't allow 3rd party 
    // or unregistered currencies to export. if same to same chain, all exports are ok.
    if (destSystemID != ASSETCHAINS_CHAINID)
    {
        if (!ConnectedChains.CurrencyExportStatus(totalExports, ASSETCHAINS_CHAINID, destSystemID, newReserveDeposits, exportBurn))
        {
            return false;
        }
    }
    else
    {
        // we should have no export from this system to this system directly
        assert(currencyID != ASSETCHAINS_CHAINID);

        // when we export from this system to a specific currency on this system,
        // we record the reserve deposits for the destination currency to ensure they are available for imports
        // which take them as inputs.
        newReserveDeposits = totalExports;
    }

    // now, we have:
    // 1) those transactions that we will take
    // 2) new reserve deposits for this export
    // 3) all transfer and expected conversion fees, including those in the second leg
    // 4) total of all currencies exported, whether fee, reserve deposit, or neither
    // 5) hash of all reserve transfers to be exported
    // 6) all reserve transfers are added to our transaction inputs

    // next actions:
    // 1) create the export
    // 2) add reserve deposit output to transaction
    // 3) if destination currency is pre-launch, update notarization based on pre-conversions
    // 4) if fractional currency is target, check fees against minimums or targets based on conversion rates in currency
    // 5) if post launch, call AddReserveTransferImportOutputs to go from the old currency state and notarization to the new one
    // 6) if actual launch closure, make launch initiating export + initial notarization

    // currencies that are going into this export and not being recorded as reserve deposits will
    // have been recorded on the other side and are being unwound. they should be considered
    // burned on this system.

    // inputs can be:
    // 1. transfers of reserve or tokens for fractional reserve chains
    // 2. pre-conversions for pre-launch participation in the premine
    // 3. reserve market conversions
    //

    CCurrencyValueMap estimatedFees = CCurrencyValueMap(newNotarization.currencyState.currencies, newNotarization.currencyState.fees).CanonicalMap();

    //printf("%s: total export amounts:\n%s\n", __func__, totalAmounts.ToUniValue().write().c_str());
    CCrossChainExport ccx(ASSETCHAINS_CHAINID,
                          sinceHeight,
                          addHeight,
                          destSystemID, 
                          currencyID, 
                          exportTransfers.size(), 
                          totalExports.CanonicalMap(), 
                          estimatedFees,
                          transferHash,
                          exportBurn,
                          inputStartNum,
                          DestinationToTransferDestination(feeOutput));

    ccx.SetPreLaunch(isPreLaunch);
    ccx.SetPostLaunch(isPostLaunch);
    ccx.SetClearLaunch(isClearLaunchExport);

    // if we should add a system export, do so
    CCrossChainExport sysCCX;
    if (crossSystem && ccx.destSystemID != ccx.destCurrencyID)
    {
        if (priorExports.size() != 2)
        {
            printf("%s: Invalid prior system export for export ccx: %s\n", __func__, ccx.ToUniValue().write(1,2).c_str());
            return false;
        }
        COptCCParams p;

        if (!(priorExports[1].scriptPubKey.IsPayToCryptoCondition(p) &&
              p.IsValid() &&
              p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
              p.vData.size() &&
              (sysCCX = CCrossChainExport(p.vData[0])).IsValid()))
        {
            printf("%s: Invalid prior system export\n", __func__);
            LogPrintf("%s: Invalid prior system export\n", __func__);
            return false;
        }
        sysCCX = CCrossChainExport(ASSETCHAINS_CHAINID,
                                   sinceHeight,
                                   addHeight,
                                   destSystemID, 
                                   destSystemID, 
                                   txInputs.size(), 
                                   totalExports.CanonicalMap(), 
                                   estimatedFees,
                                   transferHash,
                                   CCurrencyValueMap(),
                                   inputStartNum,
                                   DestinationToTransferDestination(feeOutput),
                                   std::vector<CReserveTransfer>(),
                                   sysCCX.flags);
        sysCCX.SetSystemThreadExport();
    }

    CAmount nativeReserveDeposit = 0;
    if (newReserveDeposits.valueMap.count(ASSETCHAINS_CHAINID))
    {
        nativeReserveDeposit = newReserveDeposits.valueMap[ASSETCHAINS_CHAINID];
    }

    CCcontract_info CC;
    CCcontract_info *cp;

    if (newReserveDeposits.valueMap.size())
    {
        /* printf("%s: nativeDeposit %ld, reserveDeposits: %s\n",
            __func__,
            nativeReserveDeposit,
            newReserveDeposits.ToUniValue().write(1,2).c_str()); */

        // now send transferred currencies to a reserve deposit
        cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);

        // send the entire amount to a reserve deposit output of the specific chain
        // we receive our fee on the other chain, when it comes back, or if a token,
        // when it gets imported back to the chain
        std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
        // if going off-system, reserve deposits accrue to the destination system, if same system, to the currency
        CReserveDeposit rd = CReserveDeposit(crossSystem ? destSystemID : currencyID, newReserveDeposits);
        exportOutputs.push_back(CTxOut(nativeReserveDeposit, MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd))));
    }

    int exportOutNum = exportOutputs.size();

    cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
    std::vector<CTxDestination> dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
    exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx))));

    // only add an extra system export if we are really exporting to another system. refunds are redirected back.
    bool isRefunding = newNotarization.currencyState.IsRefunding();
    if (!isRefunding && crossSystem && ccx.destSystemID != ccx.destCurrencyID)
    {
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &sysCCX))));
    }

    // all exports to a currency on this chain include a finalization that is spent by the import of this export
    // external systems and gateways get one finalization for their clear to launch export
    if (isClearLaunchExport || (destSystemID == ASSETCHAINS_CHAINID && newNotarization.IsLaunchCleared()))
    {
        cp = CCinit(&CC, EVAL_FINALIZE_EXPORT);

        CObjectFinalization finalization(CObjectFinalization::FINALIZE_EXPORT, destSystemID, uint256(), exportOutNum);

        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_EXPORT, dests, 1, &finalization))));
    }

    // if this is a pre-launch export, including clear launch, update notarization and add it to the export outputs
    if (isClearLaunchExport || isPreLaunch)
    {
        newNotarizationOutNum = exportOutputs.size();
        cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &newNotarization))));
    }

    return true;
}

void CConnectedChains::AggregateChainTransfers(const CTxDestination &feeOutput, uint32_t nHeight)
{
    // all chains aggregate reserve transfer transactions, so aggregate and add all necessary export transactions to the mem pool
    {
        if (!nHeight)
        {
            return;
        }

        std::multimap<uint160, ChainTransferData> transferOutputs;

        LOCK(cs_main);

        uint160 thisChainID = ConnectedChains.ThisChain().GetID();

        uint32_t nHeight = chainActive.Height();

        // check for currencies that should launch in the last 20 blocks, haven't yet, and can have their launch export mined
        // if we find any that have no export creation pending, add it to imports
        std::vector<CAddressIndexDbEntry> rawCurrenciesToLaunch;
        std::map<uint160, std::pair<CCurrencyDefinition, CUTXORef>> launchCurrencies;
        if (GetAddressIndex(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencyLaunchKey()),
                            CScript::P2IDX, 
                            rawCurrenciesToLaunch,
                            nHeight - 30 < 0 ? 0 : nHeight - 30,
                            nHeight) &&
            rawCurrenciesToLaunch.size())
        {
            // add any unlaunched currencies as an output
            for (auto &oneDefIdx : rawCurrenciesToLaunch)
            {
                CTransaction defTx;
                uint256 hashBlk;
                COptCCParams p;
                CCurrencyDefinition oneDef;
                if (myGetTransaction(oneDefIdx.first.txhash, defTx, hashBlk) &&
                    defTx.vout.size() > oneDefIdx.first.index &&
                    defTx.vout[oneDefIdx.first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_CURRENCY_DEFINITION &&
                    p.vData.size() &&
                    (oneDef = CCurrencyDefinition(p.vData[0])).IsValid() &&
                    oneDef.launchSystemID == ASSETCHAINS_CHAINID)
                {
                    launchCurrencies.insert(std::make_pair(oneDef.GetID(), std::make_pair(oneDef, CUTXORef())));
                }
            }
        }

        // get all available transfer outputs to aggregate into export transactions
        if (GetUnspentChainTransfers(transferOutputs))
        {
            if (!(transferOutputs.size() || launchCurrencies.size()))
            {
                return;
            }

            std::vector<ChainTransferData> txInputs;
            uint160 lastChain = transferOutputs.size() ? transferOutputs.begin()->first : launchCurrencies.begin()->second.first.GetID();

            CCoins coins;
            CCoinsView dummy;
            CCoinsViewCache view(&dummy);

            LOCK(mempool.cs);

            CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
            view.SetBackend(viewMemPool);

            auto outputIt = transferOutputs.begin();
            bool checkLaunchCurrencies = false;
            for (int outputsDone = 0; 
                 outputsDone <= transferOutputs.size() || launchCurrencies.size();
                 outputsDone++)
            {
                if (outputIt != transferOutputs.end())
                {
                    auto &output = *outputIt;
                    if (output.first == lastChain)
                    {
                        txInputs.push_back(output.second);
                        outputIt++;
                        continue;
                    }
                }
                else if (checkLaunchCurrencies || !transferOutputs.size())
                {
                    // we are done with all natural exports and have deleted any launch entries that had natural exports,
                    // since they should also handle launch naturally.
                    // if we have launch currencies that have not been launched and do not have associated
                    // transfer outputs, force launch them
                    std::vector<uint160> toErase;
                    for (auto &oneLaunchCur : launchCurrencies)
                    {
                        CChainNotarizationData cnd;
                        std::vector<std::pair<CTransaction, uint256>> txes;

                        // ensure that a currency is still unlaunched before
                        // marking it for launch
                        if (!(GetNotarizationData(oneLaunchCur.first, cnd, &txes) &&
                              cnd.vtx[cnd.lastConfirmed].second.IsValid() &&
                              !(cnd.vtx[cnd.lastConfirmed].second.currencyState.IsLaunchClear() || 
                                cnd.vtx[cnd.lastConfirmed].second.IsLaunchCleared())))
                        {
                            toErase.push_back(oneLaunchCur.first);
                        }
                    }
                    for (auto &oneToErase : toErase)
                    {
                        launchCurrencies.erase(oneToErase);
                    }
                    if (launchCurrencies.size())
                    {
                        lastChain = launchCurrencies.begin()->first;
                    }
                }
                else
                {
                    // this is when we have to finish one round and then continue with currency launches
                    checkLaunchCurrencies = launchCurrencies.size() != 0;
                }

                CCurrencyDefinition destDef, systemDef;

                destDef = GetCachedCurrency(lastChain);

                if (!destDef.IsValid())
                {
                    printf("%s: cannot find destination currency %s\n", __func__, EncodeDestination(CIdentityID(lastChain)).c_str());
                    LogPrintf("%s: cannot find destination currency %s\n", __func__, EncodeDestination(CIdentityID(lastChain)).c_str());
                    break;
                }
                uint160 destID = lastChain;

                if (destDef.systemID == thisChainID)
                {
                    if (destDef.IsGateway())
                    {
                        // if the currency is a gateway on this system, any exports go through it to the gateway, not the system ID
                        systemDef = GetCachedCurrency(destDef.gatewayID);
                    }
                    else
                    {
                        systemDef = destDef;
                    }
                }
                else if (destDef.systemID == destID)
                {
                    systemDef = destDef;
                }
                else
                {
                    systemDef = GetCachedCurrency(destDef.systemID);
                }

                if (!systemDef.IsValid())
                {
                    printf("%s: cannot find destination system definition %s\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                    LogPrintf("%s: cannot find destination system definition %s\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                    break;
                }

                bool isSameChain = destDef.systemID == thisChainID;

                // when we get here, we have a consecutive number of transfer outputs to consume in txInputs
                // we need an unspent export output to export, or use the last one of it is an export to the same
                // system
                std::vector<std::pair<int, CInputDescriptor>> exportOutputs;
                std::vector<std::pair<int, CInputDescriptor>> sysExportOutputs;
                std::vector<CInputDescriptor> allExportOutputs;

                // export outputs must come from the latest, including mempool, to ensure
                // enforcement of sequential exports. get unspent currency export, and if not on the current
                // system, the external system export as well

                bool newSystem = false;
                if (launchCurrencies.count(lastChain) && destDef.systemID == lastChain)
                {
                    newSystem = true;
                }

                if (((ConnectedChains.GetUnspentCurrencyExports(view, lastChain, exportOutputs) && exportOutputs.size()) || newSystem) &&
                    (isSameChain || (ConnectedChains.GetUnspentSystemExports(view, destDef.systemID, sysExportOutputs) && sysExportOutputs.size())))
                {
                    if (!exportOutputs.size())
                    {
                        exportOutputs.push_back(sysExportOutputs[0]);
                    }
                    assert(exportOutputs.size() == 1);
                    std::pair<int, CInputDescriptor> lastExport = exportOutputs[0];
                    allExportOutputs.push_back(lastExport.second);
                    std::pair<int, CInputDescriptor> lastSysExport = std::make_pair(-1, CInputDescriptor());
                    if (!isSameChain)
                    {
                        lastSysExport = sysExportOutputs[0];
                        allExportOutputs.push_back(lastSysExport.second);
                    }

                    COptCCParams p;
                    CCrossChainExport ccx, sysCCX;
                    if (!(lastExport.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                          p.IsValid() &&
                          p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                          p.vData.size() &&
                          (ccx = CCrossChainExport(p.vData[0])).IsValid()) ||
                        !(isSameChain ||
                          (lastSysExport.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                           p.IsValid() &&
                           p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                           p.vData.size() &&
                           (sysCCX = CCrossChainExport(p.vData[0])).IsValid())))
                    {
                        printf("%s: invalid export(s) for %s in index\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                        LogPrintf("%s: invalid export(s) for %s in index\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                        break;
                    }

                    // now, in the case that these are both the same export, and/or if this is a sys export thread export
                    // merge into one export
                    bool mergedSysExport = false;
                    if (!isSameChain &&
                        ccx.destCurrencyID == ccx.destSystemID)
                    {
                        ccx.SetSystemThreadExport(false);
                        mergedSysExport = true;
                        // remove the system output
                        allExportOutputs.pop_back();
                    }

                    // now, we have the previous export to this currency/system, which we should spend to
                    // enable this new export. if we find no export, we're done
                    int32_t numInputsUsed;
                    std::vector<CTxOut> exportTxOuts;
                    std::vector<CReserveTransfer> exportTransfers;
                    CChainNotarizationData cnd;
                    std::vector<std::pair<CTransaction, uint256>> notarizationTxes;
                    
                    // get notarization for the actual currency we are exporting
                    if (!GetNotarizationData(lastChain, cnd, &notarizationTxes) || cnd.lastConfirmed == -1)
                    {
                        printf("%s: missing or invalid notarization for %s\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                        LogPrintf("%s: missing or invalid notarization for %s\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                        break;
                    }

                    CPBaaSNotarization lastNotarization = cnd.vtx[cnd.lastConfirmed].second;
                    CInputDescriptor lastNotarizationInput = 
                        CInputDescriptor(notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].scriptPubKey,
                                         notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].nValue,
                                         CTxIn(cnd.vtx[cnd.lastConfirmed].first));
                    CPBaaSNotarization newNotarization;
                    int newNotarizationOutNum;

                    if (lastNotarization.currencyState.IsFractional() && lastNotarization.IsPreLaunch() && destDef.startBlock > nHeight)
                    {
                        // on pre-launch, we need to ensure no overflow in first pass, so we normalize expected pricing
                        // on the way in
                        CCoinbaseCurrencyState pricesState = ConnectedChains.GetCurrencyState(destDef, nHeight);
                        assert(lastNotarization.currencyState.IsValid() && lastNotarization.currencyState.GetID() == lastChain);
                        lastNotarization.currencyState.conversionPrice = pricesState.PricesInReserve();
                    }

                    while (txInputs.size() || launchCurrencies.count(lastChain))
                    {
                        launchCurrencies.erase(lastChain);
                        //printf("%s: launchCurrencies.size(): %ld\n", __func__, launchCurrencies.size());

                        // even if we have no txInputs, currencies that need to will launch
                        newNotarizationOutNum = -1;
                        if (!CConnectedChains::CreateNextExport(destDef,
                                                                txInputs,
                                                                allExportOutputs,
                                                                feeOutput,
                                                                ccx.sourceHeightEnd,
                                                                nHeight + 1,
                                                                (!isSameChain && !mergedSysExport) ? 2 : 1, // reserve transfers start at input 1 on same chain or after sys
                                                                numInputsUsed,
                                                                exportTxOuts,
                                                                exportTransfers,
                                                                lastNotarization,
                                                                CUTXORef(lastNotarizationInput.txIn.prevout),
                                                                newNotarization,
                                                                newNotarizationOutNum))
                        {
                            printf("%s: unable to create export for %s\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                            LogPrintf("%s: unable to create export for  %s\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                            break;
                        }

                        // now, if we have created any outputs, we have a transaction to make, if not, we are done
                        if (!exportTxOuts.size())
                        {
                            txInputs.clear();
                            break;
                        }

                        if (newNotarization.IsRefunding() && destDef.launchSystemID == ASSETCHAINS_CHAINID)
                        {
                            isSameChain = true;
                        }

                        TransactionBuilder tb(Params().GetConsensus(), nHeight + 1);
                        tb.SetFee(0);

                        // add input from last export, all consumed txInputs, and all outputs created to make 
                        // the new export tx. since we are exporting from this chain

                        //UniValue scriptUniOut;
                        //ScriptPubKeyToUniv(lastExport.second.scriptPubKey, scriptUniOut, false);
                        //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), lastExport.second.nValue, scriptUniOut.write(1,2).c_str());

                        // first add previous export
                        tb.AddTransparentInput(lastExport.second.txIn.prevout, lastExport.second.scriptPubKey, lastExport.second.nValue);

                        // if going to another system, add the system export thread as well
                        if (!isSameChain && !mergedSysExport)
                        {
                            //scriptUniOut = UniValue(UniValue::VOBJ);
                            //ScriptPubKeyToUniv(lastSysExport.second.scriptPubKey, scriptUniOut, false);
                            //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), lastSysExport.second.nValue, scriptUniOut.write(1,2).c_str());

                            tb.AddTransparentInput(lastSysExport.second.txIn.prevout, lastSysExport.second.scriptPubKey, lastSysExport.second.nValue);
                        }

                        // now, all reserve transfers
                        for (int i = 0; i < numInputsUsed; i++)
                        {
                            CInputDescriptor inputDesc = std::get<1>(txInputs[i]);

                            //scriptUniOut = UniValue(UniValue::VOBJ);
                            //ScriptPubKeyToUniv(inputDesc.scriptPubKey, scriptUniOut, false);
                            //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), inputDesc.nValue, scriptUniOut.write(1,2).c_str());

                            tb.AddTransparentInput(inputDesc.txIn.prevout, inputDesc.scriptPubKey, inputDesc.nValue);
                        }

                        // if we have an output notarization, spend the last one
                        if (newNotarizationOutNum >= 0)
                        {
                            //scriptUniOut = UniValue(UniValue::VOBJ);
                            //ScriptPubKeyToUniv(lastNotarizationInput.scriptPubKey, scriptUniOut, false);
                            //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), lastNotarizationInput.nValue, scriptUniOut.write(1,2).c_str());

                            tb.AddTransparentInput(lastNotarizationInput.txIn.prevout, 
                                                   lastNotarizationInput.scriptPubKey, 
                                                   lastNotarizationInput.nValue);
                        }

                        // now, add all outputs to the transaction
                        auto thisExport = lastExport;
                        int outputNum = tb.mtx.vout.size();
                        for (auto &oneOut : exportTxOuts)
                        {
                            COptCCParams xp;
                            CCrossChainExport checkCCX;
                            if (oneOut.scriptPubKey.IsPayToCryptoCondition(xp) &&
                                xp.IsValid() && 
                                xp.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                                (checkCCX = CCrossChainExport(xp.vData[0])).IsValid() &&
                                !checkCCX.IsSystemThreadExport())
                            {
                                thisExport.second.scriptPubKey = oneOut.scriptPubKey;
                                thisExport.second.nValue = oneOut.nValue;
                                thisExport.first = nHeight;
                                thisExport.second.txIn.prevout.n = outputNum;
                            }

                            /* scriptUniOut = UniValue(UniValue::VOBJ);
                            ScriptPubKeyToUniv(oneOut.scriptPubKey, scriptUniOut, false);
                            printf("%s: adding output %d with %ld nValue and script:\n%s\n", __func__, (int)tb.mtx.vout.size(), oneOut.nValue, scriptUniOut.write(1,2).c_str());
                            */

                            tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
                            outputNum++;
                        }

                        /* UniValue uni(UniValue::VOBJ);
                        TxToUniv(tb.mtx, uint256(), uni);
                        printf("%s: Ready to build tx:\n%s\n", __func__, uni.write(1,2).c_str()); */

                        TransactionBuilderResult buildResult(tb.Build());

                        if (!buildResult.IsError() && buildResult.IsTx())
                        {
                            // replace the last one only if we have a valid new one
                            CTransaction tx = buildResult.GetTxOrThrow();

                            if (newNotarizationOutNum >= 0)
                            {
                                lastNotarization = newNotarization;
                                lastNotarizationInput = CInputDescriptor(tx.vout[newNotarizationOutNum].scriptPubKey,
                                                                         tx.vout[newNotarizationOutNum].nValue,
                                                                         CTxIn(tx.GetHash(), newNotarizationOutNum));
                            }

                            /* uni = UniValue(UniValue::VOBJ);
                            TxToUniv(tx, uint256(), uni);
                            printf("%s: successfully built tx:\n%s\n", __func__, uni.write(1,2).c_str()); */

                            LOCK2(cs_main, mempool.cs);
                            static int lastHeight = 0;
                            // remove conflicts, so that we get in
                            std::list<CTransaction> removed;
                            mempool.removeConflicts(tx, removed);

                            // add to mem pool, prioritize according to the fee we will get, and relay
                            //printf("Created and signed export transaction %s\n", tx.GetHash().GetHex().c_str());
                            //LogPrintf("Created and signed export transaction %s\n", tx.GetHash().GetHex().c_str());
                            if (myAddtomempool(tx))
                            {
                                uint256 hash = tx.GetHash();
                                thisExport.second.txIn.prevout.hash = hash;
                                lastExport = thisExport;
                                CAmount nativeExportFees = ccx.totalFees.valueMap[ASSETCHAINS_CHAINID] ? ccx.totalFees.valueMap[ASSETCHAINS_CHAINID] : 10000;
                                mempool.PrioritiseTransaction(hash, hash.GetHex(), (double)(nativeExportFees << 1), nativeExportFees);
                            }
                            else
                            {
                                UniValue uni(UniValue::VOBJ);
                                TxToUniv(tx, uint256(), uni);
                                //printf("%s: created invalid transaction:\n%s\n", __func__, uni.write(1,2).c_str());
                                LogPrintf("%s: created invalid transaction:\n%s\n", __func__, uni.write(1,2).c_str());
                                break;
                            }
                            UpdateCoins(tx, view, nHeight + 1);
                        }
                        else
                        {
                            // we can't do any more useful work for this chain if we failed here
                            printf("Failed to create export transaction: %s\n", buildResult.GetError().c_str());
                            LogPrintf("Failed to create export transaction: %s\n", buildResult.GetError().c_str());
                            break;
                        }

                        // erase the inputs we've attempted to spend and loop for another export tx
                        if (numInputsUsed)
                        {
                            txInputs.erase(txInputs.begin(), txInputs.begin() + numInputsUsed);
                        }
                    }
                }
                txInputs.clear();
                launchCurrencies.erase(lastChain);

                if (outputIt != transferOutputs.end())
                {
                    lastChain = outputIt->first;
                    txInputs.push_back(outputIt->second);
                    outputIt++;
                }
            }
            CheckImports();
        }
    }
}

void CConnectedChains::SignAndCommitImportTransactions(const CTransaction &lastImportTx, const std::vector<CTransaction> &transactions)
{
    int nHeight = chainActive.LastTip()->GetHeight();
    uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, Params().GetConsensus());
    LOCK2(cs_main, mempool.cs);

    uint256 lastHash, lastSignedHash;
    CCoinsViewCache view(pcoinsTip);

    // sign and commit the transactions
    for (auto &_tx : transactions)
    {
        CMutableTransaction newTx(_tx);

        if (!lastHash.IsNull())
        {
            //printf("last hash before signing: %s\n", lastHash.GetHex().c_str());
            for (auto &oneIn : newTx.vin)
            {
                //printf("checking input with hash: %s\n", oneIn.prevout.hash.GetHex().c_str());
                if (oneIn.prevout.hash == lastHash)
                {
                    oneIn.prevout.hash = lastSignedHash;
                    //printf("updated hash before signing: %s\n", lastSignedHash.GetHex().c_str());
                }
            }
        }
        lastHash = _tx.GetHash();
        CTransaction tx = newTx;

        // sign the transaction and submit
        bool signSuccess = false;
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
                CCoins coins;
                if (!view.GetCoins(tx.vin[i].prevout.hash, coins))
                {
                    fprintf(stderr,"%s: cannot get input coins from tx: %s, output: %d\n", __func__, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    LogPrintf("%s: cannot get input coins from tx: %s, output: %d\n", __func__, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    break;
                }
                value = coins.vout[tx.vin[i].prevout.n].nValue;
                outputScript = coins.vout[tx.vin[i].prevout.n].scriptPubKey;
            }

            signSuccess = ProduceSignature(TransactionSignatureCreator(nullptr, &tx, i, value, SIGHASH_ALL), outputScript, sigdata, consensusBranchId);

            if (!signSuccess)
            {
                fprintf(stderr,"%s: failure to sign transaction\n", __func__);
                LogPrintf("%s: failure to sign transaction\n", __func__);
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

            //DEBUGGING
            //TxToJSON(tx, uint256(), jsonTX);
            //printf("signed transaction:\n%s\n", jsonTX.write(1, 2).c_str());

            if (!AcceptToMemoryPool(mempool, state, signedTx, false, &fMissingInputs)) {
                if (state.IsInvalid()) {
                    //UniValue txUni(UniValue::VOBJ);
                    //TxToUniv(signedTx, uint256(), txUni);
                    //fprintf(stderr,"%s: rejected by memory pool for %s\n%s\n", __func__, state.GetRejectReason().c_str(), txUni.write(1,2).c_str());
                    LogPrintf("%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                } else {
                    if (fMissingInputs) {
                        fprintf(stderr,"%s: missing inputs\n", __func__);
                        LogPrintf("%s: missing inputs\n", __func__);
                    }
                    else
                    {
                        fprintf(stderr,"%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                        LogPrintf("%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                    }
                }
                break;
            }
            else
            {
                UpdateCoins(signedTx, view, nHeight + 1);
                lastSignedHash = signedTx.GetHash();
            }
        }
        else
        {
            break;
        }
    }
}

// process token related, local imports and exports
void CConnectedChains::ProcessLocalImports()
{
    // first determine all exports to the current/same system marked for action
    // next, get the last import of each export thread, package all pending exports,
    // and call CreateLatestImports

    std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> exportsOut;
    uint160 thisChainID = thisChain.GetID();

    LOCK(cs_main);
    uint32_t nHeight = chainActive.Height();

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::set<uint160> currenciesProcessed;
    uint160 finalizeExportKey(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CObjectFinalization::ObjectFinalizationExportKey()));

    if (GetAddressUnspent(finalizeExportKey, CScript::P2IDX, unspentOutputs))
    {
        std::map<uint160, std::map<uint32_t, std::pair<std::pair<CInputDescriptor,CTransaction>,CCrossChainExport>>> 
            orderedExportsToFinalize;
        for (auto &oneFinalization : unspentOutputs)
        {
            COptCCParams p;
            CObjectFinalization of;
            CCrossChainExport ccx;
            CCrossChainImport cci;
            CTransaction scratchTx;
            int32_t importOutputNum;
            uint256 hashBlock;
            if (oneFinalization.second.script.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_EXPORT &&
                p.vData.size() &&
                (of = CObjectFinalization(p.vData[0])).IsValid() &&
                myGetTransaction(of.output.hash.IsNull() ? oneFinalization.first.txhash : of.output.hash, scratchTx, hashBlock) &&
                scratchTx.vout.size() > of.output.n &&
                scratchTx.vout[of.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                p.vData.size() &&
                (ccx = CCrossChainExport(p.vData[0])).IsValid())
            {
                orderedExportsToFinalize[ccx.destCurrencyID].insert(
                    std::make_pair(ccx.sourceHeightStart, 
                                   std::make_pair(std::make_pair(CInputDescriptor(scratchTx.vout[of.output.n].scriptPubKey, 
                                                                                  scratchTx.vout[of.output.n].nValue,
                                                                                  CTxIn(of.output.hash.IsNull() ? oneFinalization.first.txhash : of.output.hash,
                                                                                  of.output.n)),
                                                                 scratchTx),
                                                  ccx)));
            }
        }
        // now, we have a map of all currencies with ordered exports that have work to do and if pre-launch, may have more from this chain
        // export finalizations are either on the same transaction as the export, or in the case of a clear launch export,
        // there may be any number of pre-launch exports still to process prior to spending it
        for (auto &oneCurrencyExports : orderedExportsToFinalize)
        {
            CCrossChainExport &ccx = oneCurrencyExports.second.begin()->second.second;
            COptCCParams p;
            CCrossChainImport cci;
            CTransaction scratchTx;
            int32_t importOutputNum;
            uint256 hashBlock;
            if (GetLastImport(ccx.destCurrencyID, scratchTx, importOutputNum) &&
                scratchTx.vout.size() > importOutputNum &&
                scratchTx.vout[importOutputNum].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (cci = CCrossChainImport(p.vData[0])).IsValid() &&
                (cci.IsPostLaunch() || cci.IsDefinitionImport() || cci.sourceSystemID == ASSETCHAINS_CHAINID))
            {
                // if not post launch, we are launching from this chain and need to get exports after the last import's source height
                if (!cci.IsPostLaunch())
                {
                    std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> exportsFound;
                    if (GetCurrencyExports(ccx.destCurrencyID, exportsFound, cci.sourceSystemHeight, nHeight))
                    {
                        uint256 cciExportTxHash = cci.exportTxId.IsNull() ? scratchTx.GetHash() : cci.exportTxId;
                        if (exportsFound.size())
                        {
                            // make sure we start from the first export not imported and skip the rest
                            auto startingIt = exportsFound.begin();
                            for ( ; startingIt != exportsFound.end(); startingIt++)
                            {
                                // if this is the first. then the first is the one we will always use
                                if (cci.IsDefinitionImport())
                                {
                                    break;
                                }
                                if (startingIt->first.first.txIn.prevout.hash == cciExportTxHash && startingIt->first.first.txIn.prevout.n == cci.exportTxOutNum)
                                {
                                    startingIt++;
                                    break;
                                }
                            }
                            exportsOut.insert(exportsOut.end(), startingIt, exportsFound.end());
                        }
                        currenciesProcessed.insert(ccx.destCurrencyID);
                    }
                    continue;
                }
                else
                {
                    // import all entries that are present, since that is the correct set
                    for (auto &oneExport : oneCurrencyExports.second)
                    {
                        int primaryExportOutNumOut;
                        int32_t nextOutput;
                        CPBaaSNotarization exportNotarization;
                        std::vector<CReserveTransfer> reserveTransfers;

                        if (!oneExport.second.second.GetExportInfo(oneExport.second.first.second,
                                                                   oneExport.second.first.first.txIn.prevout.n,
                                                                   primaryExportOutNumOut,
                                                                   nextOutput,
                                                                   exportNotarization,
                                                                   reserveTransfers))
                        {
                            printf("%s: Invalid export output %s : output - %u\n",
                                __func__, 
                                oneExport.second.first.first.txIn.prevout.hash.GetHex().c_str(),
                                oneExport.second.first.first.txIn.prevout.n);
                            break;
                        }
                        exportsOut.push_back(std::make_pair(std::make_pair(oneExport.second.first.first, CPartialTransactionProof()),
                                                            reserveTransfers));
                    }
                }
            }
        }
    }

    std::map<uint160, std::vector<std::pair<int, CTransaction>>> newImports;
    if (exportsOut.size())
    {
        CreateLatestImports(thisChain, CUTXORef(), exportsOut, newImports);
    }
}

std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>>
GetPendingExports(const CCurrencyDefinition &sourceChain, 
                  const CCurrencyDefinition &destChain,
                  CPBaaSNotarization &lastConfirmed,
                  CUTXORef &lastConfirmedUTXO)
{
    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;
    uint160 sourceChainID = sourceChain.GetID();
    uint160 destChainID = destChain.GetID();

    assert(sourceChainID != destChainID);   // this function is only for cross chain exports to or from another system

    // right now, we only communicate automatically to the first notary and back
    uint160 notaryID = ConnectedChains.FirstNotaryChain().GetID();
    assert((sourceChainID == ASSETCHAINS_CHAINID && destChainID == notaryID) || (sourceChainID == notaryID && destChainID == ASSETCHAINS_CHAINID));

    bool exportsToNotary = destChainID == notaryID;

    bool found = false;
    CAddressUnspentDbEntry foundEntry;
    CCrossChainImport lastCCI;

    // if exporting to our notary chain, we need to get the latest notarization and import from that
    // chain. we only have business sending exports if we have pending exports provable by the last
    // notarization and after the last import.
    if (exportsToNotary && ConnectedChains.IsNotaryAvailable())
    {
        UniValue params(UniValue::VARR);
        UniValue result;
        params.push_back(EncodeDestination(CIdentityID(sourceChainID)));

        CPBaaSNotarization pbn;

        try
        {
            result = find_value(RPCCallRoot("getlastimportfrom", params), "result");
            pbn = CPBaaSNotarization(find_value(result, "lastconfirmednotarization"));
            found = true;
        } catch (...)
        {
            LogPrintf("%s: Could not get last import from external chain %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        if (!pbn.IsValid())
        {
            LogPrintf("%s: Invalid notarization from external chain %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        lastCCI = CCrossChainImport(find_value(result, "lastimport"));
        if (!lastCCI.IsValid())
        {
            LogPrintf("%s: Invalid last import from external chain %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        if (!pbn.proofRoots.count(sourceChainID))
        {
            LogPrintf("%s: No adequate notarization available yet to support export to %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        lastConfirmed = pbn;
        lastConfirmedUTXO = CUTXORef(find_value(result, "lastconfirmedutxo"));
        if (lastConfirmedUTXO.hash.IsNull() || lastConfirmedUTXO.n < 0)
        {
            LogPrintf("%s: No confirmed notarization available to support export to %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
    }
    else if (!exportsToNotary)
    {
        LOCK(cs_main);
        std::vector<CAddressUnspentDbEntry> unspentOutputs;

        CChainNotarizationData cnd;
        if (!GetNotarizationData(sourceChainID, cnd) ||
            !cnd.IsConfirmed() ||
            !(lastConfirmed = cnd.vtx[cnd.lastConfirmed].second).proofRoots.count(sourceChainID))
        {
            LogPrintf("%s: Unable to get notarization data for %s\n", __func__, EncodeDestination(CIdentityID(sourceChainID)).c_str());
            return exports;
        }

        lastConfirmedUTXO = cnd.vtx[cnd.lastConfirmed].first;

        if (GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(sourceChainID, CCrossChainImport::CurrencySystemImportKey())), CScript::P2IDX, unspentOutputs))
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
        }
    }

    if (found && 
        lastCCI.sourceSystemHeight < lastConfirmed.proofRoots[sourceChainID].rootHeight)
    {
        UniValue params(UniValue::VARR);
        params = UniValue(UniValue::VARR);
        params.push_back(EncodeDestination(CIdentityID(destChainID)));
        params.push_back((int64_t)lastCCI.sourceSystemHeight);
        params.push_back((int64_t)lastConfirmed.proofRoots[sourceChainID].rootHeight);

        UniValue result = NullUniValue;
        try
        {
            if (sourceChainID == ASSETCHAINS_CHAINID)
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
            printf("Could not get latest export from external chain %s\n", uni_get_str(params[0]).c_str());
            return exports;
        }

        // now, we should have a list of exports to import in order
        if (!result.isArray() || !result.size())
        {
            return exports;
        }

        LOCK(cs_main);

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
                return exports;
            }

            CTransaction exportTx;
            uint256 blkHash;
            auto proofRootIt = lastConfirmed.proofRoots.find(sourceChainID);
            if (!(txProof.IsValid() &&
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
                return exports;
            }
            else if (!(myGetTransaction(exportTxId, exportTx, blkHash) &&
                    exportTx.vout.size() > exportTxOutNum))
            {
                printf("Invalid export msg2 from %s\n", uni_get_str(params[0]).c_str());
                return exports;
            }
            if (!foundCurrent)
            {
                CCrossChainExport ccx(exportTx.vout[exportTxOutNum].scriptPubKey);
                if (!ccx.IsValid())
                {
                    printf("Invalid export msg3 from %s\n", uni_get_str(params[0]).c_str());
                    return exports;
                }
                if (ccx.IsChainDefinition() || ccx.sourceHeightEnd == 1)
                {
                    if (lastCCI.exportTxId.IsNull())
                    {
                        foundCurrent = true;
                    }
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
                    return exports;
                }
            }
            exports.push_back(oneExport);
        }
    }
    return exports;
}

void CConnectedChains::SubmissionThread()
{
    try
    {
        arith_uint256 lastHash;
        int64_t lastImportTime = 0;
        
        // wait for something to check on, then submit blocks that should be submitted
        while (true)
        {
            boost::this_thread::interruption_point();

            uint32_t height = chainActive.LastTip() ? chainActive.LastTip()->GetHeight() : 0;

            // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
            if (height > (CPBaaSNotarization::BLOCK_NOTARIZATION_MODULO + CPBaaSNotarization::MIN_BLOCKS_BEFORE_NOTARY_FINALIZED) &&
                IsNotaryAvailable(true) &&
                lastImportTime < (GetAdjustedTime() - 30))
            {
                // check for exports on this chain that we should send to the notary and do so
                // exports to another native system should be exported to that system and to the currency
                // of this system on that system
                lastImportTime = GetAdjustedTime();

                std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;
                CPBaaSNotarization lastConfirmed;
                CUTXORef lastConfirmedUTXO;
                exports = GetPendingExports(ConnectedChains.ThisChain(),
                                            ConnectedChains.FirstNotaryChain().chainDefinition,
                                            lastConfirmed,
                                            lastConfirmedUTXO);
                if (exports.size())
                {
                    bool success = true;
                    UniValue exportParamObj(UniValue::VOBJ);

                    exportParamObj.pushKV("sourcesystemid", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
                    exportParamObj.pushKV("notarizationtxid", lastConfirmedUTXO.hash.GetHex());
                    exportParamObj.pushKV("notarizationtxoutnum", (int)lastConfirmedUTXO.n);

                    UniValue exportArr(UniValue::VARR);
                    for (auto &oneExport : exports)
                    {
                        if (!oneExport.first.second.IsValid())
                        {
                            success = false;
                            break;
                        }
                        UniValue oneExportUni(UniValue::VOBJ);
                        oneExportUni.pushKV("txid", oneExport.first.first.txIn.prevout.hash.GetHex());
                        oneExportUni.pushKV("txoutnum", (int)oneExport.first.first.txIn.prevout.n);
                        oneExportUni.pushKV("partialtransactionproof", oneExport.first.second.ToUniValue());
                        UniValue rtArr(UniValue::VARR);
                        for (auto &oneTransfer : oneExport.second)
                        {
                            rtArr.push_back(oneTransfer.ToUniValue());
                        }
                        oneExportUni.pushKV("transfers", rtArr);
                        exportArr.push_back(oneExportUni);
                    }

                    exportParamObj.pushKV("exports", exportArr);

                    UniValue params(UniValue::VARR);
                    params.push_back(exportParamObj);
                    UniValue result = NullUniValue;
                    try
                    {
                        result = find_value(RPCCallRoot("submitimports", params), "result");
                    } catch (exception e)
                    {
                        LogPrintf("%s: Error submitting imports to notary chain %s\n", uni_get_str(params[0]).c_str());
                    }
                }
            }

            bool submit = false;
            if (IsVerusActive())
            {
                // blocks get discarded after no refresh for 90 seconds by default, probably should be more often
                //printf("SubmissionThread: pruning\n");
                PruneOldChains(GetAdjustedTime() - 90);
                {
                    LOCK(cs_mergemining);
                    if (mergeMinedChains.size() == 0 && qualifiedHeaders.size() != 0)
                    {
                        qualifiedHeaders.clear();
                    }
                    submit = qualifiedHeaders.size() != 0 && mergeMinedChains.size() != 0;

                    //printf("SubmissionThread: qualifiedHeaders.size(): %lu, mergeMinedChains.size(): %lu\n", qualifiedHeaders.size(), mergeMinedChains.size());
                }
                if (submit)
                {
                    //printf("SubmissionThread: calling submit qualified blocks\n");
                    SubmitQualifiedBlocks();
                }
            }

            if (!submit && !FirstNotaryChain().IsValid())
            {
                sem_submitthread.wait();
            }
            else
            {
                MilliSleep(500);
            }
            boost::this_thread::interruption_point();
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("Verus merge mining thread terminated\n");
    }
}

void CConnectedChains::SubmissionThreadStub()
{
    ConnectedChains.SubmissionThread();
}

void CConnectedChains::QueueEarnedNotarization(CBlock &blk, int32_t txIndex, int32_t height)
{
    // called after winning a block that contains an earned notarization
    // the earned notarization and its height are queued for processing by the submission thread
    // when a new notarization is added, older notarizations are removed, but all notarizations in the current height are
    // kept
    LOCK(cs_mergemining);

    // we only care about the last
    earnedNotarizationHeight = height;
    earnedNotarizationBlock = blk;
    earnedNotarizationIndex = txIndex;
}

bool IsCurrencyDefinitionInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_CURRENCY_DEFINITION;
}

