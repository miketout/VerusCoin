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
#include <map>

CConnectedChains ConnectedChains;
extern uint32_t KOMODO_STOPAT;

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
        const CChainObject<CHashCommitments> *pPriors;
        const CChainObject<CProofRoot> *pNewProofRoot;
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

        case CHAINOBJ_COMMITMENTDATA:
            return pPriors->GetHash();

        case CHAINOBJ_PROOF_ROOT:
            return ::GetHash(pNewProofRoot->object);

        case CHAINOBJ_RESERVETRANSFER:
            return pExport->GetHash();

        case CHAINOBJ_CROSSCHAINPROOF:
            return pCrossChainProof->GetHash();

        case CHAINOBJ_COMPOSITEOBJECT:
            return pCrossChainProof->GetHash();

    }
    return uint256();
}

CCrossChainExport GetExportToSpend(const CTransaction &spendingTx, uint32_t nIn, CTransaction &sourceTx, uint32_t &height, COptCCParams &p)
{
    // if not fulfilled, ensure that no part of the primary identity is modified
    CCrossChainExport oldExport;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        auto bIt = blkHash.IsNull() ? mapBlockIndex.end() : mapBlockIndex.find(blkHash);
        if (bIt == mapBlockIndex.end() || !bIt->second)
        {
            height = chainActive.Height();
        }
        else
        {
            height = bIt->second->GetHeight();
        }

        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() && 
            p.evalCode == EVAL_CROSSCHAIN_EXPORT && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldExport = CCrossChainExport(p.vData[0]);
        }
    }
    return oldExport;
}

CCrossChainImport GetImportToSpend(const CTransaction &spendingTx, uint32_t nIn, CTransaction &sourceTx, uint32_t &height, COptCCParams &p)
{
    // if not fulfilled, ensure that no part of the primary identity is modified
    CCrossChainImport oldImport;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        auto bIt = blkHash.IsNull() ? mapBlockIndex.end() : mapBlockIndex.find(blkHash);
        if (bIt == mapBlockIndex.end() || !bIt->second)
        {
            height = chainActive.Height();
        }
        else
        {
            height = bIt->second->GetHeight();
        }

        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() && 
            p.evalCode == EVAL_CROSSCHAIN_IMPORT && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldImport = CCrossChainImport(p.vData[0]);
        }
    }
    return oldImport;
}

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    uint32_t outNum;
    uint32_t spendingFromHeight;
    CTransaction txToSpend;
    COptCCParams p;

    // get reserve transfer to spend
    CCrossChainExport thisExport = GetExportToSpend(tx, nIn, txToSpend, spendingFromHeight, p);

    if (thisExport.IsValid())
    {
        if (CConstVerusSolutionVector::GetVersionByHeight(spendingFromHeight) < CActivationHeight::ACTIVATE_PBAAS)
        {
            return eval->Error("Multi-currency operation before PBaaS activation");
        }

        if (thisExport.IsSupplemental())
        {
            // TODO: HARDENING - determine if there is any reason to protect this output from being spent. if we don't, ensure
            // that it is unspent when spending it via protocol
            return true;
        }

        CCrossChainExport matchedExport;

        for (auto &oneOut : tx.vout)
        {
            // there must be an output with a valid export to the same destination
            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() && 
                p.evalCode == EVAL_CROSSCHAIN_EXPORT && 
                p.version >= COptCCParams::VERSION_V3 &&
                p.vData.size() &&
                (matchedExport = CCrossChainExport(p.vData[0])).IsValid() &&
                matchedExport.destCurrencyID == thisExport.destCurrencyID)
            {
                // TODO: HARDENING - confirm that this spending check plus precheck covers all that is required
                return true;
            }
        }
    }
    return eval->Error("Invalid cross chain export");
}

bool IsCrossChainExportInput(const CScript &scriptSig)
{
    return true;
}

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    uint32_t outNum;
    uint32_t spendingFromHeight;
    CTransaction txToSpend;
    COptCCParams p;

    // get reserve transfer to spend
    CCrossChainImport thisImport = GetImportToSpend(tx, nIn, txToSpend, spendingFromHeight, p);

    if (thisImport.IsValid())
    {
        if (CConstVerusSolutionVector::GetVersionByHeight(spendingFromHeight) < CActivationHeight::ACTIVATE_PBAAS)
        {
            return eval->Error("Multi-currency operation before PBaaS activation");
        }

        CCrossChainImport matchedImport;

        for (auto &oneOut : tx.vout)
        {
            // there must be an output with a valid import to the same destination
            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() && 
                p.evalCode == EVAL_CROSSCHAIN_IMPORT && 
                p.version >= COptCCParams::VERSION_V3 &&
                p.vData.size() &&
                (matchedImport = CCrossChainImport(p.vData[0])).IsValid() &&
                matchedImport.importCurrencyID == thisImport.importCurrencyID)
            {
                // TODO: HARDENING - confirm that this spending check plus precheck covers all that is required
                return true;
            }
        }
    }
    return eval->Error("Invalid cross chain import");
}

// ensure that the cross chain import is valid to be posted on the block chain
bool PrecheckCrossChainImport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // while most checks on import conversion accuracy are carried out in checking reserve deposits and basic checks
    // on a transaction, this check also validates that all reserve transfer fees are adequate, including ID and
    // currency import fees as well as other cross-chain service fees. This involves determining the most favorable
    // conversion price that may have been used to calculate fee conversion and using that to accept or reject every 
    // reserve transfer. It also ensures that the fee payout is properly split between miners/stakers, exporters,
    // importers, and notaries.
    if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return state.Error("Multi-currency operation before PBaaS activation");
    }

    bool isPreSync = chainActive.Height() < (height - 1);

    COptCCParams p;
    CCrossChainImport cci, sysCCI;
    CCrossChainExport ccx;
    CPBaaSNotarization notarization;
    std::vector<CReserveTransfer> reserveTransfers;

    int32_t sysOutNum = -1, notarizationOut = -1, evidenceOutStart = -1, evidenceOutEnd = -1;
    if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
        p.vData.size() > 1 &&
        (cci = CCrossChainImport(p.vData[0])).IsValid() &&
        cci.GetImportInfo(tx, height, outNum, ccx, sysCCI, sysOutNum, notarization, notarizationOut, evidenceOutStart, evidenceOutEnd, reserveTransfers, state))
    {
        // if this is a source system cci, get the base
        if (cci.IsSourceSystemImport())
        {
            if (sysOutNum != outNum || outNum <= 0 || !sysCCI.IsValid())
            {
                return state.Error("Invalid currency import transaction with import: " + cci.ToUniValue().write(1,2));
            }
            cci = CCrossChainImport(tx.vout[outNum - 1].scriptPubKey);
            if (!cci.IsValid() ||
                cci.sourceSystemID != sysCCI.sourceSystemID ||
                sysCCI.importCurrencyID != sysCCI.sourceSystemID)
            {
                return state.Error("Invalid base import from system import: " + sysCCI.ToUniValue().write(1,2));
            }
            return true;
        }

        if (cci.IsDefinitionImport())
        {
            // TODO: HARDENING - validate this belongs on a definition and is correct
            if (!cci.hashReserveTransfers.IsNull())
            {
                return state.Error("Definition import cannot contain transfers: " + cci.ToUniValue().write(1,2));
            }
            return true;
        }
        else if (cci.IsInitialLaunchImport() && height == 1)
        {
            // TODO: HARDENING - validate this is correct as the initial launch import
            return true;
        }

        if (ccx.destSystemID != ASSETCHAINS_CHAINID && notarization.IsValid() && !notarization.IsRefunding())
        {
            return state.Error("Invalid import: " + cci.ToUniValue().write(1,2));
        }
        // TODO: HARDENING - if notarization is invalid, we may need to reject
        // also need to ensure that if our current height invalidates an import from the specified height that we
        // reject this in all cases
        else if (notarization.IsValid())
        {
            if (notarization.IsSameChain())
            {
                // a notarization for a later height is not valid
                if (notarization.notarizationHeight > (height - 1))
                {
                    return state.Error("Notarization for import past height, likely due to reorg: " + notarization.ToUniValue().write(1,2));
                }
            }
            else if (notarization.proofRoots.count(ASSETCHAINS_CHAINID))
            {
                uint32_t rootHeight;
                auto mmv = chainActive.GetMMV();
                if ((!notarization.IsMirror() &&
                        notarization.IsSameChain() &&
                        notarization.notarizationHeight >= height) ||
                    (notarization.proofRoots.count(ASSETCHAINS_CHAINID) &&
                        ((rootHeight = notarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight) > (height - 1) ||
                        (mmv.resize(rootHeight + 1), rootHeight != (mmv.size() - 1)) ||
                        notarization.proofRoots[ASSETCHAINS_CHAINID].blockHash != chainActive[rootHeight]->GetBlockHash() ||
                        notarization.proofRoots[ASSETCHAINS_CHAINID].stateRoot != mmv.GetRoot())))
                {
                    return state.Error("Notarization for import past height or invalid: " + notarization.ToUniValue().write(1,2));
                }
            }

            // if we have the chain behind us, verify that the prior import imports the prior export
            // TODO: HARDENING - this needs full coverage of all cases, including pre-conversion
            if (!isPreSync && !cci.IsDefinitionImport())
            {
                // if from this system, we 

                CTransaction priorImportTx;
                CCrossChainImport priorImport = cci.GetPriorImport(tx, outNum, state, height, &priorImportTx);
                if (!priorImport.IsValid())
                {
                    // TODO: HARDENING for now, we skip checks if we fail to get prior import, but
                    // we need to look deeper to ensure that there really is not one or that we use it
                    LogPrintf("Cannot retrieve prior import: %s\n", cci.ToUniValue().write(1,2).c_str());
                }
                else if (priorImport.exportTxId.IsNull())
                {
                    if (!ccx.IsChainDefinition() && ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                    {
                        return state.Error("Out of order export for import 1: " + cci.ToUniValue().write(1,2));
                    }
                }
                else
                {
                    if (priorImport.sourceSystemID == cci.sourceSystemID)
                    {
                        if (ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                        {
                            // same chain, we can get the export transaction
                            CTransaction exportTx;
                            uint256 blockHash;
                            if (!myGetTransaction(cci.exportTxId, exportTx, blockHash))
                            {
                                return state.Error("Can't get export for import: " + cci.ToUniValue().write(1,2));
                            }
                            if (ccx.IsSystemThreadExport() || ccx.IsSupplemental())
                            {
                                return state.Error("Invalid prior import tx(" + priorImportTx.GetHash().GetHex() + "): " + cci.ToUniValue().write(1,2));
                            }

                            if (ccx.firstInput > 0 && ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                            {
                                // the prior input is 1 less than first transfer input
                                // TODO: HARDENING - need to deal with the refunding case of order
                                if (!notarization.IsRefunding() &&
                                    (priorImport.exportTxId != exportTx.vin[ccx.firstInput - 1].prevout.hash ||
                                    priorImport.exportTxOutNum != exportTx.vin[ccx.firstInput - 1].prevout.n))
                                {
                                    //printf("%s: Out of order export tx(%s) from %s to %s for import %s\n", __func__, exportTx.GetHash().GetHex().c_str(), ConnectedChains.GetFriendlyCurrencyName(cci.sourceSystemID).c_str(), ConnectedChains.GetFriendlyCurrencyName(cci.importCurrencyID).c_str(), cci.ToUniValue().write(1,2).c_str());
                                    return state.Error("Out of order export for import 2: " + cci.ToUniValue().write(1,2));
                                }
                            }
                            else
                            {
                                bool inputFound = false;
                                // search for a matching input
                                for (auto &oneIn : exportTx.vin)
                                {
                                    if (priorImport.exportTxId == oneIn.prevout.hash && priorImport.exportTxOutNum == oneIn.prevout.n)
                                    {
                                        inputFound = true;
                                        break;
                                    }
                                }
                                if (!inputFound)
                                {
                                    return state.Error("Out of order export for import 3: " + cci.ToUniValue().write(1,2));
                                }
                            }
                        }
                        else
                        {
                            // TODO: HARDENING must have evidence to reconstruct a partial transaction proof with prior tx id
                        }
                    }
                }   
            }

            if (!isPreSync && reserveTransfers.size())
            {
                // if we are importing to fractional, determine the last notarization used prior to this one for 
                // imports from the system from that, the most favorable conversion rates for fee compatible conversions 
                // are determined, and those values are passed to the import

                CCurrencyValueMap conversionMap;
                conversionMap.valueMap[ASSETCHAINS_CHAINID] = SATOSHIDEN;

                CCurrencyDefinition importingToDef = ConnectedChains.GetCachedCurrency(cci.importCurrencyID);
                if (notarization.IsRefunding() &&
                    ccx.destSystemID != ASSETCHAINS_CHAINID &&
                    (importingToDef.systemID != ccx.destSystemID || importingToDef.launchSystemID != ASSETCHAINS_CHAINID))
                {
                    return state.Error("Invalid import to incorrect system: " + cci.ToUniValue().write(1,2));
                }
                if (!importingToDef.IsValid() || !((notarization.IsRefunding() && importingToDef.launchSystemID == ASSETCHAINS_CHAINID) ||
                                                   importingToDef.SystemOrGatewayID() == ASSETCHAINS_CHAINID))
                {
                    return state.Error("Unable to retrieve currency for import: " + cci.ToUniValue().write(1,2));
                }

                CCurrencyDefinition systemSource = ConnectedChains.GetCachedCurrency(cci.sourceSystemID);
                CCoinbaseCurrencyState importState = notarization.currencyState;
                CCoinbaseCurrencyState dummyState;
                importState.RevertReservesAndSupply();

                std::vector<CTxOut> vOutputs;
                CCurrencyValueMap importedCurrency, gatewayDepositsIn, spentCurrencyOut;

                CReserveTransactionDescriptor rtxd;
                if (!rtxd.AddReserveTransferImportOutputs(systemSource, 
                                                            ConnectedChains.ThisChain(), 
                                                            importingToDef, 
                                                            importState,
                                                            reserveTransfers, 
                                                            height,
                                                            vOutputs,
                                                            importedCurrency, 
                                                            gatewayDepositsIn, 
                                                            spentCurrencyOut,
                                                            &dummyState))
                {
                    printf("Errors processing\n");
                }

                CCoinbaseCurrencyState startingState;
                uint32_t minHeight = 0;
                uint32_t maxHeight = 0;

                if (!notarization.IsRefunding() &&
                    importingToDef.IsFractional() &&
                    (notarization.currencyID == cci.importCurrencyID || notarization.currencyStates.count(cci.importCurrencyID)))
                {
                    auto currencyMap = importingToDef.GetCurrenciesMap();
                    startingState = notarization.currencyID == cci.importCurrencyID ?
                                        notarization.currencyState :
                                        notarization.currencyStates[cci.importCurrencyID];

                    // we need to populate the conversion map fully once we know we need to, then stop checking
                    // first, determine the range of notarizations we can accept, which is the first
                    // notarization we can determine was available to the other system

                    if (cci.IsSameChain())
                    {
                        // determine the minimum source height of the reserve transfer and add its
                        // pre-creation price to the conversion map
                        maxHeight = ccx.sourceHeightEnd - 1;
                        minHeight = ccx.sourceHeightStart > (DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA + 1) ? 
                                    ccx.sourceHeightStart - (DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA + 1) :
                                    0;
                    }
                    else
                    {
                        maxHeight = ccx.sourceHeightEnd - 1;
                        minHeight = ccx.sourceHeightStart > (DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA + 20) ? 
                                    ccx.sourceHeightStart - (DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA + 20) :
                                    0;
                    }

                    conversionMap = cci.GetBestPriorConversions(tx, outNum, importingToDef.GetID(), ASSETCHAINS_CHAINID, startingState, state, height, minHeight, maxHeight);
                }
                else if (!ConnectedChains.ThisChain().launchSystemID.IsNull() && ConnectedChains.ThisChain().IsMultiCurrency())
                {
                    // accept Verus (or launching chain/system) fees 1:1 if we have no fractional converter
                    conversionMap.valueMap[ConnectedChains.ThisChain().launchSystemID] = SATOSHIDEN;
                }

                for (auto &oneTransfer : reserveTransfers)
                {
                    if (!oneTransfer.IsValid())
                    {
                        return state.Error("Invalid reserve transfer: " + oneTransfer.ToUniValue().write(1,2));
                    }
                    if (!conversionMap.valueMap.count(oneTransfer.feeCurrencyID))
                    {
                        // invalid fee currency from system
                        return state.Error("Invalid fee currency for transfer 1: " + oneTransfer.ToUniValue().write(1,2));
                    }

                    CAmount nextLegFeeEquiv = 0;
                    CCurrencyValueMap nextLegConversionMap;
                    CCurrencyDefinition nextLegCurrency;
                    if (importingToDef.IsFractional() && oneTransfer.HasNextLeg() && oneTransfer.destination.gatewayID != ASSETCHAINS_CHAINID)
                    {
                        nextLegConversionMap = cci.GetBestPriorConversions(tx, outNum, importingToDef.GetID(), oneTransfer.destination.gatewayID, startingState, state, height, minHeight, maxHeight);
                        nextLegFeeEquiv = CCurrencyState::ReserveToNativeRaw(oneTransfer.destination.fees, nextLegConversionMap.valueMap[oneTransfer.feeCurrencyID]);
                        nextLegCurrency = ConnectedChains.GetCachedCurrency(oneTransfer.destination.gatewayID);
                        if (!nextLegCurrency.IsValid() || !(nextLegCurrency.IsPBaaSChain() || nextLegCurrency.IsGateway()))
                        {
                            return state.Error("Invalid next leg for transfer: " + oneTransfer.ToUniValue().write(1,2));
                        }
                    }

                    // if we get our fees from conversion, consider the conversion + fees
                    // still ensure that they are enough
                    CAmount feeEquivalent = !oneTransfer.nFees ? 0 : 
                        oneTransfer.IsPreConversion() ? oneTransfer.nFees : CCurrencyState::ReserveToNativeRaw(oneTransfer.nFees, conversionMap.valueMap[oneTransfer.feeCurrencyID]);

                    if (oneTransfer.IsPreConversion())
                    {
                        if (oneTransfer.feeCurrencyID != importingToDef.launchSystemID)
                        {
                            return state.Error("Fees for currency launch preconversions must include launch currency: " + oneTransfer.ToUniValue().write(1,2));
                        }
                        if (!importingToDef.GetCurrenciesMap().count(oneTransfer.FirstCurrency()))
                        {
                            return state.Error("Invalid source currency for preconversion: " + oneTransfer.ToUniValue().write(1,2));
                        }
                    }

                    if (oneTransfer.IsConversion())
                    {
                        uint160 sourceCurID = oneTransfer.FirstCurrency();
                        CAmount conversionFee = oneTransfer.IsReserveToReserve() ?
                                    CReserveTransactionDescriptor::CalculateConversionFee(oneTransfer.FirstValue()) << 1 :
                                    CReserveTransactionDescriptor::CalculateConversionFee(oneTransfer.FirstValue());
                        feeEquivalent += 
                            CCurrencyState::ReserveToNativeRaw(conversionFee, conversionMap.valueMap[oneTransfer.FirstCurrency()]);

                        if (!oneTransfer.IsPreConversion())
                        {
                            // TODO: HARDENING - confirm that we need to do nothing else to ensure we can convert
                        }
                    }

                    if (oneTransfer.IsIdentityExport())
                    {
                        if ((oneTransfer.HasNextLeg() && oneTransfer.destination.gatewayID != ASSETCHAINS_CHAINID ?
                                nextLegFeeEquiv :
                                feeEquivalent) < ConnectedChains.ThisChain().IDImportFee())
                        {
                            return state.Error("Insufficient fee for identity import: " + cci.ToUniValue().write(1,2));
                        }
                    }
                    else if (oneTransfer.IsCurrencyExport())
                    {
                        CCurrencyDefinition exportingDef = oneTransfer.destination.HasGatewayLeg() && oneTransfer.destination.TypeNoFlags() != oneTransfer.destination.DEST_REGISTERCURRENCY ?
                                                             ConnectedChains.GetCachedCurrency(oneTransfer.FirstCurrency()) :
                                                             CCurrencyDefinition(oneTransfer.destination.destination);
                        if (!exportingDef.IsValid())
                        {
                            return state.Error(strprintf("%s: Invalid currency import", __func__));
                        }

                        // imported currencies do need to conform to type constraints in order
                        // to benefit from reduced import fees. this happens on the precheck for currency definition

                        if ((oneTransfer.HasNextLeg() && oneTransfer.destination.gatewayID != ASSETCHAINS_CHAINID ?
                                nextLegFeeEquiv :
                                feeEquivalent) < ConnectedChains.ThisChain().GetCurrencyImportFee(exportingDef.ChainOptions() & exportingDef.OPTION_NFT_TOKEN))
                        {
                            return state.Error("Insufficient fee for currency import: " + cci.ToUniValue().write(1,2));
                        }
                    }
                    else if (!cci.IsSameChain() && !oneTransfer.IsPreConversion())
                    {
                        // import distributes both export and import fees
                        if (feeEquivalent < ConnectedChains.ThisChain().GetTransactionImportFee())
                        {
                            return state.Error("Insufficient fee for transaction in import: " + cci.ToUniValue().write(1,2));
                        }
                    }
                    // import distributes both export and import fees
                    if (cci.IsSameChain() && feeEquivalent < ConnectedChains.ThisChain().GetTransactionTransferFee())
                    {
                        return state.Error("Insufficient fee for transaction transfer in import: " + cci.ToUniValue().write(1,2));
                    }
                }
                return true;
            }
            else
            {
                return true;
            }
        }
    }

    if (!state.IsError())
    {
        return state.Error("Invalid cross chain import");
    }

    return false;
}

// ensure that the cross chain export is valid to be posted on the block chain
bool PrecheckCrossChainExport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // ensure that all reserve transfers spent are properly accounted for
    if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return state.Error("Multi-currency operation before PBaaS activation");
    }

    // TODO: HARDENING - ensure that we have confirmed all totals and fees are correct, then convert all warnings to errors
    // then convert all warnings to errors
    // ensure that this transaction has the appropriate finalization outputs, as required

    // check that all reserve transfers are matched to this export, and no others are mined in to the block that should be included
    COptCCParams p;
    CCrossChainExport ccx;
    int primaryExportOut = -1, nextOutput;
    CPBaaSNotarization notarization;
    std::vector<CReserveTransfer> reserveTransfers;
    CCurrencyDefinition destSystem;

    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
          p.vData.size() &&
          (ccx = CCrossChainExport(p.vData[0])).IsValid() &&
          (ccx.IsSupplemental() ||
           (ccx.sourceSystemID == ASSETCHAINS_CHAINID &&
            ((destSystem = ConnectedChains.GetCachedCurrency(ccx.destSystemID)).IsValid() || ccx.IsChainDefinition()) &&
             ccx.GetExportInfo(tx, outNum, primaryExportOut, nextOutput, notarization, reserveTransfers, state, 
                ccx.IsChainDefinition() ? CCurrencyDefinition::EProofProtocol::PROOF_PBAASMMR : (CCurrencyDefinition::EProofProtocol)destSystem.proofProtocol)))))
    {
        return state.Error("Invalid cross chain export");
    }

    // if we are not the primary export out or we are supplemental, no need to check further
    if (ccx.IsSupplemental() || outNum != primaryExportOut)
    {
        return true;
    }

    // if this is the definition export, we need to get the actual currency
    if (ccx.IsChainDefinition() && ccx.destSystemID != ASSETCHAINS_CHAINID)
    {
        bool found = false;
        for (auto &oneOut : tx.vout)
        {
            destSystem = CCurrencyDefinition(oneOut.scriptPubKey);
            if (destSystem.IsValid() && destSystem.GetID() == ccx.destSystemID)
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            return state.Error("Invalid cross chain export - cannot find system definition for destination");
        }
    }

    if (height > 1 && ccx.sourceHeightEnd >= height && ccx.sourceSystemID == ASSETCHAINS_CHAINID)
    {
        return state.Error("Export source height is too high for current height");
    }

    // make sure that every reserve transfer that SHOULD BE included (all mined in relevant blocks) IS included, no exceptions
    // verify all currency totals
    multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> inputDescriptors;

    // TODO: HARDENING - if source height start is 0 and this covers an actual range of
    // potential transfers, we may skip enforcement of inclusion. ensure we use the correct condition
    // and that there is no risk of missing valid transfers with the check we end up with here
    if (ccx.sourceHeightStart > 0 &&
        !GetChainTransfersUnspentBy(inputDescriptors, ccx.destCurrencyID, ccx.sourceHeightStart, ccx.sourceHeightEnd, height))
    {
        return state.Error("Error retrieving cross chain transfers");
    }

    if (inputDescriptors.size() != ccx.numInputs)
    {
        /* UniValue jsonTx(UniValue::VOBJ);
        uint256 hashBlock;
        TxToUniv(tx, hashBlock, jsonTx);
        printf("%s: candidate tx:\n%s\n", __func__, jsonTx.write(1,2).c_str());
        for (auto &oneDescr : inputDescriptors)
        {
            printf("Input: %s\nReserve transfer: %s\n\n", oneDescr.second.first.txIn.ToString().c_str(), oneDescr.second.second.ToUniValue().write(1,2).c_str());
        }
        GetChainTransfers(inputDescriptors, ccx.destCurrencyID, ccx.sourceHeightStart, ccx.sourceHeightEnd); // */
        return state.Error("Discrepancy in number of eligible reserve transfers mined during export period and included - may only be cause by async loading, if so it will resolve");
    }

    std::set<std::pair<uint256, int>> utxos;
    if (ccx.numInputs)
    {
        if (ccx.firstInput < 0)
        {
            return state.Error("First export index invalid");
        }
        for (int i = ccx.firstInput; i < (ccx.firstInput + ccx.numInputs); i++)
        {
            if (i < 0 || i >= tx.vin.size())
            {
                return state.Error("Input index out of range");
            }
            utxos.insert(std::make_pair(tx.vin[i].prevout.hash, tx.vin[i].prevout.n));
        }
    }

    // all of the input descriptors and no others should be in the export's reserve transfers
    CCurrencyValueMap totalCurrencyExported;

    for (auto &oneTransfer : inputDescriptors)
    {
        std::pair<uint256, int> transferOutput = make_pair(oneTransfer.second.first.txIn.prevout.hash, oneTransfer.second.first.txIn.prevout.n);
        if (!utxos.count(transferOutput))
        {
            // TODO: HARDENING - the case where this could be valid is if the output was already spent in a block prior
            // the one this transaction is in. since we don't have a reliable way to determine if the output will be spent in this
            // block, if the block referred to is just prior to this one, we must use it for the export, not arbitrage for an import
            return state.Error("Export excludes valid reserve transfer from source block");
        }
        totalCurrencyExported += oneTransfer.second.second.TotalCurrencyOut();
        utxos.erase(transferOutput);
    }

    if (ccx.IsClearLaunch() || ccx.IsChainDefinition())
    {
        // if this is a PBaaS launch, this should be the coinbase, and we need to get the parent chain definition,
        // including currency launch prices from the current transaction
        CCurrencyDefinition thisDef, sourceDef;
        if (height == 1 || ccx.IsChainDefinition())
        {
            std::vector<CCurrencyDefinition> currencyDefs = CCurrencyDefinition::GetCurrencyDefinitions(tx);
            for (auto &oneCur : currencyDefs)
            {
                uint160 curID = oneCur.GetID();
                if (curID == ccx.destCurrencyID)
                {
                    thisDef = oneCur;
                }
                else if (curID == ccx.sourceSystemID)
                {
                    sourceDef = oneCur;
                }
            }
            if (!sourceDef.IsValid() && ccx.IsChainDefinition())
            {
                sourceDef = ConnectedChains.ThisChain();
            }
            if (!thisDef.IsValid() ||
                (!thisDef.launchSystemID.IsNull() &&
                 (!sourceDef.IsValid() ||
                  thisDef.launchSystemID != sourceDef.GetID())))
            {
                return state.Error("Invalid launch currency");
            }
        }
        else
        {
            thisDef = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID);
            sourceDef = ConnectedChains.ThisChain();
            if (!thisDef.IsValid() ||
                !sourceDef.IsValid() ||
                (thisDef.launchSystemID != sourceDef.GetID() && !(sourceDef.IsGateway() && thisDef.launchSystemID == thisDef.systemID)) ||
                ccx.sourceSystemID != thisDef.launchSystemID)
            {
                return state.Error("Invalid source or launch currency");
            }
        }
        if (ccx.IsChainDefinition())
        {
            totalCurrencyExported.valueMap[sourceDef.GetID()] += sourceDef.LaunchFeeImportShare(thisDef.ChainOptions());
        }
    }
    if (!(height == 1 || ccx.IsChainDefinition()) && notarization.IsValid())
    {
        if (!notarization.IsPreLaunch())
        {
            return state.Error("Only prelaunch exports should have valid notarizations");
        }
        CTransaction prevNotTx;
        uint256 blkHash;
        CPBaaSNotarization pbn;
        COptCCParams prevP;
        if (notarization.prevNotarization.hash.IsNull() ||
            !myGetTransaction(notarization.prevNotarization.hash, prevNotTx, blkHash) ||
            notarization.prevNotarization.n < 0 ||
            notarization.prevNotarization.n >= prevNotTx.vout.size() ||
            !prevNotTx.vout[notarization.prevNotarization.n].scriptPubKey.IsPayToCryptoCondition(prevP) ||
            !prevP.IsValid() ||
            prevP.evalCode != EVAL_ACCEPTEDNOTARIZATION ||
            !prevP.vData.size() ||
            !(pbn = CPBaaSNotarization(prevP.vData[0])).IsValid() ||
            pbn.currencyID != notarization.currencyID)
        {
            return state.Error("Non-definition exports with valid notarizations must have prior notarizations");
        }
        CCurrencyDefinition destCurrency = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID);

        if (ccx.sourceSystemID != ASSETCHAINS_CHAINID || !destCurrency.IsValid())
        {
            return state.Error("Invalid export source system or destination currency");
        }

        uint256 transferHash;
        CPBaaSNotarization checkNotarization;
        std::vector<CTxOut> outputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsIn, spentCurrencyOut;
        if (!pbn.NextNotarizationInfo(ConnectedChains.ThisChain(),
                                      destCurrency,
                                      ccx.sourceHeightStart - 1,
                                      notarization.notarizationHeight,
                                      reserveTransfers,
                                      transferHash,
                                      checkNotarization,
                                      outputs,
                                      importedCurrency,
                                      gatewayDepositsIn,
                                      spentCurrencyOut,
                                      ccx.exporter) ||
            !checkNotarization.IsValid() ||
            (checkNotarization.IsRefunding() != notarization.IsRefunding()) ||
            ::AsVector(checkNotarization.currencyState) != ::AsVector(notarization.currencyState))
        {
            return state.Error("Invalid notarization mutation\n");
        }

        if (ccx.totalFees != CCurrencyValueMap(notarization.currencyState.currencies, notarization.currencyState.fees))
        {
            return state.Error("Export fee estimate doesn't match notarization - may only be result of async loading and not error");
        }
    }
    // TODO: HARDENING - when we know an error may be caused by sync loading, always check height against chainActive and filter errors
    if (ccx.totalAmounts != totalCurrencyExported)
    {
        return state.Error("Exported currency totals warning - may only be result of async loading and not error");
    }
    if (utxos.size())
    {
        /* for (auto &oneUtxo : utxos)
        {
            LogPrintf("txid: %s, output #: %d\n", oneUtxo.first.GetHex().c_str(), oneUtxo.second);
        }// */
        return state.Error("Invalid export input that was not mined in as valid reserve transfer");
    }
    return true;
}

bool IsCrossChainImportInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateFinalizeExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // TODO: HARDENING - must be spent by either the next export, if this is for an export offchain
    // or a matching import if same chain
    return true;
}

bool IsFinalizeExportInput(const CScript &scriptSig)
{
    return false;
}

bool PreCheckFinalizeExport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // TODO: HARDENING - ensure that this finalization represents an export that is either the clear launch beacon of
    // the currency or a same-chain export to be spent by the matching import
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

CReserveTransfer GetReserveTransferToSpend(const CTransaction &spendingTx, uint32_t nIn, CTransaction &sourceTx, uint32_t &height, COptCCParams &p)
{
    // if not fulfilled, ensure that no part of the primary identity is modified
    CReserveTransfer oldReserveTransfer;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        auto bIt = blkHash.IsNull() ? mapBlockIndex.end() : mapBlockIndex.find(blkHash);
        if (bIt == mapBlockIndex.end() || !bIt->second)
        {
            height = chainActive.Height();
        }
        else
        {
            height = bIt->second->GetHeight();
        }

        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() && 
            p.evalCode == EVAL_RESERVE_TRANSFER && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldReserveTransfer = CReserveTransfer(p.vData[0]);
        }
    }
    return oldReserveTransfer;
}


bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    uint32_t outNum;
    uint32_t spendingFromHeight;
    CTransaction txToSpend;
    COptCCParams p;

    // get reserve transfer to spend
    CReserveTransfer rt = GetReserveTransferToSpend(tx, nIn, txToSpend, spendingFromHeight, p);

    if (rt.IsValid())
    {
        uint160 systemDestID, importCurrencyID;
        CCurrencyDefinition systemDest, importCurrencyDef;
        CPBaaSNotarization startingNotarization;
        CChainNotarizationData cnd;

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
            return eval->Error("Invalid currency definition for reserve transfer being spent");
        }

        // TODO: HARDENING
        // ensure that this is fullfilled only when it is being spent to a refund address/ID
        // ensure this reserve transfer is being spent by a valid export with the appropriate system
        // and currency destinations as well as totals, or that it is fulfilled
        //if (!fulfilled)
        {
            CCrossChainExport ccx;
            CCrossChainImport cci;
            int32_t primaryExportOut, nextOutput;
            CPBaaSNotarization pbn;
            std::vector<CReserveTransfer> reserveTransfers;
            for (int i = 0; i < tx.vout.size(); i++)
            {
                COptCCParams exportP;
                if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(exportP) &&
                    exportP.IsValid() && 
                    exportP.evalCode == EVAL_CROSSCHAIN_EXPORT && 
                    exportP.vData.size() > 1 &&
                    (ccx = CCrossChainExport(exportP.vData[0])).IsValid() &&
                    !ccx.IsSystemThreadExport() &&
                    ccx.destCurrencyID == importCurrencyID)
                {
                    CCurrencyDefinition systemDef;
                    if (!(ccx.destSystemID == (importCurrencyDef.IsGateway() ? importCurrencyDef.gatewayID : importCurrencyDef.systemID)))
                    {
                        if (ccx.destSystemID != importCurrencyDef.launchSystemID ||
                            ccx.destSystemID != ASSETCHAINS_CHAINID)
                        {
                            return eval->Error("Invalid destination system " + EncodeDestination(CIdentityID(ccx.destSystemID)) + " for export");
                        }
                        systemDef = ConnectedChains.ThisChain();
                        if (!ccx.GetExportInfo(tx, i, primaryExportOut, nextOutput, pbn, reserveTransfers, (CCurrencyDefinition::EProofProtocol)systemDef.proofProtocol))
                        {
                            return eval->Error("Invalid or malformed export 1");
                        }

                        // the only case this makes sense is if we are refunding back to the launch chain from the system chain
                        if (!pbn.IsRefunding())
                        {
                            return eval->Error("Attempt to export to launch chain from external home chain that is not refunding");
                        }
                    }
                    else
                    {
                        systemDef = ConnectedChains.GetCachedCurrency(ccx.destSystemID);
                        if (!ccx.GetExportInfo(tx, i, primaryExportOut, nextOutput, pbn, reserveTransfers, (CCurrencyDefinition::EProofProtocol)systemDef.proofProtocol))
                        {
                            return eval->Error("Invalid or malformed export 1");
                        }
                    }
                    if (ccx.numInputs > 0 &&
                        nIn >= ccx.firstInput &&
                        nIn < (ccx.firstInput + ccx.numInputs))
                    {
                        // if we successfully got the export info and are included in the export reserve transfers, additional
                        // validation is done by the export
                        return true;
                    }
                }
                else if (exportP.IsValid() &&
                         exportP.evalCode == EVAL_CROSSCHAIN_IMPORT && 
                         exportP.vData.size() > 1 &&
                         (cci = CCrossChainImport(exportP.vData[0])).IsValid() &&
                         cci.importCurrencyID == importCurrencyID &&
                         rt.IsConversion() &&
                         !rt.IsPreConversion())
                {
                    CCrossChainImport sysCCI;
                    CPBaaSNotarization importNotarization;
                    int32_t sysCCIOut, importNotarizationOut, eOutStart = -1, eOutEnd = -1;
                    std::vector<CReserveTransfer> reserveTransfers;
                    // ensure that this spend is accounted for in the
                    // import. if this reserve transfer is equivalent to the last retrieved by this import,
                    // via GetImportInfo(), we consider it valid
                    if (cci.GetImportInfo(tx, spendingFromHeight, i, ccx, sysCCI, sysCCIOut, importNotarization, importNotarizationOut, eOutStart, eOutEnd, reserveTransfers) &&
                        reserveTransfers.size() &&
                        ::AsVector(reserveTransfers.back()) == ::AsVector(rt) &&
                        cci.hashReserveTransfers != ccx.hashReserveTransfers)
                    {
                        return true;
                    }
                }
            }
            return eval->Error("Unauthorized reserve transfer spend without valid export");
        }

        // TODO: HARDENING - ensure the only valid reason to approve at this point requires verification that the
        // spending transaction is signed by the refunding address.
        return true;
    }
    return eval->Error("Attempt to spend invalid reserve transfer");
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
    CCurrencyDefinition launchingCurrency;

    CCrossChainExport ccxSource;
    CPBaaSNotarization importNotarization;
    int32_t sysCCIOut, importNotarizationOut, evidenceOutStart, evidenceOutEnd;
    std::vector<CReserveTransfer> reserveTransfers;

    // looking for an import output to the controlling currency
    int i;
    for (i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.vData.size() &&
            (authorizingImport = CCrossChainImport(p.vData[0])).IsValid())
        {
            // the simple case
            if (authorizingImport.importCurrencyID == sourceRD.controllingCurrencyID)
            {
                break;
            }

            if (!authorizingImport.IsSourceSystemImport())
            {
                if (authorizingImport.GetImportInfo(tx,
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
                    if (importNotarization.IsRefunding() &&
                        (launchingCurrency = ConnectedChains.GetCachedCurrency(authorizingImport.importCurrencyID)).IsValid() &&
                        launchingCurrency.systemID != ASSETCHAINS_CHAINID &&
                        launchingCurrency.systemID == sourceRD.controllingCurrencyID)
                    {
                        break;
                    }
                }
                else
                {
                    importNotarization = CPBaaSNotarization();
                }
            }
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

    if (importNotarization.IsValid() ||
        mainImport.GetImportInfo(tx,
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
            if (!pCoins || pCoins->vout.size() <= tx.vin[i].prevout.n)
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

        if (ccxSource.IsClearLaunch() && ccxSource.sourceSystemID == destCurDef.launchSystemID)
        {
            checkState.SetLaunchCompleteMarker(false);
        }

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
                                                  &newCurState,
                                                  ccxSource.exporter,
                                                  importNotarization.proposer,
                                                  importNotarization.proofRoots.count(ccxSource.sourceSystemID) ?
                                                    importNotarization.proofRoots.find(ccxSource.sourceSystemID)->second.stateRoot :
                                                    uint256()))
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
                LogPrintf("%s: invalid use of gateway reserve deposits for currency: %s\n", __func__, EncodeDestination(CIdentityID(destCurDef.GetID())).c_str());
                return eval->Error(std::string(__func__) + ": invalid use of gateway reserve deposits for currency: " + EncodeDestination(CIdentityID(destCurDef.GetID())));
            }
        }
        else
        {
            CCurrencyValueMap currenciesIn(importedCurrency);

            // if we are not coming directly into the source system, there must be a separate source export as well,
            // so add gateway currency
            if (ccxSource.sourceSystemID != ccxSource.destSystemID && ccxSource.sourceSystemID != ccxSource.destCurrencyID)
            {
                if (!(checkState.IsRefunding() && destCurDef.launchSystemID == ASSETCHAINS_CHAINID) &&
                    authorizingImport.importCurrencyID != ccxSource.sourceSystemID)
                {
                    return eval->Error(std::string(__func__) + ": invalid currency system import thread for import to: " + EncodeDestination(CIdentityID(destCurDef.GetID())));
                }
                currenciesIn += gatewayCurrencyUsed;
            }

            if (newCurState.primaryCurrencyOut)
            {
                currenciesIn.valueMap[newCurState.GetID()] += newCurState.primaryCurrencyOut;
            }

            if ((totalDeposits + currenciesIn) != (reserveDepositChange + spentCurrencyOut))
            {
                LogPrintf("%s: Invalid use of reserve deposits -- (totalDeposits + currenciesIn):\n%s\n(reserveDepositChange + spentCurrencyOut):\n%s\n",
                       __func__, (totalDeposits + currenciesIn).ToUniValue().write().c_str(), (reserveDepositChange + spentCurrencyOut).ToUniValue().write().c_str());
                return eval->Error(std::string(__func__) + ": invalid use of reserve deposits for currency: " + EncodeDestination(CIdentityID(destCurDef.GetID())));
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

bool IsAdvancedNameReservationInput(const CScript &scriptSig)
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

int8_t ObjTypeCode(const CProofRoot &obj)
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

int8_t ObjTypeCode(const CHashCommitments &obj)
{
    return CHAINOBJ_COMMITMENTDATA;
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
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK, PBAAS_BLOCKTIME, ASSETCHAINS_LWMAPOS;
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
    if (IsVerusMainnetActive())
    {
        if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_VERUSVAULT)
        {
            return true;
        }
        else if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
        {
            return false;
        }
    }
    else if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return false;
    }

    // TODO: HARDENING - confirm that we handle all gateway and PBaaS converter and reserve definition verifications

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

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    if (GetSerializeSize(ss, CReserveTransfer(CReserveTransfer::CURRENCY_EXPORT + CReserveTransfer::VALID + CReserveTransfer::CROSS_SYSTEM,
                            CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}), std::vector<int64_t>({1})),
                            ASSETCHAINS_CHAINID,
                            0,
                            newCurrency.GetID(),
                            CTransferDestination(CTransferDestination::DEST_REGISTERCURRENCY,
                            ::AsVector(newCurrency),
                            newCurrency.GetID()))) > (CScript::MAX_SCRIPT_ELEMENT_SIZE - 128))
    {
        return state.Error("Serialized currency is too large to send across PBaaS networks");
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
            if (i < outNum &&
                oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() > 1 &&
                (cci = CCrossChainImport(p.vData[0])).IsValid())
            {
                if (cci.sourceSystemID != ASSETCHAINS_CHAINID &&
                    cci.GetImportInfo(spendingTx, height, i, ccx, sysCCI, sysCCIOut, pbn, notarizationOut, eOutStart, eOutEnd, transfers) &&
                    pbn.IsValid() &&
                    pbn.IsLaunchConfirmed() &&
                    pbn.IsLaunchComplete() &&
                    outNum > eOutEnd && 
                    outNum <= (eOutEnd + cci.numOutputs))
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
        std::map<uint160, std::string> newDefinitions;
        std::string newSystemName;
        CCurrencyDefinition newSystem;
        if (!isImportDefinition)
        {
            std::vector<CCurrencyDefinition> currencyDefs = CCurrencyDefinition::GetCurrencyDefinitions(spendingTx);

            LOCK(mempool.cs);

            if (currencyDefs.size() > 1)
            {
                for (auto &oneCur : currencyDefs)
                {
                    if (oneCur.IsPBaaSChain() || oneCur.IsGateway())
                    {
                        newSystemName = oneCur.name + "." + ConnectedChains.GetFriendlyCurrencyName(oneCur.parent);
                        newSystem = oneCur;
                        newDefinitions.insert(std::make_pair(oneCur.GetID(), newSystemName));
                    }
                    else if (!(oneCur.IsPBaaSChain() || oneCur.IsGateway()) && newSystem.IsValid())
                    {
                        if (oneCur.parent == newSystem.GetID())
                        {
                            newDefinitions.insert(std::make_pair(oneCur.GetID(), oneCur.name + "." + newSystemName));
                        }
                    }
                }
            }
            try
            {
                std::map<uint160, std::string> requiredDefinitions = newDefinitions;
                // TODO: HARDENING - Need to prepare to validate all newly mapped and defined supporting currencies
                // skips the case where we are defining a new mapped currency, need to cover that
                if (!ValidateNewUnivalueCurrencyDefinition(newCurrency.ToUniValue(), height, ASSETCHAINS_CHAINID, requiredDefinitions, false).IsValid())
                {
                    LogPrint("currencydefinition", "%s: Currency definition in output violates current definition rules.\n%s\n", __func__, newCurrency.ToUniValue().write(1,2).c_str());
                    return state.Error("Currency definition in output violates current definition rules");
                }
            }
            catch(const UniValue &e)
            {
                LogPrint("currencydefinition", "%s: %s\n", __func__, uni_get_str(find_value(e, "message")).c_str());
                LogPrint("currencydefinition", "%s\n", newCurrency.ToUniValue().write(1,2).c_str());
                return state.Error("Currency definition in output violates current definition rules");
            }
            
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
                        (oldIdentity = CIdentity(p.vData[0])).IsValid() &&
                        (oldIdentity.GetID() == newCurrency.GetID() || oldIdentity.GetID() == newCurrency.parent))
                    {
                        break;
                    }
                    oldIdentity.nVersion = oldIdentity.VERSION_INVALID;
                }
            }
            if (!oldIdentity.IsValid())
            {
                return state.Error("No valid identity found for currency definition");
            }
            if (oldIdentity.HasActiveCurrency())
            {
                return state.Error("Identity already has used its one-time ability to define a currency");
            }
            CIdentity newIdentity;
            for (auto &oneOut : spendingTx.vout)
            {
                COptCCParams p;
                if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_IDENTITY_PRIMARY &&
                    p.vData.size() > 1 &&
                    (newIdentity = CIdentity(p.vData[0])).IsValid() &&
                    (newIdentity.GetID() == newCurrency.GetID() || newIdentity.GetID() == newCurrency.parent))
                {
                    break;
                }
                newIdentity.nVersion = oldIdentity.VERSION_INVALID;
            }
            if (!newIdentity.IsValid())
            {
                return state.Error("Invalid identity found for currency definition");
            }
            if (!newIdentity.HasActiveCurrency())
            {
                return state.Error("Identity has not been set to defined currency status");
            }
            if (newIdentity.GetID() != ASSETCHAINS_CHAINID || !IsVerusActive())
            {
                CCurrencyDefinition parentCurrency = ConnectedChains.GetCachedCurrency(newIdentity.parent);
                if (!parentCurrency.IsValid())
                {
                    return state.Error("Parent currency invalid to issue identities on this chain");
                }

                // any ID with a gateway as its system ID can issue an NFT mapped currency with 0
                // satoshi supply as its currency for the cost of an ID import, not a currency import
                CCurrencyDefinition systemDef = newSystem;
                if (newCurrency.launchSystemID == ASSETCHAINS_CHAINID &&
                    newCurrency.IsNFTToken() &&
                    !systemDef.IsValid())
                {
                    systemDef = ConnectedChains.GetCachedCurrency(newCurrency.systemID);
                }

                bool isNFTMappedCurrency = false;
                if (newCurrency.IsNFTToken())
                {
                    isNFTMappedCurrency = newCurrency.IsNFTToken() &&
                                          systemDef.IsValid() &&
                                          !(newCurrency.options &
                                            newCurrency.OPTION_FRACTIONAL +
                                            newCurrency.OPTION_GATEWAY +
                                            newCurrency.OPTION_PBAAS +
                                            newCurrency.OPTION_GATEWAY_CONVERTER) &&
                                          newCurrency.IsToken();

                    if (!isNFTMappedCurrency ||
                        (!(newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETHNFT &&
                           systemDef.proofProtocol == systemDef.PROOF_ETHNOTARIZATION &&
                           systemDef.IsGateway() &&
                           newCurrency.maxPreconvert.size() == 1 &&
                           newCurrency.maxPreconvert[0] == 0 &&
                           newCurrency.GetTotalPreallocation() == 0) &&
                         !(newCurrency.systemID == ASSETCHAINS_CHAINID &&
                           ((newCurrency.GetTotalPreallocation() == 0 &&
                             newCurrency.maxPreconvert.size() == 1 &&
                             newCurrency.maxPreconvert[0] == 1) ||
                           (newCurrency.GetTotalPreallocation() == 1 &&
                             newCurrency.maxPreconvert.size() == 1 &&
                             newCurrency.maxPreconvert[0] == 0)))))
                    {
                        if (newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETHNFT)
                        {
                            return state.Error("Ethereum NFT mapped currency must have 0 satoshis of supply, maxpreconversions of [0], and follow all definition rules");
                        }
                        else
                        {
                            return state.Error("Tokenized ID control currency must have 1 satoshi of supply, and follow all definition rules");
                        }
                    }
                }

                // TODO: HARDENING - add hardening to ensure that no more than one satoshi at a time ever comes in from a bridge for an NFT mapped currency
                if (isNFTMappedCurrency && newCurrency.proofProtocol == newCurrency.PROOF_CHAINID)
                {
                    return state.Error("Identity must be set for tokenized control when defining NFT token or tokenized control currency");
                }

                if (isNFTMappedCurrency && !newIdentity.HasTokenizedControl())
                {
                    return state.Error("Identity must be set for tokenized control when defining NFT token or tokenized control currency");
                }

                if (newIdentity.parent != ASSETCHAINS_CHAINID &&
                    !isNFTMappedCurrency &&
                    !(parentCurrency.IsGateway() && parentCurrency.launchSystemID == ASSETCHAINS_CHAINID && !parentCurrency.IsNameController()))
                {
                    return state.Error("Only gateway and root chain identities may create non-NFT currencies");
                }

                if (newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETH &&
                    !(systemDef.proofProtocol == systemDef.PROOF_ETHNOTARIZATION &&
                      newCurrency.maxPreconvert.size() == 1 &&
                      newCurrency.maxPreconvert[0] == 0 &&
                      newCurrency.GetTotalPreallocation() == 0)  &&
                    !(newCurrency.systemID == newIdentity.parent ||
                      newIdentity.parent == ASSETCHAINS_CHAINID))
                {
                    return state.Error("Invalid mapped currency definition");
                }
            }
        }
    }
    return true;
}

// return currencies that are registered and may be exported to the specified system
// all returned currencies may also be used as 
std::set<uint160> BaseBridgeCurrencies(const CCurrencyDefinition &systemDest, uint32_t height, bool feeOnly)
{
    std::set<uint160> retVal;
    uint160 sysID = systemDest.GetID();
    // if this gateway or PBaaS chain was launched from this system
    if ((systemDest.IsPBaaSChain() || systemDest.IsGateway()) &&
        sysID != ASSETCHAINS_CHAINID &&
        (systemDest.launchSystemID == ASSETCHAINS_CHAINID || ConnectedChains.ThisChain().launchSystemID == sysID))
    {
        // we launched the system we are checking, or we were launched by the system we are checking
        // both cases involve the same lookups for the baseline. all connected, multi-currency systems
        // can accept this currency and the system's native currency
        retVal.insert(sysID);
        if (systemDest.IsMultiCurrency())
        {
            // whether or not we have a converter, launch currency can be used as fees for new system
            if (!feeOnly || systemDest.launchSystemID == ASSETCHAINS_CHAINID)
            {
                retVal.insert(ASSETCHAINS_CHAINID);
            }
            uint160 converterID = systemDest.launchSystemID == ASSETCHAINS_CHAINID ?
                                    systemDest.GatewayConverterID() :
                                    ConnectedChains.ThisChain().GatewayConverterID();
            if (!converterID.IsNull())
            {
                CCurrencyDefinition converter = ConnectedChains.GetCachedCurrency(converterID);
                if (converter.IsValid() && converter.IsFractional())
                {
                    retVal.insert(converterID);
                    for (auto &oneCurID : converter.currencies)
                    {
                        retVal.insert(oneCurID);
                    }
                }
            }
        }
    }
    return retVal;
}

// return currencies that are registered and may be exported to the specified system
std::set<uint160> ValidExportCurrencies(const CCurrencyDefinition &systemDest, uint32_t height)
{
    std::set<uint160> retVal = BaseBridgeCurrencies(systemDest, height, false);
    uint160 sysID = systemDest.GetID();

    // if this gateway or PBaaS chain was launched from this system
    if (retVal.size() && systemDest.IsMultiCurrency())
    {
        // now look for exported currency definitions
        std::vector<CAddressIndexDbEntry> addresses;
        // this will always validate correctly, even if the index for this block is present, as we only look up to height - 1
        if (GetAddressIndex(CTransferDestination::CurrencyExportKeyToSystem(sysID), CScript::P2IDX, addresses, 0, height - 1) &&
            addresses.size())
        {
            for (auto &oneIdx : addresses)
            {
                if (oneIdx.first.spending)
                {
                    continue;
                }
                uint256 blkHash;
                CTransaction rtTx;

                if (!myGetTransaction(oneIdx.first.txhash, rtTx, blkHash) || rtTx.vout.size() <= oneIdx.first.index)
                {
                    LogPrintf("%s: ERROR - ACTION REQUIRED: Invalid entry in transaction index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                    printf("%s: ERROR - ACTION REQUIRED: Invalid entry in transaction index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                    KOMODO_STOPAT = chainActive.Height();
                    return std::set<uint160>();
                }
                COptCCParams p;
                CReserveTransfer rt;
                CCurrencyDefinition exportCur;
                CCrossChainExport ccx;
                if (rtTx.vout[oneIdx.first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_RESERVE_TRANSFER &&
                    p.vData.size() &&
                    (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                    rt.IsCurrencyExport() &&
                    rt.IsCrossSystem() &&
                    rt.destSystemID == sysID &&
                    (exportCur = CCurrencyDefinition(rt.destination.destination)).IsValid())
                {
                    retVal.insert(exportCur.GetID());
                }
                else if (p.IsValid() &&
                            p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                            p.vData.size() &&
                            (ccx = CCrossChainExport(p.vData[0])).IsValid() &&
                            ccx.sourceSystemID != ASSETCHAINS_CHAINID &&
                            ccx.reserveTransfers.size())
                {
                    // look through reserve transfers for export imports
                    for (auto &oneRT : ccx.reserveTransfers)
                    {
                        if (oneRT.IsCurrencyExport())
                        {
                            // store the unbound and bound currency export index
                            // for each currency
                            retVal.insert(oneRT.FirstCurrency());
                        }
                    }
                }
            }
        }
    }
    return retVal;
}

// return currencies that are registered and may be exported to the specified system
bool IsValidExportCurrency(const CCurrencyDefinition &systemDest, const uint160 &exportCurrencyID, uint32_t height)
{
    std::set<uint160> retVal;
    uint160 sysID = systemDest.GetID();

    // assume the currency to export will be validity checked elsewhere,
    // if we are not exporting off chain, all valid currencies are OK
    if (sysID == ASSETCHAINS_CHAINID)
    {
        return true;
    }

    // if this gateway or PBaaS chain was launched from this system
    if ((systemDest.IsPBaaSChain() || systemDest.IsGateway()) &&
        sysID != ASSETCHAINS_CHAINID &&
        (systemDest.launchSystemID == ASSETCHAINS_CHAINID || ConnectedChains.ThisChain().launchSystemID == sysID))
    {
        if (exportCurrencyID == sysID)
        {
            return true;
        }
        if (!systemDest.IsMultiCurrency())
        {
            return false;
        }
        if (exportCurrencyID == ASSETCHAINS_CHAINID)
        {
            return true;
        }

        uint160 converterID = systemDest.GatewayConverterID();
        if (converterID.IsNull())
        {
            return false;
        }

        CCurrencyDefinition converter = ConnectedChains.GetCachedCurrency(converterID);
        if (converter.IsValid() && converter.IsFractional())
        {
            if (exportCurrencyID == converterID)
            {
                return true;
            }

            for (auto &oneCurID : converter.currencies)
            {
                if (exportCurrencyID == oneCurID)
                {
                    return true;
                }
            }
        }

        // now look for exported currency definitions
        std::vector<CAddressIndexDbEntry> addresses;
        // this will always validate correctly, even if the index for this block is present, as we only look up to height - 1
        if (GetAddressIndex(CTransferDestination::GetBoundCurrencyExportKey(sysID, exportCurrencyID),
                            CScript::P2IDX,
                            addresses, 0, height - 1) &&
            addresses.size())
        {
            for (auto &oneIdx : addresses)
            {
                if (oneIdx.first.spending)
                {
                    continue;
                }
                uint256 blkHash;
                CTransaction rtTx;

                if (!myGetTransaction(oneIdx.first.txhash, rtTx, blkHash) || rtTx.vout.size() <= oneIdx.first.index)
                {
                    LogPrintf("%s: ERROR - ACTION REQUIRED: Invalid entry in transaction index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                    printf("%s: ERROR - ACTION REQUIRED: Invalid entry in transaction index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                    KOMODO_STOPAT = chainActive.Height();
                    return false;
                }
                COptCCParams p;
                CReserveTransfer rt;
                CCurrencyDefinition exportCur;
                CCrossChainExport ccx;
                if (rtTx.vout[oneIdx.first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_RESERVE_TRANSFER &&
                    p.vData.size() &&
                    (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                    rt.IsCurrencyExport() &&
                    rt.IsCrossSystem() &&
                    rt.destSystemID == sysID &&
                    (exportCur = CCurrencyDefinition(rt.destination.destination)).IsValid() &&
                    exportCur.GetID() == exportCurrencyID)
                {
                    return true;
                }
                else if (p.IsValid() &&
                         p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                         p.vData.size() &&
                         (ccx = CCrossChainExport(p.vData[0])).IsValid() &&
                         ccx.sourceSystemID != ASSETCHAINS_CHAINID &&
                         ccx.reserveTransfers.size())
                {
                    // look through reserve transfers for export imports
                    for (auto &oneRT : ccx.reserveTransfers)
                    {
                        if (oneRT.IsCurrencyExport() && oneRT.FirstCurrency() == exportCurrencyID)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool PrecheckReserveTransfer(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // do a basic sanity check that this reserve transfer's values are consistent and that it includes the
    // basic fees required to cover the transfer
    COptCCParams p;
    CReserveTransfer rt;

    uint32_t chainHeight = chainActive.Height();
    bool haveFullChain = height <= chainHeight + 1;

    // TODO: HARDENING - go through all outputs of this transaction and do all reserve transfers at once, the
    // first time for the first reserve transfer output, if this is not the first, we will have checked them all, so
    // we are done

    // TODO: HARDENING - ensure that destinations and nested destinations are valid for the target system

    if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_RESERVE_TRANSFER &&
        p.vData.size() &&
        (rt = CReserveTransfer(p.vData[0])).IsValid() &&
        rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID] == tx.vout[outNum].nValue)
    {
        // arbitrage tranactions are determined by their context and statically setting the flags is prohibited
        if (rt.IsArbitrageOnly())
        {
            return state.Error("Reserve transfers may not be statically set as arbitrage transfers " + rt.ToUniValue().write(1,2));
        }

        // TODO: HARDENING - all cases of potential protocol issues with having a too large output need to be covered
        CDataStream ss(SER_DISK, PROTOCOL_VERSION);
        if (p.AsVector().size() > CScript::MAX_SCRIPT_ELEMENT_SIZE)
        {
            return state.Error("Reserve transferexceeds maximum size " + rt.ToUniValue().write(1,2));
        }

        // reserve transfers must be spendable by the export public / private key
        CCcontract_info CC;
        CCcontract_info *cp;

        // make a currency definition
        cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);

        bool haveRTKey = false;
        
        CTxDestination RTKey = DecodeDestination(cp->unspendableCCaddr);
        for (auto oneKey : p.vKeys)
        {
            if ((oneKey.which() == COptCCParams::ADDRTYPE_PK &&
                 RTKey.which() == COptCCParams::ADDRTYPE_PKH &&
                 GetDestinationID(oneKey) == GetDestinationID(RTKey)) ||
                oneKey == RTKey)
            {
                haveRTKey = true;
                break;
            }
        }
        COptCCParams master;
        if (!haveRTKey ||
            p.version < p.VERSION_V3 ||
            p.m != 1 ||
            p.vData.size() < 2 ||
            !(master = COptCCParams(p.vData.back())).IsValid() ||
            master.m > 1)
        {
            return state.Error("Reserve transfer must be spendable solely by private key of reserve transfer smart transaction " + rt.ToUniValue().write(1,2));
        }

        uint160 systemDestID, importCurrencyID;
        CCurrencyDefinition systemDest, importCurrencyDef;

        if (rt.IsImportToSource())
        {
            importCurrencyID = rt.FirstCurrency();
        }
        else
        {
            importCurrencyID = rt.destCurrencyID;
        }

        importCurrencyDef = ConnectedChains.GetCachedCurrency(importCurrencyID);

        // if we are an initial contribution for a currency definition, make sure we include the new currencies when checking
        std::vector<CCurrencyDefinition> newCurrencies;
        CCurrencyDefinition *pGatewayConverter = nullptr;
        std::set<uint160> definedCurrencyIDs;
        std::set<uint160> validExportCurrencies;
        uint160 gatewayConverterID;

        CCoinbaseCurrencyState importState;

        if (!(importCurrencyDef.IsValid() && (importState = ConnectedChains.GetCurrencyState(importCurrencyID, height)).IsValid()))
        {
            // only pre-conversion gets this benefit
            if (rt.IsPreConversion())
            {
                CPBaaSNotarization startingNotarization;
                CChainNotarizationData cnd;

                // the only case this is ok is if we are part of a currency definition and this is to a new currency
                // if that is the case, importCurrencyDef will always be invalid
                newCurrencies = CCurrencyDefinition::GetCurrencyDefinitions(tx);
                validExportCurrencies.insert(ASSETCHAINS_CHAINID);

                for (auto &oneCur : newCurrencies)
                {
                    uint160 oneCurID = oneCur.GetID();
                    definedCurrencyIDs.insert(oneCurID);
                    validExportCurrencies.insert(oneCurID);

                    if (oneCurID == importCurrencyID)
                    {
                        importCurrencyDef = oneCur;

                        CPBaaSNotarization oneNotarization;
                        CCurrencyDefinition tempCurDef;
                        importCurrencyDef = oneCur;
                        systemDestID = importCurrencyDef.SystemOrGatewayID();

                        // we need to get the first notarization and possibly systemDest currency here as well
                        for (auto &oneOut : tx.vout)
                        {
                            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid())
                            {
                                if ((p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                                    p.vData.size() &&
                                    (oneNotarization = CPBaaSNotarization(p.vData[0])).IsValid() &&
                                    oneNotarization.currencyID == importCurrencyID)
                                {
                                    importState = oneNotarization.currencyState;
                                }
                                else if ((p.evalCode == EVAL_CURRENCY_DEFINITION) &&
                                            p.vData.size() &&
                                            (tempCurDef = CCurrencyDefinition(p.vData[0])).IsValid() &&
                                            tempCurDef.GetID() == systemDestID)
                                {
                                    systemDest = tempCurDef;
                                }
                            }
                        }
                        if (oneCur.IsFractional())
                        {
                            for (auto &oneVEID : oneCur.currencies)
                            {
                                validExportCurrencies.insert(oneVEID);
                            }
                        }
                        if (gatewayConverterID.IsNull() && !(gatewayConverterID = oneCur.GatewayConverterID()).IsNull())
                        {
                            continue;
                        }
                    }
                    else if (gatewayConverterID == oneCurID)
                    {
                        pGatewayConverter = &oneCur;
                        for (auto &oneVEID : oneCur.currencies)
                        {
                            validExportCurrencies.insert(oneVEID);
                        }
                    }
                }
            }
        }

        if (!(importCurrencyDef.IsValid() && importState.IsValid()))
        {
            if (!haveFullChain)
            {
                return true;
            }
            // the only case this is ok is if we are part of a currency definition and this is to a new currency
            // if that is the case, importCurrencyDef will always be invalid
            if (!importCurrencyDef.IsValid())
            {
                return state.Error("Invalid currency in reserve transfer " + rt.ToUniValue().write(1,2));
            }
            else
            {
                return state.Error("Valid currency state required and not found for import currency of reserve transfer " + rt.ToUniValue().write(1,2));
            }
        }

        if (!systemDest.IsValid())
        {
            systemDestID = importCurrencyDef.SystemOrGatewayID();
            systemDest = systemDestID == importCurrencyID ? importCurrencyDef : ConnectedChains.GetCachedCurrency(systemDestID);
        }

        if (!systemDest.IsValid())
        {
            if (!haveFullChain)
            {
                return true;
            }
            return state.Error("Invalid currency system in reserve transfer " + rt.ToUniValue().write(1,2));
        }

        if (rt.flags & rt.CROSS_SYSTEM)
        {
            if (systemDestID != rt.destSystemID)
            {
                return state.Error("Mismatched destination system in reserve transfer " + rt.ToUniValue().write(1,2));
            }
        }

        CReserveTransactionDescriptor rtxd;
        CCoinbaseCurrencyState dummyState = importState;
        std::vector<CTxOut> vOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsIn, spentCurrencyOut;
        CCurrencyValueMap newPreConversionReservesIn = rt.TotalCurrencyOut();
        CCurrencyValueMap feeConversionPrices;

        if (importState.IsPrelaunch())
        {
            if (!rt.IsPreConversion())
            {
                return state.Error("Only preconversion transfers are valid during the prelaunch phase of a currency " + rt.ToUniValue().write(1,2));
            }
            if (rt.FeeCurrencyID() != importCurrencyDef.launchSystemID || importCurrencyDef.launchSystemID.IsNull())
            {
                return state.Error("Preconversion transfers must use the native fee currency of the launching system " + rt.ToUniValue().write(1,2));
            }
        }

        if (importCurrencyDef.IsFractional() && importState.IsLaunchConfirmed())
        {
            feeConversionPrices = importState.TargetConversionPrices(systemDestID);
        }
        if (importCurrencyDef.IsFractional() && !(importState.IsLaunchConfirmed() && !importState.IsLaunchCompleteMarker()))
        {
            // normalize prices on the way in to prevent overflows on first pass
            std::vector<int64_t> newReservesVector = newPreConversionReservesIn.AsCurrencyVector(importState.currencies);
            dummyState.reserves = dummyState.AddVectors(dummyState.reserves, newReservesVector);
            importState.conversionPrice = dummyState.PricesInReserve();
        }
        if (importState.currencies.size() != importState.conversionPrice.size())
        {
            importState.conversionPrice = dummyState.PricesInReserve();
        }

        CAmount feeEquivalentInNative = rt.feeCurrencyID == systemDestID ? rt.nFees : 0;

        if (importCurrencyDef.IsFractional())
        {
            auto reserveMap = importState.GetReserveMap();

            // fee currency must be destination,
            // if some fees may be coming from the conversion, calculate them
            if (rt.IsPreConversion() || !feeConversionPrices.valueMap.count(systemDestID) || !feeConversionPrices.valueMap.count(rt.feeCurrencyID))
            {
                // preconversion must have standard fees included
                if (rt.feeCurrencyID == systemDestID || rt.feeCurrencyID == systemDest.launchSystemID)
                {
                    feeEquivalentInNative += rt.nFees;
                }
                else
                {
                    return state.Error("Invalid fee currency in reserve transfer 1: " + rt.ToUniValue().write(1,2));
                }
            }
            else
            {
                // figure out all appropriate fees at current prices
                // first non-conversion fees
                if (!feeEquivalentInNative && rt.feeCurrencyID != systemDestID)
                {
                    if (!feeConversionPrices.valueMap.count(rt.feeCurrencyID))
                    {
                        return state.Error("Invalid fee currency in reserve transfer 2: " + rt.ToUniValue().write(1,2));
                    }
                    feeEquivalentInNative = CCurrencyState::ReserveToNativeRaw(rt.nFees, feeConversionPrices.valueMap[rt.feeCurrencyID]);
                }

                // all we have to do now is determine fees for conversion and add them to the explicit fees
                if (rt.IsConversion())
                {
                    CAmount conversionFeeInCur = CReserveTransactionDescriptor::CalculateConversionFee(rt.FirstValue());

                    uint160 expectedImportID = rt.IsImportToSource() ? rt.FirstCurrency() : rt.destCurrencyID;

                    // double conversion for reserve to reserve
                    if (expectedImportID != importCurrencyID)
                    {
                        return state.Error("Invalid import currency specified " + rt.ToUniValue().write(1,2));
                    }
                    else
                    {
                        if (rt.secondReserveID.IsNull() && rt.IsReserveToReserve() || !rt.secondReserveID.IsNull() && !rt.IsReserveToReserve())
                        {
                            return state.Error("Conversion is reserve to reserve but not specified or vice versa " + rt.ToUniValue().write(1,2));
                        }

                        if (rt.IsReserveToReserve())
                        {
                            if (!importCurrencyDef.GetCurrenciesMap().count(rt.secondReserveID))
                            {
                                return state.Error("Invalid reserve to reserve conversion " + rt.ToUniValue().write(1,2));
                            }
                            conversionFeeInCur <<= 1;
                        }
                    }
                    
                    feeEquivalentInNative += CCurrencyState::ReserveToNativeRaw(conversionFeeInCur,
                                                                                feeConversionPrices.valueMap[rt.FirstCurrency()]);
                }
            }
        }
        else if (rt.IsConversion() && !rt.IsPreConversion())
        {
            return state.Error("Invalid conversion requested through non-fractional currency " + rt.ToUniValue().write(1,2));
        }
        else if (rt.feeCurrencyID != systemDestID)
        {
            if (systemDest.launchSystemID.IsNull() || rt.feeCurrencyID != systemDest.launchSystemID)
            {
                return state.Error("Invalid fee currency in reserve transfer 3: " + rt.ToUniValue().write(1,2));
            }
            else
            {
                feeEquivalentInNative += rt.nFees;
            }
        }

        if (rt.IsCurrencyExport())
        {
            CCurrencyDefinition curToExport, exportDestination;
            if (rt.reserveValues > CCurrencyValueMap())
            {
                return state.Error("Currency exports should not include explicit funds beyond required fees " + rt.ToUniValue().write(1,2));
            }

            // if this is a cross chain export, the first currency must be valid and equal the exported currency
            // otherwise, we only need to ensure that the exported currency can be sent to the target destination
            // its definition will be added next round

            if (importCurrencyDef.systemID == ASSETCHAINS_CHAINID &&
                rt.HasNextLeg() &&
                rt.destination.gatewayID != ASSETCHAINS_CHAINID)
            {
                exportDestination = ConnectedChains.GetCachedCurrency(rt.destination.gatewayID);
                if (!(curToExport = ConnectedChains.GetCachedCurrency(rt.FirstCurrency())).IsValid())
                {
                    return state.Error("Invalid currency export in reserve transfer " + rt.ToUniValue().write(1,2));
                }
                if (!exportDestination.IsValid() ||
                    !exportDestination.IsMultiCurrency() ||
                    exportDestination.SystemOrGatewayID() != rt.destination.gatewayID ||
                    exportDestination.SystemOrGatewayID() == ASSETCHAINS_CHAINID ||
                    IsValidExportCurrency(exportDestination, rt.FirstCurrency(), height))
                {
                    return state.Error("Invalid currency export for next leg in reserve transfer " + rt.ToUniValue().write(1,2));
                }
                if (!systemDest.IsValidTransferDestinationType(rt.destination.TypeNoFlags()))
                {
                    return state.Error("Invalid reserve transfer destination for target system" + rt.ToUniValue().write(1,2));
                }
                if (feeEquivalentInNative < systemDest.GetTransactionTransferFee())
                {
                    return state.Error("Not enough fee for first step of currency import in reserve transfer " + rt.ToUniValue().write(1,2));
                }
                feeConversionPrices = importState.TargetConversionPrices(rt.destination.gatewayID);
                feeEquivalentInNative = CCurrencyState::ReserveToNativeRaw(rt.destination.fees, feeConversionPrices.valueMap[rt.feeCurrencyID]);
            }
            else if (!(rt.flags & rt.CROSS_SYSTEM) ||
                     rt.destination.TypeNoFlags() != rt.destination.DEST_REGISTERCURRENCY ||
                     !(curToExport = CCurrencyDefinition(rt.destination.destination)).IsValid() ||
                     curToExport.GetID() != rt.FirstCurrency())
            {
                return state.Error("Invalid currency export in reserve transfer " + rt.ToUniValue().write(1,2));
            }
            else
            {
                CCurrencyDefinition registeredCurrency = ConnectedChains.GetCachedCurrency(rt.FirstCurrency());

                if (::AsVector(registeredCurrency) != rt.destination.destination)
                {
                    return state.Error("Mismatched export and currency registration in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                if (!systemDest.IsMultiCurrency() || IsValidExportCurrency(systemDest, rt.FirstCurrency(), height))
                {
                    // if destination system is not multicurrency or currency is already a valid export currency, invalid
                    return state.Error("Unnecessary currency definition export in reserve transfer " + rt.ToUniValue().write(1,2));
                }
                curToExport = registeredCurrency;
                exportDestination = systemDest;
            }

            // ensure that we have enough fees for the currency definition import
            if (feeEquivalentInNative < systemDest.GetCurrencyImportFee(curToExport.ChainOptions() & curToExport.OPTION_NFT_TOKEN))
            {
                return state.Error("Not enough fee for currency import in reserve transfer " + rt.ToUniValue().write(1,2));
            }

            // ensure that it makes sense for us to export this currency from this system to the other
            if (!CConnectedChains::IsValidCurrencyDefinitionImport(ConnectedChains.ThisChain(), exportDestination, curToExport, height))
            {
                return state.Error("Invalid to export specified currency to destination system " + rt.ToUniValue().write(1,2));
            }
        }
        else
        {
            if (systemDestID != ASSETCHAINS_CHAINID && !rt.IsPreConversion())
            {
                validExportCurrencies = ValidExportCurrencies(systemDest, height);
            }

            if ((validExportCurrencies.size() && !validExportCurrencies.count(rt.FirstCurrency())) ||
                (!validExportCurrencies.size() && !IsValidExportCurrency(systemDest, rt.FirstCurrency(), height)))
            {
                // if destination system is not multicurrency or currency is already a valid export currency, invalid
                return state.Error("Invalid currency export in reserve transfer " + rt.ToUniValue().write(1,2));
            }

            if (rt.IsIdentityExport())
            {
                CIdentity idToExport;
                CCurrencyDefinition exportDestination;

                if (!((rt.IsCrossSystem() &&
                       rt.destination.TypeNoFlags() == rt.destination.DEST_FULLID &&
                       (idToExport = CIdentity(rt.destination.destination)).IsValid()) ||
                      (!rt.IsCrossSystem() && rt.destination.TypeNoFlags() == rt.destination.DEST_ID && rt.HasNextLeg())))
                {
                    return state.Error("Invalid identity export in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                CIdentity registeredIdentity = CIdentity::LookupIdentity(GetDestinationID(TransferDestinationToDestination(rt.destination)), height);

                if (!registeredIdentity.IsValid())
                {
                    return state.Error("Invalid identity export in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                if (rt.IsCrossSystem())
                {
                    // validate everything relating to name and control
                    if (registeredIdentity.primaryAddresses != idToExport.primaryAddresses ||
                        registeredIdentity.minSigs != idToExport.minSigs ||
                        registeredIdentity.revocationAuthority != idToExport.revocationAuthority ||
                        registeredIdentity.recoveryAuthority != idToExport.recoveryAuthority ||
                        registeredIdentity.privateAddresses != idToExport.privateAddresses ||
                        registeredIdentity.parent != idToExport.parent ||
                        boost::to_lower_copy(registeredIdentity.name) != boost::to_lower_copy(idToExport.name))
                    {
                        return state.Error("Identity being exported in reserve transfer does not match blockchain identity control " + rt.ToUniValue().write(1,2));
                    }

                    if (!(exportDestination = ConnectedChains.GetCachedCurrency(rt.SystemDestination())).IsValid())
                    {
                        return state.Error("Invalid export destination in reserve transfer with identity export " + rt.ToUniValue().write(1,2));
                    }
                }
                else
                {
                    if (feeEquivalentInNative < systemDest.GetTransactionTransferFee())
                    {
                        return state.Error("Not enough fee for first step of currency import in reserve transfer " + rt.ToUniValue().write(1,2));
                    }
                    feeConversionPrices = importState.TargetConversionPrices(rt.destination.gatewayID);
                    feeEquivalentInNative = CCurrencyState::ReserveToNativeRaw(rt.destination.fees, feeConversionPrices.valueMap[rt.feeCurrencyID]);
                }

                // ensure that we have enough fees for the identity import
                if (feeEquivalentInNative < systemDest.IDImportFee())
                {
                    return state.Error("Not enough fee for identity import in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                if (!CConnectedChains::IsValidIdentityDefinitionImport(ConnectedChains.ThisChain(), systemDest, registeredIdentity, height))
                {
                    return state.Error("Invalid to export specified identity to destination system " + rt.ToUniValue().write(1,2));
                }
            }
            else
            {
                int destType = rt.destination.TypeNoFlags();
                CTxDestination dest = TransferDestinationToDestination(rt.destination);
                if (destType == rt.destination.DEST_ETH)
                {
                    uint160 ethDest;
                    try
                    {
                        ::FromVector(rt.destination.destination, ethDest);
                    }
                    catch(...)
                    {
                        ethDest = uint160();
                    }
                    if (ethDest.IsNull())
                    {
                        return state.Error("Invalid Ethereum transfer destination");
                    }
                }
                else if (dest.which() != COptCCParams::ADDRTYPE_ID && dest.which() != COptCCParams::ADDRTYPE_PKH && dest.which() != COptCCParams::ADDRTYPE_SH)
                {
                    if (rt.destination.TypeNoFlags() != rt.destination.DEST_RAW)
                    {
                        return state.Error("Invalid transfer destination");
                    }
                    // TODO: HARDENING - either disable raw support or add support for raw gateway
                }
                else if (GetDestinationID(dest).IsNull())
                {
                    return state.Error("NULL is an invalid transfer destination");
                }

                // ensure that we have enough fees for transfer
                if (systemDestID != ASSETCHAINS_CHAINID && !rt.IsPreConversion())
                {
                    if (feeEquivalentInNative < systemDest.GetTransactionImportFee())
                    {
                        return state.Error("Not enough fee for cross chain currency operation in reserve transfer " + rt.ToUniValue().write(1,2));
                    }
                }
                else if (feeEquivalentInNative < systemDest.GetTransactionTransferFee())
                {
                    return state.Error("Not enough fee for same chain currency operation in reserve transfer " + rt.ToUniValue().write(1,2));
                }
            }

            if (rt.IsMint() || rt.IsBurnChangeWeight())
            {
                if (importCurrencyDef.proofProtocol != importCurrencyDef.PROOF_CHAINID ||
                    importCurrencyDef.SystemOrGatewayID() != ASSETCHAINS_CHAINID)
                {
                    return state.Error("Minting and/or burning while changing reserve ratios is only allowed in centralized (\"proofprotocol\":2) currencies on their native chain " + rt.ToUniValue().write(1,2));
                }
                // spent by currency ID
                bool authorizedController = false;

                CIdentity signingID = CIdentity::LookupIdentity(importCurrencyID, height);
                std::set<uint160> signingKeys;
                for (auto &oneDest : signingID.primaryAddresses)
                {
                    signingKeys.insert(GetDestinationID(oneDest));
                }
                if (!signingID.IsValid())
                {
                    return state.Error("Invalid identity or identity not found for currency mint or burn with weight change");
                }

                for (auto &oneIn : tx.vin)
                {
                    CTransaction inputTx;
                    uint256 blockHash;

                    // this is not an input check, but we will check if the input is available
                    // the precheck's can be called sometimes before their antecedents are available, but
                    // if they are available, which will be checked on the input check, they will also be
                    // available here at least once in the verification of the tx
                    if (myGetTransaction(oneIn.prevout.hash, inputTx, blockHash))
                    {
                        if (oneIn.prevout.n >= inputTx.vout.size())
                        {
                            return state.Error("Invalid input number for source transaction");
                        }

                        COptCCParams p;

                        // make sure that no form of complex output could circumvent the test for controller
                        // this should be encapsulated as a test that can handle complex cases, but until then
                        // require them to be simple when validating
                        if (!(inputTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                              p.IsValid() &&
                              p.version >= p.VERSION_V3 &&
                              inputTx.vout[oneIn.prevout.n].scriptPubKey.IsSpendableOutputType(p)))
                        {
                            continue;
                        }

                        CSmartTransactionSignatures smartSigs;
                        std::vector<unsigned char> ffVec = GetFulfillmentVector(oneIn.scriptSig);
                        if (!(ffVec.size() &&
                              (smartSigs = CSmartTransactionSignatures(std::vector<unsigned char>(ffVec.begin(), ffVec.end()))).IsValid() &&
                              smartSigs.sigHashType == SIGHASH_ALL))
                        {
                            continue;
                        }

                        int numIDSigs = 0;

                        // ensure that the transaction is sent to the ID and signed by a valid ID signature
                        for (auto &oneSig : smartSigs.signatures)
                        {
                            if (signingKeys.count(oneSig.first))
                            {
                                numIDSigs++;
                            }
                        }

                        if (numIDSigs < signingID.minSigs)
                        {
                            continue;
                        }
                        authorizedController = true;
                        break;
                    }
                }

                if (!authorizedController)
                {
                    return state.Error("Minting and/or burning while changing reserve ratios is only allowed by the controller of a centralized currency " + rt.ToUniValue().write(1,2));
                }
            }
        }

        if (!rt.HasNextLeg() && !systemDest.IsValidTransferDestinationType(rt.destination.TypeNoFlags()))
        {
            return state.Error("Invalid reserve transfer destination for target system" + rt.ToUniValue().write(1,2));
        }

        if (rtxd.AddReserveTransferImportOutputs(ConnectedChains.ThisChain(), 
                                                 systemDest, 
                                                 importCurrencyDef, 
                                                 importState,
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
    return state.Error("Invalid reserve transfer " + rt.ToUniValue().write(1,2));
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

CAmount CCrossChainExport::ExportReward(const CCurrencyDefinition &destSystem, int64_t exportFee)
{
    // by default, the individual exporter gets 1/10 of the export fee, which is sent directly to the exporter
    // on the importing system
    int64_t individualExportFee = ((arith_uint256(exportFee) * 10000000) / SATOSHIDEN).GetLow64();
    // if 1/10th of the transfer fee is less than 2x a standard transfer fee, ensure that the exporter
    // gets a standard transfer fee or whatever is available
    CAmount minFee = destSystem.GetTransactionTransferFee() << 1;
    if (individualExportFee < minFee)
    {
        individualExportFee = exportFee > minFee ? minFee : exportFee;
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

bool CConnectedChains::GetLastBlock(CBlock &block, uint32_t height)
{
    LOCK(cs_mergemining);
    if (lastBlockHeight == height && (GetAdjustedTime() - block.nTime) > (Params().consensus.nPowTargetSpacing / 2))
    {
        block = lastBlock;
        return true;
    }
    return false;
}

void CConnectedChains::SetLastBlock(CBlock &block, uint32_t height)
{
    LOCK(cs_mergemining);
    if (lastBlock.GetHash() != block.GetHash())
    {
        lastBlock = block;
        lastBlockHeight = height;
    }
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
    target.SetCompact(bh.nBits);
    
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
    if (!notarySystems.size())
    {
        return 0;
    }
    return notarySystems.begin()->second.height;
}

CProofRoot CConnectedChains::ConfirmedNotaryChainRoot()
{
    CProofRoot invalidRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);

    LOCK(cs_mergemining);
    if (!notarySystems.size())
    {
        return invalidRoot;
    }
    uint160 notaryChainID = notarySystems.begin()->second.notaryChain.GetID();
    return notarySystems.begin()->second.lastConfirmedNotarization.proofRoots.count(notaryChainID) ?
                notarySystems.begin()->second.lastConfirmedNotarization.proofRoots[notaryChainID] :
                invalidRoot;
}

CProofRoot CConnectedChains::FinalizedChainRoot()
{
    CProofRoot invalidRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);

    LOCK(cs_mergemining);
    if (!notarySystems.size())
    {
        return invalidRoot;
    }
    uint160 notaryChainID = notarySystems.begin()->second.notaryChain.GetID();
    return notarySystems.begin()->second.lastConfirmedNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ?
                notarySystems.begin()->second.lastConfirmedNotarization.proofRoots[ASSETCHAINS_CHAINID] :
                invalidRoot;
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
                chainDef = FirstNotaryChain().chainDefinition.launchSystemID == ASSETCHAINS_CHAINID ?
                            FirstNotaryChain().chainDefinition.ToUniValue() :
                            find_value(RPCCallRoot("getcurrency", params), "result");

                if (!chainDef.isNull() && CheckVerusPBaaSAvailable(chainInfo, chainDef))
                {
                    if (GetBoolArg("-miningdistributionpassthrough", false))
                    {
                        UniValue miningDistributionUni = find_value(RPCCallRoot("getminingdistribution", params), "result");
                        if (miningDistributionUni.isArray() && miningDistributionUni.size())
                        {
                            mapArgs["-miningdistribution"] = miningDistributionUni.write();
                        }
                    }

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
            LogPrint("crosschain", "%s: Error communicating with %s\n", __func__, FirstNotaryChain().chainDefinition.name.c_str());
        }
    }
    return false;
}

bool CConnectedChains::IsNotaryAvailable(bool callToCheck)
{
    if (!callToCheck)
    {
        // if we aren't checking, we consider unavailable no contact in the last two minutes
        return FirstNotaryChain().IsValid() && (GetTime() - FirstNotaryChain().LastConnectionTime() < (120000));
    }
    return !(FirstNotaryChain().rpcHost.empty() || FirstNotaryChain().rpcPort == 0 || FirstNotaryChain().rpcUserPass.empty()) &&
           CheckVerusPBaaSAvailable();
}

bool CConnectedChains::ConfigureEthBridge(bool callToCheck)
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
        return IsNotaryAvailable(callToCheck);
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
        if (ReadConfigFile("veth", settings, settingsmulti) &&
            settingsmulti.count("-rpchost") &&
            settingsmulti.count("-rpcuser") &&
            settingsmulti.count("-rpcport") &&
            settingsmulti.count("-rpcpassword"))
        {
            // the Ethereum bridge, "VETH", serves as the root currency to VRSC and for Rinkeby to VRSCTEST
            vethNotaryChain.rpcUserPass = PBAAS_USERPASS = settingsmulti.find("-rpcuser")->second[0] + ":" + settingsmulti.find("-rpcpassword")->second[0];
            vethNotaryChain.rpcPort = PBAAS_PORT = atoi(settingsmulti.find("-rpcport")->second[0]);
            PBAAS_HOST = settingsmulti.find("-rpchost")->second[0];
        }
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
        return IsNotaryAvailable(callToCheck);
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
            if (curDef.IsGatewayConverter() && curDef.gatewayConverterIssuance)
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

    if ((IsVerusActive() || height == 0) && chainID == ASSETCHAINS_CHAINID)
    {
        currencyState = GetInitialCurrencyState(thisChain);
        currencyState.SetLaunchConfirmed();
    }
    // if this is a token on this chain, it will be simply notarized
    else if (curDef.SystemOrGatewayID() == ASSETCHAINS_CHAINID || (curDef.launchSystemID == ASSETCHAINS_CHAINID && curDef.startBlock > height))
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
        if (currencyState.IsValid() && (curDef.launchSystemID == ASSETCHAINS_CHAINID && curDef.startBlock && notarization.notarizationHeight < (curDef.startBlock - 1)))
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
                        currencyState.supply = curDef.GetTotalPreallocation() + curDef.gatewayConverterIssuance;
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
        else
        {
            currencyState = GetInitialCurrencyState(curDef);
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

CCurrencyDefinition CConnectedChains::UpdateCachedCurrency(const CCurrencyDefinition &currencyDef, uint32_t height)
{
    // due to the main lock being taken on the thread that waits for transaction checks,
    // low level functions like this must be called either from a thread that holds LOCK(cs_main),
    // or script validation, where it is held either by this thread or one waiting for it.
    // in the long run, the daemon synchonrization model should be improved
    uint160 currencyID = currencyDef.GetID();
    CCurrencyDefinition retVal = currencyDef;
    currencyDefCache[currencyID] = retVal;
    if (currencyID == ASSETCHAINS_CHAINID)
    {
        ThisChain() = retVal;
    }
    return retVal;
}

// this must be protected with main lock
std::string CConnectedChains::GetFriendlyCurrencyName(const uint160 &currencyID)
{
    // basically, we lookup parent until we are at the native currency
    std::string retName;
    uint160 curID = currencyID;
    CCurrencyDefinition curDef;
    for (curDef = GetCachedCurrency(curID); curDef.IsValid(); curDef = GetCachedCurrency(curID))
    {
        if (curDef.parent.IsNull())
        {
            // if we are at a Verus root, we can omit it unless there is nothing else
            if (curDef.GetID() == VERUS_CHAINID)
            {
                if (retName.empty())
                {
                    retName = curDef.name;
                }
            }
            else
            {
                // if we are at a root that is not Verus, add it and then a "."
                retName += ".";
            }
        }
        else
        {
            if (retName.empty())
            {
                retName = curDef.name;
            }
            else
            {
                retName += "." + curDef.name;
            }
        }
        curID = curDef.parent;
    }
    return retName;
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
        std::set<COutPoint> spentMemPoolOuts;
        for (auto &oneExport : exportUTXOs)
        {
            if (oneExport.first.spending)
            {
                spentMemPoolOuts.insert(COutPoint(oneExport.second.prevhash, oneExport.second.prevout));
            }
            else
            {
                const CCoins *coin = view.AccessCoins(oneExport.first.txhash);
                if (coin->IsAvailable(oneExport.first.index))
                {
                    memPoolOuts.insert(std::make_pair(COutPoint(oneExport.first.txhash, oneExport.first.index),
                                                      CInputDescriptor(coin->vout[oneExport.first.index].scriptPubKey, oneExport.second.amount, 
                                                                       CTxIn(oneExport.first.txhash, oneExport.first.index))));
                }
            }
        }

        for (auto &oneUTXO : memPoolOuts)
        {
            if (!spentMemPoolOuts.count(oneUTXO.first))
            {
                exportOuts.push_back(std::make_pair(0, oneUTXO.second));
            }
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
        std::set<COutPoint> spentMemPoolOuts;
        for (auto &oneExport : exportUTXOs)
        {
            if (oneExport.first.spending)
            {
                spentMemPoolOuts.insert(COutPoint(oneExport.second.prevhash, oneExport.second.prevout));
            }
            else
            {
                const CCoins *coin = view.AccessCoins(oneExport.first.txhash);
                if (coin->IsAvailable(oneExport.first.index))
                {
                    memPoolOuts.insert(std::make_pair(COutPoint(oneExport.first.txhash, oneExport.first.index),
                                                      CInputDescriptor(coin->vout[oneExport.first.index].scriptPubKey, oneExport.second.amount, 
                                                                       CTxIn(oneExport.first.txhash, oneExport.first.index))));
                }
            }
        }

        for (auto &oneUTXO : memPoolOuts)
        {
            if (!spentMemPoolOuts.count(oneUTXO.first))
            {
                exportOuts.push_back(std::make_pair(0, oneUTXO.second));
            }
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
    LOCK(cs_main);
    LOCK2(smartTransactionCS, mempool.cs);

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
                (refundingPBaaSChain = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID)).IsValid() &&
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

            // TODO: HARDENING - ensure that we enforce in order export and in order import of exports, should be covered, but ensure it is

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
                lastNotarization.proposer = proofNotarization.proposer;
                lastNotarization.proofRoots[sourceSystemID] = proofNotarization.proofRoots[sourceSystemID];
                if (lastNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
                {
                    lastNotarization.proofRoots[ASSETCHAINS_CHAINID] = proofNotarization.proofRoots[ASSETCHAINS_CHAINID];
                }
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

        // this is a place where we can
        // provide a callout for arbitrage and potentially get an additional reserve transfer
        // input for this import. we should also add it to the exportTransfers vector
        // with the arbitrage flag set
        CInputDescriptor arbitrageTransferIn;
        if (LogAcceptCategory("arbitrageliquidity") &&
            destCur.IsFractional() &&
            lastNotarization.IsLaunchComplete() &&
            !lastNotarization.IsRefunding())
        {
            // TODO: HARDENING - this is not technically hardening, but this arbitrage ability needs to be tested as part of hardening
            // look for the largest unspent output that is not yet eligible for an export
        }

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

        uint32_t nextHeight = useProofs && destCur.SystemOrGatewayID() == ASSETCHAINS_CHAINID || destCurID == ASSETCHAINS_CHAINID ?
            nextHeight = nHeight : std::max(ccx.sourceHeightEnd, lastNotarization.notarizationHeight);

        if (ccx.IsPostlaunch() || lastNotarization.IsLaunchComplete())
        {
            lastNotarization.currencyState.SetLaunchCompleteMarker();
        }

        if (!lastNotarization.NextNotarizationInfo(sourceSystemDef,
                                                   destCur,
                                                   ccx.sourceHeightStart,
                                                   nextHeight,
                                                   exportTransfers,
                                                   transferHash,
                                                   newNotarization,
                                                   newOutputs,
                                                   importedCurrency,
                                                   gatewayDepositsUsed,
                                                   spentCurrencyOut,
                                                   ccx.exporter))
        {
            LogPrintf("%s: invalid export for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
            return false;
        }

        // after the last clear launch export is imported, we have completed launch
        if (ccx.IsClearLaunch())
        {
            newNotarization.SetLaunchComplete();
            newNotarization.currencyState.SetLaunchCompleteMarker();
        }

        newNotarization.prevNotarization = CUTXORef(lastNotarizationOut.txIn.prevout.hash, lastNotarizationOut.txIn.prevout.n);

        CAmount newPrimaryCurrency = newNotarization.currencyState.primaryCurrencyOut;
        CCurrencyValueMap incomingCurrency = importedCurrency + gatewayDepositsUsed;
        if (newPrimaryCurrency > 0)
        {
            incomingCurrency.valueMap[destCurID] += newPrimaryCurrency;
        }
        CCurrencyValueMap newLocalReserveDeposits = incomingCurrency.SubtractToZero(spentCurrencyOut).CanonicalMap();
        CCurrencyValueMap newLocalDepositsRequired = (((incomingCurrency - spentCurrencyOut) - newLocalReserveDeposits).CanonicalMap() * -1);
        if (newPrimaryCurrency < 0)
        {
            // we need to come up with this currency, as it will be burned
            incomingCurrency.valueMap[destCurID] += newPrimaryCurrency;
            newLocalDepositsRequired.valueMap[destCurID] -= newPrimaryCurrency;
        }

        LogPrint("crosschainimports", "%s: newNotarization:\n%s\n", __func__, newNotarization.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: ccx.totalAmounts: %s\ngatewayDepositsUsed: %s\nimportedCurrency: %s\nspentCurrencyOut: %s\n",
            __func__,
            ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
            gatewayDepositsUsed.ToUniValue().write(1,2).c_str(),
            importedCurrency.ToUniValue().write(1,2).c_str(),
            spentCurrencyOut.ToUniValue().write(1,2).c_str());

        LogPrint("crosschainimports", "%s: incomingCurrency: %s\ncurrencyChange: %s\nnewLocalDepositsRequired: %s\n",
            __func__,
            incomingCurrency.ToUniValue().write(1,2).c_str(),
            newLocalReserveDeposits.ToUniValue().write(1,2).c_str(),
            newLocalDepositsRequired.ToUniValue().write(1,2).c_str());

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
        if (useProofs && cci.sourceSystemID != cci.importCurrencyID)
        {
            // we need a new import for the source system
            sysCCI = cci;
            sysCCI.importCurrencyID = sysCCI.sourceSystemID;
            sysCCI.flags |= sysCCI.FLAG_SOURCESYSTEM;

            // for exports to the native chain, the system export thread is merged with currency export, so no need to go to next
            if (cci.importCurrencyID != ASSETCHAINS_CHAINID)
            {
                // the source of the export is an external system
                // only in PBaaS chains do we assume the export out increments
                // for gateways or other chains, they must use the same output number and adjust on the other
                // side as needed

                // TODO: HARDENING - this requirement needs to be cleaned up to provide for
                // the ETH-like model, which doesn't benefit from this and the PBaaS model, which does
                // being an option for external chains as well
                if (sourceSystemDef.IsPBaaSChain())
                {
                    sysCCI.exportTxOutNum++;                        // source thread output is +1 from the input
                }
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
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            CDataStream ds(SER_DISK, PROTOCOL_VERSION);

            // if we need to put the partial transaction proof and follow it with reserve transfers, do it
            // now, we need to put the launch notarization evidence, followed by the import outputs
            CCrossChainProof evidenceProof;
            evidenceProof << oneIT.first.second;
            CNotaryEvidence evidence = CNotaryEvidence(destCurID,
                                                       CUTXORef(confirmedSourceNotarization.hash, confirmedSourceNotarization.n),
                                                       CNotaryEvidence::STATE_CONFIRMED,
                                                       evidenceProof,
                                                       CNotaryEvidence::TYPE_IMPORT_PROOF);

            int serSize = GetSerializeSize(ds, evidence);

            // the value should be considered for reduction
            if (serSize > CScript::MAX_SCRIPT_ELEMENT_SIZE)
            {
                auto evidenceVec = evidence.BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - 128);
                if (!evidenceVec.size())
                {
                    LogPrintf("%s: failed to package evidence from system %s\n", __func__, EncodeDestination(CIdentityID(ccx.sourceSystemID)).c_str());
                    return false;
                }
                for (auto &oneProof : evidenceVec)
                {
                    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof)), 0);
                }
            }
            else
            {
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence)), 0);
            }

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
            if (useProofs && cci.sourceSystemID != cci.importCurrencyID)
            {
                tb.AddTransparentInput(COutPoint(lastSourceImportTxID, sourceOutputNum), 
                                       lastSourceImportTx.vout[sourceOutputNum].scriptPubKey, lastSourceImportTx.vout[sourceOutputNum].nValue);
            }

            // if we qualify to add and also have an additional reserve transfer
            // add it as an input
            if (lastNotarization.currencyState.IsFractional() &&
                lastNotarization.IsLaunchComplete() &&
                !lastNotarization.IsRefunding() &&
                !arbitrageTransferIn.txIn.prevout.hash.IsNull())
            {
                tb.AddTransparentInput(arbitrageTransferIn.txIn.prevout, arbitrageTransferIn.scriptPubKey, arbitrageTransferIn.nValue);
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

            gatewayChange = (totalDepositsInput - gatewayDepositsUsed).CanonicalMap();

            LogPrint("crosschainimports", "%s: gatewayDepositsUsed: %s\n", __func__, gatewayDepositsUsed.ToUniValue().write(1,2).c_str());
            LogPrint("crosschainimports", "%s: gatewayChange: %s\n", __func__, gatewayChange.ToUniValue().write(1,2).c_str());

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

        LogPrint("crosschainimports", "%s: newNotarization.currencyState: %s\n", __func__, newNotarization.currencyState.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: cci: %s\n", __func__, cci.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: spentcurrencyout: %s\n", __func__, spentCurrencyOut.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: newcurrencyin: %s\n", __func__, incomingCurrency.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: importedCurrency: %s\n", __func__, importedCurrency.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: localdepositrequirements: %s\n", __func__, newLocalDepositsRequired.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: checkImportedCurrency: %s\n", __func__, checkImportedCurrency.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: checkRequiredDeposits: %s\n", __func__, checkRequiredDeposits.ToUniValue().write(1,2).c_str());

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

            LogPrint("crosschainimports", "%s: totalDepositsInput: %s\nincomingPlusDepositsMinusSpent: %s\n", 
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
        LogPrint("crosschainimports", "%s: reserveInMap:\n%s\nspentCurrencyOut:\n%s\nccx.totalAmounts:\n%s\nccx.totalFees:\n%s\n",
                __func__,
                reserveInMap.ToUniValue().write(1,2).c_str(),
                spentCurrencyOut.ToUniValue().write(1,2).c_str(),
                ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
                ccx.totalFees.ToUniValue().write(1,2).c_str());

        // pay the fee out to the miner
        CReserveTransactionDescriptor rtxd(tb.mtx, view, nHeight + 1);
        tb.SetFee(rtxd.nativeIn - rtxd.nativeOut);
        CCurrencyValueMap reserveFees = rtxd.ReserveFees();
        if (reserveFees > CCurrencyValueMap())
        {
            tb.SetReserveFee(reserveFees);
        }

        if (LogAcceptCategory("crosschainimports"))
        {
            UniValue jsonTx(UniValue::VOBJ);
            uint256 hashBlk;
            TxToUniv(tb.mtx, hashBlk, jsonTx);
            LogPrintf("%s: building:\n%s\n", __func__, jsonTx.write(1,2).c_str()); //*/
            printf("%s: building:\n%s\n", __func__, jsonTx.write(1,2).c_str()); //*/
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
            /* // DEBUG output only
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
            lastSourceCCI = cci.importCurrencyID == cci.sourceSystemID ? cci : sysCCI;
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
// export proofs are all returned as null
bool CConnectedChains::GetDefinitionNotarization(const CCurrencyDefinition &curDef,
                                                 CInputDescriptor &notarizationRef,
                                                 CPBaaSNotarization &definitionNotarization)
{
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    uint160 currencyID = curDef.GetID();
    bool retVal = false;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::DefinitionNotarizationKey()), 
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
                if ((definitionNotarization = CPBaaSNotarization(notarizationTx.vout[idx.first.index].scriptPubKey)).IsValid())
                {
                    auto blockIt = mapBlockIndex.find(blkHash);
                    if (blockIt != mapBlockIndex.end() &&
                        chainActive.Contains(blockIt->second))
                    {
                        notarizationRef = CInputDescriptor(notarizationTx.vout[idx.first.index].scriptPubKey,
                                                                 notarizationTx.vout[idx.first.index].nValue,
                                                                 CTxIn(idx.first.txhash, idx.first.index));
                        retVal = true;
                    }
                }
            }
        }
    }
    return retVal;
}

// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// export proofs are all returned as null
bool CConnectedChains::GetDefinitionNotarization(const CCurrencyDefinition &curDef,
                                                 std::pair<CInputDescriptor, CPartialTransactionProof> &notarizationRef,
                                                 CPBaaSNotarization &definitionNotarization,
                                                 CPBaaSNotarization &notaryNotarization)
{
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    uint160 currencyID = curDef.GetID();
    bool retVal = false;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::DefinitionNotarizationKey()), 
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
                if ((definitionNotarization = CPBaaSNotarization(notarizationTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
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

bool CCurrencyDefinition::IsValidDefinitionImport(const CCurrencyDefinition &sourceSystem, const CCurrencyDefinition &destSystem, const uint160 &nameParent, uint32_t height)
{
    // the system from which the currency comes is not source or destination
    uint160 sourceSystemID = sourceSystem.GetID();
    uint160 destSystemID = destSystem.GetID();

    uint160 currencyParentID = nameParent;
    CCurrencyDefinition curSystem = ConnectedChains.GetCachedCurrency(currencyParentID);
    if (sourceSystemID == ASSETCHAINS_CHAINID)
    {
        // if we are sending from this chain, we must know that the parent has already been exported, or
        // we would create an invalid import
        if (!IsValidExportCurrency(destSystem, currencyParentID, height))
        {
            if (LogAcceptCategory("crosschain"))
            {
                printf("%s: Currency parent %s is not exported to the destination system, which is required for export.\n", __func__, EncodeDestination(CIdentityID(currencyParentID)).c_str());
                LogPrintf("%s: Currency parent %s is not exported to the destination system, which is required for export.\n", __func__, EncodeDestination(CIdentityID(currencyParentID)).c_str());
            }
            return false;
        }
    }

    do
    {
        if (!curSystem.IsValid())
        {
            if (LogAcceptCategory("crosschain"))
            {
                printf("%s: Invalid currency parent for %s. Index may be corrupt.\n", __func__, EncodeDestination(CIdentityID(currencyParentID)).c_str());
                LogPrintf("%s: Invalid currency parent for %s. Index may be corrupt.\n", __func__, EncodeDestination(CIdentityID(currencyParentID)).c_str());
            }
            return false;
        }

        // fractional currencies can support ID issuance and unless the currency is a gateway converter,
        // cannot support importing a definition from another chain
        if (curSystem.IsFractional())
        {
            // a gateway currency converter of a non-name controller
            // gateway cannot issue IDs directly, as they must be imported
            if (curSystem.IsGatewayConverter())
            {
                // if a gateway converter is the parent,
                // the system to travel up for import name control is always the
                // gateway, whether PBaaS or non-name controller. non-name controller
                // converter currencies cannot issue names themselves on the launch chain.
                curSystem = ConnectedChains.GetCachedCurrency(curSystem.gatewayID);
                if (!curSystem.IsValid())
                {
                    printf("%s: Invalid gateway currency for converter. Index may be corrupt.\n", __func__);
                    LogPrintf("%s: Invalid gateway currency for converter. Index may be corrupt.\n", __func__);
                    return false;
                }
            }
            else
            {
                curSystem = ConnectedChains.GetCachedCurrency(curSystem.systemID);
            }
        }
        // if we encounter a gateway, our action depends on whether it is a name controller or not
        else if (curSystem.IsGateway() || curSystem.IsPBaaSChain())
        {
            // a non-name controller cannot be the root system of a direct descendent
            // instead, the launching chain provides name services to the non-name controller gateway
            if (!curSystem.IsNameController() && curSystem.GetID() == nameParent)
            {
                // root system is the launch system
                curSystem = ConnectedChains.GetCachedCurrency(curSystem.launchSystemID);
            }
        }

        uint160 curSystemID = curSystem.GetID();

        if (!curSystemID.IsNull() && (curSystemID == sourceSystemID || curSystemID == destSystemID))
        {
            return curSystemID == sourceSystemID;
        }

        currencyParentID = curSystem.parent;
        if (!currencyParentID.IsNull())
        {
            curSystem = ConnectedChains.GetCachedCurrency(currencyParentID);
        }
    } while (!currencyParentID.IsNull());

    // if we got to a null root without finding the source, the only way an import from source to destination is valid
    // is if the source system is the launch chain of the destination system
    return destSystem.launchSystemID == sourceSystemID;
}

// Checks to see if a currency can be imported from a particular system to the indicated system
// The current system must be source or destination. Gateways that do not implement name or ID
// technology can use the bridged PBaaS or Verus chain to provide identity and currency definition
// services and attribute fees to the gateway currency converter. In order to do this, the
// gateway must have the option set which indicates it is not a name controller. This means that
// it cannot control or import names at the first level from the root name. All of these must be
// defined on the Verus network. Currencies defined this way must be "mapped currencies", meaning
// that they represent a currency on the other side of the gateway, and can only be acquired by having
// been exported to the gateway and then had either that currency or subcurrency definitions returned (NFTs).
// Protocol rules for a PBaaS chain or Gateway that is a name controller:
//  - All names that have parentage from the root currency of the PBaaS chain derive from it
// Protocol rules for a Gateway that is not a name controller:
//  - First level names must all be allocated on the Gateway's host blockchain (for example Verus or a PBaaS chain)
//  - "mapped currencies" and only mapped currencies may be defined from IDs, which are purchased from the bridge and
//    carry the name of the gateway as a suffix.
//  - When a mapped currency is exported to the Gateway, the gateway may return sub-currency definitions as well as
//    currency. All currencies defined on the PBaaS chain or Verus are controlled by the gateway, and will be minted
//    on import and burned on export.
bool CConnectedChains::IsValidCurrencyDefinitionImport(const CCurrencyDefinition &sourceSystemDef,
                                                       const CCurrencyDefinition &destSystemDef,
                                                       const CCurrencyDefinition &importingCurrency,
                                                       uint32_t height)
{
    assert(sourceSystemDef.IsValid() && destSystemDef.IsValid());
    if (importingCurrency.parent.IsNull())
    {
        return destSystemDef.launchSystemID == sourceSystemDef.GetID() && importingCurrency.GetID() != destSystemDef.launchSystemID;
    }
    return CCurrencyDefinition::IsValidDefinitionImport(sourceSystemDef, destSystemDef, importingCurrency.parent, height);
}

// Checks to see if an identity can be imported from a particular system to the indicated system
// The current system must be source or destination.
bool CConnectedChains::IsValidIdentityDefinitionImport(const CCurrencyDefinition &sourceSystemDef,
                                                       const CCurrencyDefinition &destSystemDef,
                                                       const CIdentity &importingIdentity,
                                                       uint32_t height)
{
    assert(sourceSystemDef.IsValid() && destSystemDef.IsValid());
    if (importingIdentity.parent.IsNull())
    {
        return destSystemDef.launchSystemID == sourceSystemDef.GetID() && importingIdentity.GetID() != destSystemDef.launchSystemID;
    }
    return CCurrencyDefinition::IsValidDefinitionImport(sourceSystemDef, destSystemDef, importingIdentity.parent, height);
}

// Determines if the currency, when exported to the destination system from the current system should:
// 1) have its accounting stored locally as reserve deposits controlled by the destination
//    system, meaning the destination system considers this system the source and controller of
//    those currencies, or
// 2) burn the outgoing currency because the destination system is considered the controlling system.
// 3) fail the export because one or more of the currencies being sent has not yet been exported
//    to the destination system.
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
            else if (oneCur.first == destSystemID)
            {
                exportBurn.valueMap[oneCur.first] += oneCur.second;
                continue;
            }

            CCurrencyDefinition oneCurDef;

            // look up the chain to find if the destination system is in the chain of the currency before the source system
            oneCurDef = ConnectedChains.GetCachedCurrency(oneCur.first);

            if (!oneCurDef.IsValid())
            {
                printf("%s: Invalid currency for export or corrupt chain state\n", __func__);
                LogPrintf("%s: Invalid currency for export or corrupt chain state\n", __func__);
                return false;
            }

            // if this is a mapped currency to a gateway that isn't a name controller, for this determination,
            // we are interested then in the launch system
            uint160 currencySystemID = oneCurDef.IsGateway() ? oneCurDef.gatewayID : oneCurDef.systemID;
            if (currencySystemID == sourceSystemID)
            {
                newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                continue;
            }
            else if (currencySystemID == destSystemID)
            {
                exportBurn.valueMap[oneCur.first] += oneCur.second;
                continue;
            }

            // the system from which the currency comes is not source or destination
            CCurrencyDefinition thirdCurSystem;

            do
            {
                thirdCurSystem = ConnectedChains.GetCachedCurrency(currencySystemID);
                if (!thirdCurSystem.IsValid())
                {
                    printf("%s: Invalid currency in origin chain. Index may be corrupt.\n", __func__);
                    LogPrintf("%s: Invalid currency in origin chain. Index may be corrupt.\n", __func__);
                    return false;
                }

                uint160 thirdCurSystemID = currencySystemID;

                // get the system ID of the PBaaS chain with the gateway or parent PBaaS chain of the PBaaS chain
                currencySystemID = thirdCurSystem.IsGateway() ? thirdCurSystem.systemID : thirdCurSystem.parent;

                if (currencySystemID == sourceSystemID)
                {
                    newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                    break;
                }
                else if (currencySystemID == destSystemID)
                {
                    exportBurn.valueMap[oneCur.first] += oneCur.second;
                    break;
                }
            } while (!currencySystemID.IsNull());

            // if the ultimate parent is null before it is us, then we must assume it is controlled outside our scope
            // meaning that if we are sending to the source system's launch system, the destination is the controller,
            // otherwise, source is the controller.
            if (currencySystemID.IsNull())
            {
                CCurrencyDefinition sourceSystem = ConnectedChains.GetCachedCurrency(sourceSystemID);
                if (!sourceSystem.IsValid())
                {
                    printf("%s: Invalid source system. Index may be corrupt.\n", __func__);
                    LogPrintf("%s: Invalid source system. Index may be corrupt.\n", __func__);
                    return false;
                }

                // if sending from source system to its launch parent,
                // consider the destination the controller, so burn
                if (sourceSystem.launchSystemID == destSystemID)
                {
                    exportBurn.valueMap[oneCur.first] += oneCur.second;
                }
                else
                {
                    newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                }
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
                                        const std::multimap<uint32_t, ChainTransferData> &_txInputs,
                                        const std::vector<CInputDescriptor> &priorExports,
                                        const CTransferDestination &feeRecipient,
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

    if (!isClearLaunchExport && (!_txInputs.size() || _txInputs.rbegin()->first <= sinceHeight) && !addInputTx)
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
        curHeight - sinceHeight < CCrossChainExport::MIN_BLOCKS && 
        _txInputs.size() < CCrossChainExport::MIN_INPUTS &&
        createOnlyIfRequired)
    {
        return true;
    }

    uint32_t addHeight = sinceHeight;
    uint32_t nextHeight = 0;
    int inputNum = 0;

    for (auto &oneInput : _txInputs)
    {
        if (oneInput.first <= sinceHeight)
        {
            continue;
        }
        if (addHeight != oneInput.first)
        {
            // if this is a launch export, we create one at the boundary
            if (isClearLaunchExport && oneInput.first >= _curDef.startBlock)
            {
                addHeight = _curDef.startBlock - 1;
                break;
            }
            // if we have skipped to the next block, and we have enough to make an export, we cannot take any more
            // except the optional block to add
            if ((isClearLaunchExport && inputNum >= CCrossChainExport::MAX_FEE_INPUTS) || (!isClearLaunchExport && inputNum >= CCrossChainExport::MIN_INPUTS))
            {
                nextHeight = oneInput.first;
                break;
            }
            addHeight = oneInput.first;
        }
        txInputs.push_back(oneInput.second);
        inputNum++;
    }

    if (!isClearLaunchExport && !inputNum && !addInputTx)
    {
        // no error, just nothing to do
        return true;
    }

    // if we have too many exports to clear launch yet, this is no longer clear launch
    isClearLaunchExport = isClearLaunchExport && !(nextHeight && nextHeight < _curDef.startBlock);

    // if we made an export before getting to the end, it doesn't clear launch
    // if we either early outed, due to height or landed right on the correct height, determine launch state
    // a clear launch export may have no inputs yet still be created with a clear launch notarization
    if (isClearLaunchExport)
    {
        addHeight = _curDef.startBlock - 1;
    }

    // all we expect to add are in txInputs now
    inputsConsumed = inputNum;

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

    if (isClearLaunchExport && destSystem.IsGateway() && !destSystem.IsNameController() && !_curDef.launchSystemID.IsNull())
    {
        if (_curDef.launchSystemID != ASSETCHAINS_CHAINID)
        {
            printf("%s: Mapped currency clear launch export can only be made on launch chain\n", __func__);
            LogPrintf("%s: Mapped currency clear launch export can only be made on launch chain\n", __func__);
            return false;
        }
        destSystem = ConnectedChains.ThisChain();
        destSystemID = ASSETCHAINS_CHAINID;
    }

    for (int i = 0; i < inputsConsumed; i++)
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

    // TODO: HARDENING - see if we can remove this block, as its function
    // has been moved to NextNotarizationInfo
    // now, if we are clearing launch, determine if we should refund or launch and set notarization appropriately
    if (isClearLaunchExport)
    {
        // if we are connected to another currency, make sure it will also start before we confirm that we can
        CCurrencyDefinition coLaunchCurrency;
        CCoinbaseCurrencyState coLaunchState;
        bool coLaunching = false;
        if (_curDef.IsGatewayConverter())
        {
            // PBaaS or gateway converters have a parent which is the PBaaS chain or gateway
            coLaunching = true;
            coLaunchCurrency = ConnectedChains.GetCachedCurrency(_curDef.parent);
        }
        else if (_curDef.IsPBaaSChain() && !_curDef.GatewayConverterID().IsNull())
        {
            coLaunching = true;
            coLaunchCurrency = GetCachedCurrency(_curDef.GatewayConverterID());
        }

        if (coLaunching)
        {
            if (!coLaunchCurrency.IsValid())
            {
                printf("%s: Invalid co-launch currency - likely corruption\n", __func__);
                LogPrintf("%s: Invalid co-launch currency - likely corruption\n", __func__);
                return false;
            }
            coLaunchState = GetCurrencyState(coLaunchCurrency, addHeight);

            if (!coLaunchState.IsValid())
            {
                printf("%s: Invalid co-launch currency state - likely corruption\n", __func__);
                LogPrintf("%s: Invalid co-launch currency state - likely corruption\n", __func__);
                return false;
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
                                                        feeRecipient,
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

    uint32_t fromBlock = sinceHeight + 1;
    uint32_t toBlock = addHeight < curHeight ? addHeight : addHeight - 1;

    //printf("%s: total export amounts:\n%s\n", __func__, totalAmounts.ToUniValue().write().c_str());
    CCrossChainExport ccx(ASSETCHAINS_CHAINID,
                          fromBlock,
                          toBlock,
                          destSystemID, 
                          currencyID, 
                          exportTransfers.size(), 
                          totalExports.CanonicalMap(), 
                          estimatedFees,
                          transferHash,
                          exportBurn,
                          inputStartNum,
                          feeRecipient);

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
                                   sysCCX.sourceHeightStart,
                                   sysCCX.sourceHeightEnd,
                                   destSystemID, 
                                   destSystemID, 
                                   txInputs.size(), 
                                   totalExports.CanonicalMap(), 
                                   estimatedFees,
                                   transferHash,
                                   CCurrencyValueMap(),
                                   inputStartNum,
                                   feeRecipient,
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

void CConnectedChains::AggregateChainTransfers(const CTransferDestination &feeRecipient, uint32_t nHeight)
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
                            nHeight - 50 < 0 ? 0 : nHeight - 50,
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

            std::multimap<uint32_t, ChainTransferData> txInputs;
            uint160 lastChain = transferOutputs.size() ? transferOutputs.begin()->first : launchCurrencies.begin()->second.first.GetID();

            CCoins coins;
            CCoinsView dummy;
            CCoinsViewCache view(&dummy);

            LOCK2(smartTransactionCS, mempool.cs);
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
                        txInputs.insert(std::make_pair(std::get<0>(output.second), output.second));
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
                        systemDef = thisChain;
                    }
                }
                else if (destDef.systemID == destID)
                {
                    systemDef = destDef;
                }
                else
                {
                    systemDef = GetCachedCurrency(destDef.systemID);

                    // any sends to a destination that is not connected will fail
                    // if this gateway or PBaaS chain was launched from this system
                    if (!(systemDef.IsPBaaSChain() || systemDef.IsGateway()) ||
                        !(systemDef.launchSystemID == ASSETCHAINS_CHAINID || ConnectedChains.ThisChain().launchSystemID == destDef.systemID))
                    {
                        printf("%s: Attempt to export to disconnected system %s\n", __func__, GetFriendlyCurrencyName(destDef.systemID).c_str());
                        LogPrintf("%s: Attempt to export to disconnected system %s\n", __func__, GetFriendlyCurrencyName(destDef.systemID).c_str());
                        continue;
                    }
                }

                if (!systemDef.IsValid())
                {
                    printf("%s: cannot find destination system definition %s\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                    LogPrintf("%s: cannot find destination system definition %s\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                    break;
                }

                bool isSameChain = destDef.SystemOrGatewayID() == thisChainID;

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
                if (launchCurrencies.count(lastChain) && destDef.SystemOrGatewayID() == lastChain)
                {
                    newSystem = true;
                }

                bool havePrimaryExports = ConnectedChains.GetUnspentCurrencyExports(view, lastChain, exportOutputs) && exportOutputs.size();
                if (!havePrimaryExports && !exportOutputs.size() && destDef.SystemOrGatewayID() == lastChain)
                {
                    havePrimaryExports = ConnectedChains.GetUnspentSystemExports(view, destDef.SystemOrGatewayID(), exportOutputs) && exportOutputs.size();
                }

                if ((isSameChain && havePrimaryExports) ||
                    (!isSameChain &&
                     (lastChain == destDef.SystemOrGatewayID() && havePrimaryExports) ||
                     (lastChain != destDef.SystemOrGatewayID() &&
                      (ConnectedChains.GetUnspentSystemExports(view, destDef.SystemOrGatewayID(), sysExportOutputs) && sysExportOutputs.size() ||
                       ConnectedChains.GetUnspentCurrencyExports(view, destDef.SystemOrGatewayID(), sysExportOutputs) && sysExportOutputs.size()))))
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
                        if (lastChain == destDef.SystemOrGatewayID())
                        {
                            lastSysExport = exportOutputs[0];
                        }
                        else
                        {
                            lastSysExport = sysExportOutputs[0];
                            allExportOutputs.push_back(lastSysExport.second);
                        }
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
                    }

                    CChainNotarizationData cnd;
                    std::vector<std::pair<CTransaction, uint256>> notarizationTxes;

                    // get notarization for the actual currency destination
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

                    if (destDef.systemID != ASSETCHAINS_CHAINID &&
                        cnd.vtx[cnd.lastConfirmed].second.IsLaunchConfirmed())
                    {
                        CChainNotarizationData systemCND;
                        if (GetNotarizationData(destDef.systemID, systemCND) &&
                            systemCND.lastConfirmed != -1 &&
                            systemCND.vtx[systemCND.lastConfirmed].second.currencyStates.count(lastChain) &&
                            systemCND.vtx[systemCND.lastConfirmed].second.currencyStates[lastChain].IsLaunchCompleteMarker())
                        {
                            lastNotarization.currencyState = systemCND.vtx[systemCND.lastConfirmed].second.currencyStates[lastChain];
                            lastNotarization.flags = systemCND.vtx[systemCND.lastConfirmed].second.flags;
                        }
                    }

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

                    // now, we have the previous export to this currency/system, which we should spend to
                    // enable this new export. if we find no export, we're done
                    int32_t numInputsUsed;
                    std::vector<CTxOut> exportTxOuts;
                    std::vector<CReserveTransfer> exportTransfers;

                    while (txInputs.size() || launchCurrencies.count(lastChain))
                    {
                        launchCurrencies.erase(lastChain);
                        //printf("%s: launchCurrencies.size(): %ld\n", __func__, launchCurrencies.size());

                        // even if we have no txInputs, currencies that need to will launch
                        newNotarizationOutNum = -1;
                        exportTxOuts.clear();
                        exportTransfers.clear();
                        if (!CConnectedChains::CreateNextExport(destDef,
                                                                txInputs,
                                                                allExportOutputs,
                                                                feeRecipient,
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

                        // now, all reserve transfers used
                        int numInputsAdded = 0;
                        for (auto &oneInput : txInputs)
                        {
                            if (numInputsAdded >= numInputsUsed)
                            {
                                break;
                            }
                            CInputDescriptor inputDesc = std::get<1>(oneInput.second);

                            //scriptUniOut = UniValue(UniValue::VOBJ);
                            //ScriptPubKeyToUniv(inputDesc.scriptPubKey, scriptUniOut, false);
                            //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), inputDesc.nValue, scriptUniOut.write(1,2).c_str());

                            tb.AddTransparentInput(inputDesc.txIn.prevout, inputDesc.scriptPubKey, inputDesc.nValue);
                            numInputsAdded++;
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

                        int exOutNum = -1;
                        int sysExOutNum = -1;

                        for (auto &oneOut : exportTxOuts)
                        {
                            COptCCParams xp;
                            CCrossChainExport checkCCX;
                            if (oneOut.scriptPubKey.IsPayToCryptoCondition(xp) &&
                                xp.IsValid() && 
                                xp.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                                (checkCCX = CCrossChainExport(xp.vData[0])).IsValid())
                            {
                                if (checkCCX.IsSystemThreadExport())
                                {
                                    sysExOutNum = outputNum;
                                }
                                else
                                {
                                    thisExport.second.scriptPubKey = oneOut.scriptPubKey;
                                    thisExport.second.nValue = oneOut.nValue;
                                    thisExport.first = checkCCX.sourceHeightEnd;
                                    thisExport.second.txIn.prevout.n = outputNum;
                                    ccx = checkCCX;
                                    exOutNum = outputNum;
                                }
                            }

                            /* scriptUniOut = UniValue(UniValue::VOBJ);
                            ScriptPubKeyToUniv(oneOut.scriptPubKey, scriptUniOut, false);
                            printf("%s: adding output %d with %ld nValue and script:\n%s\n", __func__, (int)tb.mtx.vout.size(), oneOut.nValue, scriptUniOut.write(1,2).c_str());
                            */

                            tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
                            outputNum++;
                        }

                        allExportOutputs.clear();

                        /* UniValue uni(UniValue::VOBJ);
                        TxToUniv(tb.mtx, uint256(), uni);
                        printf("%s: Ready to build tx:\n%s\n", __func__, uni.write(1,2).c_str()); // */

                        TransactionBuilderResult buildResult(tb.Build());

                        if (!buildResult.IsError() && buildResult.IsTx())
                        {
                            // replace the last one only if we have a valid new one
                            CTransaction tx = buildResult.GetTxOrThrow();

                            allExportOutputs.push_back(CInputDescriptor(tx.vout[exOutNum].scriptPubKey, tx.vout[exOutNum].nValue, CTxIn(tx.GetHash(), exOutNum)));

                            if (sysExOutNum >= 0)
                            {
                                allExportOutputs.push_back(CInputDescriptor(tx.vout[sysExOutNum].scriptPubKey, tx.vout[sysExOutNum].nValue, CTxIn(tx.GetHash(), sysExOutNum)));
                            }

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
                        for (; numInputsAdded > 0; numInputsAdded--)
                        {
                            txInputs.erase(txInputs.begin());
                        }
                    }
                }
                txInputs.clear();
                launchCurrencies.erase(lastChain);

                if (outputIt != transferOutputs.end())
                {
                    lastChain = outputIt->first;
                    txInputs.insert(std::make_pair(std::get<0>(outputIt->second), outputIt->second));
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
                if (ccx.IsClearLaunch())
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
            if (result.isNull())
            {
                return exports;
            }
            pbn = CPBaaSNotarization(find_value(result, "lastconfirmednotarization"));
            found = true;
        } catch (...)
        {
            LogPrint("notarization", "%s: Could not get last import from external chain %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        if (!pbn.IsValid())
        {
            LogPrint("notarization", "%s: Invalid notarization from external chain %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        if (pbn.IsDefinitionNotarization())
        {
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

        // TODO: HARDENING - decide if we want to confirm that the lastConfirmed notarization matches
        // the lastConfirmedUTXO on our chain
        params.push_back((int64_t)lastConfirmed.proofRoots[sourceChainID].rootHeight);

        UniValue result = NullUniValue;
        try
        {
            if (sourceChainID == ASSETCHAINS_CHAINID)
            {
                UniValue getexports(const UniValue& params, bool fHelp);
                result = getexports(params, false);
            }
            else if (ConnectedChains.IsNotaryAvailable())
            {
                result = find_value(RPCCallRoot("getexports", params), "result");
            }
        } catch (exception e)
        {
            LogPrint("notarization", "Could not get latest export from external chain %s\n", uni_get_str(params[0]).c_str());
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
                LogPrint("notarization", "%s: proofRoot: %s,\nGetPartialTransaction: %s, checkPartialTransaction: %s, TransactionHash: %s, exportTxId: %s,\nproofheight: %u,\nischainproof: %s,\nblockhash: %s\n", 
                    __func__,
                    proofRootIt->second.ToUniValue().write(1,2).c_str(),
                    txProof.GetPartialTransaction(exportTx).GetHex().c_str(),
                    txProof.CheckPartialTransaction(exportTx).GetHex().c_str(),
                    txProof.TransactionHash().GetHex().c_str(),
                    exportTxId.GetHex().c_str(),
                    txProof.GetProofHeight(),
                    txProof.IsChainProof() ? "true" : "false",
                    txProof.GetBlockHash().GetHex().c_str()); //*/
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

                        if (LogAcceptCategory("bridge") && IsVerusActive())
                        {
                            CDataStream ds = CDataStream(SER_GETHASH, PROTOCOL_VERSION);
                            for (auto &oneTransfer : oneExport.second)
                            {
                                ds << oneTransfer;
                            }
                            std::vector<unsigned char> streamVec(ds.begin(), ds.end());
                            printf("%s: transfers as hex: %s\n", __func__, HexBytes(&(streamVec[0]), streamVec.size()).c_str());
                            LogPrint("bridge", "%s: transfers as hex: %s\n", __func__, HexBytes(&(streamVec[0]), streamVec.size()).c_str());
                        }

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

