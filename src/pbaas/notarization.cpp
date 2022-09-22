/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This implements the public blockchains as a service (PBaaS) notarization protocol, VerusLink.
 * VerusLink is a new distributed consensus protocol that enables multiple public blockchains 
 * to operate as a decentralized ecosystem of chains, which can interact and easily engage in cross 
 * chain transactions.
 * 
 */

#include <univalue.h>
#include "main.h"
#include "txdb.h"
#include "rpc/pbaasrpc.h"
#include "transaction_builder.h"

#include <assert.h>

using namespace std;

extern uint160 VERUS_CHAINID;
extern uint160 ASSETCHAINS_CHAINID;
extern string VERUS_CHAINNAME;
extern string PBAAS_HOST;
extern string PBAAS_USERPASS;
extern int32_t PBAAS_PORT;
extern int32_t VERUS_MIN_STAKEAGE;

CNotaryEvidence::CNotaryEvidence(const UniValue &uni)
{
    version = uni_get_int(find_value(uni, "version"), VERSION_CURRENT);
    type = uni_get_int(find_value(uni, "type"));
    systemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "systemid"))));
    output = CUTXORef(find_value(uni, "output"));
    state = uni_get_int(find_value(uni, "state"));
    evidence = CCrossChainProof(find_value(uni, "evidence"));
}

std::vector<CNotarySignature> CNotaryEvidence::GetConfirmedAndRejectedSignatureMaps(
                                                        const std::vector<CNotarySignature> &allSigVec,
                                                        std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &confirmedByHeight,
                                                        std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &rejectedByHeight)
{
    CUTXORef output;
    uint160 systemID;
    for (auto notarySig : allSigVec)
    {
        if (output.hash.IsNull())
        {
            output = notarySig.output;
            systemID = notarySig.systemID;
        }
        if (notarySig.IsConfirmed())
        {
            // get the signature proof and add to it, do not make a new one
            for (auto &oneSignature : notarySig.signatures)
            {
                if (confirmedByHeight[oneSignature.second.blockHeight].count(oneSignature.first))
                {
                    // all signatures are the same height, merge the CIdentitySignature
                    for (auto &oneKeySig : oneSignature.second.signatures)
                    {
                        confirmedByHeight[oneSignature.second.blockHeight][oneSignature.first].AddSignature(oneKeySig);
                    }
                }
                else
                {
                    confirmedByHeight[oneSignature.second.blockHeight].insert(oneSignature);
                }
            }
        }
        else
        {
            // get the signature proof and add to it, do not make a new one
            for (auto &oneSignature : notarySig.signatures)
            {
                if (rejectedByHeight[oneSignature.second.blockHeight].count(oneSignature.first))
                {
                    // all signatures are the same height, merge the CIdentitySignature
                    for (auto &oneKeySig : oneSignature.second.signatures)
                    {
                        rejectedByHeight[oneSignature.second.blockHeight][oneSignature.first].AddSignature(oneKeySig);
                    }
                }
                else
                {
                    rejectedByHeight[oneSignature.second.blockHeight].insert(oneSignature);
                }
            }
        }
    }

    std::vector<CNotarySignature> retVal;

    std::multimap<uint32_t, CNotarySignature> combinedSignatures;
    for (auto oneHeightEntry : rejectedByHeight)
    {
        combinedSignatures.insert(std::make_pair(oneHeightEntry.first, CNotarySignature(systemID, output, false, oneHeightEntry.second)));
    }
    for (auto oneHeightEntry : confirmedByHeight)
    {
        combinedSignatures.insert(std::make_pair(oneHeightEntry.first, CNotarySignature(systemID, output, true, oneHeightEntry.second)));
    }
    // place all signature blocks at the beginning of the evidence in order of height by inserting them at 0 in reverse order
    for (auto it = combinedSignatures.rbegin(); it != combinedSignatures.rend(); it++)
    {
        retVal.push_back(it->second);
    }
    return retVal;
}

CNotaryEvidence &CNotaryEvidence::MergeEvidence(const CNotaryEvidence &mergeWith, const std::set<uint160> &notarySet, bool aggregateSignatures)
{
    std::vector<CNotarySignature> notarySignatures;

    if (output.IsNull() && !mergeWith.output.IsNull())
    {
        output = mergeWith.output;
    }
    if (systemID.IsNull() && !mergeWith.systemID.IsNull())
    {
        systemID = mergeWith.systemID;
    }

    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> confirmedByHeight;
    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> rejectedByHeight;

    for (auto oneRef : mergeWith.evidence.chainObjects)
    {
        if (aggregateSignatures && oneRef->objectType == CHAINOBJ_NOTARYSIGNATURE)
        {
            notarySignatures.push_back(((CChainObject<CNotarySignature> *)oneRef)->object);
        }
        else
        {
            evidence << oneRef;
        }
    }

    if (notarySignatures.size())
    {
        auto orderedNotarySigs = GetConfirmedAndRejectedSignatureMaps(notarySignatures, confirmedByHeight, rejectedByHeight);

        // place all signature blocks at the beginning of the evidence in order of height by inserting them at 0 in reverse order
        for (auto it = orderedNotarySigs.rbegin(); it != orderedNotarySigs.rend(); it++)
        {
            evidence.insert(0, *it);
        }
    }
    return *this;
}

CIdentitySignature::ESignatureVerification CNotaryEvidence::SignConfirmed(const std::set<uint160> &notarySet, int minConfirming, const CKeyStore &keyStore, const CTransaction &txToConfirm, const CIdentityID &signWithID, uint32_t height, CCurrencyDefinition::EProofProtocol hashType)
{
    if (!notarySet.count(signWithID))
    {
        LogPrintf("%s: Attempting to sign as notary with unauthorized ID\n", __func__);
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    COptCCParams p;

    if (txToConfirm.GetHash() != output.hash ||
        txToConfirm.vout.size() <= output.n ||
        !txToConfirm.vout[output.n].scriptPubKey.IsPayToCryptoCondition(p) ||
        !p.vData.size() ||
        !p.vData[0].size() ||
        p.evalCode == EVAL_NONE)
    {
        LogPrintf("%s: Attempting to sign an invalid or incompatible object\n", __func__);
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    // write the object to the hash writer without a vector length prefix
    CNativeHashWriter hw(hashType);
    uint256 objHash = hw.write((const char *)&(p.vData[0][0]), p.vData[0].size()).GetHash();

    uint32_t decisionHeight;
    std::map<CIdentityID, CIdentitySignature> confirmedAtHeight;
    std::map<CIdentityID, CIdentitySignature> rejectedAtHeight;

    CNotaryEvidence::EStates sigCheckResult = CheckSignatureConfirmation(objHash,
                                                                         notarySet,
                                                                         minConfirming,
                                                                         height,
                                                                         &decisionHeight,
                                                                         &confirmedAtHeight,
                                                                         &rejectedAtHeight);

    if (sigCheckResult == CNotaryEvidence::EStates::STATE_CONFIRMED || sigCheckResult == CNotaryEvidence::EStates::STATE_REJECTED)
    {
        return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
    }
    else if (sigCheckResult == CNotaryEvidence::EStates::STATE_INVALID)
    {
        return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
    }

    // sign for anything we can that is not already in the confirmedAtHeight signature block if decisionHeight is our height
    int currentNumSigs = (decisionHeight == height && confirmedAtHeight.count(signWithID)) ? confirmedAtHeight[signWithID].signatures.size() : 0;

    // all signatures present for this ID are correct, so we recover all pub keys and IDs,
    // then see if we have any of the keys in our wallet that are in the ID and have not already
    // signed
    CIdentity sigIdentity = CIdentity::LookupIdentity(signWithID, height);
    if (!sigIdentity.IsValid())
    {
        LogPrint("notarization", "%s: failed lookup of identity for rejection: %s\n", __func__, EncodeDestination(signWithID).c_str());
        return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
    }
    else
    {
        int sigsNeeded = std::max(sigIdentity.minSigs - currentNumSigs, 0);
        if (!sigsNeeded)
        {
            LogPrint("notarization", "%s: Already signed with ID\n", __func__);
            return CIdentitySignature::SIGNATURE_COMPLETE;
        }

        CIdentitySignature idSignature(height, std::set<std::vector<unsigned char>>(), hashType);

        uint256 signatureHash = idSignature.IdentitySignatureHash(std::vector<uint160>({NotaryConfirmedKey()}), 
                                                                  std::vector<uint256>(), 
                                                                  systemID,
                                                                  height,
                                                                  signWithID,
                                                                  "", 
                                                                  objHash);

        std::set<CTxDestination> validKeys;

        for (auto &oneDest : sigIdentity.primaryAddresses)
        {
            if (oneDest.which() == COptCCParams::ADDRTYPE_PK)
            {
                validKeys.insert(CKeyID(GetDestinationID(oneDest)));
            }
            else
            {
                validKeys.insert(oneDest);
            }
        }

        if (currentNumSigs)
        {
            for (auto &oneSig : confirmedAtHeight[signWithID].signatures)
            {
                CPubKey checkKey;
                checkKey.RecoverCompact(signatureHash, oneSig);
                validKeys.erase(checkKey.GetID());
            }
        }

        // as long as we can continue to make new signatures, we do
        for (auto keyIT = validKeys.begin(); sigsNeeded > 0 && keyIT != validKeys.end(); keyIT++)
        {
            CKey signingKey;
            std::vector<unsigned char> newSig;
            if (keyStore.GetKey(GetDestinationID(*keyIT), signingKey) && signingKey.SignCompact(signatureHash, newSig))
            {
                idSignature.signatures.insert(newSig);
                sigsNeeded--;
            }
        }

        if (idSignature.signatures.size())
        {
            AddToSignatures(notarySet, signWithID, idSignature, STATE_CONFIRMING);
        }

        CIdentitySignature::ESignatureVerification sigResult = idSignature.CheckSignature(sigIdentity, 
                                                                                        std::vector<uint160>({NotaryConfirmedKey()}), 
                                                                                        std::vector<uint256>(), 
                                                                                        systemID, 
                                                                                        "", 
                                                                                        objHash);

        if (sigResult == CIdentitySignature::ESignatureVerification::SIGNATURE_EMPTY ||
            sigResult == CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID)
        {
            LogPrintf("%s: Error signing confirmed with ID: %s\n", __func__, sigIdentity.ToUniValue().write(1,2).c_str());
            return sigResult;
        }
        // if we have enough signatures for the ID, make sure we return complete
        if (sigsNeeded == 0)
        {
            return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
        }
        return sigResult;
    }
}

CIdentitySignature::ESignatureVerification CNotaryEvidence::SignRejected(const std::set<uint160> &notarySet,
                                                                         int minConfirming,
                                                                         const CKeyStore &keyStore,
                                                                         const CTransaction &txToConfirm,
                                                                         const CIdentityID &signWithID,
                                                                         uint32_t height,
                                                                         CCurrencyDefinition::EProofProtocol hashType)
{
    if (!notarySet.count(signWithID))
    {
        LogPrintf("%s: Attempting to sign as notary with unauthorized ID\n", __func__);
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    COptCCParams p;

    if (txToConfirm.GetHash() != output.hash ||
        txToConfirm.vout.size() <= output.n ||
        !txToConfirm.vout[output.n].scriptPubKey.IsPayToCryptoCondition(p) ||
        !p.vData.size() ||
        !p.vData[0].size() ||
        p.evalCode == EVAL_NONE)
    {
        LogPrintf("%s: Attempting to sign an invalid or incompatible object\n", __func__);
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    // write the object to the hash writer without a vector length prefix
    CNativeHashWriter hw(hashType);
    std::map<CIdentityID, CIdentitySignature> confirmedAtHeight;
    std::map<CIdentityID, CIdentitySignature> rejectedAtHeight;
    uint256 objHash = hw.write((const char *)&(p.vData[0][0]), p.vData[0].size()).GetHash();

    uint32_t decisionHeight;

    CNotaryEvidence::EStates sigCheckResult = CheckSignatureConfirmation(objHash,
                                                                         notarySet,
                                                                         minConfirming,
                                                                         height,
                                                                         &decisionHeight,
                                                                         &confirmedAtHeight,
                                                                         &rejectedAtHeight);

    if ((sigCheckResult == CNotaryEvidence::EStates::STATE_CONFIRMED && decisionHeight != height) ||
         sigCheckResult == CNotaryEvidence::EStates::STATE_REJECTED)
    {
        return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
    }
    else if (sigCheckResult == CNotaryEvidence::EStates::STATE_INVALID)
    {
        return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
    }

    // sign for anything we can that is not already in the rejectedAtHeight signature block if decisionHeight is our height
    int currentNumSigs = (decisionHeight == height && rejectedAtHeight.count(signWithID)) ? rejectedAtHeight[signWithID].signatures.size() : 0;

    // all signatures present for this ID are correct, so we recover all pub keys and IDs,
    // then see if we have any of the keys in our wallet that are in the ID and have not already
    // signed
    CIdentity sigIdentity = CIdentity::LookupIdentity(signWithID, height);
    if (!sigIdentity.IsValid())
    {
        LogPrint("notarization", "%s: failed lookup of identity for rejection: %s\n", __func__, EncodeDestination(signWithID).c_str());
        return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
    }
    else
    {
        int sigsNeeded = std::max(sigIdentity.minSigs - currentNumSigs, 0);
        if (!sigsNeeded)
        {
            LogPrint("notarization", "%s: Already signed with ID\n", __func__);
            return CIdentitySignature::SIGNATURE_COMPLETE;
        }

        CIdentitySignature idSignature(height, std::set<std::vector<unsigned char>>(), hashType);

        uint256 signatureHash = idSignature.IdentitySignatureHash(std::vector<uint160>({NotaryRejectedKey()}), 
                                                                  std::vector<uint256>(), 
                                                                  systemID,
                                                                  height,
                                                                  signWithID,
                                                                  "", 
                                                                  objHash);

        std::set<CTxDestination> validKeys;

        for (auto &oneDest : sigIdentity.primaryAddresses)
        {
            if (oneDest.which() == COptCCParams::ADDRTYPE_PK)
            {
                validKeys.insert(CKeyID(GetDestinationID(oneDest)));
            }
            else
            {
                validKeys.insert(oneDest);
            }
        }

        if (currentNumSigs)
        {
            for (auto &oneSig : rejectedAtHeight[signWithID].signatures)
            {
                CPubKey checkKey;
                checkKey.RecoverCompact(signatureHash, oneSig);
                validKeys.erase(checkKey.GetID());
            }
        }

        // as long as we can continue to make new signatures, we do
        for (auto keyIT = validKeys.begin(); sigsNeeded > 0 && keyIT != validKeys.end(); keyIT++)
        {
            CKey signingKey;
            std::vector<unsigned char> newSig;
            if (keyStore.GetKey(GetDestinationID(*keyIT), signingKey) && signingKey.SignCompact(signatureHash, newSig))
            {
                idSignature.signatures.insert(newSig);
                sigsNeeded--;
            }
        }

        if (idSignature.signatures.size())
        {
            AddToSignatures(notarySet, signWithID, idSignature, STATE_REJECTING);
        }

        CIdentitySignature::ESignatureVerification sigResult = idSignature.CheckSignature(sigIdentity, 
                                                                                        std::vector<uint160>({NotaryRejectedKey()}), 
                                                                                        std::vector<uint256>(), 
                                                                                        systemID, 
                                                                                        "", 
                                                                                        objHash);
        
        if (sigResult == CIdentitySignature::ESignatureVerification::SIGNATURE_EMPTY ||
            sigResult == CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID)
        {
            LogPrintf("%s: Error signing rejected with ID: %s\n", __func__, sigIdentity.ToUniValue().write(1,2).c_str());
            return sigResult;
        }
        // if we have enough signatures for the ID, make sure we return complete
        if (sigsNeeded == 0)
        {
            return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
        }
        return sigResult;
    }
}

CNotaryEvidence::EStates CNotaryEvidence::CheckSignatureConfirmation(const uint256 &objHash,
                                                                     const std::set<uint160> &notarySet,
                                                                     int minConfirming,
                                                                     uint32_t checkHeight,
                                                                     uint32_t *pDecisionHeight,
                                                                     std::map<CIdentityID, CIdentitySignature> *pConfirmedAtHeight,
                                                                     std::map<CIdentityID, CIdentitySignature> *pRejectedAtHeight) const
{

    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> confirmedByHeight;
    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> rejectedByHeight;
    std::vector<CNotarySignature> notarySignatures = GetNotarySignatures(&confirmedByHeight, &rejectedByHeight);

    CNotaryEvidence::EStates retVal = CNotaryEvidence::EStates::STATE_CONFIRMING;

    if (!checkHeight)
    {
        checkHeight = UINT32_MAX;
    }

    // if we have full rejection from any IDs in any period, that is considered rejection and that ID is blacklisted from accepting
    // if we have full confirmation in the most recent period, that is considered confirmation

    // for every height, we check and merge 
    uint32_t lastHeight = 0;
    std::map<CIdentityID, std::set<std::vector<unsigned char>>> notarySetRejects;
    std::map<CIdentityID, std::set<std::vector<unsigned char>>> notarySetConfirms; 

    for (auto &oneSigBlock : notarySignatures)
    {
        // we only care up to signing height
        uint32_t height = oneSigBlock.signatures.size() ? oneSigBlock.signatures.begin()->second.blockHeight : 0;
        if (!height)
        {
            continue;
        }

        // if this was signed on this chain, it isn't valid if signed after the check height
        if (oneSigBlock.systemID == ASSETCHAINS_CHAINID && height > checkHeight)
        {
            break;
        }

        if (height != lastHeight)
        {
            notarySetRejects.clear();
            notarySetConfirms.clear();
        }

        if (oneSigBlock.IsConfirmed())
        {
            for (auto &oneIDSig : oneSigBlock.signatures)
            {
                if (!notarySet.count(oneIDSig.first))
                {
                    LogPrint("notarization", "%s: unauthorized notary identity: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }

                CIdentity sigIdentity = CIdentity::LookupIdentity(oneIDSig.first, oneSigBlock.systemID == ASSETCHAINS_CHAINID ?
                                                                                    oneIDSig.second.blockHeight :
                                                                                    checkHeight);
                if (!sigIdentity.IsValid())
                {
                    LogPrint("notarization", "%s: invalid notary identity: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }

                // we cannot confirm based on the signature of a revoked identity, but that state does not veto either
                if (sigIdentity.IsRevoked())
                {
                    confirmedByHeight[oneIDSig.second.blockHeight].erase(oneIDSig.first);
                    continue;
                }

                std::vector<std::vector<unsigned char>> dupSigs;
                CIdentitySignature::ESignatureVerification result = oneIDSig.second.CheckSignature(sigIdentity,
                                                                                                   std::vector<uint160>({NotaryConfirmedKey()}), 
                                                                                                   std::vector<uint256>(), 
                                                                                                   systemID, 
                                                                                                   "", 
                                                                                                   objHash,
                                                                                                   &dupSigs);

                for (auto &oneDup : dupSigs)
                {
                    rejectedByHeight[oneIDSig.second.blockHeight][oneIDSig.first].signatures.erase(oneDup);
                }

                if (result == oneIDSig.second.SIGNATURE_INVALID)
                {
                    LogPrint("notarization", "%s: invalid notary signature: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }
                else if (result != oneIDSig.second.SIGNATURE_COMPLETE)
                {
                    continue;
                }
                notarySetConfirms[oneIDSig.first] = oneIDSig.second.signatures;
            }
        }
        else
        {
            for (auto &oneIDSig : oneSigBlock.signatures)
            {
                if (!notarySet.count(oneIDSig.first))
                {
                    LogPrint("notarization", "%s: unauthorized notary identity for rejection: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }

                CIdentity sigIdentity = CIdentity::LookupIdentity(oneIDSig.first, oneIDSig.second.blockHeight);
                if (!sigIdentity.IsValid())
                {
                    LogPrint("notarization", "%s: invalid notary identity for rejection: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }

                // we cannot reject based on the signature of a revoked identity, but that state does not veto either
                if (sigIdentity.IsRevoked())
                {
                    rejectedByHeight[oneIDSig.second.blockHeight].erase(oneIDSig.first);
                    continue;
                }

                std::vector<std::vector<unsigned char>> dupSigs;
                CIdentitySignature::ESignatureVerification result = oneIDSig.second.CheckSignature(sigIdentity,
                                                                                                   std::vector<uint160>({NotaryRejectedKey()}), 
                                                                                                   std::vector<uint256>(), 
                                                                                                   systemID, 
                                                                                                   "", 
                                                                                                   objHash,
                                                                                                   &dupSigs);

                for (auto &oneDup : dupSigs)
                {
                    rejectedByHeight[oneIDSig.second.blockHeight][oneIDSig.first].signatures.erase(oneDup);
                }

                if (result == oneIDSig.second.SIGNATURE_INVALID)
                {
                    LogPrint("notarization", "%s: invalid notary signature for rejection: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }
                else if (result != oneIDSig.second.SIGNATURE_COMPLETE)
                {
                    continue;
                }
                notarySetRejects.insert(std::make_pair(oneIDSig.first, oneIDSig.second.signatures));
            }
        }

        lastHeight = height;

        if (notarySetRejects.size() >= minConfirming)
        {
            retVal = EStates::STATE_REJECTED;
            break;
        }
        else if (notarySetConfirms.size() >= minConfirming)
        {
            retVal = EStates::STATE_CONFIRMED;
            break;
        }
    }
    
    if (pDecisionHeight)
    {
        *pDecisionHeight = lastHeight;
    }
    if (pConfirmedAtHeight && lastHeight && confirmedByHeight.count(lastHeight))
    {
        *pConfirmedAtHeight = confirmedByHeight[lastHeight];
    }
    if (pRejectedAtHeight && lastHeight && rejectedByHeight.count(lastHeight))
    {
        *pRejectedAtHeight = rejectedByHeight[lastHeight];
    }

    if (retVal != EStates::STATE_CONFIRMED && retVal != EStates::STATE_REJECTED)
    {
        if (lastHeight == checkHeight &&
            notarySetConfirms.size() >= notarySetRejects.size())
        {
            retVal = EStates::STATE_CONFIRMING;
        }
        else
        {
            retVal = EStates::STATE_REJECTING;
        }
    }
    return retVal;
}

CPBaaSNotarization::CPBaaSNotarization(const CScript &scriptPubKey) :
                    nVersion(VERSION_INVALID),
                    flags(0),
                    notarizationHeight(0),
                    prevHeight(0)
{
    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && 
        p.IsValid() &&
        (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
        p.vData.size())
    {
        ::FromVector(p.vData[0], *this);
    }
}

CPBaaSNotarization::CPBaaSNotarization(const CTransaction &tx, int32_t *pOutIdx) :
                    nVersion(VERSION_INVALID),
                    flags(0),
                    notarizationHeight(0),
                    prevHeight(0)
{
    // the PBaaS notarization itself is a combination of proper inputs, one output, and
    // a sequence of opret chain objects as proof of the output values on the chain to which the
    // notarization refers, the opret can be reconstructed from chain data in order to validate
    // the txid of a transaction that does not contain the opret itself

    int32_t _outIdx;
    int32_t &outIdx = pOutIdx ? *pOutIdx : _outIdx;
    
    // a notarization must have notarization output that spends to the address indicated by the 
    // ChainID, an opret, that there is only one, and that it can be properly decoded to a notarization 
    // output, whether or not validate is true
    bool found = false;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && 
            p.IsValid() &&
            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
            p.vData.size())
        {
            if (found)
            {
                nVersion = VERSION_INVALID;
                proofRoots.clear();
                break;
            }
            else
            {
                found = true;
                outIdx = i;
                ::FromVector(p.vData[0], *this);
            }
        }
    }
}

uint160 ValidateCurrencyName(std::string currencyStr, bool ensureCurrencyValid=false, CCurrencyDefinition *pCurrencyDef=NULL);

CPBaaSNotarization::CPBaaSNotarization(const UniValue &obj)
{
    nVersion = (uint32_t)uni_get_int64(find_value(obj, "version"));
    flags = FLAGS_NONE;
    SetDefinitionNotarization(uni_get_bool(find_value(obj, "isdefinition")));
    SetBlockOneNotarization(uni_get_bool(find_value(obj, "isblockonenotarization")));
    SetPreLaunch(uni_get_bool(find_value(obj, "prelaunch")));
    SetLaunchCleared(uni_get_bool(find_value(obj, "launchcleared")));
    SetRefunding(uni_get_bool(find_value(obj, "refunding")));
    SetLaunchConfirmed(uni_get_bool(find_value(obj, "launchconfirmed")));
    SetLaunchComplete(uni_get_bool(find_value(obj, "launchcomplete")));
    if (uni_get_bool(find_value(obj, "ismirror")))
    {
        flags |= FLAG_ACCEPTED_MIRROR;
    }
    SetSameChain(uni_get_bool(find_value(obj, "samechain")));

    currencyID = ValidateCurrencyName(uni_get_str(find_value(obj, "currencyid")));
    if (currencyID.IsNull())
    {
        nVersion = VERSION_INVALID;
        return;
    }

    UniValue transferID = find_value(obj, "proposer");
    if (transferID.isObject())
    {
        proposer = CTransferDestination(transferID);
    }

    notarizationHeight = (uint32_t)uni_get_int64(find_value(obj, "notarizationheight"));
    currencyState = CCoinbaseCurrencyState(find_value(obj, "currencystate"));
    prevNotarization = CUTXORef(uint256S(uni_get_str(find_value(obj, "prevnotarizationtxid"))), (uint32_t)uni_get_int(find_value(obj, "prevnotarizationout")));
    hashPrevCrossNotarization = uint256S(uni_get_str(find_value(obj, "hashprevcrossnotarization")));
    prevHeight = (uint32_t)uni_get_int64(find_value(obj, "prevheight"));

    auto curStateArr = find_value(obj, "currencystates");
    auto proofRootArr = find_value(obj, "proofroots");
    auto nodesUni = find_value(obj, "nodes");

    if (curStateArr.isArray())
    {
        for (int i = 0; i < curStateArr.size(); i++)
        {
            std::vector<std::string> keys = curStateArr[i].getKeys();
            std::vector<UniValue> values = curStateArr[i].getValues();
            if (keys.size() != 1 or values.size() != 1)
            {
                nVersion = VERSION_INVALID;
                return;
            }
            currencyStates.insert(std::make_pair(GetDestinationID(DecodeDestination(keys[0])), CCoinbaseCurrencyState(values[0])));
        }
    }

    if (proofRootArr.isArray())
    {
        for (int i = 0; i < proofRootArr.size(); i++)
        {
            CProofRoot oneRoot(proofRootArr[i]);
            if (!oneRoot.IsValid())
            {
                nVersion = VERSION_INVALID;
                return;
            }
            proofRoots.insert(std::make_pair(oneRoot.systemID, oneRoot));
        }
    }

    if (nodesUni.isArray())
    {
        vector<UniValue> nodeVec = nodesUni.getValues();
        for (auto node : nodeVec)
        {
            nodes.push_back(CNodeData(uni_get_str(find_value(node, "networkaddress")), uni_get_str(find_value(node, "nodeidentity"))));
        }
    }
}

bool operator==(const CProofRoot &op1, const CProofRoot &op2)
{
    return op1.version == op2.version &&
           op1.type == op2.type &&
           op1.rootHeight == op2.rootHeight &&
           op1.stateRoot == op2.stateRoot &&
           op1.systemID == op2.systemID &&
           op1.blockHash == op2.blockHash &&
           op1.compactPower == op2.compactPower;
}

bool operator!=(const CProofRoot &op1, const CProofRoot &op2)
{
    return !(op1 == op2);
}

CProofRoot CProofRoot::GetProofRoot(uint32_t blockHeight)
{
    if (blockHeight > chainActive.Height())
    {
        return CProofRoot();
    }
    auto mmv = chainActive.GetMMV();
    mmv.resize(blockHeight + 1);
    return CProofRoot(ASSETCHAINS_CHAINID, 
                      blockHeight, 
                      mmv.GetRoot(), 
                      chainActive[blockHeight]->GetBlockHash(), 
                      chainActive[blockHeight]->chainPower.CompactChainPower());
}

CNotaryEvidence::CNotaryEvidence(const CTransaction &tx, int outputNum, int &afterEvidence, uint8_t EvidenceType) :
    type(EvidenceType), version(CNotaryEvidence::VERSION_INVALID)
{
    afterEvidence = outputNum;

    COptCCParams p;

    if (afterEvidence >= 0 &&
        tx.vout.size() > afterEvidence &&
        tx.vout[afterEvidence++].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_NOTARY_EVIDENCE &&
        p.vData.size() &&
        (*this = CNotaryEvidence(p.vData[0])).IsValid())
    {
        if (IsMultipartProof())
        {
            COptCCParams eP;
            CNotaryEvidence supplementalEvidence;
            std::vector<CNotaryEvidence> partsVector({*this});
            while (tx.vout.size() > afterEvidence &&
                tx.vout[afterEvidence++].scriptPubKey.IsPayToCryptoCondition(eP) &&
                eP.IsValid() &&
                eP.evalCode == EVAL_NOTARY_EVIDENCE &&
                eP.vData.size() &&
                (supplementalEvidence = CNotaryEvidence(eP.vData[0])).IsValid() &&
                supplementalEvidence.IsMultipartProof() &&
                supplementalEvidence.evidence.chainObjects.size() == 1)
            {
                partsVector.push_back(supplementalEvidence);
            }
            *this = CNotaryEvidence(partsVector);
        }
    }
}

bool CPBaaSNotarization::GetLastNotarization(const uint160 &currencyID,
                                             int32_t startHeight,
                                             int32_t endHeight,
                                             uint256 *txIDOut,
                                             CTransaction *txOut)
{
    CPBaaSNotarization notarization;
    std::vector<CAddressIndexDbEntry> notarizationIndex;
    // get the last notarization in the indicated height for this currency, which is valid by definition for a token
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::NotaryNotarizationKey()), CScript::P2IDX, notarizationIndex, startHeight, endHeight))
    {
        // filter out all transactions that do not spend from the notarization thread, or originate as the
        // chain definition
        for (auto it = notarizationIndex.rbegin(); it != notarizationIndex.rend(); it++)
        {
            // first unspent notarization that is valid is the one we want, skip spending
            if (it->first.spending)
            {
                continue;
            }
            LOCK(mempool.cs);
            CTransaction oneTx;
            uint256 blkHash;
            if (myGetTransaction(it->first.txhash, oneTx, blkHash))
            {
                if ((notarization = CPBaaSNotarization(oneTx.vout[it->first.index].scriptPubKey)).IsValid())
                {
                    *this = notarization;
                    if (txIDOut)
                    {
                        *txIDOut = it->first.txhash;
                    }
                    if (txOut)
                    {
                        *txOut = oneTx;
                    }
                    break;
                }
            }
            else
            {
                LogPrintf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                continue;
            }
        }
    }
    return notarization.IsValid();
}

bool CPBaaSNotarization::GetLastUnspentNotarization(const uint160 &currencyID,
                                                    uint256 &txIDOut,
                                                    int32_t &txOutNum,
                                                    CTransaction *txOut)
{
    CPBaaSNotarization notarization;
    std::vector<CAddressUnspentDbEntry> notarizationIndex;
    // get the last notarization in the indicated height for this currency, which is valid by definition for a token
    if (GetAddressUnspent(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::NotaryNotarizationKey()), CScript::P2IDX, notarizationIndex))
    {
        // first valid, unspent notarization found is the one we return
        for (auto it = notarizationIndex.rbegin(); it != notarizationIndex.rend(); it++)
        {
            LOCK(mempool.cs);
            CTransaction oneTx;
            uint256 blkHash;
            if (myGetTransaction(it->first.txhash, oneTx, blkHash))
            {
                if ((notarization = CPBaaSNotarization(oneTx.vout[it->first.index].scriptPubKey)).IsValid())
                {
                    *this = notarization;
                    txIDOut = it->first.txhash;
                    txOutNum = it->first.index;
                    if (txOut)
                    {
                        *txOut = oneTx;
                    }
                    break;
                }
            }
            else
            {
                LogPrintf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                continue;
            }
        }
    }
    return notarization.IsValid();
}

bool CPBaaSNotarization::NextNotarizationInfo(const CCurrencyDefinition &sourceSystem, 
                                              const CCurrencyDefinition &destCurrency, 
                                              uint32_t lastExportHeight, 
                                              uint32_t notaHeight, 
                                              std::vector<CReserveTransfer> &exportTransfers,       // both in and out. this may refund conversions
                                              uint256 &transferHash,
                                              CPBaaSNotarization &newNotarization,
                                              std::vector<CTxOut> &importOutputs,
                                              CCurrencyValueMap &importedCurrency,
                                              CCurrencyValueMap &gatewayDepositsUsed,
                                              CCurrencyValueMap &spentCurrencyOut,
                                              CTransferDestination feeRecipient,
                                              bool forcedRefund) const
{
    uint160 sourceSystemID = sourceSystem.GetID();
    uint160 destSystemID = destCurrency.IsGateway() ? destCurrency.gatewayID : destCurrency.systemID;

    newNotarization = *this;
    newNotarization.SetDefinitionNotarization(false);
    newNotarization.SetBlockOneNotarization(false);
    newNotarization.prevNotarization = CUTXORef();
    newNotarization.prevHeight = newNotarization.notarizationHeight;
    newNotarization.notarizationHeight = notaHeight;

    uint32_t currentHeight = chainActive.Height() + 1;

    // if we are communicating with an external system that uses a different hash, use it for everything
    CCurrencyDefinition::EProofProtocol hashType = CCurrencyDefinition::EProofProtocol::PROOF_PBAASMMR;

    uint160 externalSystemID = sourceSystem.SystemOrGatewayID() == ASSETCHAINS_CHAINID ? 
                                ((destSystemID == ASSETCHAINS_CHAINID) ? uint160() : destSystemID) : 
                                sourceSystem.GetID();

    CCurrencyDefinition externalSystemDef;
    if (externalSystemID.IsNull() || externalSystemID == ASSETCHAINS_CHAINID)
    {
        externalSystemDef = ConnectedChains.ThisChain();
    }
    else if (externalSystemID == sourceSystemID)
    {
        externalSystemDef = sourceSystem;
    }
    else if (externalSystemID == destSystemID)
    {
        if (destCurrency.GetID() == destSystemID)
        {
            externalSystemDef = destCurrency;
        }
        else
        {
            externalSystemDef = ConnectedChains.GetCachedCurrency(externalSystemID);
            if (!externalSystemDef.IsValid())
            {
                LogPrintf("%s: cannot retrieve system definition for %s\n", __func__, EncodeDestination(CIdentityID(externalSystemID)));
                return false;
            }
        }
    }

    CTransferDestination notaryPayee;

    if (!externalSystemID.IsNull())
    {
        hashType = (CCurrencyDefinition::EProofProtocol)externalSystemDef.proofProtocol;
    }

    CNativeHashWriter hwPrevNotarization;
    hwPrevNotarization << *this;
    newNotarization.hashPrevCrossNotarization = hwPrevNotarization.GetHash();

    CNativeHashWriter hw(hashType);

    CCurrencyValueMap newPreConversionReservesIn;

    if (!IsPreLaunch() && !IsLaunchComplete())
    {
        newPreConversionReservesIn = CCurrencyValueMap(currencyState.currencies, currencyState.primaryCurrencyIn);
    }

    for (int i = 0; i < exportTransfers.size(); i++)
    {
        CReserveTransfer reserveTransfer = exportTransfers[i];

        //auto transferVec = ::AsVector(reserveTransfer);
        //printf("%s: ReserveTransfer:\n%s\nSerialized:\n%s\n", __func__, reserveTransfer.ToUniValue().write(1,2).c_str(), HexBytes(&(transferVec[0]), transferVec.size()).c_str());

        // add the pre-mutation reserve transfer to the hash
        hw << reserveTransfer;

        if (currencyState.IsRefunding())
        {
            reserveTransfer = reserveTransfer.GetRefundTransfer();
        }
        // ensure that any pre-conversions or conversions are all valid, based on mined height and
        // maximum pre-conversions
        else if (reserveTransfer.IsPreConversion())
        {
            if (IsLaunchComplete())
            {
                //printf("%s: Invalid pre-conversion, mined on or after start block\n", __func__);
                LogPrintf("%s: Invalid pre-conversion, mined on or after start block\n", __func__);
                reserveTransfer = reserveTransfer.GetRefundTransfer();
            }
            else
            {
                // check if it exceeds pre-conversion maximums, and refund if so
                CCurrencyValueMap newReserveIn = CCurrencyValueMap(std::vector<uint160>({reserveTransfer.FirstCurrency()}), 
                                                                   std::vector<int64_t>({reserveTransfer.FirstValue() - CReserveTransactionDescriptor::CalculateConversionFee(reserveTransfer.FirstValue())}));
                CCurrencyValueMap newTotalReserves;
                if (IsPreLaunch())
                {
                    newTotalReserves = CCurrencyValueMap(destCurrency.currencies, newNotarization.currencyState.reserves) + newReserveIn + newPreConversionReservesIn;
                }
                else
                {
                    newTotalReserves = CCurrencyValueMap(destCurrency.currencies, newNotarization.currencyState.primaryCurrencyIn) + newReserveIn + newPreConversionReservesIn;
                }

                if (destCurrency.maxPreconvert.size() && newTotalReserves > CCurrencyValueMap(destCurrency.currencies, destCurrency.maxPreconvert))
                {
                    LogPrintf("%s: refunding pre-conversion over maximum\n", __func__);
                    reserveTransfer = reserveTransfer.GetRefundTransfer();
                }
                else
                {
                    newPreConversionReservesIn += newReserveIn;
                }
            }
        }
        else if (reserveTransfer.IsConversion())
        {
            if (!IsLaunchComplete())
            {
                //printf("%s: Invalid conversion, mined before start block\n", __func__);
                LogPrintf("%s: Invalid conversion, mined before start block\n", __func__);
                reserveTransfer = reserveTransfer.GetRefundTransfer();
            }
        }
    }

    if (exportTransfers.size())
    {
        transferHash = hw.GetHash();
    }

    CReserveTransactionDescriptor rtxd;
    std::vector<CTxOut> dummyImportOutputs;
    bool thisIsLaunchSys = destCurrency.launchSystemID == ASSETCHAINS_CHAINID;

    // if this is the clear launch notarization after start, make the notarization and determine if we should launch or refund

    uint256 weakEntropy = proofRoots.count(sourceSystemID) ? proofRoots.find(sourceSystemID)->second.stateRoot : uint256();

    // TODO: HARDENING ensure that the latest proof root of this chain is in on gateway

    if (destCurrency.launchSystemID == sourceSystemID &&
        destCurrency.startBlock &&
        ((thisIsLaunchSys && notaHeight <= (destCurrency.startBlock - 1)) ||
         (!thisIsLaunchSys &&
          destCurrency.systemID == ASSETCHAINS_CHAINID &&
          notaHeight == 1)))
    {
        // we get one pre-launch coming through here, initial supply is set and ready for pre-convert
        if (((thisIsLaunchSys && notaHeight == (destCurrency.startBlock - 1)) || sourceSystemID != ASSETCHAINS_CHAINID) && 
            newNotarization.IsPreLaunch())
        {
            // the first block executes the second time through
            if (newNotarization.IsLaunchCleared())
            {
                newNotarization.SetPreLaunch(false);
                newNotarization.currencyState.SetLaunchClear();
                newNotarization.currencyState.SetPrelaunch(false);
                newNotarization.currencyState.RevertReservesAndSupply();
            }
            else
            {
                newNotarization.SetLaunchCleared();
                newNotarization.currencyState.SetLaunchClear();

                // if we are connected to another currency, make sure it will also start before we confirm that we can
                CCurrencyDefinition coLaunchCurrency;
                CCoinbaseCurrencyState coLaunchState;
                bool coLaunching = false;
                if (destCurrency.IsGatewayConverter())
                {
                    // PBaaS or gateway converters have a parent which is the PBaaS chain or gateway
                    coLaunching = true;
                    coLaunchCurrency = ConnectedChains.GetCachedCurrency(destCurrency.parent);
                }
                else if (destCurrency.IsPBaaSChain() && !destCurrency.GatewayConverterID().IsNull())
                {
                    coLaunching = true;
                    coLaunchCurrency = ConnectedChains.GetCachedCurrency(destCurrency.GatewayConverterID());
                }

                if (coLaunching)
                {
                    if (!coLaunchCurrency.IsValid())
                    {
                        printf("%s: Invalid co-launch currency - likely corruption\n", __func__);
                        LogPrintf("%s: Invalid co-launch currency - likely corruption\n", __func__);
                        return false;
                    }
                    coLaunchState = ConnectedChains.GetCurrencyState(coLaunchCurrency, notaHeight);

                    if (!coLaunchState.IsValid())
                    {
                        printf("%s: Invalid co-launch currency state - likely corruption\n", __func__);
                        LogPrintf("%s: Invalid co-launch currency state - likely corruption\n", __func__);
                        return false;
                    }

                    // check our currency and any co-launch currency to determine our eligibility, as ALL
                    // co-launch currencies must launch for one to launch
                    if (CCurrencyValueMap(coLaunchCurrency.currencies, coLaunchState.reserveIn) < CCurrencyValueMap(coLaunchCurrency.currencies, coLaunchCurrency.minPreconvert) ||
                        (coLaunchCurrency.IsFractional() &&
                         CCurrencyValueMap(coLaunchCurrency.currencies, coLaunchState.reserveIn).CanonicalMap().valueMap.size() != coLaunchCurrency.currencies.size()))
                    {
                        forcedRefund = true;
                    }
                }

                // first time through is export, second is import, then we finish clearing the launch
                // check if the chain is qualified to launch or should refund
                CCurrencyValueMap minPreMap, fees;
                CCurrencyValueMap preConvertedMap = (CCurrencyValueMap(destCurrency.currencies, newNotarization.currencyState.reserveIn) +
                                                     newPreConversionReservesIn).CanonicalMap();

                if (destCurrency.minPreconvert.size() && destCurrency.minPreconvert.size() == destCurrency.currencies.size())
                {
                    minPreMap = CCurrencyValueMap(destCurrency.currencies, destCurrency.minPreconvert).CanonicalMap();
                }

                if (forcedRefund ||
                    (minPreMap.valueMap.size() && preConvertedMap < minPreMap) ||
                    (destCurrency.IsFractional() &&
                     (CCurrencyValueMap(destCurrency.currencies, newNotarization.currencyState.reserveIn) +
                                        newPreConversionReservesIn).CanonicalMap().valueMap.size() != destCurrency.currencies.size()))
                {
                    // we force the reserves and supply to zero
                    // in any case where there was less than minimum participation,
                    newNotarization.currencyState.supply = 0;
                    newNotarization.currencyState.reserves = std::vector<int64_t>(newNotarization.currencyState.reserves.size(), 0);
                    newNotarization.currencyState.SetRefunding(true);
                    newNotarization.SetRefunding(true);
                }
                else
                {
                    newNotarization.SetLaunchConfirmed();
                    newNotarization.currencyState.SetLaunchConfirmed();

                    // if this is a launch notarization for a PBaaS chain, add a proofroot of the
                    // current chain as an anchor for the block one import
                    if (destCurrency.IsPBaaSChain() &&
                        destCurrency.launchSystemID == ASSETCHAINS_CHAINID)
                    {
                        newNotarization.proofRoots[ASSETCHAINS_CHAINID] = CProofRoot::GetProofRoot(destCurrency.startBlock);
                    }
                }
            }
        }
        else if (thisIsLaunchSys && notaHeight < (destCurrency.startBlock - 1))
        {
            newNotarization.currencyState.SetPrelaunch();
        }

        // NOTE: destcurrency systemID is correct here, since this is only prelaunch or block 1, which doesn't apply for gateway's
        CCurrencyDefinition destSystem = newNotarization.IsRefunding() ? ConnectedChains.GetCachedCurrency(destCurrency.launchSystemID) : 
                                                                         ConnectedChains.GetCachedCurrency(destCurrency.systemID);

        CCoinbaseCurrencyState tempState = newNotarization.currencyState;
        if (destCurrency.IsFractional() &&
            !(newNotarization.IsLaunchCleared() && !newNotarization.currencyState.IsLaunchCompleteMarker()) &&
            exportTransfers.size())
        {
            // normalize prices on the way in to prevent overflows on first pass
            std::vector<int64_t> newReservesVector = newPreConversionReservesIn.AsCurrencyVector(tempState.currencies);
            tempState.reserves = tempState.AddVectors(tempState.reserves, newReservesVector);
            newNotarization.currencyState.conversionPrice = tempState.PricesInReserve();
        }

        std::vector<CTxOut> tempOutputs;
        bool retVal = rtxd.AddReserveTransferImportOutputs(newNotarization.IsRefunding() ? destSystem : sourceSystem,
                                                           newNotarization.IsRefunding() ? sourceSystem : destSystem,
                                                           destCurrency, 
                                                           newNotarization.currencyState, 
                                                           exportTransfers, 
                                                           currentHeight,
                                                           tempOutputs, 
                                                           importedCurrency,
                                                           gatewayDepositsUsed, 
                                                           spentCurrencyOut,
                                                           &tempState,
                                                           feeRecipient,
                                                           proposer,
                                                           weakEntropy);

        if (retVal)
        {
            //printf("%s: importedCurrency: %s\ngatewaysDepositsUsed: %s\n", __func__, importedCurrency.ToUniValue().write(1,2).c_str(), gatewayDepositsUsed.ToUniValue().write(1,2).c_str());
            importedCurrency.valueMap.clear();
            gatewayDepositsUsed.valueMap.clear();
            spentCurrencyOut.valueMap.clear();
            newNotarization.currencyState.conversionPrice = tempState.conversionPrice;
            newNotarization.currencyState.viaConversionPrice = tempState.viaConversionPrice;
            rtxd = CReserveTransactionDescriptor();

            retVal = rtxd.AddReserveTransferImportOutputs(newNotarization.IsRefunding() ? destSystem : sourceSystem,
                                                          newNotarization.IsRefunding() ? sourceSystem : destSystem,
                                                          destCurrency, 
                                                          newNotarization.currencyState, 
                                                          exportTransfers,
                                                          currentHeight,
                                                          importOutputs, 
                                                          importedCurrency,
                                                          gatewayDepositsUsed, 
                                                          spentCurrencyOut,
                                                          &tempState,
                                                          feeRecipient,
                                                          proposer,
                                                          weakEntropy);
        }
        else
        {
            return retVal;
        }

        //printf("%s: importedCurrency: %s\ngatewaysDepositsUsed: %s\n", __func__, importedCurrency.ToUniValue().write(1,2).c_str(), gatewayDepositsUsed.ToUniValue().write(1,2).c_str());

        // if we are in the pre-launch phase, all reserves in are cumulative and then calculated together at launch
        // reserves in represent all reserves in, and fees are taken out after launch or refund as well
        //
        // we add up until the end, then stop adding reserves at launch clear. this gives us the ability to reverse the 
        // pre-launch state for validation. we continue adding fees up to pre-launch to easily get a total of unconverted 
        // fees, which we need when creating a PBaaS chain, as all currency, both reserves and fees exported to the new
        // chain must be either output to specific addresses, taken as fees by miners, or stored in reserve deposits.
        if (tempState.IsPrelaunch())
        {
            tempState.reserveIn = tempState.AddVectors(tempState.reserveIn, this->currencyState.reserveIn);
            if (!destCurrency.IsFractional() && !this->IsDefinitionNotarization() && !tempState.IsLaunchClear())
            {
                tempState.supply += this->currencyState.supply - this->currencyState.emitted;
                tempState.preConvertedOut += this->currencyState.preConvertedOut;
                tempState.primaryCurrencyOut += this->currencyState.primaryCurrencyOut;
            }
        }
        else if (!newNotarization.currencyState.IsLaunchCompleteMarker() && !tempState.IsRefunding() && !this->currencyState.IsPrelaunch())
        {
            // accumulate reserves during pre-conversions import to enforce max pre-convert
            CCurrencyValueMap tempReserves;
            for (auto &oneCurrencyID : tempState.currencies)
            {
                if (rtxd.currencies.count(oneCurrencyID))
                {
                    int64_t reservesConverted = rtxd.currencies[oneCurrencyID].nativeOutConverted;
                    if (reservesConverted)
                    {
                        tempReserves.valueMap[oneCurrencyID] = reservesConverted;
                    }
                }
            }
    
            // use double entry to enable pass through of the accumulated reserve such that when
            // reverting supply and reserves, we end up with what we started, after prelaunch and
            // before all post launch functions are complete, we use primaryCurrencyIn to accumulate
            // reserves to enforce maxPreconvert
            tempState.primaryCurrencyIn = tempState.AddVectors(this->currencyState.primaryCurrencyIn, tempReserves.AsCurrencyVector(tempState.currencies));
            tempState.reserveOut = 
                    tempState.AddVectors(tempState.reserveOut,
                                         (CCurrencyValueMap(tempState.currencies, tempState.reserveIn) * -1).AsCurrencyVector(tempState.currencies));
            tempState.reserveIn = tempReserves.AsCurrencyVector(tempState.currencies);
        }
        if (destCurrency.IsPBaaSChain() && tempState.IsLaunchClear() && this->currencyState.IsLaunchClear())
        {
            tempState.reserveIn = this->currencyState.reserveIn;
        }
        newNotarization.currencyState = tempState;
        return retVal;
    }
    else
    {
        if (sourceSystemID != destCurrency.launchSystemID || lastExportHeight >= destCurrency.startBlock || newNotarization.IsLaunchComplete())
        {
            newNotarization.currencyState.SetLaunchCompleteMarker();
        }
        newNotarization.currencyState.SetLaunchClear(false);

        CCurrencyDefinition destSystem = newNotarization.IsRefunding() ? ConnectedChains.GetCachedCurrency(destCurrency.launchSystemID) : 
                                                                         ConnectedChains.GetCachedCurrency(destCurrency.SystemOrGatewayID());

        // calculate new state from processing all transfers
        // we are not refunding, and it is possible that we also have
        // normal conversions in addition to pre-conversions. add any conversions that may 
        // be present into the new currency state
        CCoinbaseCurrencyState intermediateState = newNotarization.currencyState;
        bool isValidExport = rtxd.AddReserveTransferImportOutputs(sourceSystem,
                                                                  destSystem,
                                                                  destCurrency, 
                                                                  intermediateState, 
                                                                  exportTransfers, 
                                                                  currentHeight,
                                                                  dummyImportOutputs, 
                                                                  importedCurrency,
                                                                  gatewayDepositsUsed, 
                                                                  spentCurrencyOut,
                                                                  &newNotarization.currencyState,
                                                                  feeRecipient,
                                                                  proposer,
                                                                  weakEntropy);
        if (!newNotarization.currencyState.IsPrelaunch() &&
            isValidExport &&
            destCurrency.IsFractional())
        {
            // we want the new price and the old state as a starting point to ensure no rounding error impact
            // on reserves
            importedCurrency = CCurrencyValueMap();
            gatewayDepositsUsed = CCurrencyValueMap();
            CCoinbaseCurrencyState tempCurState = intermediateState;
            tempCurState.conversionPrice = newNotarization.currencyState.conversionPrice;
            tempCurState.viaConversionPrice = newNotarization.currencyState.viaConversionPrice;
            rtxd = CReserveTransactionDescriptor();
            isValidExport = rtxd.AddReserveTransferImportOutputs(sourceSystem,
                                                                 destSystem,
                                                                 destCurrency, 
                                                                 tempCurState, 
                                                                 exportTransfers, 
                                                                 currentHeight,
                                                                 importOutputs, 
                                                                 importedCurrency,
                                                                 gatewayDepositsUsed, 
                                                                 spentCurrencyOut,
                                                                 &newNotarization.currencyState,
                                                                 feeRecipient,
                                                                 proposer,
                                                                 weakEntropy);
            if (isValidExport)
            {
                newNotarization.currencyState.conversionPrice = tempCurState.conversionPrice;
                newNotarization.currencyState.viaConversionPrice = tempCurState.viaConversionPrice;
            }
        }
        else if (isValidExport)
        {
            importOutputs.insert(importOutputs.end(), dummyImportOutputs.begin(), dummyImportOutputs.end());
        }
        
        if (!isValidExport)
        {
            LogPrintf("%s: invalid export\n", __func__);
            return false;
        }
        return true;
    }

    // based on the last notarization and existing
    return false;
}

CObjectFinalization::CObjectFinalization(const CScript &script) : version(VERSION_INVALID)
{
    COptCCParams p;
    if (script.IsPayToCryptoCondition(p) && p.IsValid())
    {
        if ((p.evalCode == EVAL_FINALIZE_NOTARIZATION || p.evalCode == EVAL_FINALIZE_EXPORT) &&
            p.vData.size())
        {
            *this = CObjectFinalization(p.vData[0]);
        }
    }
}

CObjectFinalization::CObjectFinalization(const CTransaction &tx, uint32_t *pEcode, int32_t *pFinalizationOutNum, uint32_t minFinalHeight, uint8_t Version) :
    minFinalizationHeight(minFinalHeight),
    version(Version)
{
    uint32_t _ecode;
    uint32_t &ecode = pEcode ? *pEcode : _ecode;
    int32_t _finalizeOutNum;
    int32_t &finalizeOutNum = pFinalizationOutNum ? *pFinalizationOutNum : _finalizeOutNum;
    finalizeOutNum = -1;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
        {
            if (p.evalCode == EVAL_FINALIZE_NOTARIZATION || p.evalCode == EVAL_FINALIZE_EXPORT)
            {
                if (finalizeOutNum != -1)
                {
                    version = VERSION_INVALID;
                    finalizeOutNum = -1;
                    break;
                }
                else
                {
                    finalizeOutNum = i;
                    ecode = p.evalCode;
                }
            }
        }
    }
}

CChainNotarizationData::CChainNotarizationData(UniValue &obj)
{
    version = (uint32_t)uni_get_int(find_value(obj, "version"));
    UniValue vtxUni = find_value(obj, "notarizations");
    if (vtxUni.isArray())
    {
        vector<UniValue> vvtx = vtxUni.getValues();
        for (auto o : vvtx)
        {
            vtx.push_back(make_pair(CUTXORef(uint256S(uni_get_str(find_value(o, "txid"))),
                                             uni_get_int(find_value(o, "vout"))),
                                    CPBaaSNotarization(find_value(o, "notarization"))));
        }
    }

    lastConfirmed = (uint32_t)uni_get_int(find_value(obj, "lastconfirmed"));
    UniValue forksUni = find_value(obj, "forks");
    if (forksUni.isArray())
    {
        vector<UniValue> forksVec = forksUni.getValues();
        for (auto fv : forksVec)
        {
            if (fv.isArray())
            {
                forks.push_back(vector<int32_t>());
                vector<UniValue> forkVec = fv.getValues();
                for (auto fidx : forkVec)
                {
                    forks.back().push_back(uni_get_int(fidx));
                }
            }
        }
    }

    bestChain = (uint32_t)uni_get_int(find_value(obj, "bestchain"));
}

UniValue CChainNotarizationData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)version));
    UniValue notarizations(UniValue::VARR);
    for (int64_t i = 0; i < vtx.size(); i++)
    {
        UniValue notarization(UniValue::VOBJ);
        notarization.push_back(Pair("index", i));
        notarization.push_back(Pair("txid", vtx[i].first.hash.GetHex()));
        notarization.push_back(Pair("vout", (int32_t)vtx[i].first.n));
        notarization.push_back(Pair("notarization", vtx[i].second.ToUniValue()));
        notarizations.push_back(notarization);
    }
    obj.push_back(Pair("notarizations", notarizations));
    UniValue Forks(UniValue::VARR);
    for (int32_t i = 0; i < forks.size(); i++)
    {
        UniValue Fork(UniValue::VARR);
        for (int32_t j = 0; j < forks[i].size(); j++)
        {
            Fork.push_back(forks[i][j]);
        }
        Forks.push_back(Fork);
    }
    obj.push_back(Pair("forks", Forks));
    if (IsConfirmed())
    {
        obj.push_back(Pair("lastconfirmedheight", (int32_t)vtx[lastConfirmed].second.notarizationHeight));
    }
    obj.push_back(Pair("lastconfirmed", lastConfirmed));
    obj.push_back(Pair("bestchain", bestChain));
    return obj;
}

bool CPBaaSNotarization::IsNotarizationConfirmed(const CPBaaSNotarization &notarization,
                                                 const CNotaryEvidence &notaryEvidence,
                                                 CValidationState &state) const
{
    // TODO: HARDENING - remove or implement and use
    return false;
}

bool CPBaaSNotarization::IsNotarizationRejected(const CPBaaSNotarization &notarization,
                                                const CNotaryEvidence &notaryEvidence,
                                                CValidationState &state) const
{
    // TODO: HARDENING - remove or implement and use
    return false;
}

bool CChainNotarizationData::CalculateConfirmation(int confirmingIdx, std::set<int> &confirmedOutputNums, std::set<int> &invalidatedOutputNums) const
{
    int forkIdx = -1, forkPos = -1;

    if (confirmingIdx != lastConfirmed)
    {
        // if the third notarization does not equal the last confirmed notarization, it
        // must equal a last pending notarization to confirm. that will always be the
        // first non-confirmed entry in a fork of the notarization data, if it is present
        for (int i = 0; i < forks.size(); i++)
        {
            if (forks[i].size() > 1)
            {
                for (int j = forks[i].size() - 1; j >= 0; j--)
                {
                    if (forks[i][j] == confirmingIdx)
                    {
                        forkIdx = i;
                        forkPos = j;
                        break;
                    }
                }
                if (forkIdx > -1)
                {
                    break;
                }
            }
        }
        // if it wasn't the confirmed entry and wasn't pending confirmation, it is referring to an
        // invalid predecessor and therefore, confirmingIdx is invalid
        if (forkIdx == -1)
        {
            LogPrint("notarization", "%s: invalid prior notarization - neither pending nor confirmed\n", __func__);
            return false;
        }
    }

    if (forkIdx > -1)
    {
        // if this finalization is either confirmed or invalidated by the new accepted notarization,
        // add a spend here
        for (int i = 0; i <= forkPos; i++)
        {
            confirmedOutputNums.insert(forks[forkIdx][i]);
        }

        for (int i = 0; i < forks.size(); i++)
        {
            // already did the fork that is our focus
            if (i == forkIdx)
            {
                continue;
            }
            bool failed = false;

            int j;
            for (j = 0; j < forks[i].size(); j++)
            {
                // if we reach the end, the rest after are ignored
                if (forks[i][j] == confirmingIdx)
                {
                    break;
                }
                if (confirmedOutputNums.count(forks[i][j]))
                {
                    continue;
                }
                // it did not derive from the newly confirmed index, so it is invalid and all after this
                failed = true;
                break;
            }
            // if failed, invalidate all until the end, otherwise, ignore all until the end
            if (failed)
            {
                for (int k = j; k < forks[i].size(); k++)
                {
                    invalidatedOutputNums.insert(forks[i][k]);
                }
            }
        }
    }
    return true;
}

bool CChainNotarizationData::CorrelatedFinalizationSpends(const std::vector<std::pair<CTransaction, uint256>> &txes,
                                                          std::vector<std::vector<CInputDescriptor>> &spendsToClose,
                                                          std::vector<CInputDescriptor> &extraSpends,
                                                          std::vector<std::vector<CNotaryEvidence>> *pEvidenceVec) const
{
    if (!(IsValid() && IsConfirmed()))
    {
        return false;
    }
    uint160 currencyID = vtx[0].second.currencyID;

    if (pEvidenceVec)
    {
        *pEvidenceVec = std::vector<std::vector<CNotaryEvidence>>(vtx.size());
    }

    std::map<CUTXORef, int> notarizationOutputMap;

    for (int i = 0; i < vtx.size(); i++)
    {
        notarizationOutputMap.insert(std::make_pair(vtx[i].first, i));
    }

    uint32_t confirmedBlockHeight = mapBlockIndex.count(txes[lastConfirmed].second) ? mapBlockIndex[txes[lastConfirmed].second]->GetHeight() : 0;
    if (!confirmedBlockHeight)
    {
        LogPrint("notarization", "%s: last confirmed notarization not found in block index\n", __func__);
        return false;
    }

    spendsToClose = std::vector<std::vector<CInputDescriptor>>(vtx.size());

    for (auto onePending : CObjectFinalization::GetUnspentPendingFinalizations(currencyID))
    {
        // determine the notarization output that this is referring to
        COptCCParams p;
        CObjectFinalization existingFinalization;
        CUTXORef pendingNotarizationOutput;
        std::set<CUTXORef> evidenceOutputSet;
        if (onePending.second.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.vData.size())
        {
            if (p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                (existingFinalization = CObjectFinalization(p.vData[0])).IsValid())
            {
                if (existingFinalization.output.IsOnSameTransaction())
                {
                    pendingNotarizationOutput = CUTXORef(onePending.second.txIn.prevout.hash, existingFinalization.output.n);
                }
                else
                {
                    pendingNotarizationOutput = existingFinalization.output;
                }
            }
            else if (p.evalCode == EVAL_EARNEDNOTARIZATION)
            {
                pendingNotarizationOutput = CUTXORef(onePending.second.txIn.prevout.hash, onePending.second.txIn.prevout.n);
            }
        }
        else
        {
            // this is likely some form of incorrect index
            LogPrintf("%s: LIKELY LOCAL STATE OR INDEX CORRUPTION. Bootstrap, reindex, or resync recommended\n", __func__);
            continue;
        }

        // if this is a finalization with some evidence, add the spends to close it that include the finalization and
        // its evidence outputs
        int associatedIdx = -1;
        if (pendingNotarizationOutput.IsValid() && !pendingNotarizationOutput.hash.IsNull())
        {
            std::vector<CInputDescriptor> associatedSpends;
            associatedSpends.push_back(onePending.second);      // this is a finalization or earned notarization, so it is first associated spend

            if (notarizationOutputMap.count(pendingNotarizationOutput))
            {
                associatedIdx = notarizationOutputMap[pendingNotarizationOutput];
            }

            // if we are asssociated with a known node,
            // get additional associated evidence as well
            if (associatedIdx != -1)
            {
                // if there is a finalization, we need to add it and its evidence,
                if (existingFinalization.IsValid() && existingFinalization.evidenceOutputs.size())
                {
                    CTransaction finalizationTx;
                    const CTransaction *pEvidenceOutputTx = nullptr;
                    if (existingFinalization.output.IsOnSameTransaction())
                    {
                        pEvidenceOutputTx = &(txes[associatedIdx].first);
                    }
                    else
                    {
                        LOCK(mempool.cs);
                        uint256 hashBlock;
                        if (myGetTransaction(onePending.second.txIn.prevout.hash, finalizationTx, hashBlock))
                        {
                            pEvidenceOutputTx = &finalizationTx;
                        }
                        else
                        {
                            LogPrint("notarization", "%s: cannot access transaction required as input for notarization\n", __func__);
                            return false;
                        }
                    }

                    // add evidence outs as spends to close this entry as well
                    int afterMultiPart = existingFinalization.evidenceOutputs.size() ? existingFinalization.evidenceOutputs[0] : 0;
                    for (auto oneEvidenceOutN : existingFinalization.evidenceOutputs)
                    {
                        if (pEvidenceOutputTx->vout.size() <= oneEvidenceOutN)
                        {
                            LogPrint("notarization", "%s: indexing error for notarization evidence\n", __func__);
                            return false;
                        }

                        if (pEvidenceVec &&
                            oneEvidenceOutN >= afterMultiPart &&
                            associatedIdx != -1)
                        {
                            CNotaryEvidence oneEvidenceObj(*pEvidenceOutputTx, oneEvidenceOutN, afterMultiPart);
                            if (oneEvidenceObj.IsValid())
                            {
                                (*pEvidenceVec)[associatedIdx].push_back(oneEvidenceObj);
                            }
                        }

                        associatedSpends.push_back(
                            CInputDescriptor(pEvidenceOutputTx->vout[oneEvidenceOutN].scriptPubKey,
                                                pEvidenceOutputTx->vout[oneEvidenceOutN].nValue,
                                                CTxIn(pEvidenceOutputTx->GetHash(), oneEvidenceOutN)));
                        evidenceOutputSet.insert(associatedSpends.back().txIn.prevout);
                    }
                }

                // unspent evidence is specific to the target notarization
                std::vector<std::pair<uint32_t, CInputDescriptor>> unspentEvidence =
                    CObjectFinalization::GetUnspentEvidence(currencyID, vtx[associatedIdx].first.hash, vtx[associatedIdx].first.n);
                for (auto &oneEvidenceSpend : unspentEvidence)
                {
                    // if not already added to our spends as evidence, add it
                    if (!evidenceOutputSet.count(oneEvidenceSpend.second.txIn.prevout))
                    {
                        COptCCParams tP;
                        CNotaryEvidence oneEvidenceObj;
                        if (pEvidenceVec &&
                            oneEvidenceSpend.second.scriptPubKey.IsPayToCryptoCondition(tP) &&
                            tP.IsValid() &&
                            tP.vData.size() &&
                            tP.evalCode == EVAL_NOTARY_EVIDENCE &&
                            (oneEvidenceObj = CNotaryEvidence(tP.vData[0])).IsValid())
                        {
                            (*pEvidenceVec)[associatedIdx].push_back(oneEvidenceObj);
                        }

                        associatedSpends.push_back(oneEvidenceSpend.second);
                    }
                }

                spendsToClose[associatedIdx].insert(spendsToClose[associatedIdx].end(), associatedSpends.begin(), associatedSpends.end());
            }
            else
            {
                // it may be a straggler that came in before confirmation. if so, just clean it up
                if (onePending.first)
                {
                    // add it to unknown closing spends
                    extraSpends.insert(extraSpends.end(), associatedSpends.begin(), associatedSpends.end());
                }
                else
                {
                    LogPrint("notarization", "%s: no associated notarization located for pending finalization in mempool:\n%s\n", __func__, pendingNotarizationOutput.ToString().c_str());
                }
            }
        }
    }

    for (auto oneConfirmed : CObjectFinalization::GetUnspentConfirmedFinalizations(currencyID))
    {
        // since we are creating a new, confirmed finalization, spend old one here
        // determine the notarization output that this is referring to
        COptCCParams p;
        CObjectFinalization confirmedFinalization;
        CUTXORef confirmedNotarizationOutput;
        std::set<CUTXORef> evidenceOutputSet;

        if (oneConfirmed.second.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid())
        {
            CPBaaSNotarization confirmedNotarization;
            if (p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                p.vData.size() &&
                (confirmedFinalization = CObjectFinalization(p.vData[0])).IsValid())
            {
                if (confirmedFinalization.output.IsOnSameTransaction())
                {
                    confirmedNotarizationOutput = CUTXORef(oneConfirmed.second.txIn.prevout.hash, confirmedFinalization.output.n);
                }
                else
                {
                    confirmedNotarizationOutput = confirmedFinalization.output;
                }
            }
            else if ((p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                     p.vData.size() &&
                     (confirmedNotarization = CPBaaSNotarization(p.vData[0])).IsValid() &&
                     (confirmedNotarization.IsDefinitionNotarization() || confirmedNotarization.IsBlockOneNotarization()))
            {
                confirmedFinalization = CObjectFinalization(CObjectFinalization::FINALIZE_CONFIRMED + CObjectFinalization::FINALIZE_NOTARIZATION,
                                                            confirmedNotarization.currencyID,
                                                            oneConfirmed.second.txIn.prevout.hash,
                                                            oneConfirmed.second.txIn.prevout.n);
                confirmedNotarizationOutput = confirmedFinalization.output;
            }
        }
        else
        {
            // this is likely some form of incorrect index
            LogPrintf("%s: LIKELY LOCAL STATE OR INDEX CORRUPTION. Bootstrap, reindex, or resync recommended\n", __func__);
            continue;
        }

        // if this is a finalization, add the spends to close it that include the finalization and
        // its evidence outputs
        int associatedIdx = -1;
        if (confirmedFinalization.IsValid())
        {
            std::vector<CInputDescriptor> associatedSpends;
            associatedSpends.push_back(oneConfirmed.second);

            if (notarizationOutputMap.count(confirmedNotarizationOutput))
            {
                associatedIdx = notarizationOutputMap[confirmedNotarizationOutput];
            }

            if (associatedIdx != -1)
            {
                if (confirmedFinalization.evidenceOutputs.size() || confirmedFinalization.evidenceInputs.size())
                {
                    CTransaction finalizationTx;
                    const CTransaction *pEvidenceOutputTx = nullptr;
                    if (confirmedFinalization.output.IsOnSameTransaction())
                    {
                        pEvidenceOutputTx = &(txes[associatedIdx].first);
                    }
                    else
                    {
                        LOCK(mempool.cs);
                        uint256 hashBlock;
                        if (myGetTransaction(oneConfirmed.second.txIn.prevout.hash, finalizationTx, hashBlock))
                        {
                            pEvidenceOutputTx = &finalizationTx;
                        }
                        else
                        {
                            LogPrint("notarization", "%s: cannot access transaction required as input for notarization\n", __func__);
                            return false;
                        }
                    }

                    // add evidence outs as spends to close this entry as well
                    int afterMultiPart = confirmedFinalization.evidenceOutputs.size() ? confirmedFinalization.evidenceOutputs[0] : 0;
                    for (auto oneEvidenceOutN : confirmedFinalization.evidenceOutputs)
                    {
                        if (pEvidenceOutputTx->vout.size() <= oneEvidenceOutN)
                        {
                            LogPrint("notarization", "%s: indexing error for notarization evidence\n", __func__);
                            return false;
                        }

                        if (pEvidenceVec &&
                            oneEvidenceOutN >= afterMultiPart &&
                            associatedIdx != -1)
                        {
                            CNotaryEvidence oneEvidenceObj(*pEvidenceOutputTx, oneEvidenceOutN, afterMultiPart);
                            if (oneEvidenceObj.IsValid())
                            {
                                (*pEvidenceVec)[associatedIdx].push_back(oneEvidenceObj);
                            }
                        }

                        associatedSpends.push_back(
                            CInputDescriptor(pEvidenceOutputTx->vout[oneEvidenceOutN].scriptPubKey,
                                                pEvidenceOutputTx->vout[oneEvidenceOutN].nValue,
                                                CTxIn(pEvidenceOutputTx->GetHash(), oneEvidenceOutN)));
                        evidenceOutputSet.insert(associatedSpends.back().txIn.prevout);
                    }

                    if (pEvidenceVec &&
                        associatedIdx != -1)
                    {
                        // on a confirmed notarization, get input evidence as well, even though it doesn't need to be cleaned up
                        CTransaction priorOutputTx;
                        CNotaryEvidence oneEvidenceObj;
                        std::vector<CNotaryEvidence> evidenceInVec;
                        for (auto oneIn : confirmedFinalization.evidenceInputs)
                        {
                            uint256 hashBlock;
                            if (priorOutputTx.GetHash() != pEvidenceOutputTx->vin[oneIn].prevout.hash &&
                                !myGetTransaction(pEvidenceOutputTx->vin[oneIn].prevout.hash, priorOutputTx, hashBlock))
                            {
                                printf("%s: cannot access transaction for notarization evidence\n", __func__);
                                LogPrint("%s: cannot access transaction for notarization evidence\n", __func__);
                                return false;
                            }

                            COptCCParams inP;
                            if (priorOutputTx.vout[pEvidenceOutputTx->vin[oneIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(inP) &&
                                inP.IsValid() &&
                                inP.evalCode == EVAL_NOTARY_EVIDENCE &&
                                inP.vData.size() &&
                                (oneEvidenceObj = CNotaryEvidence(inP.vData[0])).IsValid() &&
                                oneEvidenceObj.evidence.chainObjects.size())
                            {
                                // there is no spend to store, as it has already been spent, but we
                                // still want to get its evidence

                                // if we are starting a new object, finish the old one
                                if (!oneEvidenceObj.IsMultipartProof() ||
                                    ((CChainObject<CEvidenceData> *)oneEvidenceObj.evidence.chainObjects[0])->object.md.index == 0)
                                {
                                    // if we have a composite evidence object, store it and clear the vector
                                    if (evidenceInVec.size())
                                    {
                                        CNotaryEvidence multiPartEvidence(evidenceInVec);
                                        if (multiPartEvidence.IsValid())
                                        {
                                            (*pEvidenceVec)[associatedIdx].push_back(multiPartEvidence);
                                        }
                                        evidenceInVec.clear();
                                    }
                                }

                                if (!oneEvidenceObj.IsMultipartProof())
                                {
                                    (*pEvidenceVec)[associatedIdx].push_back(oneEvidenceObj);
                                }
                                else
                                {
                                    evidenceInVec.push_back(oneEvidenceObj);
                                }
                            }
                        }

                        // if we have a composite evidence object, store it and clear the vector
                        if (evidenceInVec.size())
                        {
                            CNotaryEvidence multiPartEvidence(evidenceInVec);
                            if (multiPartEvidence.IsValid())
                            {
                                (*pEvidenceVec)[associatedIdx].push_back(multiPartEvidence);
                            }
                            else
                            {
                                printf("%s: invalid multipart evidence on input\n", __func__);
                                LogPrint("%s: invalid multipart evidence on input\n", __func__);
                                return false;
                            }
                        }
                    }
                }

                // unspent evidence is specific to the target notarization
                std::vector<std::pair<uint32_t, CInputDescriptor>> unspentEvidence =
                    CObjectFinalization::GetUnspentEvidence(currencyID, vtx[associatedIdx].first.hash, vtx[associatedIdx].first.n);

                for (auto &oneEvidenceSpend : unspentEvidence)
                {
                    // if not already added to our spends as evidence, add it
                    if (!evidenceOutputSet.count(oneEvidenceSpend.second.txIn.prevout))
                    {
                        COptCCParams tP;
                        CNotaryEvidence oneEvidenceObj;
                        int afterEvidence;
                        if (pEvidenceVec &&
                            oneEvidenceSpend.second.scriptPubKey.IsPayToCryptoCondition(tP) &&
                            tP.IsValid() &&
                            tP.vData.size() &&
                            tP.evalCode == EVAL_NOTARY_EVIDENCE &&
                            (oneEvidenceObj = CNotaryEvidence(tP.vData[0])).IsValid())
                        {
                            (*pEvidenceVec)[associatedIdx].push_back(oneEvidenceObj);
                        }

                        associatedSpends.push_back(oneEvidenceSpend.second);
                    }
                }

                spendsToClose[associatedIdx].insert(spendsToClose[associatedIdx].end(), associatedSpends.begin(), associatedSpends.end());
            }
            else
            {
                extraSpends.insert(extraSpends.end(), associatedSpends.begin(), associatedSpends.end());
            }
        }

        // this output wasn't found associated with any valid confirmed or pending notarization
        if (associatedIdx == -1)
        {
            // for finalizations that have no found association, we warn
            // printf("%s: no associated notarization located for confirmed finalization:\n%s\n", __func__, confirmedNotarizationOutput.ToString().c_str());
            LogPrint("notarization", "%s: no associated notarization located for confirmed finalization:\n%s\n", __func__, confirmedNotarizationOutput.ToString().c_str());
        }
    }
    return true;
}

bool CPBaaSNotarization::CreateAcceptedNotarization(const CCurrencyDefinition &externalSystem,
                                                    const CPBaaSNotarization &earnedNotarization,
                                                    const CNotaryEvidence &notaryEvidence,
                                                    CValidationState &state,
                                                    TransactionBuilder &txBuilder)
{
    std::string errorPrefix(strprintf("%s: ", __func__));
    uint160 SystemID = externalSystem.GetID();

    const CCurrencyDefinition *pNotaryCurrency;
    if (IsVerusActive() || !ConnectedChains.notarySystems.count(SystemID))
    {
        pNotaryCurrency = &externalSystem;
    }
    else
    {
        pNotaryCurrency = &ConnectedChains.ThisChain();
    }

    std::set<uint160> notarySet = pNotaryCurrency->GetNotarySet();
    int minimumNotariesConfirm = pNotaryCurrency->MinimumNotariesConfirm();

    // for an accepted notarization to be finalized, it must be either a chain ID notarization protocol or signed by all notaries
    // in addition, an auto-notarization submission must be mined in and settle for one period without notary rejection before it
    // can be used as proof.
    //
    // after a notarization is mined in, it is not considered actually finalized until one notarization period of blocks where it
    // has remained on the blockchain. at the 10th block, if a majority of the voting notaries are revoked, 

    // now, verify the evidence. accepted notarizations for another system must have at least one
    // valid piece of evidence, which currently means at least one notary signature
    if (externalSystem.notarizationProtocol != externalSystem.NOTARIZATION_NOTARY_CHAINID && notaryEvidence.evidence.Empty())
    {
        return state.Error(errorPrefix + "Requires at least some evidence to accept notarization");
    }

    // create an accepted notarization based on the cross-chain notarization provided
    CPBaaSNotarization newNotarization = earnedNotarization;

    // this should be mirrored for us to continue, if it can't be, it is invalid
    if (earnedNotarization.IsMirror() || !newNotarization.SetMirror())
    {
        return state.Error(errorPrefix + "invalid earned notarization");
    }

    LOCK(cs_main);

    uint32_t height = chainActive.Height();
    CProofRoot ourRoot = newNotarization.proofRoots[ASSETCHAINS_CHAINID];

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> txes;
    if (!GetNotarizationData(SystemID, cnd, &txes))
    {
        return state.Error(errorPrefix + "cannot locate notarization history");
    }

    // any notarization submitted must include a proof root of this chain that is later than the last confirmed
    // notarization
    uint32_t lastHeight;

    if (!cnd.IsConfirmed())
    {
        return state.Error(errorPrefix + "earned notarization proof root cannot be verified without at least one prior confirmed for this chain");
    }

    CPBaaSNotarization lastConfirmedNotarization = cnd.vtx[cnd.lastConfirmed].second;

    lastHeight = lastConfirmedNotarization.IsPreLaunch() ? 
                            lastConfirmedNotarization.notarizationHeight :
                            lastConfirmedNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ?
                                lastConfirmedNotarization.proofRoots.find(ASSETCHAINS_CHAINID)->second.rootHeight :
                                UINT32_MAX;

    if (ourRoot.rootHeight <= lastHeight)
    {
        return state.Error(errorPrefix + "earned notarization proof root cannot be verified as later than prior confirmed for this chain");
    }

    // all notarization protocols in Verus do the heavy lifting on the Verus side
    // as a result, the hash is currently assumed to be the default
    CNativeHashWriter hw;

    std::vector<unsigned char> notarizationVec = ::AsVector(earnedNotarization);
    uint256 objHash = hw.write((const char *)&(notarizationVec[0]), notarizationVec.size()).GetHash();

    CNotaryEvidence::EStates confirmationState = notaryEvidence.CheckSignatureConfirmation(objHash, notarySet, minimumNotariesConfirm, height);
    if (confirmationState != CNotaryEvidence::EStates::STATE_CONFIRMED)
    {
        return state.Error(errorPrefix + "insufficient signature evidence confirming notarization");
    }

    int forkIdx = -1, forkPos = -1;
    int priorNotarizationIdx = -1;

    CPBaaSNotarization thirdNotarization;

    // auto notarization protocol requires
    // full quorum of notaries to sign in order to
    // enter a pending notarization or confirm a prior
    // notarization
    if (externalSystem.notarizationProtocol == externalSystem.NOTARIZATION_AUTO)
    {
        std::set<int> evidenceTypes;
        evidenceTypes.insert(CHAINOBJ_PROOF_ROOT);
        evidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);
        evidenceTypes.insert(CHAINOBJ_HEADER);
        evidenceTypes.insert(CHAINOBJ_HEADER_REF);
        CCrossChainProof autoProof(notaryEvidence.GetSelectEvidence(evidenceTypes));

        // in auto-notarization, the first CPartialTransactionProof should be a proof 
        // of the last notarization output that was confirmed on the other chain, proven by this new notarization

        // the proof must contain:
        // 1) A notarization merge mined or staked that references the last modulo period of blocks on this
        //    chain. If mined, it must have a merge mining entry with prior data matching this chain, and it must
        //    contain a proof of a prior staked notarization that it agrees with. If staked, it must 
        //    contain a proof of a prior merge mined entry that it agrees with. Further, it must have a proof using
        //    the second notarization that further references either the last pending notarization, or the last
        //    confirmed notarization. If it references the last pending then the last pending will be
        //    be confirmed if this notarization is accepted.
        //
        // 2) The new pending notarization signed by all unrevoked notaries.
        //
        // Once verified, the prior pending notarization will be confirmed and all alternate notarizations
        // closed by being spent, and the new pending notarization that closed the last will be placed onto the 
        // chain in a pending state.
        //

        // chain objects that should be present:
        //
        // proof root of the chain as of the most recent notarization
        // being mined in. That should contain a proof root of this chain
        // within the last period of BLOCK_NOTARIZATION_MODULO number
        // of blocks on this chain and be either an arguably legitimate
        // PoW or PoS header on the other chain.
        //
        // that first notarization should point to a second notarization mined or staked
        // in an alternate validation type to the first and a transaction output proof, 
        // proven against the proof root of the first notarization.
        //
        // finally, that second notarization must then refer to and prove with its proof root,
        // a new notarization to enter as pending. the new notarization must include proof
        // of either the last confirmed or one of the last pending notarizations on this chain.
        //
        // each proof includes a power proof of the block before, committing to and enabling 
        // determination of PoW or PoS for the block containing the earned notarization, based on
        // its change in work or stake from the block before. this enables a lighter weight
        // proof with a header commitment vs. requiring headers initially.

        //
        // An accepted notarization must be signed by an unrevoked majority of necessary notaries.
        //
        // Notarization evidence includes an asserted proof root
        //
        // A partial transaction proof of an earned notarization against the initial proof root.
        // A header reference proof of the block before the notarization block to enable determination
        // of validation method.
        //
        // A partial transaction proof of the second prior and agreed earned notarization
        // A header reference proof of the block before the second notarization block to enable determination
        // of validation method, which must be opposite to the validation method in the first block.
        //
        // A partial transaction proof of the third prior and agreed earned notarization, which is proposed
        // as the new pending notarization. In addition, it has a proof for a prior notarization, which
        // must be either the last confirmed on this chain or one of the last pending, which will then
        // become the last confirmedd.
        // 

        CTransaction fNTx;

        if (autoProof.chainObjects.size() < 7)
        {
            // TODO: HARDENING - enable this error and require the evidence
            // return state.Error(errorPrefix + "insufficient cross chain proof for notarization");
            LogPrint("notarization", "%s: insufficient cross chain proof for notarization\n");
            if (cnd.forks.size() != 1)
            {
                return state.Error(errorPrefix + "cannot resolve conflict without sufficient evidence");
            }
            thirdNotarization = cnd.vtx[cnd.forks[0].back()].second;
        }
        else
        {
            for (auto oneObjRef : autoProof.chainObjects)
            {
                if (!oneObjRef)
                {
                    return state.Error(errorPrefix + "null cross chain proof for notarization");
                }
            }

            COptCCParams tmpP;

            CProofRoot firstProofRoot;
            CPartialTransactionProof firstProof;
            if (autoProof.chainObjects[0]->objectType != CHAINOBJ_PROOF_ROOT ||
                !(firstProofRoot = ((CChainObject<CProofRoot> *)autoProof.chainObjects[0])->object).IsValid() ||
                autoProof.chainObjects[1]->objectType != CHAINOBJ_TRANSACTION_PROOF ||
                !(firstProof = ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[1])->object).IsValid() ||
                firstProof.CheckPartialTransaction(fNTx) != firstProofRoot.stateRoot ||
                autoProof.chainObjects[2]->objectType != CHAINOBJ_HEADER_REF)
            {
                return state.Error(errorPrefix + "invalid cross chain proof for notarization");
            }

            CBlockHeaderProof priorHeaderProof = ((CChainObject<CBlockHeaderProof> *)autoProof.chainObjects[2])->object;
            CChainPower thisPower = CChainPower::ExpandCompactPower(firstProof.GetBlockPower());
            CChainPower priorPower = CChainPower::ExpandCompactPower(priorHeaderProof.GetBlockPower());
            bool firstIsStake = (priorPower - thisPower).chainStake > arith_uint256(0);

            // get the proof root to use for the next proof from firstProof notarization output
            int outIdx;
            CPBaaSNotarization firstNotarization(fNTx, &outIdx), secondNotarization;
            CPartialTransactionProof secondProof;

            if (!firstNotarization.IsValid() ||
                !fNTx.vout[outIdx].scriptPubKey.IsPayToCryptoCondition(tmpP) ||
                !tmpP.IsValid() ||
                tmpP.evalCode != EVAL_EARNEDNOTARIZATION ||
                !firstNotarization.proofRoots.count(SystemID) ||
                firstNotarization.proofRoots[SystemID].rootHeight >= firstProofRoot.rootHeight ||
                autoProof.chainObjects[3]->objectType != CHAINOBJ_TRANSACTION_PROOF ||
                !(secondProof = ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[3])->object).IsValid() ||
                secondProof.TransactionHash() != firstNotarization.prevNotarization.hash ||
                secondProof.CheckPartialTransaction(fNTx) != firstNotarization.proofRoots[SystemID].stateRoot ||
                fNTx.vout.size() <= firstNotarization.prevNotarization.n ||
                !fNTx.vout[firstNotarization.prevNotarization.n].scriptPubKey.IsPayToCryptoCondition(tmpP) ||
                !tmpP.IsValid() ||
                tmpP.evalCode != EVAL_EARNEDNOTARIZATION ||
                !tmpP.vData.size() ||
                !(secondNotarization = CPBaaSNotarization(tmpP.vData[0])).IsValid() ||
                !secondNotarization.proofRoots.count(SystemID) ||
                ::AsVector(secondNotarization) != ::AsVector(earnedNotarization) ||
                autoProof.chainObjects[4]->objectType != CHAINOBJ_HEADER_REF)
            {
                return state.Error(errorPrefix + "invalid cross chain proof for notarization - first or second notarization");
            }

            priorHeaderProof = ((CChainObject<CBlockHeaderProof> *)autoProof.chainObjects[4])->object;
            thisPower = CChainPower::ExpandCompactPower(secondProof.GetBlockPower());
            priorPower = CChainPower::ExpandCompactPower(priorHeaderProof.GetBlockPower());
            bool secondIsStake = (priorPower - thisPower).chainStake > arith_uint256(0);

            CPartialTransactionProof thirdProof;

            if (secondNotarization.proofRoots[SystemID].rootHeight >= firstNotarization.proofRoots[SystemID].rootHeight ||
                autoProof.chainObjects[5]->objectType != CHAINOBJ_TRANSACTION_PROOF ||
                !(thirdProof = ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[5])->object).IsValid() ||
                thirdProof.TransactionHash() != secondNotarization.prevNotarization.hash ||
                thirdProof.CheckPartialTransaction(fNTx) != secondNotarization.proofRoots[SystemID].stateRoot ||
                fNTx.vout.size() <= secondNotarization.prevNotarization.n ||
                !fNTx.vout[secondNotarization.prevNotarization.n].scriptPubKey.IsPayToCryptoCondition(tmpP) ||
                !tmpP.IsValid() ||
                !tmpP.vData.size() ||
                !(thirdNotarization = CPBaaSNotarization(tmpP.vData[0])).IsValid() ||
                (tmpP.evalCode != EVAL_EARNEDNOTARIZATION &&
                 !(thirdNotarization.IsDefinitionNotarization() || thirdNotarization.IsBlockOneNotarization())) ||
                (tmpP.evalCode == EVAL_EARNEDNOTARIZATION &&
                 (!(thirdNotarization.proofRoots.count(SystemID) && thirdNotarization.proofRoots.count(ASSETCHAINS_CHAINID)) ||
                  !thirdNotarization.SetMirror())) ||
                autoProof.chainObjects[6]->objectType != CHAINOBJ_HEADER_REF)
            {
                return state.Error(errorPrefix + "invalid cross chain proof for notarization - second notarization");
            }

            priorHeaderProof = ((CChainObject<CBlockHeaderProof> *)autoProof.chainObjects[6])->object;
            thisPower = CChainPower::ExpandCompactPower(thirdProof.GetBlockPower());
            priorPower = CChainPower::ExpandCompactPower(priorHeaderProof.GetBlockPower());
            bool thirdIsStake = (priorPower - thisPower).chainStake > arith_uint256(0);

            if (lastConfirmedNotarization.notarizationHeight > (VERUS_MIN_STAKEAGE << 1) && (firstIsStake == secondIsStake || secondIsStake == thirdIsStake))
            {
                return state.Error(errorPrefix + "invalid validation alternation for one or more notarizations");
            }
        }

        // fNTx & thirdNotarization must match the last confirmed or one pending. if it matches one pending, that one will be confirmed
        auto serializedVec = ::AsVector(thirdNotarization);
        if (serializedVec != ::AsVector(cnd.vtx[cnd.lastConfirmed].second))
        {
            // if the third notarization does not equal the last confirmed notarization, it
            // must equal a last pending notarization to confirm. that should always be a
            // non-confirmed entry in a fork of the notarization data, if it is present
            for (int i = 0; i < cnd.forks.size(); i++)
            {
                if (cnd.forks[i].size() > 1)
                {
                    for (int j = cnd.forks[i].size() - 1; j >= 0; j--)
                    {
                        if (serializedVec == ::AsVector(cnd.vtx[cnd.forks[i][j]].second))
                        {
                            forkIdx = i;
                            forkPos = j;
                            break;
                        }
                    }
                    if (forkIdx > -1)
                    {
                        break;
                    }
                }
            }

            // if it wasn't the confirmed entry and wasn't pending confirmation, it is referring to an
            // invalid predecessor and is therefore invalid
            if (forkIdx == -1)
            {
                return state.Error(errorPrefix + "invalid prior notarization - neither pending nor confirmed");
            }
        }

        // if we should confirm a notarization, it will be the first in forkIdx
        if (forkIdx > -1)
        {
            printf("ready to confirm notarization tx: %s, output %d\n", cnd.vtx[cnd.forks[forkIdx][forkPos]].first.hash.GetHex().c_str(), cnd.vtx[cnd.forks[forkIdx][forkPos]].first.n);
            priorNotarizationIdx = cnd.forks[forkIdx][forkPos];
        }
        else
        {
            priorNotarizationIdx = cnd.lastConfirmed;
        }
        // earned notarization is entered as pending if we get here
    }
    else
    {
        if (cnd.forks.size() != 1)
        {
            LogPrint("notarization", "%s: insufficient cross chain proof for non-auto notarization\n");
            return state.Error(errorPrefix + "cannot resolve conflict without sufficient evidence");
        }
        priorNotarizationIdx = cnd.forks[0].back();
        thirdNotarization = cnd.vtx[priorNotarizationIdx].second;
        thirdNotarization = cnd.vtx[cnd.forks[0].size() > 1 ? cnd.forks[0][1] : cnd.lastConfirmed].second;
    }

    // all proof roots in a prior, agreed notarization must be present and have moved forward
    for (auto &oneProofRoot : thirdNotarization.proofRoots)
    {
        if (!newNotarization.proofRoots.count(oneProofRoot.first) ||
            newNotarization.proofRoots[oneProofRoot.first].rootHeight <= oneProofRoot.second.rootHeight)
        {
            return state.Error(errorPrefix + "insufficient progress in chain " + EncodeDestination(CIdentityID(oneProofRoot.first)) + " to accept notarization");
        }
    }

    auto mmv = chainActive.GetMMV();
    mmv.resize(ourRoot.rootHeight + 1);

    // we only create accepted notarizations for notarizations that are earned for this chain on another system
    // currently, we support ethereum and PBaaS types.
    if (!newNotarization.proofRoots.count(SystemID) ||
        !newNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ||
        !(ourRoot = newNotarization.proofRoots[ASSETCHAINS_CHAINID]).IsValid() ||
        ourRoot.rootHeight > height ||
        ourRoot.blockHash != chainActive[ourRoot.rootHeight]->GetBlockHash() ||
        ourRoot.stateRoot != mmv.GetRoot() ||
        (ourRoot.type != ourRoot.TYPE_PBAAS && ourRoot.type != ourRoot.TYPE_ETHEREUM))
    {
        return state.Error(errorPrefix + "can only create accepted notarization from notarization with valid proof root of this chain");
    }

    // ensure that the data present is valid, as of the height
    CCoinbaseCurrencyState oldCurState = ConnectedChains.GetCurrencyState(ASSETCHAINS_CHAINID, ourRoot.rootHeight);
    if (!oldCurState.IsValid() ||
        ::GetHash(oldCurState) != ::GetHash(earnedNotarization.currencyState))
    {
        return state.Error(errorPrefix + "currency state is invalid in accepted notarization. is:\n" + 
                                            newNotarization.currencyState.ToUniValue().write(1,2) + 
                                            "\nshould be:\n" + 
                                            oldCurState.ToUniValue().write(1,2) + "\n");
    }

    // ensure that all locally provable info is valid as of our root height
    // and determine if the new notarization should be already finalized or not
    for (auto &oneCur : newNotarization.currencyStates)
    {
        if (oneCur.first == SystemID)
        {
            return state.Error(errorPrefix + "cannot accept redundant currency state in notarization for " + EncodeDestination(CIdentityID(SystemID)));
        }
        else if (oneCur.first != ASSETCHAINS_CHAINID)
        {
            // see if this currency is on our chain, and if so, it must be correct as of the proof root of this chain
            CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(oneCur.first);
            // we must have all currencies
            if (!curDef.IsValid())
            {
                return state.Error(errorPrefix + "all currencies in accepted notarizatoin must be registered on this chain");
            }
            // if the currency is not from this chain, we cannot validate it
            if (curDef.systemID != ASSETCHAINS_CHAINID)
            {
                continue;
            }
            // ensure that the data present is valid, as of the height
            oldCurState = ConnectedChains.GetCurrencyState(oneCur.first, ourRoot.rootHeight);
            if (!oldCurState.IsValid() ||
                ::GetHash(oldCurState) != ::GetHash(oneCur.second))
            {
                return state.Error(errorPrefix + "currecy state is invalid in accepted notarization. is:\n" + 
                                                 oneCur.second.ToUniValue().write(1,2) + 
                                                 "\nshould be:\n" + 
                                                 oldCurState.ToUniValue().write(1,2) + "\n");
            }
        }
        else
        {
            // already checked above
            continue;
        }
    }

    for (auto &oneRoot : newNotarization.proofRoots)
    {
        if (oneRoot.first == SystemID)
        {
            continue;
        }
        else
        {
            // see if this currency is on our chain, and if so, it must be correct as of the proof root of this chain
            CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(oneRoot.first);
            // we must have all currencies in this notarization registered
            if (!curDef.IsValid())
            {
                return state.Error(errorPrefix + "all currencies in accepted notarizatoin must be registered on this chain");
            }
            uint160 curDefID = curDef.GetID();

            // only check other currencies on this chain, not the main chain itself
            if (curDefID != ASSETCHAINS_CHAINID && curDef.systemID == ASSETCHAINS_CHAINID)
            {
                return state.Error(errorPrefix + "proof roots are not accepted for token currencies");
            }
        }
    }

    // now create the new notarization, add the proof, finalize if appropriate, and finish

    // add spend of prior notarization and then outputs
    CPBaaSNotarization lastUnspentNotarization;
    uint256 lastTxId;
    int32_t lastTxOutNum;
    CTransaction lastTx;
    if (!lastUnspentNotarization.GetLastUnspentNotarization(SystemID, lastTxId, lastTxOutNum, &lastTx))
    {
        return state.Error(errorPrefix + "invalid prior notarization");
    }

    // add prior unspent accepted notarization as our input
    txBuilder.AddTransparentInput(CUTXORef(lastTxId, lastTxOutNum), lastTx.vout[lastTxOutNum].scriptPubKey, lastTx.vout[lastTxOutNum].nValue);

    // if we are going to confirm a prior notarization, we also should spend its prior
    // pending finalizations and all conflicting as well
    CUTXORef newConfirmedOutput;

    std::map<CUTXORef, int> notarizationOutputMap;

    for (int i = 0; i < cnd.vtx.size(); i++)
    {
        notarizationOutputMap.insert(std::make_pair(cnd.vtx[i].first, i));
    }

    std::vector<std::vector<CInputDescriptor>> spendsToClose(cnd.vtx.size());
    std::vector<CInputDescriptor> extraSpends;

    // now, figure out which elements we spend, whether confirming or invalidating
    std::set<int> confirmedOutputNums;
    std::set<int> invalidatedOutputNums;

    if (forkIdx > -1)
    {
        if (!cnd.CorrelatedFinalizationSpends(txes, spendsToClose, extraSpends))
        {
            return state.Error(errorPrefix + "error correlating spends");
        }

        if (!cnd.CalculateConfirmation(priorNotarizationIdx, confirmedOutputNums, invalidatedOutputNums))
        {
            return state.Error(errorPrefix + "error calculating confirmation");
        }

        // any fork that does not match the confirmed fork up to the same index will be
        // considered invalid from all of its entries to its end
        for (auto oneConfirmedIdx : confirmedOutputNums)
        {
            if (oneConfirmedIdx != priorNotarizationIdx)
            {
                for (auto &oneInput : spendsToClose[oneConfirmedIdx])
                {
                    txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                }
            }
        }

        for (auto oneInvalidatedIdx : invalidatedOutputNums)
        {
            for (auto &oneInput : spendsToClose[oneInvalidatedIdx])
            {
                txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
            }
        }
    }

    CCcontract_info CC;
    CCcontract_info *cp;
    std::vector<CTxDestination> dests;

    // make the accepted notarization output
    cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);

    if (externalSystem.notarizationProtocol == externalSystem.NOTARIZATION_NOTARY_CHAINID)
    {
        dests = std::vector<CTxDestination>({CIdentityID(externalSystem.GetID())});
    }
    else
    {
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
    }

    txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &newNotarization)), 0);

    // now add the notary evidence and finalization that uses it to assert validity
    // make the evidence notarization output
    cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

    CDataStream ds(SER_DISK, PROTOCOL_VERSION);
    int serSize = GetSerializeSize(ds, notaryEvidence);

    std::vector<int32_t> evidenceOuts;

    // the value should be considered for reduction
    if (serSize > CScript::MAX_SCRIPT_ELEMENT_SIZE)
    {
        auto evidenceVec = notaryEvidence.BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - 128);
        if (!evidenceVec.size())
        {
            LogPrintf("%s: failed to package evidence from system %s\n", __func__, EncodeDestination(CIdentityID(SystemID)).c_str());
            return false;
        }
        for (auto &oneProof : evidenceVec)
        {
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            evidenceOuts.push_back(txBuilder.mtx.vout.size());
            txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof)), 0);
        }
    }
    else
    {
        evidenceOuts.push_back(txBuilder.mtx.vout.size());
        txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &notaryEvidence)), 0);
    }

    // now make 1 or two finalization outputs
    cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

    // create the pending finalization for our new notarization first
    CObjectFinalization of = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION, newNotarization.currencyID, uint256(), txBuilder.mtx.vout.size() - (1 + evidenceOuts.size()), height + 1);
    of.evidenceOutputs = evidenceOuts;
    txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of)), 0);

    // if there are outputs to close for this entry, it will first be
    // a finalization, then evidence
    COptCCParams fP;

    for (auto &oneInput : spendsToClose[priorNotarizationIdx])
    {
        txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
    }

    if (spendsToClose[priorNotarizationIdx].size() &&
        spendsToClose[priorNotarizationIdx][0].scriptPubKey.IsPayToCryptoCondition(fP) &&
        fP.IsValid() &&
        fP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
        fP.vData.size() &&
        (of = CObjectFinalization(fP.vData[0])).IsValid())
    {
        if (of.output.hash.IsNull())
        {
            of.output.hash = spendsToClose[priorNotarizationIdx][0].txIn.prevout.hash;
        }
        // inputs will be finalization followed by evidence
        // outputs are cleared to carry it forward, as they are on inputs
        of.evidenceInputs.clear();
        of.evidenceOutputs.clear();
        if (spendsToClose[priorNotarizationIdx].size())
        {
            for (int evidenceNIn = txBuilder.mtx.vin.size() - spendsToClose[priorNotarizationIdx].size();
                 evidenceNIn < txBuilder.mtx.vin.size();
                 evidenceNIn++)
            {
                of.evidenceInputs.push_back(evidenceNIn);
            }
        }
        of.minFinalizationHeight = height;
    }
    else
    {
        // we have no valid finalization to close for this list of spends
        // spend whatever we have and make an output finalization
        of = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION,
                                    newNotarization.currencyID,
                                    cnd.vtx[priorNotarizationIdx].first.hash,
                                    cnd.vtx[priorNotarizationIdx].first.n,
                                    height);
    }
    of.SetConfirmed(); 
    txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of)), 0);

    /* UniValue univTx(UniValue::VOBJ);
    TxToUniv(txBuilder.mtx, uint256(), univTx);
    printf("%s: txBuilder returning:\n%s\n", __func__, univTx.write(1,2).c_str());
    // */

    return true;
}

extern void CopyNodeStats(std::vector<CNodeStats>& vstats);

std::vector<CNodeData> GetGoodNodes(int maxNum)
{
    // good nodes ordered by time connected
    std::map<int64_t, CNode *> goodNodes;
    std::vector<CNodeData> retVal;

    LOCK(cs_vNodes);
    for (auto oneNode : vNodes)
    {
        if (!oneNode->fInbound)
        {
            if (oneNode->fWhitelisted)
            {
                goodNodes.insert(std::make_pair(oneNode->nTimeConnected, oneNode));
            }
            else if (oneNode->GetTotalBytesRecv() > (1024 * 1024))
            {
                goodNodes.insert(std::make_pair(oneNode->nTimeConnected, oneNode));
            }
        }
    }
    if (goodNodes.size() > 1)
    {
        seed_insecure_rand();
        for (auto &oneNode : goodNodes)
        {
            if (insecure_rand() & 1)
            {
                retVal.push_back(CNodeData(oneNode.second->addr.ToStringIPPort(), oneNode.second->hashPaymentAddress));
                if (retVal.size() >= maxNum)
                {
                    break;
                }
            }
        }
        if (!retVal.size())
        {
            retVal.push_back(CNodeData(goodNodes.begin()->second->addr.ToStringIPPort(), goodNodes.begin()->second->hashPaymentAddress));
        }
    }
    else if (goodNodes.size())
    {
        retVal.push_back(CNodeData(goodNodes.begin()->second->addr.ToStringIPPort(), goodNodes.begin()->second->hashPaymentAddress));
    }
    return retVal;
}

// create a notarization that is validated as part of the block, generally benefiting the miner or staker if the
// cross notarization is valid
bool CPBaaSNotarization::CreateEarnedNotarization(const CRPCChainData &externalSystem,
                                                  const CTransferDestination &Proposer,
                                                  bool isStake,
                                                  CValidationState &state,
                                                  std::vector<CTxOut> &txOutputs,
                                                  CPBaaSNotarization &notarization)
{
    std::string errorPrefix(strprintf("%s: ", __func__));

    uint32_t height;
    uint160 SystemID;
    const CCurrencyDefinition &systemDef = externalSystem.chainDefinition;
    SystemID = externalSystem.chainDefinition.GetID();

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> txes;

    {
        LOCK2(cs_main, mempool.cs);
        height = chainActive.Height();

        // we can only create an earned notarization for a notary chain, so there must be a notary chain and a network connection to it
        // we also need to ensure that our notarization would be the first notarization in this notary block period  with which we agree.
        if (!externalSystem.IsValid() || externalSystem.rpcHost.empty())
        {
            // technically not a real error
            return state.Error("no-notary");
        }

        if (!GetNotarizationData(SystemID, cnd, &txes) || !cnd.IsConfirmed())
        {
            return state.Error(errorPrefix + "no prior confirmed notarization found");
        }
    }

    bool isGatewayFirstContact = systemDef.IsGateway() && cnd.vtx[cnd.lastConfirmed].second.IsDefinitionNotarization();

    // all we really want is the system proof roots for each notarization to make the JSON for the API smaller
    UniValue proofRootsUni(UniValue::VARR);
    for (auto &oneNot : cnd.vtx)
    {
        auto rootIt = oneNot.second.proofRoots.find(SystemID);
        if (rootIt != oneNot.second.proofRoots.end())
        {
            proofRootsUni.push_back(rootIt->second.ToUniValue());
        }
        else
        {
            auto oneProofRoot = CProofRoot();
            oneProofRoot.rootHeight = 1;
            proofRootsUni.push_back(oneProofRoot.ToUniValue());
        }
    }

    if (!proofRootsUni.size() && !isGatewayFirstContact)
    {
        return state.Error(errorPrefix + "no valid prior state root found");
    }

    // call notary to determine the prior notarization that we agree with
    UniValue params(UniValue::VARR);

    UniValue oneParam(UniValue::VOBJ);
    if (proofRootsUni.size())
    {
        oneParam.push_back(Pair("proofroots", proofRootsUni));
    }
    if (!isGatewayFirstContact)
    {
        oneParam.push_back(Pair("lastconfirmed", cnd.lastConfirmed));
    }
    params.push_back(oneParam);

    //printf("%s: about to get cross notarization with %lu notarizations found\n", __func__, cnd.vtx.size());

    UniValue result;
    try
    {
        result = find_value(RPCCallRoot("getbestproofroot", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }

    int32_t notaryIdx = uni_get_int(find_value(result, "bestindex"), isGatewayFirstContact ? 0 : -1);

    UniValue lastConfirmedUni = find_value(result, "lastconfirmedproofroot");
    CProofRoot lastConfirmedProofRoot;
    if (!lastConfirmedUni.isNull())
    {
        lastConfirmedProofRoot = CProofRoot(lastConfirmedUni);
    }

    if (result.isNull() || notaryIdx == -1)
    {
        return state.Error(result.isNull() ? "no-notary" : "no-matching-proof-roots-found");
    }

    CProofRoot lastStableProofRoot(find_value(result, "laststableproofroot"));

    // work around race condition or Infura API issue under investigation in ETH bridge, where it does not confirm
    // one of our proof roots, while at the same time returning identical data in laststableproofroot.
    if (!lastConfirmedProofRoot.IsValid() && lastStableProofRoot.IsValid())
    {
        for (int i = cnd.vtx.size() - 1; i >= 0; i--)
        {
            auto it = cnd.vtx[i].second.proofRoots.find(SystemID);
            if (it != cnd.vtx[i].second.proofRoots.end())
            {
                if (it->second.rootHeight < lastStableProofRoot.rootHeight)
                {
                    break;
                }
                else if (it->second.rootHeight == lastStableProofRoot.rootHeight &&
                         it->second == lastStableProofRoot && notaryIdx != i)
                {
                    LogPrintf("%s: notarization was rejected with identical proof root to last stable: %s\n", __func__, cnd.vtx[i].second.ToUniValue().write(1,2).c_str());
                    notaryIdx = i;
                }
            }
        }
    }

    // now, we have the index for the transaction and notarization we agree with, a list of those we consider invalid,
    // and the most recent notarization to use when creating the new one
    const CTransaction &priorNotarizationTx = txes[notaryIdx].first;
    uint256 priorBlkHash = txes[notaryIdx].second;
    const CUTXORef &priorUTXO = cnd.vtx[notaryIdx].first;
    const CPBaaSNotarization &priorNotarization = cnd.vtx[notaryIdx].second;

    // find out the block height holding the last notarization we agree with
    auto mapBlockIt = mapBlockIndex.find(priorBlkHash);
    if (mapBlockIt == mapBlockIndex.end() || !chainActive.Contains(mapBlockIt->second))
    {
        return state.Error(errorPrefix + "prior notarization not in blockchain");
    }

    // first determine if the prior notarization we agree with would make this one moot
    int blockPeriodNumber = (height + 1) / BLOCK_NOTARIZATION_MODULO;
    int priorBlockPeriod = mapBlockIt->second->GetHeight() / BLOCK_NOTARIZATION_MODULO;

    // for decentralized notarization, we must alternate between proof of stake and proof of work blocks
    // to confirm a prior earned notarization
    if (blockPeriodNumber <= priorBlockPeriod ||
        (height > (VERUS_MIN_STAKEAGE << 1) &&
         (ConnectedChains.ThisChain().notarizationProtocol == CCurrencyDefinition::NOTARIZATION_AUTO &&
         ((isStake && mapBlockIt->second->IsVerusPOSBlock()) || (!isStake && !mapBlockIt->second->IsVerusPOSBlock())))))
    {
        if (LogAcceptCategory("notarization"))
        {
            LogPrintf("%s: block period #%d, prior block period #%d, height: %u, notarization protocol: %d, isPoS: %s, is last notarization PoS: %s\n",
                    __func__,
                    blockPeriodNumber,
                    priorBlockPeriod,
                    height,
                    ConnectedChains.ThisChain().notarizationProtocol,
                    isStake ? "true" : "false",
                    mapBlockIt->second->IsVerusPOSBlock() ? "true" : "false");
            if (LogAcceptCategory("verbose"))
            {
                printf("%s: block period #%d, prior block period #%d, height: %u, notarization protocol: %d, isPoS: %s, is last notarization PoS: %s\n",
                        __func__,
                        blockPeriodNumber,
                        priorBlockPeriod,
                        height,
                        ConnectedChains.ThisChain().notarizationProtocol,
                        isStake ? "true" : "false",
                        mapBlockIt->second->IsVerusPOSBlock() ? "true" : "false");
            }
        }
        return state.Error("ineligible");
    }

    notarization = priorNotarization;
    notarization.SetBlockOneNotarization(false);
    notarization.SetDefinitionNotarization(false);
    notarization.SetSameChain(false);
    notarization.SetPreLaunch(false);
    notarization.SetLaunchCleared(true);
    notarization.SetLaunchConfirmed(true);
    notarization.proposer = Proposer;
    notarization.prevHeight = priorNotarization.notarizationHeight;

    // get the latest notarization information for the new, earned notarization
    // one system may provide one proof root and multiple currency states
    CProofRoot latestProofRoot = lastConfirmedProofRoot.IsValid() ? lastConfirmedProofRoot : CProofRoot(find_value(result, "laststableproofroot"));

    if (!latestProofRoot.IsValid() || notarization.proofRoots[latestProofRoot.systemID].rootHeight >= latestProofRoot.rootHeight)
    {
        return state.Error("no-new-stable-proof-root");
    }

    notarization.proofRoots[latestProofRoot.systemID] = latestProofRoot;
    notarization.notarizationHeight = latestProofRoot.rootHeight;

    UniValue currencyStatesUni = find_value(result, "currencystates");

    if (!systemDef.IsGateway() && !(currencyStatesUni.isArray() && currencyStatesUni.size()))
    {
        return state.Error(errorPrefix + "invalid or missing currency state data from notary");
    }

    params = UniValue(UniValue::VARR);
    params.push_back(EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
    try
    {
        result = find_value(RPCCallRoot("getnotarizationdata", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }
    CChainNotarizationData crosschainCND;
    if (result.isNull() ||
        !(crosschainCND = CChainNotarizationData(result)).IsValid() ||
        (!externalSystem.chainDefinition.IsGateway() && !crosschainCND.IsConfirmed()))
    {
        LogPrint("notarization", "Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(externalSystem.GetID())).c_str());
        return state.Error("invalid crosschain notarization data");
    }

    // take the lock again, now that we're back from calling out
    LOCK2(cs_main, mempool.cs);

    // if height changed, we need to fail and possibly try again
    if (height != chainActive.Height())
    {
        return state.Error("stale-block");
    }

    if (crosschainCND.vtx.size())
    {
        int prevNotarizationIdx;
        CPBaaSNotarization lastPBN;
        for (prevNotarizationIdx = crosschainCND.vtx.size() - 1; prevNotarizationIdx >= 0; prevNotarizationIdx--)
        {
            lastPBN = crosschainCND.vtx[prevNotarizationIdx].second;

            // TODO: HARDENING check all currency states on this chain in last valid as well
            std::map<uint160, CProofRoot>::iterator pIT = lastPBN.proofRoots.find(ASSETCHAINS_CHAINID);
            if (pIT != lastPBN.proofRoots.end() &&
                (!priorNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ||
                 pIT->second.rootHeight <= priorNotarization.proofRoots.find(ASSETCHAINS_CHAINID)->second.rootHeight) &&
                CProofRoot::GetProofRoot(pIT->second.rootHeight) == pIT->second)
            {
                break;
            }
            else if (pIT == crosschainCND.vtx[prevNotarizationIdx].second.proofRoots.end() &&
                     !prevNotarizationIdx &&
                     (crosschainCND.vtx[prevNotarizationIdx].second.IsDefinitionNotarization() || crosschainCND.vtx[prevNotarizationIdx].second.IsLaunchCleared()))
            {
                // use the 0th element if no proof root and it is definition or start, since it has no proof root to be wrong
                break;
            }
        }
        if (prevNotarizationIdx >= 0 &&
            lastPBN.SetMirror(false) &&
            !lastPBN.IsMirror())
        {
            if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
            {
                std::vector<unsigned char> checkHex = ::AsVector(lastPBN);
                LogPrintf("%s: hex of notarization: %s\nnotarization: %s\n", __func__, HexBytes(&(checkHex[0]), checkHex.size()).c_str(), lastPBN.ToUniValue().write(1,2).c_str());
                printf("%s: notarization: %s\n", __func__, lastPBN.ToUniValue().write(1,2).c_str());
            }

            CNativeHashWriter hw;
            hw << lastPBN;
            notarization.hashPrevCrossNotarization = hw.GetHash();
        }
        else
        {
            notarization.hashPrevCrossNotarization.SetNull();
        }
    }

    notarization.currencyStates.clear();
    for (int i = 0; i < currencyStatesUni.size(); i++)
    {
        CCoinbaseCurrencyState oneCurState(currencyStatesUni[i]);
        CCurrencyDefinition oneCurDef;
        if (!oneCurState.IsValid())
        {
            return state.Error(errorPrefix + "invalid or missing currency state data from notary");
        }
        if (!(oneCurDef = ConnectedChains.GetCachedCurrency(oneCurState.GetID())).IsValid())
        {
            // if we don't have the currency for the state specified, and it isn't critical, ignore
            if (oneCurDef.GetID() == SystemID)
            {
                return state.Error(errorPrefix + "system currency invalid - possible corruption");
            }
            continue;
        }
        if (oneCurDef.systemID == SystemID)
        {
            uint160 oneCurDefID = oneCurDef.GetID();
            if (notarization.currencyID == oneCurDefID)
            {
                notarization.currencyState = oneCurState;
            }
            else
            {
                notarization.currencyStates[oneCurDefID] = oneCurState;
            }
        }
    }
    notarization.currencyStates[ASSETCHAINS_CHAINID] = ConnectedChains.GetCurrencyState(height);
    if (!systemDef.GatewayConverterID().IsNull())
    {
        notarization.currencyStates[systemDef.GatewayConverterID()] = ConnectedChains.GetCurrencyState(systemDef.GatewayConverterID(), height);
    }

    // add this blockchain's info, based on the requested height
    uint160 thisChainID = ConnectedChains.ThisChain().GetID();
    notarization.proofRoots[thisChainID] = CProofRoot::GetProofRoot(height);

    // add currency states that we should include and then we're done
    // currency states to include are either a gateway currency indicated by the
    // gateway or our gateway converter for our PBaaS chain
    uint160 gatewayConverterID = systemDef.GatewayConverterID();
    if (systemDef.IsGateway() && (!systemDef.GatewayConverterID().IsNull()))
    {
        gatewayConverterID = systemDef.GatewayConverterID();
    }
    else if (SystemID == ConnectedChains.FirstNotaryChain().chainDefinition.GetID() && !ConnectedChains.ThisChain().GatewayConverterID().IsNull())
    {
        gatewayConverterID = ConnectedChains.ThisChain().GatewayConverterID();
    }
    if (!gatewayConverterID.IsNull())
    {
        // get the gateway converter currency from the gateway definition
        CChainNotarizationData gatewayCND;
        if (GetNotarizationData(gatewayConverterID, gatewayCND) && gatewayCND.vtx.size())
        {
            notarization.currencyStates[gatewayConverterID] = gatewayCND.vtx[gatewayCND.lastConfirmed].second.currencyState;
        }
    }

    notarization.nodes = GetGoodNodes(CPBaaSNotarization::MAX_NODES);

    notarization.prevNotarization = cnd.vtx[notaryIdx].first;
    notarization.prevHeight = cnd.vtx[notaryIdx].second.notarizationHeight;

    CCcontract_info CC;
    CCcontract_info *cp;
    std::vector<CTxDestination> dests;

    // make the earned notarization output
    cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);

    if (systemDef.notarizationProtocol == systemDef.NOTARIZATION_NOTARY_CHAINID)
    {
        dests = std::vector<CTxDestination>({CIdentityID(systemDef.GetID())});
    }
    else
    {
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
    }

    txOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &notarization))));

    if (systemDef.notarizationProtocol != systemDef.NOTARIZATION_NOTARY_CHAINID)
    {
        // make the finalization output
        cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);

        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

        // we need to store the input that we confirmed if we spent finalization outputs
        CObjectFinalization of = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION, notarization.currencyID, uint256(), txOutputs.size() - 1, height + 15);
        txOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of))));
    }
    return true;
}

std::vector<std::pair<uint32_t, CInputDescriptor>> CObjectFinalization::GetUnspentConfirmedFinalizations(const uint160 &currencyID)
{
    LOCK(mempool.cs);
    std::vector<std::pair<uint32_t, CInputDescriptor>> retVal;
    std::vector<CAddressUnspentDbEntry> indexUnspent;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolUnspent;
    
    uint160 indexKey = CCrossChainRPCData::GetConditionID(
        CCrossChainRPCData::GetConditionID(currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey()), 
        ObjectFinalizationConfirmedKey());
    if ((GetAddressUnspent(indexKey, CScript::P2IDX, indexUnspent) &&
         mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{indexKey, CScript::P2IDX}}), mempoolUnspent)) &&
        (indexUnspent.size() || mempoolUnspent.size()))
    {
        /* printf("%s: confirmedNotarizationKey: %s / 0x%s\nconfirmed finalizations\n",
            __func__, 
            EncodeDestination(CIdentityID(indexKey)).c_str(),
            indexKey.GetHex().c_str()); */
        std::vector<int> toRemove;
        std::map<COutPoint, int> outputMap;
        for (int i = 0; i < mempoolUnspent.size(); i++)
        {
            if (mempoolUnspent[i].first.spending)
            {
                auto it = outputMap.find(COutPoint(mempoolUnspent[i].second.prevhash, mempoolUnspent[i].second.prevout));
                if (it != outputMap.end())
                {
                    it->second < i ? toRemove.push_back(it->second) : toRemove.push_back(i);
                    it->second < i ? toRemove.push_back(i) : toRemove.push_back(it->second);
                }
                else
                {
                    toRemove.push_back(i);
                }
            }
            else
            {
                outputMap.insert(std::make_pair(COutPoint(mempoolUnspent[i].first.txhash, mempoolUnspent[i].first.index), i));
            }
        }
        for (auto it = toRemove.rbegin(); it != toRemove.rend(); it++)
        {
            mempoolUnspent.erase(mempoolUnspent.begin() + *it);
        }

        for (auto &oneConfirmed : indexUnspent)
        {
            //printf("%s: txid: %s, vout: %lu, blockheight: %d\n", __func__, oneConfirmed.first.txhash.GetHex().c_str(), oneConfirmed.first.index, oneConfirmed.second.blockHeight);
            retVal.push_back(std::make_pair(oneConfirmed.second.blockHeight,
                             CInputDescriptor(oneConfirmed.second.script, oneConfirmed.second.satoshis, CTxIn(oneConfirmed.first.txhash, oneConfirmed.first.index))));
        }
        std::set<std::pair<uint256,int>> mempoolSpent;
        for (auto &oneConfirmed : mempoolUnspent)
        {
            if (oneConfirmed.first.spending)
            {
                if (retVal.size() &&
                    retVal.back().second.txIn.prevout == COutPoint(oneConfirmed.first.txhash, oneConfirmed.first.index))
                {
                    // remove it if spent
                    //printf("%s: REMOVING txid: %s, vout: %u\n", __func__, oneConfirmed.first.txhash.GetHex().c_str(), oneConfirmed.first.index);
                    retVal.pop_back();
                }
                mempoolSpent.insert(std::make_pair(oneConfirmed.first.txhash, oneConfirmed.first.index));
            }
        }
        for (auto &oneConfirmed : mempoolUnspent)
        {
            if (mempoolSpent.count(std::make_pair(oneConfirmed.first.txhash, oneConfirmed.first.index)))
            {
                continue;
            }

            auto txProxy = mempool.mapTx.find(oneConfirmed.first.txhash);
            if (txProxy != mempool.mapTx.end())
            {
                auto &mpEntry = *txProxy;
                auto &tx = mpEntry.GetTx();
                //printf("%s: txid: %s, vout: %u\n", __func__, oneConfirmed.first.txhash.GetHex().c_str(), oneConfirmed.first.index);
                retVal.push_back(std::make_pair(0,
                                 CInputDescriptor(tx.vout[oneConfirmed.first.index].scriptPubKey,
                                                  tx.vout[oneConfirmed.first.index].nValue, 
                                                  CTxIn(oneConfirmed.first.txhash, oneConfirmed.first.index))));
            }
        }
    }
    return retVal;
}

std::vector<std::pair<uint32_t, CInputDescriptor>> CObjectFinalization::GetUnspentPendingFinalizations(const uint160 &currencyID)
{
    LOCK(mempool.cs);
    std::vector<std::pair<uint32_t, CInputDescriptor>> retVal;
    std::vector<CAddressUnspentDbEntry> indexUnspent;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolUnspent;

    uint160 indexKey = CCrossChainRPCData::GetConditionID(
        CCrossChainRPCData::GetConditionID(currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey()), 
        ObjectFinalizationPendingKey());
    if ((GetAddressUnspent(indexKey, CScript::P2IDX, indexUnspent) &&
         mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{indexKey, CScript::P2IDX}}), mempoolUnspent)) &&
        (indexUnspent.size() || mempoolUnspent.size()))
    {
        /* printf("%s: pendingNotarizationKey: %s / 0x%s\npending finalizations\n",
            __func__, 
            EncodeDestination(CIdentityID(indexKey)).c_str(),
            indexKey.GetHex().c_str()); */

        std::vector<int> toRemove;
        std::map<COutPoint, int> outputMap;
        for (int i = 0; i < mempoolUnspent.size(); i++)
        {
            if (mempoolUnspent[i].first.spending)
            {
                auto it = outputMap.find(COutPoint(mempoolUnspent[i].second.prevhash, mempoolUnspent[i].second.prevout));
                if (it != outputMap.end())
                {
                    it->second < i ? toRemove.push_back(it->second) : toRemove.push_back(i);
                    it->second < i ? toRemove.push_back(i) : toRemove.push_back(it->second);
                }
                else
                {
                    toRemove.push_back(i);
                }
            }
            else
            {
                outputMap.insert(std::make_pair(COutPoint(mempoolUnspent[i].first.txhash, mempoolUnspent[i].first.index), i));
            }
        }
        for (auto it = toRemove.rbegin(); it != toRemove.rend(); it++)
        {
            mempoolUnspent.erase(mempoolUnspent.begin() + *it);
        }

        for (auto &oneConfirmed : indexUnspent)
        {
            //printf("%s: txid: %s, vout: %lu, blockheight: %d\n", __func__, oneConfirmed.first.txhash.GetHex().c_str(), oneConfirmed.first.index, oneConfirmed.second.blockHeight);
            retVal.push_back(std::make_pair(oneConfirmed.second.blockHeight,
                             CInputDescriptor(oneConfirmed.second.script, oneConfirmed.second.satoshis, CTxIn(oneConfirmed.first.txhash, oneConfirmed.first.index))));
        }
        std::set<std::pair<uint256,int>> mempoolSpent;
        for (auto &oneUnconfirmed : mempoolUnspent)
        {
            if (oneUnconfirmed.first.spending)
            {
                if (retVal.size() &&
                    retVal.back().second.txIn.prevout == COutPoint(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index))
                {
                    // remove it if spent
                    //printf("%s: REMOVING txid: %s, vout: %u\n", __func__, oneUnconfirmed.first.txhash.GetHex().c_str(), oneUnconfirmed.first.index);
                    retVal.pop_back();
                }
                mempoolSpent.insert(std::make_pair(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index));
            }
        }
        for (auto &oneUnconfirmed : mempoolUnspent)
        {
            if (mempoolSpent.count(std::make_pair(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index)))
            {
                continue;
            }

            auto txProxy = mempool.mapTx.find(oneUnconfirmed.first.txhash);
            if (txProxy != mempool.mapTx.end())
            {
                auto &mpEntry = *txProxy;
                auto &tx = mpEntry.GetTx();
                retVal.push_back(std::make_pair(0,
                                 CInputDescriptor(tx.vout[oneUnconfirmed.first.index].scriptPubKey,
                                                  tx.vout[oneUnconfirmed.first.index].nValue, 
                                                  CTxIn(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index))));
            }
        }
    }
    return retVal;
}

std::vector<std::pair<uint32_t, CInputDescriptor>> CObjectFinalization::GetUnspentEvidence(const uint160 &currencyID,
                                                                                           const uint256 &notarizationTxId,
                                                                                           int32_t notarizationOutNum)
{
    LOCK(mempool.cs);
    std::vector<std::pair<uint32_t, CInputDescriptor>> retVal;
    std::vector<CAddressUnspentDbEntry> indexUnspent;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolUnspent;
    uint160 indexKey = CCrossChainRPCData::GetConditionID(CNotaryEvidence::NotarySignatureKey(), notarizationTxId, notarizationOutNum);

    if ((GetAddressUnspent(indexKey, CScript::P2IDX, indexUnspent) &&
         mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{indexKey, CScript::P2IDX}}), mempoolUnspent)) &&
        (indexUnspent.size() || mempoolUnspent.size()))
    {
        /* printf("%s: unspentEvidenceKey: %s / 0x%s\nunspent evidence\n",
            __func__, 
            EncodeDestination(CIdentityID(indexKey)).c_str(),
            indexKey.GetHex().c_str()); */

        std::vector<int> toRemove;
        std::map<COutPoint, int> outputMap;
        for (int i = 0; i < mempoolUnspent.size(); i++)
        {
            if (mempoolUnspent[i].first.spending)
            {
                auto it = outputMap.find(COutPoint(mempoolUnspent[i].second.prevhash, mempoolUnspent[i].second.prevout));
                if (it != outputMap.end())
                {
                    it->second < i ? toRemove.push_back(it->second) : toRemove.push_back(i);
                    it->second < i ? toRemove.push_back(i) : toRemove.push_back(it->second);
                }
                else
                {
                    toRemove.push_back(i);
                }
            }
            else
            {
                outputMap.insert(std::make_pair(COutPoint(mempoolUnspent[i].first.txhash, mempoolUnspent[i].first.index), i));
            }
        }
        for (auto it = toRemove.rbegin(); it != toRemove.rend(); it++)
        {
            mempoolUnspent.erase(mempoolUnspent.begin() + *it);
        }

        for (auto &oneConfirmed : indexUnspent)
        {
            //printf("%s: txid: %s, vout: %lu, blockheight: %d\n", __func__, oneConfirmed.first.txhash.GetHex().c_str(), oneConfirmed.first.index, oneConfirmed.second.blockHeight);
            retVal.push_back(std::make_pair(oneConfirmed.second.blockHeight,
                             CInputDescriptor(oneConfirmed.second.script, oneConfirmed.second.satoshis, CTxIn(oneConfirmed.first.txhash, oneConfirmed.first.index))));
        }
        std::set<std::pair<uint256,int>> mempoolSpent;
        for (auto &oneUnconfirmed : mempoolUnspent)
        {
            if (oneUnconfirmed.first.spending)
            {
                if (retVal.size() &&
                    retVal.back().second.txIn.prevout == COutPoint(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index))
                {
                    // remove it if spent
                    //printf("%s: REMOVING txid: %s, vout: %u\n", __func__, oneUnconfirmed.first.txhash.GetHex().c_str(), oneUnconfirmed.first.index);
                    retVal.pop_back();
                }
                mempoolSpent.insert(std::make_pair(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index));
            }
        }
        for (auto &oneUnconfirmed : mempoolUnspent)
        {
            if (mempoolSpent.count(std::make_pair(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index)))
            {
                continue;
            }

            auto txProxy = mempool.mapTx.find(oneUnconfirmed.first.txhash);
            if (txProxy != mempool.mapTx.end())
            {
                auto &mpEntry = *txProxy;
                auto &tx = mpEntry.GetTx();
                retVal.push_back(std::make_pair(0,
                                 CInputDescriptor(tx.vout[oneUnconfirmed.first.index].scriptPubKey,
                                                  tx.vout[oneUnconfirmed.first.index].nValue, 
                                                  CTxIn(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index))));
            }
        }
    }
    return retVal;
}

int CChainNotarizationData::BestConfirmedNotarization(int minConfirms)
{
    if (!IsConfirmed() || !vtx.size())
    {
        return -1;
    }

    uint160 currencyID = vtx[0].second.currencyID;

    std::vector<int> bestFork;
    if (forks.size() > 1)
    {
        // need to get most recent forks. if we have
        // no conflict for the past 3 earned notarizations,
        // we are good to confirm, otherwise after 10 blocks, the one
        // that ends up > 2 longer can be notarized/finalized.
        std::multimap<int, std::pair<int, int>> forkAndIndexByBlock;
        for (int i = 0; i < forks.size(); i++)
        {
            auto &oneFork = forks[i];
            for (auto &oneRoot : oneFork)
            {
                if (vtx[oneRoot].second.proofRoots.count(currencyID))
                {
                    forkAndIndexByBlock.insert(std::make_pair(vtx[oneRoot].second.proofRoots[currencyID].rootHeight, std::make_pair(i, oneRoot)));
                }
            }
        }

        int forkNum = -1;
        int elemCount = 0;
        for (auto firstIt = forkAndIndexByBlock.rbegin(); firstIt != forkAndIndexByBlock.rend(); firstIt++)
        {
            if (forkNum == -1 || forkNum == firstIt->second.first)
            {
                elemCount++;
                forkNum = firstIt->second.first;
            }
            else
            {
                break;
            }
        }
        if (elemCount >= minConfirms)
        {
            bestFork = forks[forkNum];
        }
    }
    else if (forks.size() &&
             (forks[0].size() > std::max(minConfirms, 1) || ConnectedChains.ThisChain().notarizationProtocol != CCurrencyDefinition::NOTARIZATION_AUTO))
    {
        bestFork = forks[0];
    }

    if (bestFork.size() < minConfirms || !vtx[lastConfirmed].second.proofRoots.count(currencyID))
    {
        LogPrint("notarization", "insufficient validator confirmations\n");
        return -1;
    }

    // all we really want is the system proof roots for each notarization to make the JSON for the API smaller
    UniValue proofRootsUni(UniValue::VARR);

    proofRootsUni.push_back(vtx[lastConfirmed].second.proofRoots[currencyID].ToUniValue());

    for (auto forkIdxIt = bestFork.begin(); forkIdxIt != bestFork.end(); forkIdxIt++)
    {
        // don't enter the confirmed notarization twice
        if (*forkIdxIt != lastConfirmed)
        {
            auto &oneNot = vtx[*forkIdxIt];
            auto rootIt = oneNot.second.proofRoots.find(currencyID);
            if (rootIt != oneNot.second.proofRoots.end())
            {
                proofRootsUni.push_back(rootIt->second.ToUniValue());
            }
            else
            {
                proofRootsUni.push_back(CProofRoot().ToUniValue());
            }
        }
    }

    if (!proofRootsUni.size())
    {
        LogPrint("notarization", "no valid prior state root found\n");
        return -1;
    }

    UniValue firstParam(UniValue::VOBJ);
    firstParam.push_back(Pair("proofroots", proofRootsUni));
    firstParam.push_back(Pair("lastconfirmed", 0));

    // call notary to determine the notarization that we should notarize
    UniValue params(UniValue::VARR);
    params.push_back(firstParam);

    //printf("%s: about to getbestproofroot with:\n%s\n", __func__, params.write(1,2).c_str());

    UniValue result;
    try
    {
        result = find_value(RPCCallRoot("getbestproofroot", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }

    CProofRoot lastConfirmedRoot(find_value(result, "lastconfirmedproofroot"));
    int32_t notaryIdx = lastConfirmedRoot.IsValid() ? uni_get_int(find_value(result, "lastconfirmedindex"), -1) :
                                                      uni_get_int(find_value(result, "bestindex"), -1);

    if (result.isNull() || notaryIdx == -1)
    {
        LogPrint("notarization", "no-matching-notarization-found\n");
        return -1;
    }

    // now, assuming that our notarization of the other chain is confirmed, sign the latest valid one on this chain
    UniValue proofRootArr = find_value(result, "validindexes");

    if (!proofRootArr.isArray() || !proofRootArr.size())
    {
        LogPrint("notarization", "no valid notarizations found\n");
        return -1;
    }
    return bestFork[notaryIdx];
}

// this is called by notaries to locate any notarizations of a specific system that they can notarize, to determine if we
// agree with the notarization in question, and to confirm or reject the notarization
bool CPBaaSNotarization::ConfirmOrRejectNotarizations(CWallet *pWallet,
                                                      const CRPCChainData &externalSystem,
                                                      CValidationState &state,
                                                      std::vector<TransactionBuilder> &txBuilders,
                                                      uint32_t nHeight,
                                                      bool &finalized)
{
    auto txBuilder = TransactionBuilder(Params().GetConsensus(), nHeight, pWallet);

    std::string errorPrefix(strprintf("%s: ", __func__));

    finalized = false;

    CCurrencyDefinition::EProofProtocol hashType = (CCurrencyDefinition::EProofProtocol)externalSystem.chainDefinition.proofProtocol;

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> txes;

    uint32_t height, signingHeight;
    uint160 SystemID = externalSystem.chainDefinition.GetID();

    const CCurrencyDefinition *pNotaryCurrency;
    if (IsVerusActive() || !ConnectedChains.notarySystems.count(SystemID))
    {
        pNotaryCurrency = &externalSystem.chainDefinition;
    }
    else
    {
        pNotaryCurrency = &ConnectedChains.ThisChain();
    }

    std::set<uint160> notarySet = pNotaryCurrency->GetNotarySet();
    int minimumNotariesConfirm = pNotaryCurrency->MinimumNotariesConfirm();

    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> mine;
    {
        std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> imsigner, watchonly;
        LOCK(pWallet->cs_wallet);
        pWallet->GetIdentities(pNotaryCurrency->notaries, mine, imsigner, watchonly);
    }

    {
        LOCK2(cs_main, mempool.cs);
        signingHeight = height = chainActive.Height();

        // we can only create an earned notarization for a notary chain, so there must be a notary chain and a network connection to it
        // we also need to ensure that our notarization would be the first notarization in this notary block period  with which we agree.
        if (!externalSystem.IsValid() || externalSystem.rpcHost.empty())
        {
            // technically not a real error
            return state.Error("no-notary");
        }

        if (!GetNotarizationData(SystemID, cnd, &txes))
        {
            return state.Error(errorPrefix + "no prior notarization found");
        }
    }

    if (cnd.IsConfirmed() && cnd.vtx.size() == 1)
    {
        return state.Error("no-unconfirmed");
    }

    if (height <= ((CPBaaSNotarization::MIN_BLOCKS_BEFORE_NOTARY_FINALIZED << 1) + 1))
    {
        return state.Error(errorPrefix + "too early");
    }
    // TODO: HARDENING - make sure we can spend all outputs we need to, even if there gets to be too many for 1 tx
    // rules to confirm or reject an earned notarization
    // 1) Notaries may confirm an earned notarization if and only if the following is true:
    //   a) There is no previous, valid notarization in the same eligible period with which the notarization agrees and should confirm
    //   b) If auto-notarization and in a staked block, the last entry to confirm was an earned notarization from a mining block
    //   c) If auto-notarization and making a mined block, the last entry to confirm must be an earned notarization from a staked block
    //   d) The miner or staker has entered accurate information about the other system, which must be confirmed by the notary
    //
    // 2) Each earned notarization in a staked block contains a proof of the stake transaction in the header.
    // 
    // 3) Each includes a proof of the prior notarization with which it agrees and either a PoW or PoS proof of its own.
    //
    // 4) Once a notarization gets 3 uncontested and agreed notarizations in a row, notaries of an auto-notarized chain
    //    may sign and confirm, also including the proof of each of the confirmation outputs.
    //
    // if we are auto-notarizing, the following conditions must be true to qualify for us to confirm a notarization:
    // 1) the notarization must be agreed to by 2 or greater valid earned notarizations since the next longest fork.
    //
    std::vector<int> bestFork;
    if (cnd.forks.size() > 1)
    {
        // need to get most recent forks. if we have
        // no conflict for the past 3 earned notarizations,
        // we are good to confirm, otherwise after 10 blocks, the one
        // that ends up > 2 longer can be notarized/finalized.
        std::multimap<uint32_t, std::pair<int, int>> forkAndIndexByBlock;
        for (int i = 0; i < cnd.forks.size(); i++)
        {
            auto &oneFork = cnd.forks[i];
            for (auto &oneRoot : oneFork)
            {
                if (cnd.vtx[oneRoot].second.proofRoots.count(SystemID))
                {
                    forkAndIndexByBlock.insert(std::make_pair(cnd.vtx[oneRoot].second.proofRoots[SystemID].rootHeight, std::make_pair(i, oneRoot)));
                }
            }
        }

        int forkNum = -1;
        int elemCount = 0;
        int disagreements = 0;
        for (auto firstIt = forkAndIndexByBlock.rbegin(); firstIt != forkAndIndexByBlock.rend(); firstIt++)
        {
            if (forkNum == -1 || forkNum == firstIt->second.first)
            {
                elemCount++;
                forkNum = firstIt->second.first;
            }
            else
            {
                // this is an element that does not agree with the fork being processed
                // before we fail as a result, ensure that the associated earned notarization is a PoS block's
                // notarization to prevent successful periodic mining/notarization DoS attacks, where the cost is
                // 1/5th the actual mining power to effectively block cross-chain notarization. PoS is much harder
                // to periodically attack without having statistical holes, enabling notarizations to get confirmed
                // and defeating the attack, without attackers having much >50% network staking power to continuously deny
                // notary confirmation.
                uint256 blockHash = txes[firstIt->second.second].second;

                // if inexplicable error or PoS block disagrees, abort
                if (blockHash.IsNull() ||
                    !mapBlockIndex.count(blockHash) ||
                    mapBlockIndex[blockHash]->IsVerusPOSBlock())
                {
                    break;
                }
                // PoW disagreements do not veto, or DoS attacks on the cross-chain protocols become too easy
                continue;
            }
        }
        if (elemCount >= 2)
        {
            bestFork = cnd.forks[forkNum];
        }
    }
    else if (cnd.forks.size() &&
             (cnd.forks[0].size() > 2 || pNotaryCurrency->notarizationProtocol != CCurrencyDefinition::NOTARIZATION_AUTO))
    {
        bestFork = cnd.forks[0];
    }

    bool isFirstConfirmedCND = cnd.vtx[cnd.lastConfirmed].second.IsBlockOneNotarization() || cnd.vtx[cnd.lastConfirmed].second.IsDefinitionNotarization();

    if ((bestFork.size() < ((pNotaryCurrency->notarizationProtocol == CCurrencyDefinition::NOTARIZATION_AUTO) ? 3 : 2)) ||
        (!isFirstConfirmedCND && !cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(SystemID)))
    {
        return state.Error("insufficient validator confirmations");
    }

    // any valid earned notarization that we choose to use for our proof, which will determine
    // the signing height, enabling all of them to match without additional coordination
    uint32_t eligibleHeight = height - CPBaaSNotarization::MIN_BLOCKS_BEFORE_NOTARY_FINALIZED;

    // all we really want is the system proof roots for each notarization to make the JSON for the API smaller
    UniValue proofRootsUni(UniValue::VARR);

    // start with the last confirmed notarization, which should have originally come from the notary system,
    // and whether it was ever posted to the notary system, should match what the notary system reported as final.
    proofRootsUni.push_back(cnd.vtx[cnd.lastConfirmed].second.proofRoots[SystemID].ToUniValue());

    for (auto forkIdxIt = bestFork.begin(); forkIdxIt != bestFork.end(); forkIdxIt++)
    {
        // don't enter the confirmed notarization twice
        if (*forkIdxIt != cnd.lastConfirmed)
        {
            auto &oneNot = cnd.vtx[*forkIdxIt];
            auto rootIt = oneNot.second.proofRoots.find(SystemID);
            if (rootIt != oneNot.second.proofRoots.end())
            {
                proofRootsUni.push_back(rootIt->second.ToUniValue());
            }
            else
            {
                proofRootsUni.push_back(CProofRoot().ToUniValue());
            }
        }
    }

    if (!proofRootsUni.size())
    {
        return state.Error(errorPrefix + "no valid prior state root found");
    }

    UniValue firstParam(UniValue::VOBJ);
    firstParam.push_back(Pair("proofroots", proofRootsUni));
    firstParam.push_back(Pair("lastconfirmed", 0));

    // call notary to determine the notarization that we should notarize
    UniValue params(UniValue::VARR);
    params.push_back(firstParam);

    //printf("%s: about to getbestproofroot with:\n%s\n", __func__, params.write(1,2).c_str());

    UniValue result;
    try
    {
        result = find_value(RPCCallRoot("getbestproofroot", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }

    CProofRoot lastConfirmedRoot(find_value(result, "lastconfirmedproofroot"));
    int32_t notaryIdx = lastConfirmedRoot.IsValid() ? uni_get_int(find_value(result, "lastconfirmedindex"), -1) :
                                                      uni_get_int(find_value(result, "bestindex"), -1);

    if (result.isNull() || notaryIdx == -1)
    {
        return state.Error(result.isNull() ? "no-notary" : "no-matching-notarization-found");
    }

    // get the index from the best fork to make it an index into cnd.vtx
    notaryIdx = bestFork[notaryIdx];

    // take the lock again, now that we're back from calling out
    LOCK(cs_main);

    // if height changed, we need to fail and possibly try again later
    if (height != chainActive.Height())
    {
        return state.Error("stale-block");
    }

    // if the most recent valid earned notarization is prior to the eligible height,
    // we cannot notarize until a more recent one is mined

    // now, assuming that our notarization of the other chain is confirmed, sign the latest valid one on this chain
    UniValue proofRootArr = find_value(result, "validindexes");

    if (!proofRootArr.isArray() || !proofRootArr.size())
    {
        return state.Error("no-valid-unconfirmed");
    }

    bool retVal = false;
    int firstNotarizationIndex = -1;

    LogPrint("notarization", "%s: proofRootArr: %s\n", __func__, proofRootArr.write().c_str());

    // we seem to be getting an extra element at times
    // TODO: HARDENING - fix this in bridgekeeper
    if (proofRootArr.size() > bestFork.size())
    {
        UniValue tempArr(UniValue::VARR);
        for (int i = 0; i < bestFork.size(); i++)
        {
            tempArr.push_back(proofRootArr[i]);
        }
    }

    // look from the latest notarization that may qualify
    for (int i = (proofRootArr.size() - 1); i >= 0; i--)
    {
        int idx = uni_get_int(proofRootArr[i]);
        if (idx >= bestFork.size())
        {
            continue;
        }
        idx = bestFork[idx];

        auto proofIt = cnd.vtx[idx].second.proofRoots.find(ASSETCHAINS_CHAINID);

        if (proofIt != cnd.vtx[idx].second.proofRoots.end())
        {
            if (firstNotarizationIndex == -1 && proofIt->second.rootHeight > eligibleHeight)
            {
                firstNotarizationIndex = idx;
                signingHeight = proofIt->second.rootHeight + 1;
                continue;
            }
            else if (proofIt->second.rootHeight <= eligibleHeight)
            {
                // if no notarization is in front of us and recent, we have no more to check
                if (firstNotarizationIndex == -1 || cnd.lastConfirmed == idx)
                {
                    break;
                }

                // these are deleted, mutated below, and recreated each iteration
                std::set<CIdentityID> myIDSet;
                for (auto &oneID : mine)
                {
                    myIDSet.insert(oneID.first.idID);
                }

                // before signing the one we are about to, we want to ensure that it isn't already signed sufficiently
                // if there are enough signatures to confirm it without signature, make our signature, then create a finalization
                CObjectFinalization of = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION,
                                                             SystemID,
                                                             cnd.vtx[idx].first.hash,
                                                             cnd.vtx[idx].first.n,
                                                             height);

                std::vector<std::pair<CInputDescriptor, CNotaryEvidence>> additionalEvidence;

                std::set<CIdentityID> sigSet;

                std::set<CIdentityID> notarySetRejects;
                std::map<CIdentityID, CInputDescriptor> notarySetConfirms; 

                std::vector<std::vector<CNotaryEvidence>> evidenceVec;
                std::vector<std::vector<CInputDescriptor>> spendsToClose;
                std::vector<CInputDescriptor> extraSpends;

                std::set<int> confirmedOutputNums;
                std::set<int> invalidatedOutputNums;

                std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolUnspent;
                if (mempool.getAddressIndex(
                        std::vector<std::pair<uint160, int32_t>>({
                            {CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationFinalizedKey(),
                                                                cnd.vtx[idx].first.hash,
                                                                cnd.vtx[idx].first.n), 
                             CScript::P2IDX}}), 
                        mempoolUnspent) &&
                    mempoolUnspent.size())
                {
                    /* printf("%s: confirmedNotarizationKey: %s / 0x%s\nconfirmed finalizations\n",
                        __func__, 
                        EncodeDestination(CIdentityID(indexKey)).c_str(),
                        indexKey.GetHex().c_str()); */
                    std::vector<int> toRemove;
                    std::map<COutPoint, int> outputMap;
                    for (int j = 0; j < mempoolUnspent.size(); j++)
                    {
                        if (mempoolUnspent[j].first.spending)
                        {
                            auto it = outputMap.find(COutPoint(mempoolUnspent[j].second.prevhash, mempoolUnspent[j].second.prevout));
                            if (it != outputMap.end())
                            {
                                it->second < j ? toRemove.push_back(it->second) : toRemove.push_back(j);
                                it->second < j ? toRemove.push_back(j) : toRemove.push_back(it->second);
                            }
                            else
                            {
                                toRemove.push_back(j);
                            }
                        }
                        else
                        {
                            outputMap.insert(std::make_pair(COutPoint(mempoolUnspent[j].first.txhash, mempoolUnspent[j].first.index), j));
                        }
                    }
                    for (auto it = toRemove.rbegin(); it != toRemove.rend(); it++)
                    {
                        mempoolUnspent.erase(mempoolUnspent.begin() + *it);
                    }
                    for (auto &oneUnspent : mempoolUnspent)
                    {
                        // if we have a confirmed, valid entry in the mempool already, we don't have something to do
                        CTransaction oneTx;
                        COptCCParams optP;
                        CObjectFinalization checkOf;
                        if (mempool.lookup(oneUnspent.first.txhash, oneTx) &&
                            oneTx.vout.size() > oneUnspent.first.index &&
                            oneTx.vout[oneUnspent.first.index].scriptPubKey.IsPayToCryptoCondition(optP) &&
                            optP.IsValid() &&
                            optP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                            optP.vData.size() &&
                            (checkOf = CObjectFinalization(optP.vData[0])).IsValid() &&
                            checkOf.currencyID == SystemID &&
                            checkOf.IsConfirmed())
                        {
                            return state.Error("notarization confirmed in mempool");
                        }
                    }
                }

                if (!cnd.CorrelatedFinalizationSpends(txes, spendsToClose, extraSpends, &evidenceVec) ||
                    !cnd.CalculateConfirmation(idx, confirmedOutputNums, invalidatedOutputNums))
                {
                    return state.Error("invalid-correlated-spends");
                }

                if (LogAcceptCategory("notarization"))
                {
                    for (int j = 0; j < spendsToClose.size(); j++)
                    {
                        auto &oneEntrySpends = spendsToClose[j];
                        LogPrintf("%s: index #%d - %s\n", __func__, j, confirmedOutputNums.count(j) ? "confirmed" : invalidatedOutputNums.count(j) ? "rejected" : "pending");
                        for (auto &oneSpend : oneEntrySpends)
                        {
                            UniValue scriptUni(UniValue::VOBJ);
                            ScriptPubKeyToUniv(oneSpend.scriptPubKey, scriptUni, false, false);
                            LogPrintf("txid: %s:%d, nValue: %ld\n", oneSpend.txIn.prevout.hash.GetHex().c_str(), oneSpend.txIn.prevout.n, oneSpend.nValue);
                        }
                    }
                    for (int j = 0; j < evidenceVec.size(); j++)
                    {
                        auto &oneEvidenceVec = evidenceVec[j];
                        LogPrintf("evidence vector: index #%d\n", j);
                        for (auto &oneEvidence : oneEvidenceVec)
                        {
                            LogPrintf("%s\n", oneEvidence.ToUniValue().write(1,2).c_str());
                        }
                    }
                }

                CNotaryEvidence ne(ASSETCHAINS_CHAINID, cnd.vtx[idx].first, CNotaryEvidence::STATE_CONFIRMING);
                CCcontract_info CC;
                CCcontract_info *cp;
                std::vector<CTxDestination> dests;

                COptCCParams p;
                if (!(txes[idx].first.vout[ne.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                      p.IsValid() &&
                      p.evalCode != EVAL_NONE))
                {
                    return state.Error(errorPrefix + "invalid output for notarization");
                }
                CNativeHashWriter hw(hashType);
                uint256 objHash = hw.write((const char *)&(p.vData[0][0]), p.vData[0].size()).GetHash();

                // combine signatures and evidence
                // add additional evidence spends
                CNotaryEvidence mergedEvidence = ne;
                for (auto &oneEvidenceObj : evidenceVec[idx])
                {
                    mergedEvidence.MergeEvidence(oneEvidenceObj, notarySet);
                }

                uint32_t decisionHeight;
                std::map<CIdentityID, CIdentitySignature> confirmedAtHeight;
                std::map<CIdentityID, CIdentitySignature> rejectedAtHeight;
                CNotaryEvidence::EStates confirmationResult = mergedEvidence.CheckSignatureConfirmation(objHash,
                                                                                                        notarySet,
                                                                                                        minimumNotariesConfirm,
                                                                                                        signingHeight,
                                                                                                        &decisionHeight,
                                                                                                        &confirmedAtHeight,
                                                                                                        &rejectedAtHeight);

                // rejected is irreversible, so we are done
                if (confirmationResult == CNotaryEvidence::EStates::STATE_REJECTED)
                {
                    // we should consider different spends to close when rejecting
                    // a notarization, only pruning it and all dependent on it, confirming nothing
                    // currently, rejected notarizations would get consumed by confirmed notarizations
                }
                else if (confirmationResult != CNotaryEvidence::EStates::STATE_CONFIRMED)
                {
                    LOCK(cs_main);

                    // if we can still sign, do so and check confirmation
                    if (myIDSet.size())
                    {
                        cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
                        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

                        auto currentSignatures = mergedEvidence.GetNotarySignatures();
                        for (auto &oneSignature : currentSignatures)
                        {
                            if (oneSignature.IsConfirmed())
                            {
                                for (auto &oneIDSig : oneSignature.signatures)
                                {
                                    std::set<CTxDestination> idDestinations;

                                    for (auto &oneKeySig : oneIDSig.second.signatures)
                                    {
                                        // TODO: HARDENING - for efficiency, not security, remove destinations already signed
                                    }
                                }
                            }
                        }

                        {
                            LOCK(pWallet->cs_wallet);
                            // sign with all IDs under our control that are eligible for this currency
                            for (auto &oneID : myIDSet)
                            {
                                printf("Signing notarization (%s:%u) to confirm for %s\n", ne.output.hash.GetHex().c_str(), ne.output.n, EncodeDestination(oneID).c_str());

                                auto signResult = ne.SignConfirmed(notarySet, minimumNotariesConfirm, *pWallet, txes[idx].first, oneID, signingHeight, hashType);

                                if (signResult == CIdentitySignature::SIGNATURE_PARTIAL || signResult == CIdentitySignature::SIGNATURE_COMPLETE)
                                {
                                    sigSet.insert(oneID);

                                    // if our signatures altogether have provided a complete validation, we can early out
                                    // check to see if this notarization now qualifies with signatures
                                    if (signResult == CIdentitySignature::SIGNATURE_COMPLETE &&
                                        ne.CheckSignatureConfirmation(objHash, notarySet, minimumNotariesConfirm, signingHeight) == CNotaryEvidence::EStates::STATE_CONFIRMED)
                                    {
                                        break;
                                    }
                                }
                                else
                                {
                                    return state.Error(errorPrefix + "invalid identity signature");
                                }
                            }
                        }

                        if (!ne.evidence.Empty())
                        {
                            /* for (auto &debugOut : ne.signatures)
                            {
                                printf("%s: onesig - ID: %s, signature: %s\n", __func__, EncodeDestination(debugOut.first).c_str(), debugOut.second.ToUniValue().write(1,2).c_str());
                            } */

                            mergedEvidence.MergeEvidence(ne, notarySet, true);

                            retVal = true;
                            CScript evidenceScript = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &ne));
                            of.evidenceOutputs.push_back(txBuilder.mtx.vout.size());
                            txBuilder.AddTransparentOutput(evidenceScript, CNotaryEvidence::DEFAULT_OUTPUT_VALUE);
                        }
                    }

                    confirmationResult = mergedEvidence.CheckSignatureConfirmation(objHash, notarySet, minimumNotariesConfirm, signingHeight);
                }

                // if we have enough to finalize, do so as a combination of pre-existing evidence and this
                if (confirmationResult == CNotaryEvidence::EStates::STATE_CONFIRMED)
                {
                    std::set<COutPoint> inputSet;
                    std::vector<CInputDescriptor> nonEvidenceSpends;
                    for (auto &oneEvidenceSpend : spendsToClose[idx])
                    {
                        COptCCParams tP;
                        if (oneEvidenceSpend.scriptPubKey.IsPayToCryptoCondition(tP) &&
                            tP.IsValid() &&
                            tP.evalCode == EVAL_NOTARY_EVIDENCE || tP.evalCode == EVAL_FINALIZE_NOTARIZATION)
                        {
                            // if our evidence include an already confirmed finalization for the same output,
                            // abort with nothing to do
                            CObjectFinalization tPOF;
                            if (tP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                                tP.vData.size() &&
                                (tPOF = CObjectFinalization(tP.vData[0])).IsValid() &&
                                tPOF.output == of.output &&
                                tPOF.IsConfirmed())
                            {
                                return state.Error(errorPrefix + "target notarization already confirmed");
                            }
                            of.evidenceInputs.push_back(txBuilder.mtx.vin.size());
                            if (!inputSet.count(oneEvidenceSpend.txIn.prevout))
                            {
                                inputSet.insert(oneEvidenceSpend.txIn.prevout);
                                txBuilder.AddTransparentInput(oneEvidenceSpend.txIn.prevout, oneEvidenceSpend.scriptPubKey, oneEvidenceSpend.nValue);
                            }
                            else if (LogAcceptCategory("notarization"))
                            {
                                printf("%s: duplicate input: %s\n", __func__, oneEvidenceSpend.txIn.prevout.ToString().c_str());
                                LogPrintf("%s: duplicate input: %s\n", __func__, oneEvidenceSpend.txIn.prevout.ToString().c_str());
                            }
                        }
                        else
                        {
                            nonEvidenceSpends.push_back(oneEvidenceSpend);
                        }
                    }
                    for (auto &oneSpend : nonEvidenceSpends)
                    {
                        if (!inputSet.count(oneSpend.txIn.prevout))
                        {
                            inputSet.insert(oneSpend.txIn.prevout);
                            txBuilder.AddTransparentInput(oneSpend.txIn.prevout, oneSpend.scriptPubKey, oneSpend.nValue);
                        }
                        else if (LogAcceptCategory("notarization"))
                        {
                            printf("%s: duplicate input: %s\n", __func__, oneSpend.txIn.prevout.ToString().c_str());
                            LogPrintf("%s: duplicate input: %s\n", __func__, oneSpend.txIn.prevout.ToString().c_str());
                        }
                    }

                    int sigCount = 0;

                    of.SetConfirmed();

                    // any fork that does not match the confirmed fork up to the same index will be
                    // considered invalid from all of its entries to its end.
                    //
                    bool makeInputTxes = confirmedOutputNums.size() > 3;
                    for (auto oneConfirmedIdx : confirmedOutputNums)
                    {
                        if (oneConfirmedIdx != idx)
                        {
                            bool makeInputTx = (makeInputTxes && spendsToClose[oneConfirmedIdx].size() > 2);
                            // if we are confirming more
                            // than 2 additional pending notarizations (3 total), we break the spends up into one
                            // transaction to close out each pending transaction into a pending finalization, which
                            // then is spent into the main transaction
                            std::vector<int> evidenceInputs;
                            auto newTxBuilder = TransactionBuilder(Params().GetConsensus(), nHeight, pWallet);
                            TransactionBuilder &oneConfirmedBuilder = (oneConfirmedIdx != cnd.lastConfirmed && makeInputTx) ? newTxBuilder : txBuilder;

                            bool isConfirmed = false;
                            for (auto &oneInput : spendsToClose[oneConfirmedIdx])
                            {
                                COptCCParams tP;
                                if (oneInput.scriptPubKey.IsPayToCryptoCondition(tP) &&
                                    tP.IsValid() &&
                                    tP.evalCode == EVAL_NOTARY_EVIDENCE || tP.evalCode == EVAL_FINALIZE_NOTARIZATION)
                                {
                                    // if our evidence include an already confirmed finalization for the same output,
                                    // abort with nothing to do
                                    CObjectFinalization tPOF;
                                    if (tP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                                        tP.vData.size() &&
                                        (tPOF = CObjectFinalization(tP.vData[0])).IsValid() &&
                                        tPOF.IsConfirmed() &&
                                        ((tPOF.output.hash.IsNull() &&
                                          oneInput.txIn.prevout.hash == cnd.vtx[oneConfirmedIdx].first.hash &&
                                          tPOF.output.n == cnd.vtx[oneConfirmedIdx].first.n) ||
                                         tPOF.output == cnd.vtx[oneConfirmedIdx].first))
                                    {
                                        isConfirmed = true;
                                        makeInputTx = false;
                                    }
                                }

                                if (!inputSet.count(oneInput.txIn.prevout))
                                {
                                    inputSet.insert(oneInput.txIn.prevout);
                                    evidenceInputs.push_back(oneConfirmedBuilder.mtx.vin.size());
                                    oneConfirmedBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                                }
                                else if (LogAcceptCategory("notarization"))
                                {
                                    printf("%s: duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                                    LogPrintf("%s: duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                                }
                            }

                            if (makeInputTx)
                            {
                                CObjectFinalization oneConfirmedFinalization = 
                                    CObjectFinalization(isConfirmed ? 
                                                            CObjectFinalization::FINALIZE_NOTARIZATION + CObjectFinalization::FINALIZE_CONFIRMED :
                                                            CObjectFinalization::FINALIZE_NOTARIZATION,
                                                        SystemID,
                                                        cnd.vtx[oneConfirmedIdx].first.hash,
                                                        cnd.vtx[oneConfirmedIdx].first.n,
                                                        height);

                                cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
                                dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

                                CScript finalizeScript = MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &oneConfirmedFinalization));
                                oneConfirmedBuilder.AddTransparentOutput(finalizeScript, 0);
                                txBuilders.push_back(oneConfirmedBuilder);
                            }
                        }
                    }

                    makeInputTxes = invalidatedOutputNums.size() > 3;
                    for (auto oneInvalidatedIdx : invalidatedOutputNums)
                    {
                        bool makeInputTx = (makeInputTxes && spendsToClose[oneInvalidatedIdx].size() > 2);

                        auto newTxBuilder = TransactionBuilder(Params().GetConsensus(), nHeight, pWallet);
                        TransactionBuilder &oneInvalidatedBuilder = makeInputTx ? newTxBuilder : txBuilder;

                        for (auto &oneInput : spendsToClose[oneInvalidatedIdx])
                        {
                            if (!inputSet.count(oneInput.txIn.prevout))
                            {
                                inputSet.insert(oneInput.txIn.prevout);
                                oneInvalidatedBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                            }
                            else if (LogAcceptCategory("notarization"))
                            {
                                printf("%s: duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                                LogPrintf("%s: duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                            }
                        }

                        if (makeInputTx)
                        {
                            CObjectFinalization oneConfirmedFinalization = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION,
                                                                                               SystemID,
                                                                                               cnd.vtx[oneInvalidatedIdx].first.hash,
                                                                                               cnd.vtx[oneInvalidatedIdx].first.n,
                                                                                               height);

                            cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
                            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

                            CScript finalizeScript = MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &oneConfirmedFinalization));
                            oneInvalidatedBuilder.AddTransparentOutput(finalizeScript, 0);
                            txBuilders.push_back(oneInvalidatedBuilder);
                        }
                    }

                    retVal = true;
                    finalized = true;
                    cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
                    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

                    CScript finalizeScript = MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of));
                    txBuilder.AddTransparentOutput(finalizeScript, 0);
                    txBuilders.push_back(txBuilder);
                }
                else if (txBuilder.mtx.vout.size())
                {
                    txBuilders.push_back(txBuilder);
                }
                break;
            }
        }
        if (finalized)
        {
            break;
        }
    }
    return retVal;
}

bool CallNotary(const CRPCChainData &notarySystem, std::string command, const UniValue &params, UniValue &result, UniValue &error);

bool CPBaaSNotarization::FindEarnedNotarization(CObjectFinalization &confirmedFinalization, CAddressIndexDbEntry *pEarnedNotarizationIndex) const
{
    CAddressIndexDbEntry __earnedNotarizationIndex;
    CAddressIndexDbEntry &earnedNotarizationIndex = pEarnedNotarizationIndex ? *pEarnedNotarizationIndex : __earnedNotarizationIndex;

    bool retVal = false;
    CPBaaSNotarization checkNotarization = *this;
    if (checkNotarization.IsMirror())
    {
        if (!checkNotarization.SetMirror(false))
        {
            LogPrintf("Unable to interpret notarization data for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
            printf("Unable to interpret notarization data for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
            return retVal;
        }
    }

    if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
    {
        std::vector<unsigned char> checkHex = ::AsVector(checkNotarization);
        LogPrintf("%s: hex of notarization: %s\n", __func__, HexBytes(&(checkHex[0]), checkHex.size()).c_str());
        printf("%s: hex of notarization: %s\n", __func__, HexBytes(&(checkHex[0]), checkHex.size()).c_str());
    }

    CNativeHashWriter hw;
    hw << checkNotarization;
    uint256 objHash = hw.GetHash();
    uint160 notarizationIdxKey = CCrossChainRPCData::GetConditionID(checkNotarization.currencyID, CPBaaSNotarization::EarnedNotarizationKey(), objHash);

    std::vector<CAddressIndexDbEntry> addressIndex;
    if (!GetAddressIndex(notarizationIdxKey, CScript::P2IDX, addressIndex) || !addressIndex.size())
    {
        LogPrintf("Unable to confirm notarization data for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
        printf("Unable to confirm notarization data for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
        return retVal;
    }

    for (auto &oneIndexEntry : addressIndex)
    {
        if (oneIndexEntry.first.spending)
        {
            continue;
        }
        earnedNotarizationIndex = oneIndexEntry;
        break;
    }
    if (!earnedNotarizationIndex.first.blockHeight)
    {
        LogPrintf("Unable to locate transaction for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
        printf("Unable to locate transaction for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
        return retVal;
    }

    uint160 finalizedNotarizationKey = CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationFinalizedKey(),
                                                                          earnedNotarizationIndex.first.txhash,
                                                                          earnedNotarizationIndex.first.index);

    addressIndex.clear();
    if (!GetAddressIndex(finalizedNotarizationKey, CScript::P2IDX, addressIndex) ||
         !addressIndex.size())
    {
        return true;
    }

    CAddressIndexDbEntry finalizationIndex;
    for (auto &oneIndexEntry : addressIndex)
    {
        if (oneIndexEntry.first.spending)
        {
            continue;
        }
        finalizationIndex = oneIndexEntry;
        break;
    }
    if (!finalizationIndex.first.blockHeight)
    {
        LogPrintf("Unable to locate indexed finalization transaction for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
        printf("Unable to locate indexed finalization transaction for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
        return retVal;
    }

    CTransaction finalizationTx;
    uint256 blkHash;
    COptCCParams fP;
    if (!myGetTransaction(finalizationIndex.first.txhash, finalizationTx, blkHash) ||
        finalizationIndex.first.index >= finalizationTx.vout.size() ||
        !(finalizationTx.vout[finalizationIndex.first.index].scriptPubKey.IsPayToCryptoCondition(fP) &&
            fP.IsValid() &&
            fP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
            fP.vData.size() &&
            (confirmedFinalization = CObjectFinalization(fP.vData[0])).IsValid()))
    {
        LogPrintf("Invalid finalization transaction %s for notarization:\n%s\n", finalizationIndex.first.txhash.GetHex().c_str(), checkNotarization.ToUniValue().write(1,2).c_str());
        printf("Invalid finalization transaction %s for notarization:\n%s\n", finalizationIndex.first.txhash.GetHex().c_str(), checkNotarization.ToUniValue().write(1,2).c_str());
        return retVal;
    }

    // if the entry is finalized and not confirmed
    if (!confirmedFinalization.IsConfirmed())
    {
        LogPrint("notarization", "Finalization unconfirmed on transaction %s for notarization:\n%s\n", finalizationIndex.first.txhash.GetHex().c_str(), checkNotarization.ToUniValue().write(1,2).c_str());
        return false;
    }
    return true;
}


// look for finalized notarizations either on chain or in the mempool, which are eligible for submission
// and submit them to the notary chain, referring to the last on the notary chain that we agree with.
std::vector<uint256> CPBaaSNotarization::SubmitFinalizedNotarizations(const CRPCChainData &externalSystem,
                                                                      CValidationState &state)
{
    std::vector<uint256> retVal;

    // look for finalized notarizations for our notary chains in recent blocks
    // if we find any and are connected, submit them
    uint160 systemID = externalSystem.chainDefinition.GetID();

    const CCurrencyDefinition *pNotaryCurrency;
    if (IsVerusActive() || !ConnectedChains.notarySystems.count(systemID))
    {
        pNotaryCurrency = &externalSystem.chainDefinition;
    }
    else
    {
        pNotaryCurrency = &ConnectedChains.ThisChain();
    }

    std::set<uint160> notarySet = pNotaryCurrency->GetNotarySet();

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> notarizationTxes;

    // define here to construct in netsted scope and then access below
    CNotaryEvidence allEvidence(CNotaryEvidence::TYPE_NOTARY_EVIDENCE, CNotaryEvidence::VERSION_CURRENT);

    // first, put in a current proof root of the current chain
    // then, using that, prove the last earned notarization that we
    // agree with
    std::vector<std::vector<CInputDescriptor>> spendsToClose;
    std::vector<CInputDescriptor> extraSpends;
    std::vector<std::vector<CNotaryEvidence>> evidenceVec;

    std::pair<CInputDescriptor, CPartialTransactionProof> notarizationTxInfo;

    {
        LOCK2(cs_main, mempool.cs);

        // we need to start with a confirmed notarization and one pending after that, which we agree with to move forward
        // this is to ensure that any transaction we intend to finalize has both a minimum number of mining/staking confirmations
        // and a minimum number of notary confirmation signatures
        if (!GetNotarizationData(systemID, cnd, &notarizationTxes))
        {
            return retVal;
        }
    }

    // to submit a confirmed notarization to the alternate chain, we need another earned notarization
    // that we agree with to be mined into the chain, look from the end of the vtx to find one we agree with
    // the index returned is the one we agree with, and the one that we will use to prove
    int startingNotarizationIdx = cnd.BestConfirmedNotarization(2);
    if (startingNotarizationIdx == -1)
    {
        LogPrint("notarization", "Not enough confirmations to submit finalized notarizations for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
        return retVal;
    }

    // if latest confirmed notarization on this chain is not present on notary chain, we need to submit it and reinforce
    // the last matching notarization from the other system, which should correspond to a prior confirmed notarization
    // on this chain
    UniValue params(UniValue::VARR);
    params.push_back(EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));

    UniValue result;
    try
    {
        result = find_value(RPCCallRoot("getnotarizationdata", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }

    CChainNotarizationData crosschainCND;
    if (result.isNull() ||
        !(crosschainCND = CChainNotarizationData(result)).IsValid() ||
        (!externalSystem.chainDefinition.IsGateway() && !crosschainCND.IsConfirmed()))
    {
        LogPrintf("Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
        printf("Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
        return retVal;
    }

    // if the returned data is not confirmed, then it is a gateway that has not yet confirmed its first transaction
    // it may still have unconfirmed notarizations
    // if it is a gateway that is unconfirmed on the other side, we will insert its definition notarization as confirmed,
    // until it is confirmed on its side.
    if (!crosschainCND.IsConfirmed())
    {
        LOCK(cs_main);
        CInputDescriptor notarizationRef;
        CPBaaSNotarization definitionNotarization;
        if (!ConnectedChains.GetDefinitionNotarization(externalSystem.chainDefinition, notarizationRef, definitionNotarization))
        {
            LogPrintf("Unable to get definition notarization for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            printf("Unable to get definition notarization for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            return retVal;
        }
        crosschainCND.lastConfirmed = 0;
        crosschainCND.vtx.insert(crosschainCND.vtx.begin(), std::make_pair(CUTXORef(notarizationRef.txIn.prevout), definitionNotarization));

        if (crosschainCND.vtx.size() == 1)
        {
            crosschainCND.bestChain = 0;
            crosschainCND.forks = std::vector<std::vector<int>>({std::vector<int>({0})});
        }
        else
        {
            // loop through the forks, insert 0, and increment all following indices
            for (auto &oneFork : crosschainCND.forks)
            {
                for (auto &oneIndex : oneFork)
                {
                    oneIndex++;
                }
                oneFork.insert(oneFork.begin(), 0);
            }
        }
    }

    // our latest confirmed is what we may submit.
    // if it is already on that chain, we have nothing to do
    CPBaaSNotarization firstProofNotarization = cnd.vtx[cnd.lastConfirmed].second;
    auto searchVec = ::AsVector(firstProofNotarization);

    for (auto oneNotarization : crosschainCND.vtx)
    {
        if (oneNotarization.second.IsMirror() &&
            !oneNotarization.second.SetMirror(false))
        {
            LogPrintf("Failure to unmirror notarization from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            printf("Failure to unmirror notarization from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            return retVal;
        }
        if (searchVec == ::AsVector(oneNotarization.second))
        {
            LogPrint("notarization", "No new confirmed notarizations for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            return retVal;
        }
        // all proof roots in a prior, agreed notarization must be present and have moved forward
        for (auto &oneProofRoot : oneNotarization.second.proofRoots)
        {
            if (!cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(oneProofRoot.first) ||
                cnd.vtx[cnd.lastConfirmed].second.proofRoots[oneProofRoot.first].rootHeight <= oneProofRoot.second.rootHeight)
            {
                LogPrint("notarization", "Skip submission - no new confirmed notarizations for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                return retVal;
            }
        }
    }

    uint32_t nHeight;

    {
        LOCK2(cs_main, mempool.cs);

        nHeight = chainActive.Height();

        // check to see if any of the pending notarizations match either our last confirmed
        // or the one before it
        int confirmingIdx = 0;

        bool isFirstLaunchingNotarization = crosschainCND.vtx[confirmingIdx].second.IsDefinitionNotarization() ||
                                            crosschainCND.vtx[confirmingIdx].second.IsPreLaunch() ||
                                            crosschainCND.vtx[confirmingIdx].second.IsBlockOneNotarization();

        CAddressIndexDbEntry earnedNotarizationIndexEntry;

        if (crosschainCND.IsConfirmed() || crosschainCND.vtx.size() == 1)
        {
            // ensure that we at least agree with the last notarization, or we can't submit
            confirmingIdx = crosschainCND.IsConfirmed() ? crosschainCND.lastConfirmed : 0;
            CObjectFinalization finalizationObj;

            if (!isFirstLaunchingNotarization)
            {
                if (!crosschainCND.vtx[confirmingIdx].second.FindEarnedNotarization(finalizationObj, &earnedNotarizationIndexEntry))
                {
                    return retVal;
                }
                else if (!finalizationObj.IsValid() || !finalizationObj.IsConfirmed())
                {
                    // the notarization considered confirmed on the other
                    // chain must be in the same notarization chain as the one confirmed on this chain that would
                    // be true if it is on both chains, accurate on both, and behind this confirmed notarization
                    CTransaction notarizationTx;
                    CPBaaSNotarization checkNotarization1, checkNotarization2 = crosschainCND.vtx[confirmingIdx].second;
                    uint256 blkHash;
                    COptCCParams nP;
                    if (!myGetTransaction(earnedNotarizationIndexEntry.first.txhash, notarizationTx, blkHash) ||
                        earnedNotarizationIndexEntry.first.index >= notarizationTx.vout.size() ||
                        !(notarizationTx.vout[earnedNotarizationIndexEntry.first.index].scriptPubKey.IsPayToCryptoCondition(nP) &&
                        nP.IsValid() &&
                        nP.evalCode == EVAL_EARNEDNOTARIZATION &&
                        nP.vData.size() &&
                        (checkNotarization1 = CPBaaSNotarization(nP.vData[0])).IsValid() &&
                        checkNotarization2.SetMirror(false) &&
                        ::AsVector(checkNotarization1) == ::AsVector(checkNotarization2) &&
                        checkNotarization1.proofRoots.count(ASSETCHAINS_CHAINID) &&
                        checkNotarization2.proofRoots.count(ASSETCHAINS_CHAINID) &&
                        checkNotarization1.proofRoots[ASSETCHAINS_CHAINID].rootHeight < checkNotarization2.proofRoots[ASSETCHAINS_CHAINID].rootHeight))
                    {
                        LogPrintf("Invalid notarization index entry for txid: %s\n", earnedNotarizationIndexEntry.first.txhash.GetHex().c_str());
                        printf("Invalid notarization index entry for txid: %s\n", earnedNotarizationIndexEntry.first.txhash.GetHex().c_str());
                        return retVal;
                    }
                }
            } 
        }

        // if we have pending notarizations, see which of the possible ones we agree with
        if (!(crosschainCND.vtx.size() == 1 && isFirstLaunchingNotarization))
        {
            // go backwards until we find one to confirm or fail
            for (int i = crosschainCND.vtx.size() - 1; i > 0; i--)
            {
                CAddressIndexDbEntry tmpIndexEntry;
                CObjectFinalization finalizationObj;
                if (crosschainCND.vtx[i].second.proofRoots.count(ASSETCHAINS_CHAINID) &&
                    crosschainCND.vtx[i].second.FindEarnedNotarization(finalizationObj, &tmpIndexEntry) &&
                    finalizationObj.IsConfirmed())
                {
                    earnedNotarizationIndexEntry = tmpIndexEntry;
                    confirmingIdx = i;
                    break;
                }
            }
            if (!crosschainCND.vtx[confirmingIdx].second.IsDefinitionNotarization())
            {
                // if we found one we agree with, make it the one we prove with our own notarization
                // CPartialTransactionProof(const CTransaction tx,
                //                          const std::vector<int> &inputNums,
                //                          const std::vector<int> &outputNums,
                //                          const CBlockIndex *pIndex,
                //                          uint32_t proofAtHeight)
                uint256 blockHash;
                CTransaction confirmedNTx;
                CBlockIndex *pIndex;
                if (earnedNotarizationIndexEntry.first.txhash.IsNull() ||
                    !myGetTransaction(earnedNotarizationIndexEntry.first.txhash, confirmedNTx, blockHash) ||
                    !mapBlockIndex.count(blockHash) ||
                    !chainActive.Contains(pIndex = mapBlockIndex[blockHash]))
                {
                    LogPrintf("Unable to get confirmed notarization transaction for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                    printf("Unable to get confirmed notarization transaction for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                    return retVal;
                }
                CPartialTransactionProof firstProof(confirmedNTx,
                                                    std::vector<int>(),
                                                    std::vector<int>({(int)earnedNotarizationIndexEntry.first.index}),
                                                    pIndex,
                                                    crosschainCND.vtx[confirmingIdx].second.proofRoots[ASSETCHAINS_CHAINID].rootHeight);
                notarizationTxInfo = std::make_pair(CInputDescriptor(confirmedNTx.vout[earnedNotarizationIndexEntry.first.index].scriptPubKey,
                                                                     confirmedNTx.vout[earnedNotarizationIndexEntry.first.index].nValue,
                                                                     CTxIn(earnedNotarizationIndexEntry.first.txhash, earnedNotarizationIndexEntry.first.index)),
                                                    firstProof);
            }
        }

        if (isFirstLaunchingNotarization)
        {
            // TODO: HARDENING
            /* // get and prove our block 1 notarization on the coinbase, if this is the definition notarization
            if (firstProofNotarization.IsBlockOneNotarization())
            {
                CBlock block;
                if (!ReadBlockFromDisk(block, chainActive[1], Params().GetConsensus(), false))
                {
                    LogPrintf("%s: ERROR: could not read block one from disk\n", __func__);
                    return retVal;
                }

                auto blockOneMMR = block.GetBlockMMRTree()

                CPartialTransactionProof blockOneCoinbaseProof = CPartialTransactionProof()


                // get map and MMR for stake source transaction
                CTransactionMap txMap(stakeSource);
                TransactionMMView txView(txMap.transactionMMR);
                uint256 txRoot = txView.GetRoot();

                std::vector<CTransactionComponentProof> txProofVec;
                txProofVec.push_back(CTransactionComponentProof(txView, txMap, stakeSource, CTransactionHeader::TX_HEADER, 0));
                txProofVec.push_back(CTransactionComponentProof(txView, txMap, stakeSource, CTransactionHeader::TX_OUTPUT, pwinner->i));

                // now, both the header and stake output are dependent on the transaction MMR root being provable up
                // through the block MMR, and since we don't cache the new MMR proof for transactions yet, we need the block to create the proof.
                // when we switch to the new MMR in place of a merkle tree, we can keep that in the wallet as well

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
                    LogPrintf("%s: ERROR: could not find source transaction root in block %u\n", __func__, srcIndex);
                    return false;
                }

                // prove the tx up to the MMR root, which also contains the block hash
                CMMRProof txRootProof;
                if (!blockView.GetProof(txRootProof, txIndexPos))
                {
                    LogPrintf("%s: ERROR: could not create proof of source transaction in block %u\n", __func__, srcIndex);
                    return false;
                }

                mmrView.resize(proveBlockHeight + 1);
                chainActive.GetMerkleProof(mmrView, txRootProof, srcIndex);

                headerStream << CPartialTransactionProof(txRootProof, txProofVec);

                CMMRProof blockHeaderProof1;
                if (!chainActive.GetBlockProof(mmrView, blockHeaderProof1, proveBlockHeight))
                {
                    LogPrintf("%s: ERROR: could not create block proof for block %u\n", __func__, srcIndex);
                    return false;
                }
                headerStream << CBlockHeaderProof(blockHeaderProof1, chainActive[proveBlockHeight]->GetBlockHeader());











            } *///


            //
            //
            CPBaaSNotarization launchNotarization;
            ConnectedChains.GetLaunchNotarization(externalSystem.chainDefinition,
                                                    notarizationTxInfo,
                                                    launchNotarization,
                                                    firstProofNotarization);

            if (::AsVector(firstProofNotarization) != ::AsVector(cnd.vtx[cnd.lastConfirmed].second))
            {
                LogPrintf("Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                printf("Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                return retVal;
            }
        }

        // TODO: HARDENING - ensure that notarizationTxInfo gets passed to the other side
        if (!isFirstLaunchingNotarization && !(notarizationTxInfo.second.IsValid() && notarizationTxInfo.second.components.size()))
        {
            LogPrintf("Cannot construct notarization proof for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            printf("Cannot construct notarization proof for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            return retVal;
        }

        if (!cnd.CorrelatedFinalizationSpends(notarizationTxes, spendsToClose, extraSpends, &evidenceVec) ||
            (!evidenceVec[cnd.lastConfirmed].size()))
        {
            LogPrint("notarization", "Cannot correlate adequate proof evidence for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            return retVal;
        }

        // now, we have our first proof of our prior, proven by our current, which is new to the notary chain
        // we need to prove the confirmed notarization with one after it and a proof root after that

        // we have:
        // 1) Access to the confirmed earned notarization on this chain, which has been determined
        //    not to have been submitted and mined into the notary chain as a confirmed or pending notarization yet.
        // 2) Proof using our confirmed notarization of a transaction that corresponds to either the last confirmed
        //    notarization on the notary chain or a pending notarization on the notary chain to confirm. In the case
        //    of a gateway, this proof may also apply to the definition transaction.
        //
        // we need to still get:
        // 1) proof root from tip
        // 2) partial transaction proof using the proof root in #1 of the startingNotarizationIdx notarization that we agree with
        // 3) proof using the notarization in #2 of the block behind it, enabling determination of PoW or PoS for notarization
        // 3) partial transaction proof using the notarization in #2 of our confirmed notarization on this chain
        // 4) proof using the confirmed notarization in #3 of the block behind, enabling determination of PoW or PoS for notarization
        // 5) proof using the last confirmed notarization of the notarization already known to the other chain in #2 of what we have above.
        // 6) proof using the last confirmed notarization of the block header ref prior to the previous notarization, enabling
        //    confirmation that the last notarization on the notary chain was earned from a PoS or PoW block

        // get all evidence for the confirmed notarization and combine it
        // all we care about in PBaaS v1 is the signatures, which we will add to cross-chain proofs
        for (auto &oneEvidenceObj : evidenceVec[cnd.lastConfirmed])
        {
            allEvidence.MergeEvidence(oneEvidenceObj, notarySet, true);
        }

        // now, allEvidence has all signatures that were used to confirm on this chain
        // now add the supporting evidence
    }

    // allEvidence has all signatures that were used to confirm on this chain
    // now, if we are auto-notarizing, add the supporting evidence
    if (pNotaryCurrency->notarizationProtocol == pNotaryCurrency->NOTARIZATION_AUTO)
    {
        // make sure we have a more recent notarization, after the one we are posting, that is consistent with the other chain/system
        LOCK(cs_main);
        CProofRoot firstProofRoot = CProofRoot::GetProofRoot(nHeight);



        /*
        CHAINOBJ_TRANSACTION_PROOF          - valid proof after us
        CHAINOBJ_TRANSACTION_PROOF          - pre header proof

        CHAINOBJ_TRANSACTION_PROOF          - valid proof of this confirmed notarization output
        CHAINOBJ_TRANSACTION_PROOF          - pre header proof of this header

        CHAINOBJ_TRANSACTION_PROOF          - valid proof of the last confirmed transaction
        CHAINOBJ_TRANSACTION_PROOF          - pre header proof of this header
        */
    }

    CPBaaSNotarization lastConfirmedNotarization = cnd.vtx[cnd.lastConfirmed].second;

    // now, we should have enough evidence to prove
    // the notarization. the API call will ensure that we do
    params = UniValue(UniValue::VARR);
    UniValue error;
    std::string strTxId;
    params.push_back(lastConfirmedNotarization.ToUniValue());
    params.push_back(allEvidence.ToUniValue());
    // printf("%s: sending evidence:\n%s\n", __func__, allEvidence.ToUniValue().write(1,2).c_str());

    /* for (auto &debugOut : oneNotarization.second.signatures)
    {
        printf("%s: onesig - ID: %s, signature: %s\n", __func__, EncodeDestination(debugOut.first).c_str(), debugOut.second.ToUniValue().write(1,2).c_str());
    }
    printf("%s: submitting notarization with parameters:\n%s\n%s\n", __func__, params[0].write(1,2).c_str(), params[1].write(1,2).c_str());
    printf("%s: initial notarization:\n%s\n", __func__, oneNotarization.first.ToUniValue().write(1,2).c_str());
    std::vector<unsigned char> notVec1 = ::AsVector(oneNotarization.first);
    CPBaaSNotarization checkNotarization(oneNotarization.first.ToUniValue());
    std::vector<unsigned char> notVec2 = ::AsVector(checkNotarization);
    printf("%s: processed notarization:\n%s\n", __func__, checkNotarization.ToUniValue().write(1,2).c_str());
    std::vector<unsigned char> notVec3 = ::AsVector(CPBaaSNotarization(notVec1));
    printf("%s: hex before univalue:\n%s\n", __func__, HexBytes(&(notVec1[0]), notVec1.size()).c_str());
    printf("%s: hex after univalue:\n%s\n", __func__, HexBytes(&(notVec2[0]), notVec2.size()).c_str());
    printf("%s: hex after reserialization:\n%s\n", __func__, HexBytes(&(notVec3[0]), notVec3.size()).c_str()); */

    if (!CallNotary(externalSystem, "submitacceptednotarization", params, result, error) ||
        !error.isNull() ||
        (strTxId = uni_get_str(result)).empty() ||
        !IsHex(strTxId))
    {
        return retVal;
    }
    // store the transaction ID and accepted notariation to prevent redundant submits
    retVal.push_back(uint256S(strTxId));
    return retVal;
}

/*
 * Validates a notarization output spend by ensuring that the spending transaction fulfills all requirements.
 * to accept an earned notarization as valid on the Verus blockchain, it must prove a transaction on the alternate chain, which is 
 * either the original chain definition transaction, which CAN and MUST be proven ONLY in block 1, or the latest notarization transaction 
 * on the alternate chain that represents an accurate MMR for this chain.
 * In addition, any accepted notarization must fullfill the following requirements:
 * 1) Must prove either a PoS block from the alternate chain or a merge mined block that is owned by the submitter and in either case, 
 *    the block must be exactly 8 blocks behind the submitted MMR used for proof.
 * 2) Must prove a chain definition tx and be block 1 or asserts a previous, valid MMR for the notarizing
 *    chain and properly prove objects using that MMR.
 * 3) Must spend the main notarization thread as well as any finalization outputs of either valid or invalid prior
 *    notarizations, and any unspent notarization contributions for this era. May also spend other inputs.
 * 4) Must output:
 *      a) finalization output of the expected reward amount, which will be sent when finalized
 *      b) normal output of reward from validated/finalized input if present, 50% to recipient / 50% to block miner less miner fee this tx
 *      c) main notarization thread output with remaining funds, no other output or fee deduction
 * 
 */
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // TODO: HARDENING
    // the spending transaction must be a notarization in the same thread of notarizations
    // check the following things:
    // 1. It represents a valid PoS or merge mined block on the other chain, and contains the header in the opret
    // 2. The MMR and proof provided for the currently asserted block can prove the provided header. The provided
    //    header can prove the last block referenced.
    // 3. This notarization is not a superset of an earlier notarization posted before it that it does not
    //    reference. If that is the case, it is rejected.
    // 4. Has all relevant inputs, including finalizes all necessary transactions, both confirmed and orphaned
    //printf("ValidateAcceptedNotarization\n");
    return true;
}

bool PreCheckAcceptedOrEarnedNotarization(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    if (height < 1567999 && CConstVerusSolutionVector::activationHeight.ActiveVersion(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return true;
    }
    // ensure that we never accept an invalid proofroot for this chain in a notarization
    COptCCParams p;
    CPBaaSNotarization currentNotarization;
    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
         p.IsValid() &&
         (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
         p.vData.size() &&
         (currentNotarization = CPBaaSNotarization(p.vData[0])).IsValid() &&
         currentNotarization.currencyState.IsValid() &&
         currentNotarization.currencyState.GetID() == currentNotarization.currencyID))
    {
        return state.Error("Invalid notarization output");
    }

    if (currentNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
    {
        CProofRoot notarizationRoot = currentNotarization.proofRoots[ASSETCHAINS_CHAINID];
        if (notarizationRoot.rootHeight >= height)
        {
            return true;
        }
        CProofRoot correctRoot = CProofRoot::GetProofRoot(notarizationRoot.rootHeight);

        if (!correctRoot.IsValid())
        {
            return true;
        }

        if (correctRoot != notarizationRoot)
        {
            return state.Error("Incorrect proof root in notarization transaction");
        }

        // earned notarizations are only supported for 
        if (p.evalCode == EVAL_EARNEDNOTARIZATION &&
            !currentNotarization.IsBlockOneNotarization() &&
            !currentNotarization.proofRoots.count(currentNotarization.currencyID))
        {
            return state.Error("Earned notarization besides PBaaS block one must contain proof root of system being notarized");
        }
    }
    else if (p.evalCode == EVAL_EARNEDNOTARIZATION &&
             !currentNotarization.IsBlockOneNotarization())
    {
        return state.Error("Earned notarization must contain proof root of current chain");
    }

    // if this is a notarization for this chain's notary chain or system, and this chain is running an auto-notarization protocol,
    // only earned notarizations may be entered, and those notarizations must alternate between being entered by a staker and
    // then a miner
    uint32_t nHeight = chainActive.Height();

    // do full checks if the chain is in sync behind us
    if (nHeight >= (height - 1))
    {
        // ensure that on a chain requiring earned notarizations, we do not enter new chain roots in the form of
        // accepted notarizations. accepted notarizations can be generated on cross-chain imports, and in that case,
        // may only include proof roots from a prior confirmed notarization.

        // if this is one of the recognized notary chains, the notarizations are "earned" by miners and stakers,
        // if not a notary chain, the currency or chain must have been launched by this chain and notarizations are "accepted"
        // either unquestioningly for notarization protocols other than auto notarization or with auto-notarization
        // requirements
        if (ConnectedChains.notarySystems.count(currentNotarization.currencyID))
        {
            // chain roots may only come from earned notarizations that alternate between staked and mined
            // blocks. accepted notarizations may include chain roots from currently confirmed notarizations
            if (p.evalCode == EVAL_ACCEPTEDNOTARIZATION)
            {
                // if this notarization is not the current chain, but it does have a proof root
                // present, ensure that the proof root accurately reflects the last earned and confirmed notarization
                if (currentNotarization.currencyID != ASSETCHAINS_CHAINID && currentNotarization.proofRoots.count(currentNotarization.currencyID))
                {
                    CTransaction priorNotTx;
                    uint256 hashBlock;
                    if ((currentNotarization.prevNotarization.IsNull() && !currentNotarization.IsDefinitionNotarization()) ||
                        !myGetTransaction(currentNotarization.prevNotarization.hash, priorNotTx, hashBlock))
                    {
                        return state.Error("Invalid prior notarization");
                    }
                    if (currentNotarization.IsDefinitionNotarization())
                    {
                        // let it go and if valid, it will be confirmed
                    }
                    else
                    {
                        // if there is a proof root in this accepted notarization, it must be as part of an import
                        // and the proof root should match the evidence notarization reference used to prove the
                        // import.
                        // TODO: HARDENING - consider that it may never be necessary to have a proof root in import notarizations
                        //
                    }
                }
            }
            else
            {
                // ensure that this earned notarization follows all relevant rules
            }
        }
        else
        {
            // we should only approve accepted notarizations that have the following qualifications
            // for the following protocols:
            // NOTARIZATION_AUTO        -   must have evidence to prove that one recent earned notarization
            //                              from either a PoW or PoS block refers to and proves another alternated
            //                              and proven PoW or PoS earned notarization, which then alternates and proves
            //                              the notarization being confirmed. This allows us to post it, but it must mature
            //                              N blocks without being rejected by the notaries to be considered confirmed.
            // NOTARIZATION_NOTARY_CONFIRM - requires no evidence beyond notary signatures
            // NOTARIZATION_NOTARY_CHAINID - requires no evidence beyond chain signature
        }
    }
    return true;
}

// get and aggregate all evidence from a finalization
std::vector<CNotaryEvidence> CObjectFinalization::GetFinalizationEvidence(const CTransaction &thisTx, CValidationState &state, CTransaction *pOutputTx) const
{
    CTransaction _outputTx;
    CUTXORef fullOutput(output);
    uint256 outputTxBlockHash;
    CTransaction &finalizedTx = pOutputTx ? *pOutputTx : _outputTx;

    if (fullOutput.hash.IsNull())
    {
        fullOutput.hash = thisTx.GetHash();
    }

    if (!GetOutputTransaction(thisTx, finalizedTx, outputTxBlockHash))
    {
        state.Error(std::string(__func__) + ": cannot retrieve output transaction for finalization");
        LogPrint("notarization", "%s: cannot retrieve output transaction for finalization\n", __func__);
        return std::vector<CNotaryEvidence>();
    }

    CPBaaSNotarization notarization;
    std::vector<CNotaryEvidence> evidenceVec;

    COptCCParams p;
    if (!(finalizedTx.vout[output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
          p.vData.size() &&
          (notarization = CPBaaSNotarization(p.vData[0])).IsValid()))
    {
        state.Error(std::string(__func__) + ": invalid notarization output for finalization");
        LogPrint("notarization", "%s: Invalid notarization output for finalization\n", __func__);
        return std::vector<CNotaryEvidence>();
    }

    // collect all evidence, outputs first
    if (evidenceOutputs.size() || evidenceInputs.size())
    {
        CTransaction evidenceTx;

        // add evidence outs as spends to close this entry as well
        int afterMultiPart = evidenceOutputs.size() ? evidenceOutputs[0] : 0;
        for (int i = 0; i < evidenceOutputs.size(); i++)
        {
            auto oneEvidenceOutN = evidenceOutputs[i];
            if (thisTx.vout.size() <= oneEvidenceOutN)
            {
                state.Error(std::string(__func__) + ": indexing error for finalization evidence");
                LogPrint("notarization", "%s: indexing error for finalization evidence\n", __func__);
                return std::vector<CNotaryEvidence>();
            }

            if (oneEvidenceOutN >= afterMultiPart)
            {
                CNotaryEvidence oneEvidenceObj(thisTx, oneEvidenceOutN, afterMultiPart);
                if (oneEvidenceObj.IsValid())
                {
                    evidenceVec.push_back(oneEvidenceObj);
                }
            }
        }

        CTransaction priorOutputTx;
        CNotaryEvidence oneEvidenceObj;
        std::vector<CNotaryEvidence> evidenceInVec;
        CObjectFinalization priorFinalization;
        for (int i = 0; i < evidenceInputs.size(); i++)
        {
            auto oneIn = evidenceInputs[i];
            uint256 hashBlock;
            if (priorOutputTx.GetHash() != thisTx.vin[oneIn].prevout.hash &&
                !myGetTransaction(thisTx.vin[oneIn].prevout.hash, priorOutputTx, hashBlock))
            {
                state.Error(std::string(__func__) + ": cannot access transaction " + thisTx.vin[oneIn].prevout.hash.GetHex() + " for notarization evidence");
                LogPrint("notarization", "%s: cannot access transaction %s for notarization evidence\n", __func__, thisTx.vin[oneIn].prevout.hash.GetHex().c_str());
                return std::vector<CNotaryEvidence>();
            }

            COptCCParams inP;
            if (priorOutputTx.vout[thisTx.vin[oneIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(inP) &&
                inP.IsValid() &&
                inP.evalCode == EVAL_NOTARY_EVIDENCE &&
                inP.vData.size() &&
                (oneEvidenceObj = CNotaryEvidence(inP.vData[0])).IsValid() &&
                oneEvidenceObj.evidence.chainObjects.size())
            {
                // if we are starting a new object, finish the old one
                if (!oneEvidenceObj.IsMultipartProof() ||
                    ((CChainObject<CEvidenceData> *)oneEvidenceObj.evidence.chainObjects[0])->object.md.index == 0)
                {
                    // if we have a composite evidence object, store it and clear the vector
                    if (evidenceInVec.size())
                    {
                        CNotaryEvidence multiPartEvidence(evidenceInVec);
                        if (multiPartEvidence.IsValid())
                        {
                            evidenceVec.push_back(multiPartEvidence);
                        }
                        evidenceInVec.clear();
                    }
                }

                if (!oneEvidenceObj.IsMultipartProof())
                {
                    evidenceVec.push_back(oneEvidenceObj);
                }
                else
                {
                    evidenceInVec.push_back(oneEvidenceObj);
                }
            }
            else if (inP.IsValid() &&
                     inP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                     inP.vData.size() &&
                     (priorFinalization = CObjectFinalization(inP.vData[0])).IsValid())
            {
                // cleanup any pending multipart
                if (evidenceInVec.size())
                {
                    CNotaryEvidence multiPartEvidence(evidenceInVec);
                    if (multiPartEvidence.IsValid())
                    {
                        evidenceVec.push_back(multiPartEvidence);
                    }
                    evidenceInVec.clear();
                }

                CTransaction priorFinalizationTx;
                auto priorFinalizationVec = priorFinalization.GetFinalizationEvidence(priorOutputTx, state, &priorFinalizationTx);

                // TODO: HARDENING - this assumes that evidence inputs for a finalization are consecutive to calculate how to get
                // to the end of the inputs as a result, we MUST enforce that inputs from a prior finalization are consecutive. 
                // they are made that way now, but not yet enforced as of this note.
                if (priorFinalizationVec.size())
                {
                    evidenceVec.insert(evidenceVec.end(), priorFinalizationVec.begin(), priorFinalizationVec.end());
                    i = oneIn + priorFinalization.evidenceOutputs.size() + 1;
                    continue;
                }
            }
        }

        // if we have a composite evidence object, store it and clear the vector
        if (evidenceInVec.size())
        {
            CNotaryEvidence multiPartEvidence(evidenceInVec);
            if (multiPartEvidence.IsValid())
            {
                evidenceVec.push_back(multiPartEvidence);
            }
            else
            {
                state.Error(std::string(__func__) + ": invalid multipart evidence on input");
                LogPrint("notarization", "%s: invalid multipart evidence on input\n", __func__);
                return std::vector<CNotaryEvidence>();
            }
        }
    }
    return evidenceVec;
}

bool PreCheckFinalizeNotarization(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // ensure that if we are finalizing a notarization, we have followed all rules to do so
    // after we precheck and confirm a notarization finalization for a notary chain of this chain, we record it
    // as the last notarized checkpoint and prevent any unwind of the blockchain from that point

    uint32_t chainHeight = chainActive.Height();
    bool haveFullChain = height <= chainHeight + 1;

    auto upgradeVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
    if (upgradeVersion < CActivationHeight::ACTIVATE_VERUSVAULT)
    {
        return true;
    }
    else if (upgradeVersion < CActivationHeight::ACTIVATE_PBAAS)
    {
        return false;
    }

    // ensure that we never accept an invalid proofroot for this chain in a notarization
    COptCCParams p;
    CObjectFinalization currentFinalization;
    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
          p.vData.size() &&
          (currentFinalization = CObjectFinalization(p.vData[0])).IsValid()))
    {
        return state.Error("Invalid finalization for notarization output");
    }

    CTransaction finalizedTx;
    uint256 txBlockHash;
    CPBaaSNotarization notarization;
    std::vector<CNotaryEvidence> evidenceVec;

    if (!(currentFinalization.GetOutputTransaction(tx, finalizedTx, txBlockHash) &&
          finalizedTx.vout[currentFinalization.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
          p.vData.size() &&
          (notarization = CPBaaSNotarization(p.vData[0])).IsValid()))
    {
        if (!haveFullChain)
        {
            return true;
        }
        return state.Error("Invalid notarization output for finalization");
    }

    if (p.evalCode == EVAL_EARNEDNOTARIZATION &&
        !ConnectedChains.notarySystems.count(notarization.currencyID))
    {
        if (!haveFullChain)
        {
            return true;
        }
        return state.Error("Earned notarizations are only valid for notary systems");
    }

    CCurrencyDefinition notaryCurrencyDef = ConnectedChains.GetCachedCurrency(notarization.currencyID);
    if (!notaryCurrencyDef.IsValid())
    {
        return state.Error("Cannot get currency definition for notarization");
    }

    const CCurrencyDefinition *pNotaryCurrency;
    if (IsVerusActive() || !ConnectedChains.notarySystems.count(notaryCurrencyDef.GetID()))
    {
        pNotaryCurrency = &notaryCurrencyDef;
    }
    else
    {
        pNotaryCurrency = &ConnectedChains.thisChain;
    }

    CNativeHashWriter hw(
        (pNotaryCurrency->IsGateway() &&
        pNotaryCurrency->launchSystemID == ASSETCHAINS_CHAINID &&
        pNotaryCurrency->proofProtocol == pNotaryCurrency->PROOF_ETHNOTARIZATION) ? 
            notaryCurrencyDef.PROOF_ETHNOTARIZATION : 
            pNotaryCurrency->PROOF_PBAASMMR);

    if (!notarization.SetMirror(false))
    {
        return state.Error("Cannot prepare notarization to validate finalization");
    }

    hw << notarization;
    uint256 objHash = hw.GetHash();

    CTransaction notarizationTx;

    if (currentFinalization.IsConfirmed())
    {
        // if confirmed, combine and verify all evidence
        // ensure the finalization adheres to the following on-chain rules:

        evidenceVec = currentFinalization.GetFinalizationEvidence(tx, state, &notarizationTx);
        if (state.IsError())
        {
            return false;
        }

        // combine and verify signatures, accepting only evidence from this chain
        std::map<uint160, CNotaryEvidence> evidenceMap;
        auto notarySet = pNotaryCurrency->GetNotarySet();

        // merge accumulated evidence, keeping system separate
        for (auto &e : evidenceVec)
        {
            if (evidenceMap.count(e.systemID))
            {
                evidenceMap[e.systemID].MergeEvidence(e, notarySet);
            }
            else
            {
                evidenceMap[e.systemID] = e;
            }
        }

        if (p.evalCode == EVAL_EARNEDNOTARIZATION)
        {
            if (!ConnectedChains.notarySystems.count(notarization.currencyID))
            {
                return state.Error("insufficient foundation for proof of notary chain");
            }

            // 1) for earned notarizations:
            //  a) Notarization being confirmed must be agreed to by 2 subsequent consecutive notarizations for auto-notarization and
            //     1 for centralized notarization and in all cases, have no interceding disagreements
            //  b) Block height must be at least 1 after last required agreed notarization
            //  c) evidence up to this point on chain must all be spent or output by this transaction and must contain necessary
            //     signatures from valid, unrevoked notaries to confirm, as well as none of the following counter evidence:
            //      i) disagreeing earned notarization between the notarization and the second agreed notarization
            //      ii) other forms of proof that render the to-be-confirmed proof root invalid, such as rejecting signatures
            //          by the confirming IDs that cancel enough confirming, or proof of a more powerful, provably mined and
            //          staked chain since the last notarization
            // 2) for accepted notarizations (see below after else):

            if (!evidenceMap.count(ASSETCHAINS_CHAINID) ||
                evidenceMap[ASSETCHAINS_CHAINID].CheckSignatureConfirmation(objHash,
                                                                            notarySet,
                                                                            pNotaryCurrency->minNotariesConfirm,
                                                                            height) != CNotaryEvidence::STATE_CONFIRMED)
            {
                return state.Error("insufficient evidence for finalization");
            }

            // get simulated notarization data assuming the notarization confirmed, starting from that notarization
            // to now and ensure that we have sufficient earned notarization confirmation

            // ensure that we meet all counter-evidence requirements

            // if we get here, store the verified proof root of this chain as notarized
            ConnectedChains.notarySystems[notarization.currencyID].lastConfirmedNotarization = notarization;
        }
        else
        {
            // accepted notarization
            // 2) for accepted notarizations:
            //  a) Confirmed finalizations must accompany a valid, notary signed, earned notarization with proof and notary
            //     agreement from the other chain.
            //  b) All on-chain evidence will be retrieved to ensure there is none of the following counter evidence:
            //      i) on-chain rejection signatures in blocks prior to this one
            //      ii) IDs revoked that result in less than majority for the confirmation
            //      iii) proof of a more powerful, provably mined/staked chain since the last notarization that is different than
            //           the accepted notarization.

            if (notarization.currencyID != ASSETCHAINS_CHAINID &&
                (notaryCurrencyDef.IsPBaaSChain() || notaryCurrencyDef.IsGateway()) &&
                !notarization.IsPreLaunch() &&
                (notaryCurrencyDef.launchSystemID != ASSETCHAINS_CHAINID ||
                 !evidenceMap.count(notarization.currencyID) ||
                 evidenceMap[notarization.currencyID].CheckSignatureConfirmation(objHash,
                                                                                 notarySet,
                                                                                 pNotaryCurrency->minNotariesConfirm,
                                                                                 height) != CNotaryEvidence::STATE_CONFIRMED))
            {
                return state.Error("insufficient evidence from notary system to accept finalization");
            }
        }
    }
    else if (currentFinalization.IsRejected())
    {
        evidenceVec = currentFinalization.GetFinalizationEvidence(tx, state, &notarizationTx);
        if (state.IsError())
        {
            return false;
        }

        // this is asserting rejection, so we must confirm that it can be rejected and that it only spends
        // inputs that are now invalidated due to the rejection
        if (p.evalCode == EVAL_EARNEDNOTARIZATION)
        {
            // 1) for earned notarizations:
            //  a) disagreeing earned notarization between the notarization and the second agreed notarization
            //  b) other forms of proof that render the to-be-confirmed proof root invalid, such as rejecting signatures
            //     by the confirming IDs that cancel enough confirming, or proof of a more powerful, provably mined and
            //     staked chain since the last notarization
        }
        else
        {
            // 2) for accepted notarizations:
            //  a) Majority on-chain rejection signatures in blocks prior to this one
            //  b) IDs revoked that result in less than majority for the confirmation
            //  c) proof of a more powerful, provably mined/staked chain since the last notarization that is different than
            //     the accepted notarization.
        }
    }
    else
    {
        // TODO: HARDENING - finalization is pending, ensure that it makes sense as a pending finalization, generally,
        // most often, such a finalization is on the same transaction as the notarization it sets as pending
        // then evidence for that notarization is posted, which could be aggregated by a pending finalization,
        // then, when there is enough evidence to pass, it is finalized.
    }

    return true;
}

bool IsAcceptedNotarizationInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_ACCEPTEDNOTARIZATION;
}


// earned notarizations can be spent when finalized as either confirmed or invalidated due to a disagreeing,
// confirmed notarization
bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // TODO: HARDENING ensure that earned notarization UTXOs are spent appropriately
    // the spending transaction must be a finalization that either confirms or invalidates this notarization
    return true;
}

bool IsEarnedNotarizationInput(const CScript &scriptSig)
{
    // this is an output check, and is incorrect. need to change to input
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_EARNEDNOTARIZATION;
}

CObjectFinalization GetOldFinalization(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx=nullptr, uint32_t *pHeight=nullptr);
CObjectFinalization GetOldFinalization(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx, uint32_t *pHeight)
{
    CTransaction _sourceTx;
    CTransaction &sourceTx(pSourceTx ? *pSourceTx : _sourceTx);

    CObjectFinalization oldFinalization;
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
            (p.evalCode == EVAL_FINALIZE_NOTARIZATION || p.evalCode == EVAL_FINALIZE_EXPORT) && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldFinalization = CObjectFinalization(p.vData[0]);
        }
    }
    return oldFinalization;
}


/*
 * Ensures that the finalization, either asserted to be confirmed or rejected, has all signatures and evidence
 * necessary for confirmation.
 */
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // to validate a finalization spend, we need to validate the spender's assertion of confirmation or rejection as proven

    // first, determine our notarization finalization protocol
    CTransaction sourceTx;
    uint32_t oldHeight;
    CObjectFinalization oldFinalization = GetOldFinalization(tx, nIn, &sourceTx, &oldHeight);
    if (!oldFinalization.IsValid())
    {
        return eval->Error("Invalid finalization output");
    }

    // if we are spending a confirmed notarization, then as long as we are being spent by
    // an accepted notarization and have the same confirmation on an output just after a pending output,
    // it is ok
    if (oldFinalization.IsConfirmed())
    {
        int priorPendingFinalization = -1, notarizationOut = -1;
        for (int i = 0; i < tx.vout.size(); i++)
        {
            auto &oneOut = tx.vout[i];

            COptCCParams p;
            CObjectFinalization oneOF;

            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                p.vData.size() &&
                (oneOF = CObjectFinalization(p.vData[0])).IsValid() &&
                oneOF.IsNotarizationFinalization() &&
                oneOF.currencyID == oldFinalization.currencyID &&
                oneOF.IsConfirmed())
            {
                return true;
            }
        }
        if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
        {
            UniValue jsonNTx(UniValue::VOBJ);
            TxToUniv(tx, uint256(), jsonNTx);
            LogPrintf("%s: Invalid spend of confirmed finalization on transaction:\n%s\n", __func__, jsonNTx.write(1,2).c_str());
        }
        return eval->Error("Invalid spend of confirmed finalization to transaction with no confirmed output");
    }

    // get currency to determine system and notarization method
    CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(oldFinalization.currencyID);
    if (!curDef.IsValid())
    {
        return eval->Error("Invalid currency ID in finalization output");
    }
    uint160 SystemID = curDef.GetID();

    // for now, auto notarization uses defined notaries. it can be updated later, while leaving those that
    // select notary confirm explicitly to remain on that protocol
    if (curDef.notarizationProtocol == curDef.NOTARIZATION_NOTARY_CONFIRM || curDef.notarizationProtocol == curDef.NOTARIZATION_AUTO)
    {
        // get the notarization this finalizes and its index output
        int32_t notaryOutNum;
        CTransaction notarizationTx;
        
        if (oldFinalization.output.IsOnSameTransaction())
        {
            notarizationTx = sourceTx;
            // output needs non-null hash below
            oldFinalization.output.hash = notarizationTx.GetHash();
        }
        else
        {
            uint256 blkHash;
            if (!oldFinalization.GetOutputTransaction(sourceTx, notarizationTx, blkHash))
            {
                return eval->Error("notarization-transaction-not-found");
            }
        }
        if (notarizationTx.vout.size() <= oldFinalization.output.n)
        {
            return eval->Error("invalid-finalization");
        }

        CPBaaSNotarization pbn(notarizationTx.vout[oldFinalization.output.n].scriptPubKey);
        if (!pbn.IsValid())
        {
            return eval->Error("invalid-notarization");
        }

        // now, we have an unconfirmed, non-rejected finalization being spent by a transaction
        // confirm that the spender contains one finalization output either correctly confirming or invalidating
        // the finalization. rejection may be implicit by confirming another, later notarization.

        // First. make sure the oldFinalization is not referring to an earlier notarization than the 
        // one most recently confirmed. If so. then it can be spent by anyone.
        CChainNotarizationData cnd;
        if (!GetNotarizationData(SystemID, cnd) || !cnd.IsConfirmed())
        {
            return eval->Error("invalid-notarization");
        }

        CObjectFinalization newFinalization;
        int finalizationOutNum = -1;
        bool foundFinalization = false;
        for (int i = 0; i < tx.vout.size(); i++)
        {
            auto &oneOut = tx.vout[i];
            COptCCParams p;
            // we can accept only one finalization of this notarization as an output, find it and reject more than one

            // TODO: HARDENING - ensure that the output of the finalization we are spending is either a confirmed, earlier
            // output or invalidated alternate to the one we are finalizing
            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                p.vData.size() &&
                (newFinalization = CObjectFinalization(p.vData[0])).IsValid() &&
                newFinalization.currencyID == oldFinalization.currencyID &&
                (newFinalization.IsConfirmed() || newFinalization.output == oldFinalization.output))
            {
                if (foundFinalization)
                {
                    return eval->Error("duplicate-finalization");
                }
                foundFinalization = true;
                finalizationOutNum = i;
            }
        }

        if (!foundFinalization)
        {
            return eval->Error("invalid-finalization-spend");
        }

        // TODO: HARDENING - complete
        // validate both rejection and confirmation
        // in order to finalize confirmation and not just rejection, we need to spend the last
        // confirmed transaction. that means that if this finalization asserts it is confirmed, we must prove it
        if (newFinalization.IsConfirmed())
        {
        }
    }
    return true;
}

bool IsFinalizeNotarizationInput(const CScript &scriptSig)
{
    // this is an output check, and is incorrect. need to change to input
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_FINALIZE_NOTARIZATION;
}

bool CObjectFinalization::GetOutputTransaction(const CTransaction &initialTx, CTransaction &tx, uint256 &blockHash) const
{
    if (output.hash.IsNull())
    {
        tx = initialTx;
        return true;
    }
    else if (myGetTransaction(output.hash, tx, blockHash) && tx.vout.size() > output.n)
    {
        return true;
    }
    return false;
}

// Sign the output object with an ID or signing authority of the ID from the wallet.
CNotaryEvidence CObjectFinalization::SignConfirmed(const std::set<uint160> &notarySet, int minConfirming, const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID, uint32_t signingHeight, CCurrencyDefinition::EProofProtocol hashType) const
{
    CNotaryEvidence retVal = CNotaryEvidence(ASSETCHAINS_CHAINID, output, CNotaryEvidence::STATE_CONFIRMING);

    AssertLockHeld(cs_main);

    CTransaction tx;
    uint256 blockHash;
    if (GetOutputTransaction(initialTx, tx, blockHash))
    {
        retVal.SignConfirmed(notarySet, minConfirming, *pWallet, tx, signatureID, signingHeight, hashType);
    }
    return retVal;
}

CNotaryEvidence CObjectFinalization::SignRejected(const std::set<uint160> &notarySet, int minConfirming, const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID, uint32_t signingHeight, CCurrencyDefinition::EProofProtocol hashType) const
{
    CNotaryEvidence retVal = CNotaryEvidence(ASSETCHAINS_CHAINID, output, CNotaryEvidence::STATE_REJECTING);

    AssertLockHeld(cs_main);

    CTransaction tx;
    uint256 blockHash;
    if (GetOutputTransaction(initialTx, tx, blockHash))
    {
        retVal.SignRejected(notarySet, minConfirming, *pWallet, tx, signatureID, signingHeight, hashType);
    }
    return retVal;
}

// Verify that the output object of "p" is signed appropriately with the indicated signature
// and that the signature is fully authorized to sign
// TODO: THIS SHOULD BE UPDATED TO REFLECT USAGE, WHICH IT DOESN'T YET HAVE
// SPECIFICALLY, THE currencyID, WHICH IS USED, SHOULD BE SEPARATED FROM minimum signatures required
CIdentitySignature::ESignatureVerification CObjectFinalization::VerifyOutputSignature(const CTransaction &initialTx, const std::vector<CNotarySignature> &signatureVec, const COptCCParams &p, uint32_t height) const
{
    CCurrencyDefinition curDef;
    int32_t currencyDefHeight;

    CCurrencyDefinition::EProofProtocol hashType = CCurrencyDefinition::EProofProtocol::PROOF_INVALID;
    for (auto oneSig : signatureVec)
    {
        hashType = oneSig.signatures.size() ? (CCurrencyDefinition::EProofProtocol)oneSig.signatures.begin()->second.hashType : CCurrencyDefinition::EProofProtocol::PROOF_INVALID;
        if (CNativeHashWriter::IsValidHashType(hashType))
        {
            break;
        }
    }
    if (hashType == CCurrencyDefinition::EProofProtocol::PROOF_INVALID)
    {
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    std::map<CIdentityID, CIdentitySignature> confirmedSigs;
    std::map<CIdentityID, CIdentitySignature> rejectedSigs;

    std::set<CIdentityID> completeConfirmedIDs;
    std::set<CIdentityID> partialConfirmedIDs;
    std::set<CIdentityID> completeRejectedIDs;
    std::set<CIdentityID> partialRejectedIDs;

    if (p.IsValid() && 
        p.version >= p.VERSION_V3 && 
        p.vData.size() &&
        GetCurrencyDefinition(currencyID, curDef, &currencyDefHeight) &&
        curDef.IsValid())
    {
        CCurrencyDefinition *pNotaryCurrency;
        if (IsVerusActive() || !ConnectedChains.notarySystems.count(currencyID))
        {
            pNotaryCurrency = &curDef;
        }
        else
        {
            pNotaryCurrency = &ConnectedChains.ThisChain();
        }

        auto notarySet = pNotaryCurrency->GetNotarySet();
        int minNotariesConfirm = pNotaryCurrency->MinimumNotariesConfirm();

        for (auto &oneSigBlock : signatureVec)
        {
            if (oneSigBlock.IsConfirmed())
            {
                for (auto &oneIDSig : oneSigBlock.signatures)
                {
                    if (oneIDSig.second.blockHeight == height)
                    {
                        // merge signatures
                        if (!confirmedSigs.count(oneIDSig.first))
                        {
                            confirmedSigs[oneIDSig.first] = oneIDSig.second;
                        }
                        else
                        {
                            for (auto oneKeySig : oneIDSig.second.signatures)
                            {
                                confirmedSigs[oneIDSig.first].signatures.insert(oneKeySig);
                            }
                        }
                    }
                }
            }
            else
            {
                for (auto &oneIDSig : oneSigBlock.signatures)
                {
                    if (oneIDSig.second.blockHeight == height)
                    {
                        // merge signatures
                        if (!rejectedSigs.count(oneIDSig.first))
                        {
                            rejectedSigs[oneIDSig.first] = oneIDSig.second;
                        }
                        else
                        {
                            for (auto oneKeySig : oneIDSig.second.signatures)
                            {
                                rejectedSigs[oneIDSig.first].signatures.insert(oneKeySig);
                            }
                        }
                    }
                }
            }
        }

        uint256 txId = output.hash.IsNull() ? initialTx.GetHash() : output.hash;
        std::vector<uint160> vdxfCodes = {CCrossChainRPCData::GetConditionID(CNotaryEvidence::NotarySignatureKey(), txId, output.n)};
        std::vector<uint256> statements;

        // check that signature is of the hashed vData[0] data
        CNativeHashWriter hw(hashType);
        hw.write((const char *)&(p.vData[0][0]), p.vData[0].size());
        uint256 msgHash = hw.GetHash();

        for (auto &authorizedSignature : confirmedSigs)
        {
            if (notarySet.count(authorizedSignature.first))
            {
                // we might have a partial or complete signature by one notary here
                const CIdentitySignature &oneIDSig = authorizedSignature.second;

                uint256 sigHash = oneIDSig.IdentitySignatureHash(vdxfCodes, statements, currencyID, height, authorizedSignature.first, "", msgHash);

                // get identity used to sign
                CIdentity signer = CIdentity::LookupIdentity(authorizedSignature.first, height);
                if (signer.IsValid())
                {
                    std::set<uint160> idAddresses;
                    std::set<uint160> verifiedSignatures;

                    for (const CTxDestination &oneAddress : signer.primaryAddresses)
                    {
                        if (oneAddress.which() != COptCCParams::ADDRTYPE_PK || oneAddress.which() != COptCCParams::ADDRTYPE_PKH)
                        {
                            // currently, can only check secp256k1 signatures
                            //return state.Error("Unsupported signature type");
                            return CIdentitySignature::SIGNATURE_INVALID;
                        }
                        idAddresses.insert(GetDestinationID(oneAddress));
                    }

                    for (auto &oneSig : authorizedSignature.second.signatures)
                    {
                        CPubKey pubKey;
                        pubKey.RecoverCompact(sigHash, oneSig);
                        if (!idAddresses.count(pubKey.GetID()))
                        {
                            // invalid signature or ID
                            return CIdentitySignature::SIGNATURE_INVALID;
                        }
                        verifiedSignatures.insert(pubKey.GetID());
                    }
                    if (verifiedSignatures.size() >= signer.minSigs)
                    {
                        completeConfirmedIDs.insert(authorizedSignature.first);
                    }
                    else
                    {
                        partialConfirmedIDs.insert(authorizedSignature.first);
                    }
                }
                else
                {
                    // invalid signing identity in signature
                    return CIdentitySignature::SIGNATURE_INVALID;
                }
            }
        }

        if (completeConfirmedIDs.size() >= curDef.minNotariesConfirm)
        {
            return CIdentitySignature::SIGNATURE_COMPLETE;
        }
        else if (completeConfirmedIDs.size() || partialConfirmedIDs.size())
        {
            return CIdentitySignature::SIGNATURE_PARTIAL;
        }
    }
    // missing or invalid
    return CIdentitySignature::SIGNATURE_INVALID;
}

// Verify that the output object is signed with an authorized signing authority
CIdentitySignature::ESignatureVerification CObjectFinalization::VerifyOutputSignature(const CTransaction &initialTx, const std::vector<CNotarySignature> &signatureVec, uint32_t height) const
{
    // now, get the output to check and check to ensure the signature is good
    CTransaction tx;
    uint256 blkHash;
    COptCCParams p;
    if (GetOutputTransaction(initialTx, tx, blkHash) &&
        tx.vout.size() > output.n &&
        tx.vout[output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.vData.size())
    {
        return VerifyOutputSignature(initialTx, signatureVec, p, height);
    }
    else
    {
        return CIdentitySignature::SIGNATURE_INVALID;
    }
}

// this ensures that the signature is, in fact, both authorized to sign, and also a
// valid signature of the specified output object. if so, this is accepted and
// results in a valid index entry as a confirmation of the notary signature
// all signatures must be from a valid notary, or this returns false and should be
// considered invalid.
// returns the number of valid, unique notary signatures, enabling a single output
// to be sufficient to authorize.
bool ValidateNotarizationEvidence(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height, int &confirmedCount, bool &provenFalse)
{
    // we MUST know that the cs_main lock is held. since it can be held on the validation thread while smart transactions
    // execute, we cannot take it or assert here
    return true;
    /*
    CNotaryEvidence notarySig;
    COptCCParams p;
    CCurrencyDefinition curDef;

    confirmedCount = 0;         // if a unit of evidence, whether signature or otherwise, is validated as confirming
    provenFalse = false;        // if the notarization is proven false

    if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) && 
        p.IsValid() && 
        p.version >= p.VERSION_V3 && 
        p.vData.size() && 
        (notarySig = CNotaryEvidence(p.vData[0])).IsValid() &&
        (curDef = ConnectedChains.GetCachedCurrency(notarySig.systemID)).IsValid())
    {
        // now, get the output to check and ensure the signature is good
        CObjectFinalization of;
        CPBaaSNotarization notarization;
        uint256 notarizationTxId;
        CTransaction nTx;
        uint256 blkHash;
        if (notarySig.output.hash.IsNull() ? (nTx = tx), true : myGetTransaction(notarySig.output.hash, nTx, blkHash) &&
            nTx.vout.size() > notarySig.output.n &&
            nTx.vout[notarySig.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            (p.evalCode == EVAL_FINALIZE_NOTARIZATION) &&
            p.vData.size() &&
            (of = CObjectFinalization(p.vData[0])).IsValid() &&
            of.IsNotarizationFinalization() &&
            of.output.hash.IsNull() ? (nTx = tx), true : myGetTransaction(of.output.hash, nTx, blkHash) &&
            !(notarizationTxId = nTx.GetHash()).IsNull() &&
            nTx.vout.size() > of.output.n &&
            nTx.vout[of.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            (p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
            p.vData.size() &&
            (notarization = CPBaaSNotarization(p.vData[0])).IsValid() &&
            notarization.proofRoots.count(notarySig.systemID))
        {
            // signature is relative only to the notarization, not the finalization
            // that way, the information we put into the vdxfCodes have some meaning beyond
            // the blockchain on which it was signed, and we do not have to carry the
            // finalization mechanism cross-chain.
            std::vector<uint160> vdxfCodes = {CCrossChainRPCData::GetConditionID(notarySig.systemID, 
                                                                                 CNotaryEvidence::NotarySignatureKey(), 
                                                                                 notarizationTxId, 
                                                                                 of.output.n)};
            std::vector<uint256> statements;

            // check that signature is of the hashed vData[0] data
            CNativeHashWriter hw;
            hw.write((const char *)&(p.vData[0][0]), p.vData[0].size());
            uint256 msgHash = hw.GetHash();

            for (auto &authorizedNotary : curDef.notaries)
            {
                std::map<CIdentityID, CIdentitySignature>::iterator sigIt = notarySig.signatures.find(authorizedNotary);
                if (sigIt != notarySig.signatures.end())
                {
                    // get identity used to sign
                    CIdentity signer = CIdentity::LookupIdentity(authorizedNotary, height);
                    uint256 sigHash = sigIt->second.IdentitySignatureHash(vdxfCodes, statements, of.currencyID, height, authorizedNotary, "", msgHash);

                    if (signer.IsValid())
                    {
                        std::set<uint160> idAddresses;
                        std::set<uint160> verifiedSignatures;
                        
                        for (const CTxDestination &oneAddress : signer.primaryAddresses)
                        {
                            if (oneAddress.which() != COptCCParams::ADDRTYPE_PK || oneAddress.which() != COptCCParams::ADDRTYPE_PKH)
                            {
                                // currently, can only check secp256k1 signatures
                                return state.Error("Unsupported signature type");
                            }
                            idAddresses.insert(GetDestinationID(oneAddress));
                        }

                        for (auto &oneSig : notarySig.signatures[authorizedNotary].signatures)
                        {
                            CPubKey pubKey;
                            pubKey.RecoverCompact(sigHash, oneSig);
                            uint160 pkID = pubKey.GetID();
                            if (!idAddresses.count(pkID))
                            {
                                return state.Error("Mismatched pubkey and ID in signature");
                            }
                            if (verifiedSignatures.count(pkID))
                            {
                                return state.Error("Duplicate key use in ID signature");
                            }
                            verifiedSignatures.insert(pkID);
                        }
                        if (verifiedSignatures.size() >= signer.minSigs)
                        {
                            confirmedCount++;
                        }
                        else
                        {
                            return state.Error("Insufficient signatures on behalf of ID: " + signer.name);
                        }
                    }
                    else
                    {
                        return state.Error("Invalid notary identity or corrupt local state");
                    }
                }
                else
                {
                    return state.Error("Unauthorized notary");
                }
            }
        }
        else
        {
            return state.Error("Invalid notarization reference");
        }
    }
    else
    {
        return state.Error("Invalid or non-evidence output");
    }
    
    if (!confirmedCount)
    {
        return state.Error("No evidence present");
    }
    else
    {
        return true;
    }
    */
}

