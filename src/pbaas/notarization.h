/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This defines the public blockchains as a service (PBaaS) notarization protocol, VerusLink.
 * VerusLink is a new distributed consensus protocol that enables multiple public blockchains 
 * to operate as a decentralized ecosystem of chains, which can interact and easily engage in cross 
 * chain transactions.
 * 
 * In all notarization services, there is notarizing chain and a chain paying notarization rewards. They are not the same.
 * The notarizing chain earns the right to submit notarizations onto the paying chain, which uses provable Verus chain power 
 * of each chain combined with a confirmation process to validate the correct version of one chain to another and vice versa.
 * Generally, the paying chain will be Verus, and the notarizing chain will be the PBaaS chain started with a root of Verus 
 * notarization.
 * 
 * On each chain, notarizations spend the output of the prior transaction that spent the notarization output, which has some spending
 * rules that create a thread of one attempted notarization per block, each of them properly representing the current chain, whether 
 * the prior transaction represents a valid representation of the other chain or not. In order to move the notarization forward,
 * it must also be accepted onto the paying chain, then referenced to move confirmed notarization forward again on the current chain. 
 * All notarization threads are started with a chain definition on the paying chain, or at block 1 on the PBaaS chain.
 * 
 * Every notarization besides the chain definition is initiated on the PBaaS chain as an effort to create a notarization that is accepted
 * and confirmed on the paying chain by first being accepted by a Verus miner before a more valuable 
 * notarization is completed and available for acceptance, then being confirmed by multiple cross notarizations.
 * 
 * A notarization submission is earned when a block is won by staking or mining on the PBaaS chain. The miner puts a notarization
 * of the paying chain into the block mined, spending the notarization thread. In order for the miner to have a transaction output to spend from,
 * all PBaaS chains have a block 1 output of a small, transferable amount of Verus, which is only used as a notarization thread.
 * 
 * After "n" blocks, currently 8, from the block won, the earned notarization may be submitted, proving the last notarization and 
 * including an MMR root that is 8 blocks after the asserted winning block, which must also be proven along with at least one staked block. 
 * Once accepted and confirmed, the notarization transaction itself may be used to spend from the pool of notarization rewards, 
 * with an output that pays 50% to the notary and 50% to the block miner/staker recipient on the paying chain.
 *
 * A notarizaton must be either the first in the chain or refer to a prior notarization with which it agrees. If it skips existing
 * notarizations, referring to a prior notarization as valid, that is the same as asserting that the skipped notarizations are invalid.
 * In that case, the notarization and 2 after it must prove one additional block since the notarization skipped.
 * 
 * The intent is to make it extremely improbable cryptographically to achieve full confirmation of any notarization unless an alternate 
 * fork actually represents a valid chain with a majority of combined work and stake, even if more than the majority of notarizers are 
 * attempting to notarize an invalid chain.
 * 
 * to accept an earned notarization as valid on the Verus blockchain, it must prove a transaction on the alternate chain, which is 
 * either the original chain definition transaction, which CAN and MUST be proven ONLY in block 1, or the latest notarization transaction 
 * on the alternate chain that represents an accurate MMR for the accepting chain.
 * In addition, any accepted notarization must fullfill the following requirements:
 * 1) Must prove either a PoS block from the alternate chain or a merge mined
 *    block that is owned by the submitter and exactly 8 blocks behind the submitted MMR, which is used for proof.
 * 2) must prove a chain definition tx and be block 1 or contain a notarization tx, which asserts a previous, valid MMR for this
 *    chain and properly proves objects using that MMR, as well as has the proper notarization thread inputs and outputs.
 * 3) must spend the notarization thread to the specified chainID in a fee free transaction with notarization thread input and output
 * 
 * to agree with a previous notarization, we must:
 * 1) agree that at the indicated block height, the MMR root is the root claimed, and is a correct representation of the best chain.
 * 
 */

#ifndef PBAAS_NOTARIZATION_H
#define PBAAS_NOTARIZATION_H

#include "key_io.h"
#include "pbaas/pbaas.h"

class CObjectFinalization
{
public:
    static const int32_t UNCONFIRMED_INPUT = -1;
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1
    };

    enum EFinalizationType {
        FINALIZE_INVALID = 0,
        FINALIZE_NOTARIZATION = 1,      // confirmed when notarization is deemed correct / final
        FINALIZE_EXPORT = 2,            // confirmed when export has no more work to do
        FINALIZE_CURRENCY_LAUNCH = 4,   // confirmed on successful currency launch, rejected on refund
        FINALIZE_REJECTED = 0x40,       // flag set when confirmation is rejected and/or proven false
        FINALIZE_CONFIRMED = 0x80,      // flag set when object finalization is confirmed
        FINALIZE_TYPE_MASK = ~(FINALIZE_REJECTED | FINALIZE_CONFIRMED)
    };

    uint8_t version;
    uint8_t finalizationType;
    uint32_t minFinalizationHeight;     // to enable indexing/querying potential finalizations by height
    uint160 currencyID;                 // here when needed for indexing purposes
    CUTXORef output;                    // output/object to finalize
    std::vector<int32_t> evidenceInputs; // indexes into vin that are evidence to support the current state
    std::vector<int32_t> evidenceOutputs; // tx output indexes that are evidence to support the current state    

    CObjectFinalization() : version(VERSION_INVALID), finalizationType(FINALIZE_INVALID) {}
    CObjectFinalization(uint8_t fType, const uint160 &curID, const uint256 &TxId, uint32_t outNum, uint32_t minFinalHeight=0) : 
        version(VERSION_CURRENT), finalizationType(fType), minFinalizationHeight(minFinalHeight), currencyID(curID), output(TxId, outNum) {}
    CObjectFinalization(const std::vector<unsigned char> &vch)
    {
        ::FromVector(vch, *this);
    }
    CObjectFinalization(const CTransaction &tx, uint32_t *pEcode=nullptr, int32_t *pFinalizationOutNum=nullptr);
    CObjectFinalization(const CScript &script);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(finalizationType);
        READWRITE(currencyID);
        READWRITE(output);
        if (IsConfirmed() || IsRejected())
        {
            READWRITE(evidenceInputs);
            READWRITE(evidenceOutputs);
        }
    }

    bool IsValid() const
    {
        return version >= VERSION_FIRST && 
                version <= VERSION_LAST &&
                finalizationType != FINALIZE_INVALID && 
                !currencyID.IsNull() &&
                output.IsValid();
    }

    EFinalizationType FinalizationType() const
    {
        return (EFinalizationType)(finalizationType & FINALIZE_TYPE_MASK);
    }

    bool IsPending() const
    {
        return !(finalizationType & FINALIZE_REJECTED || finalizationType & FINALIZE_CONFIRMED);
    }

    bool IsConfirmed() const
    {
        return finalizationType & FINALIZE_CONFIRMED;
    }

    void SetConfirmed(bool setTrue=true)
    {
        if (setTrue)
        {
            SetRejected(false);
            finalizationType |= FINALIZE_CONFIRMED;
        }
        else
        {
            finalizationType &= ~FINALIZE_CONFIRMED;
        }
    }

    bool IsRejected() const
    {
        return finalizationType & FINALIZE_REJECTED;
    }

    void SetRejected(bool setTrue=true)
    {
        if (setTrue)
        {
            SetConfirmed(false);
            finalizationType |= FINALIZE_REJECTED;
        }
        else
        {
            finalizationType &= ~FINALIZE_REJECTED;
        }
    }

    bool IsLaunchFinalization() const
    {
        return (finalizationType & FINALIZE_TYPE_MASK) == FINALIZE_CURRENCY_LAUNCH;
    }

    bool IsExportFinalization() const
    {
        return (finalizationType & FINALIZE_TYPE_MASK) == FINALIZE_EXPORT;
    }

    bool IsNotarizationFinalization() const
    {
        return (finalizationType & FINALIZE_TYPE_MASK) == FINALIZE_NOTARIZATION;
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool GetOutputTransaction(const CTransaction &initialTx, CTransaction &tx, uint256 &blockHash) const;

    // Sign the output object with an ID or signing authority of the ID from the wallet.
    CNotaryEvidence SignConfirmed(const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID, CCurrencyDefinition::EProofProtocol hashType) const;
    CNotaryEvidence SignRejected(const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID, CCurrencyDefinition::EProofProtocol hashType) const;

    // Verify that the output object is signed with an ID or signing authority of the ID from the wallet.
    CIdentitySignature::ESignatureVerification VerifyOutputSignature(const CTransaction &initialTx, const CNotaryEvidence &signature, const COptCCParams &p, uint32_t height) const;
    CIdentitySignature::ESignatureVerification VerifyOutputSignature(const CTransaction &initialTx, const CNotaryEvidence &signature, uint32_t height) const;

    static std::vector<std::pair<uint32_t, CInputDescriptor>> GetUnspentConfirmedFinalizations(const uint160 &currencyID);
    static std::vector<std::pair<uint32_t, CInputDescriptor>> GetUnspentPendingFinalizations(const uint160 &currencyID);
    static std::vector<std::pair<uint32_t, CInputDescriptor>> GetUnspentEvidence(const uint160 &currencyID,
                                                                                 const uint256 &notarizationTxId,
                                                                                 int32_t notarizationOutNum);

    // enables easily finding all pending finalizations for a
    // currency, either notarizations or exports
    static std::string ObjectFinalizationPendingKeyName()
    {
        return "vrsc::system.finalization.pending";
    }

    // enables easily finding all pending finalizations for a
    // currency, either notarizations or exports
    static std::string ObjectFinalizationPrelaunchKeyName()
    {
        return "vrsc::system.finalization.prelaunch";
    }

    // enables easily finding all pending finalizations for a
    // currency, either notarizations or exports
    static std::string ObjectFinalizationNotarizationKeyName()
    {
        return "vrsc::system.finalization.notarization";
    }

    // enables easily finding all pending finalizations for a
    // currency, either notarizations or exports
    static std::string ObjectFinalizationExportKeyName()
    {
        return "vrsc::system.finalization.export";
    }

    // enables easily finding all confirmed finalizations
    static std::string ObjectFinalizationConfirmedKeyName()
    {
        return "vrsc::system.finalization.confirmed";
    }

    // enables location of rejected finalizations
    static std::string ObjectFinalizationRejectedKeyName()
    {
        return "vrsc::system.finalization.rejected";
    }

    static uint160 ObjectFinalizationPendingKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationPendingKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationPrelaunchKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationPrelaunchKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationNotarizationKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationExportKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationExportKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationConfirmedKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationConfirmedKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationRejectedKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationRejectedKeyName(), nameSpace);
        return key;
    }

    UniValue ToUniValue() const;
};

class CChainNotarizationData
{
public:
    static const int CURRENT_VERSION = PBAAS_VERSION;
    uint32_t version;

    std::vector<std::pair<CUTXORef, CPBaaSNotarization>> vtx;
    int32_t lastConfirmed;                          // last confirmed notarization
    std::vector<std::vector<int32_t>> forks;        // chains that represent alternate branches from the last confirmed notarization
    int32_t bestChain;                              // index in forks of the chain, beginning with the last confirmed notarization, that has the most power

    CChainNotarizationData() : version(0), lastConfirmed(-1) {}

    CChainNotarizationData(const std::vector<std::pair<CUTXORef, CPBaaSNotarization>> &txes,
                           int32_t lastConf=-1,
                           const std::vector<std::vector<int32_t>> &Forks=std::vector<std::vector<int32_t>>(),
                           int32_t Best=-1, 
                           uint32_t ver=CURRENT_VERSION) : 
                           version(ver),
                           vtx(txes), 
                           lastConfirmed(lastConf), 
                           bestChain(Best), 
                           forks(Forks) {}

    CChainNotarizationData(std::vector<unsigned char> vch)
    {
        ::FromVector(vch, *this);
    }

    CChainNotarizationData(UniValue &obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(vtx);
        READWRITE(bestChain);
        READWRITE(lastConfirmed);
        READWRITE(forks);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        // this needs an actual check
        return version != 0;
    }

    bool IsConfirmed() const
    {
        return lastConfirmed != -1;
    }

    UniValue ToUniValue() const;
};

std::vector<CNodeData> GetGoodNodes(int maxNum=CCurrencyDefinition::MAX_STARTUP_NODES);
bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsEarnedNotarizationInput(const CScript &scriptSig);
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsAcceptedNotarizationInput(const CScript &scriptSig);
bool PreCheckAcceptedOrEarnedNotarization(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsFinalizeNotarizationInput(const CScript &scriptSig);
bool IsNotaryEvidenceInput(const CScript &scriptSig);
extern string PBAAS_HOST, PBAAS_USERPASS, ASSETCHAINS_RPCHOST, ASSETCHAINS_RPCCREDENTIALS;;
extern int32_t PBAAS_PORT;

#endif
