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
        FINALIZE_NOTARIZATION = 1,      // confirmed with FINALIZE_CONFIRMED when notarization is deemed correct / final
        FINALIZE_EXPORT = 2,            // confirmed when export has no more work to do
        FINALIZE_CHALLENGES = 0x08,     // flag set when this is a challenge of an existing notarization
        FINALIZE_INVALIDATES = 0x10,    // flag set when this challenge invalidates what it is challenging
        FINALIZE_MOREPOWERFUL = 0x20,   // flag set when this is a challenge that is more powerful than what it is challenging
        FINALIZE_REJECTED = 0x40,       // flag set when confirmation is rejected and/or proven false
        FINALIZE_CONFIRMED = 0x80,      // flag set when object finalization is confirmed
        FINALIZE_TYPE_MASK = ~(FINALIZE_REJECTED | FINALIZE_CONFIRMED | FINALIZE_MOREPOWERFUL)
    };

    uint8_t version;
    uint8_t finalizationType;
    uint32_t minFinalizationHeight;     // to enable indexing/querying potential finalizations by height
    uint160 currencyID;                 // here when needed for indexing purposes
    CUTXORef output;                    // output/object to finalize
    std::vector<int32_t> evidenceInputs; // indexes into vin that are evidence to support the current state
    std::vector<int32_t> evidenceOutputs; // tx output indexes that are evidence to support the current state

    CObjectFinalization(uint8_t Version=VERSION_INVALID) : version(Version), finalizationType(FINALIZE_INVALID), minFinalizationHeight(0) {}
    CObjectFinalization(uint8_t fType, const uint160 &curID, const uint256 &TxId, uint32_t outNum, uint32_t minFinalHeight=0, uint8_t Version=VERSION_CURRENT) :
        version(Version), finalizationType(fType), minFinalizationHeight(minFinalHeight), currencyID(curID), output(TxId, outNum) {}
    CObjectFinalization(const std::vector<unsigned char> &vch)
    {
        ::FromVector(vch, *this);
    }
    CObjectFinalization(const CTransaction &tx, uint32_t *pEcode=nullptr, int32_t *pFinalizationOutNum=nullptr, uint32_t minFinalHeight=0, uint8_t Version=VERSION_CURRENT);
    CObjectFinalization(const CScript &script);
    CObjectFinalization(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(finalizationType);
        READWRITE(currencyID);
        READWRITE(output);
        READWRITE(evidenceInputs);
        READWRITE(evidenceOutputs);
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

    bool IsChallenge() const
    {
        return finalizationType & FINALIZE_CHALLENGES;
    }

    void SetChallenge(bool setTrue=true)
    {
        if (setTrue)
        {
            SetConfirmed(false);
            finalizationType |= FINALIZE_CHALLENGES;
        }
        else
        {
            finalizationType &= ~FINALIZE_CHALLENGES;
        }
    }

    bool IsMorePowerful() const
    {
        return finalizationType & FINALIZE_MOREPOWERFUL;
    }

    void SetMorePowerful(bool setTrue=true)
    {
        if (setTrue)
        {
            SetConfirmed(false);
            finalizationType |= FINALIZE_MOREPOWERFUL;
        }
        else
        {
            finalizationType &= ~FINALIZE_MOREPOWERFUL;
        }
    }

    bool Invalidates() const
    {
        return finalizationType & FINALIZE_INVALIDATES;
    }

    void SetInvalidates(bool setTrue=true)
    {
        if (setTrue)
        {
            SetConfirmed(false);
            finalizationType |= FINALIZE_INVALIDATES;
        }
        else
        {
            finalizationType &= ~FINALIZE_INVALIDATES;
        }
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

    bool GetOutputTransaction(const CTransaction &initialTx, CTransaction &tx, uint256 &blockHash, bool checkMempool=true) const;
    std::vector<std::pair<CObjectFinalization, CNotaryEvidence>>
        GetFinalizationEvidence(const CTransaction &thisTx, int32_t outputNum, CValidationState &state, CTransaction *pOutputTx=nullptr) const;

    // Sign the output object with an ID or signing authority of the ID from the wallet.
    CNotaryEvidence SignConfirmed(const std::set<uint160> &notarySet, int minConfirming, const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID, uint32_t signingHeight, CCurrencyDefinition::EHashTypes hashType, CNotaryEvidence *pNewSignatureEvidence=nullptr) const;
    CNotaryEvidence SignRejected(const std::set<uint160> &notarySet, int minConfirming, const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID, uint32_t signingHeight, CCurrencyDefinition::EHashTypes hashType, CNotaryEvidence *pNewSignatureEvidence=nullptr) const;

    static std::vector<std::pair<uint32_t, CInputDescriptor>> GetUnspentConfirmedFinalizations(const uint160 &currencyID);
    static std::vector<std::pair<uint32_t, CInputDescriptor>> GetUnspentPendingFinalizations(const uint160 &currencyID);
    static std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>>
        GetFinalizations(const uint160 &currencyID, const uint160 &finalizationTypeKey, uint32_t startHeight=0, uint32_t endHeight=0);

    static std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>>
        GetFinalizations(const CUTXORef &outputRef, const uint160 &finalizationTypeKey, uint32_t startHeight=0, uint32_t endHeight=0);

    static bool GetPendingEvidence(const CCurrencyDefinition &externalSystem,
                                   const CUTXORef &notarizationRef,
                                   uint32_t untilHeight,
                                   std::vector<std::pair<bool, CProofRoot>> &validCounterRoots,
                                   CProofRoot &challengeStartRoot,
                                   std::vector<CInputDescriptor> &outputs,
                                   bool &invalidates,
                                   CValidationState &state);

    static std::vector<std::pair<uint32_t, CInputDescriptor>> GetUnspentEvidence(const uint160 &currencyID,
                                                                                 const uint256 &notarizationTxId,
                                                                                 int32_t notarizationOutNum);

    static std::string FinalizationMorePowerfulKeyName()
    {
        return "vrsc::system.finalization.morepowerful";
    }

    static std::string FinalizationInvalidatesKeyName()
    {
        return "vrsc::system.finalization.invalidates";
    }

    static std::string FinalizationIsChallengeKeyName()
    {
        return "vrsc::system.finalization.ischallenge";
    }

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

    // enables easily finding all confirmed finalizations
    static std::string ObjectFinalizationFinalizedKeyName()
    {
        return "vrsc::system.finalization.finalized";
    }

    // enables location of rejected finalizations
    static std::string ObjectFinalizationRejectedKeyName()
    {
        return "vrsc::system.finalization.rejected";
    }

    static uint160 FinalizationMorePowerfulKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(FinalizationMorePowerfulKeyName(), nameSpace);
        return key;
    }

    static uint160 FinalizationInvalidatesKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(FinalizationInvalidatesKeyName(), nameSpace);
        return key;
    }

    static uint160 FinalizationIsChallengeKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(FinalizationIsChallengeKeyName(), nameSpace);
        return key;
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

    static uint160 ObjectFinalizationFinalizedKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationFinalizedKeyName(), nameSpace);
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

class CPrimaryProofDescriptor
{
public:
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = VERSION_LAST
    };

    uint32_t version;
    std::vector<CUTXORef> challengeOutputs;

    CPrimaryProofDescriptor(uint32_t Version=VERSION_INVALID) : version(Version) {}

    CPrimaryProofDescriptor(const std::vector<CUTXORef> &ChallengeOutputs,
                            uint32_t Version=VERSION_CURRENT) :
                            version(Version), challengeOutputs(ChallengeOutputs) {}

    CPrimaryProofDescriptor(std::vector<unsigned char> vch)
    {
        ::FromVector(vch, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        int vecSize = challengeOutputs.size();
        READWRITE(VARINT(vecSize));
        if (challengeOutputs.size() != vecSize)
        {
            challengeOutputs.resize(vecSize);
        }
        for (auto &oneElem : challengeOutputs)
        {
            READWRITE(oneElem);
        }
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return version >= VERSION_FIRST && version <= VERSION_LAST;
    }
};

class CChainNotarizationData
{
public:
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        CURRENT_VERSION = VERSION_LAST
    };
    uint32_t version;

    std::vector<std::pair<CUTXORef, CPBaaSNotarization>> vtx;
    int32_t lastConfirmed;                          // last confirmed notarization
    std::vector<std::vector<int32_t>> forks;        // chains that represent alternate branches from the last confirmed notarization
    int32_t bestChain;                              // index in forks of the chain, beginning with the last confirmed notarization, that has the most power

    CChainNotarizationData(uint32_t Version=VERSION_INVALID) : version(Version), lastConfirmed(-1), bestChain(-1) {}

    CChainNotarizationData(const std::vector<std::pair<CUTXORef, CPBaaSNotarization>> &notarizations,
                           int32_t lastConf=-1,
                           const std::vector<std::vector<int32_t>> &Forks=std::vector<std::vector<int32_t>>(),
                           int32_t Best=-1,
                           uint32_t ver=CURRENT_VERSION) :
                           version(ver),
                           vtx(notarizations),
                           lastConfirmed(lastConf),
                           bestChain(Best),
                           forks(Forks) {}

    CChainNotarizationData(std::vector<unsigned char> vch)
    {
        ::FromVector(vch, *this);
    }

    CChainNotarizationData(UniValue &obj,
                           bool loadNotarizations=false,
                           std::vector<uint256> *pBlockHash=nullptr,
                           std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> *pCounterEvidence=nullptr,
                           std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> *pEvidence=nullptr);

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
        return version >= VERSION_FIRST && version <= VERSION_LAST &&
               ((!vtx.size() && !forks.size()) || (vtx.size() && forks.size()));
    }

    bool IsConfirmed() const
    {
        return lastConfirmed != -1;
    }

    void SetBestChain(const CCurrencyDefinition &fromChainDef,
                      const std::vector<std::pair<CTransaction, uint256>> &txesAndBlocks);

    bool CorrelatedFinalizationSpends(const std::vector<std::pair<CTransaction, uint256>> &txes,
                                      std::vector<std::vector<CInputDescriptor>> &spendsToClose,
                                      std::vector<CInputDescriptor> &extraSpends,
                                      std::vector<std::vector<CNotaryEvidence>> *pEvidenceSpends=nullptr) const;

    bool CalculateConfirmation(int confirmingIdx, std::set<int> &confirmedOutputNums, std::set<int> &invalidatedOutputNums) const;

    // returns the best notarization with a minimum of minNotaryConfirms confirmations by later earned notarizations
    // without conflicts in agreement. calls out, so should not be called holding locks. returns -1 if none found.
    int BestConfirmedNotarization(const CCurrencyDefinition &notarizingSystem,
                                  int minNotaryConfirms,
                                  int minBlockConfirms,
                                  uint32_t height,
                                  uint32_t lastConfirmedHeight,
                                  const std::vector<std::pair<CTransaction, uint256>> &txAndBlockVec) const;

    UniValue ToUniValue(const std::vector<std::pair<CTransaction, uint256>> &transactionsAndBlockHash=std::vector<std::pair<CTransaction, uint256>>(),
                        const std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> &counterEvidence=
                            std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>>(),
                        const std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> &evidence=
                            std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>>()) const;
};

std::vector<CNodeData> GetGoodNodes(int maxNum=CCurrencyDefinition::MAX_STARTUP_NODES);
std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> GetLastConfirmedNotarization(uint160 curID, uint32_t height);
std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> GetPriorReferencedNotarization(const CTransaction &tx,
                                                                                                int32_t notarizationOut,
                                                                                                const CPBaaSNotarization &notarization);
bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsEarnedNotarizationInput(const CScript &scriptSig);
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsAcceptedNotarizationInput(const CScript &scriptSig);
bool PreCheckAcceptedOrEarnedNotarization(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool PreCheckFinalizeNotarization(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool PreCheckNotaryEvidence(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsFinalizeNotarizationInput(const CScript &scriptSig);
bool IsNotaryEvidenceInput(const CScript &scriptSig);
std::vector<unsigned char> CreatePoSBlockProof(ChainMerkleMountainView &mmrView,
                                               const CBlock &checkBlock,
                                               const CTransaction &stakeSource,
                                               int outNum,
                                               uint32_t sourceBlockNum,
                                               uint32_t height);
bool ProvePosBlock(uint32_t lastProofRootHeight, const CBlockIndex *pindex, CNotaryEvidence &evidence, CValidationState &state, int32_t *proofSize=nullptr);
std::vector<__uint128_t> GetBlockCommitments(uint32_t lastNotarizationHeight, uint32_t currentNotarizationHeight, const uint256 &entropy);

CProofRoot IsValidChallengeEvidence(const CCurrencyDefinition &externalSystem,
                                    const CProofRoot &defaultProofRoot,
                                    const CNotaryEvidence &e,
                                    const uint256 &entropyHash,
                                    bool &invalidates,
                                    CProofRoot &challengeStartRoot,
                                    uint32_t height);
CPBaaSNotarization IsValidPrimaryChainEvidence(const CCurrencyDefinition &externalSystem,
                                               const CNotaryEvidence &evidence,
                                               const CPBaaSNotarization &expectedNotarization,
                                               uint32_t lastConfirmedHeight,
                                               uint32_t height,
                                               uint256 *pOptEntropyHash=nullptr, // only needed when responding to a challenge
                                               const CProofRoot &challengeProofRoot=CProofRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID));
extern string PBAAS_HOST, PBAAS_USERPASS, ASSETCHAINS_RPCHOST, ASSETCHAINS_RPCCREDENTIALS;;
extern int32_t PBAAS_PORT;

#endif
