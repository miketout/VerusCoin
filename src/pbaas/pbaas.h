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
 * 
 */

#ifndef PBAAS_H
#define PBAAS_H

#include <vector>
#include <univalue.h>

#include "cc/CCinclude.h"
#include "streams.h"
#include "script/script.h"
#include "amount.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/reserves.h"
#include "mmr.h"

#include <boost/algorithm/string.hpp>

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex, bool fIncludeAsm=true);

class CPBaaSNotarization;
class TransactionBuilder;

// these are output cryptoconditions for the Verus reserve liquidity system
// VRSC can be proxied to other PBaaS chains and sent back for use with this system
// The assumption that Verus is either the proxy on the PBaaS chain or the native
// coin on Verus enables us to reduce data requirements systemwide

// this is for transaction outputs with a Verus proxy on a PBaaS chain cryptoconditions with these outputs
// must also be funded with the native chain for fees, unless the chain is a Verus reserve chain, in which
// case the fee will be autoconverted from the Verus proxy through the conversion rules of this chain

static const uint32_t PBAAS_NODESPERNOTARIZATION = 2;       // number of nodes to reference in each notarization
static const int64_t PBAAS_MINNOTARIZATIONOUTPUT = 10000;   // enough for one fee worth to finalization and notarization thread
static const int32_t PBAAS_MINSTARTBLOCKDELTA = 50;         // minimum number of blocks to wait for starting a chain after definition
static const int32_t PBAAS_MAXPRIORBLOCKS = 16;             // maximum prior block commitments to include in prior blocks chain object

// This data structure is used on an output that provides proof of stake validation for other crypto conditions
// with rate limited spends based on a PoS contest
class CPoSSelector
{
public:
    uint32_t nBits;                         // PoS difficulty target
    uint32_t nTargetSpacing;                // number of 1/1000ths of a block between selections (e.g. 1 == 1000 selections per block)

    CPoSSelector(uint32_t bits, uint32_t TargetSpacing)
    {
        nBits = bits; 
        nTargetSpacing = TargetSpacing;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBits);
        READWRITE(nTargetSpacing);
    }

    CPoSSelector(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return nBits != 0;
    }
};

class CInputDescriptor
{
public:
    CScript scriptPubKey;
    CAmount nValue;
    CTxIn txIn;
    CInputDescriptor() : nValue(0) {}
    CInputDescriptor(CScript script, CAmount value, CTxIn input) : scriptPubKey(script), nValue(value), txIn(input) {}
    bool operator<(const CInputDescriptor &op) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(scriptPubKey);
        READWRITE(nValue);
        READWRITE(txIn);
    }
};

class CRPCChainData
{
public:
    CCurrencyDefinition chainDefinition;    // chain information for the specific chain
    std::string     rpcHost;                // host of the chain's daemon
    int32_t         rpcPort;                // port of the chain's daemon
    std::string     rpcUserPass;            // user and password for this daemon
    int64_t         lastConnectTime;        // set whenever we check valid

    CRPCChainData() {}
    CRPCChainData(CCurrencyDefinition &chainDef, std::string host, int32_t port, std::string userPass) :
        chainDefinition(chainDef), rpcHost{host}, rpcPort(port), rpcUserPass(userPass), lastConnectTime(0) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainDefinition);
        READWRITE(rpcHost);
        READWRITE(rpcPort);
        READWRITE(rpcUserPass);
        READWRITE(lastConnectTime);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return chainDefinition.IsValid();
    }

    int64_t SetLastConnection(int64_t setTime)
    {
        return (lastConnectTime = setTime);
    }

    int64_t LastConnectionTime() const
    {
        return lastConnectTime;
    }

    uint160 GetID() const
    {
        return chainDefinition.GetID();
    }
};

// Each merge mined chain gets an entry that includes information required to connect to a live daemon
// for that block, cross notarize, and validate notarizations.
class CPBaaSMergeMinedChainData : public CRPCChainData
{
public:
    CBlock          block;                  // full block to submit upon winning header

    CPBaaSMergeMinedChainData() {}
    CPBaaSMergeMinedChainData(CCurrencyDefinition &chainDef, std::string host, int32_t port, std::string userPass, CBlock &blk) :
        CRPCChainData(chainDef, host, port, userPass), block(blk) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainDefinition);
        READWRITE(rpcHost);
        READWRITE(rpcPort);
        READWRITE(rpcUserPass);
        READWRITE(block);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }
};

class CGateway
{
public:
    virtual bool ValidateDestination(const std::string &destination) const = 0;
    virtual CTransferDestination ToTransferDestination(const std::string &destination) const = 0;
    virtual std::set<uint160> FeeCurrencies() const = 0;
    virtual uint160 GatewayID() const = 0;
};

class CEthGateway : public CGateway
{
public:
    virtual bool ValidateDestination(const std::string &destination) const;
    virtual CTransferDestination ToTransferDestination(const std::string &destination) const;
    virtual std::set<uint160> FeeCurrencies() const;
    virtual uint160 GatewayID() const;
};

class CObjectFinalization;

// This is the data for a PBaaS notarization transaction, either of a PBaaS chain into the Verus chain, or the Verus
// chain into a PBaaS chain.

// Part of a transaction with an opret that contains only the hashes and proofs, without the source
// headers, transactions, and objects. This type of notarizatoin is mined into a block by the miner, and is created on the PBaaS
// chain.
//
// Notarizations include the following elements in order:
//  Latest block header being notarized, or a header ref for a merge-mined header
//  Proof of the header using the latest MMR root
//  Cross notarization transaction less its op_ret
//  Proof of the cross notarization using the latest MMR root
class CPBaaSNotarization
{
public:
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1,
        FINAL_CONFIRMATIONS = 9,
        DEFAULT_NOTARIZATION_FEE = 10000,               // price of a notarization fee in native or launch system currency
        BLOCK_NOTARIZATION_MODULO = 10,                 // incentive to earn one valid notarization during this many blocks
        MIN_BLOCKS_BEFORE_NOTARY_FINALIZED = 15,        // 15 blocks must go by before notary signatures or confirming evidence can be provided
        MAX_NOTARIZATION_CONVERSION_PRICING_INTERVAL = 100,  // there must be a notarization with conversion at least 100 blocks before reserve transfer
        MAX_NODES = 2,                                  // only provide 2 nodes per notarization
        MIN_NOTARIZATION_OUTPUT = 0,                    // minimum amount for notarization output
    };
    //static const int FINAL_CONFIRMATIONS = 10;
    //static const int MIN_BLOCKS_BETWEEN_NOTARIZATIONS = 8;

    enum FLAGS
    {
        FLAGS_NONE = 0,
        FLAG_DEFINITION_NOTARIZATION = 1,   // initial notarization on definition of currency/system/chain
        FLAG_PRE_LAUNCH = 2,                // pre-launch notarization
        FLAG_START_NOTARIZATION = 4,        // first notarization after pre-launch
        FLAG_LAUNCH_CONFIRMED = 8,
        FLAG_REFUNDING = 0x10,
        FLAG_ACCEPTED_MIRROR = 0x20,        // if this is set, this notarization is a mirror of an earned notarization on another chain
        FLAG_BLOCKONE_NOTARIZATION = 0x40,  // block 1 notarizations are auto-finalized, the blockchain itself will be worthless if it is wrong
        FLAG_SAME_CHAIN = 0x80,             // set if all currency information is verifiable on this chain
        FLAG_LAUNCH_COMPLETE = 0x100        // set if all currency information is verifiable on this chain
    };

    uint32_t nVersion;
    uint32_t flags;                         // notarization options
    CTransferDestination proposer;          // paid when this gets used on import (miner/staker, shares this with 1 notary for each validation)

    uint160 currencyID;                     // the primary currency this notarization represents for the system, may be gateway or external chain
    uint32_t notarizationHeight;            // <= height on the current system as of this notarization (can't be confirmed earlier)
    CCoinbaseCurrencyState currencyState;   // state of the currency being notarized as of this notarization

    CUTXORef prevNotarization;              // reference of the prior notarization on this system with which we agree
    uint256 hashPrevCrossNotarization;      // (this is not the same notarization as the prev notarization or prev height)
                                            //  it is the hash of the prior notarization on the other chain with which we agree, even one not yet confirmed
    uint32_t prevHeight;                    // height of previous notarization we agree with

    std::map<uint160, CCoinbaseCurrencyState> currencyStates; // currency state of other currencies to be co-notarized for gateways
    std::map<uint160, CProofRoot> proofRoots; // if cross-chain notarization, includes valid proof root of systemID at notarizationHeight + others verified

    std::vector<CNodeData> nodes;           // if cross chain notarization, network nodes

    CPBaaSNotarization() : nVersion(PBAAS_VERSION_INVALID), flags(0), notarizationHeight(0), prevHeight(0) {}

    CPBaaSNotarization(const uint160 &currencyid,
                       const CCoinbaseCurrencyState CurrencyState,
                       uint32_t height,
                       const CUTXORef &prevnotarization,
                       uint32_t prevheight,
                       const std::vector<CNodeData> &Nodes=std::vector<CNodeData>(),
                       const std::map<uint160, CCoinbaseCurrencyState> &CurrencyStates=std::map<uint160, CCoinbaseCurrencyState>(),
                       const CTransferDestination &Proposer=CTransferDestination(),
                       const std::map<uint160, CProofRoot> &ProofRoots=std::map<uint160, CProofRoot>(),
                       uint32_t version=VERSION_CURRENT,
                       uint32_t Flags=FLAGS_NONE) : 
                       nVersion(version),
                       flags(Flags),
                       proposer(Proposer),
                       currencyID(currencyid),
                       notarizationHeight(height),
                       currencyState(CurrencyState),
                       prevNotarization(prevnotarization),
                       prevHeight(prevheight),
                       currencyStates(CurrencyStates),
                       proofRoots(ProofRoots),
                       nodes(Nodes)
    {
    }

    CPBaaSNotarization(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CPBaaSNotarization(const CTransaction &tx, int32_t *pOutIdx=nullptr);

    CPBaaSNotarization(const CScript &scriptPubKey);

    CPBaaSNotarization(const UniValue &obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nVersion));
        READWRITE(VARINT(flags));
        READWRITE(proposer);
        READWRITE(currencyID);
        READWRITE(currencyState);
        READWRITE(notarizationHeight);
        READWRITE(prevNotarization);
        READWRITE(hashPrevCrossNotarization);
        READWRITE(prevHeight);

        std::vector<std::pair<uint160, CCoinbaseCurrencyState>> vecCurrencyStates;
        if (ser_action.ForRead())
        {
            READWRITE(vecCurrencyStates);
            for (auto &oneState : vecCurrencyStates)
            {
                currencyStates.insert(oneState);
            }
        }
        else
        {
            for (auto &oneState : currencyStates)
            {
                vecCurrencyStates.push_back(oneState);
            }
            READWRITE(vecCurrencyStates);
        }

        std::vector<std::pair<uint160, CProofRoot>> vecProofRoots;

        if (ser_action.ForRead())
        {
            READWRITE(vecProofRoots);
            for (auto &oneRoot : vecProofRoots)
            {
                proofRoots.insert(oneRoot);
            }
        }
        else
        {
            for (auto &oneRoot : proofRoots)
            {
                vecProofRoots.push_back(oneRoot);
            }
            READWRITE(vecProofRoots);
        }

        READWRITE(nodes);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return nVersion >= VERSION_FIRST && nVersion <= VERSION_LAST && !currencyID.IsNull();
    }

    static std::string NotaryNotarizationKeyName()
    {
        return "vrsc::system.notarization.notarization";
    }

    static std::string DefinitionNotarizationKeyName()
    {
        return "vrsc::system.notarization.definitionnotarization";
    }

    static std::string EarnedNotarizationKeyName()
    {
        return "vrsc::system.notarization.earnednotarization";
    }

    static std::string AcceptedNotarizationKeyName()
    {
        return "vrsc::system.notarization.acceptednotarization";
    }

    static std::string LaunchNotarizationKeyName()
    {
        return "vrsc::system.currency.launch.notarization";
    }

    static std::string LaunchPrelaunchKeyName()
    {
        return "vrsc::system.currency.launch.prelaunch";
    }

    static std::string LaunchRefundKeyName()
    {
        return "vrsc::system.currency.launch.refund";
    }

    static std::string LaunchConfirmKeyName()
    {
        return "vrsc::system.currency.launch.confirm";
    }

    static std::string LaunchCompleteKeyName()
    {
        return "vrsc::system.currency.launch.complete";
    }

    static uint160 NotaryNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 notaryNotarizationKey = CVDXF::GetDataKey(NotaryNotarizationKeyName(), nameSpace);
        return notaryNotarizationKey;
    }

    static uint160 DefinitionNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 definitionNotarizationKey = CVDXF::GetDataKey(DefinitionNotarizationKeyName(), nameSpace);
        return definitionNotarizationKey;
    }

    static uint160 EarnedNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 earnedNotarizationKey = CVDXF::GetDataKey(EarnedNotarizationKeyName(), nameSpace);
        return earnedNotarizationKey;
    }

    static uint160 AcceptedNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 acceptedNotarizationKey = CVDXF::GetDataKey(AcceptedNotarizationKeyName(), nameSpace);
        return acceptedNotarizationKey;
    }

    static uint160 LaunchNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchNotarizationKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 LaunchPrelaunchKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchPrelaunchKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 LaunchRefundKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchRefundKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 LaunchConfirmKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchConfirmKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 LaunchCompleteKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchCompleteKeyName(), nameSpace);
        return signatureKey;
    }

    // if false, *this is unmodifed, otherwise, it is set to the last valid notarization in the requested range
    bool GetLastNotarization(const uint160 &currencyID, 
                             int32_t startHeight=0, 
                             int32_t endHeight=0, 
                             uint256 *txIDOut=nullptr,
                             CTransaction *txOut=nullptr);

    // if false, no matching, unspent notarization found
    bool GetLastUnspentNotarization(const uint160 &currencyID, 
                                    uint256 &txIDOut,
                                    int32_t &txOutNum,
                                    CTransaction *txOut=nullptr);

    bool NextNotarizationInfo(const CCurrencyDefinition &sourceSystem, 
                              const CCurrencyDefinition &destCurrency, 
                              uint32_t lastExportHeight, 
                              uint32_t notaHeight, 
                              std::vector<CReserveTransfer> &exportTransfers,
                              uint256 &transferHash,
                              CPBaaSNotarization &newNotarization,
                              std::vector<CTxOut> &importOutputs,
                              CCurrencyValueMap &importedCurrency,
                              CCurrencyValueMap &gatewayDepositsUsed,
                              CCurrencyValueMap &spentCurrencyOut,
                              CTransferDestination feeRecipient=CTransferDestination(),
                              bool forcedRefunding=false) const;

    static bool CreateEarnedNotarization(const CRPCChainData &externalSystem,
                                         const CTransferDestination &Proposer,
                                         bool isStake,
                                         CValidationState &state,
                                         std::vector<CTxOut> &txOutputs,
                                         CPBaaSNotarization &notarization);

    bool FindEarnedNotarization(CObjectFinalization &finalization, CAddressIndexDbEntry *pEarnedNotarizationIndex=nullptr) const;

    // accepts enough information to build a local accepted notarization transaction
    // miner fees are deferred until an import that uses this notarization, in which case
    // Proposer will get a share of the fees, if they are large enough. any miner,
    // who is mining the bridge can make such a notarization.
    static bool CreateAcceptedNotarization(const CCurrencyDefinition &externalSystem,
                                           const CPBaaSNotarization &notarization,
                                           const CNotaryEvidence &notaryEvidence,
                                           CValidationState &state,
                                           TransactionBuilder &txBuilder);

    static bool ConfirmOrRejectNotarizations(CWallet *pWallet,
                                             const CRPCChainData &externalSystem,
                                             CValidationState &state,
                                             std::vector<TransactionBuilder> &txBuilders,
                                             uint32_t nHeight,
                                             bool &finalized);

    bool IsNotarizationConfirmed(const CPBaaSNotarization &notarization,
                                 const CNotaryEvidence &notaryEvidence,
                                 CValidationState &state) const;

    bool IsNotarizationRejected(const CPBaaSNotarization &notarization,
                                const CNotaryEvidence &notaryEvidence,
                                CValidationState &state) const;

    static std::vector<uint256> SubmitFinalizedNotarizations(const CRPCChainData &externalSystem,
                                                             CValidationState &state);

    bool CheckProof(const uint160 &systemID, const CMMRProof &transactionBlockProof, uint256 checkHash)
    {
        auto proofRootIt = proofRoots.find(systemID);
        if (proofRootIt == proofRoots.end())
        {
            return false;
        }
        return transactionBlockProof.CheckProof(checkHash) == proofRootIt->second.stateRoot;
    }

    CProofRoot GetProofRoot(const uint160 &systemID) const
    {
        auto proofRootIt = proofRoots.find(systemID);
        if (proofRootIt == proofRoots.end())
        {
            return CProofRoot();
        }
        return proofRootIt->second;
    }

    void SetLaunchComplete(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_LAUNCH_COMPLETE;
        }
        else
        {
            flags &= ~FLAG_LAUNCH_COMPLETE;
        }
    }

    bool IsLaunchComplete() const
    {
        return flags & FLAG_LAUNCH_COMPLETE;
    }

    void SetSameChain(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_SAME_CHAIN;
        }
        else
        {
            flags &= ~FLAG_SAME_CHAIN;
        }
    }

    bool IsSameChain() const
    {
        return flags & FLAG_SAME_CHAIN;
    }

    bool IsMirror() const
    {
        return flags & FLAG_ACCEPTED_MIRROR;
    }

    // both sets the mirror flag and also transforms the notarization
    // between mirror states. returns false if could not change state to requested.
    bool SetMirror(bool setTrue=true);

    bool IsDefinitionNotarization() const
    {
        return flags & FLAG_DEFINITION_NOTARIZATION;
    }

    void SetDefinitionNotarization(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_DEFINITION_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_DEFINITION_NOTARIZATION;
        }
    }

    bool IsBlockOneNotarization() const
    {
        return flags & FLAG_BLOCKONE_NOTARIZATION;
    }

    void SetBlockOneNotarization(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_BLOCKONE_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_BLOCKONE_NOTARIZATION;
        }
    }

    bool IsPreLaunch() const
    {
        return flags & FLAG_PRE_LAUNCH;
    }

    void SetPreLaunch(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_PRE_LAUNCH;
        }
        else
        {
            flags &= ~FLAG_PRE_LAUNCH;
        }
    }

    bool IsLaunchCleared() const
    {
        return flags & FLAG_START_NOTARIZATION;
    }

    void SetLaunchCleared(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_START_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_START_NOTARIZATION;
        }
    }

    bool IsLaunchConfirmed() const
    {
        return flags & FLAG_LAUNCH_CONFIRMED;
    }

    void SetLaunchConfirmed(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_LAUNCH_CONFIRMED;
        }
        else
        {
            flags &= ~FLAG_LAUNCH_CONFIRMED;
        }
    }

    bool IsRefunding() const
    {
        return flags & FLAG_REFUNDING;
    }

    void SetRefunding(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_REFUNDING;
        }
        else
        {
            flags &= ~FLAG_REFUNDING;
        }
    }

    UniValue ToUniValue() const;
};

class CNotarySystemInfo
{
public:
    enum EVersions
    {
        VERSION_INVALID = 0,
        VERSION_CURRENT = 1,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
    };

    enum ENotarySystemTypes
    {
        TYPE_INVALID = 0,
        TYPE_PBAAS = 1,
        TYPE_ETH = 2,
        TYPE_KOMODO = 3,
    };

    uint32_t notarySystemVersion;
    uint32_t notarySystemType;
    uint32_t height;                            // height of last notarization
    CRPCChainData notaryChain;                  // notary chain information and connectivity for PBaaS protocol
    CPBaaSNotarization lastConfirmedNotarization;

    CNotarySystemInfo(uint32_t NotarySystemType=TYPE_PBAAS, uint32_t NotaryVersion=VERSION_INVALID) : notarySystemVersion(NotaryVersion), notarySystemType(NotarySystemType), height(0) {}

    CNotarySystemInfo(uint32_t Height, 
                      const CRPCChainData &NotaryChain, 
                      const CPBaaSNotarization &lastNotarization,
                      uint32_t NotarySystemType=TYPE_PBAAS,
                      uint32_t notaryVersion=VERSION_CURRENT) :
                      notarySystemVersion(notaryVersion),
                      notarySystemType(NotarySystemType),
                      height(Height),
                      notaryChain(NotaryChain),
                      lastConfirmedNotarization(lastNotarization)
    {}
};

class CConnectedChains
{
protected:
    CPBaaSMergeMinedChainData *GetChainInfo(uint160 chainID);

public:
    uint32_t lastBlockHeight;
    CBlock lastBlock;
    std::map<uint160, CPBaaSMergeMinedChainData> mergeMinedChains;
    std::multimap<arith_uint256, CPBaaSMergeMinedChainData *> mergeMinedTargets;

    std::map<uint160, std::pair<CCurrencyDefinition, const CGateway *>> gateways;       // gateway currencies, which bridge to other blockchains/systems

    // currency definition cache, needs LRU
    std::map<uint160, CCurrencyDefinition> currencyDefCache;                            // protected by cs_main, which is used for lookup

    // make earned notarizations for one or more notary chains
    std::map<uint160, CNotarySystemInfo> notarySystems;

    CCurrencyDefinition thisChain;
    bool readyToStart;
    std::vector<CNodeData> defaultPeerNodes;    // updated by notarizations
    std::vector<CTxOut> latestMiningOutputs;    // accessible from all merge miners - can be invalid

    int32_t earnedNotarizationHeight;           // zero or the height of one or more potential submissions
    CBlock earnedNotarizationBlock;
    int32_t earnedNotarizationIndex;            // index of earned notarization in block

    bool dirty;
    bool lastSubmissionFailed;                  // if we submit a failed block, make another
    std::map<arith_uint256, CBlockHeader> qualifiedHeaders;

    CCriticalSection cs_mergemining;
    CSemaphore sem_submitthread;

    CConnectedChains() : lastBlockHeight(0), readyToStart(0), sem_submitthread(0), earnedNotarizationHeight(0), dirty(0), lastSubmissionFailed(0) {}

    arith_uint256 LowestTarget()
    {
        if (mergeMinedTargets.size())
        {
            return mergeMinedTargets.begin()->first;
        }
        else
        {
            return arith_uint256(0);
        }
    }

    void SubmissionThread();
    static void SubmissionThreadStub();
    std::vector<std::pair<std::string, UniValue>> SubmitQualifiedBlocks();

    void QueueNewBlockHeader(CBlockHeader &bh);
    void QueueEarnedNotarization(CBlock &blk, int32_t txIndex, int32_t height);
    void CheckImports();
    void SignAndCommitImportTransactions(const CTransaction &lastImportTx, const std::vector<CTransaction> &transactions);
    // send new imports from this chain to the specified chain, which generally will be the notary chain
    void ProcessLocalImports();

    // return the last block if one is cached
    bool GetLastBlock(CBlock &block, uint32_t height);
    void SetLastBlock(CBlock &block, uint32_t height);
    bool AddMergedBlock(CPBaaSMergeMinedChainData &blkData);
    bool RemoveMergedBlock(uint160 chainID);
    bool GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData);
    void PruneOldChains(uint32_t pruneBefore);
    uint32_t CombineBlocks(CBlockHeader &bh);

    // returns false if destinations are empty or first is not either pubkey or pubkeyhash
    bool SetLatestMiningOutputs(const std::vector<CTxOut> &minerOutputs);
    void AggregateChainTransfers(const CTransferDestination &feeRecipient, uint32_t nHeight);
    CCurrencyDefinition GetCachedCurrency(const uint160 &currencyID);
    std::string GetFriendlyCurrencyName(const uint160 &currencyID);
    CCurrencyDefinition UpdateCachedCurrency(const CCurrencyDefinition &currentCurrency, uint32_t height);

    bool GetLastImport(const uint160 &currencyID, 
                       CTransaction &lastImport, 
                       int32_t &outputNum);

    bool GetLastSourceImport(const uint160 &currencyID, 
                             CTransaction &lastImport, 
                             int32_t &outputNum);

    bool GetUnspentSystemExports(const CCoinsViewCache &view,
                                 const uint160 systemID, 
                                 std::vector<pair<int, CInputDescriptor>> &exportOutputs);

    bool GetUnspentCurrencyExports(const CCoinsViewCache &view,
                                   const uint160 currencyID, 
                                   std::vector<pair<int, CInputDescriptor>> &exportOutputs);

    // get the exports to a specific system on this chain from a specific height up to a specific height
    bool GetSystemExports(const uint160 &systemID,                                 // transactions exported to system
                          std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> &exports,
                          uint32_t fromHeight,
                          uint32_t toHeight,
                          bool withProofs=false);
    
    // gets both the launch notarization and its partial transaction proof if launching to a new system
    bool GetLaunchNotarization(const CCurrencyDefinition &curDef,
                               std::pair<CInputDescriptor, CPartialTransactionProof> &notarizationTx,
                               CPBaaSNotarization &launchNotarization,
                               CPBaaSNotarization &notaryNotarization);

    // gets the definition notarization if it was defined on this system
    bool GetDefinitionNotarization(const CCurrencyDefinition &curDef,
                                   CInputDescriptor &notarizationRef,
                                   CPBaaSNotarization &definitionNotarization);

    // gets the definition notarization if it was defined on this system
    bool GetDefinitionNotarization(const CCurrencyDefinition &curDef,
                                   std::pair<CInputDescriptor, CPartialTransactionProof> &notarizationTx,
                                   CPBaaSNotarization &definitionNotarization,
                                   CPBaaSNotarization &notaryNotarization);

    // get the exports to a specific system on this chain from a specific height up to a specific height
    bool GetCurrencyExports(const uint160 &currencyID,                             // transactions exported to system
                            std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> &exports,
                            uint32_t fromHeight,
                            uint32_t toHeight);

    bool GetPendingSystemExports(const uint160 systemID,
                                 uint32_t fromHeight,
                                 multimap<uint160, pair<int, CInputDescriptor>> &exportOutputs);

    bool GetPendingCurrencyExports(const uint160 currencyID,
                                   uint32_t fromHeight,
                                   std::vector<pair<int, CInputDescriptor>> &exportOutputs);

    // given exports on this chain, provide the proofs of those export outputs
    bool GetExportProofs(uint32_t height,
                         std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports);

    static bool GetReserveDeposits(const uint160 &currencyID, const CCoinsViewCache &view, std::vector<CInputDescriptor> &reserveDeposits);

    static bool IsValidCurrencyDefinitionImport(const CCurrencyDefinition &sourceSystemDef,
                                                const CCurrencyDefinition &destSystemDef,
                                                const CCurrencyDefinition &importingCurrency,
                                                uint32_t height);

    static bool IsValidIdentityDefinitionImport(const CCurrencyDefinition &sourceSystemDef,
                                                const CCurrencyDefinition &destSystemDef,
                                                const CIdentity &importingIdentity,
                                                uint32_t height);

    static bool CurrencyExportStatus(const CCurrencyValueMap &totalExports,
                                     const uint160 &sourceSystemID,
                                     const uint160 &destSystemID,
                                     CCurrencyValueMap &newReserveDeposits,
                                     CCurrencyValueMap &exportBurn);

    static bool CurrencyImportStatus(const CCurrencyValueMap &totalExports,
                                     const uint160 &sourceSystemID,
                                     const uint160 &destSystemID,
                                     CCurrencyValueMap &newReserveDeposits,
                                     CCurrencyValueMap &exportBurn);

    bool CreateNextExport(const CCurrencyDefinition &_curDef,
                          const std::multimap<uint32_t, ChainTransferData> &txInputs,
                          const std::vector<CInputDescriptor> &priorExports,
                          const CTransferDestination &feeRecipient,
                          uint32_t sinceHeight,
                          uint32_t curHeight,
                          int32_t inputStartNum,
                          int32_t &inputsConsumed,
                          std::vector<CTxOut> &exportOutputs,
                          std::vector<CReserveTransfer> &exportTransfers,
                          const CPBaaSNotarization &lastNotarization,
                          const CUTXORef &lastNotarizationUTXO,
                          CPBaaSNotarization &newNotarization,
                          int &newNotarizationOutNum,
                          bool onlyIfRequired=true,
                          const ChainTransferData *addInputTx=nullptr);

    // create a set of imports on the current chain for a set of exports
    bool CreateLatestImports(const CCurrencyDefinition &sourceSystemDef,                            // transactions imported from system
                             const CUTXORef &confirmedSourceNotarization,
                             const std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                             std::map<uint160, std::vector<std::pair<int, CTransaction>>> &newImports);

    // returns the first notary system, if there is more than one
    const CRPCChainData &FirstNotaryChain() const
    {
        if (notarySystems.size())
        {
            return notarySystems.begin()->second.notaryChain;
        }
        static CRPCChainData invalidChain;
        return invalidChain;
    }

    // returns the map of notary systems
    const std::map<uint160, CNotarySystemInfo> &NotarySystems() const
    {
        return notarySystems;
    }

    CProofRoot ConfirmedNotaryChainRoot();
    CProofRoot FinalizedChainRoot();
    uint32_t NotaryChainHeight();

    CCurrencyDefinition &ThisChain()
    {
        return thisChain;
    }

    const std::map<uint160, std::pair<CCurrencyDefinition, const CGateway *>> &Gateways() const
    {
        return gateways;
    }

    std::pair<CCurrencyDefinition, const CGateway *> GetGateway(const uint160 &gatewayID) const
    {
        auto it = gateways.find(gatewayID);
        if (it != gateways.end())
        {
            return it->second;
        }
        return std::make_pair(CCurrencyDefinition(), nullptr);
    }

    int GetThisChainPort() const;

    // start with existing currency state and currency definitino and add
    // all pre-launch activity to bring them both up to date
    CCoinbaseCurrencyState AddPrelaunchConversions(CCurrencyDefinition &curDef,
                                                   const CCoinbaseCurrencyState &currencyState,
                                                   int32_t fromHeight,
                                                   int32_t height,
                                                   int32_t curDefHeight);

    CCoinbaseCurrencyState GetCurrencyState(int32_t height);                                // gets this chain's native currency state by block height
    CCoinbaseCurrencyState GetCurrencyState(CCurrencyDefinition &curDef, int32_t height, int32_t curDefHeight=0); // gets currency state
    CCoinbaseCurrencyState GetCurrencyState(const uint160 &currencyID, int32_t height);     // gets currency state

    CCurrencyDefinition GetDestinationCurrency(const CReserveTransfer &rt) const;

    bool CheckVerusPBaaSAvailable(UniValue &chainInfo, UniValue &chainDef);
    bool CheckVerusPBaaSAvailable();      // may use RPC to call Verus
    bool IsVerusPBaaSAvailable();
    bool IsNotaryAvailable(bool callToCheck=false);
    bool ConfigureEthBridge(bool callToCheck=false);

    std::vector<CCurrencyDefinition> GetMergeMinedChains()
    {
        std::vector<CCurrencyDefinition> ret;
        LOCK(cs_mergemining);
        for (auto &chain : mergeMinedChains)
        {
            ret.push_back(chain.second.chainDefinition);
        }
        return ret;
    }

    bool GetNotaryCurrencies(const CRPCChainData notaryChain, 
                             const std::set<uint160> &currencyIDs, 
                             std::map<uint160, std::pair<CCurrencyDefinition,CPBaaSNotarization>> &currencyDefs);
    bool GetNotaryIDs(const CRPCChainData notaryChain, const std::set<uint160> &idIDs, std::map<uint160,CIdentity> &identities);
};

template <typename TOBJ>
CTxOut MakeCC1of1Vout(uint8_t evalcode, CAmount nValue, CPubKey pk, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    assert(vDest.size() < 256);

    CTxOut vout;
    CC *payoutCond = MakeCCcond1(evalcode, pk);
    vout = CTxOut(nValue, CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, (uint8_t)(vDest.size()), vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1ofAnyVout(uint8_t evalcode, CAmount nValue, std::vector<CTxDestination> vDest, const TOBJ &obj, const CPubKey &pk=CPubKey())
{
    // if pk is valid, we will make sure that it is one of the signature options on this CC
    if (pk.IsValid())
    {
        CCcontract_info C;
        CCcontract_info *cp;
        cp = CCinit(&C, evalcode);
        int i;
        bool addPubKey = false;
        for (i = 0; i < vDest.size(); i++)
        {
            CPubKey oneKey(boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), vDest[i]));
            if ((oneKey.IsValid() && oneKey == pk) || CKeyID(GetDestinationID(vDest[i])) == pk.GetID())
            {
                // found, so don't add
                break;
            }
        }
        // if not found, add the pubkey
        if (i >= vDest.size())
        {
            vDest.push_back(CTxDestination(pk));
        }
    }

    CTxOut vout;
    CC *payoutCond = MakeCCcondAny(evalcode, vDest);
    vout = CTxOut(nValue, CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 0, (uint8_t)(vDest.size()), vDest, vvch);

    for (auto dest : vDest)
    {
        CPubKey oneKey(boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), dest));
        std::vector<unsigned char> bytes = GetDestinationBytes(dest);
        if ((!oneKey.IsValid() && bytes.size() != 20) || (bytes.size() != 33 && bytes.size() != 20))
        {
            printf("Invalid destination %s\n", EncodeDestination(dest).c_str());
        }
    }

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1of2Vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode, pk1, pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<CPubKey> vpk({pk1, pk2});
    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, 2, vpk, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1of2Vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode, pk1, pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<CPubKey> vpk({pk1, pk2});
    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, (uint8_t)(vDest.size()), vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

bool IsVerusActive();
bool IsVerusMainnetActive();

bool IsValidExportCurrency(const CCurrencyDefinition &systemDest, const uint160 &exportCurrencyID, uint32_t height);
std::set<uint160> BaseBridgeCurrencies(const CCurrencyDefinition &systemDest, uint32_t height, bool feeOnly=false);
std::set<uint160> ValidExportCurrencies(const CCurrencyDefinition &systemDest, uint32_t height);


// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool PrecheckCrossChainExport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool IsCrossChainExportInput(const CScript &scriptSig);

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool PrecheckCrossChainImport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool IsCrossChainImportInput(const CScript &scriptSig);

bool ValidateFinalizeExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsFinalizeExportInput(const CScript &scriptSig);
bool PreCheckFinalizeExport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);

bool ValidateNotaryEvidence(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsNotaryEvidenceInput(const CScript &scriptSig);

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveOutputInput(const CScript &scriptSig);

// used to transfer a reserve currency between chains
bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveTransferInput(const CScript &scriptSig);

// used as exchange tokens between reserves and fractional reserves
bool ValidateReserveExchange(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveExchangeInput(const CScript &scriptSig);

// used to deposit reserves into a reserve UTXO set
bool ValidateReserveDeposit(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveDepositInput(const CScript &scriptSig);

bool ValidateCurrencyDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool PrecheckCurrencyDefinition(const CTransaction &spendingTx, int32_t outNum, CValidationState &state, uint32_t height);
bool IsCurrencyDefinitionInput(const CScript &scriptSig);

bool ValidateCurrencyState(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsCurrencyStateInput(const CScript &scriptSig);

bool SetPeerNodes(const UniValue &nodes);
bool SetThisChain(const UniValue &chainDefinition, CCurrencyDefinition *retDef);

extern CConnectedChains ConnectedChains;
extern uint160 ASSETCHAINS_CHAINID;
extern CCriticalSection smartTransactionCS;

CCoinbaseCurrencyState GetInitialCurrencyState(const CCurrencyDefinition &chainDef);

CCurrencyDefinition ValidateNewUnivalueCurrencyDefinition(const UniValue &uniObj,
                                                          uint32_t height,
                                                          const uint160 systemID,
                                                          std::map<uint160, std::string> &requiredDefinitions,
                                                          bool checkMempool=true);

#endif
