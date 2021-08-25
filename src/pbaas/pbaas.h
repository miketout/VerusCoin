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

// these are object types that can be stored and recognized in an opret array
enum CHAIN_OBJECT_TYPES
{
    CHAINOBJ_INVALID = 0,
    CHAINOBJ_HEADER = 1,            // serialized full block header w/proof
    CHAINOBJ_HEADER_REF = 2,        // equivalent to header, but only includes non-canonical data
    CHAINOBJ_TRANSACTION_PROOF = 3, // serialized transaction or partial transaction with proof
    CHAINOBJ_PROOF_ROOT = 4,        // merkle proof of preceding block or transaction
    CHAINOBJ_PRIORBLOCKS = 5,       // prior block commitments to ensure recognition of overlapping notarizations
    CHAINOBJ_RESERVETRANSFER = 6,   // serialized transaction, sometimes without an opret, which will be reconstructed
    CHAINOBJ_COMPOSITEOBJECT = 7,   // can hold and index a variety and multiplicity of objects
    CHAINOBJ_CROSSCHAINPROOF = 8,   // specific composite object, which is a single or multi-proof
    CHAINOBJ_NOTARYSIGNATURE = 9    // notary signature
};

// the proof of an opret output, which is simply the types of objects and hashes of each
class COpRetProof
{
public:
    uint32_t orIndex;                   // index into the opret objects to begin with
    std::vector<uint8_t>    types;
    std::vector<uint256>    hashes;

    COpRetProof() : orIndex(0), types(0), hashes(0) {}
    COpRetProof(std::vector<uint8_t> &rTypes, std::vector<uint256> &rHashes, uint32_t opretIndex = 0) : types(rTypes), hashes(rHashes), orIndex(opretIndex) {}

    void AddObject(CHAIN_OBJECT_TYPES typeCode, uint256 objHash)
    {
        types.push_back(typeCode);
        hashes.push_back(objHash);
    }

    template <typename CHAINOBJTYPE>
    void AddObject(CHAINOBJTYPE &co, uint256 objHash)
    {
        types.push_back(ObjTypeCode(co));
        hashes.push_back(objHash);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(orIndex);
        READWRITE(types);
        READWRITE(hashes);
    }
};

class CHeaderRef
{
public:
    uint256 hash;               // block hash
    CPBaaSPreHeader preHeader;  // non-canonical pre-header data of source chain

    CHeaderRef() : hash() {}
    CHeaderRef(uint256 &rHash, CPBaaSPreHeader ph) : hash(rHash), preHeader(ph) {}
    CHeaderRef(const CBlockHeader &bh) : hash(bh.GetHash()), preHeader(bh) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(hash);
        READWRITE(preHeader);
    }

    uint256 GetHash() { return hash; }
};

class CPriorBlocksCommitment
{
public:
    std::vector<uint256> priorBlocks;       // prior block commitments, which are node hashes that include merkle root, block hash, and compact power
    uint256 pastBlockType;                  // 1 = POS, 0 = POW indicators for past blocks, enabling selective, pseudorandom proofs of past blocks by type

    CPriorBlocksCommitment() : priorBlocks() {}
    CPriorBlocksCommitment(const std::vector<uint256> &priors, const uint256 &pastTypes) : priorBlocks(priors), pastBlockType(pastTypes) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(priorBlocks);
        READWRITE(pastBlockType);
    }
};

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora);

class CBaseChainObject
{
public:
    uint16_t objectType;                    // type of object, such as blockheader, transaction, proof, tokentx, etc.

    CBaseChainObject() : objectType(CHAINOBJ_INVALID) {}
    CBaseChainObject(uint16_t objType) : objectType(objType) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(objectType);
    }
};

template <typename SERIALIZABLE>
class CChainObject : public CBaseChainObject
{
public:
    SERIALIZABLE object;                    // the actual object

    CChainObject() : CBaseChainObject() {}

    CChainObject(uint16_t objType, const SERIALIZABLE &rObject) : CBaseChainObject(objType), object(rObject) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*(CBaseChainObject *)this);
        READWRITE(object);
    }

    uint256 GetHash() const
    {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);

        hw << object;
        return GetHash();
    }
};

// each notarization will have an opret object that contains various kind of proof of the notarization itself
// as well as recent POW and POS headers and entropy sources.
class CCrossChainProof
{
public:
    enum
    {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_CURRENT = 1,
        VERSION_LAST = 1
    };
    uint32_t version;
    std::vector<CBaseChainObject *> chainObjects;    // this owns the memory associated with chainObjects and deletes it on destructions

    CCrossChainProof() : version(VERSION_CURRENT) {}
    CCrossChainProof(const CCrossChainProof &oldObj)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << oldObj;
        s >> *this;
    }
    CCrossChainProof(const std::vector<CBaseChainObject *> &objects, int Version=VERSION_CURRENT) : version(Version), chainObjects(objects) { }

    ~CCrossChainProof()
    {
        DeleteOpRetObjects(chainObjects);
        version = VERSION_INVALID;
    }

    const CCrossChainProof &operator=(const CCrossChainProof &operand)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << operand;
        DeleteOpRetObjects(chainObjects);
        s >> *this;
        return *this;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        if (ser_action.ForRead())
        {
            int32_t proofSize;
            READWRITE(VARINT(proofSize));

            bool error = false;
            for (int i = 0; i < proofSize && !error; i++)
            {
                try
                {
                    uint16_t objType;
                    READWRITE(objType);
                    union {
                        CChainObject<CBlockHeaderAndProof> *pNewHeader;
                        CChainObject<CPartialTransactionProof> *pNewTx;
                        CChainObject<uint256> *pNewProof;
                        CChainObject<CBlockHeaderProof> *pNewHeaderRef;
                        CChainObject<CPriorBlocksCommitment> *pPriors;
                        CChainObject<CReserveTransfer> *pExport;
                        CChainObject<CCrossChainProof> *pCrossChainProof;
                        CChainObject<CNotaryEvidence> *pNotarySignature;
                        CBaseChainObject *pobj;
                    };

                    pobj = nullptr;

                    switch(objType)
                    {
                        case CHAINOBJ_HEADER:
                        {
                            CBlockHeaderAndProof obj;
                            READWRITE(obj);
                            pNewHeader = new CChainObject<CBlockHeaderAndProof>();
                            if (pNewHeader)
                            {
                                pNewHeader->objectType = objType;
                                pNewHeader->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_TRANSACTION_PROOF:
                        {
                            CPartialTransactionProof obj;
                            READWRITE(obj);
                            pNewTx = new CChainObject<CPartialTransactionProof>();
                            if (pNewTx)
                            {
                                pNewTx->objectType = objType;
                                pNewTx->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_PROOF_ROOT:
                        {
                            uint256 obj;
                            READWRITE(obj);
                            pNewProof = new CChainObject<uint256>();
                            if (pNewProof)
                            {
                                pNewProof->objectType = objType;
                                pNewProof->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_HEADER_REF:
                        {
                            CBlockHeaderProof obj;
                            READWRITE(obj);
                            pNewHeaderRef = new CChainObject<CBlockHeaderProof>();
                            if (pNewHeaderRef)
                            {
                                pNewHeaderRef->objectType = objType;
                                pNewHeaderRef->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_PRIORBLOCKS:
                        {
                            CPriorBlocksCommitment obj;
                            READWRITE(obj);
                            pPriors = new CChainObject<CPriorBlocksCommitment>();
                            if (pPriors)
                            {
                                pPriors->objectType = objType;
                                pPriors->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_RESERVETRANSFER:
                        {
                            CReserveTransfer obj;
                            READWRITE(obj);
                            pExport = new CChainObject<CReserveTransfer>();
                            if (pExport)
                            {
                                pExport->objectType = objType;
                                pExport->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_CROSSCHAINPROOF:
                        {
                            CCrossChainProof obj;
                            READWRITE(obj);
                            pCrossChainProof = new CChainObject<CCrossChainProof>();
                            if (pCrossChainProof)
                            {
                                pCrossChainProof->objectType = objType;
                                pCrossChainProof->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_COMPOSITEOBJECT:
                        {
                            CCrossChainProof obj;
                            READWRITE(obj);
                            pCrossChainProof = new CChainObject<CCrossChainProof>();
                            if (pCrossChainProof)
                            {
                                pCrossChainProof->objectType = CHAINOBJ_COMPOSITEOBJECT;
                                pCrossChainProof->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_NOTARYSIGNATURE:
                        {
                            CNotaryEvidence obj;
                            READWRITE(obj);
                            pNotarySignature = new CChainObject<CNotaryEvidence>();
                            if (pNotarySignature)
                            {
                                pNotarySignature->objectType = CHAINOBJ_NOTARYSIGNATURE;
                                pNotarySignature->object = obj;
                            }
                            break;
                        }
                    }

                    if (pobj)
                    {
                        //printf("%s: storing object, code %u\n", __func__, objType);
                        chainObjects.push_back(pobj);
                    }
                }
                catch(const std::exception& e)
                {
                    error = true;
                    break;
                }
            }

            if (error)
            {
                printf("%s: ERROR: opret is likely corrupt\n", __func__);
                LogPrintf("%s: ERROR: opret is likely corrupt\n", __func__);
                DeleteOpRetObjects(chainObjects);
            }
        }
        else
        {
            //printf("entering CCrossChainProof serialize\n");
            int32_t proofSize = chainObjects.size();
            READWRITE(VARINT(proofSize));
            for (auto &oneVal : chainObjects)
            {
                DehydrateChainObject(s, oneVal);
            }
        }
    }

    bool IsValid() const
    {
        return (version >= VERSION_FIRST || version <= VERSION_LAST);
    }

    bool Empty() const
    {
        return chainObjects.size() == 0;
    }

    const std::vector<uint16_t> TypeVector() const
    {
        std::vector<uint16_t> retVal;
        for (auto &pChainObj : chainObjects)
        {
            if (pChainObj)
            {
                retVal.push_back(pChainObj->objectType);
            }
        }
        return retVal;
    }

    const CCrossChainProof &operator<<(const CPartialTransactionProof &partialTxProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CPartialTransactionProof>(CHAINOBJ_TRANSACTION_PROOF, partialTxProof)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CBlockHeaderAndProof &headerRefProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CBlockHeaderAndProof>(CHAINOBJ_HEADER_REF, headerRefProof)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CBlockHeaderProof &headerProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CBlockHeaderProof>(CHAINOBJ_HEADER, headerProof)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CPriorBlocksCommitment &priorBlocks)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CPriorBlocksCommitment>(CHAINOBJ_PRIORBLOCKS, priorBlocks)));
        return *this;
    }

    const CCrossChainProof &operator<<(const uint256 &proofRoot)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<uint256>(CHAINOBJ_PROOF_ROOT, proofRoot)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CReserveTransfer &reserveTransfer)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CReserveTransfer>(CHAINOBJ_RESERVETRANSFER, reserveTransfer)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CCrossChainProof &crossChainProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CCrossChainProof>(CHAINOBJ_CROSSCHAINPROOF, crossChainProof)));
        return *this;
    }
};

// this must remain cast/data compatible with CCompositeChainObject
class CCompositeChainObject : public CCrossChainProof
{
public:
    CCompositeChainObject() : CCrossChainProof() {}
    CCompositeChainObject(const std::vector<CBaseChainObject *> &proofs, int Version=VERSION_CURRENT) : 
        CCrossChainProof(proofs, Version) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CCrossChainProof *)this);
    }

    const CCompositeChainObject &operator<<(const CCompositeChainObject &compositeChainObject)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CCompositeChainObject>(CHAINOBJ_COMPOSITEOBJECT, compositeChainObject)));
        return *this;
    }
};

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
uint256 GetChainObjectHash(const CBaseChainObject &bo);

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
template <typename OStream>
CBaseChainObject *RehydrateChainObject(OStream &s)
{
    int16_t objType;

    try
    {
        s >> objType;
    }
    catch(const std::exception& e)
    {
        return NULL;
    }

    union {
        CChainObject<CBlockHeaderAndProof> *pNewHeader;
        CChainObject<CPartialTransactionProof> *pNewTx;
        CChainObject<uint256> *pNewProof;
        CChainObject<CBlockHeaderProof> *pNewHeaderRef;
        CChainObject<CPriorBlocksCommitment> *pPriors;
        CChainObject<CReserveTransfer> *pExport;
        CChainObject<CCrossChainProof> *pCrossChainProof;
        CChainObject<CCompositeChainObject> *pCompositeChainObject;
        CBaseChainObject *retPtr;
    };

    retPtr = NULL;

    switch(objType)
    {
        case CHAINOBJ_HEADER:
            pNewHeader = new CChainObject<CBlockHeaderAndProof>();
            if (pNewHeader)
            {
                s >> pNewHeader->object;
                pNewHeader->objectType = objType;
            }
            break;
        case CHAINOBJ_TRANSACTION_PROOF:
            pNewTx = new CChainObject<CPartialTransactionProof>();
            if (pNewTx)
            {
                s >> pNewTx->object;
                pNewTx->objectType = objType;
            }
            break;
        case CHAINOBJ_PROOF_ROOT:
            pNewProof = new CChainObject<uint256>();
            if (pNewProof)
            {
                s >> pNewProof->object;
                pNewProof->objectType = objType;
            }
            break;
        case CHAINOBJ_HEADER_REF:
            pNewHeaderRef = new CChainObject<CBlockHeaderProof>();
            if (pNewHeaderRef)
            {
                s >> pNewHeaderRef->object;
                pNewHeaderRef->objectType = objType;
            }
            break;
        case CHAINOBJ_PRIORBLOCKS:
            pPriors = new CChainObject<CPriorBlocksCommitment>();
            if (pPriors)
            {
                s >> pPriors->object;
                pPriors->objectType = objType;
            }
            break;
        case CHAINOBJ_RESERVETRANSFER:
            pExport = new CChainObject<CReserveTransfer>();
            if (pExport)
            {
                s >> pExport->object;
                pExport->objectType = objType;
            }
            break;
        case CHAINOBJ_CROSSCHAINPROOF:
            pCrossChainProof = new CChainObject<CCrossChainProof>();
            if (pCrossChainProof)
            {
                s >> pCrossChainProof->object;
                pCrossChainProof->objectType = objType;
            }
            break;
        case CHAINOBJ_COMPOSITEOBJECT:
            pCompositeChainObject = new CChainObject<CCompositeChainObject>();
            if (pCompositeChainObject)
            {
                s >> pCompositeChainObject->object;
                pCompositeChainObject->objectType = objType;
            }
            break;
    }
    return retPtr;
}

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
template <typename OStream>
bool DehydrateChainObject(OStream &s, const CBaseChainObject *pobj)
{
    switch(pobj->objectType)
    {
        case CHAINOBJ_HEADER:
        {
            s << *(CChainObject<CBlockHeaderAndProof> *)pobj;
            return true;
        }

        case CHAINOBJ_TRANSACTION_PROOF:
        {
            s << *(CChainObject<CPartialTransactionProof> *)pobj;
            return true;
        }

        case CHAINOBJ_PROOF_ROOT:
        {
            s << *(CChainObject<uint256> *)pobj;
            return true;
        }

        case CHAINOBJ_HEADER_REF:
        {
            s << *(CChainObject<CBlockHeaderProof> *)pobj;
            return true;
        }

        case CHAINOBJ_PRIORBLOCKS:
        {
            s << *(CChainObject<CPriorBlocksCommitment> *)pobj;
            return true;
        }

        case CHAINOBJ_RESERVETRANSFER:
        {
            s << *(CChainObject<CReserveTransfer> *)pobj;
            return true;
        }
        case CHAINOBJ_CROSSCHAINPROOF:
        {
            s << *(CChainObject<CCrossChainProof> *)pobj;
            return true;
        }
        case CHAINOBJ_COMPOSITEOBJECT:
        {
            s << *(CChainObject<CCompositeChainObject> *)pobj;
            return true;
        }
    }
    return false;
}

int8_t ObjTypeCode(const CBlockHeaderAndProof &obj);

int8_t ObjTypeCode(const CPartialTransactionProof &obj);

int8_t ObjTypeCode(const CBlockHeaderProof &obj);

int8_t ObjTypeCode(const CPriorBlocksCommitment &obj);

int8_t ObjTypeCode(const CReserveTransfer &obj);

int8_t ObjTypeCode(const CCrossChainProof &obj);

int8_t ObjTypeCode(const CCompositeChainObject &obj);

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(const std::vector<CBaseChainObject *> &objPtrs);

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora);

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript);

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
    static const uint32_t MAX_MERGE_CHAINS = 15;
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
    uint256 hashPrevNotarization;           // hash of the prior notarization on this system with which we agree, even one not accepted yet
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
        READWRITE(hashPrevNotarization);
        READWRITE(prevHeight);

        std::vector<std::pair<uint160, CCoinbaseCurrencyState>> vecCurrencyStates;
        if (ser_action.ForRead())
        {
            READWRITE(vecCurrencyStates);
            for (auto &oneRoot : vecCurrencyStates)
            {
                currencyStates.insert(oneRoot);
            }
        }
        else
        {
            for (auto &oneRoot : currencyStates)
            {
                vecCurrencyStates.push_back(oneRoot);
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
                              bool forcedRefunding=false) const;

    static bool CreateEarnedNotarization(const CRPCChainData &externalSystem,
                                         const CTransferDestination &Proposer,
                                         CValidationState &state,
                                         std::vector<CTxOut> &txOutputs,
                                         CPBaaSNotarization &notarization);

    // accepts enough information to build a local accepted notarization transaction
    // miner fees are deferred until an import that uses this notarization, in which case
    // Proposer will get a share of the fees, if they are large enough. any miner,
    // who is mining the bridge can make such a notarization.
    static bool CreateAcceptedNotarization(const CCurrencyDefinition &externalSystem,
                                           const CPBaaSNotarization &notarization,
                                           const CNotaryEvidence &notaryEvidence,
                                           CValidationState &state,
                                           TransactionBuilder &txBuilder);

    static bool ConfirmOrRejectNotarizations(const CWallet *pWallet,
                                             const CRPCChainData &externalSystem,
                                             CValidationState &state,
                                             TransactionBuilder &txBuilder,
                                             bool &finalized);

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

    CNotarySystemInfo() : notarySystemVersion(VERSION_INVALID), height(0) {}

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
    std::map<uint160, CPBaaSMergeMinedChainData> mergeMinedChains;
    std::multimap<arith_uint256, CPBaaSMergeMinedChainData *> mergeMinedTargets;

    std::map<uint160, std::pair<CCurrencyDefinition, const CGateway *>> gateways;       // gateway currencies, which bridge to other blockchains/systems

    // incoming export transactions from one currency & system and a UTXORef to a valid notarization each depends upon
    // indexed by the target, destination currency
    std::map<uint160, std::pair<uint32_t, std::pair<CUTXORef, CPartialTransactionProof>>> incomingBridgeTransfers;

    // currency definition cache, needs LRU
    std::map<uint160, CCurrencyDefinition> currencyDefCache;                            // protected by cs_main, which is used for lookup

    // make earned notarizations on one or more notary chains
    // On Verus, this can be set to ETH and Ethereum chain data will be pushed to us through Alan (Bridgekeeper) and the RPC API
    std::map<uint160, CNotarySystemInfo> notarySystems;

    CCurrencyDefinition thisChain;
    bool readyToStart;
    std::vector<CNodeData> defaultPeerNodes;    // updated by notarizations
    std::vector<CTxOut> latestMiningOutputs;    // accessible from all merge miners - can be invalid
    int64_t lastAggregation = 0;                // adjusted time of last aggregation

    int32_t earnedNotarizationHeight;           // zero or the height of one or more potential submissions
    CBlock earnedNotarizationBlock;
    int32_t earnedNotarizationIndex;            // index of earned notarization in block

    bool dirty;
    bool lastSubmissionFailed;                  // if we submit a failed block, make another
    std::map<arith_uint256, CBlockHeader> qualifiedHeaders;

    CCriticalSection cs_mergemining;
    CSemaphore sem_submitthread;

    CConnectedChains() : readyToStart(0), sem_submitthread(0), earnedNotarizationHeight(0), dirty(0), lastSubmissionFailed(0) {}

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

    bool AddMergedBlock(CPBaaSMergeMinedChainData &blkData);
    bool RemoveMergedBlock(uint160 chainID);
    bool GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData);
    void PruneOldChains(uint32_t pruneBefore);
    uint32_t CombineBlocks(CBlockHeader &bh);

    // returns false if destinations are empty or first is not either pubkey or pubkeyhash
    bool SetLatestMiningOutputs(const std::vector<CTxOut> &minerOutputs);
    void AggregateChainTransfers(const CTxDestination &feeOutput, uint32_t nHeight);
    CCurrencyDefinition GetCachedCurrency(const uint160 &currencyID);
    CCurrencyDefinition UpdateCachedCurrency(const uint160 &currencyID, uint32_t height);

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
                          const std::vector<ChainTransferData> &txInputs,
                          const std::vector<CInputDescriptor> &priorExports,
                          const CTxDestination &feeOutput,
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
    bool ConfigureEthBridge();

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

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsCrossChainExportInput(const CScript &scriptSig);

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsCrossChainImportInput(const CScript &scriptSig);

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
bool SetThisChain(const UniValue &chainDefinition);

extern CConnectedChains ConnectedChains;
extern uint160 ASSETCHAINS_CHAINID;
CCoinbaseCurrencyState GetInitialCurrencyState(const CCurrencyDefinition &chainDef);

#endif
