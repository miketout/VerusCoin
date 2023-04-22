/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This is an implementation of a Merkle Mountain Range that can work on a variety of node types and is optimized for the following uses:
 * 1. Easy append of new elements without invalidate or change of any prior proofs
 * 2. Fast, simple rewind/truncate to previous size
 * 3. Fast, state view into the MMR at any given prior size, making creation of
 *    any proof from any prior, valid state a simple matter
 * 4. Support for additional information to be captured and propagated along with the
 *    MMR through nodes that may have a more complex combination step, for example, to track aggregate work and stake (power) across all
 *    headers in a chain.
 * 
 * 2/23/2020 - added support for alternate hash algorithms
 */

#ifndef MMR_H
#define MMR_H

#include <vector>
#include <univalue.h>


#include "streams.h"
#include "hash.h"
#include "arith_uint256.h"


#ifndef BEGIN
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))
#endif

template <typename HASHALGOWRITER=CBLAKE2bWriter>
class CMMRNode
{
public:
    uint256 hash;
    CMMRNode() {}
    CMMRNode(uint256 Hash) : hash(Hash) {}

    template <typename SERIALIZABLE>
    static uint256 HashObj(const SERIALIZABLE &obj)
    {
        HASHALGOWRITER hw(SER_GETHASH, 0);
        hw << obj;
        return hw.GetHash();
    }

    template <typename SERIALIZABLE1, typename SERIALIZABLE2>
    static uint256 HashObj(const SERIALIZABLE1 &objL, const SERIALIZABLE2 &objR)
    {
        HASHALGOWRITER hw(SER_GETHASH, 0);
        hw << objL;
        hw << objR;
        return hw.GetHash();
    }

    static HASHALGOWRITER GetHashWriter()
    {
        return HASHALGOWRITER(SER_GETHASH, 0);
    }

    // add a right to this left and create a parent node
    CMMRNode CreateParentNode(const CMMRNode nRight) const
    {
        HASHALGOWRITER hw(SER_GETHASH, 0);
        hw << hash;
        hw << nRight.hash;
        return CMMRNode(hw.GetHash());
    }

    std::vector<uint256> GetProofHash(const CMMRNode &opposite) const
    {
        return {hash};
    }

    // leaf nodes that track additional data, such as block power, may need a hash added to the path
    // at the very beginning
    std::vector<uint256> GetLeafHash() { return {}; }

    static uint32_t GetExtraHashCount()
    {
        // how many extra proof hashes per layer are added with this node
        return 0;
    }
};
typedef CMMRNode<CBLAKE2bWriter> CDefaultMMRNode;
typedef CMMRNode<CKeccack256Writer> CDefaultETHNode;

template <typename HASHALGOWRITER=CBLAKE2bWriter>
class CMMRPowerNode
{
public:
    uint256 hash;
    uint256 power;

    CMMRPowerNode() : hash() {}
    CMMRPowerNode(uint256 Hash, uint256 Power) : hash(Hash), power(Power) {}

    template <typename SERIALIZABLE>
    static const uint256 &HashObj(const SERIALIZABLE &obj)
    {
        HASHALGOWRITER hw(SER_GETHASH, 0);
        hw << obj;
        return hw.GetHash();
    }

    template <typename SERIALIZABLE1, typename SERIALIZABLE2>
    static uint256 HashObj(const SERIALIZABLE1 &objL, const SERIALIZABLE2 &objR)
    {
        HASHALGOWRITER hw(SER_GETHASH, 0);
        hw << objL;
        hw << objR;
        return hw.GetHash();
    }

    arith_uint256 Work() const
    {
        return (UintToArith256(power) << 128) >> 128;
    }

    arith_uint256 Stake() const
    {
        return UintToArith256(power) >> 128;
    }

    static HASHALGOWRITER GetHashWriter()
    {
        return HASHALGOWRITER(SER_GETHASH, 0);
    }

    // add a right to this left and create a parent node
    CMMRPowerNode CreateParentNode(const CMMRPowerNode nRight) const
    {
        arith_uint256 work = Work() + nRight.Work();
        arith_uint256 stake = Stake() + nRight.Stake();
        assert(work << 128 >> 128 == work && stake << 128 >> 128 == stake);

        uint256 nodePower = ArithToUint256(stake << 128 | work);

        HASHALGOWRITER hw(SER_GETHASH, 0);
        hw << hash;
        hw << nRight.hash;
        uint256 preHash = hw.GetHash();

        hw = HASHALGOWRITER(SER_GETHASH, 0);
        hw << preHash;
        hw << nodePower;

        // these separate hashing steps allow the proof to be represented just as a Merkle proof, with steps along the way
        // hashing with nodePower instead of other hashes
        return CMMRPowerNode(hw.GetHash(), nodePower);
    }

    std::vector<uint256> GetProofHash(const CMMRPowerNode &proving) const
    {
        return {hash, ArithToUint256((Stake() + proving.Stake()) << 128 | (Work() + proving.Work()))};
    }

    std::vector<uint256> GetLeafHash() { return { power }; }

    static uint32_t GetExtraHashCount()
    {
        // how many extra proof hashes per layer are added with this node
        return 1;
    }
};
typedef CMMRPowerNode<CBLAKE2bWriter> CDefaultMMRPowerNode;

template <typename NODE_TYPE, int CHUNK_SHIFT = 9>
class CChunkedLayer
{
private:
    uint64_t vSize;
    std::vector<std::vector<NODE_TYPE>> nodes;

public:
    CChunkedLayer() : nodes(), vSize(0) {}

    static inline uint64_t chunkSize()
    {
        return 1 << CHUNK_SHIFT;
    }

    static inline uint64_t chunkMask()
    {
        return chunkSize() - 1;
    }

    uint64_t size() const
    {
        return vSize;
    }

    NODE_TYPE operator[](uint64_t idx) const
    {
        if (idx < vSize)
        {
            return nodes[idx >> CHUNK_SHIFT][idx & chunkMask()];
        }
        else
        {
            std::__throw_length_error("CChunkedLayer [] index out of range");
            return NODE_TYPE();
        }
    }

    void push_back(NODE_TYPE node)
    {
        vSize++;

        // if we wrapped around and need more space, we need to allocate a new chunk
        // printf("vSize: %lx, chunkMask: %lx\n", vSize, chunkMask());

        if ((vSize & chunkMask()) == 1)
        {
            nodes.push_back(std::vector<NODE_TYPE>());
            nodes.back().reserve(chunkSize());
        }
        nodes.back().push_back(node);
        // printf("nodes.size(): %lu\n", nodes.size());
    }

    void clear()
    {
        nodes.clear();
        vSize = 0;
    }

    void resize(uint64_t newSize)
    {
        if (newSize == 0)
        {
            clear();
        }
        else
        {
            uint64_t chunksSize = ((newSize - 1) >> CHUNK_SHIFT) + 1;
            nodes.resize(chunksSize);
            for (uint64_t i = size() ? ((size() - 1) >> CHUNK_SHIFT) + 1 : 1; i <= chunksSize; i++)
            {
                if (i < chunksSize)
                {
                    nodes.back().resize(chunkSize());
                }
                else
                {
                    nodes.back().reserve(chunkSize());
                    nodes.back().resize(((newSize - 1) & chunkMask()) + 1);
                }
            }

            vSize = ((nodes.size() - 1) << CHUNK_SHIFT) + ((newSize - 1) & chunkMask()) + 1;
        }
    }

    void Printout() const
    {
        printf("vSize: %lu, first vector size: %lu\n", vSize, vSize ? nodes[0].size() : vSize);
    }
};

// NODE_TYPE must have a default constructor
template <typename NODE_TYPE, typename UNDERLYING>
class COverlayNodeLayer
{
private:
    const UNDERLYING *nodeSource;
    uint64_t vSize;

public:
    COverlayNodeLayer() { assert(false); }
    COverlayNodeLayer(const UNDERLYING &NodeSource) : nodeSource(&NodeSource), vSize(0) {}

    uint64_t size() const
    {
        return vSize;
    }

    NODE_TYPE operator[](uint64_t idx) const
    {
        if (idx < vSize)
        {
            return nodeSource->GetMMRNode(idx);
        }
        else
        {
            std::__throw_length_error("COverlayNodeLayer [] index out of range");
            return NODE_TYPE();
        }
    }

    // node type must be moveable just to be passed here, but the default overlay has no control over the underlying storage
    // and only tracks size changes
    void push_back(NODE_TYPE node) { vSize++; }
    void clear() { vSize = 0; }
    void resize(uint64_t newSize) { vSize = newSize; }
};

class CMerkleBranchBase
{
public:
    enum BRANCH_TYPE
    {
        BRANCH_INVALID = 0,
        BRANCH_BTC = 1,
        BRANCH_MMRBLAKE_NODE = 2,
        BRANCH_MMRBLAKE_POWERNODE = 3,
        BRANCH_ETH = 4,
        BRANCH_MULTIPART = 5,
        BRANCH_LAST = 5
    };

    uint8_t branchType;

    CMerkleBranchBase() : branchType(BRANCH_INVALID) {}
    CMerkleBranchBase(BRANCH_TYPE type) : branchType(type) {}

    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(branchType);
    }

    std::string HashAbbrev(uint256 hash) const
    {
        std::string ret;
        for (int i = 0; i < 5; i++)
        {
            ret += " " + std::to_string(*((uint8_t *)&hash + i));
        }
        return ret;
    }

    // return the index that would be generated for an mmv of the indicated size at the specified position
    // kept static and doesn't support templates, which is why it is here, but should only be called on CMMRBranch derived classes
    static uint64_t GetMMRProofIndex(uint64_t pos, uint64_t mmvSize, int extrahashes);
};

// by default, this is compatible with normal merkle proofs with the existing
// block merkle roots. different hash algorithms may be selected for performance,
// security, or other purposes
template <typename HASHALGOWRITER=CBLAKE2bWriter, typename NODETYPE=CDefaultMMRNode>
class CMMRBranch : public CMerkleBranchBase
{
public:
    uint32_t nIndex;                // index of the element in this merkle mountain range
    uint32_t nSize;                 // size of the entire MMR, which is used to determine correct path
    std::vector<uint256> branch;    // variable size branch, depending on the position in the range

    CMMRBranch() : nIndex(0), nSize(0) {}
    CMMRBranch(BRANCH_TYPE type) : CMerkleBranchBase(type), nIndex(0), nSize(0) {}
    CMMRBranch(BRANCH_TYPE type, int size, int i, const std::vector<uint256> &b) : CMerkleBranchBase(type), nSize(size), nIndex(i), branch(b) {}

    CMMRBranch& operator<<(CMMRBranch append)
    {
        nIndex += append.nIndex << branch.size();
        branch.insert(branch.end(), append.branch.begin(), append.branch.end());
        return *this;
    }

    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CMerkleBranchBase *)this);
        READWRITE(VARINT(nIndex));
        READWRITE(VARINT(nSize));
        READWRITE(branch);
    }

    // extraHashes are the count of additional elements, such as work or power, to also incorporate into the hash tree
    uint256 SafeCheck(uint256 hash) const
    {
        int64_t index = GetMMRProofIndex(nIndex, nSize, NODETYPE::GetExtraHashCount());

        if (index == -1)
        {
            //printf("returning null 1\n");
            return uint256();
        }

        // printf("start SafeCheck branch.size(): %lu, index: %lu, hash: %s\n", branch.size(), index, HashAbbrev(hash).c_str());
        for (auto it(branch.begin()); it != branch.end(); it++)
        {
            HASHALGOWRITER hw(SER_GETHASH, 0);
            if (index & 1) 
            {
                if (*it == hash) 
                {
                    // non canonical. hash may be equal to node but never on the right.
                    //printf("returning null 2\n");
                    return uint256();
                }
                hw << *it;
                hw << hash;
                //printf("safeCheck: %s:%s\n", it->GetHex().c_str(), hash.GetHex().c_str());
            }
            else
            {
                hw << hash;
                hw << *it;
                //printf("safeCheck: %s:%s\n", hash.GetHex().c_str(), it->GetHex().c_str());
            }
            hash = hw.GetHash();
            index >>= 1;
            //printf("safeCheck: %s\n", hash.GetHex().c_str());
        }
        return hash;
    }
};
typedef CMMRBranch<CBLAKE2bWriter> CMMRNodeBranch;
typedef CMMRBranch<CBLAKE2bWriter, CMMRPowerNode<CBLAKE2bWriter>> CMMRPowerNodeBranch;


// by default, this is compatible with normal merkle proofs with the existing
// block merkle roots. different hash algorithms may be selected for performance,
// security, or other purposes
template <typename HASHALGOWRITER=CHashWriter, typename NODETYPE=CMMRNode<HASHALGOWRITER>>
class CMerkleBranch : public CMerkleBranchBase
{
public:
    uint32_t nIndex;                // index of the element in this merkle tree
    std::vector<uint256> branch;

    CMerkleBranch() : CMerkleBranchBase(BRANCH_BTC), nIndex(0) {}
    CMerkleBranch(int i, std::vector<uint256> b) : CMerkleBranchBase(BRANCH_BTC), nIndex(i), branch(b) {}

    CMerkleBranch& operator<<(CMerkleBranch append)
    {
        nIndex += append.nIndex << branch.size();
        branch.insert(branch.end(), append.branch.begin(), append.branch.end());
        return *this;
    }

    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CMerkleBranchBase *)this);
        READWRITE(VARINT(nIndex));
        READWRITE(branch);
    }

    // extraHashes are the count of additional elements, such as work or power, to also incorporate into the hash tree
    uint256 SafeCheck(uint256 hash) const
    {
        int64_t index = nIndex;

        if (index == -1)
            return uint256();

        // printf("start SafeCheck branch.size(): %lu, index: %lu, hash: %s\n", branch.size(), index, HashAbbrev(hash).c_str());
        for (auto it(branch.begin()); it != branch.end(); ++it)
        {
            HASHALGOWRITER hw(SER_GETHASH, 0);
            if (index & 1) 
            {
                if (*it == hash) 
                {
                    // non canonical. hash may be equal to node but never on the right.
                    return uint256();
                }
                hw << *it;
                hw << hash;
            }
            else
            {
                hw << hash;
                hw << *it;
            }
            hash = hw.GetHash();
            index >>= 1;
        }
        // printf("end SafeCheck\n");
        return hash;
    }
};
typedef CMerkleBranch<CHashWriter> CBTCMerkleBranch;

class CRLPProof
{
public:
    std::vector<std::vector <unsigned char>> proof_branch;
    CRLPProof() {}

    ADD_SERIALIZE_METHODS;

    std::string string_to_hex(const std::string& input)
    {
        static const char hex_digits[] = "0123456789ABCDEF";

        std::string output;
        output.reserve(input.length() * 2);
        for (unsigned char c : input)
        {
            output.push_back(hex_digits[c >> 4]);
            output.push_back(hex_digits[c & 15]);
        }
        return output;
    }

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        if (ser_action.ForRead())
        {
            int32_t proofSize;
            READWRITE(VARINT(proofSize));

            for (int i = 0; i < proofSize; i++)
            {
                std::vector<unsigned char> temp;
                READWRITE(temp);
                proof_branch.push_back(temp);            
            }
        } 
        else
        {
            int32_t proofSize = proof_branch.size();
            READWRITE(VARINT(proofSize));
            for (int i = 0; i < proofSize; i++)
            {
                std::vector<unsigned char> temp(proof_branch[i].begin(), proof_branch[i].end());
                READWRITE(temp);     
            }
        }
    }
};


template <typename HASHALGOWRITER=CKeccack256Writer, typename NODETYPE=CMMRNode<HASHALGOWRITER>>
class CPATRICIABranch : public CMerkleBranchBase
{
public:
    std::vector<std::vector<unsigned char>> accountProof;
    uint256 balance;
    uint64_t nonce;
    uint256 storageHash;
    uint256 storageProofKey;
    uint256 stateRoot, storageProofValue,codeHash, rootProof; 
    std::vector<uint256> branch;
    CRLPProof proofdata;
    CRLPProof storageProof; 
    uint160 address;
    CPATRICIABranch() : CMerkleBranchBase(BRANCH_ETH) {}
    CPATRICIABranch(std::vector<std::vector<unsigned char>> a, std::vector<std::vector<unsigned char>> b) : CMerkleBranchBase(BRANCH_ETH), accountProof(a), storageProof(b) {}
    
    CPATRICIABranch& operator<<(CPATRICIABranch append)
    {
        //TODO
        branch.insert(branch.end(), append.branch.begin(), append.branch.end());
        return *this;
    }

    std::vector<unsigned char> verifyAccountProof();
    std::vector<unsigned char> verifyProof(uint256& rootHash,std::vector<unsigned char> key,std::vector<std::vector<unsigned char>>& proof);
    uint256 verifyStorageProof(uint256 hash);
    bool verifyStorageValue(std::vector<unsigned char> testStorageValue);

    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CMerkleBranchBase *)this);
        READWRITE(proofdata);
        READWRITE(address);
        READWRITE(balance);
        READWRITE(codeHash);
        READWRITE(VARINT(nonce));
        READWRITE(storageHash);
        READWRITE(storageProofKey);
        READWRITE(storageProof);
    }

    uint256 SafeCheck(uint256 hash) 
    {
        return verifyStorageProof(hash);
    }

    std::vector<unsigned char> GetBalanceAsBEVector() const
    {
        arith_uint256 bigValue;
        std::vector<unsigned char> vecVal;
        for (bigValue = UintToArith256(balance); bigValue > 0; bigValue = bigValue >> 8)
        {
            vecVal.insert(vecVal.begin(), (unsigned char)(bigValue & 0xff).GetLow64());
        }
        return vecVal;
    }
};
typedef CPATRICIABranch<CHashWriter> CETHPATRICIABranch;

class RLP {
public:
    struct rlpDecoded {
        std::vector<std::vector<unsigned char>> data;
        std::vector<unsigned char> remainder; 
    };

    std::vector<unsigned char> encodeLength(int length,int offset);
    std::vector<unsigned char> encode(std::vector<unsigned char> input);
    std::vector<unsigned char> encode(std::vector<std::vector<unsigned char>> input);
    rlpDecoded decode(std::vector<unsigned char> inputBytes);
    rlpDecoded decode(std::string inputString);
};

class TrieNode {
public: 
    enum nodeType{
        BRANCH,
        LEAF,
        EXTENSION
    };
    nodeType type;
    std::vector<std::vector<unsigned char>> raw;
    std::vector<unsigned char> key;
    std::vector<unsigned char> value;

    TrieNode(std::vector<std::vector<unsigned char>> rawNode) {
        raw = rawNode;
        type = setType();
        setKey();
        setValue();
    }

private: 
    nodeType setType();
    void setKey();
    void setValue();
};


// This class is used to break proofs into multiple parts and still store them in a CMMRProof object
// that can be used to make a multipart CPartialTransactionProof
class CMMRProof;
class CMultiPartProof : public CMerkleBranchBase
{
public:
    std::vector<unsigned char> vch;

    CMultiPartProof() : CMerkleBranchBase(BRANCH_MULTIPART) {}
    CMultiPartProof(BRANCH_TYPE type) : CMerkleBranchBase(type)
    {
        assert(type == BRANCH_MULTIPART);
    }
    CMultiPartProof(BRANCH_TYPE type, const std::vector<unsigned char> &vec) : CMerkleBranchBase(type), vch(vec) {}
    CMultiPartProof(const std::vector<CMMRProof> &chunkVec);

    CMultiPartProof& operator<<(CMultiPartProof append)
    {
        vch.insert(vch.end(), append.vch.begin(), append.vch.end());
        return *this;
    }

    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CMerkleBranchBase *)this);
        READWRITE(vch);
    }

    std::vector<CMMRProof> BreakToChunks(int maxSize) const;

    // extraHashes are the count of additional elements, such as work or power, to also incorporate into the hash tree
    uint256 SafeCheck(uint256 hash) const
    {
        return uint256();
    }
};


class CMMRProof
{
public:
    std::vector<CMerkleBranchBase *> proofSequence;

    CMMRProof() {}
    CMMRProof(const CMMRProof &oldProof)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << oldProof;
        DeleteProofSequence();
        s >> *this;
    }
    const CMMRProof &operator=(const CMMRProof &operand)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << operand;
        DeleteProofSequence();
        s >> *this;
        return *this;
    }

    ~CMMRProof()
    {
        DeleteProofSequence();
    }

    void DeleteProofSequence();
    void DeleteProofSequenceEntry(int index);

    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (ser_action.ForRead())
        {
            int32_t proofSize;
            READWRITE(proofSize);

            // in case it is deserialized with something present
            DeleteProofSequence();

            bool error = false;
            for (int i = 0; i < proofSize && !error; i++)
            {
                try
                {
                    // our normal way out is an exception at end of stream
                    // would prefer a better way
                    uint8_t branchType;
                    READWRITE(branchType);

                    union {
                        CBTCMerkleBranch *pBranch;
                        CMMRNodeBranch *pNodeBranch;
                        CMMRPowerNodeBranch *pPowerNodeBranch;
                        CMerkleBranchBase *pobj;
                        CETHPATRICIABranch *pETHBranch;
                        CMultiPartProof *pMultiProofBranch;
                    };

                    // non-error exception comes from the first try on each object. after this, it is an error
                    pobj = nullptr;

                    switch(branchType)
                    {
                        case CMerkleBranchBase::BRANCH_BTC:
                        {
                            pBranch = new CBTCMerkleBranch();
                            if (pBranch)
                            {
                                READWRITE(*pBranch);
                            }
                            break;
                        }
                        case CMerkleBranchBase::BRANCH_MMRBLAKE_NODE:
                        {
                            pNodeBranch = new CMMRNodeBranch();
                            if (pNodeBranch)
                            {
                                READWRITE(*pNodeBranch);
                            }
                            break;
                        }
                        case CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE:
                        {
                            pPowerNodeBranch = new CMMRPowerNodeBranch();
                            if (pPowerNodeBranch)
                            {
                                READWRITE(*pPowerNodeBranch);
                            }
                            break;
                        }
                        case CMerkleBranchBase::BRANCH_ETH:
                        {
                            pETHBranch = new CETHPATRICIABranch();
                            if (pETHBranch)
                            {
                                READWRITE(*pETHBranch);
                            }
                            break;
                        }
                        case CMerkleBranchBase::BRANCH_MULTIPART:
                        {
                            pMultiProofBranch = new CMultiPartProof();
                            if (pMultiProofBranch)
                            {
                                READWRITE(*pMultiProofBranch);
                            }
                            break;
                        }
                        default:
                        {
                            printf("%s: ERROR: default case - proof sequence is likely corrupt, code %d\n", __func__, branchType);
                            LogPrintf("%s: ERROR: default case - proof sequence is likely corrupt, code %d\n", __func__, branchType);
                            error = true;
                        }
                    }

                    if (pobj)
                    {
                        proofSequence.push_back(pobj);
                    }
                }
                catch(const std::exception& e)
                {
                    error = true;
                }
            }

            if (error)
            {
                printf("%s: ERROR: failure - proof sequence is likely corrupt\n", __func__);
                LogPrintf("%s: ERROR: proof sequence is likely corrupt\n", __func__);
                DeleteProofSequence();
            }
        }
        else
        {
            int32_t proofSize = proofSequence.size();
            READWRITE(proofSize);

            for (auto pProof : proofSequence)
            {
                bool error = false;
                READWRITE(pProof->branchType);

                switch(pProof->branchType)
                {
                    case CMerkleBranchBase::BRANCH_BTC:
                    {
                        READWRITE(*(CBTCMerkleBranch *)pProof);
                        break;
                    }
                    case CMerkleBranchBase::BRANCH_MMRBLAKE_NODE:
                    {
                        READWRITE(*(CMMRNodeBranch *)pProof);
                        break;
                    }
                    case CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE:
                    {
                        READWRITE(*(CMMRPowerNodeBranch *)pProof);
                        break;
                    }
                    case CMerkleBranchBase::BRANCH_ETH:
                    {
                        READWRITE(*(CETHPATRICIABranch *)pProof);
                        break;
                    }
                    case CMerkleBranchBase::BRANCH_MULTIPART:
                    {
                        READWRITE(*(CMultiPartProof *)pProof);
                        break;
                    }
                    default:
                    {
                        error = true;
                        printf("ERROR: unknown branch type (%u), likely corrupt\n", pProof->branchType);
                        break;
                    }
                }
                assert(!error);
            }
        }
    }

    const CMMRProof &operator<<(const CBTCMerkleBranch &append);
    const CMMRProof &operator<<(const CMMRNodeBranch &append);
    const CMMRProof &operator<<(const CMMRPowerNodeBranch &append);
    const CMMRProof &operator<<(const CETHPATRICIABranch &append);
    const CMMRProof &operator<<(const CMultiPartProof &append);
    bool IsMultiPart() const
    {
        return proofSequence.size() == 1 && proofSequence[0]->branchType == CMerkleBranchBase::BRANCH_MULTIPART;
    }
    uint256 CheckProof(uint256 checkHash) const;
    uint160 GetNativeAddress() const;
    UniValue ToUniValue() const;
};

// an in memory MMR is represented by a vector of vectors of hashes, each being a layer of nodes of the binary tree, with the lowest layer
// being the leaf nodes, and the layers above representing full layers in a mountain or when less than half the length of the layer below,
// representing a peak.
template <typename NODE_TYPE=CDefaultMMRNode, typename LAYER_TYPE=CChunkedLayer<NODE_TYPE>, typename LAYER0_TYPE=LAYER_TYPE>
class CMerkleMountainRange
{
public:
    std::vector<LAYER_TYPE> upperNodes;
    LAYER0_TYPE layer0;

    CMerkleMountainRange() {}
    CMerkleMountainRange(const LAYER0_TYPE &Layer0) : layer0(Layer0) {}

    // add a leaf node and return the new index. this copies the memory of the leaf node, but does not keep the node itself
    // returns the index # of the new item
    uint64_t Add(NODE_TYPE leaf)
    {
        layer0.push_back(leaf);

        uint32_t height = 0;
        uint32_t layerSize;
        for (layerSize = layer0.size(); height <= upperNodes.size() && layerSize > 1; height++)
        {
            uint32_t newSizeAbove = layerSize >> 1;

            // expand vector of vectors if we are adding a new layer
            if (height == upperNodes.size())
            {
                upperNodes.resize(upperNodes.size() + 1);
                // printf("adding2: upperNodes.size(): %lu, upperNodes[%d].size(): %lu\n", upperNodes.size(), height, height && upperNodes.size() ? upperNodes[height-1].size() : 0);
            }

            uint32_t curSizeAbove = upperNodes[height].size();

            // if we need to add an element to the vector above us, do it
            // printf("layerSize: %u, newSizeAbove: %u, curSizeAbove: %u\n", layerSize, newSizeAbove, curSizeAbove);
            if (!(layerSize & 1) && newSizeAbove > curSizeAbove)
            {
                uint32_t idx = layerSize - 2;
                if (height)
                {
                    // printf("upperNodes.size(): %lu, upperNodes[%d].size(): %lu, upperNodes[%d].size(): %lu\n", upperNodes.size(), height, upperNodes[height].size(), height - 1, upperNodes[height - 1].size());
                    // upperNodes[height - 1].Printout();
                    // upperNodes[height].Printout();
                    // printf("upperNodes[%d].size(): %lu, nodep hash: %s\n", height - 1, upperNodes[height - 1].size(), upperNodes[height - 1][idx].hash.GetHex().c_str());
                    // printf("nodep + 1 hash: %p\n", upperNodes[height - 1][idx + 1].hash.GetHex().c_str());
                    upperNodes[height].push_back(upperNodes[height - 1][idx].CreateParentNode(upperNodes[height - 1][idx + 1]));
                }
                else
                {
                    upperNodes[height].push_back(layer0[idx].CreateParentNode(layer0[idx + 1]));
                    // printf("upperNodes.size(): %lu, upperNodes[%d].size(): %lu\n", upperNodes.size(), height, upperNodes[height].size());
                    // upperNodes[height].Printout();
                }
            }
            layerSize = newSizeAbove;
        }
        // return new index
        return layer0.size() - 1;
    }

    // add a default node
    uint64_t Add()
    {
        return Add(NODE_TYPE());
    }

    uint64_t size() const
    {
        return layer0.size();
    }

    uint32_t height() const
    {
        return layer0.size() ? upperNodes.size() + 1 : 0;
    }

    // returns the level 0 node at a particular location, or NULL if not present
    NODE_TYPE operator[](uint64_t pos) const
    {
        if (pos >= size())
        {
            std::__throw_length_error("CMerkleMountainRange [] index out of range");
            return NODE_TYPE();
        }
        return layer0[pos];
    }

    NODE_TYPE GetNode(uint32_t Height, uint64_t Index) const
    {
        uint32_t layers = height();
        if (Height < layers)
        {
            if (Height)
            {
                if (Index < upperNodes[Height - 1].size())
                {
                    return upperNodes[Height - 1][Index];
                }
            }
            else
            {
                if (Index < layer0.size())
                {
                    return layer0[Index];
                }
            }
        }
        return NODE_TYPE();
    }

    NODE_TYPE GetNode(uint32_t index) const
    {
        return GetNode(0, index);
    }

    // truncate to a specific size smaller than the current size
    // this has the potential to create catastrophic problems for views of the current
    // mountain range that continue to use the mountain range after it is truncated
    // THIS SHOULD BE SYNCHRONIZED WITH ANY USE OF VIEWS FROM THIS MOUNTAIN RANGE THAT
    // MAY EXTEND BEYOND THE TRUNCATION
    void Truncate(uint64_t newSize)
    {
        std::vector<uint64_t> sizes;

        uint64_t curSize = size();
        if (newSize < curSize)
        {
            uint64_t maxSize = size();
            if (newSize > maxSize)
            {
                newSize = maxSize;
            }
            sizes.push_back(newSize);
            newSize >>= 1;

            while (newSize)
            {
                sizes.push_back(newSize);
                newSize >>= 1;
            }

            upperNodes.resize(sizes.size() - 1);
            layer0.resize(sizes[0]);
            for (int i = 0; i < upperNodes.size(); i++)
            {
                upperNodes[i].resize(sizes[i + 1]);
            }
        }
    }
};

// a view of a merkle mountain range with the size of the range set to a specific position that is less than or equal
// to the size of the underlying range
template <typename NODE_TYPE, typename LAYER_TYPE=CChunkedLayer<NODE_TYPE>, typename LAYER0_TYPE=LAYER_TYPE, typename HASHALGOWRITER=CBLAKE2bWriter>
class CMerkleMountainView
{
public:
    const CMerkleMountainRange<NODE_TYPE, LAYER_TYPE, LAYER0_TYPE> &mmr; // the underlying mountain range, which provides the hash vectors
    std::vector<uint64_t> sizes;                    // sizes that we will use as proxies for the size of each vector at each height
    std::vector<NODE_TYPE> peaks;                   // peaks
    std::vector<std::vector<NODE_TYPE>> peakMerkle; // cached layers for the peak merkle if needed

    CMerkleMountainView(const CMerkleMountainRange<NODE_TYPE, LAYER_TYPE, LAYER0_TYPE> &mountainRange, uint64_t viewSize=0) : mmr(mountainRange), peaks(), peakMerkle()
    {
        uint64_t maxSize = mountainRange.size();
        if (viewSize > maxSize || viewSize == 0)
        {
            viewSize = maxSize;
        }
        sizes.push_back(viewSize);

        for (viewSize >>= 1; viewSize; viewSize >>= 1)
        {
            sizes.push_back(viewSize);
            /*
            printf("sizes height: %lu, values:\n", sizes.size());
            for (auto s : sizes)
            {
                printf("%lu\n", s);
            }
            */
        }
    }

    CMerkleMountainView(const CMerkleMountainView &mountainView, uint64_t viewSize=0) : mmr(mountainView.mmr)
    {
        uint64_t maxSize = mountainView.mmr.size();
        if (viewSize > maxSize || viewSize == 0)
        {
            viewSize = maxSize;
        }
        sizes.push_back(viewSize);
        viewSize >>= 1;

        while (viewSize)
        {
            sizes.push_back(viewSize);
            viewSize >>= 1;
        }
    }

    // how many elements are stored in this view
    uint64_t size() const
    {
        // zero if empty or the size of the zeroeth layer
        return sizes.size() == 0 ? 0 : sizes[0];
    }

    void CalcPeaks(bool force = false)
    {
        // if we don't yet have calculated peaks, calculate them
        if (force || (peaks.size() == 0 && size() != 0))
        {
            // reset the peak merkle tree, in case this is forced
            peaks.clear();
            peakMerkle.clear();
            for (int ht = 0; ht < sizes.size(); ht++)
            {
                // if we're at the top or the layer above us is smaller than 1/2 the size of this layer, rounded up, we are a peak
                if (ht == (sizes.size() - 1) || sizes[ht + 1] < ((sizes[ht] + 1) >> 1))
                {
                    peaks.insert(peaks.begin(), mmr.GetNode(ht, sizes[ht] - 1));
                }
            }
        }
    }

    uint64_t resize(uint64_t newSize)
    {
        if (newSize != size())
        {
            sizes.clear();
            peaks.clear();
            peakMerkle.clear();

            uint64_t maxSize = mmr.size();
            if (newSize > maxSize)
            {
                newSize = maxSize;
            }
            sizes.push_back(newSize);
            newSize >>= 1;

            while (newSize)
            {
                sizes.push_back(newSize);
                newSize >>= 1;
            }
        }
        return size();
    }

    uint64_t maxsize() const
    {
        return mmr.size() - 1;
    }

    const std::vector<NODE_TYPE> &GetPeaks()
    {
        CalcPeaks();
        return peaks;
    }

    uint256 GetRoot()
    {
        uint256 rootHash;

        if (size() > 0 && peakMerkle.size() == 0)
        {
            // get peaks and hash to a root
            CalcPeaks();

            uint32_t layerNum = 0, layerSize = peaks.size();
            // with an odd number of elements below, the edge passes through
            for (bool passThrough = (layerSize & 1); layerNum == 0 || layerSize > 1; passThrough = (layerSize & 1), layerNum++)
            {
                peakMerkle.push_back(std::vector<NODE_TYPE>());

                uint64_t i;
                uint32_t layerIndex = layerNum ? layerNum - 1 : 0;      // layerNum is base 1

                for (i = 0; i < (layerSize >> 1); i++)
                {
                    if (layerNum)
                    {
                        peakMerkle.back().push_back(peakMerkle[layerIndex][i << 1].CreateParentNode(peakMerkle[layerIndex][(i << 1) + 1]));
                    }
                    else
                    {
                        peakMerkle.back().push_back(peaks[i << 1].CreateParentNode(peaks[(i << 1) + 1]));
                    }
                }
                if (passThrough)
                {
                    if (layerNum)
                    {
                        // pass the end of the prior layer through
                        peakMerkle.back().push_back(peakMerkle[layerIndex].back());
                    }
                    else
                    {
                        peakMerkle.back().push_back(peaks.back());
                    }
                }
                // each entry in the next layer should be either combined two of the prior layer, or a duplicate of the prior layer's end
                layerSize = peakMerkle.back().size();
            }
            rootHash = peakMerkle.back()[0].hash;
        }
        else if (peakMerkle.size() > 0)
        {
            rootHash = peakMerkle.back()[0].hash;
        }
        return rootHash;
    }

    const NODE_TYPE *GetRootNode()
    {
        // ensure merkle tree is calculated
        uint256 root = GetRoot();
        if (!root.IsNull())
        {
            return &(peakMerkle.back()[0]);
        }
        else
        {
            return NULL;
        }
    }

    // return hash of the element at "index"
    uint256 GetHash(uint64_t index)
    {
        if (index < size())
        {
            return mmr.layer0[index].hash;
        }
        else
        {
            return uint256();
        }
    }

    uint8_t GetBranchType(const CDefaultMMRNode &overload)
    {
        return CMerkleBranchBase::BRANCH_MMRBLAKE_NODE;
    }

    uint8_t GetBranchType(const CDefaultMMRPowerNode &overload)
    {
        return CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE;
    }

    // return a proof of the element at "pos"
    bool GetProof(CMMRProof &retProof, uint64_t pos)
    {
        // find a path from the indicated position to the root in the current view
        CMMRBranch<HASHALGOWRITER, NODE_TYPE> retBranch;

        if (pos < size())
        {
            // just make sure the peakMerkle tree is calculated
            GetRoot();

            // if we have leaf information, add it
            std::vector<uint256> toAdd = mmr.layer0[pos].GetLeafHash();
            if (toAdd.size())
            {
                retBranch.branch.insert(retBranch.branch.end(), toAdd.begin(), toAdd.end());
            }

            uint64_t p = pos;
            for (int l = 0; l < sizes.size(); l++)
            {
                if (p & 1)
                {
                    std::vector<uint256> proofHashes = mmr.GetNode(l, p - 1).GetProofHash(mmr.GetNode(l, p));
                    retBranch.branch.insert(retBranch.branch.end(), proofHashes.begin(), proofHashes.end());
                    p >>= 1;
                }
                else
                {
                    // make sure there is one after us to hash with or we are a peak and should be hashed with the rest of the peaks
                    if (sizes[l] > (p + 1))
                    {
                        std::vector<uint256> proofHashes = mmr.GetNode(l, p + 1).GetProofHash(mmr.GetNode(l, p));
                        retBranch.branch.insert(retBranch.branch.end(), proofHashes.begin(), proofHashes.end());
                        p >>= 1;
                    }
                    else
                    {
                        /* for (auto &oneNode : peaks)
                        {
                            printf("peaknode: ");
                            for (auto oneHash : oneNode.GetProofHash(oneNode))
                            {
                                printf("%s:", oneHash.GetHex().c_str());
                            }
                            printf("\n");
                        } */

                        // we are at a peak, the alternate peak to us, or the next thing we should be hashed with, if there is one, is next on our path
                        uint256 peakHash = mmr.GetNode(l, p).hash;

                        // linear search to find out which peak we are in the base of the peakMerkle
                        for (p = 0; p < peaks.size(); p++)
                        {
                            if (peaks[p].hash == peakHash)
                            {
                                break;
                            }
                        }

                        // p is the position in the merkle tree of peaks
                        assert(p < peaks.size());

                        // move up to the top, which is always a peak of size 1
                        uint32_t layerNum, layerSize;
                        for (layerNum = 0, layerSize = peaks.size(); layerNum == 0 || layerSize > 1; layerSize = peakMerkle[layerNum++].size())
                        {
                            uint32_t layerIndex = layerNum ? layerNum - 1 : 0;      // layerNum is base 1

                            // we are an odd member on the end (even index) and will not hash with the next layer above, we will propagate to its end
                            if ((p < layerSize - 1) || (p & 1))
                            {
                                if (p & 1)
                                {
                                    // hash with the one before us
                                    if (layerNum)
                                    {
                                        std::vector<uint256> proofHashes = peakMerkle[layerIndex][p - 1].GetProofHash(peakMerkle[layerIndex][p]);
                                        retBranch.branch.insert(retBranch.branch.end(), proofHashes.begin(), proofHashes.end());
                                    }
                                    else
                                    {
                                        std::vector<uint256> proofHashes = peaks[p - 1].GetProofHash(peaks[p]);
                                        retBranch.branch.insert(retBranch.branch.end(), proofHashes.begin(), proofHashes.end());
                                    }
                                }
                                else
                                {
                                    // hash with the one in front of us
                                    if (layerNum)
                                    {
                                        std::vector<uint256> proofHashes = peakMerkle[layerIndex][p + 1].GetProofHash(peakMerkle[layerIndex][p]);
                                        retBranch.branch.insert(retBranch.branch.end(), proofHashes.begin(), proofHashes.end());
                                    }
                                    else
                                    {
                                        std::vector<uint256> proofHashes = peaks[p + 1].GetProofHash(peaks[p]);
                                        retBranch.branch.insert(retBranch.branch.end(), proofHashes.begin(), proofHashes.end());
                                    }
                                }
                            }
                            p >>= 1;
                        }

                        // finished
                        break;
                    }
                }
            }
            retBranch.branchType = GetBranchType(NODE_TYPE());
            retBranch.nSize = size();
            retBranch.nIndex = pos;
            retProof << retBranch;
            return true;
        }
        return false;
    }

    // return a vector of the bits, either 1 or 0 in each byte, to represent both the size
    // of the proof by the size of the vector, and the expected bit in each position for the given
    // position in a Merkle Mountain View of the specified size
    static std::vector<unsigned char> GetProofBits(uint64_t pos, uint64_t mmvSize)
    {
        std::vector<unsigned char> Bits;
        std::vector<uint64_t> Sizes;
        std::vector<unsigned char> PeakIndexes;
        std::vector<uint64_t> MerkleSizes;

        // printf("GetProofBits - pos: %lu, mmvSize: %lu\n", pos, mmvSize);

        // find a path from the indicated position to the root in the current view
        if (pos > 0 && pos < mmvSize)
        {
            int extrahashes = NODE_TYPE::GetExtraHashCount();

            Sizes.push_back(mmvSize);
            mmvSize >>= 1;

            while (mmvSize)
            {
                Sizes.push_back(mmvSize);
                mmvSize >>= 1;
            }

            for (uint32_t ht = 0; ht < Sizes.size(); ht++)
            {
                // if we're at the top or the layer above us is smaller than 1/2 the size of this layer, rounded up, we are a peak
                if (ht == ((uint32_t)Sizes.size() - 1) || (Sizes[ht] & 1))
                {
                    PeakIndexes.insert(PeakIndexes.begin(), ht);
                }
            }

            // figure out the peak merkle
            uint64_t layerNum = 0, layerSize = PeakIndexes.size();
            // with an odd number of elements below, the edge passes through
            for (bool passThrough = (layerSize & 1); layerNum == 0 || layerSize > 1; passThrough = (layerSize & 1), layerNum++)
            {
                layerSize = (layerSize >> 1) + passThrough;
                if (layerSize)
                {
                    MerkleSizes.push_back(layerSize);
                }
            }

            // add extra hashes for a node on the right
            for (int i = 0; i < extrahashes; i++)
            {
                Bits.push_back(0);
            }

            uint64_t p = pos;
            for (int l = 0; l < Sizes.size(); l++)
            {
                // printf("GetProofBits - Bits.size: %lu\n", Bits.size());

                if (p & 1)
                {
                    Bits.push_back(1);
                    p >>= 1;

                    for (int i = 0; i < extrahashes; i++)
                    {
                        Bits.push_back(0);
                    }
                }
                else
                {
                    // make sure there is one after us to hash with or we are a peak and should be hashed with the rest of the peaks
                    if (Sizes[l] > (p + 1))
                    {
                        Bits.push_back(0);
                        p >>= 1;

                        for (int i = 0; i < extrahashes; i++)
                        {
                            Bits.push_back(0);
                        }
                    }
                    else
                    {
                        for (p = 0; p < PeakIndexes.size(); p++)
                        {
                            if (PeakIndexes[p] == l)
                            {
                                break;
                            }
                        }

                        // p is the position in the merkle tree of peaks
                        assert(p < PeakIndexes.size());

                        // move up to the top, which is always a peak of size 1
                        uint64_t layerNum;
                        uint64_t layerSize;
                        for (layerNum = -1, layerSize = PeakIndexes.size(); layerNum == -1 || layerSize > 1; layerSize = MerkleSizes[++layerNum])
                        {
                            // printf("GetProofBits - Bits.size: %lu\n", Bits.size());
                            if (p < (layerSize - 1) || (p & 1))
                            {
                                if (p & 1)
                                {
                                    // hash with the one before us
                                    Bits.push_back(1);

                                    for (int i = 0; i < extrahashes; i++)
                                    {
                                        Bits.push_back(0);
                                    }
                                }
                                else
                                {
                                    // hash with the one in front of us
                                    Bits.push_back(0);

                                    for (int i = 0; i < extrahashes; i++)
                                    {
                                        Bits.push_back(0);
                                    }
                                }
                            }
                            p >>= 1;
                        }
                        // finished
                        break;
                    }
                }
            }
        }
        return Bits;
    }
};


#endif // MMR_H
