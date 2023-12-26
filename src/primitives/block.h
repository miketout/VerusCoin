// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/nonce.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "primitives/solutiondata.h"
#include "mmr.h"

// does not check for height / sapling upgrade, etc. this should not be used to get block proofs
// on a pre-VerusPoP chain
arith_uint256 GetCompactPower(const uint256 &nNonce, uint32_t nBits, int32_t version=CPOSNonce::VERUS_V2);
class CBlockHeader;

// nodes for the entire chain MMR
typedef CMMRPowerNode<CBLAKE2bWriter> ChainMMRNode;

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const size_t HEADER_SIZE = 4+32+32+32+4+4+32;  // excluding Equihash solution
    static const int32_t CURRENT_VERSION = CPOSNonce::VERUS_V1;
    static const int32_t CURRENT_VERSION_MASK = 0x0000ffff; // for compatibility
    static const int32_t VERUS_V2 = CPOSNonce::VERUS_V2;

    static uint256 (CBlockHeader::*hashFunction)() const;

    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashFinalSaplingRoot;
    uint32_t nTime;
    uint32_t nBits;
    CPOSNonce nNonce;
    std::vector<unsigned char> nSolution;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nSolution);
    }

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashFinalSaplingRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = uint256();
        nSolution.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // returns 0 if pre-advanced header, 1 if post & PoW, -1 if post & PoS
    int32_t IsAdvancedHeader() const
    {
        if (nVersion == VERUS_V2)
        {
            return CConstVerusSolutionVector::IsAdvancedSolution(nSolution);
        }
        return 0;
    }

    int32_t HasPBaaSHeader() const
    {
        if (nVersion == VERUS_V2)
        {
            return CConstVerusSolutionVector::HasPBaaSHeader(nSolution);
        }
        return 0;
    }

    // return a vector of bytes that contains the internal data for this solution vector
    void GetExtraData(std::vector<unsigned char> &dataVec) const
    {
        std::vector<unsigned char> writeSolution = nSolution;
        CVerusSolutionVector(writeSolution).GetExtraData(dataVec);
    }

    // set the extra data with a pointer to bytes and length
    bool SetExtraData(const unsigned char *pbegin, uint32_t len)
    {
        return CVerusSolutionVector(nSolution).SetExtraData(pbegin, len);
    }

    void ResizeExtraData(uint32_t newSize)
    {
        CVerusSolutionVector(nSolution).ResizeExtraData(newSize);
    }

    uint32_t ExtraDataLen()
    {
        return CVerusSolutionVector(nSolution).ExtraDataLen();
    }

    // returns -1 on failure, upon failure, pbbh is undefined and likely corrupted
    int32_t GetPBaaSHeader(CPBaaSBlockHeader &pbh, const uint160 &cID) const;

    // returns false on failure to read data
    bool GetPBaaSHeader(CPBaaSBlockHeader &pbh, uint32_t idx) const
    {
        // search in the solution for this header index and return it if found
        CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
        if (nVersion == VERUS_V2 && CConstVerusSolutionVector::HasPBaaSHeader(nSolution) != 0 && idx < descr.numPBaaSHeaders)
        {
            pbh = *(CConstVerusSolutionVector::GetFirstPBaaSHeader(nSolution) + idx);
            return true;
        }
        return false;
    }

    // returns false on failure to read data
    int32_t NumPBaaSHeaders() const
    {
        // search in the solution for this header index and return it if found
        CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
        return descr.numPBaaSHeaders;
    }

    // this can save a new header into an empty space or update an existing header
    bool SavePBaaSHeader(CPBaaSBlockHeader &pbh, uint32_t idx)
    {
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();
        int ix;

        CVerusSolutionVector sv = CVerusSolutionVector(nSolution);

        if (sv.HasPBaaSHeader() && !pbh.IsNull() && idx < sv.GetNumPBaaSHeaders() && (((ix = GetPBaaSHeader(pbbh, pbh.chainID)) == -1) || ix == idx))
        {
            sv.SetPBaaSHeader(pbh, idx);
            return true;
        }
        return false;
    }

    bool UpdatePBaaSHeader(const CPBaaSBlockHeader &pbh)
    {
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();
        uint32_t idx;

        // what we are updating, must be present
        if (!pbh.IsNull() && (idx = GetPBaaSHeader(pbbh, pbh.chainID)) != -1)
        {
            CVerusSolutionVector(nSolution).SetPBaaSHeader(pbh, idx);
            return true;
        }
        return false;
    }

    void DeletePBaaSHeader(uint32_t idx)
    {
        CVerusSolutionVector sv = CVerusSolutionVector(nSolution);
        CPBaaSSolutionDescriptor descr = sv.Descriptor();
        if (idx < descr.numPBaaSHeaders)
        {
            CPBaaSBlockHeader pbh;
            // if we weren't last, move the one that was last to our prior space
            if (idx < (descr.numPBaaSHeaders - 1))
            {
                sv.GetPBaaSHeader(pbh, descr.numPBaaSHeaders - 1);
            }
            sv.SetPBaaSHeader(pbh, idx);

            descr.numPBaaSHeaders--;
            sv.SetDescriptor(descr);
        }
    }

    // returns the index of the new header if added, otherwise, -1
    int32_t AddPBaaSHeader(const CPBaaSBlockHeader &pbh);

    // add the parts of this block header that can be represented by a PBaaS header to the solution
    int32_t AddPBaaSHeader(const uint160 &cID)
    {
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader(cID, CPBaaSPreHeader(*this));
        return AddPBaaSHeader(pbbh);
    }

    bool AddUpdatePBaaSHeader();
    bool AddUpdatePBaaSHeader(const CPBaaSBlockHeader &pbh);

    // clears everything except version, time, and solution, which are shared across all merge mined blocks
    void ClearNonCanonicalData()
    {
        hashPrevBlock = uint256();
        hashMerkleRoot = uint256();
        hashFinalSaplingRoot = uint256();
        nBits = 0;
        nNonce = uint256();
        CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
        if (descr.version >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS_HEADER)
        {
            descr.hashPrevMMRRoot = descr.hashBlockMMRRoot = uint256();
            CConstVerusSolutionVector::SetDescriptor(nSolution, descr);
        }
    }

    // this confirms that the current header's data matches what would be expected from its preheader hash in the
    // solution
    bool CheckNonCanonicalData() const;
    bool CheckNonCanonicalData(const uint160 &cID) const;

    uint256 GetHash() const
    {
        return (this->*hashFunction)();
    }

    // return a node from this block header, including hash of merkle root and block hash as well as compact chain power, to put into an MMR
    ChainMMRNode GetBlockMMRNode() const;

    // getters/setters for extra data in extended solution
    uint256 GetPrevMMRRoot() const;
    void SetPrevMMRRoot(const uint256 &prevMMRRoot);

    // returns the hashMerkleRoot for blocks before PBaaS
    uint256 GetBlockMMRRoot() const;
    void SetBlockMMRRoot(const uint256 &blockMMRRoot);

    uint256 GetSHA256DHash() const;
    static void SetSHA256DHash();

    uint256 GetVerusHash() const;
    static void SetVerusHash();

    uint256 GetVerusV2Hash() const;
    static void SetVerusV2Hash();

    static uint256 GetRawVerusPOSHash(int32_t blockVersion, uint32_t solVersion, uint32_t magic, const uint256 &nonce, int32_t height, bool isVerusMainnet=true);

    // returns the preheader for this block with another hash substituted for hashBlockMMRRoot, since this goes in the block MMR
    CPBaaSPreHeader GetSubstitutedPreHeader(const uint256 &pastHash) const;

    bool GetRawVerusPOSHash(uint256 &ret, int32_t nHeight) const;
    bool GetVerusPOSHash(arith_uint256 &ret, int32_t nHeight, CAmount value) const; // value is amount of stake tx
    uint256 GetVerusEntropyHashComponent(uint32_t magic, int32_t height, bool isVerusMainnet) const;
    uint256 GetVerusEntropyHashComponent(int32_t nHeight) const;
    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    uint32_t GetVerusPOSTarget() const
    {
        uint32_t nBits = 0;

        for (const unsigned char *p = nNonce.begin() + 3; p >= nNonce.begin(); p--)
        {
            nBits <<= 8;
            nBits += *p;
        }
        return nBits;
    }

    bool IsVerusPOSBlock() const
    {
        return nNonce.IsPOSNonce(nVersion) && GetVerusPOSTarget() != 0;
    }

    void SetVerusPOSTarget(uint32_t nBits)
    {
        if (nVersion == VERUS_V2)
        {
            CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);

            arith_uint256 arNonce = UintToArith256(nNonce);

            // printf("before svpt: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            arNonce = (arNonce & CPOSNonce::entropyMask) | nBits;

            // printf("after clear: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            hashWriter << ArithToUint256(arNonce);
            nNonce = CPOSNonce(ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | arNonce));

            // printf(" after svpt: %s\n", nNonce.GetHex().c_str());
        }
        else
        {
            CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

            arith_uint256 arNonce = UintToArith256(nNonce);

            // printf("before svpt: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            arNonce = (arNonce & CPOSNonce::entropyMask) | nBits;

            // printf("after clear: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            hashWriter << ArithToUint256(arNonce);
            nNonce = CPOSNonce(ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | arNonce));

            // printf(" after svpt: %s\n", nNonce.GetHex().c_str());
        }
    }

    void SetVersionByHeight(uint32_t height)
    {
        CVerusSolutionVector vsv = CVerusSolutionVector(nSolution);
        if (vsv.SetVersionByHeight(height) && vsv.Version() > 0)
        {
            nVersion = VERUS_V2;
        }
    }

    static uint32_t GetVersionByHeight(uint32_t height)
    {
        if (CVerusSolutionVector::GetVersionByHeight(height) > 0)
        {
            return VERUS_V2;
        }
        else
        {
            return CURRENT_VERSION;
        }
    }

    CMMRNodeBranch MMRProofBridge() const
    {
        // we need to add the block hash on the right, no change to index, as bit is zero
        return CMMRNodeBranch(CMMRNodeBranch::BRANCH_MMRBLAKE_NODE, 2, 0, std::vector<uint256>({GetHash()}));
    }

    // this does not work on blocks prior to the Verus PBaaS hard fork
    // to force that to work, the block MMR root will need to be calculated from
    // the actual block. since blocks being proven are expected to be post-fork
    // and transaction proofs will work on all blocks, this should be fine
    CMMRNodeBranch BlockProofBridge()
    {
        // we need to add the merkle root on the left
        return CMMRNodeBranch(CMMRNodeBranch::BRANCH_MMRBLAKE_NODE, 2, 1, std::vector<uint256>({GetBlockMMRRoot()}));
    }
};

// this class is used to address the type mismatch that existed between nodes, where block headers
// were being serialized by senders as CBlock and deserialized as CBlockHeader + an assumed extra
// compact value. although it was working, I made this because it did break, and makes the connection
// between CBlock and CBlockHeader more brittle.
// by using this intentionally specified class instead, we remove an instability in the code that could break
// due to unrelated changes, but stay compatible with the old method.
class CNetworkBlockHeader : public CBlockHeader
{
    public:
        std::vector<CTransaction> compatVec;

    CNetworkBlockHeader() : CBlockHeader()
    {
        SetNull();
    }

    CNetworkBlockHeader(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(compatVec);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        compatVec.clear();
    }
};

// for the MMRs for each block
class CBlock;
typedef COverlayNodeLayer<CDefaultMMRNode, CBlock> BlockMMRNodeLayer;
typedef CMerkleMountainRange<CDefaultMMRNode, CChunkedLayer<CDefaultMMRNode, 2>, BlockMMRNodeLayer> BlockMMRange;
typedef CMerkleMountainView<CDefaultMMRNode, CChunkedLayer<CDefaultMMRNode, 2>, BlockMMRNodeLayer> BlockMMView;

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vMerkleTree.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashFinalSaplingRoot   = hashFinalSaplingRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nSolution      = nSolution;
        return block;
    }

    // Build the in-memory merkle tree for this block and return the merkle root.
    // If non-NULL, *mutated is set to whether mutation was detected in the merkle
    // tree (a duplication of transactions in the block leading to an identical
    // merkle root).
    uint32_t GetHeight() const;
    uint256 BuildMerkleTree(bool* mutated = NULL) const;
    BlockMMRange BuildBlockMMRTree(const uint256 &entropyHash) const;
    BlockMMRange GetBlockMMRTree(const uint256 &entropyHash) const;

    // get transaction node from the block
    CDefaultMMRNode GetMMRNode(int index) const;

    CPartialTransactionProof GetPartialTransactionProof(const CTransaction &tx, int txIndex, const std::vector<std::pair<int16_t, int16_t>> &partIndexes=std::vector<std::pair<int16_t, int16_t>>(), const uint256 &pastHash=uint256()) const;

    std::vector<uint256> GetMerkleBranch(int nIndex) const;
    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);
    std::string ToString() const;
};


uint256 BuildMerkleTree(bool* fMutated, const std::vector<uint256> leaves,
        std::vector<uint256> &vMerkleTree);

std::vector<uint256> GetMerkleBranch(int nIndex, int nLeaves, const std::vector<uint256> &vMerkleTree);


/**
 * Custom serializer for CBlockHeader that omits the nonce and solution, for use
 * as input to Equihash.
 */
class CEquihashInput : private CBlockHeader
{
public:
    CEquihashInput(const CBlockHeader &header)
    {
        CBlockHeader::SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nTime);
        READWRITE(nBits);
    }
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }

    friend bool operator==(const CBlockLocator& a, const CBlockLocator& b) {
        return (a.vHave == b.vHave);
    }
};

// class that enables efficient cross-chain proofs of a block
class CBlockHeaderProof
{
public:
    enum {
        VERSION_INVALID = INT32_MAX,
        VERSION_CURRENT = 0,
        VERSION_FIRST = 0,
        VERSION_LAST = 0,
    };
    uint32_t version;
    CMMRProof headerProof;                                  // proof of the block power node
    CMMRNodeBranch mmrBridge;                               // merkle bridge that also provides a block hash
    CPBaaSPreHeader preHeader;                              // non-canonical information from block header

    CBlockHeaderProof(uint32_t nVersion=VERSION_INVALID) : version(nVersion) {}
    CBlockHeaderProof(const CBlockHeaderProof &obj) : version(obj.version), headerProof(obj.headerProof), mmrBridge(obj.mmrBridge), preHeader(obj.preHeader) {}
    CBlockHeaderProof(const CMMRProof &powerNodeProof, const CBlockHeader &bh, uint32_t nVersion=VERSION_CURRENT) :
        headerProof(powerNodeProof), mmrBridge(bh.MMRProofBridge()), preHeader(bh), version(nVersion) {}

    CBlockHeaderProof(const UniValue &uniObj)
    {
        try
        {
            std::string hexData = uni_get_str(find_value(uniObj, "hex"));
            if (!hexData.empty() && IsHex(hexData))
            {
                ::FromVector(ParseHex(hexData), *this);
            }
        }
        catch(...)
        {
            version = VERSION_INVALID;
        }
    }

    const CBlockHeaderProof &operator=(const CBlockHeaderProof &operand)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << operand;
        s >> *this;
        return *this;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(version));
        if (version >= VERSION_FIRST && version <= VERSION_LAST)
        {
            READWRITE(headerProof);
            READWRITE(mmrBridge);
            READWRITE(preHeader);
        }
    }

    CBlockHeader NonCanonicalHeader(const CBlockHeader &header)
    {
        CBlockHeader bh(header);
        preHeader.SetBlockData(bh);
        return bh;
    }

    int32_t BlockNum()
    {
        if (headerProof.proofSequence.size() && headerProof.proofSequence[0]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE)
        {
            return ((CMMRPowerNodeBranch *)(headerProof.proofSequence[0]))->nIndex;
        }
        return -1;
    }

    uint256 BlockHash()
    {
        return mmrBridge.branch.size() == 1 ? mmrBridge.branch[0] : uint256();
    }

    CPBaaSPreHeader BlockPreHeader()
    {
        return preHeader;
    }

    uint256 GetBlockPower() const
    {
        int proofIdx = headerProof.proofSequence.size() == 2 ? 1 : 0;
        if (headerProof.proofSequence.size() && headerProof.proofSequence[proofIdx]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE)
        {
            std::vector<uint256> &branch = ((CMMRPowerNodeBranch *)(headerProof.proofSequence[proofIdx]))->branch;
            if (branch.size() >= 1)
            {
                return branch[0];
            }
        }
        return uint256();
    }

    uint32_t GetBlockHeight() const
    {
        int proofIdx = headerProof.proofSequence.size() == 2 ? 1 : 0;
        if (headerProof.proofSequence.size() && headerProof.proofSequence[proofIdx]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE)
        {
            return ((CMMRPowerNodeBranch *)(headerProof.proofSequence[proofIdx]))->nIndex;
        }
        return 0;
    }

    // a block header proof validates the block MMR root, which is used
    // for proving down to the transaction sub-component. the first value
    // hashed against is the block hash, which enables proving the block hash as well
    uint256 ValidateBlockMMRRoot(const uint256 &checkHash, int32_t blockHeight) const;

    uint256 ValidateBlockHash(const uint256 &checkHash, int blockHeight) const;

    UniValue ToUniValue() const
    {
        UniValue retVal(UniValue::VOBJ);
        retVal.pushKV("version", (int64_t)version);
        std::vector<unsigned char> thisVec = ::AsVector(*this);
        retVal.pushKV("hex", HexBytes(&(thisVec[0]), thisVec.size()));
        return retVal;
    }

    bool IsValid() const
    {
        return version >= VERSION_FIRST && version <= VERSION_LAST;
    }
};

// class that enables efficient cross-chain proofs of a block
class CBlockHeaderAndProof
{
public:
    enum {
        VERSION_CURRENT = 0,
        VERSION_FIRST = 0,
        VERSION_LAST = 0,
        VERSION_INVALID = UINT32_MAX,
    };
    uint32_t version;
    CMMRProof headerProof;                                  // proof of the block power node
    CBlockHeader blockHeader;                               // full block header

    CBlockHeaderAndProof(uint32_t nVersion=VERSION_INVALID) : version(nVersion) {}
    CBlockHeaderAndProof(const CMMRProof &powerNodeProof, const CBlockHeader &bh, uint32_t nVersion=VERSION_CURRENT) :
        headerProof(powerNodeProof), blockHeader(bh), version(nVersion) {}

    CBlockHeaderAndProof(const UniValue &uniObj) : version(VERSION_CURRENT)
    {
        try
        {
            std::string hexData = uni_get_str(find_value(uniObj, "hex"));
            if (!hexData.empty() && IsHex(hexData))
            {
                ::FromVector(ParseHex(hexData), *this);
            }
        }
        catch(...)
        {
            version = VERSION_INVALID;
        }
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(version));
        if (version >= VERSION_FIRST && version <= VERSION_LAST)
        {
            READWRITE(headerProof);
            READWRITE(blockHeader);
        }
    }

    UniValue ToUniValue() const
    {
        UniValue retVal(UniValue::VOBJ);
        retVal.pushKV("version", (int64_t)version);
        std::vector<unsigned char> thisVec = ::AsVector(*this);
        retVal.pushKV("hex", HexBytes(&(thisVec[0]), thisVec.size()));
        return retVal;
    }

    CBlockHeader NonCanonicalHeader()
    {
        return blockHeader;
    }

    int32_t BlockNum()
    {
        if (headerProof.proofSequence.size() && headerProof.proofSequence[0]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE)
        {
            return ((CMMRPowerNodeBranch *)(headerProof.proofSequence[0]))->nIndex;
        }
        return -1;
    }

    uint256 BlockHash()
    {
        return blockHeader.GetHash();
    }

    CPBaaSPreHeader BlockPreHeader()
    {
        return CPBaaSPreHeader(blockHeader);
    }

    uint256 GetBlockPower() const
    {
        int proofIdx = headerProof.proofSequence.size() == 2 ? 1 : 0;
        if (headerProof.proofSequence.size() && headerProof.proofSequence[proofIdx]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE)
        {
            std::vector<uint256> &branch = ((CMMRPowerNodeBranch *)(headerProof.proofSequence[proofIdx]))->branch;
            if (branch.size() >= 1)
            {
                return branch[0];
            }
        }
        return uint256();
    }

    uint32_t GetBlockHeight() const
    {
        int proofIdx = headerProof.proofSequence.size() == 2 ? 1 : 0;
        if (headerProof.proofSequence.size() && headerProof.proofSequence[proofIdx]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE)
        {
            return ((CMMRPowerNodeBranch *)(headerProof.proofSequence[proofIdx]))->nIndex;
        }
        return 0;
    }

    // a block header proof validates the block MMR root, which is used
    // for proving down to the transaction sub-component. the first value
    // hashed against is the block hash, which enables proving the block hash as well
    uint256 ValidateBlockMMRRoot(const uint256 &checkHash, int32_t blockHeight) const;
    uint256 ValidateBlockHash(const uint256 &checkHash, int blockHeight) const;
    uint256 ValidateBlockHash(const uint160 &chainID, const uint256 &checkHash, int blockHeight) const;

    // simple version check
    bool IsValid() const
    {
        return version >= VERSION_FIRST &&
               version <= VERSION_LAST &&
               blockHeader.nVersion != 0;
    }
};

// these are object types that can be stored and recognized in an opret array
enum CHAIN_OBJECT_TYPES
{
    CHAINOBJ_INVALID = 0,
    CHAINOBJ_HEADER = 1,            // serialized full block header w/proof
    CHAINOBJ_HEADER_REF = 2,        // equivalent to header, but only includes non-canonical data
    CHAINOBJ_TRANSACTION_PROOF = 3, // serialized transaction or partial transaction with proof
    CHAINOBJ_PROOF_ROOT = 4,        // merkle proof of preceding block or transaction
    CHAINOBJ_COMMITMENTDATA = 5,    // prior block commitments to ensure recognition of overlapping notarizations
    CHAINOBJ_RESERVETRANSFER = 6,   // serialized transaction, sometimes without an opret, which will be reconstructed
    CHAINOBJ_RESERVED = 7,          // unused and reserved
    CHAINOBJ_CROSSCHAINPROOF = 8,   // specific composite object, which is a single or multi-proof
    CHAINOBJ_NOTARYSIGNATURE = 9,   // notary signature
    CHAINOBJ_EVIDENCEDATA = 10      // flexible evidence data
};

std::vector<uint32_t> UnpackBlockCommitment(__uint128_t oneBlockCommitment);

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

class CHashCommitments
{
public:
    enum {
        VERSION_CURRENT = 0,
        VERSION_FIRST = 0,
        VERSION_LAST = 0,
        VERSION_INVALID = INT32_MAX
    };
    uint32_t version;
    std::vector<uint256> hashCommitments;       // prior block commitments, which are node hashes that include merkle root, block hash, and compact power
    uint256 commitmentTypes;                    // context dependent flags for commitments

    CHashCommitments(uint32_t nVersion=VERSION_INVALID) :  version(nVersion) {}
    CHashCommitments(const std::vector<uint256> &priors, const uint256 &pastTypes, uint32_t nVersion=VERSION_CURRENT) :
        hashCommitments(priors), commitmentTypes(pastTypes), version(nVersion) {}

    // takes any size vector of 128 byte values with a low bool indicator, packs them in with the indicator
    // in bits for commitment types. if there are more than 256 total when finished, the first 256 are represented
    // in the commitmentTypes as low bit boolean indicators of PoS vs. PoW (PoS == true)
    CHashCommitments(const std::vector<__uint128_t> &smallCommitmentsLowBool, uint32_t nVersion=VERSION_CURRENT);

    CHashCommitments(const UniValue &uniObj, uint32_t nVersion=VERSION_CURRENT)
    {
        try
        {
            version = uni_get_int64(find_value(uniObj, "version"), nVersion);
            std::string hexData = uni_get_str(find_value(uniObj, "hex"));
            if (!hexData.empty() && IsHex(hexData))
            {
                ::FromVector(ParseHex(hexData), *this);
            }
        }
        catch(...)
        {
            version = VERSION_INVALID;
        }
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(VARINT(version));
        if (version >= VERSION_FIRST && version <= VERSION_LAST)
        {
            READWRITE(hashCommitments);
            READWRITE(commitmentTypes);
        }
    }

    UniValue ToUniValue() const
    {
        UniValue retVal(UniValue::VOBJ);
        retVal.pushKV("version", (int64_t)version);
        std::vector<unsigned char> thisVec = ::AsVector(*this);
        retVal.pushKV("hex", HexBytes(&(thisVec[0]), thisVec.size()));
        return retVal;
    }

    uint256 GetSmallCommitments(std::vector<__uint128_t> &smallCommitments) const;

    bool IsValid() const
    {
        return version >= VERSION_FIRST && version <= VERSION_LAST;
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

class CNotarySignature
{
public:
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1
    };

    uint8_t version;
    uint160 systemID;                       // system this evidence is from
    CUTXORef output;                        // output to finalize or root notarization for partial tx proof, can have multiple for one object output
    bool confirmed;                         // confirmed or rejected if signed
    std::map<CIdentityID, CIdentitySignature> signatures; // one or more notary signatures with same statements combined

    CNotarySignature(uint8_t nVersion=VERSION_CURRENT) : version(nVersion) {}
    CNotarySignature(const uint160 &sysID,
                     const CUTXORef &finalRef,
                     bool Confirmed=true,
                     const std::map<CIdentityID, CIdentitySignature> &Signatures=std::map<CIdentityID, CIdentitySignature>(),
                     uint8_t Version=VERSION_CURRENT) :
                        version(Version),
                        systemID(sysID),
                        output(finalRef),
                        confirmed(Confirmed),
                        signatures(Signatures)
    {}

    CNotarySignature(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CNotarySignature(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(systemID);
        READWRITE(output);
        READWRITE(confirmed);
        std::vector<std::pair<CIdentityID, CIdentitySignature>> sigVec;
        if (ser_action.ForRead())
        {
            READWRITE(sigVec);
            for (auto &oneSig : sigVec)
            {
                signatures[oneSig.first] = oneSig.second;
            }
        }
        else
        {
            for (auto &oneSigPair : signatures)
            {
                sigVec.push_back(oneSigPair);
            }
            READWRITE(sigVec);
        }
    }

    static std::string NotarySignatureKeyName()
    {
        return "vrsc::system.notarization.signature";
    }

    static uint160 NotarySignatureKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotarySignatureKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string NotarySignaturesKeyName()
    {
        return "vrsc::system.notarization.signatures";
    }

    static uint160 NotarySignaturesKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotarySignaturesKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string NotarizationHashDataKeyName()
    {
        return "vrsc::system.notarization.hashdata";
    }

    static uint160 NotarizationHashDataKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotarizationHashDataKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string NotaryConfirmedKeyName()
    {
        return "vrsc::system.notarization.confirmed";
    }

    static uint160 NotaryConfirmedKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotaryConfirmedKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string NotaryRejectedKeyName()
    {
        return "vrsc::system.notarization.rejected";
    }

    static uint160 NotaryRejectedKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotaryRejectedKeyName(), nameSpace);
        return signatureKey;
    }

    bool IsConfirmed() const
    {
        return confirmed;
    }

    bool IsRejected() const
    {
        return !confirmed;
    }

    bool IsSigned() const
    {
        return signatures.size() != 0;
    }

    UniValue ToUniValue() const;

    bool IsValid() const
    {
        return version >= VERSION_FIRST &&
               version <= VERSION_LAST &&
               !systemID.IsNull() &&
               output.IsValid() &&
               signatures.size();
    }
};

class CEvidenceData
{
public:
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1
    };

    class CMultiPartDescriptor {
    public:
        uint32_t index;                         // index of this object in all sub-objects of this data
        int64_t totalLength;                    // length of the total data
        int64_t start;                          // start offset from 0
        CMultiPartDescriptor() : index(0), totalLength(0), start(0) {}
        CMultiPartDescriptor(uint32_t IndexNum, int64_t TotalLength, int64_t Start) : index(IndexNum), totalLength(TotalLength), start(Start) {}

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(VARINT(index));
            READWRITE(VARINT(totalLength));
            READWRITE(VARINT(start));
        }
    };

    enum ETypes {
        TYPE_INVALID = 0,
        TYPE_FIRST_VALID = 1,
        TYPE_DATA = 1,                      // holding a transaction proof of export with finalization referencing finalization of root notarization
        TYPE_MULTIPART_DATA = 2,            // this is used to combine multiple outputs that can be used to reconstruct one evidence set
        TYPE_LAST_VALID = 2,
    };

    uint32_t version;
    uint32_t type;                          // is this local or referenced data, etc.

    union {
        CMultiPartDescriptor md;            // if this is multipart, there is no VDXF descriptor
        uint160 vdxfd;                      // vdxfDescriptor is only for non-multipart types
    };

    std::vector<unsigned char> dataVec;     // actual data or reference, depending on type

    CEvidenceData(uint32_t EvidenceType=TYPE_DATA, uint32_t nVersion=VERSION_CURRENT) : type(EvidenceType), version(nVersion) {}

    CEvidenceData(const std::vector<unsigned char> &DataVec, uint32_t IndexNum, int64_t TotalLength, int64_t Start,
                  uint32_t EvidenceType=TYPE_DATA, uint32_t nVersion=VERSION_CURRENT) :
        type(EvidenceType),
        version(nVersion),
        dataVec(DataVec)
    {
        if (type == TYPE_MULTIPART_DATA)
        {
            md = CMultiPartDescriptor(IndexNum, TotalLength, Start);
        }
    }

    CEvidenceData(uint160 vdxfKey, const std::vector<unsigned char> &DataVec, uint32_t nVersion=VERSION_CURRENT) :
        type(TYPE_DATA),
        vdxfd(vdxfKey),
        version(nVersion),
        dataVec(DataVec) {}

    CEvidenceData(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CEvidenceData(const UniValue &uni)
    {
        try
        {
            std::string hexData = uni_get_str(find_value(uni, "hex"));
            if (!hexData.empty() && IsHex(hexData))
            {
                ::FromVector(ParseHex(hexData), *this);
            }
        }
        catch(...)
        {
            version = VERSION_INVALID;
        }
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(version));
        READWRITE(VARINT(version));
        if (version >= VERSION_FIRST && version <= VERSION_LAST)
        {
            READWRITE(VARINT(type));
            if (type == TYPE_MULTIPART_DATA)
            {
                READWRITE(md);
            }
            else
            {
                READWRITE(vdxfd);
            }
            READWRITE(dataVec);
        }
    }

    // takes two
    const CEvidenceData &mergeData(const CEvidenceData &mergeWith);

    // used to span multiple outputs if a cross-chain proof becomes too big for just one
    std::vector<CEvidenceData> BreakApart(int maxChunkSize=(CScript::MAX_SCRIPT_ELEMENT_SIZE-256)) const;
    static CEvidenceData Reassemble(const std::vector<CEvidenceData> &evidenceVec);

    UniValue ToUniValue() const
    {
        UniValue retVal(UniValue::VOBJ);
        retVal.pushKV("version", (int64_t)version);
        std::vector<unsigned char> thisVec = ::AsVector(*this);
        retVal.pushKV("hex", HexBytes(&(thisVec[0]), thisVec.size()));
        return retVal;
    }

    bool IsValid() const
    {
        return version >= VERSION_FIRST &&
               version <= VERSION_LAST &&
               type >= TYPE_FIRST_VALID &&
               type <= TYPE_LAST_VALID;
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

    CCrossChainProof(uint32_t nVersion=VERSION_CURRENT) : version(nVersion) {}
    CCrossChainProof(const CCrossChainProof &oldObj)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << oldObj;
        s >> *this;
    }
    CCrossChainProof(const std::vector<CBaseChainObject *> &objects, int Version=VERSION_CURRENT) : version(Version), chainObjects(objects) { }
    CCrossChainProof(const UniValue &uniObj);

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
                        CChainObject<CProofRoot> *pNewProof;
                        CChainObject<CBlockHeaderProof> *pNewHeaderRef;
                        CChainObject<CHashCommitments> *pPriors;
                        CChainObject<CReserveTransfer> *pExport;
                        CChainObject<CCrossChainProof> *pCrossChainProof;
                        CChainObject<CNotarySignature> *pNotarySignature;
                        CChainObject<CEvidenceData> *pBytes;
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
                            CProofRoot obj;
                            READWRITE(obj);
                            pNewProof = new CChainObject<CProofRoot>();
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

                        case CHAINOBJ_COMMITMENTDATA:
                        {
                            CHashCommitments obj;
                            READWRITE(obj);
                            pPriors = new CChainObject<CHashCommitments>();
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

                        case CHAINOBJ_NOTARYSIGNATURE:
                        {
                            CNotarySignature obj;
                            READWRITE(obj);
                            pNotarySignature = new CChainObject<CNotarySignature>();
                            if (pNotarySignature)
                            {
                                pNotarySignature->objectType = CHAINOBJ_NOTARYSIGNATURE;
                                pNotarySignature->object = obj;
                            }
                            break;
                        }

                        case CHAINOBJ_EVIDENCEDATA:
                        {
                            CEvidenceData obj;
                            READWRITE(obj);
                            pBytes = new CChainObject<CEvidenceData>();
                            if (pBytes)
                            {
                                pBytes->objectType = CHAINOBJ_EVIDENCEDATA;
                                pBytes->object = obj;
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
        union {
            CChainObject<CBlockHeaderAndProof> *pNewHeader;
            CChainObject<CPartialTransactionProof> *pNewTx;
            CChainObject<CProofRoot> *pNewProof;
            CChainObject<CBlockHeaderProof> *pNewHeaderRef;
            CChainObject<CHashCommitments> *pPriors;
            CChainObject<CReserveTransfer> *pExport;
            CChainObject<CCrossChainProof> *pCrossChainProof;
            CChainObject<CNotarySignature> *pNotarySignature;
            CChainObject<CEvidenceData> *pBytes;
            CBaseChainObject *pobj;
        };

        for (int i = 0; i < chainObjects.size(); i++)
        {
            pobj = chainObjects[i];
            switch(pobj->objectType)
            {
                case CHAINOBJ_HEADER:
                    if (!pNewHeader->object.IsValid()) return false;
                    break;

                case CHAINOBJ_TRANSACTION_PROOF:
                    if (!pNewTx->object.IsValid()) return false;
                    break;

                case CHAINOBJ_HEADER_REF:
                    if (!pNewHeaderRef->object.IsValid()) return false;
                    break;

                case CHAINOBJ_COMMITMENTDATA:
                    if (!pPriors->object.IsValid()) return false;
                    break;

                case CHAINOBJ_PROOF_ROOT:
                    if (!pNewProof->object.IsValid()) return false;
                    break;

                case CHAINOBJ_RESERVETRANSFER:
                    if (!pExport->object.IsValid()) return false;
                    break;

                case CHAINOBJ_CROSSCHAINPROOF:
                    if (!pCrossChainProof->object.IsValid()) return false;
                    break;

                case CHAINOBJ_NOTARYSIGNATURE:
                    if (!pNotarySignature->object.IsValid()) return false;
                    break;

                case CHAINOBJ_EVIDENCEDATA:
                    if (!pBytes->object.IsValid()) return false;
                    break;

                default:
                    return false;
            }
        }
        return (version >= VERSION_FIRST && version <= VERSION_LAST);
    }

    bool Empty() const
    {
        return chainObjects.size() == 0;
    }

    void RemoveElement(int idxNum)
    {
        if (chainObjects.size() > idxNum)
        {
            std::vector<CBaseChainObject *> toRemove;
            toRemove.push_back(chainObjects[idxNum]);
            chainObjects.erase(chainObjects.begin() + idxNum);
            DeleteOpRetObjects(toRemove);
        }
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

    const CCrossChainProof &operator<<(const CBlockHeaderAndProof &headerAndProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CBlockHeaderAndProof>(CHAINOBJ_HEADER, headerAndProof)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CBlockHeaderProof &headerRefProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CBlockHeaderProof>(CHAINOBJ_HEADER_REF, headerRefProof)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CHashCommitments &hashCommitments)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CHashCommitments>(CHAINOBJ_COMMITMENTDATA, hashCommitments)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CProofRoot &proofRoot)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CProofRoot>(CHAINOBJ_PROOF_ROOT, proofRoot)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CEvidenceData &pBytes)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CEvidenceData>(CHAINOBJ_EVIDENCEDATA, pBytes)));
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

    const CCrossChainProof &operator<<(const CNotarySignature &notarySignature)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CNotarySignature>(CHAINOBJ_NOTARYSIGNATURE, notarySignature)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CPartialTransactionProof &partialTxProof)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CPartialTransactionProof>(CHAINOBJ_TRANSACTION_PROOF, partialTxProof)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CBlockHeaderAndProof &headerAndProof)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CBlockHeaderAndProof>(CHAINOBJ_HEADER, headerAndProof)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CBlockHeaderProof &headerProof)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CBlockHeaderProof>(CHAINOBJ_HEADER_REF, headerProof)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CHashCommitments &hashCommitments)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CHashCommitments>(CHAINOBJ_COMMITMENTDATA, hashCommitments)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CProofRoot &proofRoot)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CProofRoot>(CHAINOBJ_PROOF_ROOT, proofRoot)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CEvidenceData &pBytes)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CEvidenceData>(CHAINOBJ_EVIDENCEDATA, pBytes)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CReserveTransfer &reserveTransfer)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CReserveTransfer>(CHAINOBJ_RESERVETRANSFER, reserveTransfer)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CCrossChainProof &crossChainProof)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CCrossChainProof>(CHAINOBJ_CROSSCHAINPROOF, crossChainProof)));
        return *this;
    }

    const CCrossChainProof &insert(int position, const CNotarySignature &notarySignature)
    {
        chainObjects.insert(chainObjects.begin() + position, static_cast<CBaseChainObject *>(new CChainObject<CNotarySignature>(CHAINOBJ_NOTARYSIGNATURE, notarySignature)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CBaseChainObject *baseObj)
    {
        switch (baseObj->objectType)
        {
            case CHAINOBJ_HEADER:
            {
                *this << ((CChainObject<CBlockHeaderAndProof> *)baseObj)->object;
                break;
            }

            case CHAINOBJ_TRANSACTION_PROOF:
            {
                *this << ((CChainObject<CPartialTransactionProof> *)baseObj)->object;
                break;
            }

            case CHAINOBJ_PROOF_ROOT:
            {
                *this << ((CChainObject<CProofRoot> *)baseObj)->object;
                break;
            }

            case CHAINOBJ_HEADER_REF:
            {
                *this << ((CChainObject<CBlockHeaderProof> *)baseObj)->object;
                break;
            }

            case CHAINOBJ_COMMITMENTDATA:
            {
                *this << ((CChainObject<CHashCommitments> *)baseObj)->object;
                break;
            }

            case CHAINOBJ_RESERVETRANSFER:
            {
                *this << ((CChainObject<CReserveTransfer> *)baseObj)->object;
                break;
            }

            case CHAINOBJ_CROSSCHAINPROOF:
            {
                *this << ((CChainObject<CCrossChainProof> *)baseObj)->object;
                break;
            }

            case CHAINOBJ_NOTARYSIGNATURE:
            {
                *this << ((CChainObject<CNotarySignature> *)baseObj)->object;
                break;
            }

            case CHAINOBJ_EVIDENCEDATA:
            {
                *this << ((CChainObject<CEvidenceData> *)baseObj)->object;
                break;
            }
            default:
            {
                printf("%s: invalid chain object data of type: %d\n", __func__, baseObj->objectType);
                LogPrintf("%s: invalid chain object data of type: %d\n", __func__, baseObj->objectType);
                assert(false);
            }
        }
        return *this;
    }

    static std::string NotarySignatureKeyName()
    {
        return CNotarySignature::NotarySignatureKeyName();
    }

    static uint160 NotarySignatureKey()
    {
        return CNotarySignature::NotarySignatureKey();
    }

    static std::string EvidenceDataKeyName()
    {
        return "vrsc::system.crosschain.evidencedata";
    }

    static uint160 EvidenceDataKey()
    {
        static uint160 nameSpace;
        static uint160 byteVectorKey = CVDXF::GetDataKey(EvidenceDataKeyName(), nameSpace);
        return byteVectorKey;
    }

    static std::string HeaderAndProofKeyName()
    {
        return "vrsc::system.crosschain.headerandproof";
    }

    static uint160 HeaderAndProofKey()
    {
        static uint160 nameSpace;
        static uint160 headerProofKey = CVDXF::GetDataKey(HeaderAndProofKeyName(), nameSpace);
        return headerProofKey;
    }

    static std::string HeaderProofKeyName()
    {
        return "vrsc::system.crosschain.headerproof";
    }

    static uint160 HeaderProofKey()
    {
        static uint160 nameSpace;
        static uint160 headerProofKey = CVDXF::GetDataKey(HeaderProofKeyName(), nameSpace);
        return headerProofKey;
    }

    static std::string HashCommitmentsKeyName()
    {
        return "vrsc::system.crosschain.hashcommitments";
    }

    static uint160 HashCommitmentsKey()
    {
        static uint160 nameSpace;
        static uint160 priorBlocksKey = CVDXF::GetDataKey(HashCommitmentsKeyName(), nameSpace);
        return priorBlocksKey;
    }

    static std::string TransactionProofKeyName()
    {
        return "vrsc::system.crosschain.transactionproof";
    }

    static uint160 TransactionProofKey()
    {
        static uint160 nameSpace;
        static uint160 transactionProofKey = CVDXF::GetDataKey(TransactionProofKeyName(), nameSpace);
        return transactionProofKey;
    }

    static std::string ProofRootKeyName()
    {
        return "vrsc::system.crosschain.proofroot";
    }

    static uint160 ProofRootKey()
    {
        static uint160 nameSpace;
        static uint160 proofRootKey = CVDXF::GetDataKey(ProofRootKeyName(), nameSpace);
        return proofRootKey;
    }

    static std::string ReserveTransferKeyName()
    {
        return "vrsc::system.crosschain.reservetransfer";
    }

    static uint160 ReserveTransferKey()
    {
        static uint160 nameSpace;
        static uint160 reserveTransferKey = CVDXF::GetDataKey(ReserveTransferKeyName(), nameSpace);
        return reserveTransferKey;
    }

    static std::string CrossChainProofKeyName()
    {
        return "vrsc::system.crosschain.reservetransfer";
    }

    static uint160 CrossChainProofKey()
    {
        static uint160 nameSpace;
        static uint160 crossChainProofKey = CVDXF::GetDataKey(CrossChainProofKeyName(), nameSpace);
        return crossChainProofKey;
    }

    static const std::map<uint160, int> &KnownVDXFKeys();
    static const std::map<int, uint160> &KnownVDXFIndices();

    UniValue ToUniValue() const;
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
        CChainObject<CProofRoot> *pNewProof;
        CChainObject<CBlockHeaderProof> *pNewHeaderRef;
        CChainObject<CHashCommitments> *pPriors;
        CChainObject<CReserveTransfer> *pExport;
        CChainObject<CCrossChainProof> *pCrossChainProof;
        CChainObject<CNotarySignature> *pNotarySig;
        CChainObject<CEvidenceData> *pBytes;
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
            pNewProof = new CChainObject<CProofRoot>();
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
        case CHAINOBJ_COMMITMENTDATA:
            pPriors = new CChainObject<CHashCommitments>();
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

        case CHAINOBJ_EVIDENCEDATA:
        {
            pBytes = new CChainObject<CEvidenceData>();
            if (pBytes)
            {
                s >> pBytes->object;
                pBytes->objectType = objType;
            }
            break;
        }

        case CHAINOBJ_NOTARYSIGNATURE:
        {
            pNotarySig = new CChainObject<CNotarySignature>();
            if (pNotarySig)
            {
                s >> pNotarySig->object;
                pNotarySig->objectType = objType;
            }
            break;
        }
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
            s << *(CChainObject<CProofRoot> *)pobj;
            return true;
        }

        case CHAINOBJ_EVIDENCEDATA:
        {
            s << *(CChainObject<CEvidenceData> *)pobj;
            return true;
        }

        case CHAINOBJ_HEADER_REF:
        {
            s << *(CChainObject<CBlockHeaderProof> *)pobj;
            return true;
        }

        case CHAINOBJ_COMMITMENTDATA:
        {
            s << *(CChainObject<CHashCommitments> *)pobj;
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
        case CHAINOBJ_NOTARYSIGNATURE:
        {
            s << *(CChainObject<CNotarySignature> *)pobj;
            return true;
        }
    }
    return false;
}

int8_t ObjTypeCode(const CBlockHeaderAndProof &obj);

int8_t ObjTypeCode(const CPartialTransactionProof &obj);

int8_t ObjTypeCode(const CBlockHeaderProof &obj);

int8_t ObjTypeCode(const CHashCommitments &obj);

int8_t ObjTypeCode(const CReserveTransfer &obj);

int8_t ObjTypeCode(const CCrossChainProof &obj);

int8_t ObjTypeCode(const CNotarySignature &obj);

int8_t ObjTypeCode(const CEvidenceData &obj);

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(const std::vector<CBaseChainObject *> &objPtrs);

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora);

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript);

// this is a spend that only exists to provide a signature and be indexed as having done
// so. It is a form of vote, expressed by signing a specific output script, this is used
// for finalizing notarizations and can be used for other types of votes where signatures
// are required.
//
// to be valid, a finalization vote is authorized via the currency definition,
// and, if so, their signature is checked against the serialised notarization in the output
// script. once validated, all IDs are indexed.
//
class CNotaryEvidence
{
public:
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1
    };

    enum EConstants {
        DEFAULT_OUTPUT_VALUE = 0,
    };

    enum ETypes {
        TYPE_INVALID = 0,
        TYPE_NOTARY_EVIDENCE = 1,           // this is notary evidence, including signatures and other types of proofs
        TYPE_MULTIPART_DATA = 2,            // this is used to combine multiple outputs that can be used to reconstruct one evidence set
        TYPE_IMPORT_PROOF = 3,              // this is notary evidence, including signatures and other types of proofs
    };

    enum EStates {
        STATE_INVALID = 0,
        STATE_CONFIRMING = 1,
        STATE_SUPPORTING = 2,
        STATE_REJECTING = 3,
        STATE_PROVINGFALSE = 4,
        STATE_PROVINGTRUE = 5,
        STATE_CONFIRMED = 6,
        STATE_REJECTED = 7
    };

    uint8_t version;
    uint8_t type;
    uint160 systemID;                       // system this evidence is from
    CUTXORef output;                        // output to finalize or root notarization for partial tx proof, can have multiple for one object output
    uint8_t state;                          // confirmed or rejected if signed
    CCrossChainProof evidence;              // evidence in the form of signatures, cross chain proofs of transactions, block hashes, and power

    CNotaryEvidence(uint8_t EvidenceType=TYPE_NOTARY_EVIDENCE,
                    uint8_t nVersion=VERSION_CURRENT,
                    uint8_t State=STATE_CONFIRMED,
                    const uint160 &System=ASSETCHAINS_CHAINID) :
                    version(nVersion), type(EvidenceType), state(State), systemID(System) {}
    CNotaryEvidence(const uint160 &sysID,
                    const CUTXORef &finalRef,
                    uint8_t State=STATE_CONFIRMED,
                    const CCrossChainProof &Evidence=CCrossChainProof(),
                    uint8_t Type=TYPE_NOTARY_EVIDENCE,
                    uint8_t Version=VERSION_CURRENT) :
                    version(Version),
                    type(Type),
                    systemID(sysID),
                    output(finalRef),
                    state(State),
                    evidence(Evidence)
    {}

    CNotaryEvidence(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CNotaryEvidence(const UniValue &uni);

    CNotaryEvidence(const std::vector<CNotaryEvidence> &evidenceVec);
    CNotaryEvidence(const CTransaction &tx, int outputNum, int &afterEvidence, uint8_t EvidenceType=TYPE_NOTARY_EVIDENCE);

    // used to span multiple outputs if a cross-chain proof becomes too big for just one
    std::vector<CNotaryEvidence> BreakApart(int maxChunkSize=(CScript::MAX_SCRIPT_ELEMENT_SIZE-256)) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(type);
        READWRITE(systemID);
        READWRITE(output);
        READWRITE(state);
        READWRITE(evidence);
    }

    // organizes confirmations and rejections by height and also returns rejections and confirmations in a new
    // vector ordered by height
    static std::vector<CNotarySignature> GetConfirmedAndRejectedSignatureMaps(
                                                    const std::vector<CNotarySignature> &allSigVec,
                                                    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &confirmedByHeight,
                                                    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &rejectedByHeight);

    std::vector<CNotarySignature> GetNotarySignatures(std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> *pConfirmedByHeight=nullptr,
                                                      std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> *pRejectedByHeight=nullptr) const
    {
        std::vector<CNotarySignature> retVal;
        for (auto &oneEvidenceItem : evidence.chainObjects)
        {
            if (oneEvidenceItem && oneEvidenceItem->objectType == CHAINOBJ_NOTARYSIGNATURE)
            {
                retVal.push_back(((CChainObject<CNotarySignature> *)oneEvidenceItem)->object);
            }
        }
        if (pConfirmedByHeight || pRejectedByHeight)
        {
            std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> _confirmedByHeight;
            std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> _rejectedByHeight;
            std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &confirmedByHeight = pConfirmedByHeight ? *pConfirmedByHeight : _confirmedByHeight;
            std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &rejectedByHeight = pRejectedByHeight ? *pRejectedByHeight : _rejectedByHeight;

            return GetConfirmedAndRejectedSignatureMaps(retVal, confirmedByHeight, rejectedByHeight);
        }
        return retVal;
    }

    CCrossChainProof GetSelectEvidence(const std::set<int> &evidenceTypes) const
    {
        CCrossChainProof retVal;
        for (auto &oneEvidenceItem : evidence.chainObjects)
        {
            if (oneEvidenceItem && evidenceTypes.count(oneEvidenceItem->objectType))
            {
                retVal << oneEvidenceItem;
            }
        }
        return retVal;
    }

    // merges a second CNotaryEvidence instance with this one, mutating the "this" instance
    CNotaryEvidence &MergeEvidence(const CNotaryEvidence &mergeWith,
                                   bool aggregateSignatures=true,
                                   bool onlySignatures=false);

    CNotaryEvidence &AddToSignatures(const std::set<uint160> &notarySet,
                                     const CIdentityID &signingID,
                                     const CIdentitySignature &idSignature,
                                     uint8_t thisState=STATE_CONFIRMING)
    {
        std::map<CIdentityID, CIdentitySignature> newSigMap;
        newSigMap.insert(std::make_pair(signingID, idSignature));
        CNotarySignature newSignature(systemID, output, true, newSigMap);
        CCrossChainProof sigProof;
        sigProof << newSignature;
        CNotaryEvidence newEvidence(systemID, output, thisState, sigProof);
        MergeEvidence(newEvidence, true);
        return *this;
    }

    EStates CheckSignatureConfirmation(const uint256 &objHash,
                                       CCurrencyDefinition::EHashTypes hashType,
                                       const std::set<uint160> &notarySet,
                                       int minConfirming,
                                       uint32_t checkHeight=0,
                                       uint32_t *pDecisionHeight=nullptr,
                                       std::map<CIdentityID, CIdentitySignature> *pNotarySetRejects=nullptr,
                                       std::map<CIdentityID, CIdentitySignature> *pNotarySetConfirms=nullptr,
                                       std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> *pRejectsByHeight=nullptr,
                                       std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> *pConfirmsByHeight=nullptr) const;

    static std::string NotarySignatureKeyName()
    {
        return CNotarySignature::NotarySignatureKeyName();
    }

    static uint160 NotarySignatureKey()
    {
        return CNotarySignature::NotarySignatureKey();
    }

    static std::string NotarySignaturesKeyName()
    {
        return "vrsc::system.notarization.signatures";
    }

    static uint160 NotarySignaturesKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotarySignaturesKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string NotarizationHashDataKeyName()
    {
        return "vrsc::system.notarization.hashdata";
    }

    static uint160 NotarizationHashDataKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotarizationHashDataKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string NotaryConfirmedKeyName()
    {
        return "vrsc::system.notarization.confirmed";
    }

    static uint160 NotaryConfirmedKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotaryConfirmedKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string NotaryRejectedKeyName()
    {
        return "vrsc::system.notarization.rejected";
    }

    static uint160 NotaryRejectedKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(NotaryRejectedKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string SkipChallengeKeyName()
    {
        return "vrsc::evidence.skipchallenge";
    }

    static uint160 SkipChallengeKey()
    {
        static uint160 nameSpace;
        static uint160 challengeKey = CVDXF::GetDataKey(SkipChallengeKeyName(), nameSpace);
        return challengeKey;
    }

    static std::string TipChallengeKeyName()
    {
        return "vrsc::evidence.tipchallenge";
    }

    static uint160 TipChallengeKey()
    {
        static uint160 nameSpace;
        static uint160 challengeKey = CVDXF::GetDataKey(TipChallengeKeyName(), nameSpace);
        return challengeKey;
    }

    static std::string ValidityChallengeKeyName()
    {
        return "vrsc::evidence.validitychallenge";
    }

    static uint160 ValidityChallengeKey()
    {
        static uint160 nameSpace;
        static uint160 challengeKey = CVDXF::GetDataKey(ValidityChallengeKeyName(), nameSpace);
        return challengeKey;
    }

    static std::string PrimaryProofKeyName()
    {
        return "vrsc::evidence.primaryproof";
    }

    static uint160 PrimaryProofKey()
    {
        static uint160 nameSpace;
        static uint160 proofKey = CVDXF::GetDataKey(PrimaryProofKeyName(), nameSpace);
        return proofKey;
    }

    static std::string NotarizationTipKeyName()
    {
        return "vrsc::evidence.notarizationtip";
    }

    static uint160 NotarizationTipKey()
    {
        static uint160 nameSpace;
        static uint160 proofKey = CVDXF::GetDataKey(NotarizationTipKeyName(), nameSpace);
        return proofKey;
    }

    CIdentitySignature::ESignatureVerification SignConfirmed(const std::set<uint160> &notarySet, int minConfirming, const CKeyStore &keyStore, const CTransaction &txToConfirm, const CIdentityID &signWithID, uint32_t height, CCurrencyDefinition::EHashTypes hashType, CNotaryEvidence *pNewSignatures=nullptr);
    CIdentitySignature::ESignatureVerification SignRejected(const std::set<uint160> &notarySet, int minConfirming, const CKeyStore &keyStore, const CTransaction &txToConfirm, const CIdentityID &signWithID, uint32_t height, CCurrencyDefinition::EHashTypes hashType, CNotaryEvidence *pNewSignatures=nullptr);

    bool IsMultipartProof() const
    {
        return evidence.chainObjects.size() == 1 &&
               evidence.chainObjects[0]->objectType == CHAINOBJ_EVIDENCEDATA &&
               ((CChainObject<CEvidenceData> *)evidence.chainObjects[0])->object.type == CEvidenceData::TYPE_MULTIPART_DATA;
    }

    bool IsNotaryEvidence() const
    {
        return type == TYPE_NOTARY_EVIDENCE;
    }

    bool IsConfirmed() const
    {
        return state == STATE_CONFIRMED;
    }

    bool IsRejected() const
    {
        return state == STATE_REJECTED;
    }

    bool IsSigned() const
    {
        return GetNotarySignatures().size() != 0;
    }

    UniValue ToUniValue() const;

    bool IsValid() const
    {
        return version >= VERSION_FIRST &&
               version <= VERSION_LAST &&
               !systemID.IsNull() &&
               output.IsValid();
    }

    bool HasEvidence() const
    {
        return IsValid() && evidence.chainObjects.size();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
