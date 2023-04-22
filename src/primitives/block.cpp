// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "mmr.h"

extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_VERUSHASH;
extern uint160 ASSETCHAINS_CHAINID;
extern uint160 VERUS_CHAINID;

// default hash algorithm for block
uint256 (CBlockHeader::*CBlockHeader::hashFunction)() const = &CBlockHeader::GetSHA256DHash;

// does not check for height / sapling upgrade, etc. this should not be used to get block proofs
// on a pre-VerusPoP chain
arith_uint256 GetCompactPower(const uint256 &nNonce, uint32_t nBits, int32_t version)
{
    arith_uint256 bnWork, bnStake = arith_uint256(0);
    arith_uint256 BIG_ZERO = bnStake;

    bool fNegative;
    bool fOverflow;
    bnWork.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow || bnWork == 0)
        return BIG_ZERO;

    // if POS block, add stake
    CPOSNonce nonce(nNonce);
    if (nonce.IsPOSNonce(version))
    {
        bnStake.SetCompact(nonce.GetPOSTarget(), &fNegative, &fOverflow);
        if (fNegative || fOverflow || bnStake == 0)
            return BIG_ZERO;

        // as the nonce has a fixed definition for a POS block, add the random amount of "work" from the nonce, so there will
        // statistically always be a deterministic winner in POS
        arith_uint256 aNonce;

        // random amount of additional stake added is capped to 1/2 the current stake target
        aNonce = UintToArith256(nNonce) | (bnStake << (uint64_t)1);

        // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
        // as it's too large for a arith_uint256. However, as 2**256 is at least as large
        // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
        // or ~bnTarget / (nTarget+1) + 1.
        bnWork = (~bnWork / (bnWork + 1)) + 1;
        bnStake = ((~bnStake / (bnStake + 1)) + 1) + ((~aNonce / (aNonce + 1)) + 1);
        if (!(bnWork >> 128 == BIG_ZERO && bnStake >> 128 == BIG_ZERO))
        {
            return BIG_ZERO;
        }
        return bnWork + (bnStake << 128);
    }
    else
    {
        bnWork = (~bnWork / (bnWork + 1)) + 1;

        // this would be overflow
        if (!((bnWork >> 128) == BIG_ZERO))
        {
            printf("Overflow\n");
            return BIG_ZERO;
        }
        return bnWork;
    }
}

ChainMMRNode CBlockHeader::GetBlockMMRNode() const
{
    uint256 blockHash = GetHash();

    uint256 preHash = ChainMMRNode::HashObj(GetBlockMMRRoot(), blockHash);
    uint256 power = ArithToUint256(GetCompactPower(nNonce, nBits, nVersion));

    return ChainMMRNode(ChainMMRNode::HashObj(preHash, power), power);
}

uint256 CBlockHeader::GetPrevMMRRoot() const
{
    CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
    if (descr.version >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS_HEADER)
    {
        return descr.hashPrevMMRRoot;
    }
    else
    {
        return uint256();
    }
}

void CBlockHeader::SetPrevMMRRoot(const uint256 &prevMMRRoot)
{
    CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
    if (descr.version >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS_HEADER)
    {
        descr.hashPrevMMRRoot = prevMMRRoot;
    }
    CConstVerusSolutionVector::SetDescriptor(nSolution, descr);
}

uint256 CBlockHeader::GetBlockMMRRoot() const
{
    CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
    if (descr.version >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS_HEADER)
    {
        return descr.hashBlockMMRRoot;
    }
    else
    {
        return hashMerkleRoot;
    }
}

void CBlockHeader::SetBlockMMRRoot(const uint256 &transactionMMRRoot)
{
    CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
    if (descr.version >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS_HEADER)
    {
        descr.hashBlockMMRRoot = transactionMMRRoot;
    }
    CConstVerusSolutionVector::SetDescriptor(nSolution, descr);
}

// checks that the solution stored data for this header matches what is expected, ensuring that the
// values in the header match the hash of the pre-header.
bool CBlockHeader::CheckNonCanonicalData(const uint160 &cID) const
{
    CPBaaSPreHeader pbph(*this);
    CPBaaSBlockHeader pbbh1 = CPBaaSBlockHeader(cID, pbph);
    CPBaaSBlockHeader pbbh2;
    int32_t idx = GetPBaaSHeader(pbbh2, cID);
    if (idx != -1)
    {
        if (pbbh1.hashPreHeader == pbbh2.hashPreHeader)
        {
            return true;
        }
    }
    return false;
}

// checks that the solution stored data for this header matches what is expected, ensuring that the
// values in the header match the hash of the pre-header.
bool CBlockHeader::CheckNonCanonicalData() const
{
    // true this chain first for speed
    if (CheckNonCanonicalData(ASSETCHAINS_CHAINID))
    {
        return true;
    }
    else
    {
        CPBaaSSolutionDescriptor d = CVerusSolutionVector::solutionTools.GetDescriptor(nSolution);
        if (CVerusSolutionVector::solutionTools.HasPBaaSHeader(nSolution) != 0)
        {
            int32_t len = CVerusSolutionVector::solutionTools.ExtraDataLen(nSolution, true);
            int32_t numHeaders = d.numPBaaSHeaders;
            if (numHeaders * sizeof(CPBaaSBlockHeader) > len)
            {
                numHeaders = len / sizeof(CPBaaSBlockHeader);
            }
            const CPBaaSBlockHeader *ppbbh = CVerusSolutionVector::solutionTools.GetFirstPBaaSHeader(nSolution);
            for (int32_t i = 0; i < numHeaders; i++)
            {
                if ((ppbbh + i)->chainID == ASSETCHAINS_CHAINID)
                {
                    continue;
                }
                if (CheckNonCanonicalData((ppbbh + i)->chainID))
                {
                    return true;
                }
            }
        }
    }
    return false;
}

// returns -1 on failure, upon failure, pbbh is undefined and likely corrupted
int32_t CBlockHeader::GetPBaaSHeader(CPBaaSBlockHeader &pbh, const uint160 &cID) const
{
    // find the specified PBaaS header in the solution and return its index if present
    // if not present, return -1
    if (nVersion == VERUS_V2)
    {
        // search in the solution for this header index and return it if found
        CPBaaSSolutionDescriptor d = CVerusSolutionVector::solutionTools.GetDescriptor(nSolution);
        if (CVerusSolutionVector::solutionTools.HasPBaaSHeader(nSolution) != 0)
        {
            int32_t len = CVerusSolutionVector::solutionTools.ExtraDataLen(nSolution, true);
            int32_t numHeaders = d.numPBaaSHeaders;
            if (numHeaders * sizeof(CPBaaSBlockHeader) > len)
            {
                numHeaders = len / sizeof(CPBaaSBlockHeader);
            }
            const CPBaaSBlockHeader *ppbbh = CVerusSolutionVector::solutionTools.GetFirstPBaaSHeader(nSolution);
            for (int32_t i = 0; i < numHeaders; i++)
            {
                if ((ppbbh + i)->chainID == cID)
                {
                    pbh = *(ppbbh + i);
                    return i;
                }
            }
        }
    }
    return -1;
}

// returns the index of the new header if added, otherwise, -1
int32_t CBlockHeader::AddPBaaSHeader(const CPBaaSBlockHeader &pbh)
{
    CVerusSolutionVector sv(nSolution);
    CPBaaSSolutionDescriptor d = sv.Descriptor();
    int32_t retVal = d.numPBaaSHeaders;

    // make sure we have space. do not adjust capacity
    // if there is anything in the extradata, we have no more room
    if (!d.extraDataSize && (uint32_t)(sv.ExtraDataLen() / sizeof(CPBaaSBlockHeader)) > 0)
    {
        d.numPBaaSHeaders++;
        sv.SetDescriptor(d);                            // update descriptor to make sure it will accept the set
        sv.SetPBaaSHeader(pbh, d.numPBaaSHeaders - 1);
        return retVal;
    }

    return -1;
}

// add or update the PBaaS header for this block from the current block header & this prevMMR. This is required to make a valid PoS or PoW block.
bool CBlockHeader::AddUpdatePBaaSHeader(const CPBaaSBlockHeader &pbh)
{
    CPBaaSBlockHeader pbbh;
    if (nVersion == VERUS_V2 && CConstVerusSolutionVector::Version(nSolution) >= CActivationHeight::ACTIVATE_PBAAS_HEADER)
    {
        if (int32_t idx = GetPBaaSHeader(pbbh, pbh.chainID) != -1)
        {
            return UpdatePBaaSHeader(pbh);
        }
        else
        {
            return (AddPBaaSHeader(pbh) != -1);
        }
    }
    return false;
}

// add or update the current PBaaS header for this block from the current block header & this prevMMR.
// This is required to make a valid PoS or PoW block.
bool CBlockHeader::AddUpdatePBaaSHeader()
{
    if (nVersion == VERUS_V2 && CConstVerusSolutionVector::Version(nSolution) >= CActivationHeight::ACTIVATE_PBAAS_HEADER)
    {
        CPBaaSBlockHeader pbh(ASSETCHAINS_CHAINID, CPBaaSPreHeader(*this));

        CPBaaSBlockHeader pbbh;
        int32_t idx = GetPBaaSHeader(pbbh, ASSETCHAINS_CHAINID);

        if (idx != -1)
        {
            return UpdatePBaaSHeader(pbh);
        }
        else
        {
            return (AddPBaaSHeader(pbh) != -1);
        }
    }
    return false;
}

uint256 CBlockHeader::GetSHA256DHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetVerusHash() const
{
    if (hashPrevBlock.IsNull())
        // always use SHA256D for genesis block
        return SerializeHash(*this);
    else
        return SerializeVerusHash(*this);
}

uint256 CBlockHeader::GetVerusV2Hash() const
{
    if (hashPrevBlock.IsNull())
    {
        // always use SHA256D for genesis block
        return SerializeHash(*this);
    }
    else
    {
        if (nVersion == VERUS_V2)
        {
            int solutionVersion = CConstVerusSolutionVector::Version(nSolution);

            // in order for this to work, the PBaaS hash of the pre-header must match the header data
            // otherwise, it cannot clear the canonical data and hash in a chain-independent manner
            int pbaasType = CConstVerusSolutionVector::HasPBaaSHeader(nSolution);
            //bool debugPrint = false;
            //if (pbaasType != 0 && solutionVersion == CActivationHeight::SOLUTION_VERUSV5_1)
            //{
            //    debugPrint = true;
            //    printf("%s: version V5_1 header, pbaasType: %d, CheckNonCanonicalData: %d\n", __func__, pbaasType, CheckNonCanonicalData());
            //}
            if (pbaasType != 0 && CheckNonCanonicalData())
            {
                CBlockHeader bh = CBlockHeader(*this);
                bh.ClearNonCanonicalData();
                //if (debugPrint)
                //{
                //    printf("%s\n", SerializeVerusHashV2b(bh, solutionVersion).GetHex().c_str());
                //    printf("%s\n", SerializeVerusHashV2b(*this, solutionVersion).GetHex().c_str());
                //}
                return SerializeVerusHashV2b(bh, solutionVersion);
            }
            else
            {
                //if (debugPrint)
                //{
                //    printf("%s\n", SerializeVerusHashV2b(*this, solutionVersion).GetHex().c_str());
                //}
                return SerializeVerusHashV2b(*this, solutionVersion);
            }
        }
        else
        {
            return SerializeVerusHash(*this);
        }
    }
}

void CBlockHeader::SetSHA256DHash()
{
    CBlockHeader::hashFunction = &CBlockHeader::GetSHA256DHash;
}

void CBlockHeader::SetVerusHash()
{
    CBlockHeader::hashFunction = &CBlockHeader::GetVerusHash;
}

void CBlockHeader::SetVerusV2Hash()
{
    CBlockHeader::hashFunction = &CBlockHeader::GetVerusV2Hash;
}

uint256 CBlockHeader::GetRawVerusPOSHash(int32_t blockVersion, uint32_t solVersion, uint32_t magic, const uint256 &nonce, int32_t height, bool isVerusMainnet)
{
    if (isVerusMainnet && !CPOSNonce::NewNonceActive(height))
    {
        return uint256();
    }
    if (blockVersion == VERUS_V2)
    {
        CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);

        hashWriter << magic;
        hashWriter << nonce;
        hashWriter << height;
        return hashWriter.GetHash();
    }
    else
    {
        CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

        hashWriter << magic;
        hashWriter << nonce;
        hashWriter << height;
        return hashWriter.GetHash();
    }
}

// returns false if unable to fast calculate the VerusPOSHash from the header.
// if it returns false, value is set to 0, but it can still be calculated from the full block
// in that case. the only difference between this and the POS hash for the contest is that it is not divided by the value out
// this is used as a source of entropy
bool CBlockHeader::GetRawVerusPOSHash(uint256 &ret, int32_t nHeight) const
{
    // if below the required height or no storage space in the solution, we can't get
    // a cached txid value to calculate the POSHash from the header
    if (!(CPOSNonce::NewNonceActive(nHeight) && IsVerusPOSBlock()))
    {
        ret = uint256();
        return false;
    }

    ret = GetRawVerusPOSHash(nVersion, CConstVerusSolutionVector::Version(nSolution), ASSETCHAINS_MAGIC, nNonce, nHeight);
    return true;
}

bool CBlockHeader::GetVerusPOSHash(arith_uint256 &ret, int32_t nHeight, CAmount value) const
{
    uint256 raw;
    if (GetRawVerusPOSHash(raw, nHeight))
    {
        ret = UintToArith256(raw) / value;
        return true;
    }
    return false;
}

// depending on the height of the block and its type, this returns the POS hash or the POW hash
uint256 CBlockHeader::GetVerusEntropyHashComponent(int32_t height) const
{
    uint256 retVal;
    // if we qualify as PoW, use PoW hash, regardless of PoS state
    if (IsVerusPOSBlock() && GetRawVerusPOSHash(retVal, height))
    {
        // POS hash
        return retVal;
    }
    return GetHash();
}

uint256 BuildMerkleTree(bool* fMutated, const std::vector<uint256> leaves,
        std::vector<uint256> &vMerkleTree)
{
    /* WARNING! If you're reading this because you're learning about crypto
       and/or designing a new system that will use merkle trees, keep in mind
       that the following merkle tree algorithm has a serious flaw related to
       duplicate txids, resulting in a vulnerability (CVE-2012-2459).

       The reason is that if the number of hashes in the list at a given time
       is odd, the last one is duplicated before computing the next level (which
       is unusual in Merkle trees). This results in certain sequences of
       transactions leading to the same merkle root. For example, these two
       trees:

                   A                A
                 /  \            /    \
                B    C          B       C
               / \    \        / \     / \
              D   E   F       D   E   F   F
             / \ / \ / \     / \ / \ / \ / \
             1 2 3 4 5 6     1 2 3 4 5 6 5 6

       for transaction lists [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6] (where 5 and
       6 are repeated) result in the same root hash A (because the hash of both
       of (F) and (F,F) is C).

       The vulnerability results from being able to send a block with such a
       transaction list, with the same merkle root, and the same block hash as
       the original without duplication, resulting in failed validation. If the
       receiving node proceeds to mark that block as permanently invalid
       however, it will fail to accept further unmodified (and thus potentially
       valid) versions of the same block. We defend against this by detecting
       the case where we would hash two identical hashes at the end of the list
       together, and treating that identically to the block having an invalid
       merkle root. Assuming no double-SHA256 collisions, this will detect all
       known ways of changing the transactions without affecting the merkle
       root.
    */

    vMerkleTree.clear();
    vMerkleTree.reserve(leaves.size() * 2 + 16); // Safe upper bound for the number of total nodes.
    for (std::vector<uint256>::const_iterator it(leaves.begin()); it != leaves.end(); ++it)
        vMerkleTree.push_back(*it);
    int j = 0;
    bool mutated = false;
    for (int nSize = leaves.size(); nSize > 1; nSize = (nSize + 1) / 2)
    {
        for (int i = 0; i < nSize; i += 2)
        {
            int i2 = std::min(i+1, nSize-1);
            if (i2 == i + 1 && i2 + 1 == nSize && vMerkleTree[j+i] == vMerkleTree[j+i2]) {
                // Two identical hashes at the end of the list at a particular level.
                mutated = true;
            }
            vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                       BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
        }
        j += nSize;
    }
    if (fMutated) {
        *fMutated = mutated;
    }
    return (vMerkleTree.empty() ? uint256() : vMerkleTree.back());
}


uint256 CBlock::BuildMerkleTree(bool* fMutated) const
{
    std::vector<uint256> leaves;
    for (int i=0; i<vtx.size(); i++) leaves.push_back(vtx[i].GetHash());
    return ::BuildMerkleTree(fMutated, leaves, vMerkleTree);
}


CDefaultMMRNode CBlock::GetMMRNode(int index) const
{
    if (index >= vtx.size())
    {
        return CDefaultMMRNode(uint256());
    }
    return vtx[index].GetDefaultMMRNode();
}


CPBaaSPreHeader CBlock::GetSubstitutedPreHeader() const
{
    CPBaaSPreHeader substitutedPreHeader(*this);
    auto solutionCopy = nSolution;
    arith_uint256 extraData = (arith_uint256((uint64_t)CVerusSolutionVector(solutionCopy).Version()) << 64) +
                              (arith_uint256((uint64_t)((uint32_t)nVersion)) << 32) +
                              arith_uint256((uint64_t)nTime);

    substitutedPreHeader.hashBlockMMRRoot = ArithToUint256(extraData);
    return substitutedPreHeader;
}


// This creates the MMR tree for the block, which replaces the merkle tree used today
// while enabling a proof of the transaction hash as well as parts of the transaction
// such as inputs, outputs, shielded spends and outputs, transaction header info, etc.
BlockMMRange CBlock::BuildBlockMMRTree() const
{
    // build a tree of transactions, each having both the transaction ID and root of the transaction
    // map's MMR. that enables any part of a transaction in the blockchain to be proven outside the
    // blockchain, without having to also hash an original transaction in order to know what part of it contains.
    // for now, we will duplicate the merkle tree and enable proof of an element within a transaction using the MMR.
    // at some point, we should replace the txid with a fully hashed transaction tree and deprecate standard
    // txids altogether.
    BlockMMRange mmRange(BlockMMRNodeLayer(*this));
    for (auto &tx : vtx)
    {
        mmRange.Add(tx.GetDefaultMMRNode());
    }

    if (IsAdvancedHeader() != 0)
    {
        // add one additional object to the block MMR that contains
        // a hash of the entire CPBaaSPreHeader for this block, except
        // the hashBlockMMRRoot, which is dependent on the rest
        // this enables a blockhash-algorithm-independent proof of
        // sapling transactions, nonces, nBits, and nTime of a block,
        // which is stored in the pre header in place of hashBlockMMRRoot
        // before hashing.
        auto hw = CDefaultMMRNode::GetHashWriter();
        hw << GetSubstitutedPreHeader();
        mmRange.Add(CDefaultMMRNode(hw.GetHash()));
    }

    return mmRange;
}

BlockMMRange CBlock::GetBlockMMRTree() const
{
    // no caching yet, the anticipation of which is why this is separate from build
    return BuildBlockMMRTree();
}

CPartialTransactionProof CBlock::GetPreHeaderProof() const
{
    if (IsAdvancedHeader() != 0)
    {
        // make a partial transaction proof for the export opret only
        BlockMMRange blockMMR(GetBlockMMRTree());
        BlockMMView blockMMV(blockMMR);
        CMMRProof txProof;

        if (!blockMMV.GetProof(txProof, vtx.size()))
        {
            LogPrintf("%s: Cannot make pre header proof in block\n", __func__);
            printf("%s: Cannot make pre header in block\n", __func__);
            return CPartialTransactionProof();
        }
        return CPartialTransactionProof(txProof, CPBaaSPreHeader(*this));
    }
    else
    {
        // invalid proof
        CPartialTransactionProof errorProof;
        errorProof.version = errorProof.VERSION_INVALID;
        return errorProof;
    }
}

CPartialTransactionProof CBlock::GetPartialTransactionProof(const CTransaction &tx, int txIndex, const std::vector<std::pair<int16_t, int16_t>> &partIndexes) const
{
    std::vector<CTransactionComponentProof> components;

    if (IsAdvancedHeader() != 0 && partIndexes.size())
    {
        // make a partial transaction proof for the export opret only
        BlockMMRange blockMMR(GetBlockMMRTree());
        BlockMMView blockMMV(blockMMR);
        CMMRProof txProof;

        if (!blockMMV.GetProof(txProof, txIndex))
        {
            LogPrintf("%s: Cannot make transaction proof in block\n", __func__);
            printf("%s: Cannot make transaction proof in block\n", __func__);
            return CPartialTransactionProof();
        }

        CTransactionMap txMap(tx);
        TransactionMMView txMMV(txMap.transactionMMR);

        for (auto &partIdx : partIndexes)
        {
            components.push_back(CTransactionComponentProof(txMMV, txMap, tx, partIdx.first, partIdx.second));
        }

        return CPartialTransactionProof(txProof, components);
    }
    else
    {
        // make a proof of the whole transaction
        CMMRProof exportProof = CMMRProof() << CBTCMerkleBranch(txIndex, GetMerkleBranch(txIndex));
        return CPartialTransactionProof(exportProof, tx);
    }
}


std::vector<uint256> GetMerkleBranch(int nIndex, int nLeaves, const std::vector<uint256> &vMerkleTree)
{
    std::vector<uint256> vMerkleBranch;
    int j = 0;
    for (int nSize = nLeaves; nSize > 1; nSize = (nSize + 1) / 2)
    {
        int i = std::min(nIndex^1, nSize-1);
        vMerkleBranch.push_back(vMerkleTree[j+i]);
        nIndex >>= 1;
        j += nSize;
    }
    return vMerkleBranch;
}


std::vector<uint256> CBlock::GetMerkleBranch(int nIndex) const
{
    if (vMerkleTree.empty())
        BuildMerkleTree();
    return ::GetMerkleBranch(nIndex, vtx.size(), vMerkleTree);
}


uint256 CBlock::CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
{
    if (nIndex == -1)
        return uint256();
    for (std::vector<uint256>::const_iterator it(vMerkleBranch.begin()); it != vMerkleBranch.end(); ++it)
    {
        if (nIndex & 1)
            hash = Hash(BEGIN(*it), END(*it), BEGIN(hash), END(hash));
        else
            hash = Hash(BEGIN(hash), END(hash), BEGIN(*it), END(*it));
        nIndex >>= 1;
    }
    return hash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, hashFinalSaplingRoot=%s, nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        hashFinalSaplingRoot.ToString(),
        nTime, nBits, nNonce.ToString(),
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    s << "  vMerkleTree: ";
    for (unsigned int i = 0; i < vMerkleTree.size(); i++)
        s << " " << vMerkleTree[i].ToString();
    s << "\n";
    return s.str();
}

// a block header proof validates the block MMR root, which is used
// for proving down to the transaction sub-component. the first value
// hashed against is the block hash, which enables proving the block hash as well
uint256 CBlockHeaderProof::ValidateBlockMMRRoot(const uint256 &checkHash, int32_t blockHeight) const
{
    CBlockHeaderProof bhp = *this;
    // if this proof has a blockproofbridge, replace it with an MMR proof bridge
    if (bhp.headerProof.proofSequence.size() > 1)
    {
        bhp.headerProof.DeleteProofSequenceEntry(0);
    }
    uint256 hash = mmrBridge.SafeCheck(checkHash);
    hash = bhp.headerProof.CheckProof(hash);
    return blockHeight == GetBlockHeight() ? hash : uint256();
}

uint256 CBlockHeaderProof::ValidateBlockHash(const uint256 &checkHash, int blockHeight) const
{
    uint256 hash = headerProof.CheckProof(checkHash);
    return blockHeight == GetBlockHeight() ? hash : uint256();
}

// a block header proof validates the block MMR root, which is used
// for proving down to the transaction sub-component. the first value
// hashed against is the block hash, which enables proving the block hash as well
uint256 CBlockHeaderAndProof::ValidateBlockMMRRoot(const uint256 &checkHash, int32_t blockHeight) const
{
    CBlockHeaderAndProof bhp = *this;
    // if this proof has a blockproofbridge, replace it with an MMR proof bridge
    if (bhp.headerProof.proofSequence.size() > 1)
    {
        bhp.headerProof.DeleteProofSequenceEntry(0);
    }
    uint256 hash = blockHeader.MMRProofBridge().SafeCheck(checkHash);
    hash = bhp.headerProof.CheckProof(hash);
    return blockHeight == GetBlockHeight() ? hash : uint256();
}

UniValue BlockHeaderToUni(const CBlockHeader &block)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", block.GetHash().GetHex()));

    if (block.IsVerusPOSBlock())
    {
        result.push_back(Pair("validationtype", "stake"));
        arith_uint256 posTarget;
        posTarget.SetCompact(block.GetVerusPOSTarget());
        result.push_back(Pair("postarget", ArithToUint256(posTarget).GetHex()));
        CPOSNonce scratchNonce(block.nNonce);
    }
    else
    {
        result.push_back(Pair("validationtype", "work"));
    }

    // Only report confirmations if the block is on the main chain
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("finalsaplingroot", block.hashFinalSaplingRoot.GetHex()));
    result.push_back(Pair("time", (int64_t)block.nTime));
    result.push_back(Pair("nonce", block.nNonce.GetHex()));
    result.push_back(Pair("solution", HexStr(block.nSolution)));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    if (block.nVersion >= block.VERUS_V2)
    {
        auto vch = block.nSolution;
        CPBaaSSolutionDescriptor solDescr = CVerusSolutionVector(vch).Descriptor();
        result.push_back(Pair("previousstateroot", solDescr.hashPrevMMRRoot.GetHex()));
        result.push_back(Pair("blockmmrroot", solDescr.hashBlockMMRRoot.GetHex()));
    }
    result.push_back(Pair("previousblockhash", block.hashPrevBlock.GetHex()));
    std::vector<unsigned char> hexBytes = ::AsVector(block);
    result.push_back(Pair("hex", HexBytes(&(hexBytes[0]), hexBytes.size())));
    return result;
}

uint256 CBlockHeaderAndProof::ValidateBlockHash(const uint256 &checkHash, int blockHeight) const
{
    uint256 hash = headerProof.CheckProof(checkHash);

    if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
    {
        UniValue blockHeaderJSON = BlockHeaderToUni(blockHeader);
        printf("%s: blockHeight: %u, GetBlockHeight(): %u, checkHash: %s, blockHeader: %s\n, blockHeader.GetHash(): %s, returning: %s\n",
            __func__,
            blockHeight,
            GetBlockHeight(),
            checkHash.GetHex().c_str(),
            blockHeaderJSON.write(1,2).c_str(),
            blockHeader.GetHash().GetHex().c_str(),
            (blockHeight == GetBlockHeight() && checkHash == blockHeader.GetHash() ? hash : uint256()).GetHex().c_str());
    }
    return blockHeight == GetBlockHeight() && checkHash == blockHeader.GetHash() ? hash : uint256();
}

// used to span multiple outputs if a cross-chain proof becomes too big for just one
std::vector<CNotaryEvidence> CNotaryEvidence::BreakApart(int maxChunkSize) const
{
    std::vector<CNotaryEvidence> retVal;

    CNotaryEvidence scratchEvidence;

    // we put our entire self into a multipart proof and return multiple parts that must be reconstructed
    std::vector<unsigned char> serialized = ::AsVector(*this);
    size_t fullLength = serialized.size();
    size_t startOffset = 0;
    int indexNum = 0;

    while (serialized.size())
    {
        int curLength = std::min(maxChunkSize, (int)serialized.size());
        CEvidenceData oneDataChunk(std::vector<unsigned char>(&(serialized[0]), &(serialized[0]) + curLength), indexNum++, fullLength, startOffset, CEvidenceData::TYPE_MULTIPART_DATA);
        serialized.erase(serialized.begin(), serialized.begin() + curLength);
        startOffset += curLength;

        CCrossChainProof oneChunkProof;
        oneChunkProof << oneDataChunk;
        retVal.push_back(CNotaryEvidence(systemID, output, state, oneChunkProof, (int)CNotaryEvidence::TYPE_MULTIPART_DATA));
    }

    return retVal;
}

CNotaryEvidence::CNotaryEvidence(const std::vector<CNotaryEvidence> &evidenceVec)
{
    if (!evidenceVec.size() ||
        !evidenceVec[0].IsValid() ||
        evidenceVec[0].type != TYPE_MULTIPART_DATA ||
        evidenceVec[0].evidence.chainObjects.size() != 1 ||
        evidenceVec[0].evidence.chainObjects[0]->objectType != CHAINOBJ_EVIDENCEDATA)
    {
        return;
    }
    size_t fullLength = ((CChainObject<CEvidenceData> *)(evidenceVec[0].evidence.chainObjects[0]))->object.md.totalLength;
    std::vector<unsigned char> fullVec;
    int index = 0;
    for (auto &onePart : evidenceVec)
    {
        if (onePart.type != onePart.TYPE_MULTIPART_DATA ||
            onePart.evidence.chainObjects.size() != 1 ||
            onePart.evidence.chainObjects[0]->objectType != CHAINOBJ_EVIDENCEDATA ||
            ((CChainObject<CEvidenceData> *)(onePart.evidence.chainObjects[0]))->object.type != CEvidenceData::TYPE_MULTIPART_DATA ||
            ((CChainObject<CEvidenceData> *)(onePart.evidence.chainObjects[0]))->object.md.totalLength != fullLength ||
            ((CChainObject<CEvidenceData> *)(onePart.evidence.chainObjects[0]))->object.md.index != index++ ||
            ((CChainObject<CEvidenceData> *)(onePart.evidence.chainObjects[0]))->object.md.start != fullVec.size())
        {
            version = VERSION_INVALID;
            return;
        }
        std::vector<unsigned char> &onePartVec = ((CChainObject<CEvidenceData> *)(onePart.evidence.chainObjects[0]))->object.dataVec;
        fullVec.insert(fullVec.end(), onePartVec.begin(), onePartVec.end());
    }
    ::FromVector(fullVec, *this);
}

CHashCommitments::CHashCommitments(const std::vector<__uint128_t> &smallCommitmentsLowBool, uint32_t nVersion) :
    version(nVersion),
    hashCommitments((smallCommitmentsLowBool.size() >> 1) + (smallCommitmentsLowBool.size() & 1))
{
    std::vector<__uint128_t> smallCommitments = smallCommitmentsLowBool;
    if (smallCommitments.size())
    {
        int lastSmallIndex = (smallCommitments.size() - 1);
        int currentIndex = lastSmallIndex >> 1;
        int currentOffset = lastSmallIndex & 1;
        arith_uint256 typeBitsVal(0);
        for (; currentIndex >= 0 && smallCommitments.size(); smallCommitments.pop_back())
        {
            typeBitsVal = typeBitsVal << 1;
            typeBitsVal |= (smallCommitmentsLowBool.back() & 1);
            arith_uint256 from128 = (arith_uint256(int64_t((uint64_t)(smallCommitments.back() >> 64))) << 64) + arith_uint256(int64_t((uint64_t)smallCommitments.back()));
            hashCommitments[currentIndex] = ArithToUint256(UintToArith256(hashCommitments[currentIndex]) | (currentOffset ? from128 << 128 : from128));
            if (currentOffset ^= 1)
            {
                currentIndex--;
            }
        }
        commitmentTypes = ArithToUint256(typeBitsVal);
    }
}

// returns a vector of unsigned 32 bit values as:
// 0 - nTime
// 1 - nBits
// 2 - nPoSBits
// 3 - (block height << 1) + IsPos bit
std::vector<uint32_t> UnpackBlockCommitment(__uint128_t oneBlockCommitment)
{
    std::vector<uint32_t> retVal;
    retVal.push_back(oneBlockCommitment & UINT32_MAX);
    oneBlockCommitment >>= 32;
    retVal.insert(retVal.begin(), oneBlockCommitment & UINT32_MAX);
    oneBlockCommitment >>= 32;
    retVal.insert(retVal.begin(), oneBlockCommitment & UINT32_MAX);
    oneBlockCommitment >>= 32;
    retVal.insert(retVal.begin(), oneBlockCommitment & UINT32_MAX);
    return retVal;
}

uint256 CHashCommitments::GetSmallCommitments(std::vector<__uint128_t> &smallCommitments) const
{
    // if have something, process it
    if (hashCommitments.size())
    {
        // if the first high 128 bit word != zero, we have two in the last slot, otherwise 1
        int currentBigOffset = ((UintToArith256(hashCommitments.back()) >> 128) != 0) ? 1 : 0;
        smallCommitments = std::vector<__uint128_t>((hashCommitments.size() << 1) - (1 - currentBigOffset));
        int smallIndex = smallCommitments.size() - 1;
        int bigIndex = hashCommitments.size() - 1;

        for (; smallIndex >= 0; smallIndex--)
        {
            arith_uint256 from256 = UintToArith256(hashCommitments[bigIndex]);
            if (!currentBigOffset)
            {
                from256 = from256 << 128;
            }
            from256 = from256 >> 128;
            smallCommitments[smallIndex] = ((__uint128_t)(from256 >> 64).GetLow64() << 64) + (__uint128_t)(from256.GetLow64());
            if (currentBigOffset ^= 1)
            {
                bigIndex--;
            }
        }
        if (LogAcceptCategory("notarization"))
        {
            LogPrintf("%s: RETURNING COMMITMENTS:\n", __func__);
            for (int currentOffset = 0; currentOffset < smallCommitments.size(); currentOffset++)
            {
                auto commitmentVec = UnpackBlockCommitment(smallCommitments[currentOffset]);
                arith_uint256 powTarget, posTarget;
                powTarget.SetCompact(commitmentVec[1]);
                posTarget.SetCompact(commitmentVec[2]);
                LogPrintf("nHeight: %u, nTime: %u, PoW target: %s, PoS target: %s, isPoS: %u\n",
                            commitmentVec[3] >> 1,
                            commitmentVec[0],
                            powTarget.GetHex().c_str(),
                            posTarget.GetHex().c_str(),
                            commitmentVec[3] & 1);
                if (!commitmentVec[1])
                {
                    LogPrintf("INVALID ENTRY\n");
                }
            }
        }
    }
    return commitmentTypes;
}

