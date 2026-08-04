/********************************************************************
 * (C) 2020 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 */

#include "mmr.h"

// just used for setting breakpoints that may be hard to set and printing messages
void ErrorAndBP(std::string msg)
{
    printf("%s\n", msg.c_str());
    LogPrintf("%s\n", msg.c_str());
}


CMultiPartProof::CMultiPartProof(const std::vector<CMMRProof> &chunkVec) : CMerkleBranchBase(BRANCH_MULTIPART)
{
    for (const CMMRProof &oneChunk : chunkVec)
    {
        assert(oneChunk.IsMultiPart());
        const auto* p = std::get_if<CMultiPartProof>(&oneChunk.proofSequence[0]);
        assert(p);
        vch.insert(vch.end(), p->vch.begin(), p->vch.end());
    }
}

std::vector<CMMRProof> CMultiPartProof::BreakToChunks(int maxSize) const
{
    std::vector<CMMRProof> retVal;

    int curIndex, bytesLeft;
    CDataStream ds(SER_DISK, PROTOCOL_VERSION);
    CMMRProof wrapper;
    wrapper << CMultiPartProof();
    int minOverhead = GetSerializeSize(ds, wrapper);

    // make sure we have some space for overhead and vector in each chunk
    assert(maxSize > minOverhead + 8);

    for (curIndex = 0, bytesLeft = vch.size(); bytesLeft > 0; )
    {
        CMMRProof oneChunk;
        std::vector<unsigned char> oneVch(vch.begin() + curIndex, vch.begin() + curIndex + std::min(vch.size() - curIndex, (size_t)(maxSize - minOverhead)));
        oneChunk << CMultiPartProof(CMerkleBranchBase::BRANCH_MULTIPART, oneVch);

        int removeBytes = GetSerializeSize(ds, oneChunk) - maxSize;

        // if we are at the end and have space
        if (removeBytes <= 0)
        {
            bytesLeft = 0;
            retVal.push_back(oneChunk);
        }
        else
        {
            auto* pEntry = std::get_if<CMultiPartProof>(&oneChunk.proofSequence[0]);
            assert(pEntry);
            std::vector<unsigned char> &oneChunkVec = pEntry->vch;
            oneChunkVec.erase(oneChunkVec.begin() + (oneChunkVec.size() - removeBytes), oneChunkVec.end());
            bytesLeft -= oneChunkVec.size();
            curIndex += oneChunkVec.size();
            retVal.push_back(oneChunk);
        }
    }
    return retVal;
}

void CMMRProof::DeleteProofSequenceEntry(int index)
{
    if (index >= 0 && index < (int)proofSequence.size())
        proofSequence.erase(proofSequence.begin() + index);
}

void CMMRProof::DeleteProofSequence()
{
    proofSequence.clear();
}

const CMMRProof &CMMRProof::operator<<(const CBTCMerkleBranch &append)
{
    proofSequence.emplace_back(append);
    return *this;
}

const CMMRProof &CMMRProof::operator<<(const CMMRNodeBranch &append)
{
    proofSequence.emplace_back(append);
    return *this;
}

const CMMRProof &CMMRProof::operator<<(const CMMRPowerNodeBranch &append)
{
    proofSequence.emplace_back(append);
    return *this;
}

const CMMRProof &CMMRProof::operator<<(const CETHPATRICIABranch &append)
{
    proofSequence.emplace_back(append);
    return *this;
}

const CMMRProof &CMMRProof::operator<<(const CMultiPartProof &append)
{
    proofSequence.emplace_back(append);
    return *this;
}

uint160 CMMRProof::GetNativeAddress() const
{
    uint160 retAddress;
    for (const auto& entry : proofSequence)
    {
        if (const auto* p = std::get_if<CETHPATRICIABranch>(&entry))
            retAddress = p->address;
        else
            return uint160();
    }
    return retAddress;
}

bool CMMRProof::CheckStorageKey(uint32_t height) const
{
    for (const auto& entry : proofSequence)
    {
        if (const auto* p = std::get_if<CETHPATRICIABranch>(&entry))
            return p->CheckStorageKeyHash(height);
        else
            return false;
    }
    return false;
}

uint256 CMMRProof::CheckProof(uint256 hash, bool optimized) const
{
    for (const auto& entry : proofSequence)
    {
        if (const auto* p = std::get_if<CBTCMerkleBranch>(&entry))
            hash = p->SafeCheck(hash);
        else if (const auto* p = std::get_if<CMMRNodeBranch>(&entry))
            hash = p->SafeCheck(hash);
        else if (const auto* p = std::get_if<CMMRPowerNodeBranch>(&entry))
            hash = p->SafeCheck(hash);
        else if (const auto* p = std::get_if<CETHPATRICIABranch>(&entry))
        {
            hash = p->SafeCheck(hash, optimized);
            LogPrint("crosschain", "Result from ETHBranch check: %s\n", hash.GetHex().c_str());
        }
        else
            return uint256();
    }
    return hash;
}

// return the index that would be generated for an mmv of the indicated size at the specified position
uint64_t CMerkleBranchBase::GetMMRProofIndex(uint64_t pos, uint64_t mmvSize, int extrahashes)
{
    uint64_t retIndex = 0;
    int bitPos = 0;
    std::vector<uint64_t> Sizes;
    std::vector<unsigned char> PeakIndexes;
    std::vector<uint64_t> MerkleSizes;

    // printf("%s: pos: %lu, mmvSize: %lu\n", __func__, pos, mmvSize);

    // find a path from the indicated position to the root in the current view
    if (pos > 0 && pos < mmvSize)
    {
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
        for (int passThrough = (layerSize & 1); layerNum == 0 || layerSize > 1; passThrough = (layerSize & 1), layerNum++)
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
            // move to the next position
            bitPos++;
        }

        uint64_t p = pos;
        for (int l = 0; l < Sizes.size(); l++)
        {
            // printf("GetProofBits - Bits.size: %lu\n", Bits.size());

            if (p & 1)
            {
                retIndex |= ((uint64_t)1) << bitPos++;
                p >>= 1;

                for (int i = 0; i < extrahashes; i++)
                {
                    bitPos++;
                }
            }
            else
            {
                // make sure there is one after us to hash with or we are a peak and should be hashed with the rest of the peaks
                if (Sizes[l] > (p + 1))
                {
                    bitPos++;
                    p >>= 1;

                    for (int i = 0; i < extrahashes; i++)
                    {
                        bitPos++;
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
                                retIndex |= ((uint64_t)1) << bitPos;
                                bitPos++;

                                for (int i = 0; i < extrahashes; i++)
                                {
                                    bitPos++;
                                }
                            }
                            else
                            {
                                // hash with the one in front of us
                                bitPos++;

                                for (int i = 0; i < extrahashes; i++)
                                {
                                    bitPos++;
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
    //printf("retindex: %lu\n", retIndex);
    return retIndex;
}
