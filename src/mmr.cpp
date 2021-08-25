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


void CMMRProof::DeleteProofSequence()
{
    // delete any objects that may be present
    for (int i = proofSequence.size() - 1; i >= 0 && proofSequence[i]; i--)
    {
        CMerkleBranchBase *pProof = proofSequence[i];
        switch(pProof->branchType)
        {
            case CMerkleBranchBase::BRANCH_BTC:
            {
                delete (CBTCMerkleBranch *)pProof;
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_NODE:
            {
                delete (CMMRNodeBranch *)pProof;
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE:
            {
                delete (CMMRPowerNodeBranch *)pProof;
                break;
            }
            case CMerkleBranchBase::BRANCH_ETH:
            {
                delete (CETHPATRICIABranch *)pProof;
                break;
            }
            default:
            {
                ErrorAndBP("ERROR: likely double-free or memory corruption, unrecognized object in proof sequence");
                // this is likely a memory error
                // delete pProof;
            }
        }
        proofSequence.pop_back();
    }
}

const CMMRProof &CMMRProof::operator<<(const CBTCMerkleBranch &append)
{
    CMerkleBranchBase *pNewProof = new CBTCMerkleBranch(append);
    pNewProof->branchType = CMerkleBranchBase::BRANCH_BTC;
    proofSequence.push_back(pNewProof);
    return *this;
}

const CMMRProof &CMMRProof::operator<<(const CMMRNodeBranch &append)
{
    CMerkleBranchBase *pNewProof = new CMMRNodeBranch(append);
    pNewProof->branchType = CMerkleBranchBase::BRANCH_MMRBLAKE_NODE;
    proofSequence.push_back(pNewProof);
    return *this;
}

const CMMRProof &CMMRProof::operator<<(const CMMRPowerNodeBranch &append)
{
    CMerkleBranchBase *pNewProof = new CMMRPowerNodeBranch(append);
    pNewProof->branchType = CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE;
    proofSequence.push_back(pNewProof);
    return *this;
}

const CMMRProof &CMMRProof::operator<<(const CETHPATRICIABranch &append)
{
    CETHPATRICIABranch *pNewProof = new CETHPATRICIABranch(append);
    pNewProof->branchType = CMerkleBranchBase::BRANCH_ETH;
    proofSequence.push_back(pNewProof);
    return *this;
}

uint256 CMMRProof::CheckProof(uint256 hash) const
{
    for (auto &pProof : proofSequence)
    {
        switch(pProof->branchType)
        {
            case CMerkleBranchBase::BRANCH_BTC:
            {
                hash = ((CBTCMerkleBranch *)pProof)->SafeCheck(hash);
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_NODE:
            {
                hash = ((CMMRNodeBranch *)pProof)->SafeCheck(hash);
                //printf("Result from CMMRNodeBranch check: %s\n", hash.GetHex().c_str());
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE:
            {
                hash = ((CMMRPowerNodeBranch *)pProof)->SafeCheck(hash);
                //printf("Result from CMMRPowerNodeBranch check: %s\n", hash.GetHex().c_str());
                break;
            }
            case CMerkleBranchBase::BRANCH_ETH:
            {
                hash = ((CETHPATRICIABranch *)pProof)->SafeCheck(hash);
                printf("Result from ETHBranch check: %s\n", hash.GetHex().c_str());
                break;
            }
        }
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
