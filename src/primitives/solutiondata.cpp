// Copyright (c) 2018 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/solutiondata.h"
#include "primitives/block.h"

const int32_t numVersions = 2;
CActivationHeight CConstVerusSolutionVector::activationHeight = CActivationHeight();
CConstVerusSolutionVector CVerusSolutionVector::solutionTools;

bool CCompactSolutionVector::useCompression = true;

void CConstVerusSolutionVector::SetPBaaSHeader(std::vector<unsigned char> &vch, const CPBaaSBlockHeader &pbh, int32_t idx)
{
    if (idx < GetDescriptor(vch).numPBaaSHeaders)
    {
        *(((CPBaaSBlockHeader *)(&vch[0] + sizeof(CPBaaSSolutionDescriptor))) + idx) = pbh;
    }
}

bool CVerusSolutionVector::GetPBaaSHeader(CPBaaSBlockHeader &pbh, uint32_t idx) const
{
    if (idx < GetNumPBaaSHeaders())
    {
        pbh = *(GetFirstPBaaSHeader() + idx);
        return true;
    }
    return false;
}

CPBaaSPreHeader::CPBaaSPreHeader(const CBlockHeader &bh)
{
    hashPrevBlock = bh.hashPrevBlock;
    hashMerkleRoot = bh.hashMerkleRoot;
    hashFinalSaplingRoot = bh.hashFinalSaplingRoot;
    nNonce = bh.nNonce;
    nBits = bh.nBits;
    CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(bh.nSolution);
    if (descr.version >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS_HEADER)
    {
        hashPrevMMRRoot = descr.hashPrevMMRRoot;
        hashBlockMMRRoot = descr.hashBlockMMRRoot;
    }
}

void CPBaaSPreHeader::SetBlockData(CBlockHeader &bh)
{
    bh.hashPrevBlock = hashPrevBlock;
    bh.hashFinalSaplingRoot = hashFinalSaplingRoot;
    bh.nBits = nBits;
    bh.nNonce = nNonce;
    bh.hashMerkleRoot = hashMerkleRoot;
    CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(bh.nSolution);
    if (descr.version >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS)
    {
        descr.hashPrevMMRRoot = hashPrevMMRRoot;
        descr.hashBlockMMRRoot = hashBlockMMRRoot;
        CConstVerusSolutionVector::SetDescriptor(bh.nSolution, descr);
    }
}

CPBaaSBlockHeader::CPBaaSBlockHeader(const uint160 &cID, const CPBaaSPreHeader &pbph) : chainID(cID)
{
    CBLAKE2bWriter hw(SER_GETHASH, PROTOCOL_VERSION);

    // all core data besides version, and solution, which are shared across all headers 
    hw << pbph;

    hashPreHeader = hw.GetHash();
}

