// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "primitives/block.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <boost/optional.hpp>
#include <stdint.h>

class CBlockIndex;
class CChainParams;
class CScript;
namespace Consensus { struct Params; };

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};
#define KOMODO_MAXGPUCOUNT 65

/** Generate a new block, without valid proof-of-work */
CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn, bool isStake=false, uint256 useNonce=uint256());
CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const std::vector<CTxOut> &minerOutputs, bool isStake=false, uint256 useNonce=uint256());
#ifdef ENABLE_WALLET
boost::optional<CScript> GetMinerScriptPubKey(CReserveKey& reservekey);
CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey, int32_t nHeight, bool isStake=false, uint256 useNonce=uint256());
#else
boost::optional<CScript> GetMinerScriptPubKey();
CBlockTemplate* CreateNewBlockWithKey();
#endif

#ifdef ENABLE_MINING
/** Get script for -mineraddress */
void GetScriptForMinerAddress(boost::shared_ptr<CReserveScript> &script);
/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce, bool buildMerkle=true, uint32_t *pSaveBits=NULL);
/** Run the miner threads */
#ifdef ENABLE_WALLET
    void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads);
#else
    void GenerateBitcoins(bool fGenerate, int nThreads);
#endif
#endif

void UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

#endif // BITCOIN_MINER_H
