/********************************************************************
 * (C) 2018 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This supports code to catch nothing at stake cheaters who stake
 * on multiple forks.
 *
 */

#include "cc/StakeGuard.h"
#include "script/script.h"
#include "main.h"
#include "hash.h"
#include "cheatcatcher.h"
#include "streams.h"

using namespace std;

CCheatList cheatList;
boost::optional<libzcash::SaplingPaymentAddress> defaultSaplingDest;

uint32_t CCheatList::Prune(uint32_t height)
{
    uint32_t count = 0;
    pair<multimap<const uint32_t, CTxHolder>::iterator, multimap<const uint32_t, CTxHolder>::iterator> range;
    vector<CTxHolder> toPrune;

    if (height > 0 && Params().GetConsensus().NetworkUpgradeActive(height, Consensus::UPGRADE_SAPLING))
    {
        LOCK(cs_cheat);
        for (auto it = orderedCheatCandidates.begin(); it != orderedCheatCandidates.end() && it->second.height <= height; it++)
        {
            toPrune.push_back(it->second);
        }
        count = toPrune.size();
        for (auto &ptxHolder : toPrune)
        {
            Remove(ptxHolder);
        }
    }
    return count;   // return how many removed
}

bool GetStakeParams(const CTransaction &stakeTx, CStakeParams &stakeParams);

bool CCheatList::IsHeightOrGreaterInList(uint32_t height)
{
    auto range = orderedCheatCandidates.equal_range(height);
    //printf("IsHeightOrGreaterInList: %s\n", range.second == orderedCheatCandidates.end() ? "false" : "true");
    return (range.first != orderedCheatCandidates.end() || range.second != orderedCheatCandidates.end());
}

bool CCheatList::IsCheatInList(const CTransaction &tx, CTransaction *cheatTx)
{
    // for a tx to be cheat, it needs to spend the same UTXO and be for a different prior block
    // the list should be pruned before this call
    // we return the first valid cheat we find
    CVerusHashWriter hw = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

    hw << tx.vin[0].prevout.hash;
    hw << tx.vin[0].prevout.n;
    uint256 utxo = hw.GetHash();

    pair<multimap<const uint256, CTxHolder *>::iterator, multimap<const uint256, CTxHolder *>::iterator> range;
    CStakeParams p, s;

    if (GetStakeParams(tx, p))
    {
        LOCK(cs_cheat);
        range = indexedCheatCandidates.equal_range(utxo);

        //printf("IsCheatInList - found candidates: %s\n", range.first == range.second ? "false" : "true");

        for (auto it = range.first; it != range.second; it++)
        {
            CTransaction &cTx = it->second->tx;
            //printf("cTx::opret : %s\n", cTx.vout[1].scriptPubKey.ToString().c_str());

            // need both parameters to check
            if (GetStakeParams(cTx, s))
            {
                if (p.prevHash != s.prevHash && s.blkHeight >= p.blkHeight)
                {
                    *cheatTx = cTx;
                    return true;
                }
            }
        }
    }
    return false;
}

bool CCheatList::IsUTXOInList(COutPoint _utxo, uint32_t height)
{
    // for a tx to be cheat, it needs to spend the same UTXO and be for a different prior block
    // the list should be pruned before this call
    // we return the first valid cheat we find
    CVerusHashWriter hw = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

    hw << _utxo.hash;
    hw << _utxo.n;
    uint256 utxo = hw.GetHash();

    pair<multimap<const uint256, CTxHolder *>::iterator, multimap<const uint256, CTxHolder *>::iterator> range;
    CStakeParams p, s;

    LOCK(cs_cheat);
    range = indexedCheatCandidates.equal_range(utxo);

    for (auto it = range.first; it != range.second; it++)
    {
        CTransaction &cTx = it->second->tx;
        //printf("cTx::opret : %s\n", cTx.vout[1].scriptPubKey.ToString().c_str());

        // need both parameters to check
        if (GetStakeParams(cTx, s))
        {
            if (s.blkHeight >= height)
            {
                return true;
            }
        }
    }
    return false;
}

void CCheatList::Add(const CTxHolder &txh)
{
    if (Params().GetConsensus().NetworkUpgradeActive(txh.height, Consensus::UPGRADE_SAPLING))
    {
        LOCK(cs_cheat);
        auto it = orderedCheatCandidates.insert(pair<const uint32_t, CTxHolder>(txh.height, txh));
        indexedCheatCandidates.insert(pair<const uint256, CTxHolder *>(txh.utxo, &it->second));
        //printf("CCheatList::Add orderedCheatCandidates.size: %d, indexedCheatCandidates.size: %d\n", (int)orderedCheatCandidates.size(), (int)indexedCheatCandidates.size());
    }
}

void CCheatList::Remove(const CTxHolder &txh)
{
    uint32_t count;
    vector<multimap<const uint256, CTxHolder *>::iterator> utxoPrune;
    vector<multimap<const int32_t, CTxHolder>::iterator> heightPrune;

    {
        // if the one found is at less than or equal to the height provided, then it is either the same one or
        // if less than, may have been an orphan and can also be removed
        uint32_t startHeight = txh.height;
        uint32_t endHeight = txh.height;

        LOCK(cs_cheat);
        auto range = indexedCheatCandidates.equal_range(txh.utxo);
        auto it = range.first;
        for ( ; it != range.second; it++)
        {
            if (it->second->height <= txh.height)
            {
                if (it->second->height < startHeight)
                {
                    startHeight = it->second->height;
                }
                utxoPrune.push_back(it);
            }
        }

        // remove those we removed from the height list as well
        auto orderedIt = orderedCheatCandidates.lower_bound(startHeight);
        auto upperIt = orderedCheatCandidates.upper_bound(endHeight);
        for (; orderedIt != upperIt; orderedIt++)
        {
            if (orderedIt->second.utxo == txh.utxo)
            {
                // add and remove them together
                heightPrune.push_back(orderedIt);
            }
        }

        for (auto it : utxoPrune)
        {
            indexedCheatCandidates.erase(it);
        }
        for (auto it : heightPrune)
        {
            orderedCheatCandidates.erase(it);
        }
    }
}
