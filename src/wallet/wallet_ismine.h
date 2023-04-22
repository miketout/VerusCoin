// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_WALLET_WALLET_ISMINE_H
#define BITCOIN_WALLET_WALLET_ISMINE_H

#include "key.h"
#include "script/standard.h"

class CKeyStore;
class CScript;

/** IsMine() return codes */
enum isminetype
{
    ISMINE_NO = 0,
    ISMINE_WATCH_ONLY = 1,
    ISMINE_SPENDABLE = 2,
    ISMINE_CHANGE = 4,
    ISMINE_SHARED = 8,
    ISMINE_ALL = ISMINE_WATCH_ONLY | ISMINE_SPENDABLE,
    ISMINE_ALLANDSHARED = ISMINE_ALL | ISMINE_SHARED,
    ISMINE_ALLANDCHANGE = ISMINE_ALL | ISMINE_CHANGE,
    ISMINE_ALLANDSHAREDANDCHANGE = ISMINE_ALLANDSHARED | ISMINE_CHANGE
};
/** used for bitflags of isminetype */
typedef isminetype isminefilter;

isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey, uint32_t height=INT_MAX);
isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest);

#endif // BITCOIN_WALLET_WALLET_ISMINE_H
