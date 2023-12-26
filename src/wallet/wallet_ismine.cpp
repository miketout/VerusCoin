// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "wallet_ismine.h"

#include "key.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"
#include "cc/eval.h"
#include "pbaas/identity.h"
#include "cc/CCinclude.h"

#include <boost/foreach.hpp>

using namespace std;

typedef vector<unsigned char> valtype;

unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys)
    {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

isminetype IsMine(const CKeyStore &keystore, const CTxDestination& dest)
{
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script);
}

isminetype IsMine(const CKeyStore &keystore, const CScript& _scriptPubKey, uint32_t height)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    CScript scriptPubKey = _scriptPubKey;

    if (scriptPubKey.IsCheckLockTimeVerify())
    {
        uint8_t pushOp = scriptPubKey[0];
        uint32_t scriptStart = pushOp + 3;

        // continue with post CLTV script
        scriptPubKey = CScript(scriptPubKey.size() > scriptStart ? scriptPubKey.begin() + scriptStart : scriptPubKey.end(), scriptPubKey.end());
    }

    COptCCParams p;
    std::vector<CTxDestination> dests;
    int minSigs;
    bool canSign = false;
    bool canSpend = false;

    if (scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        ExtractDestinations(scriptPubKey, whichType, dests, minSigs, &keystore, &canSign, &canSpend, height))
    {
        bool isAdvancedIdentity = CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_VERUSVAULT;
        if (canSpend)
        {
            std::set<CTxDestination> unknownRecipients;
            // check for multiple recipients, possibly not in this keystore, and if not, it is shared
            if (isAdvancedIdentity && dests.size() > 1)
            {
                for (auto &oneDest : dests)
                {
                    switch (oneDest.which())
                    {
                        case COptCCParams::ADDRTYPE_PK:
                        {
                            if (keystore.HaveKey(GetDestinationID(oneDest)))
                            {
                                continue;
                            }
                            CCcontract_info *cp, C;
                            cp = CCinit(&C, p.evalCode);
                            if (GetDestinationID(DecodeDestination(std::string(cp->unspendableCCaddr))) == GetDestinationID(oneDest))
                            {
                                continue;
                            }
                            unknownRecipients.insert(oneDest);
                            break;
                        }
                        case COptCCParams::ADDRTYPE_PKH:
                        {
                            if (keystore.HaveKey(GetDestinationID(oneDest)))
                            {
                                continue;
                            }
                            CCcontract_info *cp, C;
                            cp = CCinit(&C, p.evalCode);
                            if (DecodeDestination(std::string(cp->unspendableCCaddr)) == oneDest)
                            {
                                continue;
                            }
                            unknownRecipients.insert(oneDest);
                            break;
                        }
                        case COptCCParams::ADDRTYPE_ID:
                        {
                            std::pair<CIdentityMapKey, CIdentityMapValue> retVal;
                            if (keystore.GetIdentity(GetDestinationID(oneDest), retVal) &&
                                retVal.first.CanSpend())
                            {
                                continue;
                            }
                            unknownRecipients.insert(oneDest);
                            break;
                        }
                        case COptCCParams::ADDRTYPE_SH:
                        {
                            if (keystore.HaveCScript(GetDestinationID(oneDest)))
                            {
                                continue;
                            }
                            unknownRecipients.insert(oneDest);
                            break;
                        }
                    }
                }
                if (unknownRecipients.size())
                {
                    return ISMINE_SHARED;
                }
            }
            return ISMINE_SPENDABLE;
        }
        else if (canSign)
        {
            return ISMINE_WATCH_ONLY;
        }
        else
        {
            return ISMINE_NO;
        }
    }
    else if (!Solver(scriptPubKey, whichType, vSolutions))
    {
        if (keystore.HaveWatchOnly(scriptPubKey))
            return ISMINE_WATCH_ONLY;
        return ISMINE_NO;
    }

    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;
    case TX_CRYPTOCONDITION:
        {
            // for now, default is that the first value returned will be the target address, subsequent values will be
            // pubkeys. if we have the first in our wallet, we consider it spendable for now
            if (vSolutions[0].size() == 33)
            {
                keyID = CPubKey(vSolutions[0]).GetID();
            }
            else if (vSolutions[0].size() == 20)
            {
                keyID = CKeyID(uint160(vSolutions[0]));
            }
            if (!keyID.IsNull() && keystore.HaveKey(keyID))
            {
                return ISMINE_SPENDABLE;
            }
        }
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_SCRIPTHASH:
    {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            isminetype ret = IsMine(keystore, subscript);
            if (ret == ISMINE_SPENDABLE)
                return ret;
        }
        break;
    }
    case TX_MULTISIG:
    {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (HaveKeys(keys, keystore) == keys.size())
            return ISMINE_SPENDABLE;
        break;
    }
    }

    if (keystore.HaveWatchOnly(scriptPubKey))
        return ISMINE_WATCH_ONLY;
    return ISMINE_NO;
}
