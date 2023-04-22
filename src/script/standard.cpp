// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "script/standard.h"

#include "pubkey.h"
#include "script/script.h"
#include "util.h"
#include "utilstrencodings.h"
#include "script/cc.h"
#include "key_io.h"
#include "keystore.h"
#include "pbaas/identity.h"
#include "pbaas/reserves.h"
#include "cc/eval.h"
#include "cc/CCinclude.h"

#include <boost/foreach.hpp>

using namespace std;

typedef vector<unsigned char> valtype;

unsigned nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

COptCCParams::COptCCParams(const std::vector<unsigned char> &vch)
{
    CScript inScr = CScript(vch.begin(), vch.end());
    if (inScr.size() > 1)
    {
        CScript::const_iterator pc = inScr.begin();
        opcodetype opcode;
        std::vector<std::vector<unsigned char>> data;
        std::vector<unsigned char> param;
        bool valid = true;

        while (pc < inScr.end())
        {
            param.clear();
            if (inScr.GetOp(pc, opcode, param))
            {
                if (opcode == OP_0)
                {
                    param.resize(1);
                    param[0] = 0;
                    data.push_back(param);
                }
                else if (opcode >= OP_1 && opcode <= OP_16)
                {
                    param.resize(1);
                    param[0] = (opcode - OP_1) + 1;
                    data.push_back(param);
                }
                else if (opcode > 0 && opcode <= OP_PUSHDATA4 && param.size() > 0)
                {
                    data.push_back(param);
                }
                else
                {
                    valid = false;
                    break;
                }
            }
        }

        if (valid && pc == inScr.end() && data.size() > 0)
        {
            version = 0;
            param = data[0];
            if (param.size() == 4)
            {
                version = param[0];
                evalCode = param[1];
                m = param[2];
                n = param[3];
                if (version == 0 || version > VERSION_V3 || m > n || ((version < VERSION_V3 && n < 1) || n > 4) || (version < VERSION_V3 ? data.size() <= n : data.size() < n))
                {
                    // set invalid
                    version = 0;
                }
                else
                {
                    // load keys and data
                    vKeys.clear();
                    vData.clear();
                    int i;
                    int limit = n == data.size() ? n : n + 1;
                    for (i = 1; version != 0 && i < limit; i++)
                    {
                        std::vector<unsigned char> &keyVec = data[i];
                        if (keyVec.size() == 20)
                        {
                            vKeys.push_back(CKeyID(uint160(keyVec)));
                        }
                        else if (keyVec.size() == 33)
                        {
                            CPubKey key(keyVec);
                            if (key.IsValid())
                            {
                                vKeys.push_back(CTxDestination(key));
                            }
                            else
                            {
                                version = 0;
                            }
                        }
                        else if (version > VERSION_V2 && (keyVec.size() == 21 || keyVec.size() == 34))
                        {
                            // the first byte is an indicator of type of destination, the
                            // rest is either a hash of an ID or another type of address
                            switch (keyVec[0])
                            {
                                case ADDRTYPE_PK:
                                {
                                    if (keyVec.size() == 34)
                                    {
                                        CPubKey key(std::vector<unsigned char>(keyVec.begin() + 1, keyVec.end()));
                                        if (key.IsValid())
                                        {
                                            vKeys.push_back(CTxDestination(key));
                                        }
                                    }
                                    else
                                    {
                                        version = 0;
                                    }
                                    break;
                                }
                                case ADDRTYPE_PKH:
                                {
                                    if (keyVec.size() == 21)
                                    {
                                        vKeys.push_back(CKeyID(uint160(std::vector<unsigned char>(keyVec.begin() + 1, keyVec.end()))));
                                    }
                                    else
                                    {
                                        version = 0;
                                    }
                                    break;
                                }
                                case ADDRTYPE_SH:
                                {
                                    if (keyVec.size() == 21)
                                    {
                                        vKeys.push_back(CScriptID(uint160(std::vector<unsigned char>(keyVec.begin() + 1, keyVec.end()))));
                                    }
                                    else
                                    {
                                        version = 0;
                                    }
                                    break;
                                }
                                case ADDRTYPE_ID:
                                {
                                    if (keyVec.size() == 21)
                                    {
                                        vKeys.push_back(CIdentityID(uint160(std::vector<unsigned char>(keyVec.begin() + 1, keyVec.end()))));
                                    }
                                    else
                                    {
                                        version = 0;
                                    }
                                    break;
                                }
                                case ADDRTYPE_INDEX:
                                {
                                    if (keyVec.size() == 21)
                                    {
                                        vKeys.push_back(CIndexID(uint160(std::vector<unsigned char>(keyVec.begin() + 1, keyVec.end()))));
                                    }
                                    else
                                    {
                                        version = 0;
                                    }
                                    break;
                                }
                                default:
                                    version = 0;
                            }
                        }
                        else
                        {
                            version = 0;
                            break;
                        }
                    }
                    if (version != 0)
                    {
                        // get the rest of the data
                        for ( ; i < data.size(); i++)
                        {
                            vData.push_back(data[i]);
                        }
                    }
                }
            }
        }
    }
}

std::vector<unsigned char> COptCCParams::AsVector() const
{
    CScript cData = CScript();

    cData << std::vector<unsigned char>({version, evalCode, m, n});
    for (auto k : vKeys)
    {
        std::vector<unsigned char> keyBytes = GetDestinationBytes(k);
        if (version > VERSION_V2 && k.which() != ADDRTYPE_PK && k.which() != ADDRTYPE_PKH)
        {
            keyBytes.insert(keyBytes.begin(), (uint8_t)k.which());
        }
        cData << keyBytes;
    }
    for (auto d : vData)
    {
        cData << std::vector<unsigned char>(d);
    }
    return std::vector<unsigned char>(cData.begin(), cData.end());
}

bool IsPayToCryptoCondition(const CScript &scr, COptCCParams &ccParams)
{
    return scr.IsPayToCryptoCondition(ccParams);
}

CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

const char* GetTxnOutputType(txnouttype t)
{
    switch (t)
    {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_NULL_DATA: return "nulldata";
    case TX_CRYPTOCONDITION: return "cryptocondition";
    default: return "invalid";
    }
    return NULL;
}

/**
 * Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
 */
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, vector<vector<unsigned char> >& vSolutionsRet)
{
    if (IsCryptoConditionsEnabled()) {
        // Shortcut for pay-to-crypto-condition
        CScript ccSubScript = CScript();
        std::vector<std::vector<unsigned char>> vParams;
        COptCCParams cp;
        if (scriptPubKey.IsPayToCryptoCondition(cp))
        {
            if (cp.IsValid() && cp.version >= cp.VERSION_V3)
            {
                typeRet = TX_CRYPTOCONDITION;
                static std::set<int> VALID_EVAL_CODES({
                    EVAL_NONE,
                    EVAL_STAKEGUARD,
                    EVAL_CURRENCY_DEFINITION,
                    EVAL_NOTARY_EVIDENCE,
                    EVAL_EARNEDNOTARIZATION,
                    EVAL_ACCEPTEDNOTARIZATION,
                    EVAL_FINALIZE_NOTARIZATION,
                    EVAL_CURRENCYSTATE,
                    EVAL_RESERVE_TRANSFER,
                    EVAL_RESERVE_OUTPUT,
                    EVAL_RESERVE_DEPOSIT,
                    EVAL_CROSSCHAIN_EXPORT,
                    EVAL_CROSSCHAIN_IMPORT,
                    EVAL_IDENTITY_PRIMARY,
                    EVAL_IDENTITY_REVOKE,
                    EVAL_IDENTITY_RECOVER,
                    EVAL_IDENTITY_COMMITMENT,
                    EVAL_IDENTITY_RESERVATION,
                    EVAL_IDENTITY_ADVANCEDRESERVATION,
                    EVAL_FINALIZE_EXPORT,
                    EVAL_FEE_POOL
                });
                if (VALID_EVAL_CODES.count(cp.evalCode))
                {
                    for (auto k : cp.vKeys)
                    {
                        if (k.which() == COptCCParams::ADDRTYPE_SH || k.which() == COptCCParams::ADDRTYPE_ID)
                        {
                            std::vector<unsigned char> vch(GetDestinationBytes(k));
                            vch.insert(vch.begin(), (uint8_t)k.which());
                            vSolutionsRet.push_back(vch);
                        }
                        else
                        {
                            vSolutionsRet.push_back(GetDestinationBytes(k));
                        }
                    }
                    return true;
                }
            }
            else if (scriptPubKey.IsPayToCryptoCondition(&ccSubScript, vParams))
            {
                typeRet = TX_CRYPTOCONDITION;

                if (cp.IsValid())
                {
                    if (cp.evalCode != EVAL_STAKEGUARD)
                    {
                        LogPrint("precheck", "unrecognized smart transaction script type\n");
                        return false;
                    }
                    for (auto k : cp.vKeys)
                    {
                        vSolutionsRet.push_back(GetDestinationBytes(k));
                    }
                }

                uint160 scrHash;
                scrHash = Hash160(ccSubScript);
                vSolutionsRet.push_back(std::vector<unsigned char>(scrHash.begin(), scrHash.end()));
                return true;
            }
            return false;
        }
    }

    // Templates
    static multimap<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

        // Empty, provably prunable, data-carrying output
        if (GetBoolArg("-datacarrier", true))
            mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_RETURN << OP_SMALLDATA));
        mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_RETURN));
    }

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    // Scan templates
    const CScript& script1 = scriptPubKey;
    BOOST_FOREACH(const PAIRTYPE(txnouttype, CScript)& tplate, mTemplates)
    {
        const CScript& script2 = tplate.second;
        vSolutionsRet.clear();

        opcodetype opcode1, opcode2;
        vector<unsigned char> vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        while (true)
        {
            if (pc1 == script1.end() && pc2 == script2.end())
            {
                // Found a match
                typeRet = tplate.first;
                if (typeRet == TX_MULTISIG)
                {
                    // Additional checks for TX_MULTISIG:
                    unsigned char m = vSolutionsRet.front()[0];
                    unsigned char n = vSolutionsRet.back()[0];
                    if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                        return false;
                }
                return true;
            }
            if (!script1.GetOp(pc1, opcode1, vch1))
                break;
            if (!script2.GetOp(pc2, opcode2, vch2))
                break;

            // Template matching opcodes:
            if (opcode2 == OP_PUBKEYS)
            {
                while (vch1.size() >= 33 && vch1.size() <= 65)
                {
                    vSolutionsRet.push_back(vch1);
                    if (!script1.GetOp(pc1, opcode1, vch1))
                        break;
                }
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;
                // Normal situation is to fall through
                // to other if/else statements
            }

            if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() < 33 || vch1.size() > 65)
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_SMALLINTEGER)
            {   // Single-byte small integer pushed onto vSolutions
                if (opcode1 == OP_0 ||
                    (opcode1 >= OP_1 && opcode1 <= OP_16))
                {
                    char n = (char)CScript::DecodeOP_N(opcode1);
                    vSolutionsRet.push_back(valtype(1, n));
                }
                else
                    break;
            }
            else if (opcode2 == OP_SMALLDATA)
            {
                // small pushdata, <= nMaxDatacarrierBytes
                if (vch1.size() > nMaxDatacarrierBytes)
                {
                    //fprintf(stderr,"size.%d > nMaxDatacarrier.%d\n",(int32_t)vch1.size(),(int32_t)nMaxDatacarrierBytes);
                    break;
                }
            }
            else if (opcode1 != opcode2 || vch1 != vch2)
            {
                // Others must match exactly
                break;
            }
        }
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char> >& vSolutions)
{
    switch (t)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return -1;
    case TX_PUBKEY:
        return 1;
    case TX_PUBKEYHASH:
        return 2;
    case TX_MULTISIG:
        if (vSolutions.size() < 1 || vSolutions[0].size() < 1)
            return -1;
        return vSolutions[0][0] + 1;
    case TX_SCRIPTHASH:
        return 1; // doesn't include args needed by the script
    case TX_CRYPTOCONDITION:
        return 1;
    }
    return -1;
}

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType)
{
    vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
    {
        //int32_t i; uint8_t *ptr = (uint8_t *)scriptPubKey.data();
        //for (i=0; i<scriptPubKey.size(); i++)
        //    fprintf(stderr,"%02x",ptr[i]);
        //fprintf(stderr," non-standard scriptPubKey\n");
        return false;
    }

    if (whichType == TX_MULTISIG)
    {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-9 multisig txns as standard
        if (n < 1 || n > 9)
            return false;
        if (m < 1 || m > n)
            return false;
    }
    return whichType != TX_NONSTANDARD;
}

bool ExtractDestination(const CScript& _scriptPubKey, CTxDestination& addressRet, bool returnPubKey)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    CScript scriptPubKey = _scriptPubKey;

    // if this is a CLTV script, get the destination after CLTV
    if (scriptPubKey.IsCheckLockTimeVerify())
    {
        uint8_t pushOp = scriptPubKey[0];
        uint32_t scriptStart = pushOp + 3;

        // check post CLTV script
        scriptPubKey = CScript(scriptPubKey.size() > scriptStart ? scriptPubKey.begin() + scriptStart : scriptPubKey.end(), scriptPubKey.end());
    }

    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid())
        {
            fprintf(stderr,"TX_PUBKEY invalid pubkey\n");
            return false;
        }

        if (returnPubKey)
            addressRet = pubKey;
        else
            addressRet = pubKey.GetID();
        return true;
    }

    else if (whichType == TX_PUBKEYHASH)
    {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_SCRIPTHASH)
    {
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    }

    else if (IsCryptoConditionsEnabled() != 0 && whichType == TX_CRYPTOCONDITION)
    {
        COptCCParams p;
        if (scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.vKeys.size())
        {
            addressRet = p.vKeys[0];
            return true;
        }
    }
    // Multisig txns have more than one address...
    return false;
}

bool ExtractDestinations(const CScript& scriptPubKey,
                         txnouttype& typeRet,
                         std::vector<CTxDestination>& addressRet,
                         int &nRequiredRet,
                         const CKeyStore *pKeyStore,
                         bool *pCanSign,
                         bool *pCanSpend,
                         uint32_t nHeight,
                         std::map<uint160, CKey> *pPrivKeys)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    vector<valtype> vSolutions;

    // if this is a CLTV script, get the destinations after CLTV
    if (scriptPubKey.IsCheckLockTimeVerify())
    {
        uint8_t pushOp = scriptPubKey[0];
        uint32_t scriptStart = pushOp + 3;

        // check post CLTV script
        CScript postfix = CScript(scriptPubKey.size() > scriptStart ? scriptPubKey.begin() + scriptStart : scriptPubKey.end(), scriptPubKey.end());

        // check again with only postfix subscript
        return(ExtractDestinations(postfix, typeRet, addressRet, nRequiredRet, pKeyStore, pCanSign, pCanSpend, nHeight, pPrivKeys));
    }

    int canSpendCount = 0;
    bool canSign = false;

    if (pCanSign)
    {
        *pCanSign = false;
    }
    if (pCanSpend)
    {
        *pCanSpend = false;
    }

    COptCCParams master, p;
    bool ccValid;
    if (scriptPubKey.IsPayToCryptoCondition(p))
    {
        std::set<CScriptID> idSet;

        if (p.IsValid(true, nHeight) &&
            p.n >= 1 &&
            p.vKeys.size() >= p.n)
        {
            typeRet = TX_CRYPTOCONDITION;
            if (p.version < p.VERSION_V3)
            {
                for (auto dest : p.vKeys)
                {
                    uint160 destId = GetDestinationID(dest);
                    addressRet.push_back(dest);
                    if (dest.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        // lookup identity, we must have all registered target identity scripts in our keystore, or we try as if they are a keyID, which will be the same
                        // if revoked or undefined
                        std::pair<CIdentityMapKey, CIdentityMapValue> identity;
                        idSet.insert(destId);

                        if (pKeyStore && pKeyStore->GetIdentity(destId, identity, std::max((uint32_t)1, nHeight - 1)) && identity.second.IsValidUnrevoked())
                        {
                            int canSignCount = 0;
                            for (auto oneKey : identity.second.primaryAddresses)
                            {
                                uint160 oneKeyID = GetDestinationID(oneKey);
                                CKey privKey;
                                if (pKeyStore->GetKey(oneKeyID, privKey))
                                {
                                    canSign = true;
                                    canSignCount++;
                                    if (pPrivKeys)
                                    {
                                        (*pPrivKeys)[oneKeyID] = privKey;
                                    }
                                }
                            }
                            if (canSignCount >= identity.second.minSigs)
                            {
                                canSpendCount++;
                            }
                        }
                    }
                    else if (pKeyStore)
                    {
                        CKey privKey;
                        if (pKeyStore->GetKey(destId, privKey))
                        {
                            canSign = true;
                            canSpendCount++;
                            if (pPrivKeys)
                            {
                                (*pPrivKeys)[destId] = privKey;
                            }
                        }
                    }
                }
                nRequiredRet = p.m;
                if (canSpendCount >= p.m && pCanSpend)
                {
                    *pCanSpend = true;
                }
                if (canSign && pCanSign)
                {
                    *pCanSign = true;
                }
            }
            else if (p.vData.size() && (ccValid = (master = COptCCParams(p.vData.back())).IsValid()))
            {
                // if we have more than master and primary params
                int numConditionsNeeded = 1;
                if (p.vData.size() > 2)
                {
                    numConditionsNeeded = master.m;
                }

                // always add the index keys to destinations, but that has nothing to do with whether or not
                // an ID present in that index represents an address that can sign or spend. ids in this block
                // are ignored, as all IDs in an output are always indexed in the address and unspent indexes.
                std::set<CTxDestination> indexSet;
                for (auto dest : master.vKeys)
                {
                    // all but ID types
                    if (dest.which() != COptCCParams::ADDRTYPE_ID)
                    {
                        // include all non-name addresses from master as destinations as well
                        // name addresses can only be destinations if they are at least "cansign" on one of the subconditions
                        if (!indexSet.count(dest))
                        {
                            addressRet.push_back(dest);
                        }
                        indexSet.insert(dest);
                    }
                }

                // handle the case where we have no object in the params, but a valid transaction
                int loopEnd = p.vData.size() == 1 ? 1 : p.vData.size() - 1;
                for (int i = 0; ccValid && i < loopEnd; i++)
                {
                    // first, process P, then any sub-conditions
                    COptCCParams _oneP;
                    COptCCParams &oneP = (i == 0) ? p : (_oneP = COptCCParams(p.vData[i]));

                    if (ccValid = oneP.IsValid())
                    {
                        int canSpendOneCount = 0;

                        for (auto dest : oneP.vKeys)
                        {
                            uint160 destId = GetDestinationID(dest);
                            if (!indexSet.count(dest))
                            {
                                addressRet.push_back(dest);
                            }
                            if (dest.which() == COptCCParams::ADDRTYPE_ID)
                            {
                                // lookup identity, we must have all registered target identity scripts in our keystore, or we try as if they are a keyID, which will be the same
                                // as if revoked or undefined
                                std::pair<CIdentityMapKey, CIdentityMapValue> identity;
                                idSet.insert(destId);

                                //printf("checking: %s\n", EncodeDestination(dest).c_str());

                                if (pKeyStore && pKeyStore->GetIdentity(destId, identity, std::max((uint32_t)1, nHeight - 1)) && identity.second.IsValidUnrevoked())
                                {
                                    int canSignCount = 0;
                                    for (auto oneKey : identity.second.primaryAddresses)
                                    {
                                        uint160 oneKeyID = GetDestinationID(oneKey);

                                        CKey privKey;
                                        if (pKeyStore->GetKey(oneKeyID, privKey))
                                        {
                                            canSign = true;
                                            canSignCount++;
                                            if (pPrivKeys)
                                            {
                                                (*pPrivKeys)[oneKeyID] = privKey;
                                            }
                                        }
                                    }
                                    if (canSignCount >= identity.second.minSigs)
                                    {
                                        canSpendOneCount++;
                                    }
                                }
                            }
                            else
                            {
                                if (pKeyStore)
                                {
                                    CKey privKey;
                                    if (pKeyStore->GetKey(destId, privKey))
                                    {
                                        canSign = true;
                                        canSpendOneCount++;
                                        if (pPrivKeys)
                                        {
                                            (*pPrivKeys)[destId] = privKey;
                                        }
                                    }
                                }
                            }
                        }
                        if (canSpendOneCount >= oneP.m)
                        {
                            canSpendCount++;
                        }
                    }
                }

                if (!ccValid)
                {
                    LogPrintf("Invalid smart transaction %d\n", p.evalCode);
                    //return false;
                }

                // if this is a compound cc, the master m of n is the top level as an m of n of the sub-conditions
                nRequiredRet = numConditionsNeeded;
                if (canSpendCount >= numConditionsNeeded && pCanSpend)
                {
                    *pCanSpend = true;
                }
                if (canSign && pCanSign)
                {
                    *pCanSign = true;
                }
            }
            else
            {
                CScript subScr;
                if (scriptPubKey.IsPayToCryptoCondition(&subScr))
                {
                    // this kind of ID is defined as a CKeyID, since use of script hash type in CCs are reserved for IDs
                    addressRet.push_back(CKeyID(Hash160(subScr)));
                    nRequiredRet = 1;
                    if (pCanSign)
                    {
                        *pCanSign = true;
                    }
                    if (pCanSpend)
                    {
                        *pCanSpend = true;
                    }
                }
                else
                {
                    return false;
                }
            }
        }
        else
        {
            // if it's a bad smart transaction output, we can't spend it, but
            // that doesn't mean that we should return false unless we are PBaaS or later
            // for compatibility
            if (pCanSign)
            {
                *pCanSign = false;
            }
            if (pCanSpend)
            {
                *pCanSpend = false;
            }
            return CConstVerusSolutionVector::GetVersionByHeight(nHeight) < CActivationHeight::ACTIVATE_PBAAS;
        }
    }
    else
    {
        if (!Solver(scriptPubKey, typeRet, vSolutions))
            return false;

        if (typeRet == TX_NULL_DATA){
            // This is data, not addresses
            return false;
        }

        if (typeRet == TX_MULTISIG)
        {
            nRequiredRet = vSolutions.front()[0];
            int nHaveKeys = 0;
            for (unsigned int i = 1; i < vSolutions.size()-1; i++)
            {
                CPubKey pubKey(vSolutions[i]);
                if (!pubKey.IsValid())
                    continue;

                CTxDestination address = pubKey.GetID();
                addressRet.push_back(address);

                // if we were asked to see whether we can sign or spend, determine
                if ((pCanSign || pCanSpend) && pKeyStore)
                {
                    if (pKeyStore->HaveKey(GetDestinationID(address)))
                    {
                        nHaveKeys++;
                    }
                }
            }

            if (addressRet.empty())
                return false;

            if (pCanSign && nHaveKeys)
            {
                *pCanSign = true;
            }
            if (pCanSpend && nHaveKeys >= nRequiredRet)
            {
                *pCanSpend = true;
            }
        }
        else
        {
            nRequiredRet = 1;
            CTxDestination address;
            if (!ExtractDestination(scriptPubKey, address))
            {
                return false;
            }
            addressRet.push_back(address);
            if ((pCanSign || pCanSpend) && pKeyStore)
            {
                if (pKeyStore->HaveKey(GetDestinationID(address)))
                {
                    if (pCanSign)
                    {
                        *pCanSign = true;
                    }
                    if (pCanSpend)
                    {
                        *pCanSpend = true;
                    }
                }
            }
        }
    }

    return true;
}

namespace
{
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CIndexID &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CQuantumID &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CPubKey &key) const {
        script->clear();
        *script << ToByteVector(key) << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CIdentityID &idID) const {
        *script = CIdentity::TransparentOutput(idID);
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }
};
}

CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;

    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;

    script << CScript::EncodeOP_N(nRequired);
    BOOST_FOREACH(const CPubKey& key, keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
    return script;
}

bool IsValidDestination(const CTxDestination& dest) {
    return dest.which() != 0;
}

bool IsTransparentAddress(const CTxDestination& dest) {
    return dest.which() == 1 || dest.which() == 2;
}

CTxDestination DestFromAddressHash(int scriptType, uint160& addressHash)
{
    switch (scriptType) {
    case CScript::P2PKH:
        return CTxDestination(CKeyID(addressHash));
    case CScript::P2ID:
        return CTxDestination(CIdentityID(addressHash));
    case CScript::P2SH:
        return CTxDestination(CScriptID(addressHash));
    case CScript::P2IDX:
        return CTxDestination(CIndexID(addressHash));
    case CScript::P2QRK:
        return CTxDestination(CQuantumID(addressHash));
    default:
        // This probably won't ever happen, because it would mean that
        // the addressindex contains a type (say, 3) that we (currently)
        // don't recognize; maybe we "dropped support" for it?
        return CNoDestination();
    }
}

CScript::ScriptType AddressTypeFromDest(const CTxDestination &dest)
{
    switch (dest.which()) {

    case COptCCParams::ADDRTYPE_PK:
    case COptCCParams::ADDRTYPE_PKH:
        return CScript::P2PKH;
    case COptCCParams::ADDRTYPE_SH:
        return CScript::P2SH;
    case COptCCParams::ADDRTYPE_ID:
        return CScript::P2ID;
    case COptCCParams::ADDRTYPE_INDEX:
        return CScript::P2IDX;
    case COptCCParams::ADDRTYPE_QUANTUM:
        return CScript::P2QRK;
    default:
        // This probably won't ever happen, because it would mean that
        // the addressindex contains a type (say, 3) that we (currently)
        // don't recognize; maybe we "dropped support" for it?
        return CScript::UNKNOWN;
    }
}

