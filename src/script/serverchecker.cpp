// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <univalue.h>
#include "serverchecker.h"
#include "script/cc.h"
#include "cc/eval.h"

#include "pubkey.h"
#include "random.h"
#include "uint256.h"
#include "util.h"

#include "pbaas/identity.h"
#include "chain.h"

#undef __cpuid
#include <boost/thread.hpp>
#include <boost/tuple/tuple_comparison.hpp>

extern uint32_t KOMODO_STOPAT;
extern int32_t VERUS_MIN_STAKEAGE;
extern CChain chainActive;

namespace {

/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class CSignatureCache
{
private:
     //! sigdata_type is (signature hash, signature, public key):
    typedef boost::tuple<uint256, std::vector<unsigned char>, CPubKey> sigdata_type;
    std::set< sigdata_type> setValid;
    boost::shared_mutex cs_serverchecker;

public:
    bool
    Get(const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubKey)
    {
        boost::shared_lock<boost::shared_mutex> lock(cs_serverchecker);

        sigdata_type k(hash, vchSig, pubKey);
        std::set<sigdata_type>::iterator mi = setValid.find(k);
        if (mi != setValid.end())
            return true;
        return false;
    }

    void Set(const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubKey)
    {
        // DoS prevention: limit cache size to less than 10MB
        // (~200 bytes per cache entry times 50,000 entries)
        // Since there can be no more than 20,000 signature operations per block
        // 50,000 is a reasonable default.
        int64_t nMaxCacheSize = GetArg("-maxservercheckersize", 50000);
        if (nMaxCacheSize <= 0) return;

        boost::unique_lock<boost::shared_mutex> lock(cs_serverchecker);

        while (static_cast<int64_t>(setValid.size()) > nMaxCacheSize)
        {
            // Evict a random entry. Random because that helps
            // foil would-be DoS attackers who might try to pre-generate
            // and re-use a set of valid signatures just-slightly-greater
            // than our cache size.
            uint256 randomHash = GetRandHash();
            std::vector<unsigned char> unused;
            std::set<sigdata_type>::iterator it =
                setValid.lower_bound(sigdata_type(randomHash, unused, unused));
            if (it == setValid.end())
                it = setValid.begin();
            setValid.erase(*it);
        }

        sigdata_type k(hash, vchSig, pubKey);
        setValid.insert(k);
    }
};

}

// uses blockchain lookup
std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> ServerTransactionSignatureChecker::ExtractIDMap(const CScript &scriptPubKeyIn, uint32_t spendHeight, bool isStake)
{
    // create an ID map here, which late binds to the IDs on the blockchain as of the spend height,
    // and substitute the correct addresses when checking signatures
    COptCCParams p;
    std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> idAddresses;

    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(spendHeight) >= CActivationHeight::ACTIVATE_PBAAS;

    uint32_t checkHeight = chainActive.Height() < spendHeight ? chainActive.Height() : spendHeight - 1;
    bool enforceIDStakeHeightLimit = isPBaaS;

    if (scriptPubKeyIn.IsPayToCryptoCondition(p) && p.IsValid() && p.n >= 1 && p.vKeys.size() >= p.n && p.version >= p.VERSION_V3 && p.vData.size())
    {
        // get mapping to any identities used that are available. if a signing identity is unavailable, a transaction may still be able to be spent
        COptCCParams master = COptCCParams(p.vData.back());
        bool ccValid = master.IsValid();

        CIdentity selfIdentity;
        uint160 selfID;

        if (p.evalCode == EVAL_IDENTITY_PRIMARY)
        {
            selfIdentity = CIdentity(p.vData[0]);
            selfID = selfIdentity.GetID();
        }

        // if we are sign-only, "p" will have no data object of its own, so we do not have to subtract 1
        int loopMax = p.evalCode ? p.vData.size() - 1 : p.vData.size();

        for (int i = 0; ccValid && i < loopMax; i++)
        {
            COptCCParams oneP(i ? p.vData[i] : p);
            ccValid = oneP.IsValid();

            if (ccValid)
            {
                for (auto dest : oneP.vKeys)
                {
                    uint160 destId = GetDestinationID(dest);
                    if (dest.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        // lookup identity
                        CIdentity id;
                        std::pair<CIdentityMapKey, CIdentityMapValue> idMapEntry;
                        bool sourceIsSelf = selfIdentity.IsValid() && destId == selfID;
                        uint32_t idHeight = 0;
                        if (selfIdentity.IsValidUnrevoked() && destId == selfID)
                        {
                            id = selfIdentity;
                        }
                        else
                        {
                            id = CIdentity::LookupIdentity(destId, spendHeight, &idHeight);
                        }
                        // we won't enable a stake spend from an ID that isn't > min stakeage since
                        // its last modification
                        if (id.IsValidUnrevoked() &&
                            ((isStake && (!enforceIDStakeHeightLimit || (idHeight && (spendHeight - idHeight) >= VERUS_MIN_STAKEAGE))) ||
                             sourceIsSelf ||
                             !id.IsLocked(spendHeight)))
                        {
                            std::vector<std::vector<unsigned char>> idAddrBytes;
                            for (auto &oneAddr : id.primaryAddresses)
                            {
                                idAddrBytes.push_back(GetDestinationBytes(oneAddr));
                            }
                            idAddresses[destId] = make_pair(id.minSigs, idAddrBytes);
                        }
                        else if (!id.IsValid())
                        {
                            uint32_t idHeightDef;
                            if ((id = CIdentity::LookupFirstIdentity(destId, &idHeightDef)).IsValid())
                            {
                                LogPrintf("%s: ERROR - ACTION REQUIRED: Corrupt Index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                                printf("%s: ERROR - ACTION REQUIRED: Corrupt Index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                                KOMODO_STOPAT = chainActive.Height();
                            }
                        }
                    }
                }
            }
        }
    }
    return idAddresses;
}

bool ServerTransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    static CSignatureCache signatureCache;

    if (signatureCache.Get(sighash, vchSig, pubkey))
        return true;

    if (!TransactionSignatureChecker::VerifySignature(vchSig, pubkey, sighash))
        return false;

    if (store)
        signatureCache.Set(sighash, vchSig, pubkey);
    return true;
}

/*
 * The reason that these functions are here is that the what used to be the
 * CachingTransactionSignatureChecker, now the ServerTransactionSignatureChecker,
 * is an entry point that the server uses to validate signatures and which is not
 * included as part of bitcoin common libs. Since Crypto-Conditions eval methods
 * may call server code (GetTransaction etc), the best way to get it to run this
 * code without pulling the whole bitcoin server code into bitcoin common was
 * using this class. Thus it has been renamed to ServerTransactionSignatureChecker.
 */
int ServerTransactionSignatureChecker::CheckEvalCondition(const CC *cond, int fulfilled) const
{
    //fprintf(stderr,"call RunCCeval from ServerTransactionSignatureChecker::CheckEvalCondition\n");
    return RunCCEval(cond, *txTo, nIn, fulfilled != 0);
}
