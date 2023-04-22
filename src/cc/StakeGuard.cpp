/********************************************************************
 * (C) 2018 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This crypto-condition eval solves the problem of nothing-at-stake
 * in a proof of stake consensus system.
 *
 */

#include "StakeGuard.h"
#include "script/script.h"
#include "main.h"
#include "hash.h"
#include "key_io.h"
#include "pbaas/pbaas.h"

#include <vector>
#include <map>

#include "streams.h"

extern int32_t VERUS_MIN_STAKEAGE;

bool IsData(opcodetype opcode)
{
    return (opcode >= 0 && opcode <= OP_PUSHDATA4) || (opcode >= OP_1 && opcode <= OP_16);
}

bool UnpackStakeOpRet(const CTransaction &stakeTx, std::vector<std::vector<unsigned char>> &vData)
{
    bool isValid = stakeTx.vout[stakeTx.vout.size() - 1].scriptPubKey.GetOpretData(vData);

    if (isValid && vData.size() == 1)
    {
        CScript data = CScript(vData[0].begin(), vData[0].end());
        vData.clear();

        uint32_t bytesTotal;
        CScript::const_iterator pc = data.begin();
        std::vector<unsigned char> vch = std::vector<unsigned char>();
        opcodetype op;
        bool moreData = true;

        for (bytesTotal = vch.size();
             bytesTotal <= nMaxDatacarrierBytes && !(isValid = (pc == data.end())) && (moreData = data.GetOp(pc, op, vch)) && IsData(op);
             bytesTotal += vch.size())
        {
            if (op >= OP_1 && op <= OP_16)
            {
                vch.resize(1);
                vch[0] = (op - OP_1) + 1;
            }
            vData.push_back(vch);
        }

        // if we ran out of data, we're ok
        if (isValid && (vData.size() >= CStakeParams::STAKE_MINPARAMS) && (vData.size() <= CStakeParams::STAKE_MAXPARAMS))
        {
            return true;
        }
    }
    return false;
}

CStakeParams::CStakeParams(const std::vector<std::vector<unsigned char>> &vData)
{
    // An original format stake OP_RETURN contains:
    // 1. source block height in little endian 32 bit
    // 2. target block height in little endian 32 bit
    // 3. 32 byte prev block hash
    // 4. 33 byte pubkey, or not present to use same as stake destination
    // New format serialization and deserialization is handled by normal stream serialization.
    version = VERSION_INVALID;
    srcHeight = 0;
    blkHeight = 0;
    if (vData[0].size() == 1 &&
        vData[0][0] == OPRETTYPE_STAKEPARAMS2 &&
        vData.size() == 2)
    {
        ::FromVector(vData[1], *this);
    }
    else if (vData[0].size() == 1 &&
        vData[0][0] == OPRETTYPE_STAKEPARAMS && vData[1].size() <= 4 &&
        vData[2].size() <= 4 &&
        vData[3].size() == sizeof(prevHash) &&
        (vData.size() == STAKE_MINPARAMS || (vData.size() == STAKE_MAXPARAMS && vData[4].size() == 33)))
    {
        version = VERSION_ORIGINAL;
        for (int i = 0, size = vData[1].size(); i < size; i++)
        {
            srcHeight = srcHeight | vData[1][i] << (8 * i);
        }
        for (int i = 0, size = vData[2].size(); i < size; i++)
        {
            blkHeight = blkHeight | vData[2][i] << (8 * i);
        }

        prevHash = uint256(vData[3]);

        if (vData.size() == 4)
        {
            pk = CPubKey();
        }
        else if (vData[4].size() == 33)
        {
            pk = CPubKey(vData[4]);
            if (!pk.IsValid())
            {
                // invalidate
                srcHeight = 0;
                version = VERSION_INVALID;
            }
        }
        else
        {
            // invalidate
            srcHeight = 0;
            version = VERSION_INVALID;
        }
    }
}

bool GetStakeParams(const CTransaction &stakeTx, CStakeParams &stakeParams)
{
    std::vector<std::vector<unsigned char>> vData = std::vector<std::vector<unsigned char>>();

    //printf("opret stake script: %s\nvalue at scriptPubKey[0]: %x\n", stakeTx.vout[1].scriptPubKey.ToString().c_str(), stakeTx.vout[1].scriptPubKey[0]);

    if (stakeTx.vin.size() == 1 &&
        stakeTx.vout.size() == 2 &&
        stakeTx.vout[0].nValue > 0 &&
        stakeTx.vout[1].scriptPubKey.IsOpReturn() &&
        UnpackStakeOpRet(stakeTx, vData))
    {
        stakeParams = CStakeParams(vData);
        return stakeParams.IsValid();
    }
    return false;
}

// this validates the format of the stake transaction and, optionally, whether or not it is
// properly signed to spend the source stake.
// it does not validate the relationship to a coinbase guard, PoS eligibility or the actual stake spend.
// the only time it matters is to validate a properly formed stake transaction for either pre-check before PoS validity check,
// or to validate the stake transaction on a fork that will be used to spend a winning stake that cheated by being posted
// on two fork chains
bool ValidateStakeTransaction(const CCurrencyDefinition &sourceChain, const CTransaction &stakeTx, CStakeParams &stakeParams, bool slowValidation)
{
    std::vector<std::vector<unsigned char>> vData = std::vector<std::vector<unsigned char>>();

    // a valid stake transaction has one input and two outputs, one output is the monetary value and one is an op_ret with CStakeParams
    // stake output #1 must be P2PK or P2PKH, unless a delegate for the coinbase is specified
    if (GetStakeParams(stakeTx, stakeParams))
    {
        // if we have gotten this far and are still valid, we need to validate everything else
        // even if the utxo is spent, this can succeed, as it only checks that is was ever valid
        CTransaction srcTx = CTransaction();
        uint256 blkHash = uint256();
        txnouttype txType;
        CBlockIndex *pindex;
        if (!slowValidation)
        {
            return true;
        }
        else if (myGetTransaction(stakeTx.vin[0].prevout.hash, srcTx, blkHash))
        {
            // see if we should only allow staking with funds held under IDs native to this chain
            // if so, only outputs specifically to a valid ID and no other destination can stake
            if (sourceChain.IDStaking() && sourceChain.GetID() == ASSETCHAINS_CHAINID)
            {
                txnouttype txType;
                std::vector<CTxDestination> addressesRet;
                int nRequiredRet;
                bool canSpend;
                extern CWallet *pwalletMain;
                if (ExtractDestinations(srcTx.vout[stakeTx.vin[0].prevout.n].scriptPubKey,
                                        txType,
                                        addressesRet,
                                        nRequiredRet,
                                        pwalletMain,
                                        nullptr,
                                        &canSpend) &&
                    canSpend)
                {
                    bool invalidOutput = false;
                    for (auto &oneAddr : addressesRet)
                    {
                        if (oneAddr.which() == COptCCParams::ADDRTYPE_ID)
                        {
                            CIdentity stakingIdentity = CIdentity::LookupIdentity(GetDestinationID(oneAddr));
                            if (stakingIdentity.parent != ASSETCHAINS_CHAINID)
                            {
                                invalidOutput = true;
                            }
                        }
                        else if (oneAddr.which() == COptCCParams::ADDRTYPE_PK ||
                                 oneAddr.which() == COptCCParams::ADDRTYPE_PKH)
                        {
                            // check for known, standard eval output
                            COptCCParams p;
                            if (!srcTx.vout[stakeTx.vin[0].prevout.n].scriptPubKey.IsPayToCryptoCondition(p))
                            {
                                LogPrint("staking", "%s: internal error - this should never happen\n");
                                return false;
                            }
                            CCcontract_info CC;
                            CCcontract_info *cp;
                            cp = CCinit(&CC, p.evalCode);
                            if (GetDestinationID(oneAddr) != GetDestinationID(DecodeDestination(CC.unspendableCCaddr)))
                            {
                                invalidOutput = true;
                            }
                        }
                        if (invalidOutput)
                        {
                            LogPrint("staking", "%s: Invalid stake for OPTION_IDSTAKING -- only outputs spendable to native ID of chain may stake\n");
                            return false;
                        }
                    }
                }
            }

            BlockMap::const_iterator it = mapBlockIndex.find(blkHash);
            if (it != mapBlockIndex.end() && (pindex = it->second) != NULL && chainActive.Contains(pindex))
            {
                std::vector<std::vector<unsigned char>> vAddr = std::vector<std::vector<unsigned char>>();
                bool extendedStake = CConstVerusSolutionVector::GetVersionByHeight(stakeParams.blkHeight) >= CActivationHeight::ACTIVATE_EXTENDEDSTAKE;
                COptCCParams p;

                if (stakeParams.srcHeight == pindex->GetHeight() &&
                    ((stakeParams.blkHeight - stakeParams.srcHeight) >= VERUS_MIN_STAKEAGE) &&
                    ((srcTx.vout[stakeTx.vin[0].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                      extendedStake &&
                      p.IsValid() &&
                      srcTx.vout[stakeTx.vin[0].prevout.n].scriptPubKey.IsSpendableOutputType(p)) ||
                    (!p.IsValid() && Solver(srcTx.vout[stakeTx.vin[0].prevout.n].scriptPubKey, txType, vAddr))))
                {
                    if (!p.IsValid() && txType == TX_PUBKEY && !stakeParams.pk.IsValid())
                    {
                        stakeParams.pk = CPubKey(vAddr[0]);
                    }
                    // once extended stake hits, we only accept extended form of staking
                    if (!(extendedStake && stakeParams.Version() < stakeParams.VERSION_EXTENDED_STAKE) &&
                        !(!extendedStake && stakeParams.Version() >= stakeParams.VERSION_EXTENDED_STAKE) &&
                        ((extendedStake && p.IsValid()) || (txType == TX_PUBKEY) || (txType == TX_PUBKEYHASH && (extendedStake || stakeParams.pk.IsFullyValid()))))
                    {
                        auto consensusBranchId = CurrentEpochBranchId(stakeParams.blkHeight, Params().GetConsensus());

                        std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> idAddressMap;
                        idAddressMap = ServerTransactionSignatureChecker::ExtractIDMap(srcTx.vout[stakeTx.vin[0].prevout.n].scriptPubKey, stakeParams.blkHeight, true);

                        if (VerifyScript(stakeTx.vin[0].scriptSig,
                                         srcTx.vout[stakeTx.vin[0].prevout.n].scriptPubKey,
                                         MANDATORY_SCRIPT_VERIFY_FLAGS,
                                         TransactionSignatureChecker(&stakeTx, (uint32_t)0, srcTx.vout[stakeTx.vin[0].prevout.n].nValue, &idAddressMap),
                                         consensusBranchId))
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool ValidateStakeTransaction(const CTransaction &stakeTx, CStakeParams &stakeParams, bool slowValidation)
{
    return ValidateStakeTransaction(ConnectedChains.ThisChain(), stakeTx, stakeParams, slowValidation);
}

bool MakeGuardedOutput(CAmount value, CTxDestination &dest, CTransaction &stakeTx, CTxOut &vout)
{
    CStakeParams p;
    if (GetStakeParams(stakeTx, p) && p.IsValid())
    {
        CVerusHashWriter hw = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

        hw << stakeTx.vin[0].prevout.hash;
        hw << stakeTx.vin[0].prevout.n;

        uint256 utxo = hw.GetHash();

        if (p.Version() >= p.VERSION_EXTENDED_STAKE)
        {
            CCcontract_info *cp, C;
            cp = CCinit(&C,EVAL_STAKEGUARD);

            CStakeInfo stakeInfo(p.blkHeight, p.srcHeight, utxo, p.prevHash);

            std::vector<CTxDestination> dests1({dest});
            CConditionObj<CStakeInfo> primary(EVAL_STAKEGUARD, dests1, 1, &stakeInfo);
            std::vector<CTxDestination> dests2({CTxDestination(CPubKey(ParseHex(cp->CChexstr)))});
            CConditionObj<CStakeInfo> cheatCatcher(EVAL_STAKEGUARD, dests2, 1);
            vout = CTxOut(value, MakeMofNCCScript(1, primary, cheatCatcher));
        }
        else if (dest.which() == COptCCParams::ADDRTYPE_PK)
        {
            CCcontract_info *cp, C;
            cp = CCinit(&C,EVAL_STAKEGUARD);

            CPubKey ccAddress = CPubKey(ParseHex(cp->CChexstr));

            // return an output that is bound to the stake transaction and can be spent by presenting either a signed condition by the original
            // destination address or a properly signed stake transaction of the same utxo on a fork
            vout = MakeCC1of2vout(EVAL_STAKEGUARD, value, boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), dest), ccAddress);

            std::vector<CTxDestination> vKeys;
            vKeys.push_back(dest);
            vKeys.push_back(ccAddress);

            std::vector<std::vector<unsigned char>> vData = std::vector<std::vector<unsigned char>>();

            vData.push_back(std::vector<unsigned char>(utxo.begin(), utxo.end()));

            // prev block hash and height is here to make validation easy
            vData.push_back(std::vector<unsigned char>(p.prevHash.begin(), p.prevHash.end()));
            std::vector<unsigned char> height = std::vector<unsigned char>(4);
            for (int i = 0; i < 4; i++)
            {
                height[i] = (p.blkHeight >> (8 * i)) & 0xff;
            }
            vData.push_back(height);

            COptCCParams ccp = COptCCParams(COptCCParams::VERSION_V1, EVAL_STAKEGUARD, 1, 2, vKeys, vData);

            vout.scriptPubKey << ccp.AsVector() << OP_DROP;
        }

        return true;
    }
    return false;
}

// validates if a stake transaction is both valid and cheating, defined by:
// the same exact utxo source, a target block height of later than that of the provided coinbase tx that is also targeting a fork
// of the chain. the source transaction must be a coinbase
bool ValidateMatchingStake(const CTransaction &ccTx, uint32_t voutNum, const CTransaction &stakeTx, bool &cheating, bool slowValidation)
{
    // an invalid or non-matching stake transaction cannot cheat
    cheating = false;

    //printf("ValidateMatchingStake: ccTx.vin[0].prevout.hash: %s, ccTx.vin[0].prevout.n: %d\n", ccTx.vin[0].prevout.hash.GetHex().c_str(), ccTx.vin[0].prevout.n);

    if (ccTx.IsCoinBase())
    {
        CStakeParams p;
        if (ValidateStakeTransaction(stakeTx, p, slowValidation))
        {
            std::vector<std::vector<unsigned char>> vParams = std::vector<std::vector<unsigned char>>();
            CScript dummy;

            if (ccTx.vout[voutNum].scriptPubKey.IsPayToCryptoCondition(&dummy, vParams) && vParams.size() > 0)
            {
                COptCCParams ccp = COptCCParams(vParams[0]);
                CVerusHashWriter hw = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

                if (p.version >= p.VERSION_EXTENDED_STAKE && ccp.version >= ccp.VERSION_V3 && ccp.vData.size())
                {
                    CStakeInfo stakeInfo(ccp.vData[0]);
                    hw << stakeTx.vin[0].prevout.hash;
                    hw << stakeTx.vin[0].prevout.n;
                    uint256 utxo = hw.GetHash();

                    if (utxo == stakeInfo.utxo)
                    {
                        if (p.prevHash != stakeInfo.prevHash && p.blkHeight >= stakeInfo.height)
                        {
                            cheating = true;
                            return true;
                        }
                        // if block height is equal and we are at the else, prevHash must have been equal
                        else if (p.blkHeight >= stakeInfo.height)
                        {
                            return true;
                        }
                    }
                }
                else if (p.version < p.VERSION_EXTENDED_STAKE &&
                         ccp.version < ccp.VERSION_V3 &&
                         ccp.IsValid() &&
                         ccp.vData.size() >= 3 &&
                         ccp.vData[2].size() <= 4)
                {
                    hw << stakeTx.vin[0].prevout.hash;
                    hw << stakeTx.vin[0].prevout.n;
                    uint256 utxo = hw.GetHash();

                    uint32_t height = 0;
                    int i, dataLen = ccp.vData[2].size();
                    for (i = dataLen - 1; i >= 0; i--)
                    {
                        height = (height << 8) + ccp.vData[2][i];
                    }
                    // for debugging strange issue
                    // printf("iterator: %d, height: %d, datalen: %d\n", i, height, dataLen);

                    if (utxo == uint256(ccp.vData[0]))
                    {
                        if (p.prevHash != uint256(ccp.vData[1]) && p.blkHeight >= height)
                        {
                            cheating = true;
                            return true;
                        }
                        // if block height is equal and we are at the else, prevHash must have been equal
                        else if (p.blkHeight == height)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

// this attaches an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
bool MakeCheatEvidence(CMutableTransaction &mtx, const CTransaction &ccTx, uint32_t voutNum, const CTransaction &cheatTx)
{
    std::vector<unsigned char> vch;
    CDataStream s = CDataStream(SER_DISK, PROTOCOL_VERSION);
    bool isCheater = false;

    if (ValidateMatchingStake(ccTx, voutNum, cheatTx, isCheater, true) && isCheater)
    {
        CTxOut vOut = CTxOut();
        int64_t opretype_stakecheat = OPRETTYPE_STAKECHEAT;

        CScript vData = CScript();
        cheatTx.Serialize(s);
        vch = std::vector<unsigned char>(s.begin(), s.end());
        vData << opretype_stakecheat << vch;
        vch = std::vector<unsigned char>(vData.begin(), vData.end());
        vOut.scriptPubKey << OP_RETURN << vch;

        // printf("Script encoding inner:\n%s\nouter:\n%s\n", vData.ToString().c_str(), vOut.scriptPubKey.ToString().c_str());

        vOut.nValue = 0;
        mtx.vout.push_back(vOut);
    }
    return isCheater;
}

// a version 3 guard output should be a 1 of 2 meta condition, with both of the
// conditions being stakeguard only and one of the conditions being sent to the public
// stakeguard destination. Only for smart transaction V3 and beyond.
bool RawPrecheckStakeGuardOutput(const CTransaction &tx, int32_t outNum, CValidationState &state)
{
    // ensure that we have all required spend conditions
    COptCCParams p, master, secondary;

    CCcontract_info *cp, C;
    cp = CCinit(&C,EVAL_STAKEGUARD);
    CPubKey defaultPubKey(ParseHex(cp->CChexstr));

    if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.version >= p.VERSION_V3 &&
        p.evalCode == EVAL_STAKEGUARD &&
        p.vData.size() == 3 &&
        (master = COptCCParams(p.vData.back())).IsValid() &&
        master.evalCode == 0 &&
        master.m == 1 &&
        (secondary = COptCCParams(p.vData[1])).IsValid() &&
        secondary.evalCode == EVAL_STAKEGUARD &&
        secondary.m == 1 &&
        secondary.n == 1 &&
        secondary.vKeys.size() == 1 &&
        secondary.vKeys[0].which() == COptCCParams::ADDRTYPE_PK &&
        GetDestinationBytes(secondary.vKeys[0]) == GetDestinationBytes(defaultPubKey))
    {
        return true;
    }
    return false;
}

bool PrecheckStakeGuardOutput(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_EXTENDEDSTAKE)
    {
        return true;
    }
    return RawPrecheckStakeGuardOutput(tx, outNum, state);
}

typedef struct ccFulfillmentCheck {
    std::vector<CPubKey> &vPK;
    std::vector<uint32_t> &vCount;
} ccFulfillmentCheck;

// to figure out which node is signed
int CCFulfillmentVisitor(CC *cc, struct CCVisitor visitor)
{
    //printf("cc_typeName: %s, cc_isFulfilled: %x, cc_isAnon: %x, cc_typeMask: %x, cc_condToJSONString:\n%s\n",
    //       cc_typeName(cc), cc_isFulfilled(cc), cc_isAnon(cc), cc_typeMask(cc), cc_conditionToJSONString(cc));

    if (strcmp(cc_typeName(cc), "secp256k1-sha-256") == 0)
    {
        cJSON *json = cc_conditionToJSON(cc);
        if (json)
        {
            cJSON *pubKeyNode = json->child->next;
            if (strcmp(pubKeyNode->string, "publicKey") == 0)
            {
                ccFulfillmentCheck *pfc = (ccFulfillmentCheck *)(visitor.context);

                //printf("public key: %s\n", pubKeyNode->valuestring);
                CPubKey pubKey = CPubKey(ParseHex(pubKeyNode->valuestring));

                for (int i = 0; i < pfc->vPK.size(); i++)
                {
                    if (i < pfc->vCount.size() && (pfc->vPK[i] == pubKey))
                    {
                        pfc->vCount[i]++;
                    }
                }
            }
            cJSON_free(json);
        }
    }
    return 1;
}

int IsCCFulfilled(CC *cc, ccFulfillmentCheck *ctx)
{
    struct CCVisitor visitor = {&CCFulfillmentVisitor, NULL, 0, (void *)ctx};
    cc_visit(cc, visitor);

    //printf("count key 1: %d, count key 2: %d\n", ctx->vCount[0], ctx->vCount[1]);
    return ctx->vCount[0];
}

bool StakeGuardValidate(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // WARNING: this has not been tested combined with time locks
    // validate this spend of a transaction with it being past any applicable time lock and one of the following statements being true:
    //  1. the spend is signed by the original output destination's private key and normal payment requirements, spends as normal
    //  2. the spend is signed by the private key of the StakeGuard contract and pushes a signed stake transaction
    //     with the same exact utxo source, a target block height of later than or equal to this tx, and a different prevBlock hash

    // first, check to see if the spending contract is signed by the default destination address
    // if so, success and we are done

    // get preConditions and parameters
    std::vector<std::vector<unsigned char>> preConditions = std::vector<std::vector<unsigned char>>();
    std::vector<std::vector<unsigned char>> params = std::vector<std::vector<unsigned char>>();
    CTransaction txOut;

    bool signedByFirstKey = false;
    bool validCheat = false;

    CC *cc = GetCryptoCondition(tx.vin[nIn].scriptSig);

    // tx is the spending tx, the cc transaction comes back in txOut
    bool validCCParams = GetCCParams(eval, tx, nIn, txOut, preConditions, params);
    COptCCParams ccp;
    if (preConditions.size() > 0)
    {
        ccp = COptCCParams(preConditions[0]);
    }

    if (validCCParams && ccp.IsValid() && ((cc && ccp.version < COptCCParams::VERSION_V3) || (!cc && ccp.version >= COptCCParams::VERSION_V3)))
    {
        signedByFirstKey = false;
        validCheat = false;

        if (ccp.version >= COptCCParams::VERSION_V3)
        {
            CPubKey defaultPubKey(ParseHex(cp->CChexstr));

            CSmartTransactionSignatures smartSigs;
            bool signedByDefaultKey = false;
            std::vector<unsigned char> ffVec = GetFulfillmentVector(tx.vin[nIn].scriptSig);
            smartSigs = CSmartTransactionSignatures(std::vector<unsigned char>(ffVec.begin(), ffVec.end()));
            CKeyID checkKeyID = defaultPubKey.GetID();
            for (auto &keySig : smartSigs.signatures)
            {
                CPubKey thisKey;
                thisKey.Set(keySig.second.pubKeyData.begin(), keySig.second.pubKeyData.end());
                if (thisKey.GetID() == checkKeyID)
                {
                    signedByDefaultKey = true;
                    break;
                }
            }

            // if we don't have enough signatures to satisfy conditions,
            // it will fail before we check this. that means if it is not signed
            // by the default key, it must be signed / fulfilled by the alternate, which is
            // the first condition/key/identity
            signedByFirstKey = fulfilled || !signedByDefaultKey;

            if (!signedByFirstKey &&
                params.size() == 2 &&
                params[0].size() > 0 &&
                params[0][0] == OPRETTYPE_STAKECHEAT)
            {
                CDataStream s = CDataStream(std::vector<unsigned char>(params[1].begin(), params[1].end()), SER_DISK, PROTOCOL_VERSION);
                bool checkOK = false;
                CTransaction cheatTx;
                try
                {
                    cheatTx.Unserialize(s);
                    checkOK = true;
                }
                catch (...)
                {
                }
                if (checkOK && !ValidateMatchingStake(txOut, tx.vin[0].prevout.n, cheatTx, validCheat, true))
                {
                    validCheat = false;
                }
            }
        }
        else if (ccp.m == 1 && ccp.n == 2 && ccp.vKeys.size() == 2)
        {
            std::vector<uint32_t> vc = {0, 0};
            std::vector<CPubKey> keys;

            for (auto pk : ccp.vKeys)
            {
                uint160 keyID = GetDestinationID(pk);
                std::vector<unsigned char> vkch = GetDestinationBytes(pk);
                if (vkch.size() == 33)
                {
                    keys.push_back(CPubKey(vkch));
                }
            }

            if (keys.size() == 2)
            {
                ccFulfillmentCheck fc = {keys, vc};
                signedByFirstKey = (IsCCFulfilled(cc, &fc) != 0);

                if (!signedByFirstKey &&
                    ccp.evalCode == EVAL_STAKEGUARD &&
                    ccp.vKeys.size() == 2 &&
                    params.size() == 2 &&
                    params[0].size() > 0 &&
                    params[0][0] == OPRETTYPE_STAKECHEAT)
                {
                    CDataStream s = CDataStream(std::vector<unsigned char>(params[1].begin(), params[1].end()), SER_DISK, PROTOCOL_VERSION);
                    bool checkOK = false;
                    CTransaction cheatTx;
                    try
                    {
                        cheatTx.Unserialize(s);
                        checkOK = true;
                    }
                    catch (...)
                    {
                    }
                    if (checkOK && !ValidateMatchingStake(txOut, tx.vin[0].prevout.n, cheatTx, validCheat, true))
                    {
                        validCheat = false;
                    }
                }
            }
        }
    }
    if (cc)
    {
        cc_free(cc);
    }
    if (!(signedByFirstKey || validCheat))
    {
        return eval->Error("error reading coinbase or spending proof invalid\n");
    }
    else return true;
}

bool IsStakeGuardInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_STAKEGUARD;
}

UniValue StakeGuardInfo()
{
    UniValue result(UniValue::VOBJ); char numstr[64];
    CMutableTransaction mtx;
    CPubKey pk;

    CCcontract_info *cp,C;

    cp = CCinit(&C,EVAL_STAKEGUARD);

    result.push_back(Pair("result","success"));
    result.push_back(Pair("name","StakeGuard"));

    // all UTXOs to the contract address that are to any of the wallet addresses are to us
    // each is spendable as a normal transaction, but the spend may fail if it gets spent out
    // from under us
    pk = GetUnspendable(cp,0);
    return(result);
}

