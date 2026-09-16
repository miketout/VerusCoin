#include "cryptoconditions/include/cryptoconditions.h"
#include "script/cc.h"


bool IsCryptoConditionsEnabled()
{
    return 0 != ASSETCHAINS_CC;
}

bool IsSupportedCryptoCondition(const CC *cond, int evalCode)
{
    int mask = cc_typeMask(cond);

    if (mask & ~CCEnabledTypes) return false;

    // Also require that the condition have at least one signable node or be a PBaaS compatible condition
    // and at least have an eval node instead
    if (!(mask & CCSigningNodes) && !(evalCode >= CCFirstEvalOnly && evalCode <= CCLastEvalOnly && mask & CCEvalNode)) return false;

    return true;
}

bool IsSignedCryptoCondition(const CC *cond)
{
    if (!cc_isFulfilled(cond)) return false;
    if (1 << cc_typeId(cond) & CCSigningNodes) return true;
    if (cc_typeId(cond) == CC_Threshold)
        for (int i=0; i<cond->size; i++)
            if (IsSignedCryptoCondition(cond->subconditions[i])) return true;
    return false;
}


static unsigned char* CopyPubKey(CPubKey pkIn)
{
    unsigned char* pk = (unsigned char*) malloc(33);
    if (!pk)
    {
        return NULL;
    }
    memcpy(pk, pkIn.begin(), 33);  // TODO: compressed?
    return pk;
}

static unsigned char* CopyKeyIDChars(uint8_t *chars)
{
    unsigned char* pk = (unsigned char*) malloc(33);
    if (!pk)
    {
        return NULL;
    }
    memcpy(pk, chars, 20);  // only the keyID
    memset(pk + 20, 0, 13);
    return pk;
}

CC* CCNewThreshold(int t, std::vector<CC*> v)
{
    CC *cond = cc_new(CC_Threshold);
    if (!cond)
    {
        return NULL;
    }
    cond->threshold = t;
    cond->size = v.size();
    cond->subconditions = (CC**) calloc(v.size(), sizeof(CC*));
    memcpy(cond->subconditions, v.data(), v.size() * sizeof(CC*));
    return cond;
}

CC* CCNewSecp256k1(CPubKey k)
{
    CC *cond = cc_new(CC_Secp256k1);
    if (!cond)
    {
        return NULL;
    }
    cond->publicKey = CopyPubKey(k);
    return cond;
}

CC* CCNewHashedSecp256k1(CKeyID keyID)
{
    CC *cond = cc_new(CC_Secp256k1);
    if (!cond)
    {
        return NULL;
    }
    cond->publicKey = CopyKeyIDChars(keyID.begin());
    return cond;
}

CC* CCNewEval(std::vector<unsigned char> code)
{
    CC *cond = cc_new(CC_Eval);
    if (!cond)
    {
        return NULL;
    }
    cond->code = (unsigned char*) malloc(code.size());
    memcpy(cond->code, code.data(), code.size());
    cond->codeLength = code.size();
    return cond;
}

std::vector<unsigned char> CCPubKeyVec(const CC *cond)
{
    unsigned char buf[MAX_BINARY_CC_SIZE];
    size_t len = cc_conditionBinary(cond, buf, MAX_BINARY_CC_SIZE);
    return std::vector<unsigned char>(buf, buf+len);
}

CScript CCPubKey(const CC *cond)
{
    return CScript() << CCPubKeyVec(cond) << OP_CHECKCRYPTOCONDITION;
}

CScript CCSig(const CC *cond)
{
    unsigned char buf[MAX_BINARY_CC_SIZE];
    size_t len = cc_fulfillmentBinary(cond, buf, MAX_BINARY_CC_SIZE);
    auto ffill = std::vector<unsigned char>(buf, buf+len);
    ffill.push_back(1);  // SIGHASH_ALL
    return CScript() << ffill;
}

std::vector<unsigned char> CCSigVec(const CC *cond)
{
    unsigned char buf[MAX_BINARY_CC_SIZE];
    size_t len = cc_fulfillmentBinary(cond, buf, MAX_BINARY_CC_SIZE);
    auto ffill = std::vector<unsigned char>(buf, buf+len);
    ffill.push_back(1);  // SIGHASH_ALL
    return ffill;
}

std::vector<unsigned char> CCPartialSigVec(const CC *cond)
{
    unsigned char buf[MAX_BINARY_CC_SIZE];
    size_t len = cc_partialFulfillmentBinary(cond, buf, MAX_BINARY_CC_SIZE);
    auto ffill = std::vector<unsigned char>(buf, buf+len);
    ffill.push_back(1);  // SIGHASH_ALL
    return ffill;
}

std::string CCShowStructure(CC *cond)
{
    std::string out;
    if (cc_isAnon(cond)) {
        out = "A" + std::to_string(cc_typeId(cond));
    }
    else if (cc_typeId(cond) == CC_Threshold) {
        out += "(" + std::to_string(cond->threshold) + " of ";
        for (int i=0; i<cond->size; i++) {
            out += CCShowStructure(cond->subconditions[i]);
            if (i < cond->size - 1) out += ",";
        }
        out += ")";
    }
    else {
        out = std::to_string(cc_typeId(cond));
    }
    return out;
}


CC* CCPrune(CC *cond)
{
    std::vector<unsigned char> ffillBin;
    GetPushData(CCSig(cond), ffillBin);
    return cc_readFulfillmentBinary(ffillBin.data(), ffillBin.size()-1);
}


bool GetPushData(const CScript &sig, std::vector<unsigned char> &data)
{
    opcodetype opcode;
    auto pc = sig.begin();
    if (sig.GetOp(pc, opcode, data)) return opcode > OP_0 && opcode <= OP_PUSHDATA4;
    return false;
}


bool GetOpReturnData(const CScript &sig, std::vector<unsigned char> &data)
{
    auto pc = sig.begin();
    opcodetype opcode;
    if (sig.GetOp2(pc, opcode, NULL))
        if (opcode == OP_RETURN)
            if (sig.GetOp(pc, opcode, data))
                return opcode > OP_0 && opcode <= OP_PUSHDATA4;
    return false;
}
