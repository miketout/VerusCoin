// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "primitives/transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "pbaas/reserves.h"
#include "mmr.h"

#include "librustzcash.h"
#include "cc/CCinclude.h"

JSDescription::JSDescription(
    ZCJoinSplit& params,
    const uint256& joinSplitPubKey,
    const uint256& anchor,
    const std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
    const std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
    CAmount vpub_old,
    CAmount vpub_new,
    bool computeProof,
    uint256 *esk // payment disclosure
) : vpub_old(vpub_old), vpub_new(vpub_new), anchor(anchor)
{
    std::array<libzcash::SproutNote, ZC_NUM_JS_OUTPUTS> notes;

    proof = params.prove(
        inputs,
        outputs,
        notes,
        ciphertexts,
        ephemeralKey,
        joinSplitPubKey,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        anchor,
        computeProof,
        esk // payment disclosure
    );
}

JSDescription JSDescription::Randomized(
    ZCJoinSplit& params,
    const uint256& joinSplitPubKey,
    const uint256& anchor,
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
    std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
    std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,
    CAmount vpub_old,
    CAmount vpub_new,
    bool computeProof,
    uint256 *esk, // payment disclosure
    std::function<int(int)> gen
)
{
    // Randomize the order of the inputs and outputs
    inputMap = {0, 1};
    outputMap = {0, 1};

    assert(gen);

    MappedShuffle(inputs.begin(), inputMap.begin(), ZC_NUM_JS_INPUTS, gen);
    MappedShuffle(outputs.begin(), outputMap.begin(), ZC_NUM_JS_OUTPUTS, gen);

    return JSDescription(
        params, joinSplitPubKey, anchor, inputs, outputs,
        vpub_old, vpub_new, computeProof,
        esk // payment disclosure
    );
}

class SproutProofVerifier : public boost::static_visitor<bool>
{
    ZCJoinSplit& params;
    libzcash::ProofVerifier& verifier;
    const uint256& joinSplitPubKey;
    const JSDescription& jsdesc;

public:
    SproutProofVerifier(
        ZCJoinSplit& params,
        libzcash::ProofVerifier& verifier,
        const uint256& joinSplitPubKey,
        const JSDescription& jsdesc
        ) : params(params), jsdesc(jsdesc), verifier(verifier), joinSplitPubKey(joinSplitPubKey) {}

    bool operator()(const libzcash::PHGRProof& proof) const
    {
        // We checkpoint after Sapling activation, so we can skip verification
        // for all Sprout proofs.
        return true;
    }

    bool operator()(const libzcash::GrothProof& proof) const
    {
        uint256 h_sig = params.h_sig(jsdesc.randomSeed, jsdesc.nullifiers, joinSplitPubKey);

        return librustzcash_sprout_verify(
            proof.begin(),
            jsdesc.anchor.begin(),
            h_sig.begin(),
            jsdesc.macs[0].begin(),
            jsdesc.macs[1].begin(),
            jsdesc.nullifiers[0].begin(),
            jsdesc.nullifiers[1].begin(),
            jsdesc.commitments[0].begin(),
            jsdesc.commitments[1].begin(),
            jsdesc.vpub_old,
            jsdesc.vpub_new
        );
    }
};

bool JSDescription::Verify(
    ZCJoinSplit& params,
    libzcash::ProofVerifier& verifier,
    const uint256& joinSplitPubKey
) const {
    auto pv = SproutProofVerifier(params, verifier, joinSplitPubKey, *this);
    return boost::apply_visitor(pv, proof);
}

uint256 JSDescription::h_sig(ZCJoinSplit& params, const uint256& joinSplitPubKey) const
{
    return params.h_sig(randomSeed, nullifiers, joinSplitPubKey);
}

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString(), n);
}

std::string SaplingOutPoint::ToString() const
{
    return strprintf("SaplingOutPoint(%s, %u)", hash.ToString().substr(0, 10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != std::numeric_limits<unsigned int>::max())
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, const CScript &scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

uint256 CTxOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxOut::ToString() const
{
    UniValue scriptUni(UniValue::VOBJ);
    ScriptPubKeyToUniv(scriptPubKey, scriptUni, true);
    return strprintf("CTxOut(nValue=%s, scriptPubKey=%s)", ValueFromAmount(nValue).write().c_str(), scriptUni.write().c_str());
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::SPROUT_MIN_CURRENT_VERSION), fOverwintered(false), nVersionGroupId(0), nExpiryHeight(0), nLockTime(0), valueBalance(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nExpiryHeight(tx.nExpiryHeight),
                                                                   vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime),
                                                                   valueBalance(tx.valueBalance), vShieldedSpend(tx.vShieldedSpend), vShieldedOutput(tx.vShieldedOutput),
                                                                   vJoinSplit(tx.vJoinSplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig),
                                                                   bindingSig(tx.bindingSig)
{

}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this);
}

CTransactionMap::CTransactionMap(const CTransaction &tx)
{
    // hash header information and put in MMR and map, followed by all elements in order
    int32_t idx = 0;
    CTransactionHeader txHeader(tx);

    {
        auto hw = CDefaultMMRNode::GetHashWriter();
        hw << txHeader;
        transactionMMR.Add(CDefaultMMRNode(hw.GetHash()));
        elementHashMap[std::make_pair((int16_t)CTransactionHeader::TX_HEADER, (int16_t)0)] = idx++;
    }

    int testSize = elementHashMap.size();
    if (!testSize)
    {
        printf("testing mode on %d\n", testSize);

        auto hw = CDefaultMMRNode::GetHashWriter();
        hw << txHeader;
        transactionMMR.Add(CDefaultMMRNode(hw.GetHash()));
        elementHashMap[std::make_pair((int16_t)CTransactionHeader::TX_HEADER, (int16_t)1)] = idx++;

        hw = CDefaultMMRNode::GetHashWriter();
        hw << txHeader;
        transactionMMR.Add(CDefaultMMRNode(hw.GetHash()));
        elementHashMap[std::make_pair((int16_t)CTransactionHeader::TX_HEADER, (int16_t)2)] = idx++;
    }

    for (unsigned int n = 0; n < txHeader.nVins; n++) {
        auto hw = CDefaultMMRNode::GetHashWriter();
        hw << tx.vin[n].prevout;
        hw << tx.vin[n].nSequence;
        transactionMMR.Add(CDefaultMMRNode(hw.GetHash()));
        elementHashMap[std::make_pair((int16_t)CTransactionHeader::TX_PREVOUTSEQ, (int16_t)n)] = idx++;
    }

    for (unsigned int n = 0; n < txHeader.nVins; n++) {
        auto hw = CDefaultMMRNode::GetHashWriter();
        hw << tx.vin[n];
        transactionMMR.Add(CDefaultMMRNode(hw.GetHash()));
        elementHashMap[std::make_pair((int16_t)CTransactionHeader::TX_SIGNATURE, (int16_t)n)] = idx++;
    }

    for (unsigned int n = 0; n < txHeader.nVouts; n++) {
        auto hw = CDefaultMMRNode::GetHashWriter();
        hw << tx.vout[n];
        transactionMMR.Add(CDefaultMMRNode(hw.GetHash()));
        elementHashMap[std::make_pair((int16_t)CTransactionHeader::TX_OUTPUT, (int16_t)n)] = idx++;
    }

    for (unsigned int n = 0; n < txHeader.nShieldedSpends; n++) {
        auto hw = CDefaultMMRNode::GetHashWriter();
        hw << tx.vShieldedSpend[n].cv;
        hw << tx.vShieldedSpend[n].anchor;
        hw << tx.vShieldedSpend[n].nullifier;
        hw << tx.vShieldedSpend[n].rk;
        hw << tx.vShieldedSpend[n].zkproof;
        transactionMMR.Add(CDefaultMMRNode(hw.GetHash()));
        elementHashMap[std::make_pair((int16_t)CTransactionHeader::TX_SHIELDEDSPEND, (int16_t)n)] = idx++;
    }

    for (unsigned int n = 0; n < txHeader.nShieldedOutputs; n++) {
        auto hw = CDefaultMMRNode::GetHashWriter();
        hw << tx.vShieldedOutput[n];
        transactionMMR.Add(CDefaultMMRNode(hw.GetHash()));
        elementHashMap[std::make_pair((int16_t)CTransactionHeader::TX_SHIELDEDOUTPUT, (int16_t)n)] = idx++;
    }
}

void CTransaction::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this);
}

CTransaction::CTransaction() : nVersion(CTransaction::SPROUT_MIN_CURRENT_VERSION), fOverwintered(false), nVersionGroupId(0), nExpiryHeight(0), vin(), vout(), nLockTime(0), valueBalance(0), vShieldedSpend(), vShieldedOutput(), vJoinSplit(), joinSplitPubKey(), joinSplitSig(), bindingSig() { }

CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nExpiryHeight(tx.nExpiryHeight),
                                                            vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime),
                                                            valueBalance(tx.valueBalance), vShieldedSpend(tx.vShieldedSpend), vShieldedOutput(tx.vShieldedOutput),
                                                            vJoinSplit(tx.vJoinSplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig),
                                                            bindingSig(tx.bindingSig)
{
    UpdateHash();
}

// Protected constructor which only derived classes can call.
// For developer testing only.
CTransaction::CTransaction(
    const CMutableTransaction &tx,
    bool evilDeveloperFlag) : nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId), nExpiryHeight(tx.nExpiryHeight),
                              vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime),
                              valueBalance(tx.valueBalance), vShieldedSpend(tx.vShieldedSpend), vShieldedOutput(tx.vShieldedOutput),
                              vJoinSplit(tx.vJoinSplit), joinSplitPubKey(tx.joinSplitPubKey), joinSplitSig(tx.joinSplitSig),
                              bindingSig(tx.bindingSig)
{
    assert(evilDeveloperFlag);
}

CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), fOverwintered(tx.fOverwintered), nVersionGroupId(tx.nVersionGroupId),
                                                       vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime), nExpiryHeight(tx.nExpiryHeight),
                                                       valueBalance(tx.valueBalance),
                                                       vShieldedSpend(std::move(tx.vShieldedSpend)), vShieldedOutput(std::move(tx.vShieldedOutput)),
                                                       vJoinSplit(std::move(tx.vJoinSplit)),
                                                       joinSplitPubKey(std::move(tx.joinSplitPubKey)), joinSplitSig(std::move(tx.joinSplitSig))
{
    UpdateHash();
}

CTransaction& CTransaction::operator=(const CTransaction &tx) {
    *const_cast<bool*>(&fOverwintered) = tx.fOverwintered;
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<uint32_t*>(&nVersionGroupId) = tx.nVersionGroupId;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<uint32_t*>(&nExpiryHeight) = tx.nExpiryHeight;
    *const_cast<CAmount*>(&valueBalance) = tx.valueBalance;
    *const_cast<std::vector<SpendDescription>*>(&vShieldedSpend) = tx.vShieldedSpend;
    *const_cast<std::vector<OutputDescription>*>(&vShieldedOutput) = tx.vShieldedOutput;
    *const_cast<std::vector<JSDescription>*>(&vJoinSplit) = tx.vJoinSplit;
    *const_cast<uint256*>(&joinSplitPubKey) = tx.joinSplitPubKey;
    *const_cast<joinsplit_sig_t*>(&joinSplitSig) = tx.joinSplitSig;
    *const_cast<binding_sig_t*>(&bindingSig) = tx.bindingSig;
    *const_cast<uint256*>(&hash) = tx.hash;
    return *this;
}


uint256 CTransaction::GetMMRRoot() const
{
    CTransactionMap txMap(*this);
    return TransactionMMView(txMap.transactionMMR, txMap.transactionMMR.size()).GetRoot();
}


CDefaultMMRNode CTransaction::GetDefaultMMRNode() const
{
    return CDefaultMMRNode(GetMMRRoot());
}


TransactionMMRange CTransaction::GetTransactionMMR() const
{
    CTransactionMap txMap(*this);
    return txMap.transactionMMR;
}


CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }

    if (valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -valueBalance;

        if (!MoneyRange(-valueBalance) || !MoneyRange(nValueOut)) {
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
        }
    }

    for (std::vector<JSDescription>::const_iterator it(vJoinSplit.begin()); it != vJoinSplit.end(); ++it)
    {
        // NB: vpub_old "takes" money from the transparent value pool just as outputs do
        nValueOut += it->vpub_old;

        if (!MoneyRange(it->vpub_old) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }
    return nValueOut;
}

CCurrencyValueMap CTransaction::GetReserveValueOut() const
{
    CCurrencyValueMap retVal;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        COptCCParams p;
        CCurrencyValueMap oneOut = it->scriptPubKey.ReserveOutValue(p);

        for (auto &oneCur : oneOut.valueMap)
        {
            if (!MoneyRange(oneCur.second) ||
                !MoneyRange(retVal.valueMap[oneCur.first] += oneCur.second))
            {
                LogPrint("defi", "%s: currency value overflow -- total: %ld, adding: %ld\n", __func__, retVal.valueMap[oneCur.first], oneCur.second);
                throw std::runtime_error("CTransaction::GetReserveValueOut(): value out of range");
            }
        }
    }
    return retVal;
}

CAmount CTransaction::GetShieldedValueOut() const
{
    CAmount nValueOut = 0;

    if (valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -valueBalance;

        if (!MoneyRange(-valueBalance) || !MoneyRange(nValueOut)) {
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
        }
    }

    for (std::vector<JSDescription>::const_iterator it(vJoinSplit.begin()); it != vJoinSplit.end(); ++it)
    {
        // NB: vpub_old "takes" money from the transparent value pool just as outputs do
        nValueOut += it->vpub_old;

        if (!MoneyRange(it->vpub_old) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }
    return nValueOut;
}

// SAPLINGTODO: make this accurate for all transactions, including sapling
CAmount CTransaction::GetShieldedValueIn() const
{
    CAmount nValue = 0;

    if (valueBalance >= 0) {
        // NB: positive valueBalance "gives" money to the transparent value pool just as inputs do
        nValue += valueBalance;

        if (!MoneyRange(valueBalance) || !MoneyRange(nValue)) {
            throw std::runtime_error("CTransaction::GetShieldedValueIn(): value out of range");
        }
    }

    for (std::vector<JSDescription>::const_iterator it(vJoinSplit.begin()); it != vJoinSplit.end(); ++it)
    {
        // NB: vpub_new "gives" money to the transparent value pool just as inputs do
        nValue += it->vpub_new;
        
        if (!MoneyRange(it->vpub_new) || !MoneyRange(nValue))
            throw std::runtime_error("CTransaction::GetShieldedValueIn(): value out of range");
    }
    
    return nValue;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

// will return the open time or block if this is a time locked transaction output that we recognize.
// if we can't determine that it has a valid time lock, it returns 0
int64_t CTransaction::UnlockTime(uint32_t voutNum) const
{
    if (vout.size() > voutNum + 1 && vout[voutNum].scriptPubKey.IsPayToScriptHash())
    {
        std::vector<uint8_t> opretData;
        uint160 scriptID = uint160(std::vector<unsigned char>(vout[voutNum].scriptPubKey.begin() + 2, vout[voutNum].scriptPubKey.begin() + 22));
        CScript::const_iterator it = vout.back().scriptPubKey.begin() + 1;

        opcodetype op;
        if (vout.back().scriptPubKey.GetOp2(it, op, &opretData))
        {
            if (opretData.size() > 0 && opretData.data()[0] == OPRETTYPE_TIMELOCK)
            {
                int64_t unlocktime;
                CScript opretScript = CScript(opretData.begin() + 1, opretData.end());
                if (Hash160(opretScript) == scriptID &&
                    opretScript.IsCheckLockTimeVerify(&unlocktime))
                {
                    return(unlocktime);
                }
            }
        }
    }
    return(0);
}

std::string CTransaction::ToString() const
{
    std::string str;
    if (!fOverwintered) {
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);
    } else if (nVersion >= SAPLING_MIN_TX_VERSION) {
        str += strprintf("CTransaction(hash=%s, ver=%d, fOverwintered=%d, nVersionGroupId=%08x, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u, valueBalance=%u, vShieldedSpend.size=%u, vShieldedOutput.size=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            fOverwintered,
            nVersionGroupId,
            vin.size(),
            vout.size(),
            nLockTime,
            nExpiryHeight,
            valueBalance,
            vShieldedSpend.size(),
            vShieldedOutput.size());
    } else if (nVersion >= 3) {
        str += strprintf("CTransaction(hash=%s, ver=%d, fOverwintered=%d, nVersionGroupId=%08x, vin.size=%u, vout.size=%u, nLockTime=%u, nExpiryHeight=%u)\n",
            GetHash().ToString().substr(0,10),
            nVersion,
            fOverwintered,
            nVersionGroupId,
            vin.size(),
            vout.size(),
            nLockTime,
            nExpiryHeight);
    }
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

CTransactionComponentProof::CTransactionComponentProof(TransactionMMView &txView, const CTransactionMap &txMap, const CTransaction &tx, int16_t partType, int16_t subIndex) : 
    elType(partType), elIdx(subIndex)
{
    std::pair<int16_t, int16_t> idx({partType, subIndex});
    switch(partType)
    {
        case CTransactionHeader::TX_FULL:
        {
            elVchObj = ::AsVector(tx);
            break;
        }
        case CTransactionHeader::TX_HEADER:
        {
            if (txMap.elementHashMap.count(idx) && txView.GetProof(elProof, txMap.elementHashMap.find(idx)->second))
            {
                elVchObj = ::AsVector(CTransactionHeader(tx));
            }
            break;
        }
        case CTransactionHeader::TX_PREVOUTSEQ:
        {
            if (txMap.elementHashMap.count(idx) && txView.GetProof(elProof, txMap.elementHashMap.find(idx)->second))
            {
                CTxIn prevOutSeqOnly = tx.vin[subIndex];
                prevOutSeqOnly.scriptSig = CScript();
                elVchObj = ::AsVector(prevOutSeqOnly);
            }
            break;
        }
        case CTransactionHeader::TX_SIGNATURE:
        {
            if (txMap.elementHashMap.count(idx) && txView.GetProof(elProof, txMap.elementHashMap.find(idx)->second))
            {
                elVchObj = ::AsVector(tx.vin[subIndex]);
            }
            break;
        }
        case CTransactionHeader::TX_OUTPUT:
        {
            if (txMap.elementHashMap.count(idx) && txView.GetProof(elProof, txMap.elementHashMap.find(idx)->second))
            {
                elVchObj = ::AsVector(tx.vout[subIndex]);
            }
            break;
        }
        case CTransactionHeader::TX_SHIELDEDSPEND:
        {
            if (txMap.elementHashMap.count(idx) && txView.GetProof(elProof, txMap.elementHashMap.find(idx)->second))
            {
                elVchObj = ::AsVector(tx.vShieldedSpend[subIndex]);
            }
            break;
        }
        case CTransactionHeader::TX_SHIELDEDOUTPUT:
        {
            if (txMap.elementHashMap.count(idx) && txView.GetProof(elProof, txMap.elementHashMap.find(idx)->second))
            {
                elVchObj = ::AsVector(tx.vShieldedOutput[subIndex]);
            }
            break;
        }
    }
}

UniValue CPartialTransactionProof::ToUniValue() const
{
    // univalue of this is just hex
    std::vector<unsigned char> serBytes(::AsVector(*this));
    return HexBytes(&(serBytes[0]), serBytes.size());
}

CPartialTransactionProof::CPartialTransactionProof(const UniValue &uni)
{
    // univalue of this is just hex
    std::vector<unsigned char> serializedBytes = ParseHex(uni_get_str(uni));
    if (serializedBytes.size())
    {
        ::FromVector(serializedBytes, *this);
    }
}

// this validates that all parts of a transaction match and either returns a full transaction
// and its hash, a partially filled transaction and its MMR root, or NULL
uint256 CPartialTransactionProof::GetPartialTransaction(CTransaction &outTx, bool *pIsPartial) const
{
    CTransactionHeader txh;
    CMutableTransaction mtx;
    CVDXF_Data vdxfObj;

    uint256 txRoot;
    bool checkOK = false;
    bool isPartial = true;
    if (components.size())
    {
        if (components[0].elType == CTransactionHeader::TX_HEADER && components[0].Rehydrate(txh))
        {
            // validate the header and calculate a transaction root
            txRoot = components[0].CheckProof();

            checkOK = true;
            mtx = txh.RehydrateTransactionScaffold();
            for (int i = 1; i < components.size(); i++)
            {
                if (components[i].CheckProof() != txRoot)
                {
                    checkOK = false;
                    break;
                }
                else
                {
                    switch (components[i].elType)
                    {
                        case CTransactionHeader::TX_PREVOUTSEQ:
                        case CTransactionHeader::TX_SIGNATURE:
                        {
                            if (mtx.vin.size() > components[i].elIdx)
                            {
                                ::FromVector(components[i].elVchObj, mtx.vin[components[i].elIdx]);
                            }
                            else
                            {
                                checkOK = false;
                            }
                            break;
                        }
                        case CTransactionHeader::TX_OUTPUT:
                        {
                            if (mtx.vout.size() > components[i].elIdx)
                            {
                                ::FromVector(components[i].elVchObj, mtx.vout[components[i].elIdx]);
                            }
                            else
                            {
                                checkOK = false;
                            }
                            break;
                        }
                        case CTransactionHeader::TX_SHIELDEDSPEND:
                        {
                            if (mtx.vShieldedSpend.size() > components[i].elIdx)
                            {
                                ::FromVector(components[i].elVchObj, mtx.vShieldedSpend[components[i].elIdx]);
                            }
                            else
                            {
                                checkOK = false;
                            }
                            break;
                        }
                        case CTransactionHeader::TX_SHIELDEDOUTPUT:
                        {
                            if (mtx.vShieldedOutput.size() > components[i].elIdx)
                            {
                                ::FromVector(components[i].elVchObj, mtx.vShieldedOutput[components[i].elIdx]);
                            }
                            else
                            {
                                checkOK = false;
                            }
                            break;
                        }
                    }
                }
            }
            if (checkOK && !txRoot.IsNull())
            {
                outTx = mtx;
            }
            else
            {
                txRoot = uint256();
            }
        }
        else if (components[0].elType == CTransactionHeader::TX_FULL && components[0].Rehydrate(outTx))
        {
            isPartial = false;
            txRoot = outTx.GetHash();
        }
        else if (components[0].elType == CTransactionHeader::TX_ETH_OBJECT && components[0].Rehydrate(vdxfObj))
        {
            if (vdxfObj.key == CCrossChainExport::CurrencyExportKey())
            {
                // unpack data specific to export and reserve transfers
                CDataStream s = CDataStream(vdxfObj.data, SER_NETWORK, PROTOCOL_VERSION);
                uint256 prevtxid;
                CCrossChainExport ccx;
                CCcontract_info CC;
                CCcontract_info *cp;
                checkOK = true;
                try
                {
                    s >> ccx;
                    s >> prevtxid;
                }
                catch (const std::runtime_error &e)
                {
                    LogPrintf("ETH Rehydrate(vdxfObj) Error : %s\n", e.what());
                    checkOK = false;
                }

                if (ccx.IsValid() && checkOK)
                {
                    CNativeHashWriter hw2(CCurrencyDefinition::EProofProtocol::PROOF_ETHNOTARIZATION);
                    hw2 << ccx;
                    hw2 << prevtxid;

                    txRoot = hw2.GetHash();
                    cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                    mtx.vin.push_back(CTxIn(prevtxid, 0));
                    mtx.vout.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx))));

                    isPartial = true;

                    outTx = mtx;
                }
                else
                {
                    if(checkOK)
                        LogPrintf("Invalid ETH ccx : %s\n", __func__);
                    txRoot = uint256();
                }
            }
        }
    }
    if (pIsPartial)
    {
        *pIsPartial = isPartial;
    }
    return txRoot;
}

// this validates that all parts of a transaction match and also whether or not it
// matches the block MMR root, which should be the return value
uint256 CPartialTransactionProof::CheckPartialTransaction(CTransaction &outTx, bool *pIsPartial, bool optimizedETH) const
{
    return txProof.CheckProof(GetPartialTransaction(outTx, pIsPartial), optimizedETH);
}

uint256 CPartialTransactionProof::CheckBlockPreHeader(CPBaaSPreHeader &outPreHeader, bool newPosFormat) const
{
    outPreHeader = GetBlockPreHeader();
    if (LogAcceptCategory("notarization"))
    {
        printf("%s: preHeader: %s\n", __func__, outPreHeader.ToUniValue().write(1,2).c_str());
    }
    if (outPreHeader.IsValid())
    {
        auto hw = CDefaultMMRNode::GetHashWriter();
        return txProof.CheckProof(newPosFormat ? (hw << outPreHeader).GetHash() : uint256());
    }
    return uint256();
}

