// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "core_io.h"

#include "key_io.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include "univalue.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

#include "cc/eval.h"
#include "pbaas/reserves.h"
#include "pbaas/notarization.h"

#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

using namespace std;

string FormatScript(const CScript& script)
{
    string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        vector<unsigned char> vch;
        if (script.GetOp2(it, op, &vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_CHECKMULTISIGVERIFY) {
                string str(GetOpName(op));
                if (str.substr(0, 3) == string("OP_")) {
                    ret += str.substr(3, string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(it2, it - vch.size()), HexStr(it - vch.size(), it));
            } else {
                ret += strprintf("0x%x", HexStr(it2, it));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(it2, script.end()));
        break;
    }
    return ret.substr(0, ret.size() - 1);
}

const map<unsigned char, string> mapSigHashTypes =
    boost::assign::map_list_of
    (static_cast<unsigned char>(SIGHASH_ALL), string("ALL"))
    (static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), string("ALL|ANYONECANPAY"))
    (static_cast<unsigned char>(SIGHASH_NONE), string("NONE"))
    (static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), string("NONE|ANYONECANPAY"))
    (static_cast<unsigned char>(SIGHASH_SINGLE), string("SINGLE"))
    (static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), string("SINGLE|ANYONECANPAY"))
    ;

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures. For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode)
{
    string str;
    opcodetype opcode;
    vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, NULL)) {
                        const unsigned char chSigHashType = vch.back();
                        if (mapSigHashTypes.count(chSigHashType)) {
                            strSigHashDecode = "[" + mapSigHashTypes.find(chSigHashType)->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

string EncodeHexTx(const CTransaction& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

string EncodeHexBlk(const CBlock& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

UniValue ValueFromAmount(const CAmount& amount)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", sign ? "-" : "", quotient, remainder));
}

UniValue CNodeData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("networkaddress", networkAddress));
    obj.push_back(Pair("nodeidentity", EncodeDestination(CIdentityID(nodeIdentity))));
    return obj;
}

CCurrencyValueMap::CCurrencyValueMap(const UniValue &uni)
{
    // must be an array of key:value, where key is currency ID encoded as i-address
    if (uni.isObject())
    {
        const std::vector<std::string> &keys(uni.getKeys());
        const std::vector<UniValue> &values(uni.getValues());
        for (int i = 0; i < keys.size(); i++)
        {
            uint160 currencyID = GetDestinationID(DecodeDestination(keys[i]));
            if (currencyID.IsNull())
            {
                LogPrintf("Invalid JSON CurrencyValueMap\n");
                valueMap.clear();
                break;
            }
            if (valueMap.count(currencyID))
            {
                LogPrintf("Duplicate currency in JSON CurrencyValueMap\n");
                valueMap.clear();
                break;
            }

            try
            {
                valueMap[currencyID] = AmountFromValueNoErr(values[i]);
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
                valueMap.clear();
                break;
            }
        }
    }
}

UniValue CCurrencyValueMap::ToUniValue() const
{
    UniValue retVal(UniValue::VOBJ);
    for (auto &curValue : valueMap)
    {
        retVal.push_back(Pair(EncodeDestination(CIdentityID(curValue.first)), ValueFromAmount(curValue.second)));
    }
    return retVal;
}

uint160 CCurrencyDefinition::GetID(const std::string &Name, uint160 &Parent)
{
    return CIdentity::GetID(Name, Parent);
}

uint160 CCurrencyDefinition::GetConditionID(int32_t condition) const
{
    return CCrossChainRPCData::GetConditionID(name, condition);
}

UniValue CCurrencyDefinition::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);

    obj.push_back(Pair("version", (int64_t)nVersion));
    obj.push_back(Pair("options", (int64_t)options));
    obj.push_back(Pair("name", name));
    obj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(GetID()))));
    if (!parent.IsNull())
    {
        obj.push_back(Pair("parent", EncodeDestination(CIdentityID(parent))));
    }

    obj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    obj.push_back(Pair("notarizationprotocol", (int)notarizationProtocol));
    obj.push_back(Pair("proofprotocol", (int)proofProtocol));

    if (nativeCurrencyID.IsValid())
    {
        obj.push_back(Pair("nativecurrencyid", nativeCurrencyID.ToUniValue()));
    }

    if (!launchSystemID.IsNull())
    {
        obj.push_back(Pair("launchsystemid", EncodeDestination(CIdentityID(launchSystemID))));
    }
    obj.push_back(Pair("startblock", (int64_t)startBlock));
    obj.push_back(Pair("endblock", (int64_t)endBlock));

    // currencies that can be converted for pre-launch or fractional usage
    if (currencies.size())
    {
        UniValue currencyArr(UniValue::VARR);
        for (auto &currency : currencies)
        {
            currencyArr.push_back(EncodeDestination(CIdentityID(currency)));
        }
        obj.push_back(Pair("currencies", currencyArr));
    }

    if (weights.size())
    {
        UniValue weightArr(UniValue::VARR);
        for (auto &weight : weights)
        {
            weightArr.push_back(ValueFromAmount(weight));
        }
        obj.push_back(Pair("weights", weightArr));
    }

    if (conversions.size())
    {
        UniValue conversionArr(UniValue::VARR);
        for (auto &conversion : conversions)
        {
            conversionArr.push_back(ValueFromAmount(conversion));
        }
        obj.push_back(Pair("conversions", conversionArr));
    }

    if (minPreconvert.size())
    {
        UniValue minPreconvertArr(UniValue::VARR);
        for (auto &oneMin : minPreconvert)
        {
            minPreconvertArr.push_back(ValueFromAmount(oneMin));
        }
        obj.push_back(Pair("minpreconversion", minPreconvertArr));
    }

    if (maxPreconvert.size())
    {
        UniValue maxPreconvertArr(UniValue::VARR);
        for (auto &oneMax : maxPreconvert)
        {
            maxPreconvertArr.push_back(ValueFromAmount(oneMax));
        }
        obj.push_back(Pair("maxpreconversion", maxPreconvertArr));
    }

    if (preLaunchDiscount)
    {
        obj.push_back(Pair("prelaunchdiscount", ValueFromAmount(preLaunchDiscount)));
    }

    if (IsFractional())
    {
        obj.push_back(Pair("initialsupply", ValueFromAmount(initialFractionalSupply)));
        obj.push_back(Pair("prelaunchcarveout", ValueFromAmount(preLaunchCarveOut)));
    }

    if (preAllocation.size())
    {
        UniValue preAllocationArr(UniValue::VARR);
        for (auto &onePreAllocation : preAllocation)
        {
            UniValue onePreAlloc(UniValue::VOBJ);
            onePreAlloc.push_back(Pair(onePreAllocation.first.IsNull() ? "blockoneminer" : EncodeDestination(CIdentityID(onePreAllocation.first)),
                                       ValueFromAmount(onePreAllocation.second)));
            preAllocationArr.push_back(onePreAlloc);
        }
        obj.push_back(Pair("preallocations", preAllocationArr));
    }

    if (!gatewayID.IsNull())
    {
        obj.push_back(Pair("gateway", EncodeDestination(CIdentityID(gatewayID))));
    }

    if (contributions.size())
    {
        UniValue initialContributionArr(UniValue::VARR);
        for (auto &oneCurContributions : contributions)
        {
            initialContributionArr.push_back(ValueFromAmount(oneCurContributions));
        }
        obj.push_back(Pair("initialcontributions", initialContributionArr));
    }

    if (IsGateway() || IsGatewayConverter() || IsPBaaSChain())
    {
        obj.push_back(Pair("gatewayconverterissuance", ValueFromAmount(gatewayConverterIssuance)));
    }

    obj.push_back(Pair("idregistrationfees", ValueFromAmount(idRegistrationFees)));
    obj.push_back(Pair("idreferrallevels", idReferralLevels));
    obj.push_back(Pair("idimportfees", ValueFromAmount(idImportFees)));

    if (IsGateway() || IsPBaaSChain())
    {
        // notaries are identities that perform specific functions for the currency's operation
        // related to notarizing an external currency source, as well as proving imports
        if (notaries.size())
        {
            UniValue notaryArr(UniValue::VARR);
            for (auto &notary : notaries)
            {
                notaryArr.push_back(EncodeDestination(CIdentityID(notary)));
            }
            obj.push_back(Pair("notaries", notaryArr));
        }
        obj.push_back(Pair("minnotariesconfirm", minNotariesConfirm));

        obj.push_back(Pair("currencyregistrationfee", ValueFromAmount(currencyRegistrationFee)));
        obj.push_back(Pair("pbaassystemregistrationfee", ValueFromAmount(pbaasSystemLaunchFee)));
        obj.push_back(Pair("currencyimportfee", ValueFromAmount(currencyImportFee)));
        obj.push_back(Pair("transactionimportfee", ValueFromAmount(transactionImportFee)));
        obj.push_back(Pair("transactionexportfee", ValueFromAmount(transactionExportFee)));

        if (!gatewayConverterName.empty())
        {
            obj.push_back(Pair("gatewayconverterid", EncodeDestination(CIdentityID(GatewayConverterID()))));
            obj.push_back(Pair("gatewayconvertername", gatewayConverterName));
        }

        if (IsPBaaSChain())
        {
            arith_uint256 target;
            target.SetCompact(initialBits);
            obj.push_back(Pair("initialtarget", ArithToUint256(target).GetHex()));

            obj.pushKV("blocktime", (int64_t)blockTime);
            obj.pushKV("powaveragingwindow", (int64_t)powAveragingWindow);
            obj.pushKV("notarizationperiod", (int)blockNotarizationModulo);

            UniValue eraArr(UniValue::VARR);
            for (int i = 0; i < rewards.size(); i++)
            {
                UniValue era(UniValue::VOBJ);
                era.push_back(Pair("reward", rewards.size() > i ? rewards[i] : (int64_t)0));
                era.push_back(Pair("decay", rewardsDecay.size() > i ? rewardsDecay[i] : (int64_t)0));
                era.push_back(Pair("halving", halving.size() > i ? (int32_t)halving[i] : (int32_t)0));
                era.push_back(Pair("eraend", eraEnd.size() > i ? (int32_t)eraEnd[i] : (int32_t)0));
                eraArr.push_back(era);
            }
            obj.push_back(Pair("eras", eraArr));
        }
    }

    return obj;
}

UniValue CCurrencyState::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("flags", (int32_t)flags));
    ret.push_back(Pair("version", (int32_t)version));
    ret.push_back(Pair("currencyid", EncodeDestination(CIdentityID(currencyID))));

    if (IsValid())
    {
        if (IsFractional())
        {
            UniValue currencyArr(UniValue::VARR);
            for (int i = 0; i < currencies.size(); i++)
            {
                UniValue currencyObj(UniValue::VOBJ);
                currencyObj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(currencies[i]))));
                currencyObj.push_back(Pair("weight", ValueFromAmount(i < weights.size() ? weights[i] : 0)));
                currencyObj.push_back(Pair("reserves", ValueFromAmount(i < reserves.size() ? reserves[i] : 0)));
                currencyObj.push_back(Pair("priceinreserve", ValueFromAmount(PriceInReserve(i))));
                currencyArr.push_back(currencyObj);
            }
            ret.push_back(Pair("reservecurrencies", currencyArr));
        }
        else
        {
            UniValue currencyArr(UniValue::VARR);
            for (int i = 0; i < currencies.size(); i++)
            {
                UniValue currencyObj(UniValue::VOBJ);
                currencyObj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(currencies[i]))));
                currencyObj.push_back(Pair("weight", ValueFromAmount(i < weights.size() ? weights[i] : 0)));
                currencyObj.push_back(Pair("reserves", ValueFromAmount(i < reserves.size() ? reserves[i] : 0)));
                currencyObj.push_back(Pair("priceinreserve", ValueFromAmount(PriceInReserve(i))));
                currencyArr.push_back(currencyObj);
            }
            ret.push_back(Pair("launchcurrencies", currencyArr));
        }
    }
    ret.push_back(Pair("initialsupply", ValueFromAmount(initialSupply)));
    ret.push_back(Pair("emitted", ValueFromAmount(emitted)));
    ret.push_back(Pair("supply", ValueFromAmount(supply)));
    return ret;
}

CAmount CCurrencyState::PriceInReserve(int32_t reserveIndex, bool roundUp) const
{
    if (reserveIndex >= reserves.size())
    {
        return 0;
    }
    if (!IsFractional())
    {
        return reserves[reserveIndex];
    }
    if (!supply || weights[reserveIndex] == 0)
    {
        return weights[reserveIndex];
    }
    arith_uint256 Supply(supply);
    arith_uint256 Reserve(reserves[reserveIndex] ? reserves[reserveIndex] : SATOSHIDEN);
    arith_uint256 Ratio(weights[reserveIndex]);
    static arith_uint256 bigZero(0);
    static arith_uint256 BigSatoshi(SATOSHIDEN);
    static arith_uint256 BigSatoshiSquared = BigSatoshi * BigSatoshi;

    if (roundUp)
    {
        arith_uint256 denominator = Supply * Ratio;
        arith_uint256 numerator = Reserve * BigSatoshiSquared;
        arith_uint256 bigAnswer = numerator / denominator;
        int64_t remainder = (numerator - (bigAnswer * denominator)).GetLow64();
        CAmount answer = bigAnswer.GetLow64();
        if (remainder && (answer + 1) > 0)
        {
            answer++;
        }
        return answer;
    }
    else
    {
        return ((Reserve * BigSatoshiSquared) / (Supply * Ratio)).GetLow64();
    }
}

cpp_dec_float_50 CCurrencyState::PriceInReserveDecFloat50(int32_t reserveIndex) const
{
    static cpp_dec_float_50 BigSatoshiSquared("10000000000000000");
    static cpp_dec_float_50 BigZero("0");
    if (reserveIndex >= reserves.size())
    {
        return BigZero;
    }
    if (!IsFractional())
    {
        return cpp_dec_float_50(std::to_string(reserves[reserveIndex]));
    }
    if (!supply || weights[reserveIndex] == 0)
    {
        return cpp_dec_float_50(std::to_string(weights[reserveIndex]));
    }
    cpp_dec_float_50 Supply(std::to_string((supply ? supply : 1)));
    cpp_dec_float_50 Reserve(std::to_string(reserves[reserveIndex] ? reserves[reserveIndex] : SATOSHIDEN));
    cpp_dec_float_50 Ratio(std::to_string(weights[reserveIndex]));
    return (Reserve * BigSatoshiSquared) / (Supply * Ratio);
}

std::vector<CAmount> CCurrencyState::PricesInReserve(bool roundUp) const
{
    std::vector<CAmount> retVal(currencies.size());
    for (int i = 0; i < currencies.size(); i++)
    {
        retVal[i] = PriceInReserve(i, roundUp);
    }
    return retVal;
}

CAmount CCurrencyState::ReserveToNativeRaw(CAmount reserveAmount, const cpp_dec_float_50 &price)
{
    static cpp_dec_float_50 bigSatoshi(std::to_string(SATOSHIDEN));
    static cpp_dec_float_50 bigZero(std::to_string(0));
    cpp_dec_float_50 bigAmount(std::to_string(reserveAmount));

    bigAmount = price != bigZero ? (bigAmount * bigSatoshi) / price : bigZero;
    int64_t retVal;
    if (to_int64(bigAmount, retVal))
    {
        return retVal;
    }
    return 0;
}

CAmount CCurrencyState::ReserveToNativeRaw(CAmount reserveAmount, CAmount exchangeRate)
{
    //return ReserveToNativeRaw(reserveAmount, cpp_dec_float_50(std::to_string(exchangeRate)));

    static arith_uint256 bigSatoshi(SATOSHIDEN);
    static arith_uint256 bigZero(0);
    arith_uint256 bigAmount(reserveAmount);

    arith_uint256 bigRetVal = (exchangeRate != bigZero ? (bigAmount * bigSatoshi) / exchangeRate : bigZero);
    int64_t retVal = bigRetVal.GetLow64();
    if ((bigRetVal - retVal) == 0)
    {
        return retVal;
    }
    else
    {
        // return -1 on overflow
        return -1;
    }
}

CAmount CCurrencyState::ReserveToNativeRaw(const CCurrencyValueMap &reserveAmounts, const std::vector<CAmount> &exchangeRates) const
{
    CAmount nativeOut = 0;
    for (int i = 0; i < currencies.size(); i++)
    {
        auto it = reserveAmounts.valueMap.find(currencies[i]);
        if (it != reserveAmounts.valueMap.end())
        {
            nativeOut += ReserveToNativeRaw(it->second, exchangeRates[i]);
        }
    }
    return nativeOut;
}

CAmount CCurrencyState::ReserveToNativeRaw(const CCurrencyValueMap &reserveAmounts,
                                              const std::vector<uint160> &currencies,
                                              const std::vector<cpp_dec_float_50> &exchangeRates)
{
    CAmount nativeOut = 0;
    for (int i = 0; i < currencies.size(); i++)
    {
        auto it = reserveAmounts.valueMap.find(currencies[i]);
        if (it != reserveAmounts.valueMap.end())
        {
            nativeOut += ReserveToNativeRaw(it->second, exchangeRates[i]);
        }
    }
    return nativeOut;
}

CAmount CCurrencyState::ReserveToNativeRaw(const CCurrencyValueMap &reserveAmounts,
                                           const std::vector<uint160> &currencies,
                                           const std::vector<CAmount> &exchangeRates)
{
    CAmount nativeOut = 0;
    for (int i = 0; i < currencies.size(); i++)
    {
        auto it = reserveAmounts.valueMap.find(currencies[i]);
        if (it != reserveAmounts.valueMap.end())
        {
            nativeOut += ReserveToNativeRaw(it->second, exchangeRates[i]);
        }
    }
    return nativeOut;
}

CAmount CCurrencyState::ReserveToNative(CAmount reserveAmount, int32_t reserveIndex) const
{
    return ReserveToNativeRaw(reserveAmount, PriceInReserve(reserveIndex));
}

CAmount CCurrencyState::NativeToReserveRaw(CAmount nativeAmount, const cpp_dec_float_50 &price)
{
    static cpp_dec_float_50 bigSatoshi(std::to_string((SATOSHIDEN)));
    cpp_dec_float_50 bigAmount(std::to_string(nativeAmount));
    int64_t retVal;
    cpp_dec_float_50 bigReserves = (bigAmount * price) / bigSatoshi;
    if (to_int64(bigReserves, retVal))
    {
        return retVal;
    }
    return 0;
}

CAmount CCurrencyState::NativeToReserveRaw(CAmount nativeAmount, CAmount exchangeRate)
{
    //return NativeToReserveRaw(nativeAmount, cpp_dec_float_50(std::to_string(exchangeRate)));

    static arith_uint256 bigSatoshi(SATOSHIDEN);
    arith_uint256 bigAmount(nativeAmount);
    arith_uint256 bigReserves = (bigAmount * exchangeRate) / bigSatoshi;
    int64_t retVal = bigReserves.GetLow64();
    if ((bigReserves - retVal) == 0)
    {
        return retVal;
    }
    else
    {
        // return -1 on overflow
        return -1;
    }
}

CAmount CCurrencyState::NativeGasToReserveRaw(CAmount nativeAmount, CAmount exchangeRate)
{
    if (!exchangeRate)
    {
        return nativeAmount;
    }
    exchangeRate = exchangeRate / (SATOSHIDEN / 100);
    static arith_uint256 bigSatoshiX1000(SATOSHIDEN * 1000);
    arith_uint256 bigAmount(nativeAmount);
    arith_uint256 bigReserves = (bigAmount * exchangeRate) / bigSatoshiX1000;
    int64_t retVal = bigReserves.GetLow64();
    if ((bigReserves - retVal) == 0)
    {
        return retVal;
    }
    else
    {
        // return -1 on overflow
        return -1;
    }
}

CAmount CCurrencyState::NativeToReserve(CAmount nativeAmount, int32_t reserveIndex) const
{
    return NativeToReserveRaw(nativeAmount, PriceInReserve(reserveIndex));
}

CCurrencyValueMap CCurrencyState::NativeToReserveRaw(const std::vector<CAmount> &nativeAmount, const std::vector<CAmount> &exchangeRates) const
{
    static arith_uint256 bigSatoshi(SATOSHIDEN);
    CCurrencyValueMap retVal;
    for (int i = 0; i < currencies.size(); i++)
    {
        retVal.valueMap[currencies[i]] =  NativeToReserveRaw(nativeAmount[i], exchangeRates[i]);
    }
    return retVal;
}

CCurrencyValueMap CCurrencyState::NativeToReserveRaw(const std::vector<CAmount> &nativeAmount, const std::vector<cpp_dec_float_50> &exchangeRates) const
{
    static arith_uint256 bigSatoshi(SATOSHIDEN);
    CCurrencyValueMap retVal;
    for (int i = 0; i < currencies.size(); i++)
    {
        retVal.valueMap[currencies[i]] =  NativeToReserveRaw(nativeAmount[i], exchangeRates[i]);
    }
    return retVal;
}

CAmount CCurrencyState::ReserveToNative(const CCurrencyValueMap &reserveAmounts) const
{
    CAmount nativeOut = 0;
    for (int i = 0; i < currencies.size(); i++)
    {
        auto it = reserveAmounts.valueMap.find(currencies[i]);
        if (it != reserveAmounts.valueMap.end())
        {
            nativeOut += ReserveToNative(it->second, i);
        }
    }
    return nativeOut;
}

template <typename INNERVECTOR>
UniValue ValueVectorsToUniValue(const std::vector<std::string> &rowNames,
                                const std::vector<std::string> &columnNames,
                                const std::vector<INNERVECTOR *> &vec,
                                bool columnVectors)
{
    UniValue retVal(UniValue::VOBJ);
    if (columnVectors)
    {
        for (int i = 0; i < rowNames.size(); i++)
        {
            UniValue row(UniValue::VOBJ);
            for (int j = 0; j < columnNames.size(); j++)
            {
                row.push_back(Pair(columnNames[j], ValueFromAmount((*(vec[j])).size() > i ? (*(vec[j]))[i] : 0)));
            }
            retVal.push_back(Pair(rowNames[i], row));
        }
    }
    else
    {
        for (int i = 0; i < rowNames.size(); i++)
        {
            UniValue row(UniValue::VOBJ);
            for (int j = 0; j < columnNames.size(); j++)
            {
                row.push_back(Pair(columnNames[j], ValueFromAmount((*(vec[i])).size() > j ? (*(vec[i]))[j] : 0)));
            }
            retVal.push_back(Pair(rowNames[i], row));
        }
    }
    return retVal;
}

UniValue CCoinbaseCurrencyState::ToUniValue() const
{
    UniValue ret = ((CCurrencyState *)this)->ToUniValue();
    if (currencies.size())
    {
        std::vector<std::string> rowNames;
        for (int i = 0; i < currencies.size(); i++)
        {
            rowNames.push_back(EncodeDestination(CIdentityID(currencies[i])));
        }
        std::vector<std::string> columnNames({"reservein", "primarycurrencyin", "reserveout", "lastconversionprice", "viaconversionprice", "fees", "conversionfees", "priorweights"});
        std::vector<CAmount> int64PriorWeights;
        for (auto &oneWeight : priorWeights)
        {
            int64PriorWeights.push_back(oneWeight);
        }
        std::vector<const std::vector<CAmount> *> data = {&reserveIn, &primaryCurrencyIn, &reserveOut, &conversionPrice, &viaConversionPrice, &fees, &conversionFees, &int64PriorWeights};

        ret.push_back(Pair("currencies", ValueVectorsToUniValue(rowNames, columnNames, data, true)));
    }
    ret.push_back(Pair("primarycurrencyfees", ValueFromAmount(primaryCurrencyFees)));
    ret.push_back(Pair("primarycurrencyconversionfees", ValueFromAmount(primaryCurrencyConversionFees)));
    ret.push_back(Pair("primarycurrencyout", ValueFromAmount(primaryCurrencyOut)));
    ret.push_back(Pair("preconvertedout", ValueFromAmount(preConvertedOut)));
    return ret;
}

bool CPBaaSNotarization::SetMirror(bool setTrue)
{
    // if we are not changing the mirror state, just return
    if (setTrue == IsMirror())
    {
        return true;
    }

    // we can only reverse notarizations with two proof roots
    // one must be the current chain, and the other is to reverse
    if (proofRoots.size() != 2 ||
        currencyStates.count(currencyID) ||
        !(proofRoots.begin()->first == ASSETCHAINS_CHAINID || (++proofRoots.begin())->first == ASSETCHAINS_CHAINID))
    {
        LogPrint("notarization", "%s: invalid earned notarization for acceptance\n", __func__);
        return false;
    }

    uint160 oldCurrencyID = currencyID;
    uint160 newCurrencyID = proofRoots.begin()->first == currencyID ? (++proofRoots.begin())->first : proofRoots.begin()->first;

    if (currencyID != ASSETCHAINS_CHAINID && !currencyStates.count(ASSETCHAINS_CHAINID))
    {
        LogPrint("notarization", "%s: notarization for acceptance must include both currency states\n", __func__);
        return false;
    }

    /* printf("%s: currencyStates.size(): %lu, oldCurrencyID: %s, newCurrencyID: %s\n",
        __func__,
        currencyStates.size(),
        EncodeDestination(CIdentityID(oldCurrencyID)).c_str(),
        EncodeDestination(CIdentityID(newCurrencyID)).c_str());
    for (auto &oneState : currencyStates)
    {
        printf("%s:\n%s\n", EncodeDestination(CIdentityID(oneState.first)).c_str(), oneState.second.ToUniValue().write(1,2).c_str());
    } */

    notarizationHeight = proofRoots[newCurrencyID].rootHeight;
    currencyStates.insert(std::make_pair(oldCurrencyID, currencyState));
    currencyState = currencyStates[newCurrencyID];
    currencyStates.erase(newCurrencyID);

    /* for (auto &oneState : currencyStates)
    {
        printf("%s:\n%s\n", EncodeDestination(CIdentityID(oneState.first)).c_str(), oneState.second.ToUniValue().write(1,2).c_str());
    } */

    currencyID = newCurrencyID;

    if (setTrue)
    {
        flags |= FLAG_ACCEPTED_MIRROR;
    }
    else
    {
        flags &= ~FLAG_ACCEPTED_MIRROR;
        proposer.ClearAuxDests();
    }
    return true;
}

UniValue CPBaaSNotarization::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)nVersion));
    if (IsDefinitionNotarization())
    {
        obj.push_back(Pair("isdefinition", true));
    }

    if (IsBlockOneNotarization())
    {
        obj.push_back(Pair("isblockonenotarization", true));
    }

    if (IsPreLaunch())
    {
        obj.push_back(Pair("prelaunch", true));
    }

    if (IsLaunchCleared())
    {
        obj.push_back(Pair("launchcleared", true));
    }

    if (IsRefunding())
    {
        obj.push_back(Pair("refunding", true));
    }

    if (IsLaunchConfirmed())
    {
        obj.push_back(Pair("launchconfirmed", true));
    }

    if (IsLaunchComplete())
    {
        obj.push_back(Pair("launchcomplete", true));
    }

    if (IsMirror())
    {
        obj.push_back(Pair("ismirror", true));
    }

    if (IsSameChain())
    {
        obj.push_back(Pair("samechain", true));
    }

    obj.push_back(Pair("proposer", proposer.ToUniValue()));

    obj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(currencyID))));
    obj.push_back(Pair("notarizationheight", (int64_t)notarizationHeight));
    obj.push_back(Pair("currencystate", currencyState.ToUniValue()));
    obj.push_back(Pair("prevnotarizationtxid", prevNotarization.hash.GetHex()));
    obj.push_back(Pair("prevnotarizationout", (int64_t)prevNotarization.n));
    obj.push_back(Pair("prevheight", (int64_t)prevHeight));
    obj.push_back(Pair("hashprevcrossnotarization", hashPrevCrossNotarization.GetHex()));

    // now get states and roots, of which there may be multiple
    UniValue curStateArr(UniValue::VARR);
    for (auto &oneState : currencyStates)
    {
        UniValue oneCurState(UniValue::VOBJ);
        oneCurState.pushKV(EncodeDestination(CIdentityID(oneState.first)), oneState.second.ToUniValue());
        curStateArr.push_back(oneCurState);
    }
    obj.push_back(Pair("currencystates", curStateArr));

    UniValue proofRootsUni(UniValue::VARR);
    for (auto &oneRoot : proofRoots)
    {
        proofRootsUni.push_back(oneRoot.second.ToUniValue());
    }
    obj.push_back(Pair("proofroots", proofRootsUni));

    UniValue nodesUni(UniValue::VARR);
    for (auto node : nodes)
    {
        nodesUni.push_back(node.ToUniValue());
    }
    obj.push_back(Pair("nodes", nodesUni));
    return obj;
}

UniValue CTokenOutput::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("version", (int64_t)nVersion));
    ret.push_back(Pair("currencyvalues", reserveValues.ToUniValue()));
    return ret;
}

UniValue CReserveDeposit::ToUniValue() const
{
    UniValue ret = ((CTokenOutput *)this)->ToUniValue();
    ret.push_back(Pair("controllingcurrencyid", controllingCurrencyID.IsNull() ? "NULL" : EncodeDestination(CIdentityID(controllingCurrencyID))));
    return ret;
}

UniValue CETHNFTAddress::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("contract", "0x" + HexBytes(contractID.begin(), contractID.size()));
    ret.pushKV("tokenid", "0x" + HexBytes(tokenID.begin(), tokenID.size()));
    return ret;
}

UniValue CTransferDestination::ToUniValue() const
{
    UniValue destVal = UniValue(UniValue::VOBJ);
    uint8_t newType = type;

    switch (TypeNoFlags())
    {
        case CTransferDestination::DEST_PK:
        {
            CPubKey pk;
            pk.Set(destination.begin(), destination.end());
            destVal.push_back(Pair("address", HexStr(pk)));
            break;
        }

        case CTransferDestination::DEST_PKH:
            destVal.push_back(Pair("address", EncodeDestination(CKeyID(uint160(destination)))));
            break;

        case CTransferDestination::DEST_SH:
            destVal.push_back(Pair("address", EncodeDestination(CScriptID(uint160(destination)))));
            break;

        case CTransferDestination::DEST_ID:
            destVal.push_back(Pair("address", EncodeDestination(CIdentityID(uint160(destination)))));
            break;

        case CTransferDestination::DEST_QUANTUM:
            destVal.push_back(Pair("address", EncodeDestination(CQuantumID(uint160(destination)))));
            break;

        case CTransferDestination::DEST_ETH:
            destVal.push_back(Pair("address", EncodeEthDestination(uint160(destination))));
            break;

        case CTransferDestination::DEST_ETHNFT:
        {
            CETHNFTAddress oneAddr;
            bool success = false;
            ::FromVector(destination, oneAddr, &success);
            destVal.push_back(Pair("address", success ? oneAddr.ToUniValue() : UniValue(UniValue::VOBJ)));
            break;
        }

        case CTransferDestination::DEST_FULLID:
            destVal.push_back(Pair("identity", CIdentity(destination).ToUniValue()));
            destVal.push_back(Pair("serializeddata", HexBytes(&(destination[0]), destination.size())));
            break;

        case CTransferDestination::DEST_REGISTERCURRENCY:
        {
            destVal.push_back(Pair("currency", CCurrencyDefinition(destination).ToUniValue()));
            destVal.push_back(Pair("serializeddata", HexBytes(&(destination[0]), destination.size())));
            break;
        }

        case CTransferDestination::DEST_RAW:
            destVal.push_back(Pair("address", HexBytes(&(destination[0]),destination.size())));
            break;

        case CTransferDestination::DEST_NESTEDTRANSFER:
            destVal.push_back(Pair("nestedtransfer", CReserveTransfer(destination).ToUniValue()));
            break;

        default:
            destVal.push_back(Pair("undefined", ""));
            break;
    }
    if ((type & FLAG_DEST_AUX))
    {
        if (auxDests.size())
        {
            UniValue auxDestsUni(UniValue::VARR);
            for (auto &oneVec : auxDests)
            {
                CTransferDestination oneDest;
                bool success = true;
                ::FromVector(oneVec, oneDest, &success);
                // can't nest aux destinations
                if (!success || (oneDest.type & FLAG_DEST_AUX))
                {
                    newType = DEST_INVALID;
                    break;
                }
                auxDestsUni.push_back(oneDest.ToUniValue());
            }
            if (newType != DEST_INVALID)
            {
                destVal.push_back(Pair("auxdests", auxDestsUni));
            }
        }
        else
        {
            newType &= ~FLAG_DEST_AUX;
        }
    }
    if (type & FLAG_DEST_GATEWAY)
    {
        if (destVal.isNull())
        {
            destVal = UniValue(UniValue::VOBJ);
        }
        destVal.push_back(Pair("gateway", EncodeDestination(CIdentityID(gatewayID))));
        destVal.push_back(Pair("fees", ValueFromAmount(fees)));
    }
    destVal.push_back(Pair("type", newType));
    return destVal;
}

UniValue CReserveTransfer::ToUniValue() const
{
    UniValue ret(((CTokenOutput *)this)->ToUniValue());

    ret.push_back(Pair("flags", (int32_t)flags));

    if (IsCrossSystem())
    {
        ret.push_back(Pair("crosssystem", true));
        ret.push_back(Pair("exportto", EncodeDestination(CIdentityID(destSystemID))));
    }
    if (IsRefund())
        ret.push_back(Pair("refund", true));
    if (IsImportToSource())
        ret.push_back(Pair("importtosource", true));
    if (IsConversion())
        ret.push_back(Pair("convert", true));
    if (IsPreConversion())
        ret.push_back(Pair("preconvert", true));
    if (IsFeeOutput())
        ret.push_back(Pair("feeoutput", true));
    if (IsReserveToReserve())
        ret.push_back(Pair("reservetoreserve", true));
    if (IsBurnChangePrice())
        ret.push_back(Pair("burnchangeprice", true));
    if (IsBurnChangeWeight())
        ret.push_back(Pair("burnchangeweight", true));
    if (IsMint())
        ret.push_back(Pair("mint", true));

    ret.push_back(Pair("feecurrencyid", EncodeDestination(CIdentityID(feeCurrencyID))));
    ret.push_back(Pair("fees", ValueFromAmount(nFees)));
    if (IsReserveToReserve())
    {
        ret.push_back(Pair("destinationcurrencyid", EncodeDestination(CIdentityID(secondReserveID))));
        ret.push_back(Pair("via", EncodeDestination(CIdentityID(destCurrencyID))));
    }
    else
    {
        ret.push_back(Pair("destinationcurrencyid", EncodeDestination(CIdentityID(destCurrencyID))));
    }

    ret.push_back(Pair("destination", destination.ToUniValue()));
    return ret;
}

UniValue CCrossChainExport::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)nVersion));
    obj.push_back(Pair("flags", (int32_t)flags));
    if (!this->IsSupplemental())
    {
        obj.push_back(Pair("sourceheightstart", (int64_t)sourceHeightStart));
        obj.push_back(Pair("sourceheightend", (int64_t)sourceHeightEnd));
        obj.push_back(Pair("sourcesystemid", EncodeDestination(CIdentityID(sourceSystemID))));
        obj.push_back(Pair("destinationsystemid", EncodeDestination(CIdentityID(destSystemID))));
        obj.push_back(Pair("destinationcurrencyid", EncodeDestination(CIdentityID(destCurrencyID))));
        obj.push_back(Pair("numinputs", numInputs));
        obj.push_back(Pair("totalamounts", totalAmounts.ToUniValue()));
        obj.push_back(Pair("totalfees", totalFees.ToUniValue()));
        obj.push_back(Pair("hashtransfers", hashReserveTransfers.GetHex()));
        obj.push_back(Pair("totalburned", totalBurned.ToUniValue()));
        obj.push_back(Pair("rewardaddress", EncodeDestination(TransferDestinationToDestination(exporter))));
        obj.push_back(Pair("firstinput", firstInput));
    }
    else
    {
        obj.push_back(Pair("issupplemental", true));
    }
    UniValue transfers(UniValue::VARR);
    for (auto &oneTransfer : reserveTransfers)
    {
        transfers.push_back(oneTransfer.ToUniValue());
    }
    if (transfers.size())
    {
        obj.push_back(Pair("transfers", transfers));
    }
    return obj;
}

UniValue CCrossChainImport::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)nVersion));
    obj.push_back(Pair("flags", (int32_t)flags));
    obj.push_back(Pair("sourcesystemid", EncodeDestination(CIdentityID(sourceSystemID))));
    obj.push_back(Pair("sourceheight", (int64_t)sourceSystemHeight));
    obj.push_back(Pair("importcurrencyid", EncodeDestination(CIdentityID(importCurrencyID))));
    obj.push_back(Pair("valuein", importValue.ToUniValue()));
    obj.push_back(Pair("tokensout", totalReserveOutMap.ToUniValue()));
    obj.push_back(Pair("numoutputs", (int32_t)numOutputs));
    obj.push_back(Pair("hashtransfers", hashReserveTransfers.GetHex()));
    obj.push_back(Pair("exporttxid", exportTxId.GetHex()));
    obj.push_back(Pair("exporttxout", exportTxOutNum));
    return obj;
}

UniValue CUTXORef::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("txid", hash.GetHex()));
    obj.push_back(Pair("voutnum", (int64_t)n));
    return obj;
}

CUTXORef::CUTXORef(const UniValue &uni)
{
    hash = uint256S(uni_get_str(find_value(uni, "txid")));
    n = uni_get_int(find_value(uni, "voutnum"));
}

UniValue CObjectFinalization::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("finalizationtype", finalizationType));
    ret.push_back(Pair("status", IsConfirmed() ?
                                    "confirmed" :
                                    IsRejected() ?
                                        "rejected" :
                                        IsChallenge() ?
                                            "challenge" :
                                            "pending"));
    if (evidenceInputs.size())
    {
        UniValue inputsUni(UniValue::VARR);
        for (auto i : evidenceInputs)
        {
            inputsUni.push_back(i);
        }
        ret.pushKV("evidenceinputs", inputsUni);
    }
    if (evidenceOutputs.size())
    {
        UniValue outputsUni(UniValue::VARR);
        for (auto i : evidenceOutputs)
        {
            outputsUni.push_back(i);
        }
        ret.pushKV("evidenceoutputs", outputsUni);
    }
    ret.push_back(Pair("currencyid", EncodeDestination(CIdentityID(currencyID))));
    ret.push_back(Pair("output", output.ToUniValue()));
    return ret;
}

UniValue CPrincipal::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)nVersion));
    obj.push_back(Pair("flags", (int32_t)flags));

    UniValue primaryAddressesUni(UniValue::VARR);
    for (int i = 0; i < primaryAddresses.size(); i++)
    {
        primaryAddressesUni.push_back(EncodeDestination(primaryAddresses[i]));
    }
    obj.push_back(Pair("primaryaddresses", primaryAddressesUni));
    obj.push_back(Pair("minimumsignatures", minSigs));
    return obj;
}

UniValue CIdentity::ToUniValue() const
{
    UniValue obj = ((CPrincipal *)this)->ToUniValue();
    obj.push_back(Pair("name", name));

    obj.push_back(Pair("identityaddress", EncodeDestination(CIdentityID(GetID()))));
    obj.push_back(Pair("parent", EncodeDestination(CIdentityID(parent))));
    obj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));

    UniValue hashes(UniValue::VOBJ);
    for (auto &entry : contentMap)
    {
        hashes.push_back(Pair(entry.first.GetHex(), entry.second.GetHex()));
    }
    obj.push_back(Pair("contentmap", hashes));

    if (nVersion >= VERSION_PBAAS)
    {
        hashes = UniValue(UniValue::VOBJ);
        UniValue entryArr(UniValue::VARR);
        uint160 lastHash;
        for (auto &entry : contentMultiMap)
        {
            if (entry.first.IsNull())
            {
                continue;
            }
            else if (entry.first != lastHash && !lastHash.IsNull())
            {
                hashes.push_back(Pair(EncodeDestination(CIdentityID(lastHash)), entryArr));
                entryArr = UniValue(UniValue::VARR);
            }
            lastHash = entry.first;

            // if we have room for a known 20 byte value, check to see if it is one
            CDataStream ss(entry.second, PROTOCOL_VERSION, SER_DISK);
            bool objOut = false;
            UniValue entryUni(UniValue::VOBJ);

            while (ss.size() > sizeof(uint160))
            {
                try
                {
                    uint160 checkVal;
                    uint32_t version;
                    int64_t objSize;
                    ss >> checkVal;
                    UniValue objectUni(UniValue::VNULL);

                    if (checkVal == CVDXF_Data::DataCurrencyMapKey())
                    {
                        CCurrencyValueMap oneCurrencyMap;
                        ss >> VARINT(version);
                        ss >> VARINT(objSize);
                        ss >> oneCurrencyMap;
                        if (oneCurrencyMap.IsValid())
                        {
                            objectUni = oneCurrencyMap.ToUniValue();
                        }
                    }
                    else if (checkVal == CVDXF_Data::DataRatingsKey())
                    {
                        CRating oneRatingObj;
                        ss >> VARINT(version);
                        ss >> VARINT(objSize);
                        ss >> oneRatingObj;
                        if (oneRatingObj.IsValid())
                        {
                            objectUni = oneRatingObj.ToUniValue();
                        }
                    }
                    else if (checkVal == CVDXF_Data::DataTransferDestinationKey())
                    {
                        CTransferDestination oneTransferDest;
                        ss >> VARINT(version);
                        ss >> VARINT(objSize);
                        ss >> oneTransferDest;
                        if (oneTransferDest.IsValid())
                        {
                            objectUni = oneTransferDest.ToUniValue();
                        }
                    }
                    else if (checkVal == CVDXF_Data::ContentMultiMapRemoveKey())
                    {
                        CContentMultiMapRemove oneContentRemove;
                        ss >> VARINT(version);
                        ss >> VARINT(objSize);
                        ss >> oneContentRemove;
                        if (oneContentRemove.IsValid())
                        {
                            objectUni = oneContentRemove.ToUniValue();
                        }
                    }
                    else if (checkVal == CVDXF_Data::DataStringKey())
                    {
                        std::string stringVal;
                        ss >> VARINT(version);
                        ss >> VARINT(objSize);
                        ss >> stringVal;
                        objectUni = stringVal;
                    }
                    else if (checkVal == CVDXF_Data::DataByteVectorKey())
                    {
                        std::vector<unsigned char> vecVal;
                        ss >> VARINT(version);
                        ss >> VARINT(objSize);
                        ss >> vecVal;
                        objectUni = HexBytes(&(vecVal[0]), vecVal.size());
                    }

                    // if we have an object that we recognized, encode it
                    if (!objectUni.isNull())
                    {
                        objOut = true;
                        entryUni.pushKV(EncodeDestination(CIdentityID(checkVal)), objectUni);
                    }
                    else
                    {
                        objOut = false;
                        break;
                    }
                }
                catch (...)
                {
                    objOut = false;
                    break;
                }
            }
            if (objOut)
            {
                entryArr.push_back(entryUni);
            }
            else
            {
                entryArr.push_back(HexBytes(&(entry.second[0]), entry.second.size()));
            }
        }
        if (!lastHash.IsNull())
        {
            hashes.push_back(Pair(EncodeDestination(CIdentityID(lastHash)), entryArr));
        }
        obj.push_back(Pair("contentmultimap", hashes));
    }

    obj.push_back(Pair("revocationauthority", EncodeDestination(CTxDestination(CIdentityID(revocationAuthority)))));
    obj.push_back(Pair("recoveryauthority", EncodeDestination(CTxDestination(CIdentityID(recoveryAuthority)))));
    if (privateAddresses.size())
    {
        obj.push_back(Pair("privateaddress", EncodePaymentAddress(privateAddresses[0])));
    }

    obj.push_back(Pair("timelock", (int32_t)unlockAfter));

    return obj;
}

std::multimap<uint160, std::vector<std::string>> CRating::ratingsDefinitionMap;
const std::multimap<uint160, std::vector<std::string>> &CRating::GetRatingDefinitionMap(const std::locale &locale)
{
    static CCriticalSection cs;
    LOCK(cs);
    if (!ratingsDefinitionMap.size())
    {
        std::vector<std::string> defaultRatingKeys;
        defaultRatingKeys.resize(RATING_LASTDEFAULT + 1);
        defaultRatingKeys[RATING_1] = "1";
        defaultRatingKeys[RATING_2] = "2";
        defaultRatingKeys[RATING_3] = "3";
        defaultRatingKeys[RATING_4] = "4";
        defaultRatingKeys[RATING_5] = "5";
        defaultRatingKeys[RATING_6] = "6";
        defaultRatingKeys[RATING_7] = "7";
        defaultRatingKeys[RATING_8] = "8";
        defaultRatingKeys[RATING_9] = "9";
        defaultRatingKeys[RATING_10] = "10";
        defaultRatingKeys[RATING_G] = "RATED G";
        defaultRatingKeys[RATING_PG] = "RATED PG";
        defaultRatingKeys[RATING_PG13] = "RATED PG13";
        defaultRatingKeys[RATING_R] = "RATED R";
        defaultRatingKeys[RATING_NC17] = "RATED NC-17";
        defaultRatingKeys[RATING_HSEX] = "SEXUALITY";
        defaultRatingKeys[RATING_HHEALTH] = "HEALTH";
        defaultRatingKeys[RATING_DRUGS] = "SMOKING/DRUGS";
        defaultRatingKeys[RATING_NUDITY] = "NUDITY";
        defaultRatingKeys[RATING_VIOLENCE] = "VIOLENCE";
        defaultRatingKeys[RATING_1STAR] = std::string(u8"\U00002B50");
        defaultRatingKeys[RATING_2STAR] = std::string(u8"\U00002B50") + std::string(u8"\U00002B50");
        defaultRatingKeys[RATING_3STAR] = std::string(u8"\U00002B50") + std::string(u8"\U00002B50") + std::string(u8"\U00002B50");
        defaultRatingKeys[RATING_4STAR] = std::string(u8"\U00002B50") + std::string(u8"\U00002B50") + std::string(u8"\U00002B50") + std::string(u8"\U00002B50");
        defaultRatingKeys[RATING_5STAR] = std::string(u8"\U00002B50") + std::string(u8"\U00002B50") + std::string(u8"\U00002B50") + std::string(u8"\U00002B50") + std::string(u8"\U00002B50");
        defaultRatingKeys[RATING_BAD] = std::string(u8"\U0001F620");
        defaultRatingKeys[RATING_POOR] = std::string(u8"\U0001F641");
        defaultRatingKeys[RATING_OK] = std::string(u8"\U0001F610");
        defaultRatingKeys[RATING_GOOD] = std::string(u8"\U0001F642");
        defaultRatingKeys[RATING_EXCELLENT] = std::string(u8"\U0001F603");
        ratingsDefinitionMap.insert(std::make_pair(DefaultRatingTypeKey(), defaultRatingKeys));
    }
    return ratingsDefinitionMap;
}

UniValue CRating::ToUniValue() const
{
    const std::multimap<uint160, std::vector<std::string>> &ratingMap = GetRatingDefinitionMap();

    UniValue retVal(UniValue::VOBJ);
    retVal.pushKV("version", (int64_t)version);
    retVal.pushKV("trustlevel", (int)trustLevel);

    UniValue ratingsMapUni(UniValue::VOBJ);

    for (auto &oneMapEntry : ratings)
    {
        bool uniOut = false;
        auto it = ratingMap.find(oneMapEntry.first);
        if (it != ratingMap.end())
        {
            uniOut = true;
            std::set<std::pair<int,std::string>> uniStrings;
            for (auto &oneRating : oneMapEntry.second)
            {
                if (oneRating > 0 && oneRating < it->second.size())
                {
                    uniStrings.insert(std::make_pair(oneRating, it->second[oneRating]));
                }
                else
                {
                    uniOut = false;
                    break;
                }
            }
            if (uniOut)
            {
                UniValue ratingsArr(UniValue::VARR);
                for (auto &oneRatingPair : uniStrings)
                {
                    ratingsArr.push_back(oneRatingPair.second);
                }
                ratingsMapUni.pushKV(EncodeDestination(CIdentityID(oneMapEntry.first)), ratingsArr);
            }
        }
        if (!uniOut)
        {
            ratingsMapUni.pushKV(EncodeDestination(CIdentityID(oneMapEntry.first)), HexBytes(&(oneMapEntry.second[0]), oneMapEntry.second.size()));
        }
    }
    if (ratings.size())
    {
        retVal.pushKV("ratingsmap", ratingsMapUni);
    }
    return retVal;
}

UniValue CMMRProof::ToUniValue() const
{
    UniValue retObj(UniValue::VOBJ);
    for (auto &proof : proofSequence)
    {
        UniValue branchArray(UniValue::VARR);
        switch (proof->branchType)
        {
            case CMerkleBranchBase::BRANCH_BTC:
            {
                CBTCMerkleBranch &branch = *(CBTCMerkleBranch *)(proof);
                retObj.push_back(Pair("branchtype", (int)CMerkleBranchBase::BRANCH_BTC));
                retObj.push_back(Pair("index", (int64_t)(branch.nIndex)));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.push_back(Pair("hashes", branchArray));
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_NODE:
            {
                CMMRNodeBranch &branch = *(CMMRNodeBranch *)(proof);
                retObj.push_back(Pair("branchtype", (int)CMerkleBranchBase::BRANCH_MMRBLAKE_NODE));
                retObj.push_back(Pair("index", (int64_t)(branch.nIndex)));
                retObj.push_back(Pair("mmvsize", (int64_t)(branch.nSize)));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.push_back(Pair("hashes", branchArray));
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE:
            {
                CMMRPowerNodeBranch &branch = *(CMMRPowerNodeBranch *)(proof);
                retObj.push_back(Pair("branchtype", (int)CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE));
                retObj.push_back(Pair("index", (int64_t)(branch.nIndex)));
                retObj.push_back(Pair("mmvsize", (int64_t)(branch.nSize)));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.push_back(Pair("hashes", branchArray));
                break;
            }
            case CMerkleBranchBase::BRANCH_ETH:
            {
                CETHPATRICIABranch &branch = *(CETHPATRICIABranch *)(proof);
                retObj.push_back(Pair("branchtype", (int)CMerkleBranchBase::BRANCH_ETH));
                // univalue of ETH proof is just hex of whole object
                std::vector<unsigned char> serBytes(::AsVector(*this));
                retObj.push_back(Pair("data", HexBytes(&(serBytes[0]), serBytes.size())));
            }
        };
    }
    return retObj;
}

UniValue CNameReservation::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("name", name));
    ret.push_back(Pair("salt", salt.GetHex()));
    ret.push_back(Pair("referral", referral.IsNull() ? "" : EncodeDestination(referral)));

    if (_IsVerusActive())
    {
        if (boost::to_lower_copy(name) == VERUS_CHAINNAME)
        {
            ret.push_back(Pair("parent", ""));
        }
        else
        {
            ret.push_back(Pair("parent", EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID()))));
        }
        ret.push_back(Pair("nameid", EncodeDestination(DecodeDestination(name + "@"))));
    }
    else
    {
        ret.push_back(Pair("parent", EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID()))));
        ret.push_back(Pair("nameid", EncodeDestination(DecodeDestination(name + "." + ConnectedChains.ThisChain().name + "@"))));
    }

    return ret;
}

UniValue CAdvancedNameReservation::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("version", (uint64_t)version));
    ret.push_back(Pair("name", name));
    ret.push_back(Pair("parent", EncodeDestination(CIdentityID(parent))));
    ret.push_back(Pair("salt", salt.GetHex()));
    ret.push_back(Pair("referral", referral.IsNull() ? "" : EncodeDestination(referral)));
    uint160 ParentID = parent;
    ret.push_back(Pair("nameid", EncodeDestination(CIdentity::GetID(name, ParentID))));
    return ret;
}

void ScriptPubKeyToUniv(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex, bool fIncludeAsm)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    CCurrencyValueMap tokensOut = scriptPubKey.ReserveOutValue();

    // needs to be an object
    if (!out.isObject())
    {
        out = UniValue(UniValue::VOBJ);
    }

    int nRequired;
    ExtractDestinations(scriptPubKey, type, addresses, nRequired);
    out.push_back(Pair("type", GetTxnOutputType(type)));

    COptCCParams p;

    if (scriptPubKey.IsPayToCryptoCondition(p) && p.version >= COptCCParams::VERSION_V2)
    {
        switch(p.evalCode)
        {
            case EVAL_CURRENCY_DEFINITION:
            {
                CCurrencyDefinition definition;

                if (p.vData.size() &&
                    p.version >= COptCCParams::VERSION_V3 &&
                    (definition = CCurrencyDefinition(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("currencydefinition", definition.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("currencydefinition", "invalid"));
                }
                break;
            }

            case EVAL_NOTARY_EVIDENCE:
            {
                CNotaryEvidence evidence;

                if (p.vData.size() && (evidence = CNotaryEvidence(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("notaryevidence", evidence.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("notaryevidence", "invalid"));
                }
                break;
            }

            case EVAL_EARNEDNOTARIZATION:
            case EVAL_ACCEPTEDNOTARIZATION:
            {
                CPBaaSNotarization notarization;

                if (p.vData.size() && (notarization = CPBaaSNotarization(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("pbaasnotarization", notarization.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("pbaasnotarization", "invalid"));
                }
                break;
            }

            case EVAL_FINALIZE_NOTARIZATION:
            {
                CObjectFinalization finalization;

                if (p.vData.size())
                {
                    finalization = CObjectFinalization(p.vData[0]);
                    out.push_back(Pair("finalizenotarization", finalization.ToUniValue()));
                }
                break;
            }

            case EVAL_CURRENCYSTATE:
            {
                CCoinbaseCurrencyState cbcs;

                if (p.vData.size() && (cbcs = CCoinbaseCurrencyState(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("currencystate", cbcs.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("currencystate", "invalid"));
                }
                break;
            }

            case EVAL_RESERVE_TRANSFER:
            {
                CReserveTransfer rt;

                if (p.vData.size() && (rt = CReserveTransfer(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("reservetransfer", rt.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("reservetransfer", "invalid"));
                }
                break;
            }

            case EVAL_RESERVE_OUTPUT:
            {
                CTokenOutput ro;

                if (p.vData.size() && (ro = CTokenOutput(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("reserveoutput", ro.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("reserveoutput", "invalid"));
                }
                break;
            }

            case EVAL_IDENTITY_RESERVATION:
            {
                CNameReservation ar;

                if (p.vData.size() && (ar = CNameReservation(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("identityreservation", ar.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("identityreservation", "invalid"));
                }
                break;
            }

            case EVAL_IDENTITY_ADVANCEDRESERVATION:
            {
                CAdvancedNameReservation anr;

                if (p.vData.size() && (anr = CAdvancedNameReservation(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("identityreservation", anr.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("identityreservation", "invalid"));
                }
                break;
            }

            case EVAL_RESERVE_DEPOSIT:
            {
                CReserveDeposit rd;

                if (p.vData.size() && (rd = CReserveDeposit(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("reservedeposit", rd.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("reservedeposit", "invalid"));
                }
                break;
            }

            case EVAL_CROSSCHAIN_EXPORT:
            {
                CCrossChainExport ccx;

                if (p.vData.size() && (ccx = CCrossChainExport(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("crosschainexport", ccx.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("crosschainexport", "invalid"));
                }
                break;
            }

            case EVAL_CROSSCHAIN_IMPORT:
            {
                CCrossChainImport cci;

                if (p.vData.size() && (cci = CCrossChainImport(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("crosschainimport", cci.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("crosschainimport", "invalid"));
                }
                break;
            }

            case EVAL_IDENTITY_PRIMARY:
            {
                CIdentity identity;

                if (p.vData.size() && (identity = CIdentity(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("identityprimary", identity.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("identityprimary", "invalid"));
                }
                break;
            }

            case EVAL_IDENTITY_REVOKE:
                out.push_back(Pair("identityrevoke", ""));
                break;

            case EVAL_IDENTITY_RECOVER:
                out.push_back(Pair("identityrecover", ""));
                break;

            case EVAL_IDENTITY_COMMITMENT:
            {
                CCommitmentHash ch;

                if (p.vData.size())
                {
                    ch = CCommitmentHash(p.vData[0]);
                    out.push_back(Pair("commitmenthash", ch.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("commitmenthash", ""));
                }
                break;
            }

            case EVAL_STAKEGUARD:
                out.push_back(Pair("stakeguard", ""));
                break;

            case EVAL_FINALIZE_EXPORT:
            {
                CObjectFinalization finalization;

                if (p.vData.size())
                {
                    finalization = CObjectFinalization(p.vData[0]);
                    out.push_back(Pair("finalizeexport", finalization.ToUniValue()));
                }
                break;
            }

            case EVAL_FEE_POOL:
            {
                CFeePool feePool;

                if (p.vData.size())
                {
                    feePool = CFeePool(p.vData[0]);
                    out.push_back(Pair("feepool", feePool.ToUniValue()));
                }
                break;
            }

            default:
                out.push_back(Pair("unknown", ""));
        }
    }

    out.push_back(Pair("spendableoutput", scriptPubKey.IsSpendableOutputType()));

    if (tokensOut.valueMap.size())
    {
        UniValue reserveBal(UniValue::VOBJ);
        for (auto &oneBalance : tokensOut.valueMap)
        {
            reserveBal.push_back(make_pair(ConnectedChains.GetCachedCurrency(oneBalance.first).name, ValueFromAmount(oneBalance.second)));
        }
        if (reserveBal.size())
        {
            out.push_back(Pair("reserve_balance", reserveBal));
        }
    }

    if (addresses.size())
    {
        out.push_back(Pair("reqSigs", nRequired));

        UniValue a(UniValue::VARR);
        for (const CTxDestination& addr : addresses) {
            a.push_back(EncodeDestination(addr));
        }
        out.push_back(Pair("addresses", a));
    }

    if (fIncludeAsm)
    {
        out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    }

    if (fIncludeHex)
    {
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
    }
}

void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry)
{
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("version", tx.nVersion);
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin(UniValue::VARR);
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
        else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
            in.pushKV("scriptSig", o);
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        UniValue outValue(UniValue::VNUM, FormatMoney(txout.nValue));
        out.pushKV("value", outValue);
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToUniv(txout.scriptPubKey, o, true, false);
        out.pushKV("scriptPubKey", o);
        vout.push_back(out);
    }
    entry.pushKV("vout", vout);

    if (!hashBlock.IsNull())
        entry.pushKV("blockhash", hashBlock.GetHex());

    entry.pushKV("hex", EncodeHexTx(tx)); // the hex-encoded transaction. used the name "hex" to be consistent with the verbose output of "getrawtransaction".
}
