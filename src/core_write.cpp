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
    obj.pushKV("networkaddress", networkAddress);
    obj.pushKV("nodeidentity", EncodeDestination(CIdentityID(nodeIdentity)));
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
        retVal.pushKV(EncodeDestination(CIdentityID(curValue.first)), ValueFromAmount(curValue.second));
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

    obj.pushKV("version", (int64_t)nVersion);
    obj.pushKV("options", (int64_t)options);
    obj.pushKV("name", name);
    obj.pushKV("currencyid", EncodeDestination(CIdentityID(GetID())));
    if (!parent.IsNull())
    {
        obj.pushKV("parent", EncodeDestination(CIdentityID(parent)));
    }

    obj.pushKV("systemid", EncodeDestination(CIdentityID(systemID)));
    obj.pushKV("notarizationprotocol", (int)notarizationProtocol);
    obj.pushKV("proofprotocol", (int)proofProtocol);

    if (nativeCurrencyID.IsValid())
    {
        obj.pushKV("nativecurrencyid", nativeCurrencyID.ToUniValue());
    }

    if (!launchSystemID.IsNull())
    {
        obj.pushKV("launchsystemid", EncodeDestination(CIdentityID(launchSystemID)));
    }
    obj.pushKV("startblock", (int64_t)startBlock);
    obj.pushKV("endblock", (int64_t)endBlock);

    // currencies that can be converted for pre-launch or fractional usage
    if (currencies.size())
    {
        UniValue currencyArr(UniValue::VARR);
        for (auto &currency : currencies)
        {
            currencyArr.push_back(EncodeDestination(CIdentityID(currency)));
        }
        obj.pushKV("currencies", currencyArr);
    }

    if (weights.size())
    {
        UniValue weightArr(UniValue::VARR);
        for (auto &weight : weights)
        {
            weightArr.push_back(ValueFromAmount(weight));
        }
        obj.pushKV("weights", weightArr);
    }

    if (conversions.size())
    {
        UniValue conversionArr(UniValue::VARR);
        for (auto &conversion : conversions)
        {
            conversionArr.push_back(ValueFromAmount(conversion));
        }
        obj.pushKV("conversions", conversionArr);
    }

    if (minPreconvert.size())
    {
        UniValue minPreconvertArr(UniValue::VARR);
        for (auto &oneMin : minPreconvert)
        {
            minPreconvertArr.push_back(ValueFromAmount(oneMin));
        }
        obj.pushKV("minpreconversion", minPreconvertArr);
    }

    if (maxPreconvert.size())
    {
        UniValue maxPreconvertArr(UniValue::VARR);
        for (auto &oneMax : maxPreconvert)
        {
            maxPreconvertArr.push_back(ValueFromAmount(oneMax));
        }
        obj.pushKV("maxpreconversion", maxPreconvertArr);
    }

    if (preLaunchDiscount)
    {
        obj.pushKV("prelaunchdiscount", ValueFromAmount(preLaunchDiscount));
    }

    if (IsFractional())
    {
        obj.pushKV("initialsupply", ValueFromAmount(initialFractionalSupply));
        obj.pushKV("prelaunchcarveout", ValueFromAmount(preLaunchCarveOut));
    }

    if (preAllocation.size())
    {
        UniValue preAllocationArr(UniValue::VARR);
        for (auto &onePreAllocation : preAllocation)
        {
            UniValue onePreAlloc(UniValue::VOBJ);
            onePreAlloc.pushKV(onePreAllocation.first.IsNull() ? "blockoneminer" : EncodeDestination(CIdentityID(onePreAllocation.first)),
                                       ValueFromAmount(onePreAllocation.second));
            preAllocationArr.push_back(onePreAlloc);
        }
        obj.pushKV("preallocations", preAllocationArr);
    }

    if (!gatewayID.IsNull())
    {
        obj.pushKV("gateway", EncodeDestination(CIdentityID(gatewayID)));
    }

    if (contributions.size())
    {
        UniValue initialContributionArr(UniValue::VARR);
        for (auto &oneCurContributions : contributions)
        {
            initialContributionArr.push_back(ValueFromAmount(oneCurContributions));
        }
        obj.pushKV("initialcontributions", initialContributionArr);
    }

    if (IsGateway() || IsGatewayConverter() || IsPBaaSChain())
    {
        obj.pushKV("gatewayconverterissuance", ValueFromAmount(gatewayConverterIssuance));
    }

    obj.pushKV("idregistrationfees", ValueFromAmount(idRegistrationFees));
    obj.pushKV("idreferrallevels", idReferralLevels);
    obj.pushKV("idimportfees", ValueFromAmount(idImportFees));

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
            obj.pushKV("notaries", notaryArr);
        }
        obj.pushKV("minnotariesconfirm", minNotariesConfirm);

        obj.pushKV("currencyregistrationfee", ValueFromAmount(currencyRegistrationFee));
        obj.pushKV("pbaassystemregistrationfee", ValueFromAmount(pbaasSystemLaunchFee));
        obj.pushKV("currencyimportfee", ValueFromAmount(currencyImportFee));
        obj.pushKV("transactionimportfee", ValueFromAmount(transactionImportFee));
        obj.pushKV("transactionexportfee", ValueFromAmount(transactionExportFee));

        if (!gatewayConverterName.empty())
        {
            obj.pushKV("gatewayconverterid", EncodeDestination(CIdentityID(GatewayConverterID())));
            obj.pushKV("gatewayconvertername", gatewayConverterName);
        }

        if (IsPBaaSChain())
        {
            arith_uint256 target;
            target.SetCompact(initialBits);
            obj.pushKV("initialtarget", ArithToUint256(target).GetHex());

            obj.pushKV("blocktime", (int64_t)blockTime);
            obj.pushKV("powaveragingwindow", (int64_t)powAveragingWindow);
            obj.pushKV("notarizationperiod", (int)blockNotarizationModulo);

            UniValue eraArr(UniValue::VARR);
            for (int i = 0; i < rewards.size(); i++)
            {
                UniValue era(UniValue::VOBJ);
                era.pushKV("reward", rewards.size() > i ? rewards[i] : (int64_t)0);
                era.pushKV("decay", rewardsDecay.size() > i ? rewardsDecay[i] : (int64_t)0);
                era.pushKV("halving", halving.size() > i ? (int32_t)halving[i] : (int32_t)0);
                era.pushKV("eraend", eraEnd.size() > i ? (int32_t)eraEnd[i] : (int32_t)0);
                eraArr.push_back(era);
            }
            obj.pushKV("eras", eraArr);
        }
    }

    return obj;
}

UniValue CCurrencyState::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("flags", (int32_t)flags);
    ret.pushKV("version", (int32_t)version);
    ret.pushKV("currencyid", EncodeDestination(CIdentityID(currencyID)));

    if (IsValid())
    {
        if (IsFractional())
        {
            UniValue currencyArr(UniValue::VARR);
            for (int i = 0; i < currencies.size(); i++)
            {
                UniValue currencyObj(UniValue::VOBJ);
                currencyObj.pushKV("currencyid", EncodeDestination(CIdentityID(currencies[i])));
                currencyObj.pushKV("weight", ValueFromAmount(i < weights.size() ? weights[i] : 0));
                currencyObj.pushKV("reserves", ValueFromAmount(i < reserves.size() ? reserves[i] : 0));
                currencyObj.pushKV("priceinreserve", ValueFromAmount(PriceInReserve(i)));
                currencyArr.push_back(currencyObj);
            }
            ret.pushKV("reservecurrencies", currencyArr);
        }
        else
        {
            UniValue currencyArr(UniValue::VARR);
            for (int i = 0; i < currencies.size(); i++)
            {
                UniValue currencyObj(UniValue::VOBJ);
                currencyObj.pushKV("currencyid", EncodeDestination(CIdentityID(currencies[i])));
                currencyObj.pushKV("weight", ValueFromAmount(i < weights.size() ? weights[i] : 0));
                currencyObj.pushKV("reserves", ValueFromAmount(i < reserves.size() ? reserves[i] : 0));
                currencyObj.pushKV("priceinreserve", ValueFromAmount(PriceInReserve(i)));
                currencyArr.push_back(currencyObj);
            }
            ret.pushKV("launchcurrencies", currencyArr);
        }
    }
    ret.pushKV("initialsupply", ValueFromAmount(initialSupply));
    ret.pushKV("emitted", ValueFromAmount(emitted));
    ret.pushKV("supply", ValueFromAmount(supply));
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
    return -1;
}

CAmount CCurrencyState::ReserveToNativeRaw(CAmount reserveAmount, CAmount exchangeRate, bool promoteExchangeRate)
{
    //return ReserveToNativeRaw(reserveAmount, cpp_dec_float_50(std::to_string(exchangeRate)));

    static arith_uint256 bigSatoshi(SATOSHIDEN);
    static arith_uint256 bigZero(0);
    arith_uint256 bigAmount(reserveAmount);
    arith_uint256 bigRetVal;

    if (promoteExchangeRate)
    {
        arith_uint256 bigExchangeRate(exchangeRate);
        bigRetVal = (bigExchangeRate != bigZero ? (bigAmount * bigSatoshi) / bigExchangeRate : bigZero);
    }
    else
    {
        bigRetVal = (exchangeRate != bigZero ? (bigAmount * bigSatoshi) / exchangeRate : bigZero);
    }

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

CAmount CCurrencyState::ReserveToNative(CAmount reserveAmount, int32_t reserveIndex, bool promoteExchangeRate) const
{
    return ReserveToNativeRaw(reserveAmount, PriceInReserve(reserveIndex), promoteExchangeRate);
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
    return -1;
}

CAmount CCurrencyState::NativeToReserveRaw(CAmount nativeAmount, CAmount exchangeRate, bool promoteExchangeRate)
{
    static arith_uint256 bigSatoshi(SATOSHIDEN);
    arith_uint256 bigAmount(nativeAmount);
    arith_uint256 bigReserves;

    if (promoteExchangeRate)
    {
        arith_uint256 bigExchangeRate(exchangeRate);
        bigReserves = (bigAmount * bigExchangeRate) / bigSatoshi;
    }
    else
    {
        bigReserves = (bigAmount * exchangeRate) / bigSatoshi;
    }

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

CAmount CCurrencyState::NativeGasToReserveRaw(CAmount nativeAmount, CAmount exchangeRate, bool promoteExchangeRate)
{
    if (!exchangeRate)
    {
        return nativeAmount;
    }
    exchangeRate = exchangeRate / (SATOSHIDEN / 100);
    static arith_uint256 bigSatoshiX1000(SATOSHIDEN * 1000);
    arith_uint256 bigAmount(nativeAmount);

    arith_uint256 bigReserves;

    if (promoteExchangeRate)
    {
        arith_uint256 bigExchangeRate(exchangeRate);
        bigReserves = (bigAmount * bigExchangeRate) / bigSatoshiX1000;
    }
    else
    {
        bigReserves = (bigAmount * exchangeRate) / bigSatoshiX1000;
    }

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

CAmount CCurrencyState::NativeToReserve(CAmount nativeAmount, int32_t reserveIndex, bool promoteExchangeRate) const
{
    return NativeToReserveRaw(nativeAmount, PriceInReserve(reserveIndex), promoteExchangeRate);
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
    auto selfIt = reserveAmounts.valueMap.find(currencyID);
    return selfIt == reserveAmounts.valueMap.end() ? nativeOut : nativeOut + selfIt->second;
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
                row.pushKV(columnNames[j], ValueFromAmount((*(vec[j])).size() > i ? (*(vec[j]))[i] : 0));
            }
            retVal.pushKV(rowNames[i], row);
        }
    }
    else
    {
        for (int i = 0; i < rowNames.size(); i++)
        {
            UniValue row(UniValue::VOBJ);
            for (int j = 0; j < columnNames.size(); j++)
            {
                row.pushKV(columnNames[j], ValueFromAmount((*(vec[i])).size() > j ? (*(vec[i]))[j] : 0));
            }
            retVal.pushKV(rowNames[i], row);
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

        ret.pushKV("currencies", ValueVectorsToUniValue(rowNames, columnNames, data, true));
    }
    ret.pushKV("primarycurrencyfees", ValueFromAmount(primaryCurrencyFees));
    ret.pushKV("primarycurrencyconversionfees", ValueFromAmount(primaryCurrencyConversionFees));
    ret.pushKV("primarycurrencyout", ValueFromAmount(primaryCurrencyOut));
    ret.pushKV("preconvertedout", ValueFromAmount(preConvertedOut));
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
    obj.pushKV("version", (int32_t)nVersion);
    if (IsDefinitionNotarization())
    {
        obj.pushKV("isdefinition", true);
    }

    if (IsBlockOneNotarization())
    {
        obj.pushKV("isblockonenotarization", true);
    }

    if (IsPreLaunch())
    {
        obj.pushKV("prelaunch", true);
    }

    if (IsLaunchCleared())
    {
        obj.pushKV("launchcleared", true);
    }

    if (IsRefunding())
    {
        obj.pushKV("refunding", true);
    }

    if (IsLaunchConfirmed())
    {
        obj.pushKV("launchconfirmed", true);
    }

    if (IsLaunchComplete())
    {
        obj.pushKV("launchcomplete", true);
    }

    if (IsContractUpgrade())
    {
        obj.pushKV("contractupgrade", true);
    }

    if (IsMirror())
    {
        obj.pushKV("ismirror", true);
    }

    if (IsSameChain())
    {
        obj.pushKV("samechain", true);
    }

    obj.pushKV("proposer", proposer.ToUniValue());

    obj.pushKV("currencyid", EncodeDestination(CIdentityID(currencyID)));
    obj.pushKV("notarizationheight", (int64_t)notarizationHeight);
    obj.pushKV("currencystate", currencyState.ToUniValue());
    obj.pushKV("prevnotarizationtxid", prevNotarization.hash.GetHex());
    obj.pushKV("prevnotarizationout", (int64_t)prevNotarization.n);
    obj.pushKV("prevheight", (int64_t)prevHeight);
    obj.pushKV("hashprevcrossnotarization", hashPrevCrossNotarization.GetHex());

    // now get states and roots, of which there may be multiple
    UniValue curStateArr(UniValue::VARR);
    for (auto &oneState : currencyStates)
    {
        UniValue oneCurState(UniValue::VOBJ);
        oneCurState.pushKV(EncodeDestination(CIdentityID(oneState.first)), oneState.second.ToUniValue());
        curStateArr.push_back(oneCurState);
    }
    obj.pushKV("currencystates", curStateArr);

    UniValue proofRootsUni(UniValue::VARR);
    for (auto &oneRoot : proofRoots)
    {
        proofRootsUni.push_back(oneRoot.second.ToUniValue());
    }
    obj.pushKV("proofroots", proofRootsUni);

    UniValue nodesUni(UniValue::VARR);
    for (auto node : nodes)
    {
        nodesUni.push_back(node.ToUniValue());
    }
    obj.pushKV("nodes", nodesUni);
    return obj;
}

UniValue CTokenOutput::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("version", (int64_t)nVersion);
    ret.pushKV("currencyvalues", reserveValues.ToUniValue());
    return ret;
}

UniValue CReserveDeposit::ToUniValue() const
{
    UniValue ret = ((CTokenOutput *)this)->ToUniValue();
    ret.pushKV("controllingcurrencyid", controllingCurrencyID.IsNull() ? "NULL" : EncodeDestination(CIdentityID(controllingCurrencyID)));
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
            destVal.pushKV("address", HexStr(pk));
            break;
        }

        case CTransferDestination::DEST_PKH:
            destVal.pushKV("address", EncodeDestination(CKeyID(uint160(destination))));
            break;

        case CTransferDestination::DEST_SH:
            destVal.pushKV("address", EncodeDestination(CScriptID(uint160(destination))));
            break;

        case CTransferDestination::DEST_ID:
            destVal.pushKV("address", EncodeDestination(CIdentityID(uint160(destination))));
            break;

        case CTransferDestination::DEST_QUANTUM:
            destVal.pushKV("address", EncodeDestination(CQuantumID(uint160(destination))));
            break;

        case CTransferDestination::DEST_ETH:
            destVal.pushKV("address", EncodeEthDestination(uint160(destination)));
            break;

        case CTransferDestination::DEST_ETHNFT:
        {
            CETHNFTAddress oneAddr;
            bool success = false;
            ::FromVector(destination, oneAddr, &success);
            destVal.pushKV("address", success ? oneAddr.ToUniValue() : UniValue(UniValue::VOBJ));
            break;
        }

        case CTransferDestination::DEST_FULLID:
            destVal.pushKV("identity", CIdentity(destination).ToUniValue());
            destVal.pushKV("serializeddata", HexBytes(&(destination[0]), destination.size()));
            break;

        case CTransferDestination::DEST_REGISTERCURRENCY:
        {
            destVal.pushKV("currency", CCurrencyDefinition(destination).ToUniValue());
            destVal.pushKV("serializeddata", HexBytes(&(destination[0]), destination.size()));
            break;
        }

        case CTransferDestination::DEST_RAW:
            destVal.pushKV("address", HexBytes(&(destination[0]),destination.size()));
            break;

        case CTransferDestination::DEST_NESTEDTRANSFER:
            destVal.pushKV("nestedtransfer", CReserveTransfer(destination).ToUniValue());
            break;

        default:
            destVal.pushKV("undefined", "");
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
                destVal.pushKV("auxdests", auxDestsUni);
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
        destVal.pushKV("gateway", EncodeDestination(CIdentityID(gatewayID)));
        destVal.pushKV("fees", ValueFromAmount(fees));
    }
    destVal.pushKV("type", newType);
    return destVal;
}

UniValue CReserveTransfer::ToUniValue() const
{
    UniValue ret(((CTokenOutput *)this)->ToUniValue());

    ret.pushKV("flags", (int32_t)flags);

    if (IsCrossSystem())
    {
        ret.pushKV("crosssystem", true);
        ret.pushKV("exportto", EncodeDestination(CIdentityID(destSystemID)));
    }
    if (IsRefund())
        ret.pushKV("refund", true);
    if (IsImportToSource())
        ret.pushKV("importtosource", true);
    if (IsConversion())
        ret.pushKV("convert", true);
    if (IsPreConversion())
        ret.pushKV("preconvert", true);
    if (IsFeeOutput())
        ret.pushKV("feeoutput", true);
    if (IsReserveToReserve())
        ret.pushKV("reservetoreserve", true);
    if (IsBurnChangePrice())
        ret.pushKV("burnchangeprice", true);
    if (IsBurnChangeWeight())
        ret.pushKV("burnchangeweight", true);
    if (IsMint())
        ret.pushKV("mint", true);
    if (IsArbitrageOnly())
        ret.pushKV("arbitrageonly", true);

    ret.pushKV("feecurrencyid", EncodeDestination(CIdentityID(feeCurrencyID)));
    ret.pushKV("fees", ValueFromAmount(nFees));
    if (IsReserveToReserve())
    {
        ret.pushKV("destinationcurrencyid", EncodeDestination(CIdentityID(secondReserveID)));
        ret.pushKV("via", EncodeDestination(CIdentityID(destCurrencyID)));
    }
    else
    {
        ret.pushKV("destinationcurrencyid", EncodeDestination(CIdentityID(destCurrencyID)));
    }

    ret.pushKV("destination", destination.ToUniValue());
    return ret;
}

UniValue CCrossChainExport::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", (int32_t)nVersion);
    obj.pushKV("flags", (int32_t)flags);
    if (!this->IsSupplemental())
    {
        obj.pushKV("sourceheightstart", (int64_t)sourceHeightStart);
        obj.pushKV("sourceheightend", (int64_t)sourceHeightEnd);
        obj.pushKV("sourcesystemid", EncodeDestination(CIdentityID(sourceSystemID)));
        obj.pushKV("destinationsystemid", EncodeDestination(CIdentityID(destSystemID)));
        obj.pushKV("destinationcurrencyid", EncodeDestination(CIdentityID(destCurrencyID)));
        obj.pushKV("numinputs", numInputs);
        obj.pushKV("totalamounts", totalAmounts.ToUniValue());
        obj.pushKV("totalfees", totalFees.ToUniValue());
        obj.pushKV("hashtransfers", hashReserveTransfers.GetHex());
        obj.pushKV("totalburned", totalBurned.ToUniValue());
        obj.pushKV("rewardaddress", EncodeDestination(TransferDestinationToDestination(exporter)));
        obj.pushKV("firstinput", firstInput);
    }
    else
    {
        obj.pushKV("issupplemental", true);
    }
    UniValue transfers(UniValue::VARR);
    for (auto &oneTransfer : reserveTransfers)
    {
        transfers.push_back(oneTransfer.ToUniValue());
    }
    if (transfers.size())
    {
        obj.pushKV("transfers", transfers);
    }
    return obj;
}

UniValue CCrossChainImport::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", (int32_t)nVersion);
    obj.pushKV("flags", (int32_t)flags);
    obj.pushKV("sourcesystemid", EncodeDestination(CIdentityID(sourceSystemID)));
    obj.pushKV("sourceheight", (int64_t)sourceSystemHeight);
    obj.pushKV("importcurrencyid", EncodeDestination(CIdentityID(importCurrencyID)));
    obj.pushKV("valuein", importValue.ToUniValue());
    obj.pushKV("tokensout", totalReserveOutMap.ToUniValue());
    obj.pushKV("numoutputs", (int32_t)numOutputs);
    obj.pushKV("hashtransfers", hashReserveTransfers.GetHex());
    obj.pushKV("exporttxid", exportTxId.GetHex());
    obj.pushKV("exporttxout", exportTxOutNum);
    return obj;
}

UniValue CUTXORef::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", hash.GetHex());
    obj.pushKV("voutnum", (int64_t)n);
    return obj;
}

CUTXORef::CUTXORef(const UniValue &uni)
{
    hash = uint256S(uni_get_str(find_value(uni, "txid")));
    n = uni_get_int(find_value(uni, "voutnum"));
}

CPBaaSEvidenceRef::CPBaaSEvidenceRef(const UniValue &uni) :
    version(uni_get_int64(find_value(uni, "version"), CVDXF_Data::DEFAULT_VERSION)),
    flags(uni_get_int64(find_value(uni, "flags"), FLAG_ISEVIDENCE)),
    output(CUTXORef(find_value(uni, "output"))),
    systemID(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "systemid"))))),
    dataHash(uint256S(uni_get_str(find_value(uni, "datahash")))),
    objectNum(uni_get_int(find_value(uni, "objectnum"), 0)),
    subObject(uni_get_int64(find_value(uni, "subobject"), 0))
{
    SetFlags();
}

UniValue CPBaaSEvidenceRef::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);

    obj.pushKV("version", (int64_t)version);
    obj.pushKV("flags", (int64_t)flags);
    obj.pushKV("output", output.ToUniValue());
    if (flags & FLAG_HAS_SYSTEM)
    {
        obj.pushKV("systemid", EncodeDestination(CIdentityID(systemID)));
    }
    if (flags & FLAG_HAS_HASH)
    {
        obj.pushKV("datahash", dataHash.GetHex());
    }
    obj.pushKV("objectnum", objectNum);
    obj.pushKV("subobject", subObject);
    return obj;
}

CIdentityMultimapRef::CIdentityMultimapRef(const UniValue &uni) :
    version(uni_get_int64(find_value(uni, "version"), CVDXF_Data::DEFAULT_VERSION)),
    flags(uni_get_int64(find_value(uni, "flags"))),
    key(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "vdxfkey"))))),
    idID(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "identityid"))))),
    heightStart(uni_get_int64(find_value(uni, "startheight"))),
    heightEnd(uni_get_int64(find_value(uni, "endheight"))),
    dataHash(uint256S(uni_get_str(find_value(uni, "datahash")))),
    systemID(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "systemid")))))
{
    SetFlags();
}

UniValue CIdentityMultimapRef::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", (int64_t)version);
    obj.pushKV("flags", (int64_t)flags);
    obj.pushKV("vdxfkey", EncodeDestination(CIdentityID(key)));
    obj.pushKV("identityid", EncodeDestination(CIdentityID(idID)));
    if (HasDataHash())
    {
        obj.pushKV("datahash", dataHash.GetHex());
    }
    if (HasSystemID())
    {
        obj.pushKV("systemid", EncodeDestination(CIdentityID(systemID)));
    }
    obj.pushKV("startheight", (int64_t)heightStart);
    obj.pushKV("endheight", (int64_t)heightEnd);
    return obj;
}

CURLRef::CURLRef(const UniValue &uni) :
    version(uni_get_int64(find_value(uni, "version"), DEFAULT_VERSION)),
    flags(uni_get_int64(find_value(uni, "flags"), 0)),
    dataHash(uint256S(uni_get_str(find_value(uni, "datahash")))),
    url(uni_get_str(find_value(uni, "url")))
{
    if (url.size() > 4096)
    {
        url.resize(4096);
    }
}

UniValue CURLRef::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", (int64_t)version);
    obj.pushKV("flags", (int64_t)version);
    obj.pushKV("datahash", dataHash.GetHex());
    obj.pushKV("url", url);
    return obj;
}

CCrossChainDataRef::CCrossChainDataRef(const UniValue &uni)
{
    int type = uni_get_int(find_value(uni, "type"));
    switch (type)
    {
        case TYPE_CROSSCHAIN_DATAREF:
        {
            ref = CPBaaSEvidenceRef(uni);
            break;
        }
        case TYPE_IDENTITY_DATAREF:
        {
            ref = CIdentityMultimapRef(uni);
            break;
        }
        case TYPE_URL_REF:
        {
            ref = CURLRef(uni);
            break;
        }
    }
}

UniValue CCrossChainDataRef::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("type", (int)ref.which());
    switch ((int)ref.which())
    {
        case TYPE_CROSSCHAIN_DATAREF:
        {
            UniValue retVal = boost::get<CPBaaSEvidenceRef>(ref).ToUniValue();
            auto keys = retVal.getKeys();
            auto values = retVal.getValues();
            for (int i = 0; i < keys.size(); i++)
            {
                obj.pushKV(keys[i], values[i]);
            }
            break;
        }
        case TYPE_IDENTITY_DATAREF:
        {
            UniValue retVal = boost::get<CIdentityMultimapRef>(ref).ToUniValue();
            auto keys = retVal.getKeys();
            auto values = retVal.getValues();
            for (int i = 0; i < keys.size(); i++)
            {
                obj.pushKV(keys[i], values[i]);
            }
            break;
        }
        case TYPE_URL_REF:
        {
            UniValue retVal = boost::get<CURLRef>(ref).ToUniValue();
            auto keys = retVal.getKeys();
            auto values = retVal.getValues();
            for (int i = 0; i < keys.size(); i++)
            {
                obj.pushKV(keys[i], values[i]);
            }
            break;
        }
    }
    return obj;
}

UniValue CObjectFinalization::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("finalizationtype", finalizationType);
    ret.pushKV("status", IsConfirmed() ?
                                    "confirmed" :
                                    IsRejected() ?
                                        "rejected" :
                                        IsChallenge() ?
                                            "challenge" :
                                            "pending");
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
    ret.pushKV("currencyid", EncodeDestination(CIdentityID(currencyID)));
    ret.pushKV("output", output.ToUniValue());
    return ret;
}

UniValue CPrincipal::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", (int32_t)nVersion);
    obj.pushKV("flags", (int32_t)flags);

    UniValue primaryAddressesUni(UniValue::VARR);
    for (int i = 0; i < primaryAddresses.size(); i++)
    {
        primaryAddressesUni.push_back(EncodeDestination(primaryAddresses[i]));
    }
    obj.pushKV("primaryaddresses", primaryAddressesUni);
    obj.pushKV("minimumsignatures", minSigs);
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

UniValue CCredential::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    int64_t Flags = CalcFlags();

    ret.pushKV("version", (int64_t)version);
    ret.pushKV("flags", Flags);
    ret.pushKV("credentialKey", EncodeDestination(CIdentityID(credentialKey)));

    ret.pushKV("credential", credential);
    ret.pushKV("scopes", scopes);

    if (HasLabel()) {
        ret.pushKV("label", TrimSpaces(label, true, ""));
    }

    return ret;
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
                retObj.pushKV("branchtype", (int)CMerkleBranchBase::BRANCH_BTC);
                retObj.pushKV("index", (int64_t)(branch.nIndex));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.pushKV("hashes", branchArray);
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_NODE:
            {
                CMMRNodeBranch &branch = *(CMMRNodeBranch *)(proof);
                retObj.pushKV("branchtype", (int)CMerkleBranchBase::BRANCH_MMRBLAKE_NODE);
                retObj.pushKV("index", (int64_t)(branch.nIndex));
                retObj.pushKV("mmvsize", (int64_t)(branch.nSize));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.pushKV("hashes", branchArray);
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE:
            {
                CMMRPowerNodeBranch &branch = *(CMMRPowerNodeBranch *)(proof);
                retObj.pushKV("branchtype", (int)CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE);
                retObj.pushKV("index", (int64_t)(branch.nIndex));
                retObj.pushKV("mmvsize", (int64_t)(branch.nSize));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.pushKV("hashes", branchArray);
                break;
            }
            case CMerkleBranchBase::BRANCH_ETH:
            {
                CETHPATRICIABranch &branch = *(CETHPATRICIABranch *)(proof);
                retObj.pushKV("branchtype", (int)CMerkleBranchBase::BRANCH_ETH);
                // univalue of ETH proof is just hex of whole object
                std::vector<unsigned char> serBytes(::AsVector(*this));
                retObj.pushKV("data", HexBytes(&(serBytes[0]), serBytes.size()));
            }
        };
    }
    return retObj;
}

UniValue CNameReservation::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("name", name);
    ret.pushKV("salt", salt.GetHex());
    ret.pushKV("referral", referral.IsNull() ? "" : EncodeDestination(referral));

    if (_IsVerusActive())
    {
        if (boost::to_lower_copy(name) == VERUS_CHAINNAME)
        {
            ret.pushKV("parent", "");
        }
        else
        {
            ret.pushKV("parent", EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID())));
        }
        ret.pushKV("nameid", EncodeDestination(DecodeDestination(name + "@")));
    }
    else
    {
        ret.pushKV("parent", EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID())));
        ret.pushKV("nameid", EncodeDestination(DecodeDestination(name + "." + ConnectedChains.ThisChain().name + "@")));
    }

    return ret;
}

UniValue CAdvancedNameReservation::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("version", (uint64_t)version);
    ret.pushKV("name", name);
    ret.pushKV("parent", EncodeDestination(CIdentityID(parent)));
    ret.pushKV("salt", salt.GetHex());
    ret.pushKV("referral", referral.IsNull() ? "" : EncodeDestination(referral));
    uint160 ParentID = parent;
    ret.pushKV("nameid", EncodeDestination(CIdentity::GetID(name, ParentID)));
    return ret;
}

// returns 1 object or none if no valid, recognize object at front of stream
template <typename Stream> UniValue CIdentity::VDXFDataToUniValue(Stream &ss, bool *pSuccess)
{
    UniValue objectUni(UniValue::VNULL);
    try
    {
        uint160 checkVal;
        uint32_t version = 0;
        uint64_t objSize = 0;
        ss >> checkVal;

        if (checkVal == CVDXF_Data::DataCurrencyMapKey())
        {
            CCurrencyValueMap oneCurrencyMap;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> oneCurrencyMap;
            if (oneCurrencyMap.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), oneCurrencyMap.ToUniValue());
            }
        }
        else if (checkVal == CVDXF_Data::DataRatingsKey())
        {
            CRating oneRatingObj;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> oneRatingObj;
            if (oneRatingObj.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), oneRatingObj.ToUniValue());
            }
        }
        else if (checkVal == CVDXF_Data::DataCredentialKey())
        {
            CCredential oneCredentialObj;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> oneCredentialObj;
            if (oneCredentialObj.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), oneCredentialObj.ToUniValue());
            }
        }
        else if (checkVal == CVDXF_Data::DataTransferDestinationKey())
        {
            CTransferDestination oneTransferDest;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> oneTransferDest;
            if (oneTransferDest.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), oneTransferDest.ToUniValue());
            }
        }
        else if (checkVal == CVDXF_Data::ContentMultiMapRemoveKey())
        {
            CContentMultiMapRemove oneContentRemove;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> oneContentRemove;
            if (oneContentRemove.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), oneContentRemove.ToUniValue());
            }
        }
        else if (checkVal == CVDXF_Data::DataStringKey())
        {
            std::string stringVal;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> stringVal;
            objectUni = UniValue(UniValue::VOBJ);
            objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), stringVal);
        }
        else if (checkVal == CVDXF_Data::DataByteVectorKey())
        {
            std::vector<unsigned char> vecVal;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> vecVal;
            objectUni = HexBytes(&(vecVal[0]), vecVal.size());
        }
        else if (checkVal == CVDXF_Data::CrossChainDataRefKey())
        {
            CCrossChainDataRef dataRef;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> dataRef;
            if (dataRef.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), dataRef.ToUniValue());
            }
        }
        else if (checkVal == CVDXF_Data::DataDescriptorKey())
        {
            CDataDescriptor dataDescriptor;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> dataDescriptor;
            if (dataDescriptor.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), dataDescriptor.ToUniValue());
            }
        }
        else if (checkVal == CVDXF_Data::MMRDescriptorKey())
        {
            CMMRDescriptor mmrDescriptor;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> mmrDescriptor;
            if (mmrDescriptor.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), mmrDescriptor.ToUniValue());
            }
        }
        else if (checkVal == CVDXF_Data::SignatureDataKey())
        {
            CSignatureData sigData;
            ss >> VARINT(version);
            ss >> COMPACTSIZE(objSize);
            ss >> sigData;
            if (sigData.IsValid())
            {
                objectUni = UniValue(UniValue::VOBJ);
                objectUni.pushKV(EncodeDestination(CIdentityID(checkVal)), sigData.ToUniValue());
            }
        }

        // if we have an object that we recognized, encode it
        if (!objectUni.isNull())
        {
            if (pSuccess)
            {
                *pSuccess = true;
            }
        }
        else
        {
            if (pSuccess)
            {
                *pSuccess = false;
            }
        }
    }
    catch (...)
    {
        if (pSuccess)
        {
            *pSuccess = false;
        }
    }
    return objectUni;
}

UniValue CIdentity::VDXFDataToUniValue(const std::vector<unsigned char> &dataVch)
{
    UniValue entryArr(UniValue::VARR);

    size_t bytesLeft = dataVch.size();
    CDataStream ss(dataVch, SER_NETWORK, PROTOCOL_VERSION);
    while (bytesLeft > sizeof(uint160))
    {
        bool objOut = false;
        UniValue objectUni = VDXFDataToUniValue(ss, &objOut);
        bytesLeft = ss.size();
        if (objOut)
        {
            entryArr.push_back(objectUni);
        }
        else
        {
            // add the remaining data as a hex string
            entryArr.push_back(HexBytes(dataVch.data() + (dataVch.size() - (bytesLeft + sizeof(uint160))), bytesLeft + sizeof(uint160)));
            bytesLeft = 0;
            break;
        }
    }
    if (bytesLeft && bytesLeft <= sizeof(uint160))
    {
        entryArr.push_back(HexBytes(dataVch.data() + (dataVch.size() - bytesLeft), bytesLeft));
    }
    return entryArr.size() == 0 ? UniValue(UniValue::VNULL) : (entryArr.size() == 1 ? entryArr[0] : entryArr);
}

UniValue CIdentity::ToUniValue() const
{
    UniValue obj = ((CPrincipal *)this)->ToUniValue();
    obj.pushKV("name", name);

    obj.pushKV("identityaddress", EncodeDestination(CIdentityID(GetID())));
    obj.pushKV("parent", EncodeDestination(CIdentityID(parent)));
    obj.pushKV("systemid", EncodeDestination(CIdentityID(systemID)));

    UniValue hashes(UniValue::VOBJ);
    for (auto &entry : contentMap)
    {
        hashes.pushKV(entry.first.GetHex(), entry.second.GetHex());
    }
    obj.pushKV("contentmap", hashes);

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
                hashes.pushKV(EncodeDestination(CIdentityID(lastHash)), entryArr);
                entryArr = UniValue(UniValue::VARR);
            }
            lastHash = entry.first;

            UniValue entryUni(UniValue::VOBJ);
            entryUni = VDXFDataToUniValue(entry.second);
            if (!entryUni.isNull())
            {
                if (entryUni.isArray() && entryUni.size() == 1)
                {
                    entryUni = entryUni[0];
                }
                entryArr.push_back(entryUni);
            }
        }
        if (!lastHash.IsNull())
        {
            hashes.pushKV(EncodeDestination(CIdentityID(lastHash)), entryArr);
        }
        obj.pushKV("contentmultimap", hashes);
    }

    obj.pushKV("revocationauthority", EncodeDestination(CTxDestination(CIdentityID(revocationAuthority))));
    obj.pushKV("recoveryauthority", EncodeDestination(CTxDestination(CIdentityID(recoveryAuthority))));
    if (privateAddresses.size())
    {
        obj.pushKV("privateaddress", EncodePaymentAddress(privateAddresses[0]));
    }

    obj.pushKV("timelock", (int32_t)unlockAfter);

    return obj;
}

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
    out.pushKV("type", GetTxnOutputType(type));

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
                    out.pushKV("currencydefinition", definition.ToUniValue());
                }
                else
                {
                    out.pushKV("currencydefinition", "invalid");
                }
                break;
            }

            case EVAL_NOTARY_EVIDENCE:
            {
                CNotaryEvidence evidence;

                if (p.vData.size() && (evidence = CNotaryEvidence(p.vData[0])).IsValid())
                {
                    out.pushKV("notaryevidence", evidence.ToUniValue());
                }
                else
                {
                    out.pushKV("notaryevidence", "invalid");
                }
                break;
            }

            case EVAL_EARNEDNOTARIZATION:
            case EVAL_ACCEPTEDNOTARIZATION:
            {
                CPBaaSNotarization notarization;

                if (p.vData.size() && (notarization = CPBaaSNotarization(p.vData[0])).IsValid())
                {
                    out.pushKV(p.evalCode == EVAL_EARNEDNOTARIZATION ? "earnednotarization" : "acceptednotarization", notarization.ToUniValue());
                }
                else
                {
                    out.pushKV("pbaasnotarization", "invalid");
                }
                break;
            }

            case EVAL_FINALIZE_NOTARIZATION:
            {
                CObjectFinalization finalization;

                if (p.vData.size())
                {
                    finalization = CObjectFinalization(p.vData[0]);
                    out.pushKV("finalizenotarization", finalization.ToUniValue());
                }
                break;
            }

            case EVAL_CURRENCYSTATE:
            {
                CCoinbaseCurrencyState cbcs;

                if (p.vData.size() && (cbcs = CCoinbaseCurrencyState(p.vData[0])).IsValid())
                {
                    out.pushKV("currencystate", cbcs.ToUniValue());
                }
                else
                {
                    out.pushKV("currencystate", "invalid");
                }
                break;
            }

            case EVAL_RESERVE_TRANSFER:
            {
                CReserveTransfer rt;

                if (p.vData.size() && (rt = CReserveTransfer(p.vData[0])).IsValid())
                {
                    out.pushKV("reservetransfer", rt.ToUniValue());
                }
                else
                {
                    out.pushKV("reservetransfer", "invalid");
                }
                break;
            }

            case EVAL_RESERVE_OUTPUT:
            {
                CTokenOutput ro;

                if (p.vData.size() && (ro = CTokenOutput(p.vData[0])).IsValid())
                {
                    out.pushKV("reserveoutput", ro.ToUniValue());
                }
                else
                {
                    out.pushKV("reserveoutput", "invalid");
                }
                break;
            }

            case EVAL_IDENTITY_RESERVATION:
            {
                CNameReservation ar;

                if (p.vData.size() && (ar = CNameReservation(p.vData[0])).IsValid())
                {
                    out.pushKV("identityreservation", ar.ToUniValue());
                }
                else
                {
                    out.pushKV("identityreservation", "invalid");
                }
                break;
            }

            case EVAL_IDENTITY_ADVANCEDRESERVATION:
            {
                CAdvancedNameReservation anr;

                if (p.vData.size() && (anr = CAdvancedNameReservation(p.vData[0])).IsValid())
                {
                    out.pushKV("identityreservation", anr.ToUniValue());
                }
                else
                {
                    out.pushKV("identityreservation", "invalid");
                }
                break;
            }

            case EVAL_RESERVE_DEPOSIT:
            {
                CReserveDeposit rd;

                if (p.vData.size() && (rd = CReserveDeposit(p.vData[0])).IsValid())
                {
                    out.pushKV("reservedeposit", rd.ToUniValue());
                }
                else
                {
                    out.pushKV("reservedeposit", "invalid");
                }
                break;
            }

            case EVAL_CROSSCHAIN_EXPORT:
            {
                CCrossChainExport ccx;

                if (p.vData.size() && (ccx = CCrossChainExport(p.vData[0])).IsValid())
                {
                    out.pushKV("crosschainexport", ccx.ToUniValue());
                }
                else
                {
                    out.pushKV("crosschainexport", "invalid");
                }
                break;
            }

            case EVAL_CROSSCHAIN_IMPORT:
            {
                CCrossChainImport cci;

                if (p.vData.size() && (cci = CCrossChainImport(p.vData[0])).IsValid())
                {
                    out.pushKV("crosschainimport", cci.ToUniValue());
                }
                else
                {
                    out.pushKV("crosschainimport", "invalid");
                }
                break;
            }

            case EVAL_IDENTITY_PRIMARY:
            {
                CIdentity identity;

                if (p.vData.size() && (identity = CIdentity(p.vData[0])).IsValid())
                {
                    out.pushKV("identityprimary", identity.ToUniValue());
                }
                else
                {
                    out.pushKV("identityprimary", "invalid");
                }
                break;
            }

            case EVAL_IDENTITY_REVOKE:
                out.pushKV("identityrevoke", "");
                break;

            case EVAL_IDENTITY_RECOVER:
                out.pushKV("identityrecover", "");
                break;

            case EVAL_IDENTITY_COMMITMENT:
            {
                CCommitmentHash ch;

                if (p.vData.size())
                {
                    ch = CCommitmentHash(p.vData[0]);
                    out.pushKV("commitmenthash", ch.ToUniValue());
                }
                else
                {
                    out.pushKV("commitmenthash", "");
                }
                break;
            }

            case EVAL_STAKEGUARD:
            {
                out.pushKV("stakeguard", "");
                break;
            }

            case EVAL_FINALIZE_EXPORT:
            {
                CObjectFinalization finalization;

                if (p.vData.size())
                {
                    finalization = CObjectFinalization(p.vData[0]);
                    out.pushKV("finalizeexport", finalization.ToUniValue());
                }
                break;
            }

            case EVAL_FEE_POOL:
            {
                CFeePool feePool;

                if (p.vData.size())
                {
                    feePool = CFeePool(p.vData[0]);
                    out.pushKV("feepool", feePool.ToUniValue());
                }
                break;
            }

            default:
                out.pushKV("unknown", "");
        }
    }

    out.pushKV("spendableoutput", scriptPubKey.IsSpendableOutputType());

    if (tokensOut.valueMap.size())
    {
        UniValue reserveBal(UniValue::VOBJ);
        for (auto &oneBalance : tokensOut.valueMap)
        {
            reserveBal.pushKV(ConnectedChains.GetCachedCurrency(oneBalance.first).name, ValueFromAmount(oneBalance.second));
        }
        if (reserveBal.size())
        {
            out.pushKV("reserve_balance", reserveBal);
        }
    }

    if (addresses.size())
    {
        out.pushKV("reqSigs", nRequired);

        UniValue a(UniValue::VARR);
        for (const CTxDestination& addr : addresses) {
            a.push_back(EncodeDestination(addr));
        }
        out.pushKV("addresses", a);
    }

    if (fIncludeAsm)
    {
        out.pushKV("asm", ScriptToAsmStr(scriptPubKey));
    }

    if (fIncludeHex)
    {
        out.pushKV("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end()));
    }
}

UniValue CStakeParams::ToUniValue() const
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", (int64_t)version);
    out.pushKV("sourceheight", (int64_t)srcHeight);
    out.pushKV("height", (int64_t)blkHeight);
    out.pushKV("prevhash", prevHash.GetHex());
    if (delegate.which() != COptCCParams::ADDRTYPE_INVALID)
    {
        out.pushKV("delegate", EncodeDestination(delegate));
    }
    return out;
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

    CStakeParams sp;
    if (tx.IsCoinBase() && GetStakeParams(tx, sp))
    {
        entry.pushKV("stakeparams", sp.ToUniValue());
    }

    if (!hashBlock.IsNull())
        entry.pushKV("blockhash", hashBlock.GetHex());

    entry.pushKV("hex", EncodeHexTx(tx)); // the hex-encoded transaction. used the name "hex" to be consistent with the verbose output of "getrawtransaction".
}
