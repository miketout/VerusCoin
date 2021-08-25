// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <univalue.h>
#include "rpc/protocol.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/identity.h"
#include "rpc/client.h"
#include "util.h"

using namespace std;
extern std::string VERUS_CHAINNAME;

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
};

// DUMMY for compile - only used in server
UniValue RPCCallRoot(const string& strMethod, const UniValue& params, int timeout)
{
    printf("%s: Unable to communicate with specified blockchain network\n", __func__);
    return NullUniValue;
}

bool SetThisChain(const UniValue &chainDefinition) {
    return true; // (?) pbaas/pbaas.h
}

bool uni_get_bool(UniValue uv, bool def)
{
    try
    {
        if (uv.isStr())
        {
            std::string boolStr;
            if ((boolStr = uni_get_str(uv, def ? "true" : "false")) == "true" || boolStr == "1")
            {
                return true;
            }
            else if (boolStr == "false" || boolStr == "0")
            {
                return false;
            }
            return def;
        }
        else if (uv.isNum())
        {
            return uv.get_int() != 0;
        }
        else
        {
            return uv.get_bool();
        }
        return false;
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

int32_t uni_get_int(UniValue uv, int32_t def)
{
    try
    {
        if (uv.isStr())
        {
            return atoi(uv.get_str());
        }
        return uv.get_int();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

int64_t uni_get_int64(UniValue uv, int64_t def)
{
    try
    {
        if (uv.isStr())
        {
            return atoi64(uv.get_str());
        }
        return uv.get_int64();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::string uni_get_str(UniValue uv, std::string def)
{
    try
    {
        return uv.get_str();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::vector<UniValue> uni_getValues(UniValue uv, std::vector<UniValue> def)
{
    try
    {
        return uv.getValues();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

uint160 CCrossChainRPCData::GetConditionID(const uint160 &cid, uint32_t condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 GetConditionID(const uint160 &cid, const uint160 &condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 GetConditionID(const uint160 &cid, const uint160 &condition, const uint256 &txid, int32_t voutNum)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    hw << txid;
    hw << voutNum;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(std::string name, uint32_t condition)
{
    uint160 parent;
    uint160 cid = CIdentity::GetID(name, parent);

    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

std::string TrimLeading(const std::string &Name, unsigned char ch)
{
    std::string nameCopy = Name;
    int removeSpaces;
    for (removeSpaces = 0; removeSpaces < nameCopy.size(); removeSpaces++)
    {
        if (nameCopy[removeSpaces] != ch)
        {
            break;
        }
    }
    if (removeSpaces)
    {
        nameCopy.erase(nameCopy.begin(), nameCopy.begin() + removeSpaces);
    }
    return nameCopy;
}

std::string TrimTrailing(const std::string &Name, unsigned char ch)
{
    std::string nameCopy = Name;
    int removeSpaces;
    for (removeSpaces = nameCopy.size() - 1; removeSpaces >= 0; removeSpaces--)
    {
        if (nameCopy[removeSpaces] != ch)
        {
            break;
        }
    }
    nameCopy.resize(nameCopy.size() - ((nameCopy.size() - 1) - removeSpaces));
    return nameCopy;
}

// this will add the current Verus chain name to subnames if it is not present
// on both id and chain names
std::vector<std::string> ParseSubNames(const std::string &Name, std::string &ChainOut, bool displayfilter, bool addVerus)
{
    std::string nameCopy = Name;
    std::string invalidChars = "\\/:*?\"<>|";
    if (displayfilter)
    {
        invalidChars += "\n\t\r\b\t\v\f\x1B";
    }
    for (int i = 0; i < nameCopy.size(); i++)
    {
        if (invalidChars.find(nameCopy[i]) != std::string::npos)
        {
            return std::vector<std::string>();
        }
    }

    std::vector<std::string> retNames;
    boost::split(retNames, nameCopy, boost::is_any_of("@"));
    if (!retNames.size() || retNames.size() > 2)
    {
        return std::vector<std::string>();
    }

    bool explicitChain = false;
    if (retNames.size() == 2)
    {
        ChainOut = retNames[1];
        explicitChain = true;
    }    

    nameCopy = retNames[0];
    boost::split(retNames, nameCopy, boost::is_any_of("."));

    int numRetNames = retNames.size();

    std::string verusChainName = boost::to_lower_copy(VERUS_CHAINNAME);

    if (addVerus)
    {
        if (explicitChain)
        {
            std::vector<std::string> chainOutNames;
            boost::split(chainOutNames, ChainOut, boost::is_any_of("."));
            std::string lastChainOut = boost::to_lower_copy(chainOutNames.back());
            
            if (lastChainOut != "" && lastChainOut != verusChainName)
            {
                chainOutNames.push_back(verusChainName);
            }
            else if (lastChainOut == "")
            {
                chainOutNames.pop_back();
            }
        }

        std::string lastRetName = boost::to_lower_copy(retNames.back());
        if (lastRetName != "" && lastRetName != verusChainName)
        {
            retNames.push_back(verusChainName);
        }
        else if (lastRetName == "")
        {
            retNames.pop_back();
        }
    }

    for (int i = 0; i < retNames.size(); i++)
    {
        if (retNames[i].size() > KOMODO_ASSETCHAIN_MAXLEN - 1)
        {
            retNames[i] = std::string(retNames[i], 0, (KOMODO_ASSETCHAIN_MAXLEN - 1));
        }
        // spaces are allowed, but no sub-name can have leading or trailing spaces
        if (!retNames[i].size() || retNames[i] != TrimTrailing(TrimLeading(retNames[i], ' '), ' '))
        {
            return std::vector<std::string>();
        }
    }

    return retNames;
}

// takes a multipart name, either complete or partially processed with a Parent hash,
// hash its parent names into a parent ID and return the parent hash and cleaned, single name
// takes a multipart name, either complete or partially processed with a Parent hash,
// hash its parent names into a parent ID and return the parent hash and cleaned, single name
std::string CleanName(const std::string &Name, uint160 &Parent, bool displayfilter, bool addVerus)
{
    std::string chainName;
    std::vector<std::string> subNames = ParseSubNames(Name, chainName, displayfilter, addVerus);

    if (!subNames.size())
    {
        return "";
    }

    if (!Parent.IsNull() &&
        boost::to_lower_copy(subNames.back()) == boost::to_lower_copy(VERUS_CHAINNAME))
    {
        subNames.pop_back();
    }

    for (int i = subNames.size() - 1; i > 0; i--)
    {
        std::string parentNameStr = boost::algorithm::to_lower_copy(subNames[i]);
        const char *parentName = parentNameStr.c_str();
        uint256 idHash;

        if (Parent.IsNull())
        {
            idHash = Hash(parentName, parentName + parentNameStr.size());
        }
        else
        {
            idHash = Hash(parentName, parentName + strlen(parentName));
            idHash = Hash(Parent.begin(), Parent.end(), idHash.begin(), idHash.end());
        }
        Parent = Hash160(idHash.begin(), idHash.end());
        //printf("uint160 for parent %s: %s\n", parentName, Parent.GetHex().c_str());
    }
    return subNames[0];
}

UniValue CNodeData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("networkaddress", networkAddress));
    obj.push_back(Pair("nodeidentity", ""));
    return obj;
}

CNodeData::CNodeData(std::string netAddr, std::string paymentAddr) :
    networkAddress(netAddr)
{
}

CIdentityID CIdentity::GetID(const std::string &Name, uint160 &parent)
{
    std::string cleanName = CleanName(Name, parent);
    if (cleanName.empty())
    {
        return uint160();
    }

    std::string subName = boost::algorithm::to_lower_copy(cleanName);
    const char *idName = subName.c_str();
    //printf("hashing: %s, %s\n", idName, parent.GetHex().c_str());

    uint256 idHash;
    if (parent.IsNull())
    {
        idHash = Hash(idName, idName + strlen(idName));
    }
    else
    {
        idHash = Hash(idName, idName + strlen(idName));
        idHash = Hash(parent.begin(), parent.end(), idHash.begin(), idHash.end());

    }
    return Hash160(idHash.begin(), idHash.end());
}

CIdentityID CIdentity::GetID(const std::string &Name) const
{
    uint160 parent;
    std::string cleanName = CleanName(Name, parent);

    std::string subName = boost::algorithm::to_lower_copy(cleanName);
    const char *idName = subName.c_str();
    //printf("hashing: %s, %s\n", idName, parent.GetHex().c_str());

    uint256 idHash;
    if (parent.IsNull())
    {
        idHash = Hash(idName, idName + strlen(idName));
    }
    else
    {
        idHash = Hash(idName, idName + strlen(idName));
        idHash = Hash(parent.begin(), parent.end(), idHash.begin(), idHash.end());

    }
    return Hash160(idHash.begin(), idHash.end());
}

CIdentityID CIdentity::GetID() const
{
    return GetID(name);
}

uint160 CCrossChainRPCData::GetID(std::string name)
{
    uint160 parent;
    return CIdentity::GetID(name,parent);
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

static const CRPCConvertParam vRPCConvertParams[] =
{
    { "stop", 0 },
    { "setmocktime", 0 },
    { "getaddednodeinfo", 0 },
    { "setgenerate", 0 },
    { "setgenerate", 1 },
    { "generate", 0 },
    { "getnetworkhashps", 0 },
    { "getnetworkhashps", 1 },
    { "getnetworksolps", 0 },
    { "getnetworksolps", 1 },
    { "sendtoaddress", 1 },
    { "sendtoaddress", 4 },
    { "settxfee", 0 },
    { "getreceivedbyaddress", 1 },
    { "getreceivedbyaccount", 1 },
    { "listreceivedbyaddress", 0 },
    { "listreceivedbyaddress", 1 },
    { "listreceivedbyaddress", 2 },
    { "listreceivedbyaccount", 0 },
    { "listreceivedbyaccount", 1 },
    { "listreceivedbyaccount", 2 },
    { "getbalance", 1 },
    { "getbalance", 2 },
    { "getcurrencybalance", 1},
    { "getcurrencybalance", 2},
    { "getblockhash", 0 },
    { "move", 2 },
    { "move", 3 },
    { "sendfrom", 2 },
    { "sendfrom", 3 },
    { "listtransactions", 1 },
    { "listtransactions", 2 },
    { "listtransactions", 3 },
    { "listaccounts", 0 },
    { "listaccounts", 1 },
    { "walletpassphrase", 1 },
    { "getblocktemplate", 0 },
    { "listsinceblock", 1 },
    { "listsinceblock", 2 },
    { "sendmany", 1 },
    { "sendmany", 2 },
    { "sendmany", 4 },
    { "addmultisigaddress", 0 },
    { "addmultisigaddress", 1 },
    { "createmultisig", 0 },
    { "createmultisig", 1 },
    { "listunspent", 0 },
    { "listunspent", 1 },
    { "listunspent", 2 },
    { "getblock", 1 },
    { "getblockheader", 1 },
    { "gettransaction", 1 },
    { "getrawtransaction", 1 },
    { "createrawtransaction", 0 },
    { "createrawtransaction", 1 },
    { "createrawtransaction", 2 },
    { "createrawtransaction", 3 },
    { "signrawtransaction", 1 },
    { "signrawtransaction", 2 },
    { "sendrawtransaction", 1 },
    { "fundrawtransaction", 1 },
    { "gettxout", 1 },
    { "gettxout", 2 },
    { "gettxoutproof", 0 },
    { "lockunspent", 0 },
    { "lockunspent", 1 },
    { "importprivkey", 2 },
    { "importaddress", 2 },
    { "verifychain", 0 },
    { "verifychain", 1 },
    { "keypoolrefill", 0 },
    { "getrawmempool", 0 },
    { "estimatefee", 0 },
    { "estimatepriority", 0 },
    { "prioritisetransaction", 1 },
    { "prioritisetransaction", 2 },
    { "setban", 2 },
    { "setban", 3 },
    { "getspentinfo", 0},
    { "getaddresstxids", 0},
    { "getaddressbalance", 0},
    { "getaddressdeltas", 0},
    { "getaddressutxos", 0},
    { "getaddressmempool", 0},
    { "getblockhashes", 0},
    { "getblockhashes", 1},
    { "getblockhashes", 2},
    { "getblockdeltas", 0},
    { "zcrawjoinsplit", 1 },
    { "zcrawjoinsplit", 2 },
    { "zcrawjoinsplit", 3 },
    { "zcrawjoinsplit", 4 },
    { "zcbenchmark", 1 },
    { "zcbenchmark", 2 },
    { "getblocksubsidy", 0},
    { "z_listaddresses", 0},
    { "z_listreceivedbyaddress", 1},
    { "z_listunspent", 0 },
    { "z_listunspent", 1 },
    { "z_listunspent", 2 },
    { "z_listunspent", 3 },
    { "z_getbalance", 1},
    { "z_gettotalbalance", 0},
    { "z_gettotalbalance", 1},
    { "z_gettotalbalance", 2},
    { "z_mergetoaddress", 0},
    { "z_mergetoaddress", 2},
    { "z_mergetoaddress", 3},
    { "z_mergetoaddress", 4},
    { "z_sendmany", 1},
    { "z_sendmany", 2},
    { "z_sendmany", 3},
    { "z_shieldcoinbase", 2},
    { "z_shieldcoinbase", 3},
    { "z_getoperationstatus", 0},
    { "z_getoperationresult", 0},
    { "z_importkey", 1 },
    { "paxprice", 4 },
    { "paxprices", 3 },
    { "paxpending", 0 },
    { "notaries", 2 },
    { "minerids", 1 },
    { "kvsearch", 1 },
    { "kvupdate", 4 },
    { "z_importkey", 2 },
    { "z_importviewingkey", 2 },
    { "z_getpaymentdisclosure", 1},
    { "z_getpaymentdisclosure", 2},
    // crosschain
    { "assetchainproof", 1},
    { "crosschainproof", 1},
    { "getbestproofroot", 0},
    { "submitacceptednotarization", 0},
    { "submitimports", 0},
    { "height_MoM", 1},
    { "calc_MoM", 2},
    // pbaas
    { "definecurrency", 0},
    { "definecurrency", 1},
    { "definecurrency", 2},
    { "definecurrency", 3},
    { "definecurrency", 4},
    { "definecurrency", 5},
    { "definecurrency", 6},
    { "definecurrency", 7},
    { "definecurrency", 8},
    { "definecurrency", 9},
    { "definecurrency", 10},
    { "definecurrency", 11},
    { "definecurrency", 12},
    { "definecurrency", 13},
    { "listcurrencies", 0},
    { "listcurrencies", 1},
    { "sendcurrency", 1},
    { "registeridentity", 0},
    { "updateidentity", 0},
    { "recoveridentity", 0},
    // Zcash addition
    { "z_setmigration", 0},
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int> > members;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw runtime_error(string("Error JSON:")+strVal);
    return jVal[0];
}

/** Convert strings to command-specific RPC representation */
UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];
        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}
