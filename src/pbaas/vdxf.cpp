/********************************************************************
 * (C) 2020 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Support for the Verus Data Exchange Format (VDXF)
 *
 */

#include "vdxf.h"
#include "crosschainrpc.h"
#include "utf8.h"
#include "util.h"

std::string CVDXF::DATA_KEY_SEPARATOR = "::";

uint160 CVDXF::STRUCTURED_DATA_KEY = CVDXF_StructuredData::StructuredDataKey();
uint160 CVDXF::ZMEMO_MESSAGE_KEY = CVDXF_Data::ZMemoMessageKey();
uint160 CVDXF::ZMEMO_SIGNATURE_KEY = CVDXF_Data::ZMemoSignatureKey();

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

std::string TrimSpaces(const std::string &Name, bool removeDuals, const std::string &_invalidChars)
{
    std::string invalidChars = _invalidChars;
    if (removeDuals)
    {
        invalidChars += "\n\t\r\b\t\v\f\x1B";
    }
    if (utf8valid(Name.c_str()) != 0)
    {
        return "";
    }
    std::string noDuals = removeDuals ?
        std::string(u8"\u0020\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u200C\u200D\u202F\u205F\u3000") :
        " ";
    std::vector<int> allDuals;
    std::vector<int> toRemove;

    int len = utf8len(Name.c_str());
    const char *nextChar = Name.c_str();
    for (int i = 0; i < len; i++)
    {
        utf8_int32_t outPoint;
        utf8_int32_t invalidPoint;
        nextChar = utf8codepoint(nextChar, &outPoint);

        if (utf8chr(invalidChars.c_str(), outPoint))
        {
            toRemove.push_back(i);
            allDuals.push_back(i);
            continue;
        }

        char *dualCharPos = utf8chr(noDuals.c_str(), outPoint);

        if ((removeDuals ||
             (i == allDuals.size() ||
              i == (len - 1))) &&
             dualCharPos)
        {
            bool wasLastDual = allDuals.size() && allDuals.back() == (i - 1);
            if (i == allDuals.size() ||
                i == (len - 1) ||
                (removeDuals && wasLastDual))
            {
                toRemove.push_back(i);
            }
            allDuals.push_back(i);
            if (i &&
                i == (Name.size() - 1) &&
                wasLastDual)
            {
                int toRemoveIdx = toRemove.size() - 1;
                int nextDual = 0;
                for (auto dualIt = allDuals.rbegin(); dualIt != allDuals.rend(); dualIt++)
                {
                    if (nextDual && *dualIt != (nextDual - 1))
                    {
                        break;
                    }
                    if (toRemoveIdx < 0 || toRemove[toRemoveIdx] != *dualIt)
                    {
                        toRemove.insert(toRemove.begin() + ++toRemoveIdx, *dualIt);
                    }
                    toRemoveIdx--;
                }
            }
        }
    }

    // now, reconstruct the string char by char, but skip the ones to remove
    if (toRemove.size())
    {
        std::string nameCopy;
        int toRemoveIdx = 0;

        nextChar = Name.c_str();
        for (int i = 0; i < len; i++)
        {
            utf8_int32_t outPoint;
            nextChar = utf8codepoint(nextChar, &outPoint);

            if (toRemoveIdx < toRemove.size() && i++ == toRemove[toRemoveIdx])
            {
                toRemoveIdx++;
                continue;
            }
            char tmpCodePointStr[5] = {0};
            if (!utf8catcodepoint(tmpCodePointStr, outPoint, 5))
            {
                LogPrintf("%s: Invalid name string: %s\n", __func__, Name.c_str());
            }
            nameCopy += std::string(tmpCodePointStr);
        }
        return nameCopy;
    }
    else
    {
        return Name;
    }
}

bool CVDXF::HasExplicitParent(const std::string &Name)
{
    std::string ChainOut;
    bool hasExplicitParent = false;

    std::string nameCopy = Name;

    std::vector<std::string> retNames;
    boost::split(retNames, nameCopy, boost::is_any_of("@"));
    if (!retNames.size() || retNames.size() > 2)
    {
        return false;
    }

    nameCopy = retNames[0];
    boost::split(retNames, nameCopy, boost::is_any_of("."));

    if (retNames.size() && retNames.back().empty())
    {
        return true;
    }
    return false;
}

// this will add the current Verus chain name to subnames if it is not present
// on both id and chain names
std::vector<std::string> CVDXF::ParseSubNames(const std::string &Name, std::string &ChainOut, bool displayfilter, bool addVerus)
{
    std::string nameCopy = Name;

    std::vector<std::string> retNames;
    boost::split(retNames, nameCopy, boost::is_any_of("@"));
    if (!retNames.size() || retNames.size() > 2 || (retNames.size() > 1 && TrimSpaces(retNames[1]) != retNames[1]))
    {
        return std::vector<std::string>();
    }

    bool explicitChain = false;
    if (retNames.size() == 2 && !retNames[1].empty())
    {
        ChainOut = retNames[1];
        explicitChain = true;
    }

    nameCopy = retNames[0];
    boost::split(retNames, nameCopy, boost::is_any_of("."));

    if (retNames.size() && retNames.back().empty())
    {
        addVerus = false;
        retNames.pop_back();
        nameCopy.pop_back();
    }

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
        if (!retNames[i].size() || retNames[i] != TrimSpaces(retNames[i], displayfilter))
        {
            return std::vector<std::string>();
        }
    }
    return retNames;
}

// takes a multipart name, either complete or partially processed with a Parent hash,
// hash its parent names into a parent ID and return the parent hash and cleaned, single name
std::string CVDXF::CleanName(const std::string &Name, uint160 &Parent, bool displayfilter)
{
    std::string chainName;
    std::vector<std::string> subNames = ParseSubNames(Name, chainName, displayfilter);

    if (!subNames.size())
    {
        return "";
    }

    if (!Parent.IsNull() &&
        subNames.size() > 1 &&
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

uint160 CVDXF::GetID(const std::string &Name)
{
    uint160 parent;
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

uint160 CVDXF::GetID(const std::string &Name, uint160 &parent)
{
    std::string cleanName;
    cleanName = Name == DATA_KEY_SEPARATOR ? Name : CleanName(Name, parent);

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

// calculate the data key for a name inside of a namespace
// if the namespace is null, use VERUS_CHAINID
uint160 CVDXF::GetDataKey(const std::string &keyName, uint160 &nameSpaceID)
{
    std::string keyCopy = keyName;
    std::vector<std::string> addressParts;
    boost::split(addressParts, keyCopy, boost::is_any_of(":"));

    // if the first part of the address is a namespace, it is followed by a double colon
    // namespace specifiers have no implicit root
    if (addressParts.size() > 2 && addressParts[1].empty())
    {
        uint160 nsID = DecodeCurrencyName(addressParts[0].back() == '.' ? addressParts[0] : addressParts[0] + ".");

        if (!nsID.IsNull())
        {
            nameSpaceID = nsID;
        }
        keyCopy.clear();
        for (int i = 2; i < addressParts.size(); i++)
        {
            keyCopy = i == 2 ? addressParts[i] : keyCopy + ":" + addressParts[i];
        }
    }

    if (nameSpaceID.IsNull())
    {
        nameSpaceID = VERUS_CHAINID;
    }
    uint160 parent = GetID(DATA_KEY_SEPARATOR, nameSpaceID);
    return GetID(keyCopy, parent);
}

bool uni_get_bool(const UniValue &uv, bool def)
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

int32_t uni_get_int(const UniValue &uv, int32_t def)
{
    try
    {
        if (!uv.isStr() && !uv.isNum())
        {
            return def;
        }
        return (uv.isStr() ? atoi(uv.get_str()) : atoi(uv.getValStr()));
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

int64_t uni_get_int64(const UniValue &uv, int64_t def)
{
    try
    {
        if (!uv.isStr() && !uv.isNum())
        {
            return def;
        }
        return (uv.isStr() ? atoi64(uv.get_str()) : atoi64(uv.getValStr()));
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::string uni_get_str(const UniValue &uv, std::string def)
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

std::vector<UniValue> uni_getValues(const UniValue &uv, std::vector<UniValue> def)
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

// this deserializes a vector into either a VDXF data object or a VDXF structured
// object, which may contain one or more VDXF data objects.
// If the data in the sourceVector is not a recognized VDXF object, the returned
// variant will be empty/invalid, otherwise, it will be a recognized VDXF object
// or a VDXF structured object containing one or more recognized VDXF objects.
VDXFData DeserializeVDXFData(const std::vector<unsigned char> &sourceVector)
{
    CVDXF_StructuredData sData;
    ::FromVector(sourceVector, sData);
    if (sData.IsValid())
    {
        return sData;
    }
    else
    {
        CVDXF_Data Data;
        ::FromVector(sourceVector, Data);
        if (Data.IsValid())
        {
            return Data;
        }
    }
    return VDXFData();
}

std::vector<unsigned char> SerializeVDXFData(const VDXFData &vdxfData)
{
    return boost::apply_visitor(CSerializeVDXFData(), vdxfData);
}

