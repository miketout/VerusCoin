/********************************************************************
 * (C) 2020 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * The Verus Data Exchange Format provides a fully interoperable system
 * for defining data types that may consist of structured or or unstructured
 * data and associated content or keys that may be used to retrieve such
 * data from centralized or decentralized storage for use in and across
 * centralized or decentralized applications.
 * 
 * Overview
 * Verus Data Exchange Format enables application developers to define globally unique
 * data types and publish references to the same, which may refer to structured or 
 * unstructured data that can be located unambiguously via an URL, which implicitly 
 * provides both location and decoding information, enabling applications to use such 
 * data, in whole or in part, if they know how, or even ignore parts of the data, while
 * remaining compatible with those parts they understand. VDXF typee keys are globally 
 * unique identifiers, which are defined as human readable names along with a 
 * specification of how to define and convert unlimited length, human readable type 
 * names into collison-free 20 byte IDs, which can be used as type keys associated with
 * content or location values in various forms of data records. These data records, 
 * which may have application specific structures or no structure at all, besides 
 * length form the basis of an interoperable data exchange format across decentralized
 * applications.
 * 
 * Definition of VDXF types
 * VDXF is not a strongly opinionated or highly specified type description 
 * specification, and, instead, focuses on a model for recognizing an unlimited
 * number of user defined data types, using a standard human readable format for 
 * definition and encoding of the type specifier, which is hashed, using the VDXF
 * specification and standard methodology, to produce collision-free, 20 byte keys,
 * which can be associated with retrieveable content hashes and location qualifiers
 * that enable applications to locate, recognize types of, parse, and decode any form
 * of application or system specific data. VDXF specifies some basic type formats, as
 * necessary to enable initial applications, but leaves further specifications of
 * applicaiton specific data formats, of which there may be an unlimited number, as an
 * open-ended option for those needing new data type definitions for efficient
 * application development. It is recommended that new fundamental data types not be
 * defined unless necessary, but adherence to such recommendation is not enforced at
 * the consensus protocol layer.
 * 
 * Namespace for Type Definitions - VerusID
 * Namespaces for type definitions are equivalent to VerusIDs, a protocol first
 * implemented on the Verus Blockchain, and also one that can support IDs registered
 * on any blockchain or uniquely named system that becomes recognized via a consensus-
 * based bridge on the Verus network. Currently, to be recognized as a unique 
 * namespace, the easiest way is to base it on a VerusID, registered on the Verus 
 * blockchain network. While there is not a defined way of creating bridges to other
 * external networks, there is work on an Ethereum bridge in progress, and this will
 * detail the naming mechanism of an externally bridged system and how it deals with
 * naming conventions for VDXF interoperability, if not the technical details of how
 * to register and implement such a bridge.
 * 
 * Generally, one may think of two types of VerusIDs, those defined on the Verus
 * network or on independent PBaaS (Public Blockchains as a Service) blockchains
 * spawned originally from and registered on the Verus blockchain network, or
 * VerusIDs, which may also exist on fully external systems that may have been
 * created without any registration on the Verus network initially. In order for an
 * externally created VerusID to be recognizable on the Verus blockchain network or
 * by applications using the VDXF that are compatible with the Verus blockchain
 * network that external system must provide a recognized bridge to the Verus
 * blockchain. At present, the first such bridge, expected to be available along
 * with or shortly after the Verus DeFi network release, is the Ethereum blockchain
 * bridge, which will be used as the example of an externally recognized VerusID
 * system for the purpose of this explanation.
 * 
 * First, it is important to understand the requirements of registered VerusID
 * identity names, which will also inform how externally generated VerusIDs are
 * recognized as well. For the purposes of the VDXF, we do not require 
 * compatibility of the internal structure of IDs across different systems, and
 * only define compatibility requirements of the naming systems and how those
 * names translate into recognizeable IDs on the Verus network.
 * 
 * VerusID names all have some components in common. These components are:
 * 1. "name": This is the friendly name associated with the specific VerusID.
 *    As of this writing, name may consist of any unicode characters, with the 
 *    exception of the following, disallowed characters:
 *      \ / : * ? " < > |
 *      leading and trailing spaces
 * 
 *    In addition, there are further display limitations and expected display
 *    restrictions and also name restrictions expected in a future consensus
 *    change that are currently listed as "not recommended". Characters that are
 *    display restricted include:
 *      "\n\t\r\b\t\v\f\x1B"
 * 
 *    Those currently not recommended include:
 *      More than one consecutive space internally to a name
 *      Tab characters
 *      Blank unicode characters
 * 
 *    Although both upper and lower case names are allowed in VerusIDs, when
 *    using VerusIDs for lookup, duplication prevention, or namespace usage, 
 *    only the global character set latin lowercase characters are used for
 *    all upper and lowercase characters.
 * 
 * 2. "name" can be combined in various ways to provide different elements that
 *    may be used in the VDXF. In each case, a name follows the same pattern
 *    as the name of a VerusID, but is combined with specific separators for
 *    unambiguous URL references, with defaults for simplicity. Here are some
 *    examples of the names that may be used as URLs:
 * 
 *         verus://idname.vrsc@/namespaceid::keyname/contentprotocol/qualifier1/qualifier2/
 * 
 *          This is a way to refer to values that may be substituted for 
 *          information located through idname.vrsc@exportedchain.vrsc.
 *          According to the VerusID specification, the suffix ".vrsc" is 
 *          default, if not specified, and can be circumvented by terminating
 *          with a ".", when referring to non-vrsc systems that are supported
 *          in the vrsc network.
 * 
 *          In addition, the vrsc namespace defines a set of key
 *          names that provide basic, system level data structure definitions,
 *          such as claim.health.covid and claim.id.passport.firstname, etc.
 * 
 *          If no namespace is specified, the vrsc namespace is assumed.
 *          That means that an equivalent URL using keys in the vrsc namespace
 *          and leaving out defaults for brevity would be:
 * 
 *         verus://idname@/keyname/contentprotocol/qualifier1/qualifier2
 * 
 *          qualifier1 and qualifier2 are optional specifiers that are 
 *          specific to the type of key, may include sub-storage information,
 *          and follow the distributed storage system used for content.
 *          The default storage system used is ipfs, and default does not have
 *          to be specified, as long as there are not sub-storage qualifiers.
 * 
 *          Finally, the default keyname, if not specified, is vrsc::index, 
 *          which is used as a homepage for an ID. That means that a default 
 *          homepage or ID profile can be specified as simply as:
 * 
 *         verus://idname@
 * 
 *          As a result of this specification, published data types and
 *          structures, which may include alternate location and qualifier
 *          defaults, have no definitive length limit, and are hashed into
 *          a globally unique, 20 byte identifier, which shall be found in
 *          any ID specified in the "idname@". The 32 byte value of that
 *          keyed content is considered the initial locator, using the 
 *          default contentprotocol, defined by the specified keyname.
 *          As a result, the URL, verus://idname@, defines a content
 *          address to an HTML, index data structure for the specified ID, 
 *          which shall be located in IPFS storage.
 * 
 * The specifics of the above details have yet to be finalized, but this is
 * the general model, subject to modification and update before the V1 release,
 * which is expected to be released along with the first mainnet release of
 * Verus DeFi.
 */

#ifndef VDXF_H
#define VDXF_H

#include "mmr.h"
#include <boost/algorithm/string.hpp>

extern std::string VERUS_CHAINNAME;
extern uint160 VERUS_CHAINID;

template <typename SERIALIZABLE>
std::vector<unsigned char> AsVector(const SERIALIZABLE &obj)
{
    CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
    s << obj;
    return std::vector<unsigned char>(s.begin(), s.end());
}

template <typename SERIALIZABLE>
void FromVector(const std::vector<unsigned char> &vch, SERIALIZABLE &obj, bool *pSuccess=nullptr)
{
    CDataStream s(vch, SER_NETWORK, PROTOCOL_VERSION);
    if (pSuccess)
    {
        *pSuccess = false;
    }
    try
    {
        obj.Unserialize(s);
        if (pSuccess)
        {
            *pSuccess = true;
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

class CVDXF
{
public:
    static uint160 STRUCTURED_DATA_KEY;
    static uint160 ZMEMO_MESSAGE_KEY;
    static uint160 ZMEMO_SIGNATURE_KEY;

    enum
    {
        VERSION_INVALID = 0,
        FIRST_VERSION = 1,
        LAST_VERSION = 1,
        DEFAULT_VERSION = 1,
        VDXF_NONE = 0,              // variant value for empty
        VDXF_DATA = 1,              // variant value for data
        VDXF_STRUCTURED_DATA = 2    // variant value for structured data
    };
    uint160 key;
    uint32_t version;

    CVDXF(uint32_t Version=0) : version(Version) {}
    CVDXF(const uint160 &Key, uint32_t Version=DEFAULT_VERSION) : key(Key), version(Version) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(key);
        READWRITE(VARINT(version));
    }

    static std::string DATA_KEY_SEPARATOR;
    static std::vector<std::string> ParseSubNames(const std::string &Name, std::string &ChainOut, bool displayfilter=false, bool addVerus=true);
    static std::string CleanName(const std::string &Name, uint160 &Parent, bool displayapproved=false);
    static uint160 GetID(const std::string &Name);
    static uint160 GetID(const std::string &Name, uint160 &parent);
    static uint160 GetDataKey(const std::string &keyName, uint160 &nameSpaceID);
    bool IsValid()
    {
        return !key.IsNull() && version >= FIRST_VERSION && version <= LAST_VERSION;
    }
};

class CVDXF_Data : public CVDXF
{
public:
    std::vector<unsigned char> data;

    CVDXF_Data(uint32_t Version=DEFAULT_VERSION) : CVDXF(Version) {}
    CVDXF_Data(const uint160 &Key, const std::vector<unsigned char> &Data, uint32_t Version=DEFAULT_VERSION) : CVDXF(Key, Version), data(Data) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CVDXF *)this);
        if (IsValid())
        {
            READWRITE(data);
        }
    }
    static std::string ZMemoMessageKeyName()
    {
        return "vrsc::system.zmemo.message";
    }
    static uint160 ZMemoMessageKey()
    {
        static uint160 nameSpace;
        static uint160 memoMessageKey = GetDataKey(ZMemoMessageKeyName(), nameSpace);
        return memoMessageKey;
    }
    static std::string ZMemoSignatureKeyName()
    {
        return "vrsc::system.zmemo.signature";
    }
    static uint160 ZMemoSignatureKey()
    {
        static uint160 nameSpace;
        static uint160 memoSigKey = GetDataKey(ZMemoSignatureKeyName(), nameSpace);
        return memoSigKey;
    }
    static std::string CurrencyStartNotarizationKeyName()
    {
        return "vrsc::system.currency.startnotarization";
    }
    static uint160 CurrencyStartNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 currencyStartNotarization = GetDataKey(CurrencyStartNotarizationKeyName(), nameSpace);
        return currencyStartNotarization;
    }
    bool IsValid()
    {
        return CVDXF::IsValid();
    }
};

class CVDXF_StructuredData : public CVDXF
{
public:
    std::vector<std::vector<unsigned char>> data;

    CVDXF_StructuredData(uint32_t Version=DEFAULT_VERSION) : CVDXF(Version) {}
    CVDXF_StructuredData(const uint160 &Key, 
                         const std::vector<std::vector<unsigned char>> &Data, 
                         uint32_t Version=DEFAULT_VERSION) : CVDXF(Key, Version), data(Data) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CVDXF *)this);
        if (key == STRUCTURED_DATA_KEY)
        {
            version = VERSION_INVALID;
        }
        else
        {
            READWRITE(data);
        }
    }
    static std::string StructuredDataKeyName()
    {
        return "vrsc::system.structureddata";
    }
    static uint160 StructuredDataKey()
    {
        static uint160 nameSpace;
        static uint160 structuredDataKey = GetDataKey(StructuredDataKeyName(), nameSpace);
        return structuredDataKey;
    }
    bool IsValid()
    {
        // structured data must have at least enough space for 1 element
        if (CVDXF::IsValid() && data.size())
        {
            // ensure that all vectors are either valid, known types or possibly
            // valid, unknown types
            for (auto &oneVec : data)
            {
                
            }
        }
        return false;
    }
};

class CVDXF_NoData {
public:
    friend bool operator==(const CVDXF_NoData &a, const CVDXF_NoData &b) { return true; }
    friend bool operator<(const CVDXF_NoData &a, const CVDXF_NoData &b) { return true; }
};

typedef boost::variant<CVDXF_NoData, CVDXF_StructuredData, CVDXF_Data> VDXFData;

class CSerializeVDXFData : public boost::static_visitor<std::vector<unsigned char>>
{
public:
    CSerializeVDXFData() {}

    std::vector<unsigned char> operator()(const CVDXF_StructuredData& sData) const
    {
        return ::AsVector(sData);
    }

    std::vector<unsigned char> operator()(const CVDXF_Data& Data) const
    {
        return ::AsVector(Data);
    }

    std::vector<unsigned char> operator()(const CVDXF_NoData& NoData) const
    {
        return std::vector<unsigned char>();
    }
};

// standard name parsing functions
std::string TrimLeading(const std::string &Name, unsigned char ch);
std::string TrimTrailing(const std::string &Name, unsigned char ch);
std::string TrimSpaces(const std::string &Name);

// this deserializes a vector into either a VDXF data object or a VDXF structured
// object, which may contain one or more VDXF data objects.
// If the data in the sourceVector is not a recognized VDXF object, the returned
// variant will be empty/invalid, otherwise, it will be a recognized VDXF object
// or a VDXF structured object containing one or more recognized VDXF objects.
VDXFData DeserializeVDXFData(const std::vector<unsigned char> &sourceVector);
std::vector<unsigned char> SerializeVDXFData(const VDXFData &vdxfData);

bool uni_get_bool(UniValue uv, bool def=false);
int32_t uni_get_int(UniValue uv, int32_t def=0);
int64_t uni_get_int64(UniValue uv, int64_t def =0);
std::string uni_get_str(UniValue uv, std::string def="");
std::vector<UniValue> uni_getValues(UniValue uv, std::vector<UniValue> def=std::vector<UniValue>());

#endif // VDXF_H
