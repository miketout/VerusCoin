/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS cross chain communication.
 * 
 * In merge mining and notarization, Verus acts as a hub that other PBaaS chains
 * call via RPC in order to get information that allows earning and submitting
 * notarizations.
 * 
 * All PBaaS chains communicate with their primary reserve chain, which is either Verus
 * or the chain that is their reserve coin. The child PBaaS chain initiates all of
 * the communication with the parent / reserve daemon.
 * 
 * Generally, the PBaaS chain will call the Verus chain to either get information needed
 * to create an earned or accepted notarization. If there is no Verus daemon available
 * staking and mining of a PBaaS chain proceeds as usual, but without notarization
 * reward opportunities.
 * 
 */

#include "chainparamsbase.h"
#include "clientversion.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/filesystem/operations.hpp>
#include <boost/format.hpp>
#include <stdio.h>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include "support/events.h"

#include <univalue.h>

#include "uint256.h"
#include "hash.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/identity.h"

using namespace std;

extern string PBAAS_HOST;
extern string PBAAS_USERPASS;
extern int32_t PBAAS_PORT;
extern std::string VERUS_CHAINNAME;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
};

const char *http_errorstring(int code)
{
    switch(code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

static CCrossChainRPCData LoadFromConfig(std::string name)
{
    map<string, string> settings;
    map<string, vector<string>> settingsmulti;
    CCrossChainRPCData ret;

    // if we are requested to automatically load the information from the Verus chain, do it if we can find the daemon
    if (ReadConfigFile(name, settings, settingsmulti))
    {
        auto rpcuser = settings.find("-rpcuser");
        auto rpcpwd = settings.find("-rpcpassword");
        auto rpcport = settings.find("-rpcport");
        auto rpchost = settings.find("-rpchost");
        ret.credentials = rpcuser != settings.end() ? rpcuser->second + ":" : "";
        ret.credentials += rpcpwd != settings.end() ? rpcpwd->second : "";
        ret.port = rpcport != settings.end() ? atoi(rpcport->second) : (name == "VRSC" ? 27486 : 0);
        ret.host = rpchost != settings.end() ? rpchost->second : "127.0.0.1";
    }
    return ret;
}

// credentials for now are "user:password"
UniValue RPCCall(const string& strMethod, const UniValue& params, const string credentials, int port, const string host, int timeout)
{
    // Used for inter-daemon communicatoin to enable merge mining and notarization without a client
    //

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), timeout);

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(credentials)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequest(strMethod, params, 1);
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, "/");
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

UniValue RPCCallRoot(const string& strMethod, const UniValue& params, int timeout)
{
    string host, credentials;
    int port;
    map<string, string> settings;
    map<string, vector<string>> settingsmulti;

    if (PBAAS_HOST != "" && PBAAS_PORT != 0)
    {
        return RPCCall(strMethod, params, PBAAS_USERPASS, PBAAS_PORT, PBAAS_HOST);
    }
    else if (_IsVerusActive() &&
             ReadConfigFile("veth", settings, settingsmulti))
    {
        // the Ethereum bridge, "VETH", serves as the root currency to VRSC and for Rinkeby to VRSCTEST
        PBAAS_USERPASS = settingsmulti.find("-rpcuser")->second[0] + ":" + settingsmulti.find("-rpcpassword")->second[0];
        PBAAS_PORT = atoi(settingsmulti.find("-rpcport")->second[0]);
        PBAAS_HOST = settingsmulti.find("-rpchost")->second[0];
        if (!PBAAS_HOST.size())
        {
            PBAAS_HOST = "127.0.0.1";
        }
        return RPCCall(strMethod, params, credentials, port, host, timeout);
    }
    else if (ReadConfigFile(PBAAS_TESTMODE ? "vrsctest" : "VRSC", settings, settingsmulti))
    {
        PBAAS_USERPASS = settingsmulti.find("-rpcuser")->second[0] + ":" + settingsmulti.find("-rpcpassword")->second[0];
        PBAAS_PORT = atoi(settingsmulti.find("-rpcport")->second[0]);
        PBAAS_HOST = settingsmulti.find("-rpchost")->second[0];
        if (!PBAAS_HOST.size())
        {
            PBAAS_HOST = "127.0.0.1";
        }
        return RPCCall(strMethod, params, credentials, port, host, timeout);
    }
    return UniValue(UniValue::VNULL);
}

UniValue CCrossChainRPCData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("host", host));
    obj.push_back(Pair("port", port));
    obj.push_back(Pair("credentials", credentials));
    return obj;
}

CNodeData::CNodeData(const UniValue &obj)
{
    networkAddress = uni_get_str(find_value(obj, "networkaddress"));
    CTxDestination dest = DecodeDestination(uni_get_str(find_value(obj, "nodeidentity")));
    if (dest.which() != COptCCParams::ADDRTYPE_ID)
    {
        nodeIdentity = uint160();
    }
    else
    {
        nodeIdentity = GetDestinationID(dest);
    }
}

CNodeData::CNodeData(std::string netAddr, std::string paymentAddr) :
    networkAddress(netAddr)
{
    nodeIdentity = GetDestinationID(DecodeDestination(paymentAddr));
}

CIdentitySignature::CIdentitySignature(const UniValue &uni)
{
    try
    {
        version = uni_get_int(find_value(uni, "version"));
        blockHeight = uni_get_int64(find_value(uni, "blockheight"));
        UniValue sigs = find_value(uni, "signatures");
        if (sigs.isArray() && sigs.size())
        {
            for (int i = 0; i < sigs.size(); i++)
            {
                signatures.insert(ParseHex(uni_get_str(sigs[i])));
            }
        }
    }
    catch(...)
    {
        version = VERSION_INVALID;
    }
}

uint256 CIdentitySignature::IdentitySignatureHash(const std::vector<uint160> &vdxfCodes, 
                                                  const std::vector<uint256> &statements, 
                                                  const uint160 &systemID, 
                                                  uint32_t blockHeight, 
                                                  uint160 idID,
                                                  const std::string &prefixString, 
                                                  const uint256 &msgHash) const
{
    uint256 retVal;
    if (version == VERSION_VERUSID)
    {
        CHashWriterSHA256 ss(SER_GETHASH, PROTOCOL_VERSION);

        ss << prefixString;
        ss << systemID;
        ss << blockHeight;
        ss << idID;
        ss << msgHash;

        retVal = ss.GetHash();
    }
    else
    {
        auto ss = CNativeHashWriter((CCurrencyDefinition::EProofProtocol)hashType);

        bool crossChainLogging = LogAcceptCategory("notarysignatures");
        if (crossChainLogging)
        {
            printf("%s: vdxfCodes:\n", __func__);
            LogPrintf("%s: vdxfCodes:\n", __func__);
            for (auto &oneCode : vdxfCodes)
            {
                printf("%s\n", oneCode.GetHex().c_str());
                LogPrintf("%s\n", oneCode.GetHex().c_str());
            }
            printf("\n");
            LogPrintf("\n");
            printf("%s: statements:\n", __func__);
            LogPrintf("%s: statements:\n", __func__);
            for (auto &oneStatement : statements)
            {
                printf("%s\n", oneStatement.GetHex().c_str());
                LogPrintf("%s\n", oneStatement.GetHex().c_str());
            }
            printf("\n");
            LogPrintf("\n");
            printf("systemid: %s, blockheight: %u, identity: %s, prefix: %s\nmsghash: %s\n",
                EncodeDestination(CIdentityID(systemID)).c_str(),
                blockHeight,
                EncodeDestination(CIdentityID(idID)).c_str(),
                prefixString.c_str(),
                msgHash.GetHex().c_str());
            LogPrintf("systemid: %s, blockheight: %u, identity: %s, prefix: %s\nmsghash: %s\n",
                EncodeDestination(CIdentityID(systemID)).c_str(),
                blockHeight,
                EncodeDestination(CIdentityID(idID)).c_str(),
                prefixString.c_str(),
                msgHash.GetHex().c_str());
            printf("\n");
            LogPrintf("\n");
        }

        if (vdxfCodes.size())
        {
            ss << vdxfCodes;
        }
        if (statements.size())
        {
            ss << statements;
        }
        ss << systemID;
        ss << blockHeight;
        ss << idID;
        if (prefixString.size())
        {
            ss << prefixString;
        }
        ss << msgHash;
        retVal = ss.GetHash();
        if (crossChainLogging)
        {
            printf("%s\n", retVal.GetHex().c_str());
            LogPrintf("%s\n", retVal.GetHex().c_str());
        }
    }
    return retVal;
}

CIdentitySignature::ESignatureVerification CIdentitySignature::CheckSignature(const CIdentity &signingID,
                                                                              const std::vector<uint160> &vdxfCodes, 
                                                                              const std::vector<uint256> &statements, 
                                                                              const uint160 systemID, 
                                                                              const std::string &prefixString, 
                                                                              const uint256 &msgHash) const
{
    CPubKey checkKey;
    std::set<uint160> keys;
    std::set<uint160> idKeys;
    for (auto &oneKey : signingID.primaryAddresses)
    {
        // we currently only support secp256k1 signatures
        if (oneKey.which() != COptCCParams::ADDRTYPE_PK && oneKey.which() != COptCCParams::ADDRTYPE_PKH)
        {
            return SIGNATURE_INVALID;
        }
        idKeys.insert(GetDestinationID(oneKey));
    }
    uint256 signatureHash = IdentitySignatureHash(vdxfCodes, statements, systemID, blockHeight, signingID.GetID(), prefixString, msgHash);
    for (auto &oneSig : signatures)
    {
        if (oneSig.size() != ECDSA_RECOVERABLE_SIZE)
        {
            return SIGNATURE_INVALID;
        }
        if (!checkKey.RecoverCompact(signatureHash, oneSig))
        {
            return SIGNATURE_INVALID;
        }
        uint160 checkKeyID = checkKey.GetID();
        if (!idKeys.count(checkKeyID))
        {
            return SIGNATURE_INVALID;
        }
        keys.insert(checkKey.GetID());
    }
    if (keys.size() >= signingID.minSigs)
    {
        return SIGNATURE_COMPLETE;
    }
    else if (keys.size())
    {
        return SIGNATURE_PARTIAL;
    }
    else
    {
        return SIGNATURE_INVALID;
    }
}

uint160 DecodeCurrencyName(std::string currencyStr)
{
    uint160 retVal;
    currencyStr = TrimSpaces(currencyStr);
    if (!currencyStr.size())
    {
        return retVal;
    }
    if (currencyStr.back() == '@')
    {
        return retVal;
    }
    std::string copyStr = currencyStr;
    uint160 parent;
    currencyStr = CleanName(currencyStr, parent, true);
    if (!parent.IsNull() && CCurrencyDefinition::GetID(currencyStr, parent) == ASSETCHAINS_CHAINID)
    {
        return ASSETCHAINS_CHAINID;
    }
    CTxDestination currencyDest = DecodeDestination(currencyStr);
    if (currencyDest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        currencyDest = DecodeDestination(copyStr + "@");
    }
    if (currencyDest.which() != COptCCParams::ADDRTYPE_INVALID)
    {
        return GetDestinationID(currencyDest);
    }
    return retVal;
}

CCurrencyDefinition::CCurrencyDefinition(const UniValue &obj) :
    preLaunchDiscount(0),
    initialFractionalSupply(0),
    gatewayConverterIssuance(0),
    minNotariesConfirm(0),
    idRegistrationFees(IDENTITY_REGISTRATION_FEE),
    idReferralLevels(DEFAULT_ID_REFERRAL_LEVELS),
    idImportFees(IDENTITY_IMPORT_FEE),
    currencyRegistrationFee(CURRENCY_REGISTRATION_FEE),
    pbaasSystemLaunchFee(PBAAS_SYSTEM_LAUNCH_FEE),
    currencyImportFee(CURRENCY_IMPORT_FEE),
    transactionImportFee(TRANSACTION_TRANSFER_FEE >> 1),
    transactionExportFee(TRANSACTION_TRANSFER_FEE >> 1)
{
    try
    {
        nVersion = uni_get_int64(find_value(obj, "version"), VERSION_CURRENT);
        options = (uint32_t)uni_get_int64(find_value(obj, "options"));
        name = std::string(uni_get_str(find_value(obj, "name")), 0, (KOMODO_ASSETCHAIN_MAXLEN - 1));

        std::string parentStr = uni_get_str(find_value(obj, "parent"));
        if (parentStr != "")
        {
            parent = DecodeCurrencyName(parentStr);
            if (parent.IsNull())
            {
                LogPrintf("%s: invalid parent for currency: %s\n", __func__, parentStr.c_str());
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
        }

        name = CleanName(name, parent);

        std::string systemIDStr = uni_get_str(find_value(obj, "systemid"));
        if (systemIDStr != "")
        {
            systemID = DecodeCurrencyName(systemIDStr);
            // if we have a system, but it is invalid, the json for this definition cannot be valid
            if (systemID.IsNull())
            {
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
        }
        else
        {
            systemID = parent;
        }

        gatewayConverterName = uni_get_str(find_value(obj, "gatewayconvertername"));
        if (!gatewayConverterName.empty())
        {
            if (!(IsPBaaSChain() || IsGateway()) || (IsPBaaSChain() && IsGateway()))
            {
                LogPrintf("%s: a gateway converter currency may only be defined as part of a gateway or PBaaS system definition\n", __func__);
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
            else if (IsGateway())
            {
                gatewayID = GetID();
            }
            uint160 parent = GetID();
            std::string cleanGatewayName = CleanName(gatewayConverterName, parent, true);
            uint160 converterID = GetID(cleanGatewayName, parent);
            if (parent != GetID())
            {
                LogPrintf("%s: invalid name for gateway converter %s\n", __func__, cleanGatewayName.c_str());
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
        }

        if (IsPBaaSChain() || IsGateway() || IsPBaaSConverter())
        {
            gatewayConverterIssuance = AmountFromValueNoErr(find_value(obj, "gatewayconverterissuance"));
        }

        notarizationProtocol = (ENotarizationProtocol)uni_get_int(find_value(obj, "notarizationprotocol"), (int32_t)NOTARIZATION_AUTO);
        if (notarizationProtocol != NOTARIZATION_AUTO && notarizationProtocol != NOTARIZATION_NOTARY_CONFIRM)
        {
            LogPrintf("%s: notarization protocol for PBaaS chains must be %d (NOTARIZATION_AUTO) or %d (NOTARIZATION_NOTARY_CONFIRM)\n", __func__, (int)NOTARIZATION_NOTARY_CONFIRM);
            nVersion = PBAAS_VERSION_INVALID;
            return;
        }
        proofProtocol = (EProofProtocol)uni_get_int(find_value(obj, "proofprotocol"), (int32_t)PROOF_PBAASMMR);
        if (proofProtocol != PROOF_PBAASMMR && proofProtocol != PROOF_CHAINID && proofProtocol != PROOF_ETHNOTARIZATION)
        {
            LogPrintf("%s: proofprotocol must be %d, %d, or %d\n", __func__, (int)PROOF_PBAASMMR, (int)PROOF_CHAINID, (int)PROOF_ETHNOTARIZATION);
            nVersion = PBAAS_VERSION_INVALID;
            return;
        }

        // TODO: HARDENING - ensure that it makes sense for a chain to have PROOF_CHAINID still or disallow

        nativeCurrencyID = CTransferDestination(find_value(obj, "nativecurrencyid"));

        std::string launchIDStr = uni_get_str(find_value(obj, "launchsystemid"));
        if (launchIDStr != "")
        {
            launchSystemID = DecodeCurrencyName(launchIDStr);
            // if we have a system, but it is invalid, the json for this definition cannot be valid
            if (launchSystemID.IsNull())
            {
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
        }
        else
        {
            launchSystemID = parent;
        }

        startBlock = (uint32_t)uni_get_int64(find_value(obj, "startblock"));
        endBlock = (uint32_t)uni_get_int64(find_value(obj, "endblock"));

        int32_t totalReserveWeight = IsFractional() ? SATOSHIDEN : 0;
        UniValue currencyArr = find_value(obj, "currencies");
        UniValue weightArr = find_value(obj, "weights");
        UniValue conversionArr = find_value(obj, "conversions");
        UniValue minPreconvertArr = find_value(obj, "minpreconversion");
        UniValue maxPreconvertArr = find_value(obj, "maxpreconversion");
        UniValue initialContributionArr = find_value(obj, "initialcontributions");

        if (currencyArr.isArray() && currencyArr.size())
        {
            contributions = preconverted = std::vector<int64_t>(currencyArr.size());

            if (initialContributionArr.isNull())
            {
                initialContributionArr = UniValue(UniValue::VARR);
                for (int i = 0; i < currencyArr.size(); i++)
                {
                    initialContributionArr.push_back((CAmount)0);
                }
            }

            if (IsFractional())
            {
                preLaunchDiscount = AmountFromValueNoErr(find_value(obj, "prelaunchdiscount"));
                initialFractionalSupply = AmountFromValueNoErr(find_value(obj, "initialsupply"));

                if (!initialFractionalSupply)
                {
                    LogPrintf("%s: cannot specify zero initial supply for fractional currency\n", __func__);
                    printf("%s: cannot specify zero initial supply for fractional currency\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }

                preLaunchCarveOut = AmountFromValueNoErr(find_value(obj, "prelaunchcarveout"));

                // if weights are defined, use them as relative ratios of each member currency
                if (weightArr.isArray() && weightArr.size())
                {
                    if (weightArr.size() != currencyArr.size())
                    {
                        LogPrintf("%s: reserve currency weights must be specified for all currencies\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                    }
                    else
                    {
                        CAmount total = 0;
                        for (int i = 0; i < currencyArr.size(); i++)
                        {
                            int32_t weight = (int32_t)AmountFromValueNoErr(weightArr[i]);
                            if (weight <= 0)
                            {
                                nVersion = PBAAS_VERSION_INVALID;
                                total = 0;
                                break;
                            }
                            total += weight;
                            weights.push_back(weight);
                        }
                        if (nVersion != PBAAS_VERSION_INVALID)
                        {
                            // calculate each weight as a relative part of the total
                            // reserve weight
                            int64_t totalRelativeWeight = 0;
                            for (auto &onew : weights)
                            {
                                totalRelativeWeight += onew;
                            }

                            int weightIdx;
                            arith_uint256 bigReserveWeight(totalReserveWeight);
                            int32_t reserveLeft = totalReserveWeight;
                            for (weightIdx = 0; weightIdx < weights.size(); weightIdx++)
                            {
                                CAmount amount = (bigReserveWeight * arith_uint256(weights[weightIdx]) / arith_uint256(totalRelativeWeight)).GetLow64();
                                if (reserveLeft <= amount || (weightIdx + 1) == weights.size())
                                {
                                    amount = reserveLeft;
                                }
                                reserveLeft -= amount;
                                weights[weightIdx] = amount;
                            }
                        }
                    }
                }
                else if (totalReserveWeight)
                {
                    uint32_t oneWeight = totalReserveWeight / currencyArr.size();
                    uint32_t mod = totalReserveWeight % currencyArr.size();
                    for (int i = 0; i < currencyArr.size(); i++)
                    {
                        // distribute remainder of weight among first come currencies
                        int32_t weight = oneWeight;
                        if (mod > 0)
                        {
                            weight++;
                            mod--;
                        }
                        weights.push_back(weight);
                    }
                }
            }

            // if we have weights, we can be a fractional currency
            if (weights.size())
            {
                // if we are fractional, explicit conversion values are not valid
                // and are based on non-zero, initial contributions relative to supply
                if ((conversionArr.isArray() && conversionArr.size() != currencyArr.size()) ||
                    !initialContributionArr.isArray() || 
                    initialContributionArr.size() != currencyArr.size() ||
                    weights.size() != currencyArr.size() ||
                    !IsFractional())
                {
                    LogPrintf("%s: fractional currencies must have weights, initial contributions in at least one currency\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
            }
            else
            {
                // if we are not a reserve currency, we either have a conversion vector, or we are not convertible at all
                if (IsFractional())
                {
                    LogPrintf("%s: reserve currencies must define currency weight\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else if (conversionArr.isArray() && conversionArr.size() && conversionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: non-reserve currencies must define all conversion rates for supported currencies if they define any\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else if (initialContributionArr.isArray() && initialContributionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: initial contributions for currencies must all be specified if any are specified\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
            }

            if (nVersion != PBAAS_VERSION_INVALID && IsFractional())
            {
                if (minPreconvertArr.isArray() && minPreconvertArr.size() && minPreconvertArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies with minimum conversion required must define all minimums if they define any\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                if (maxPreconvertArr.isArray() && maxPreconvertArr.size() && maxPreconvertArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies that include maximum conversions on pre-launch must specify all maximums\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                if (initialContributionArr.isArray() && initialContributionArr.size() && initialContributionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies that include initial contributions in one currency on pre-launch must specify all currency amounts\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
            }

            bool isInitialContributions = initialContributionArr.isArray() && initialContributionArr.size();
            bool isPreconvertMin = minPreconvertArr.isArray() && minPreconvertArr.size();
            bool isPreconvertMax = maxPreconvertArr.isArray() && maxPreconvertArr.size();
            bool explicitConversions = (!IsFractional() && conversionArr.isArray()) && conversionArr.size();

            for (int i = 0; nVersion != PBAAS_VERSION_INVALID && i < currencyArr.size(); i++)
            {
                uint160 currencyID = DecodeCurrencyName(uni_get_str(currencyArr[i]));
                // if we have a destination, but it is invalid, the json for this definition cannot be valid
                if (currencyID.IsNull())
                {
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }
                else
                {
                    currencies.push_back(currencyID);
                }

                if (isInitialContributions && i < initialContributionArr.size())
                {
                    int64_t contrib = AmountFromValueNoErr(initialContributionArr[i]);
                    contributions[i] = contrib;
                    preconverted[i] = contrib;
                }

                int64_t minPre = 0;
                if (isPreconvertMin)
                {
                    minPre = AmountFromValueNoErr(minPreconvertArr[i]);
                    if (minPre < 0)
                    {
                        LogPrintf("%s: minimum preconversions for any currency may not be less than 0\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    minPreconvert.push_back(minPre);
                }
                if (isPreconvertMax)
                {
                    int64_t maxPre = AmountFromValueNoErr(maxPreconvertArr[i]);
                    if (maxPre < 0 || maxPre < minPre)
                    {
                        LogPrintf("%s: maximum preconversions for any currency may not be less than 0 or minimum\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    maxPreconvert.push_back(maxPre);
                }
                if (explicitConversions)
                {
                    int64_t conversion = AmountFromValueNoErr(conversionArr[i]);
                    if (conversion < 0)
                    {
                        LogPrintf("%s: conversions for any currency must be greater than 0\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    conversions.push_back(conversion);
                }
                else
                {
                    conversions.push_back(0);
                }
            }
        }

        UniValue preallocationArr = find_value(obj, "preallocations");
        if (preallocationArr.isArray())
        {
            for (int i = 0; i < preallocationArr.size(); i++)
            {
                std::vector<std::string> preallocationKey = preallocationArr[i].getKeys();
                std::vector<UniValue> preallocationValue = preallocationArr[i].getValues();
                if (preallocationKey.size() != 1 || preallocationValue.size() != 1)
                {
                    LogPrintf("%s: each preallocation entry must contain one destination identity and one amount\n", __func__);
                    printf("%s: each preallocation entry must contain one destination identity and one amount\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }

                CTxDestination preallocDest = DecodeDestination(preallocationKey[0]);

                if (preallocDest.which() != COptCCParams::ADDRTYPE_ID && preallocDest.which() != COptCCParams::ADDRTYPE_INVALID)
                {
                    LogPrintf("%s: preallocation destination must be an identity\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }

                CAmount preAllocAmount = AmountFromValueNoErr(preallocationValue[0]);
                if (preAllocAmount <= 0)
                {
                    LogPrintf("%s: preallocation values must be greater than zero\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }
                preAllocation.push_back(make_pair(CIdentityID(GetDestinationID(preallocDest)), preAllocAmount));
            }
        }

        UniValue notaryArr = find_value(obj, "notaries");
        minNotariesConfirm = 0;
        if (notaryArr.isArray())
        {
            for (int i = 0; i < notaryArr.size(); i++)
            {
                CIdentityID notaryID;
                CTxDestination notaryDest = DecodeDestination(uni_get_str(notaryArr[i]));
                notaryID = GetDestinationID(notaryDest);
                // if we have a destination, but it is invalid, the json for this definition cannot be valid
                if (notaryID.IsNull())
                {
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else
                {
                    notaries.push_back(notaryID);
                }
            }
            minNotariesConfirm = uni_get_int(find_value(obj, "minnotariesconfirm"));
        }

        idRegistrationFees = uni_get_int64(find_value(obj, "idregistrationfees"), idRegistrationFees);
        idReferralLevels = uni_get_int(find_value(obj, "idreferrallevels"), idReferralLevels);
        idImportFees = uni_get_int64(find_value(obj, "idimportfees"), idImportFees);

        auto vEras = uni_getValues(find_value(obj, "eras"));
        if (vEras.size() > ASSETCHAINS_MAX_ERAS)
        {
            vEras.resize(ASSETCHAINS_MAX_ERAS);
        }

        if (vEras.size())
        {
            currencyRegistrationFee = uni_get_int64(find_value(obj, "currencyregistrationfee"), currencyRegistrationFee);
            pbaasSystemLaunchFee = uni_get_int64(find_value(obj, "pbaassystemregistrationfee"), pbaasSystemLaunchFee);
            currencyImportFee = uni_get_int64(find_value(obj, "currencyimportfee"), currencyImportFee);
            transactionImportFee = uni_get_int64(find_value(obj, "transactionimportfee"), transactionImportFee);
            transactionExportFee = uni_get_int64(find_value(obj, "transactionexportfee"), transactionExportFee);

            if (!gatewayID.IsNull())
            {
                gatewayConverterIssuance = uni_get_int64(find_value(obj, "gatewayconverterissuance"));
            }

            for (auto era : vEras)
            {
                rewards.push_back(uni_get_int64(find_value(era, "reward")));
                rewardsDecay.push_back(uni_get_int64(find_value(era, "decay")));
                halving.push_back(uni_get_int64(find_value(era, "halving")));
                eraEnd.push_back(uni_get_int64(find_value(era, "eraend")));
            }

            if (!rewards.size())
            {
                LogPrintf("%s: PBaaS chain does not have valid rewards eras");
                nVersion = PBAAS_VERSION_INVALID;
            }
        }
    }
    catch (exception e)
    {
        LogPrintf("%s: exception reading currency definition JSON\n", __func__, e.what());
        nVersion = PBAAS_VERSION_INVALID;
    }
}

int64_t CCurrencyDefinition::CalculateRatioOfValue(int64_t value, int64_t ratio)
{
    arith_uint256 bigAmount(value);
    static const arith_uint256 bigSatoshi(SATOSHIDEN);

    int64_t retVal = ((bigAmount * arith_uint256(ratio)) / bigSatoshi).GetLow64();
    return retVal;
}

// this will only return an accurate result after total preconversion has been updated and before any emission
int64_t CCurrencyDefinition::GetTotalPreallocation() const
{
    CAmount totalPreallocatedNative = 0;
    for (auto &onePreallocation : preAllocation)
    {
        totalPreallocatedNative += onePreallocation.second;
    }
    return totalPreallocatedNative;
}

// this will only return an accurate result after total preconversion has been updated and before any emission
int32_t CCurrencyDefinition::GetTotalCarveOut() const
{
    return preLaunchCarveOut;
}

CAmount AmountFromValue(const UniValue& value)
{
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!MoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
}

