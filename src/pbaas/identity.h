/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS identity definition,
 * 
 * This is a decentralized identity class that provides the minimum
 * basic function needed to enable persistent DID-similar identities, 
 * needed for signatories, that will eventually bridge compatibly to
 * DID identities.
 * 
 * 
 */

#ifndef IDENTITY_H
#define IDENTITY_H

#include <univalue.h>
#include <sstream>
#include <vector>
#include "streams.h"
#include "pubkey.h"
#include "base58.h"
#include "uint256.h"
#include "key_io.h"
#include "crosschainrpc.h"
#include "zcash/Address.hpp"
#include "script/script.h"
#include "script/standard.h"
#include "primitives/transaction.h"
#include "arith_uint256.h"

std::string CleanName(const std::string &Name, uint160 &Parent, bool displayapproved=false, bool addVerus=true);

class CCommitmentHash
{
public:
    static const CAmount DEFAULT_OUTPUT_AMOUNT = 0;
    uint256 hash;

    CCommitmentHash() {}
    CCommitmentHash(const uint256 &Hash) : hash(Hash) {}

    CCommitmentHash(const UniValue &uni)
    {
        hash = uint256S(uni_get_str(uni));
    }

    CCommitmentHash(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CCommitmentHash(const CTransaction &tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
    }

    UniValue ToUniValue() const
    {
        return UniValue(hash.GetHex());
    }
};

class CNameReservation
{
public:
    static const CAmount DEFAULT_OUTPUT_AMOUNT = 0;
    static const int MAX_NAME_SIZE = (KOMODO_ASSETCHAIN_MAXLEN - 1);
    std::string name;
    CIdentityID referral;
    uint256 salt;

    CNameReservation() {}
    CNameReservation(const std::string &Name, const CIdentityID &Referral, const uint256 &Salt) : name(Name.size() > MAX_NAME_SIZE ? std::string(Name.begin(), Name.begin() + MAX_NAME_SIZE) : Name), referral(Referral), salt(Salt) {}

    CNameReservation(const UniValue &uni, uint160 parent=ASSETCHAINS_CHAINID)
    {
        uint160 dummy;
        std::string parentStr = CleanName(uni_get_str(find_value(uni, "parent")), dummy);
        if (!parentStr.empty())
        {
            parent = GetDestinationID(DecodeDestination(parentStr));
        }
        name = CleanName(uni_get_str(find_value(uni, "name")), parent);
        salt = uint256S(uni_get_str(find_value(uni, "salt")));
        CTxDestination dest = DecodeDestination(uni_get_str(find_value(uni, "referral")));
        if (dest.which() == COptCCParams::ADDRTYPE_ID)
        {
            referral = CIdentityID(GetDestinationID(dest));
        }
        else if (dest.which() != COptCCParams::ADDRTYPE_INVALID)
        {
            salt.SetNull(); // either valid destination, no destination, or invalid reservation
        }
    }

    CNameReservation(const CTransaction &tx, int *pNumOut=nullptr);

    CNameReservation(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
        if (name.size() > MAX_NAME_SIZE)
        {
            name = std::string(name.begin(), name.begin() + MAX_NAME_SIZE);
        }
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(name);
        READWRITE(referral);
        READWRITE(salt);
    }

    UniValue ToUniValue() const;

    CCommitmentHash GetCommitment()
    {
        return CCommitmentHash(GetHash(*this));
    }

    bool IsValid() const
    {
        return (name != "" && name.size() <= MAX_NAME_SIZE) && !salt.IsNull();
    }
};

// this includes the necessary data for a principal to sign, but does not
// include enough information to derive a persistent identity
class CPrincipal
{
public:
    static const uint8_t VERSION_INVALID = 0;
    static const uint8_t VERSION_VERUSID = 1;
    static const uint8_t VERSION_PBAAS = 2;
    static const uint8_t VERSION_FIRSTVALID = 1;
    static const uint8_t VERSION_LASTVALID = 2;

    uint32_t nVersion;
    uint32_t flags;

    // signing authority
    std::vector<CTxDestination> primaryAddresses;
    int32_t minSigs;

    CPrincipal() : nVersion(VERSION_INVALID), flags(0) {}
    CPrincipal(uint32_t Version, uint32_t Flags=0) : nVersion(Version), flags(Flags) {}

    CPrincipal(uint32_t Version,
               uint32_t Flags,
               const std::vector<CTxDestination> &primary, 
               int32_t minPrimarySigs) :
               nVersion(Version),
               flags(Flags),
               primaryAddresses(primary),
               minSigs(minPrimarySigs)
        {}

    CPrincipal(const UniValue &uni);
    CPrincipal(std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(flags);
        std::vector<std::vector<unsigned char>> addressVs;
        if (ser_action.ForRead())
        {
            READWRITE(addressVs);

            for (auto vec : addressVs)
            {
                if (vec.size() == 20)
                {
                    primaryAddresses.push_back(CTxDestination(CKeyID(uint160(vec))));
                }
                else if (vec.size() == 33)
                {
                    primaryAddresses.push_back(CTxDestination(CPubKey(vec)));
                }
                else
                {
                    primaryAddresses.push_back(CTxDestination(CNoDestination()));
                }
            }
        }
        else
        {
            for (auto dest : primaryAddresses)
            {
                addressVs.push_back(GetDestinationBytes(dest));
            }

            READWRITE(addressVs);
        }
        READWRITE(minSigs);
    }

    UniValue ToUniValue() const;

    bool IsValid(bool strict=false) const
    {
        bool primaryOK = true;
        if (strict || nVersion >= VERSION_PBAAS)
        {
            for (auto &oneAddr : primaryAddresses)
            {
                if (!(oneAddr.which() == COptCCParams::ADDRTYPE_PK || oneAddr.which() == COptCCParams::ADDRTYPE_PKH))
                {
                    primaryOK = false;
                    break;
                }
            }
        }
        return nVersion >= VERSION_FIRSTVALID && 
               nVersion <= VERSION_LASTVALID &&
               primaryOK &&
               primaryAddresses.size() && 
               minSigs >= 1 &&
               minSigs <= primaryAddresses.size() && 
               ((nVersion < VERSION_PBAAS &&
                 primaryAddresses.size() <= 10) ||
                (primaryAddresses.size() <= 25 &&
                 minSigs <= 13));
    }

    bool IsPrimaryMutation(const CPrincipal &newPrincipal) const
    {
        if (nVersion != newPrincipal.nVersion ||
            minSigs != minSigs ||
            primaryAddresses.size() != newPrincipal.primaryAddresses.size())
        {
            return true;
        }
        for (int i = 0; i < primaryAddresses.size(); i++)
        {
            if (primaryAddresses[i] != newPrincipal.primaryAddresses[i])
            {
                return true;
            }
        }       
        return false; 
    }

    void SetVersion(uint32_t version)
    {
        nVersion = version;
    }
};

class CIdentity : public CPrincipal
{
public:
    enum
    {
        FLAG_REVOKED = 0x8000,              // set when this identity is revoked
        FLAG_ACTIVECURRENCY = 0x1,          // flag that is set when this ID is being used as an active currency name
        FLAG_LOCKED = 0x2,                  // set when this identity is locked
        MAX_UNLOCK_DELAY = 60 * 24 * 22 * 365 // 21+ year maximum unlock time for an ID
    };

    static const int MAX_NAME_LEN = 64;

    uint160 parent;                         // parent in the sense of name. this could be a currency or chain.
    uint160 systemID;                       // system that this ID is homed to, enabling separate parent and system

    // real name or pseudonym, must be unique on the blockchain on which it is defined and can be used
    // as a name for blockchains or other purposes on any chain in the Verus ecosystem once exported to
    // the Verus chain. The hash of this name hashed with the parent if present, must equal the principal ID
    //
    // this name is always normalized to lower case. any identity that is registered
    // on a PBaaS chain may be exported to the Verus chain and referenced by appending
    // a dot ".", followed by the chain name on which this identity was registered.
    // that will eventually create a domain name system as follows:
    // root == VRSC (implicit), so a name that is defined on the Verus chain may be referenced as
    //         just its name.
    //
    // name from another chain == name.chainname
    //      the chainID that would derive from such a name will be Hash(ChainID(chainname) + Hash(name));
    // 
    std::string name;

    // content hashes, key value, where key is 20 byte ripemd160
    std::map<uint160, uint256> contentMap;

    // revocation authority - can only invalidate identity or update revocation
    uint160 revocationAuthority;

    // recovery authority - can change primary addresses in case of primary key loss or compromise
    uint160 recoveryAuthority;

    // z-addresses for contact and privately made attestations that can be proven to others
    std::vector<libzcash::SaplingPaymentAddress> privateAddresses;

    uint32_t unlockAfter;

    CIdentity() : CPrincipal(), unlockAfter(0) {}

    CIdentity(uint32_t Version,
              uint32_t Flags,
              const std::vector<CTxDestination> &primary,
              int32_t minPrimarySigs,
              const uint160 &Parent,
              const std::string &Name,
              const std::vector<std::pair<uint160, uint256>> &hashes,
              const uint160 &Revocation,
              const uint160 &Recovery,
              const std::vector<libzcash::SaplingPaymentAddress> &PrivateAddresses = std::vector<libzcash::SaplingPaymentAddress>(),
              const uint160 &SystemID=ASSETCHAINS_CHAINID,
              int32_t unlockTime=0) : 
              CPrincipal(Version, Flags, primary, minPrimarySigs),
              parent(Parent),
              name(Name),
              revocationAuthority(Revocation),
              recoveryAuthority(Recovery),
              privateAddresses(PrivateAddresses),
              systemID(SystemID),
              unlockAfter(unlockTime)
    {
        for (auto &entry : hashes)
        {
            if (!entry.first.IsNull())
            {
                contentMap[entry.first] = entry.second;
            }
            else
            {
                // any recognizable error should make this invalid
                nVersion = VERSION_INVALID;
            }
        }
    }

    CIdentity(const UniValue &uni);
    CIdentity(const CTransaction &tx, int *voutNum=nullptr);
    CIdentity(const CScript &scriptPubKey);
    CIdentity(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CPrincipal *)this);
        READWRITE(parent);
        READWRITE(LIMITED_STRING(name, MAX_NAME_LEN));

        std::vector<std::pair<uint160, uint256>> kvContent;
        if (ser_action.ForRead())
        {
            READWRITE(kvContent);
            for (auto &entry : kvContent)
            {
                if (!entry.first.IsNull())
                {
                    contentMap[entry.first] = entry.second;
                }
                else
                {
                    // any recognizable error should make this invalid
                    nVersion = VERSION_INVALID;
                }
            }
        }
        else
        {
            for (auto entry : contentMap)
            {
                kvContent.push_back(entry);
            }
            READWRITE(kvContent);
        }

        READWRITE(contentMap);
        READWRITE(revocationAuthority);
        READWRITE(recoveryAuthority);
        READWRITE(privateAddresses);

        if (nVersion >= VERSION_PBAAS)
        {
            READWRITE(systemID);
            READWRITE(unlockAfter);
        }
        else if (ser_action.ForRead())
        {
            REF(unlockAfter) = 0;
            REF(systemID) = parent.IsNull() ? GetID() : parent;
        }
    }

    uint160 GetSystemID() const
    {
        if (nVersion >= VERSION_PBAAS)
        {
            return parent;
        }
        else
        {
            return systemID;
        }
    }

    UniValue ToUniValue() const;

    void Revoke()
    {
        flags |= FLAG_REVOKED;
        Unlock(0, 0);
    }

    void Unrevoke()
    {
        flags &= ~FLAG_REVOKED;
    }

    bool IsRevoked() const
    {
        return flags & FLAG_REVOKED;
    }

    void Lock(int32_t unlockTime)
    {
        if (unlockTime <= 0)
        {
            unlockTime = 1;
        }
        else if (unlockTime > MAX_UNLOCK_DELAY)
        {
            unlockTime = MAX_UNLOCK_DELAY;
        }
        flags |= FLAG_LOCKED;
        unlockAfter = unlockTime;
    }

    void Unlock(uint32_t height, uint32_t txExpiryHeight)
    {
        if (IsRevoked())
        {
            flags &= ~FLAG_LOCKED;
            unlockAfter = 0;
        }
        else if (IsLocked())
        {
            flags &= ~FLAG_LOCKED;
            unlockAfter += txExpiryHeight;
        }
        else if (height > unlockAfter)
        {
            unlockAfter = 0;
        }
        if (unlockAfter > (txExpiryHeight + MAX_UNLOCK_DELAY))
        {
            unlockAfter = txExpiryHeight + MAX_UNLOCK_DELAY;
        }
    }

    // This only returns the state of the lock flag. Note that an ID stays locked from spending or
    // signing until the height it was unlocked plus the time lock applied when it was locked.
    bool IsLocked() const
    {
        return flags & FLAG_LOCKED;
    }

    // consider the unlockAfter height as well
    // this continues to return that it is locked after it is unlocked
    // until passed the parameter of the height at which it was unlocked, plus the time lock
    bool IsLocked(uint32_t height) const
    {
        return nVersion >= VERSION_PBAAS &&
               (IsLocked() || unlockAfter >= height) &&
               !IsRevoked();
    }

    int32_t UnlockHeight() const
    {
        return unlockAfter;
    }

    void ActivateCurrency()
    {
        if (nVersion == VERSION_FIRSTVALID)
        {
            nVersion = VERSION_PBAAS;
        }
        flags |= FLAG_ACTIVECURRENCY;
    }

    void DeactivateCurrency()
    {
        flags &= ~FLAG_ACTIVECURRENCY;
    }

    bool HasActiveCurrency() const
    {
        return flags & FLAG_ACTIVECURRENCY;
    }

    bool IsValid(bool strict=false) const
    {
        return CPrincipal::IsValid(strict) && name.size() > 0 && 
               (name.size() <= MAX_NAME_LEN) &&
               primaryAddresses.size() &&
               (nVersion < VERSION_PBAAS ||
               (!revocationAuthority.IsNull() &&
                !recoveryAuthority.IsNull() &&
                minSigs > 0 &&
                minSigs <= primaryAddresses.size()));
    }

    bool IsValidUnrevoked() const
    {
        return IsValid() && !IsRevoked();
    }

    CIdentityID GetID() const;
    CIdentityID GetID(const std::string &Name) const;
    static CIdentityID GetID(const std::string &Name, uint160 &parent);

    CIdentity LookupIdentity(const std::string &name, uint32_t height=0, uint32_t *pHeightOut=nullptr, CTxIn *pTxIn=nullptr);
    static CIdentity LookupIdentity(const CIdentityID &nameID, uint32_t height=0, uint32_t *pHeightOut=nullptr, CTxIn *pTxIn=nullptr);
    static CIdentity LookupFirstIdentity(const CIdentityID &idID, uint32_t *pHeightOut=nullptr, CTxIn *idTxIn=nullptr, CTransaction *pidTx=nullptr);

    CIdentity RevocationAuthority() const
    {
        return GetID() == revocationAuthority ? *this : LookupIdentity(revocationAuthority);
    }

    CIdentity RecoveryAuthority() const
    {
        return GetID() == recoveryAuthority ? *this : LookupIdentity(recoveryAuthority);
    }

    template <typename TOBJ>
    CTxOut TransparentOutput(uint8_t evalcode, CAmount nValue, const TOBJ &obj) const
    {
        CTxOut ret;

        if (IsValidUnrevoked())
        {
            CConditionObj<TOBJ> ccObj = CConditionObj<TOBJ>(evalcode, std::vector<CTxDestination>({CTxDestination(CIdentityID(GetID()))}), 1, &obj);
            ret = CTxOut(nValue, MakeMofNCCScript(ccObj));
        }
        return ret;
    }

    template <typename TOBJ>
    CTxOut TransparentOutput(CAmount nValue) const
    {
        CTxOut ret;

        if (IsValidUnrevoked())
        {
            CConditionObj<TOBJ> ccObj = CConditionObj<TOBJ>(0, std::vector<CTxDestination>({CTxDestination(CIdentityID(GetID()))}), 1);
            ret = CTxOut(nValue, MakeMofNCCScript(ccObj));
        }
        return ret;
    }

    CScript TransparentOutput() const;
    static CScript TransparentOutput(const CIdentityID &destinationID);

    // creates an output script to control updates to this identity
    CScript IdentityUpdateOutputScript(uint32_t height) const;

    bool IsInvalidMutation(const CIdentity &newIdentity, uint32_t height, uint32_t expiryHeight) const;

    bool IsPrimaryMutation(const CIdentity &newIdentity, uint32_t height) const
    {
        auto nSolVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
        bool isRevokedExempt = nSolVersion >= CActivationHeight::ACTIVATE_PBAAS && newIdentity.IsRevoked();
        if (CPrincipal::IsPrimaryMutation(newIdentity) ||
            (nSolVersion >= CActivationHeight::ACTIVATE_IDCONSENSUS2 && name != newIdentity.name && GetID() == newIdentity.GetID()) ||
            contentMap != newIdentity.contentMap ||
            privateAddresses != newIdentity.privateAddresses ||
            (unlockAfter != newIdentity.unlockAfter && (!isRevokedExempt || newIdentity.unlockAfter != 0)) ||
            (HasActiveCurrency() != newIdentity.HasActiveCurrency()) ||
            (IsLocked() != newIdentity.IsLocked() && (!isRevokedExempt || newIdentity.IsLocked())))
        {
            return true;
        }
        return false;
    }

    bool IsRevocation(const CIdentity &newIdentity) const 
    {
        if (!IsRevoked() && newIdentity.IsRevoked())
        {
            return true;
        }
        return false;
    }

    bool IsRevocationMutation(const CIdentity &newIdentity, uint32_t height) const 
    {
        auto nSolVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
        if (revocationAuthority != newIdentity.revocationAuthority &&
            (nSolVersion < CActivationHeight::ACTIVATE_IDCONSENSUS2 || !IsRevoked()))
        {
            return true;
        }
        return false;
    }

    bool IsRecovery(const CIdentity &newIdentity) const
    {
        if (IsRevoked() && !newIdentity.IsRevoked())
        {
            return true;
        }
        return false;
    }

    bool IsRecoveryMutation(const CIdentity &newIdentity, uint32_t height) const
    {
        auto nSolVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
        if (recoveryAuthority != newIdentity.recoveryAuthority ||
            (IsRevoked() &&
             ((nSolVersion >= CActivationHeight::ACTIVATE_IDCONSENSUS2 && revocationAuthority != newIdentity.revocationAuthority) ||
              IsPrimaryMutation(newIdentity, height))))
        {
            return true;
        }
        return false;
    }
};

class CIdentityMapKey
{
public:
    // the flags
    static const uint16_t VALID = 1;
    static const uint16_t CAN_SPEND = 0x8000;
    static const uint16_t CAN_SIGN = 0x4000;
    static const uint16_t MANUAL_HOLD = 0x2000; // we were CAN_SIGN in the past, so keep a last state updated after we are removed, keep it updated so its useful when signing related txes
    static const uint16_t BLACKLIST = 0x1000;   // do not track identities that are blacklisted
    static const uint32_t MAX_BLOCKHEIGHT = INT32_MAX;

    // these elements are used as a sort key for the identity map
    // with most significant member first. flags have no effect on sort order, since elements will be unique already
    CIdentityID idID;                           // 20 byte ID
    uint32_t blockHeight;                       // four byte blockheight
    uint32_t blockOrder;                        // 1-based numerical order if in the same block based on first to last spend, 1 otherwise, 0 is invalid except for queries
    uint32_t flags;

    CIdentityMapKey() : blockHeight(0), blockOrder(1), flags(0) {}
    CIdentityMapKey(const CIdentityID &id, uint32_t blkHeight=0, uint32_t orderInBlock=1, uint32_t Flags=0) : idID(id), blockHeight(blkHeight), blockOrder(orderInBlock), flags(Flags) {}

    CIdentityMapKey(const arith_uint256 &mapKey)
    {
        flags = mapKey.GetLow64() & 0xffffffff;
        blockOrder = mapKey.GetLow64() >> 32;
        blockHeight = (mapKey >> 64).GetLow64() & 0xffffffff;
        uint256 keyBytes(ArithToUint256(mapKey));
        idID = CIdentityID(uint160(std::vector<unsigned char>(keyBytes.begin() + 12, keyBytes.end())));
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(idID);
        READWRITE(blockHeight);
        READWRITE(blockOrder);
        READWRITE(flags);
    }

    arith_uint256 MapKey() const
    {
        std::vector<unsigned char> vch(idID.begin(), idID.end());
        vch.insert(vch.end(), 12, 0);
        arith_uint256 retVal = UintToArith256(uint256(vch));
        retVal = (retVal << 32) | blockHeight;
        retVal = (retVal << 32) | blockOrder;
        retVal = (retVal << 32) | flags;
        return retVal;
    }

    // if it actually represents a real identity and not just a key for queries. blockOrder is 1-based
    bool IsValid() const
    {
        return !idID.IsNull() && blockHeight != 0 && flags & VALID && blockOrder >= 1;
    }

    std::string ToString() const
    {
        return "{\"id\":" + idID.GetHex() + ", \"blockheight\":" + std::to_string(blockHeight) + ", \"blockorder\":" + std::to_string(blockOrder) + ", \"flags\":" + std::to_string(flags) + ", \"mapkey\":" + ArithToUint256(MapKey()).GetHex() + "}";
    }

    bool CanSign() const
    {
        return flags & CAN_SIGN;
    }

    bool CanSpend() const
    {
        return flags & CAN_SPEND;
    }
};

class CIdentityMapValue : public CIdentity
{
public:
    uint256 txid;

    CIdentityMapValue() : CIdentity() {}
    CIdentityMapValue(const CTransaction &tx) : CIdentity(tx), txid(tx.GetHash()) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CIdentity *)this);
        READWRITE(txid);
    }
};

struct CCcontract_info;
struct Eval;
class CValidationState;

CIdentity GetOldIdentity(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx=nullptr, uint32_t *pHeight=nullptr);
bool ValidateIdentityPrimary(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool ValidateIdentityRevoke(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool ValidateIdentityRecover(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool ValidateIdentityCommitment(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool ValidateIdentityReservation(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool PrecheckIdentityReservation(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool PrecheckIdentityReservation(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height, int referralLevels, int64_t referralAmount);
bool PrecheckIdentityPrimary(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool IsIdentityInput(const CScript &scriptSig);
bool ValidateQuantumKeyOut(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled);
bool IsQuantumKeyOutInput(const CScript &scriptSig);
bool PrecheckQuantumKeyOut(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool ValidateFinalizeExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsFinalizeExportInput(const CScript &scriptSig);
bool FinalizeExportContextualPreCheck(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);

#endif // IDENTITY_H
