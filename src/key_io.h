// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2018 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_KEYIO_H
#define BITCOIN_KEYIO_H

#include <chainparams.h>
#include <key.h>
#include <pubkey.h>
#include <zcash/Address.hpp>
#include <pbaas/vdxf.h>

#include <string>

extern CIdentityID VERUS_DEFAULTID;
extern CIdentityID VERUS_NOTARYID;
extern std::set<uint160> FREE_CURRENCY_IMPORTS;
extern CIdentityID PBAAS_NOTIFICATION_ORACLE;
extern CTransferDestination APPROVE_CONTRACT_UPGRADE;
extern std::string PBAAS_DEFAULT_NOTIFICATION_ORACLE;
extern uint160 VERUS_NODEID;
extern bool ONLY_ADD_WHITELISTED_UTXOS_ID_RESCAN;
extern int32_t MAX_UTXOS_ID_RESCAN;
extern int32_t MAX_OUR_UTXOS_ID_RESCAN;
extern bool VERUS_PRIVATECHANGE;
extern std::string VERUS_DEFAULT_ZADDR;
extern CTxDestination VERUS_DEFAULT_ARBADDRESS;
extern std::vector<uint160> VERUS_ARBITRAGE_CURRENCIES;
extern int64_t STORAGE_FEE_FACTOR;

std::vector<std::string> ParseSubNames(const std::string &Name, std::string &ChainOut, bool displayfilter=false, bool addVerus=true);
CKey DecodeSecret(const std::string& str);
std::string EncodeSecret(const CKey& key);

CExtKey DecodeExtKey(const std::string& str);
std::string EncodeExtKey(const CExtKey& extkey);
CExtPubKey DecodeExtPubKey(const std::string& str);
std::string EncodeExtPubKey(const CExtPubKey& extpubkey);

std::string EncodeDestination(const CTxDestination& dest);
std::vector<unsigned char> GetDestinationBytes(const CTxDestination& dest);
uint160 GetDestinationID(const CTxDestination dest);
CTxDestination DecodeDestination(const std::string& str);
CTxDestination ValidateDestination(const std::string &destStr);
bool IsValidDestinationString(const std::string& str);
bool IsValidDestinationString(const std::string& str, const CChainParams& params);
uint160 ParseVDXFKey(const std::string &keyString);
std::vector<unsigned char> VectorEncodeVDXFUni(const UniValue &obj);

std::string EncodePaymentAddress(const libzcash::PaymentAddress& zaddr);
libzcash::PaymentAddress DecodePaymentAddress(const std::string& str);
bool IsValidPaymentAddressString(const std::string& str, uint32_t consensusBranchId);

std::string EncodeViewingKey(const libzcash::ViewingKey& vk);
libzcash::ViewingKey DecodeViewingKey(const std::string& str);

std::string EncodeSpendingKey(const libzcash::SpendingKey& zkey);
libzcash::SpendingKey DecodeSpendingKey(const std::string& str);

#endif // BITCOIN_KEYIO_H
