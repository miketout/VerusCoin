// Copyright (c) 2019 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VERUS_PBAASRPC_H
#define VERUS_PBAASRPC_H

#include "amount.h"
#include "uint256.h"
#include "sync.h"
#include <stdint.h>
#include <map>
#include "pbaas/notarization.h"
#include "pbaas/reserves.h"

#include <boost/assign/list_of.hpp>

#include <univalue.h>

bool GetCurrencyDefinition(const std::string &name, CCurrencyDefinition &chainDef);
bool GetCurrencyDefinition(const uint160 &chainID, CCurrencyDefinition &chainDef, int32_t *pDefHeight=nullptr, bool checkMempool=false, bool notarizationCheck=false, CUTXORef *pUTXO=nullptr, std::vector<CNodeData> *pGoodNodes=nullptr);
bool GetNotarizationData(const uint160 &chainID, CChainNotarizationData &notarizationData, std::vector<std::pair<CTransaction, uint256>> *optionalTxOut = NULL);
bool GetChainTransfers(std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, 
                            uint160 chainFilter = uint160(), int start=0, int end=0, uint32_t flags=CReserveTransfer::VALID);
bool GetChainTransfersUnspentBy(std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors,
                            uint160 chainFilter, uint32_t start, uint32_t end, uint32_t unspentBy, uint32_t flags=CReserveTransfer::VALID);
bool GetUnspentChainTransfers(std::multimap<uint160, ChainTransferData> &inputDescriptors, uint160 chainFilter = uint160());
UniValue getcurrency(const UniValue& params, bool fHelp);
UniValue getnotarizationdata(const UniValue& params, bool fHelp);
UniValue definecurrency(const UniValue& params, bool fHelp);
UniValue addmergedblock(const UniValue& params, bool fHelp);

void RegisterPBaaSRPCCommands(CRPCTable &tableRPC);

std::map<std::string, UniValue> UniObjectToMap(const UniValue &obj);
UniValue MapToUniObject(const std::map<std::string, UniValue> &uniMap);

#endif // VERUS_PBAASRPC_H