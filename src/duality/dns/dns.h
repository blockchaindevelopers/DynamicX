// Copyright (c) 2009-2017 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Developers
// Copyright (c) 2013-2017 Emercoin Developers
// Copyright (c) 2016-2017 Duality Blockchain Solutions Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DNS_H
#define DNS_H

#include "base58.h"
#include "wallet/db.h"
#include "hooks.h"
#include "keystore.h"
#include "main.h"
#include "api/rpc/rpcprotocol.h"

class CTxMemPool;

static const unsigned int IDINDEX_CHAIN_SIZE = 1000;
static const int RELEASE_HEIGHT = 1<<16;
static const unsigned int IDENTITY_REGISTRATION_DAILY_FEE = 1000000; // Current set to 0.3 DYN per month or 3.65 DYN per year.

class CIdentityIndex
{
public:
    CDiskTxPos txPos;
    int nHeight;
    int op;
    CIdentityVal value;

    CIdentityIndex() : nHeight(0), op(0) {}

    CIdentityIndex(CDiskTxPos txPos, int nHeight, CIdentityVal value) :
        txPos(txPos), nHeight(nHeight), value(value) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(txPos);
        READWRITE(nHeight);
        READWRITE(op);
        READWRITE(value);
    }
};

// CIdentityRecord is all the data that is saved (in nameindex.dat) with associated name
class CIdentityRecord
{
public:
    std::vector<CIdentityIndex> vtxPos;
    int nExpiresAt;
    int nLastActiveChainIndex;  // position in vtxPos of first tx in last active chain of identity_new -> identity_update -> identity_update -> ....

    CIdentityRecord() : nExpiresAt(0), nLastActiveChainIndex(0) {}
    bool deleted()
    {
        if (!vtxPos.empty())
            return vtxPos.back().op == OP_IDENTITY_DELETE;
        else return true;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vtxPos);
        READWRITE(nExpiresAt);
        READWRITE(nLastActiveChainIndex);
    }
};

class CIdentityDB : public CDB
{
public:
    CIdentityDB(const char* pszMode="r+") : CDB("ddns.dat", pszMode) {}

    bool WriteName(const CIdentityVal& name, const CIdentityRecord& rec)
    {
        return Write(make_pair(std::string("namei"), name), rec);
    }

    bool ReadName(const CIdentityVal& name, CIdentityRecord& rec);

    bool ExistsName(const CIdentityVal& name)
    {
        return Exists(make_pair(std::string("namei"), name));
    }

    bool EraseName(const CIdentityVal& name)
    {
        return Erase(make_pair(std::string("namei"), name));
    }

    bool ScanNames(const CIdentityVal& name, unsigned int nMax,
            std::vector<
                std::pair<
                    CIdentityVal,
                    std::pair<CIdentityIndex, int>
                >
            > &nameScan
            );
    bool DumpToTextFile();
};

extern std::map<CIdentityVal, std::set<uint256> > mapNamePending;

int IndexOfNameOutput(const CTransaction& tx);
bool GetNameCurrentAddress(const CIdentityVal& name, CDynamicAddress& address, std::string& error);
CIdentityVal nameValFromString(const std::string& str);
std::string stringFromOp(int op);

CAmount GetNameOpFee(const unsigned int& nRentalDays, const int& op);

bool DecodeIdentityTx(const CTransaction& tx, IdentityTxInfo& nti, bool checkAddressAndIfIsMine = false);
void GetNameList(const CIdentityVal& nameUniq, std::map<CIdentityVal, IdentityTxInfo>& mapNames, std::map<CIdentityVal, IdentityTxInfo>& mapPending);
bool GetNameValue(const CIdentityVal& name, CIdentityVal& value);
bool SignNameSignature(const CKeyStore& keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL);
std::string MultiSigGetPubKeyFromAddress(const std::string& strAddress);

struct IdentityTxReturn
{
     bool ok;
     std::string err_msg;
     RPCErrorCode err_code;
     std::string address;
     uint256 hex;   // Transaction hash in hex
};
IdentityTxReturn identity_operation(const int op, const CIdentityVal& name, CIdentityVal value, const int nRentalDays, const std::string& strAddress, const std::string& strValueType);


struct nameTempProxy
{
    unsigned int nTime;
    CIdentityVal name;
    int op;
    uint256 hash;
    CIdentityIndex ind;
};

#endif // DNS_H
