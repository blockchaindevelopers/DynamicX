/**
 * Copyright 2017 Everybody and Nobody (Empinel/Plaxton)
 * 
 * This file is a portion of the DynamicX Protocol
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation files 
 * (the "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject 
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE 
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef FLUID_PROTOCOL_H
#define FLUID_PROTOCOL_H

#include "base58.h"
#include "amount.h"
#include "chain.h"
#include "script/script.h"
#include "consensus/validation.h"
#include "utilstrencodings.h"
#include "dbwrapper.h"

#include <stdint.h>
#include <string.h>
#include <algorithm>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

class CBlock;
class CBlockTemplate;

enum KeyNumber {
	KEY_UNE = 1,
	KEY_DEUX = 2,
	KEY_TROIS = 3,
	
	KEY_MAX = 0
};

static const CAmount BLOCKCHAIN_INIT_REWARD = COIN * 1;
static const CAmount PHASE_1_POW_REWARD = COIN * 1.5;
static const CAmount PHASE_1_DYNODE_PAYMENT = COIN * 0.382;
static const CAmount PHASE_2_DYNODE_PAYMENT = COIN * 0.618;

/** Maximum Fluid Transaction Request Validity Time */
static const int64_t 	maximumFluidDistortionTime 	= 5 * 60;
static const int 		minimumThresholdForBanning 	= 10;

/** Configuration Framework */
class CParameters {
public: 
	/*
	 * The three keys controlling the multiple signature system
	 */
	std::string defaultFluidAddressX = "DEmrYUjVeLQnuvLnZjqzCex9azDRAtPzUa"; // importprivkey MnjEkYWghQhBqSQSixDGVPpzrtYWrg1s1BZVuvznK3SF7s5dRmzd
	std::string defaultFluidAddressY = "DM1sv8zT529d7rYPtGX5kKM2MjD8YrHg5D"; // importprivkey Mn64HNSDehPY4KKP8bZCMvcweYS7wrNszNWGvPHamcyPhjoZABSp
	std::string defaultFluidAddressZ = "DKPH9BdcrVyWwRsUVbPtaUQSwJWv2AMrph"; // importprivkey MpPYgqNRGf8qQqkuds6si6UEfpddfps1NJ1uTVbp7P3g3imJLwAC

	const char* fluidImportantAddress(KeyNumber adr) {
		if (adr == KEY_UNE) { return (defaultFluidAddressX.c_str()); }
		else if (adr == KEY_DEUX) { return (defaultFluidAddressY.c_str()); }
		else if (adr == KEY_TROIS) { return (defaultFluidAddressZ.c_str()); }
		else { return "Invalid Address Requested"; }
	}
};

bool CheckIfAddressValid(std::string string);

/** Fluid Asset Management Framework */
class Fluid : public CParameters, public HexFunctions {
public:

	bool IsGivenKeyMaster(CDynamicAddress inputKey);
	bool CheckIfQuorumExists(std::string token, std::string &message, bool individual = false);
	bool GenericConsentMessage(std::string message, std::string &signedString, CDynamicAddress signer);
	bool CheckNonScriptQuorum(std::string token, std::string &message, bool individual = false);

	bool IsItHardcoded(std::string givenScriptPubKey);
	bool InitiateFluidVerify(CDynamicAddress dynamicAddress);
	bool SignIntimateMessage(CDynamicAddress address, std::string unsignedMessage, std::string &stitchedMessage, bool stitch = true);
	
	bool GenericSignMessage(std::string message, std::string &signedString, CDynamicAddress signer);
	bool GenericParseNumber(std::string scriptString, int64_t timeStamp, CAmount &howMuch, bool txCheckPurpose=false);
	bool GenericParseHash(std::string scriptString, int64_t timeStamp, uint256 &hash, bool txCheckPurpose=false);
	bool GenericVerifyInstruction(std::string uniqueIdentifier, CDynamicAddress signer, std::string &messageTokenKey, int whereToLook=1);
	
	bool ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier, bool txCheckPurpose=false);

	bool GetMintingInstructions(const CBlockHeader& blockHeader, CDynamicAddress &toMintAddress, CAmount &mintAmount);
	void GetDestructionTxes(const CBlockHeader& blockHeader, CAmount &amountDestroyed);
	
	bool GetProofOverrideRequest(const CBlockHeader& blockHeader, CAmount &howMuch);
	bool GetDynodeOverrideRequest(const CBlockHeader& blockHeader, CAmount &howMuch);
	
	void AddRemoveBanAddresses(const CBlockHeader& blockHeader, HashVector& bannedList);
	bool CheckIfAddressIsBlacklisted(CScript scriptPubKey, CBlockIndex* pindex = nullptr);
	bool ProcessBanEntry(std::string getBanInstruction, int64_t timestamp, HashVector& bannedList);
	bool RemoveEntry(std::string getBanInstruction, int64_t timestamp, HashVector& bannedList);
	
	bool InsertTransactionToRecord(CScript fluidInstruction, StringVector& transactionRecord);
	bool CheckTransactionInRecord(CScript fluidInstruction, CBlockIndex* pindex = nullptr);
	void AddFluidTransactionsToRecord(const CBlockHeader& blockHeader, StringVector& transactionRecord);
	
	bool ValidationProcesses(CValidationState& state, CScript txOut, CAmount txValue);
	bool ExtractCheckTimestamp(std::string scriptString, int64_t timeStamp);
	bool ProvisionalCheckTransaction(const CTransaction &transaction);
	bool CheckTransactionToBlock(const CTransaction &transaction, const CBlockHeader& blockHeader);
};

/** Standard Reward Payment Determination Functions */
CAmount GetDynodePayment(bool fDynode = true);

/** Override Logic Switch for Reward Payment Determination Functions */
CAmount getBlockSubsidyWithOverride(const int& nHeight, CAmount nFees, CAmount lastOverrideCommand);
CAmount getDynodeSubsidyWithOverride(CAmount lastOverrideCommand, bool fDynode = true);

void BuildFluidInformationIndex(CBlockIndex* pindex, CAmount &nExpectedBlockValue, CAmount nFees, CAmount nValueIn, 
								CAmount nValueOut, bool fDynodePaid);
bool IsTransactionFluid(CScript txOut);

int ApproximateBlocksFromTime(int64_t timeConsidered, bool fromScratch=true);
int64_t ApproximateTimeFromBlocks(int heightConsidered, bool fromScratch=true);

extern Fluid fluid;

#endif // FLUID_PROTOCOL_H

