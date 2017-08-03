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
#include "instruction.h"

#include <stdint.h>
#include <string.h>
#include <algorithm>

#include <boost/lexical_cast.hpp>

class CBlock;
class CBlockTemplate;

static const CAmount BLOCKCHAIN_INIT_REWARD = COIN * 0;
static const CAmount PHASE_1_POW_REWARD = COIN * 1;
static const CAmount PHASE_1_DYNODE_PAYMENT = COIN * 0.382;
static const CAmount PHASE_2_DYNODE_PAYMENT = COIN * 0.618;

class Fluid : public CAuthorise {
private:
	/*
	 * The three keys controlling the multiple signature system
	 */
	std::string defaultFluidAddressX = "DEmrYUjVeLQnuvLnZjqzCex9azDRAtPzUa"; // importprivkey MnjEkYWghQhBqSQSixDGVPpzrtYWrg1s1BZVuvznK3SF7s5dRmzd
	std::string defaultFluidAddressY = "DM1sv8zT529d7rYPtGX5kKM2MjD8YrHg5D"; // importprivkey Mn64HNSDehPY4KKP8bZCMvcweYS7wrNszNWGvPHamcyPhjoZABSp
	std::string defaultFluidAddressZ = "DKPH9BdcrVyWwRsUVbPtaUQSwJWv2AMrph"; // importprivkey MpPYgqNRGf8qQqkuds6si6UEfpddfps1NJ1uTVbp7P3g3imJLwAC

public:
	const char* fluidImportantAddress(KeyNumber adr) {
		if (adr == KEY_UNE) { return (defaultFluidAddressX.c_str()); }
		else if (adr == KEY_DEUX) { return (defaultFluidAddressY.c_str()); }
		else if (adr == KEY_TROIS) { return (defaultFluidAddressZ.c_str()); }
		else { return "Invalid Address Requested"; }
	}
	
	bool IsItHardcoded(std::string givenScriptPubKey);
	bool InitiateFluidVerify(CDynamicAddress dynamicAddress);
	bool IsGivenKeyMaster(CDynamicAddress inputKey, int &whichOne);
	bool HowManyKeysWeHave(CDynamicAddress inputKey, bool &keyOne, bool &keyTwo, bool &keyThree);

	bool ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier);
	bool GenericParseNumber(std::string scriptString, CAmount &howMuch);
};

/** Standard Reward Payment Determination Functions */
CAmount GetPoWBlockPayment(const int& nHeight, CAmount nFees);
CAmount GetDynodePayment(bool fDynode = true);

/** Override Logic Switch for Reward Payment Determination Functions */
CAmount getBlockSubsidyWithOverride(const int& nHeight, CAmount nFees, CAmount lastOverrideCommand);
CAmount getDynodeSubsidyWithOverride(CAmount lastOverrideCommand, bool fDynode = true);

bool RecursiveVerifyIfValid(const CTransaction& tx);
bool CheckInstruction(const CTransaction& tx, CValidationState &state);

/** Required for RPC */
opcodetype getOpcodeFromString(std::string input);

/** Simple function to come up with fee burning script */
CScript AssimilateScriptFeeBurn(int number);

extern Fluid fluid;

#endif // FLUID_PROTOCOL_H

