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

#include "fluid.h"

#include "main.h"
#include "core_io.h"

#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

Fluid fluid;

CScript AssimilateScriptFeeBurn(int number) {
	std::string output = std::to_string(number);
	fluid.ConvertToHex(output);
	return CScript() << OP_DESTROY << ParseHex(output);
}

bool RecursiveVerifyIfValid(const CTransaction& tx) {
	CAmount nFluidTransactions = 0;
	
	BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
		if (txout.scriptPubKey.IsProtocolInstruction(MINT_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(KILL_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(DYNODE_MODFIY_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(ACTIVATE_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(DEACTIVATE_TX))
			nFluidTransactions++;
	}
	
	return (nFluidTransactions != 0);
}

bool CheckInstruction(const CTransaction& tx, CValidationState &state) {
	return RecursiveVerifyIfValid(tx) && CheckTransaction(tx, state);
}

/** Checks if any given address is a master key, and if so, which one */
bool Fluid::IsGivenKeyMaster(CDynamicAddress inputKey, int &whichOne) {
	whichOne = 0;
	bool addressOne;
	{
		CDynamicAddress considerX; considerX = fluidImportantAddress(KEY_UNE);
		addressOne = (considerX == inputKey);
		if(addressOne) whichOne = 1;
	}
	bool addressTwo;
	{
		CDynamicAddress considerY; considerY = fluidImportantAddress(KEY_DEUX);
		addressTwo = (considerY == inputKey);
		if(addressTwo) whichOne = 2;
	}
	bool addressThree;
	{
		CDynamicAddress considerZ; considerZ = fluidImportantAddress(KEY_TROIS);
		addressThree = (considerZ == inputKey);
		if(addressThree) whichOne = 3;
	}
	
	if (addressOne ||
		addressTwo ||
		addressThree)
		return true;
	else
		return false;
}

/** Checks how many Fluid Keys the wallet owns */
bool Fluid::HowManyKeysWeHave(CDynamicAddress inputKey, bool &keyOne, bool &keyTwo, bool &keyThree) {
	int verifyNumber;
	keyOne = false, keyTwo = false, keyThree = false;
	
	for (int x = 0; x < 4; x++) {
		if(IsGivenKeyMaster(inputKey, verifyNumber)) {
			if(InitiateFluidVerify(inputKey)) {
				if(verifyNumber == 1)
					keyOne = true;
				else if (verifyNumber == 2)
					keyTwo = true;
				else if (verifyNumber == 3)
					keyThree = true;
				else {
					// ...
				}
			}
		}
	}
	
	if (keyOne || keyTwo || keyThree)
		return true;
	else
		return false;
}

/** Does client instance own address for engaging in processes - required for RPC (PS: NEEDS wallet) */
bool Fluid::InitiateFluidVerify(CDynamicAddress dynamicAddress) {
#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
	CDynamicAddress address(dynamicAddress);
	
	if (address.IsValid()) {
		CTxDestination dest = address.Get();
		CScript scriptPubKey = GetScriptForDestination(dest);
		isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
		
		return ((mine & ISMINE_SPENDABLE) ? true : false);
	}
	
	return false;
#else
	// Wallet cannot be accessed, cannot continue ahead!
    return false;
#endif
}

/** It will perform basic message signing functions */
bool Fluid::GenericSignMessage(std::string message, std::string &signedString, CDynamicAddress signer) {
	if(!SignIntimateMessage(signer, message, signedString, true))
		return false;
	else 
		ConvertToHex(signedString);

    return true;
}

bool Fluid::GenericParseNumber(std::string scriptString, CAmount &howMuch) {
	std::string dehexString = HexToString(scriptString); howMuch = stringToInteger(dehexString);
	return true;
}

bool Fluid::ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier) {
	std::string recipientAddress, dehexString = HexToString(uniqueIdentifier);
	uniqueIdentifier = dehexString;
	
	std::vector<std::string> strs, ptrs;
	SeperateString(dehexString, strs, false);
	SeperateString(strs.at(0), ptrs, true);
	
	coinAmount = stringToInteger(ptrs.at(0));
	recipientAddress = ptrs.at(4);
	destination.SetString(recipientAddress);

	if(!destination.IsValid())
		return false;
	
	return true;
}

CAmount GetPoWBlockPayment(const int& nHeight, CAmount nFees)
{
	CAmount nSubsidy = BLOCKCHAIN_INIT_REWARD;
	
	if (chainActive.Height() >= 1 && chainActive.Height() <= Params().GetConsensus().nRewardsStart) {
        nSubsidy = BLOCKCHAIN_INIT_REWARD;
    }
    else if (chainActive.Height() > Params().GetConsensus().nRewardsStart) {
        nSubsidy = PHASE_1_POW_REWARD;
    }
	
	LogPrint("creation", "GetPoWBlockPayment() : create=%s PoW Reward=%d\n", FormatMoney(nSubsidy+nFees), nSubsidy+nFees);

	return nSubsidy + nFees;
}

CAmount GetDynodePayment(bool fDynode)
{
	CAmount dynodePayment = BLOCKCHAIN_INIT_REWARD;
	
    if (fDynode && 
		chainActive.Height() > Params().GetConsensus().nDynodePaymentsStartBlock && 
		chainActive.Height() < Params().GetConsensus().nUpdateDiffAlgoHeight) {
        dynodePayment = PHASE_1_DYNODE_PAYMENT;
    }
    else if (fDynode && 
			chainActive.Height() > Params().GetConsensus().nDynodePaymentsStartBlock && 
			chainActive.Height() >= Params().GetConsensus().nUpdateDiffAlgoHeight) {
        dynodePayment = PHASE_2_DYNODE_PAYMENT;
    }
    else if ((fDynode && !fDynode) &&
			chainActive.Height() <= Params().GetConsensus().nDynodePaymentsStartBlock) {
        dynodePayment = BLOCKCHAIN_INIT_REWARD;
    }
	
	LogPrint("creation", "GetDynodePayment() : create=%s DN Payment=%d\n", FormatMoney(dynodePayment), dynodePayment);

    return dynodePayment;
}

/** Passover code that will act as a switch to check if override did occur for Proof of Work Rewards **/ 
CAmount getBlockSubsidyWithOverride(const int& nHeight, CAmount nFees, CAmount lastOverrideCommand) {
	if (lastOverrideCommand != 0) {
		return lastOverrideCommand;
	} else {
		return GetPoWBlockPayment(nHeight, nFees);
	}
}

/** Passover code that will act as a switch to check if override did occur for Dynode Rewards **/ 
CAmount getDynodeSubsidyWithOverride(CAmount lastOverrideCommand, bool fDynode) {
	if (lastOverrideCommand != 0) {
		return lastOverrideCommand;
	} else {
		return GetDynodePayment(fDynode);
	}
}

/** Fluid Passover Functions for Instruction Parsing Verification */
bool FluidGenericParseNumber(std::string scriptString, CAmount &howMuch) {
	return fluid.GenericParseNumber(scriptString, howMuch);
}

bool FluidParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier) {
	return fluid.ParseMintKey(nTime, destination, coinAmount, uniqueIdentifier);
}
