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

#include "core_io.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "init.h"
#include "keepass.h"
#include "net.h"
#include "netbase.h"
#include "rpcserver.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "fluid.h"
#include "main.h"

#include <univalue.h>
#include <algorithm>

Fluid fluid;

CScript AssimilateScriptFeeBurn(int number) {
	std::string output = std::to_string(number);
	fluid.ConvertToHex(output);
	return CScript() << OP_DESTROY << ParseHex(output);
}

opcodetype getOpcodeFromString(std::string input) {
    if ("OP_MINT") return OP_MINT;
	else if ("OP_DESTROY") return OP_DESTROY;
	else if ("OP_DROPLET") return OP_DROPLET;
	else if ("OP_REWARD_DYNODE") return OP_REWARD_DYNODE;
	else if ("OP_REWARD_MINING") return OP_REWARD_MINING;
	else if ("OP_STERILIZE") return OP_STERILIZE;
	else if ("OP_KILL") return OP_KILL;
	else if ("OP_FLUID_DEACTIVATE") return OP_FLUID_DEACTIVATE;
	else if ("OP_FLUID_REACTIVATE") return OP_FLUID_REACTIVATE;
	
	return OP_RETURN;
};

bool RecursiveVerifyIfValid(const CTransaction& tx) {
	CAmount nFluidTransactions = 0;
	BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
		if (txout.scriptPubKey.IsTransactionMagical())
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
	keyOne = false, keyTwo = false, keyThree = false; // Assume first
	int verifyNumber;
	
	for (int x = 0; x <= 3; x++) {
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
	
	if (keyOne == true || keyTwo == true || keyThree == true)
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

/** Simple numerical collation with hex conversion, create a bland token */
bool Fluid::GenerateFluidToken(CDynamicAddress sendToward, 
						CAmount tokenMintAmt, std::string &issuanceString) {

	if(!sendToward.IsValid())
		return false;

	if(tokenMintAmt < fluidMintingMinimum || tokenMintAmt > fluidMintingMaximum) {
		LogPrintf("Fluid::GenerateFluidToken: Token Mint Quantity is either too big or too small, %s \n", tokenMintAmt);
		return false;
	}
	
	std::string r = std::to_string(tokenMintAmt) + "::" + std::to_string(GetTime()) + "::" + sendToward.ToString();
	
	ConvertToHex(r);

    return true;
}

/** It will perform basic message signing functions */
bool Fluid::GenericSignMessage(std::string message, std::string &signedString, CDynamicAddress signer) {
	if(!SignIntimateMessage(signer, message, signedString, true))
		return false;
	else 
		ConvertToHex(signedString);

    return true;
}

/** It gets a number from the ASM of an OP_CODE without signature verification */
bool Fluid::GenericParseNumber(std::string scriptString, CAmount &howMuch) {
	// Step 1.2: Convert new Hex Data to dehexed amount
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;
	
	// Step 2: Take string and apply lexical cast to convert it to CAmount (int64_t)
	std::string lr = scriptString; std::string::iterator end_pos = std::remove(lr.begin(), lr.end(), ' '); lr.erase(end_pos, lr.end());
	
	try {
		howMuch			= boost::lexical_cast<int64_t>(lr);
	}
	catch( boost::bad_lexical_cast const& ) {
		LogPrintf("Fluid::ParseDestructionAmount: Variable is invalid!\n");
		return false;
	}

	return true;
}

bool Fluid::ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier) {
	// Step 0: Check if token matches the two/three quorum required
	/* std::string message;
	if (!CheckIfQuorumExists(uniqueIdentifier, message)) {
		LogPrintf("Fluid::ParseMintKey: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", uniqueIdentifier);
		return false;
	} */
		
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(uniqueIdentifier);
	uniqueIdentifier = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs;
	boost::split(strs, dehexString, boost::is_any_of(" "));
	boost::split(ptrs, strs.at(0), boost::is_any_of("::"));
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0); std::string::iterator end_pos = std::remove(lr.begin(), lr.end(), ' '); lr.erase(end_pos, lr.end());
	std::string ls = ptrs.at(2); std::string::iterator end_posX = std::remove(ls.begin(), ls.end(), ' '); ls.erase(end_posX, ls.end());
	
	try {
		coinAmount			 	= boost::lexical_cast<CAmount>(lr);
	}
	catch( boost::bad_lexical_cast const& ) {
		LogPrintf("Fluid::ParseMintKey: Either amount string or issuance time string are incorrect! Parsing cannot continue!\n");
		return false;
	}

	std::string recipientAddress = ptrs.at(4);
	destination.SetString(recipientAddress);
		
	if(!destination.IsValid() /* || coinAmount < fluidMintingMinimum || coinAmount > fluidMintingMaximum */)
		return false;
	
	return true;
}

bool Fluid::GetMintingInstructions(const CBlockHeader& block, CValidationState& state, CDynamicAddress &toMintAddress, CAmount &mintAmount) {
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINT_TX)) {
				std::string message, script = ScriptToAsmStr(txout.scriptPubKey);
				if (!CheckIfQuorumExists(script, message))
					LogPrintf("Fluid::GetMintingInstructions: FAILED instruction verification!\n");
				else {
					if (!ParseMintKey(GetTime(), toMintAddress, mintAmount, ScriptToAsmStr(txout.scriptPubKey))) {
						LogPrintf("Fluid::GetMintingInstructions: Failed in parsing key as, Address: %s, Amount: %s, Script: %s\n", toMintAddress.ToString(), mintAmount, ScriptToAsmStr(txout.scriptPubKey));
					} else return true;
				} 
			} else { LogPrintf("Fluid::GetMintingInstructions: No minting instruction, Script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); }
		}
	}
	return false;
}

bool Fluid::ParseDestructionAmount(std::string scriptString, CAmount coinsSpent, CAmount &coinsDestroyed) {
	// Step 1: Prepare string for extraction
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;
	
	// Step 2: Take string and apply lexical cast to convert it to CAmount (int64_t)
	std::string lr = scriptString; std::string::iterator end_pos = std::remove(lr.begin(), lr.end(), ' '); lr.erase(end_pos, lr.end());
	
	try {
		coinsDestroyed			= boost::lexical_cast<int64_t>(lr);
	}
	catch( boost::bad_lexical_cast const& ) {
		LogPrintf("Fluid::ParseDestructionAmount: Coins destroyed amount is invalid!\n");
		return false;
	}
	
	if (coinsDestroyed != coinsSpent) {
		LogPrintf("Fluid::ParseDestructionAmount: Coins claimed to be destroyed do not match coins spent to destroy! Amount is %s claimed destroyed vs %s actually spent\n", std::to_string(coinsDestroyed), std::to_string(coinsSpent));
		return false;
	}
	
	return true;
}

void Fluid::GetDestructionTxes(const CBlockHeader& block, CValidationState& state, CAmount &amountDestroyed) {
	CAmount parseToDestroy = 0;
	amountDestroyed = 0;
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(DESTROY_TX)) {
				if (ParseDestructionAmount(ScriptToAsmStr(txout.scriptPubKey), txout.nValue, parseToDestroy)) {
					amountDestroyed += txout.nValue; // This is what metric we need to get
				}
			} else { LogPrintf("Fluid::GetDestructionTxes: No destruction scripts, script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); }
		}
	}
}

bool Fluid::GetKillRequest(const CBlockHeader& block, CValidationState& state) {
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(KILL_TX)) {
				std::string message, script = ScriptToAsmStr(txout.scriptPubKey);
				if (!CheckIfQuorumExists(script, message))
					/* We must never reach here! */
					throw std::runtime_error("Network Suicide Transaction has been executed! Client will not continue!");
				else
					return false;
			}
		}
	}
	return false;
}

bool Fluid::GetProofOverrideRequest(const CBlockHeader& block, CValidationState& state, CAmount &howMuch) {
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX)) {
				std::string message, script = ScriptToAsmStr(txout.scriptPubKey);
				if (!CheckIfQuorumExists(script, message))
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), howMuch);
			}
		}
	}
	return false;
}

bool Fluid::GetDynodeOverrideRequest(const CBlockHeader& block, CValidationState& state, CAmount &howMuch) {
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX)) {
				std::string message, script = ScriptToAsmStr(txout.scriptPubKey);
				if (!CheckIfQuorumExists(script, message))
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), howMuch);
			}
		}
	}
	return false;
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

	return nSubsidy /* + nFees */; // Consensus Critical: Network fees are burnt to become coinbase for Fluid Instruction Txes
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

