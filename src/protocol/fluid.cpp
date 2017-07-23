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

extern bool EnsureWalletIsAvailable(bool avoidException);
extern void SendCustomTransaction(CScript generatedScript, CWalletTx& wtxNew, CAmount nValue = (1*COIN));

Fluid fluid;

CAmount Fluid::DeriveSupplyPercentage(int64_t percentage, CBlockIndex* pindex) {
	int64_t supply = pindex->nMoneySupply;
	return supply * percentage / 100;
}

/** Checks if scriptPubKey is that of the hardcoded addresses */
bool Fluid::IsItHardcoded(std::string givenScriptPubKey) {
#ifdef ENABLE_WALLET /// Assume that address is valid
	CDynamicAddress address(sovreignAddress);
	
	CTxDestination dest = address.Get();
	CScript scriptPubKey = GetScriptForDestination(dest);
		
	return (givenScriptPubKey == HexStr(scriptPubKey.begin(), scriptPubKey.end()));
#else /// Shouldn't happen as it musn't be called if no wallet
	return false;
#endif
}

/** Does client instance own address for engaging in processes - required for RPC (PS: NEEDS wallet) */
bool Fluid::InitiateFluidVerify(CDynamicAddress dynamicAddress) {
#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
	CDynamicAddress address(dynamicAddress);
	
	if (address.IsValid()) {
		CTxDestination dest = address.Get();
		CScript scriptPubKey = GetScriptForDestination(dest);
		
		/** Additional layer of verification, is probably redundant */
		if (IsItHardcoded(HexStr(scriptPubKey.begin(), scriptPubKey.end()))) {
			isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
			return ((mine & ISMINE_SPENDABLE) ? true : false);
		}
	}
	
	return false;
#else
	// Wallet cannot be accessed, cannot continue ahead!
    return false;
#endif
}

bool Fluid::DerivePreviousBlockInformation(CBlock &block, CBlockIndex* fromDerive) {
    uint256 hash = fromDerive->GetBlockHash();

    if (mapBlockIndex.count(hash) == 0) {
      	LogPrintf("Fluid::DerivePreviousBlockInformation: Failed in extracting block - block does not exist!, hash: %s\n", hash.ToString());
        return false;
    }
    
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0) {
		LogPrintf("Fluid::DerivePreviousBlockInformation: Failed in extracting block due to pruning, hash: %s\n", hash.ToString());
        return false;
	}
    
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
		LogPrintf("Fluid::DerivePreviousBlockInformation: Failed in extracting block - unable to read database, hash: %s\n", hash.ToString());
        return false;
	}
	
    return true;
}

bool Fluid::DerivePreviousBlockInformation(CBlock &block, const CBlockIndex* fromDerive) {
    uint256 hash = fromDerive->GetBlockHash();

    if (mapBlockIndex.count(hash) == 0) {
      	LogPrintf("Fluid::DerivePreviousBlockInformation: Failed in extracting block - block does not exist!, hash: %s\n", hash.ToString());
        return false;
    }
    
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0) {
		LogPrintf("Fluid::DerivePreviousBlockInformation: Failed in extracting block due to pruning, hash: %s\n", hash.ToString());
        return false;
	}
    
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
		LogPrintf("Fluid::DerivePreviousBlockInformation: Failed in extracting block - unable to read database, hash: %s\n", hash.ToString());
        return false;
	}
	
    return true;
}

bool Fluid::SignIntimateMessage(CDynamicAddress address, std::string unsignedMessage, std::string &stitchedMessage) {
	/** Because some things in life are meant to be intimate, like socks in a drawer */
	
	CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << unsignedMessage;
    
   	CDynamicAddress addr(address);

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
		return false;

	CKey key;
    if (!pwalletMain->GetKey(keyID, key))
		return false;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
		return false;
	else
		stitchedMessage = unsignedMessage + " " + EncodeBase64(&vchSig[0], vchSig.size());
	
	return true;
}

bool Fluid::GenerateFluidToken(CDynamicAddress sendToward, 
						CAmount tokenMintAmt, std::string &issuanceString) {

	if(!sendToward.IsValid())
		return false;

	if(tokenMintAmt < fluidMintingMinimum || tokenMintAmt > fluidMintingMaximum) {
		LogPrintf("Fluid::GenerateFluidToken: Token Mint Quantity is either too big or too small, %s \n", tokenMintAmt);
		return false;
	}

	std::string unsignedMessage = std::to_string(tokenMintAmt) + "::" + std::to_string(GetTime()) + "::" + sendToward.ToString();

	if(!SignIntimateMessage(sovreignAddress, unsignedMessage, issuanceString))
		return false;
	else 
		ConvertToHex(issuanceString);

    return true;
}

bool Fluid::GenericSignNumber(CAmount howMuch, std::string &signedString) {
	if(!SignIntimateMessage(sovreignAddress, std::to_string(howMuch), signedString))
		return false;
	else 
		ConvertToHex(signedString);

    return true;
}

bool Fluid::GenericParseNumber(std::string scriptString, CAmount &howMuch) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_DESTROY from Hex
	std::vector<std::string> transverser;
	boost::split(transverser, scriptString, boost::is_any_of(" "));
	scriptString = transverser.at(1);
	
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

bool Fluid::GenericVerifyInstruction(std::string uniqueIdentifier)
{
	std::vector<std::string> transverser;
	boost::split(transverser, uniqueIdentifier, boost::is_any_of(" "));
	uniqueIdentifier = transverser.at(1);
	CDynamicAddress addr(sovreignAddress);
    
    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
		return false;

	ConvertToString(uniqueIdentifier);
	std::vector<std::string> strs;
	boost::split(strs, uniqueIdentifier, boost::is_any_of(" "));
	
	std::string messageTokenKey = strs.at(0);
   	LogPrintf("Fluid::GenericVerifyInstruction: Instruction Verification, Message Token Key is %s \n", messageTokenKey);
	std::string digestSignature = strs.at(1);
   	LogPrintf("Fluid::GenericVerifyInstruction: Instruction Verification, Digest Signature is %s \n", digestSignature);

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(digestSignature.c_str(), &fInvalid);

    if (fInvalid) {
		LogPrintf("Fluid::GenericVerifyInstruction: Instruction Verification, Digest Signature Found Invalid, Signature: %s \n", digestSignature);
		return false;
	}
	
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << messageTokenKey;

    CPubKey pubkey;
    
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig)) {
		LogPrintf("Fluid::GenericVerifyInstruction: Instruction Verification, Public Key Recovery Failed! Hash: %s\n", ss.GetHash().ToString());
		return false;
	}
    
    if (!(CDynamicAddress(pubkey.GetID()) == addr)) {
		LogPrintf("Fluid::GenericVerifyInstruction: Instruction Verification, Address Data Comparison Failed! Address 1: %s vs Address 2: %s \n", CDynamicAddress(pubkey.GetID()).ToString(), addr.ToString());
		return false;
	}
	
	return true;
}

bool Fluid::ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier) {
	// Step 0: Check if token is even valid
	if (!GenericVerifyInstruction(uniqueIdentifier)) {
		LogPrintf("Fluid::ParseMintKey: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", uniqueIdentifier);
		return false;
	}
	
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::vector<std::string> transverser;
	boost::split(transverser, uniqueIdentifier, boost::is_any_of(" "));
	uniqueIdentifier = transverser.at(1);
	
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(uniqueIdentifier);
	uniqueIdentifier = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs;
	std::string::size_type size, sizeX;
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
		
	if(!destination.IsValid() || coinAmount < fluidMintingMinimum || coinAmount > fluidMintingMaximum)
		return false;
	
	return true;
}

bool Fluid::GetMintingInstructions(CBlockHeader& block, CValidationState& state, CDynamicAddress &toMintAddress, CAmount &mintAmount) {
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINT_TX)) {
				if (!GenericVerifyInstruction(ScriptToAsmStr(txout.scriptPubKey)))
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

UniValue mintdynamic(const UniValue& params, bool fHelp)
{
	CScript finalScript;
	std::string processedMessage;

    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "mintdynamic \"dynamicaddress\" \"amount\"\n"
            "\Generate Fluid Issuance Token that can be broadcasted by the network\n"
            "\nArguments:\n"
            "1. \"dynamicaddress\"  (string, required) The dynamic address to mint the coins toward.\n"
            "2. \"account\"         (numeric or string, required) The amount of coins to be minted.\n"
            "\nExamples:\n"
            + HelpExampleCli("mintdynamic", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"123.456\"")
            + HelpExampleRpc("mintdynamic", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\", \"123.456\"")
        );

    EnsureWalletIsUnlocked();
    
    CDynamicAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dynamic address");
    
    CAmount nAmount = AmountFromValue(params[1]);
    if (nAmount <= fluid.fluidMintingMinimum || nAmount >= fluid.fluidMintingMaximum)
        throw JSONRPCError(RPC_TYPE_ERROR,  (std::string)"Invalid amount for send, outside bounds, cannot be under 100 DYN or over " + 
											boost::lexical_cast<std::string>(fluid.fluidMintingMaximum) + 
											(std::string)" DYN");
    
	if (!fluid.InitiateFluidVerify(sovreignAddress))
		throw JSONRPCError(RPC_TYPE_ERROR, "Attempting Illegal Operation - Credentials Absent!");
		    
    finalScript = fluid.AssimilateMintingScript(address, nAmount);
    
    if (!fluid.GenericVerifyInstruction(ScriptToAsmStr(finalScript)))
		throw JSONRPCError(RPC_TYPE_ERROR, "Unknown Malformation! Script Unverifiable");
    
	CWalletTx wtx;
    SendCustomTransaction(finalScript, wtx);

    return wtx.GetHash().GetHex();
}

bool Fluid::ParseDestructionAmount(std::string scriptString, CAmount coinsSpent, CAmount &coinsDestroyed) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_DESTROY from Hex
	std::vector<std::string> transverser;
	boost::split(transverser, scriptString, boost::is_any_of(" "));
	scriptString = transverser.at(1);
	
	// Step 1.2: Convert new Hex Data to dehexed amount
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
	
	if (coinsSpent != coinsDestroyed) {
		LogPrintf("Fluid::ParseDestructionAmount: Coins claimed to be destroyed do not match coins spent to destroy!\n");
		return false;
	}
	
	return true;
}

void Fluid::GetDestructionTxes(CBlockHeader& block, CValidationState& state, CAmount &amountDestroyed) {
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

UniValue burndynamic(const UniValue& params, bool fHelp)
{
 	CWalletTx wtx;

    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "burndynamic \"amount\"\n"
            "\nSend coins to be burnt (destroyed) onto the Dynamic Network\n"
            "\nArguments:\n"
            "1. \"account\"         (numeric or string, required) The amount of coins to be minted.\n"
            "\nExamples:\n"
            + HelpExampleCli("burndynamic", "123.456")
            + HelpExampleRpc("burndynamic", "123.456")
        );

    EnsureWalletIsUnlocked();   
	
	CAmount nAmount = AmountFromValue(params[0]);
	
	if (nAmount <= 0)
		throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for destruction");
    
    SendCustomTransaction(fluid.AssimiliateDestroyScript(nAmount), wtx, nAmount);

    return wtx.GetHash().GetHex();
}

bool Fluid::GenerateKillToken(std::string &killString) {
	if(!SignIntimateMessage(sovreignAddress, std::to_string(GetTime()), killString))
		return false;
	else 
		ConvertToHex(killString);

    return true;
}

bool Fluid::GetKillRequest(CBlockHeader& block, CValidationState& state) {
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(KILL_TX)) {
				if (GenericVerifyInstruction(ScriptToAsmStr(txout.scriptPubKey)))
					throw std::runtime_error("Network Suicide Transaction has been executed! Client will not continue!");
				else
					return false;
			}
		}
	}
	return false;
}

bool Fluid::GetProofOverrideRequest(CBlockHeader& block, CValidationState& state, CAmount &howMuch) {
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX)) {
				if (GenericVerifyInstruction(ScriptToAsmStr(txout.scriptPubKey)))
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), howMuch);
			}
		}
	}
	return false;
}

bool Fluid::GetDynodeOverrideRequest(CBlockHeader& block, CValidationState& state, CAmount &howMuch) {
    BOOST_FOREACH(const CTransaction& tx, block.instructionTx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX)) {
				if (GenericVerifyInstruction(ScriptToAsmStr(txout.scriptPubKey)))
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), howMuch);
			}
		}
	}
	return false;
}

bool Fluid::DeriveBlockInfoFromHash(CBlock &block, uint256 hash) {
    if (mapBlockIndex.count(hash) == 0) {
      	LogPrintf("Fluid::DeriveBlockInfoFromHash: Failed in extracting block - block does not exist!, hash: %s\n", hash.ToString());
        return false;
    }
    
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0) {
		LogPrintf("Fluid::DeriveBlockInfoFromHash: Failed in extracting block due to pruning, hash: %s\n", hash.ToString());
        return false;
	}
    
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
		LogPrintf("Fluid::DeriveBlockInfoFromHash: Failed in extracting block - unable to read database, hash: %s\n", hash.ToString());
        return false;
	}
	
    return true;
}

UniValue getrawpubkey(const UniValue& params, bool fHelp)
{
    UniValue ret(UniValue::VOBJ);

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getrawpubkey \"address\"\n"
            "\nGet (un)compressed raw public key of an address of the wallet\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The Dynamic Address from which the pubkey is to recovered.\n"
            "\nExamples:\n"
            + HelpExampleCli("burndynamic", "123.456")
            + HelpExampleRpc("burndynamic", "123.456")
        );

    CDynamicAddress address(params[0].get_str()); bool isValid = address.IsValid();

    if (isValid)
    {
        CTxDestination dest = address.Get();
        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(HexStr(scriptPubKey.begin(), scriptPubKey.end()));
	} else {
		ret.push_back(Pair("errors", "Dynamic address is not valid!"));
	}
	
    return ret;
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
