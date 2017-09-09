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

#include "keepass.h"
#include "net.h"
#include "netbase.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "core_io.h"

#include "wallet/wallet.h"
#include "wallet/walletdb.h"

Fluid fluid;

extern CWallet* pwalletMain;
bool shouldWeCheckDatabase = true;

bool getBlockFromHeader(const CBlockHeader& blockHeader, CBlock &block) {
	uint256 hash = blockHeader.GetHash();
	
    if (mapBlockIndex.count(hash) == 0)
        return false;

    CBlockIndex* pblockindex = mapBlockIndex[hash];

	/* This should never happen */
    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
        return false;

    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        return false;
	
	return true;
}

bool IsTransactionFluid(CScript txOut) {
	return (txOut.IsProtocolInstruction(MINT_TX) 
		|| txOut.IsProtocolInstruction(DYNODE_MODFIY_TX)
		|| txOut.IsProtocolInstruction(MINING_MODIFY_TX)
		|| txOut.IsProtocolInstruction(REALLOW_TX)
		|| txOut.IsProtocolInstruction(STERILIZE_TX));
}

/** Does client instance own address for engaging in processes - required for RPC (PS: NEEDS wallet) */
bool Fluid::InitiateFluidVerify(CDynamicAddress dynamicAddress) {
#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : nullptr);
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
			}
		}
	}
	
	if (keyOne == true || keyTwo == true || keyThree == true)
		return true;
	else
		return false;
}

/** Checks whether as to parties have actually signed it - please use this with ones with the OP_CODE */
bool Fluid::CheckIfQuorumExists(std::string token, std::string &message, bool individual) {
	bool addressOneConsents, addressTwoConsents, addressThreeConsents;
	
	if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_UNE), message, 1))
		if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_UNE), message, 2))
			addressOneConsents = false;
		else 
			addressOneConsents = true;
	else 	addressOneConsents = true;

	if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_DEUX), message,1 ))
		if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_DEUX), message, 2))
			addressTwoConsents = false;
		else 
			addressTwoConsents = true;
	else 	addressTwoConsents = true;
		
	if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_TROIS), message, 1))
		if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_TROIS), message ,2))
			addressThreeConsents = false;
		else 
			addressThreeConsents = true;
	else 	addressThreeConsents = true;

	if (individual) {
		if (addressOneConsents == true ||
			addressTwoConsents == true ||
			addressThreeConsents == true)
			return true;
		else
			return false;
	} else {
	if 	( (addressOneConsents && addressTwoConsents) ||
		  (addressTwoConsents && addressThreeConsents) ||
		  (addressOneConsents && addressThreeConsents)
		)
		return true;
	else
		return false;
	}
}


/** Checks whether as to parties have actually signed it - please use this with ones **without** the OP_CODE */
bool Fluid::CheckNonScriptQuorum(std::string token, std::string &message, bool individual) {
	std::string result = "12345 " + token;
	return CheckIfQuorumExists(result, message, individual);
}

/** Because some things in life are meant to be intimate, like socks in a drawer */
bool Fluid::SignIntimateMessage(CDynamicAddress address, std::string unsignedMessage, std::string &stitchedMessage, bool stitch) {
	
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
		if(stitch)
			stitchedMessage = StitchString(unsignedMessage, EncodeBase64(&vchSig[0], vchSig.size()), false);
		else
			stitchedMessage = EncodeBase64(&vchSig[0], vchSig.size());
	
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

/** It will append a signature of the new information */
bool Fluid::GenericConsentMessage(std::string message, std::string &signedString, CDynamicAddress signer) {
	std::string token, digest;
	
	// First, is the consent message a hex?
	if (!IsHex(message))
		return false;
	
	// Is the consent message consented by one of the parties already?
	if(!CheckNonScriptQuorum(message, token, true))
		return false;
	
	// Token cannot be empty
	if(token == "")
		return false;
	
	// It is, now get back the message
	ConvertToString(message);
	
	// Sign the token of the message to append the key
	if(!SignIntimateMessage(signer, token, digest, false))
		return false;
	
	// Now actually append our new digest to the existing signed string
	signedString = StitchString(message, digest, false);
	
	ConvertToHex(signedString);

    return true;
}

bool Fluid::ExtractCheckTimestamp(std::string scriptString, int64_t timeStamp) {
	std::string r = getRidOfScriptStatement(scriptString); scriptString = r;
	std::string dehexString = HexToString(scriptString);
	StringVector strs, ptrs; SeperateString(dehexString, strs, false); SeperateString(strs.at(0), ptrs, true);
	
	if(1 >= (int)strs.size())
		return false;
	
	std::string ls = ptrs.at(1); ScrubString(ls, true);
	
	if (timeStamp > stringToInteger(ls) + maximumFluidDistortionTime)
		return false;
	
	return true;
}

/** It gets a number from the ASM of an OP_CODE without signature verification */
bool Fluid::GenericParseNumber(std::string scriptString, int64_t timeStamp, CAmount &howMuch, bool txCheckPurpose) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::string r = getRidOfScriptStatement(scriptString); scriptString = r;
	
	// Step 1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(scriptString, message)) {
		LogPrintf("GenericParseNumber: CheckNonScriptQuorum FAILED! Cannot continue!, identifier: %s\n", scriptString);
		return false;
	}
	
	// Step 1.2: Convert new Hex Data to dehexed amount
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;

	// Step 2: Convert the Dehexed Token to sense
	StringVector strs, ptrs; SeperateString(dehexString, strs, false); SeperateString(strs.at(0), ptrs, true);
	
	if(1 >= (int)strs.size())
		return false;
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0); ScrubString(lr, true); 
	std::string ls = ptrs.at(1); ScrubString(ls, true);
	
	// Step 4: Final steps of parsing, is the timestamp exceeding five minutes?
	if (timeStamp > stringToInteger(ls) + maximumFluidDistortionTime && !txCheckPurpose)
		return false;
	
	howMuch			 	= stringToInteger(lr);

	return true;
}

bool Fluid::GenericParseHash(std::string scriptString, int64_t timeStamp, uint256 &hash, bool txCheckPurpose) {
	// Step 1: Make sense out of ASM ScriptKey, split OPCODE from Hex
	std::string r = getRidOfScriptStatement(scriptString); scriptString = r;
	
	// Step 1.1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(scriptString, message)) {
		LogPrintf("GenericParseHash: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", scriptString);
		return false;
	}
	
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	StringVector strs, ptrs; SeperateString(dehexString, strs, false); SeperateString(strs.at(0), ptrs, true);
	
	if(1 >= (int)strs.size())
		return false;
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0);
	std::string ls = ptrs.at(1); ScrubString(ls, true);
	
	// Step 4: Final steps of parsing, is the timestamp exceeding five minutes?
	if (timeStamp > stringToInteger(ls) + maximumFluidDistortionTime && !txCheckPurpose)
		return false;
	
	// Step 3: Get hash
	hash = uint256S(lr);
	
	LogPrintf("Processed UINT256 HASH: %s\n", hash.ToString());
	
	return true;
}

/** Individually checks the validity of an instruction */
bool Fluid::GenericVerifyInstruction(std::string uniqueIdentifier, CDynamicAddress signer, std::string &messageTokenKey, int whereToLook)
{	
	std::string r = getRidOfScriptStatement(uniqueIdentifier); uniqueIdentifier = r; messageTokenKey = ""; 	StringVector strs;
	CDynamicAddress addr(signer);
	CKeyID keyID;
    if (!addr.GetKeyID(keyID))
		return false;

	ConvertToString(uniqueIdentifier);
	SeperateString(uniqueIdentifier, strs, false);

	messageTokenKey = strs.at(0);
	
	/* Don't even bother looking there there aren't enough digest keys or we are checking in the wrong place */
	if(whereToLook >= (int)strs.size() || whereToLook == 0)
		return false;
	
	std::string digestSignature = strs.at(whereToLook);

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(digestSignature.c_str(), &fInvalid);

    if (fInvalid) {
		LogPrintf("GenericVerifyInstruction: Digest Signature Found Invalid, Signature: %s \n", digestSignature);
		return false;
	}
	
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << messageTokenKey;

    CPubKey pubkey;
    
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig)) {
		LogPrintf("GenericVerifyInstruction: Public Key Recovery Failed! Hash: %s\n", ss.GetHash().ToString());
		return false;
	}
    
    if (!(CDynamicAddress(pubkey.GetID()) == addr))
		return false;
	
	return true;
}

bool Fluid::ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier, bool txCheckPurpose) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::string r = getRidOfScriptStatement(uniqueIdentifier); uniqueIdentifier = r;
	
	// Step 1.1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(uniqueIdentifier, message)) {
		LogPrintf("ParseMintKey: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", uniqueIdentifier);
		return false;
	}
		
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(uniqueIdentifier);
	uniqueIdentifier = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	StringVector strs, ptrs; SeperateString(dehexString, strs, false); SeperateString(strs.at(0), ptrs, true);
	
	if(1 >= (int)strs.size() || 2 >= (int)ptrs.size())
		return false;
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0); ScrubString(lr, true); 
	std::string ls = ptrs.at(1); ScrubString(ls, true);
	
	// Step 4: Final steps of parsing, is the timestamp exceeding five minutes?
	if (nTime > stringToInteger(ls) + maximumFluidDistortionTime && !txCheckPurpose)
		return false;
	
	coinAmount			 	= stringToInteger(lr);

	std::string recipientAddress = ptrs.at(2);
	destination.SetString(recipientAddress);
		
	if(!destination.IsValid())
		return false;
	
	return true;
}

bool Fluid::GetMintingInstructions(const CBlockHeader& blockHeader, CDynamicAddress &toMintAddress, CAmount &mintAmount) {
	CBlock block; 
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
    for (const CTransaction& tx : block.vtx) {
		for (const CTxOut& txout : tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINT_TX)) {
				std::string message;
				if (!CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message))
					LogPrintf("GetMintingInstructions: FAILED instruction verification!\n");
				else {
					if (!ParseMintKey(block.nTime, toMintAddress, mintAmount, ScriptToAsmStr(txout.scriptPubKey))) {
						LogPrintf("GetMintingInstructions: Failed in parsing key as, Address: %s, Amount: %s, Script: %s\n", toMintAddress.ToString(), mintAmount, ScriptToAsmStr(txout.scriptPubKey));
					} else return true;
				} 
			} else { LogPrintf("GetMintingInstructions: No minting instruction, Script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); }
		}
	}
	return false;
}

void Fluid::GetDestructionTxes(const CBlockHeader& blockHeader, CAmount &amountDestroyed) {
	CBlock block; 
	CAmount parseToDestroy = 0; amountDestroyed = 0;
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
    for (const CTransaction& tx : block.vtx) {
		for (const CTxOut& txout : tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(DESTROY_TX)) {			
				amountDestroyed += txout.nValue; // This is what metric we need to get
			}
		}
	}
}

bool Fluid::GetProofOverrideRequest(const CBlockHeader& blockHeader, CAmount &howMuch) {
	CBlock block; 
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
    for (const CTransaction& tx : block.vtx) {
		for (const CTxOut& txout : tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX)) {
				std::string message;
				if (CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message))
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), block.nTime, howMuch);
			}
		}
	}
	return false;
}

bool Fluid::GetDynodeOverrideRequest(const CBlockHeader& blockHeader, CAmount &howMuch) {
	CBlock block; 
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
    for (const CTransaction& tx : block.vtx) {
		for (const CTxOut& txout : tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(DYNODE_MODFIY_TX)) {
				std::string message;
				if (CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message))
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), block.nTime, howMuch);
			}
		}
	}
	return false;
}

void Fluid::AddFluidTransactionsToRecord(const CBlockHeader& blockHeader, StringVector& transactionRecord) {
	/* Step One: Get the bloukz! */
	CBlock block; 
	std::string message;
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
	/* Step Two: Process transactions */
    for (const CTransaction& tx : block.vtx) {
		for (const CTxOut& txout : tx.vout) {
			if (IsTransactionFluid(txout.scriptPubKey)) {
				if (!InsertTransactionToRecord(txout.scriptPubKey, transactionRecord)) {
					LogPrintf("Script Public Key Database Entry: %s , FAILED!\n", ScriptToAsmStr(txout.scriptPubKey));
				}
			}
		}
	}
}

void Fluid::AddRemoveBanAddresses(const CBlockHeader& blockHeader, HashVector& bannedList) {
	/* Step One: Get the bloukz! */
	CBlock block; 
	std::string message;
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
	/* Step Two: Process transactions */
    for (const CTransaction& tx : block.vtx) {
		for (const CTxOut& txout : tx.vout) {
			/* First those who add addresses */
			if (txout.scriptPubKey.IsProtocolInstruction(STERILIZE_TX)) {
				if (CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message)) {
					if (!ProcessBanEntry(ScriptToAsmStr(txout.scriptPubKey), block.nTime, bannedList)) {
						LogPrintf("Script Public Key for Ban: %s , FAILED!\n", ScriptToAsmStr(txout.scriptPubKey));
					}
				}
			}
			/* Second those who remove addresses */
			if (txout.scriptPubKey.IsProtocolInstruction(REALLOW_TX)) {
				if (CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message)) {
					if (!RemoveEntry(ScriptToAsmStr(txout.scriptPubKey), block.nTime, bannedList)) {
						LogPrintf("Script Public Key for Unban: %s , FAILED!\n", ScriptToAsmStr(txout.scriptPubKey));
					}
				}
			}
		}
	}
}

/* Check if transaction exists in record */
bool Fluid::CheckTransactionInRecord(CScript fluidInstruction, CBlockIndex* pindex) {
	std::string verificationString;
	StringVector transactionRecord;
	if (chainActive.Height() <= minimumThresholdForBanning || !shouldWeCheckDatabase)
		return false;
	else if (pindex == nullptr) 
		transactionRecord = chainActive.Tip()->existingFluidTransactions;
	else
		transactionRecord = pindex->existingFluidTransactions;
	
	if (IsTransactionFluid(fluidInstruction)) {
			verificationString = ScriptToAsmStr(fluidInstruction);
			
			std::string message;
			if (CheckIfQuorumExists(verificationString, message)) {
				for (const std::string& existingRecord : transactionRecord)
				{
					if (existingRecord == verificationString) {
						LogPrintf("Attempt to repeat Fluid Transaction: %s\n", existingRecord);
						return true;
					}
				}
			}
	}
	
	return false;
}

bool Fluid::CheckIfAddressIsBlacklisted(CScript scriptPubKey, CBlockIndex* pindex) {
	/* Step 1: Copy vector */
	HashVector bannedDatabase;
	
	if (chainActive.Height() <= minimumThresholdForBanning || !shouldWeCheckDatabase)
		return false;
	else if (pindex == nullptr) 
		bannedDatabase = chainActive.Tip()->bannedAddresses;
	else
		bannedDatabase = pindex->bannedAddresses;
	
	CTxDestination source;
	/* Step 2: Get destination */
	if (ExtractDestination(scriptPubKey, source)){
			/* Step 3: Hash it */
			CDynamicAddress addressSource(source);
			std::string address = addressSource.ToString();
			uint256 identiferHash = Hash(address.begin(), address.end());
			
			/* Step 4: Check for each offending entry */
			for (const uint256& offendingHash : bannedDatabase)
			{
				/* Step 5: Do the hashes match? If so, return true */
				if (offendingHash == identiferHash) {
					return true;
				}
			}
	}
	/* Step 6: Address is not banned */
	return false;
}

bool Fluid::ProcessBanEntry(std::string getBanInstruction, int64_t timestamp, HashVector& bannedList) {
	uint256 entry;
	std::string one = fluidImportantAddress(KEY_UNE), two = fluidImportantAddress(KEY_DEUX), three = fluidImportantAddress(KEY_TROIS);
	/* Can we get hash to insert? */
	if (!GenericParseHash(getBanInstruction, timestamp, entry))
		return false;
	
	LogPrintf("ProcessBanEntry(): Address hash for banning: %s\n", entry.ToString());
	
	for (const uint256& offendingHash : bannedList)
	{
		/* Is it already there? */
		if (offendingHash == entry) {
			return false;
			/* You can't jsut ban the hodl addresses */
		} else if ( entry == Hash(one.begin(), one.end()) ||
					entry == Hash(two.begin(), two.end()) ||
					entry == Hash(three.begin(), three.end()) ) {
			return false;
		}
	}
	
	/* Okay, it's not there, so it's fine */
	bannedList.push_back(entry);
	
	LogPrintf("ProcessBanEntry(): Address hash has been banned: %s\n", entry.ToString());
	
	/* It's true */
	return true;
}

bool Fluid::RemoveEntry(std::string getBanInstruction, int64_t timestamp, HashVector& bannedList) {
	uint256 entry;
	
	/* Can we get hash to insert? */
	if (!GenericParseHash(getBanInstruction, timestamp, entry))
		return false;

	LogPrintf("ProcessBanEntry(): Address hash for unbanning: %s\n", entry.ToString());

	/* Is it already there? */
	for (const uint256& offendingHash : bannedList)
	{
		/* Check if there */
		if (offendingHash == entry) {
			/* Wipe entry reference off the map */
			bannedList.erase(std::remove(bannedList.begin(), bannedList.end(), entry), bannedList.end());
			LogPrintf("ProcessBanEntry(): Successfully unbanned: %s", entry.ToString());
			return true;
		}
	}
	
	return false;
}

/* Insertion of transaction script to record */
bool Fluid::InsertTransactionToRecord(CScript fluidInstruction, StringVector& transactionRecord) {
	std::string verificationString;

	if (IsTransactionFluid(fluidInstruction)) {
			verificationString = ScriptToAsmStr(fluidInstruction);
			
			std::string message;
			if (CheckIfQuorumExists(verificationString, message)) {
				for (const std::string& existingRecord : transactionRecord)
				{
					if (existingRecord == verificationString) {
						return false;
					}
				}
				
				transactionRecord.push_back(verificationString);
				return true;
			}
	}
	
	return false;
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
		return lastOverrideCommand + nFees; // Should we add +nFees?
	} else {
		return 0*COIN; // Default to Zero
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

bool Fluid::ValidationProcesses(CValidationState &state, CScript txOut, CAmount txValue) {
	CDynamicAddress toMintAddress;
    std::string message; uint256 entry;
    CAmount nCoinsBurn = 0, mintAmount;
    
	/* Block of Fluid Verification */
	if (IsTransactionFluid(txOut)) {
			if (!CheckIfQuorumExists(ScriptToAsmStr(txOut), message)) {
				return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-auth-failure");
			}
					
			if (txOut.IsProtocolInstruction(MINT_TX) &&
				!ParseMintKey(0, toMintAddress, mintAmount, ScriptToAsmStr(txOut), true)) {
				return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-mint-auth-failure");
			} 
			
			if ((txOut.IsProtocolInstruction(STERILIZE_TX) ||
			     txOut.IsProtocolInstruction(REALLOW_TX)) &&
				 !GenericParseHash(ScriptToAsmStr(txOut), 0, entry, true)) {
					return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-hash-auth-failure");
			}
			
			if ((txOut.IsProtocolInstruction(DYNODE_MODFIY_TX) ||
				 txOut.IsProtocolInstruction(MINING_MODIFY_TX)) &&
				 !GenericParseNumber(ScriptToAsmStr(txOut), 0, mintAmount, true)) {
					return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-modify-parse-failure");
			}
	}

	return true;
}

bool Fluid::ProvisionalCheckTransaction(const CTransaction &transaction) {
	for (const CTxOut& txout : transaction.vout) {
		CScript txOut = txout.scriptPubKey;
		
		if (CheckIfAddressIsBlacklisted(txOut)) {
			LogPrintf("ProvisionalCheckTransaction(): Transaction %s is present on Banlist!\n", transaction.GetHash().ToString());
			return false;
		}
		
		if (IsTransactionFluid(txOut) && CheckTransactionInRecord(txOut)) {
			LogPrintf("ProvisionalCheckTransaction(): Fluid Transaction %s has already been executed!\n", transaction.GetHash().ToString());
			return false;
		}
	}
	
	return true;
}

bool Fluid::CheckTransactionToBlock(const CTransaction &transaction, const CBlockHeader& blockHeader) {
	uint256 hash = blockHeader.GetHash();
	
    if (mapBlockIndex.count(hash) == 0)
        return false;

    CBlockIndex* pblockindex = mapBlockIndex[hash];

	for (const CTxOut& txout : transaction.vout) {
		CScript txOut = txout.scriptPubKey;
		
		if (CheckIfAddressIsBlacklisted(txOut, pblockindex)) {
			LogPrintf("CheckTransactionToBlock(): Transaction %s is present on Banlist!\n", transaction.GetHash().ToString());
			return false;
		}
		
		if (IsTransactionFluid(txOut) && CheckTransactionInRecord(txOut, pblockindex)) {
			LogPrintf("CheckTransactionToBlock(): Fluid Transaction %s has already been executed!\n", transaction.GetHash().ToString());
			return false;
		}
	}
	
	return true;
}

void BuildFluidInformationIndex(CBlockIndex* pindex, CAmount &nExpectedBlockValue, CAmount nFees, CAmount nValueIn, 
								CAmount nValueOut, bool fDynodePaid) {
	
	CBlockIndex* prevIndex = pindex->pprev;
	const CBlockHeader& previousBlock = pindex->pprev->GetBlockHeader();
	
	CAmount fluidIssuance, dynamicBurnt, newReward = 0, newDynodeReward = 0;
	CDynamicAddress addressX;
	
	if (fluid.GetMintingInstructions(previousBlock, addressX, fluidIssuance)) {
	    nExpectedBlockValue = 	getDynodeSubsidyWithOverride(prevIndex->overridenDynodeReward, fDynodePaid) + 
								getBlockSubsidyWithOverride(prevIndex->nHeight, nFees, prevIndex->overridenBlockReward) + 
								fluidIssuance;
	} else {
		nExpectedBlockValue = 	getDynodeSubsidyWithOverride(prevIndex->overridenDynodeReward, fDynodePaid) + 
								getBlockSubsidyWithOverride(prevIndex->nHeight, nFees, prevIndex->overridenBlockReward);
	}

    // Get Destruction Transactions on the Network
    fluid.GetDestructionTxes(previousBlock, dynamicBurnt);

   	pindex->nMoneySupply = (prevIndex? prevIndex->nMoneySupply : 0) + (nValueOut - nValueIn) - dynamicBurnt;
   	pindex->nDynamicBurnt = (prevIndex? prevIndex->nDynamicBurnt : 0) + dynamicBurnt;

	// Get override reward transactions from the network
	if (!fluid.GetProofOverrideRequest(previousBlock, newReward)) {
			pindex->overridenBlockReward = (prevIndex? prevIndex->overridenBlockReward : 0);
	} else {
			pindex->overridenBlockReward = newReward;
	}
	 
	if (!fluid.GetDynodeOverrideRequest(previousBlock, newDynodeReward)) {
	 		pindex->overridenDynodeReward = (prevIndex? prevIndex->overridenDynodeReward : 0);
	} else {
	 		pindex->overridenDynodeReward = newDynodeReward;
	}
	
	HashVector bannedAddresses;
	StringVector existingFluidTransactions;
	
	if (chainActive.Height() >= minimumThresholdForBanning) {
		// Handle the ban address system and update the vector
		bannedAddresses.insert(bannedAddresses.end(), prevIndex->bannedAddresses.begin(), prevIndex->bannedAddresses.end());	
		fluid.AddRemoveBanAddresses(prevIndex->GetBlockHeader(), bannedAddresses);

		std::set<uint256> set(bannedAddresses.begin(), bannedAddresses.end());
		bannedAddresses.assign(set.begin(), set.end());
		pindex->bannedAddresses = bannedAddresses;
		
		// Scan and add Fluid Transactions to the Database
		existingFluidTransactions.insert(existingFluidTransactions.end(), prevIndex->existingFluidTransactions.begin(), prevIndex->existingFluidTransactions.end());
		fluid.AddFluidTransactionsToRecord(prevIndex->GetBlockHeader(), existingFluidTransactions);

		std::set<std::string> setX(existingFluidTransactions.begin(), existingFluidTransactions.end());
		existingFluidTransactions.assign(setX.begin(), setX.end());
		pindex->existingFluidTransactions = existingFluidTransactions;
	}
}
