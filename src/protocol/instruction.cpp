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

#include "instruction.h"

/** Because some things in life are meant to be intimate, like socks in a drawer */
bool CAuthorise::SignIntimateMessage(CDynamicAddress address, ProtocolToken unsignedMessage, 
									 ProtocolToken &stitchedMessage, bool stitch) {
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
			stitchedMessage = unsignedMessage + " " + EncodeBase64(&vchSig[0], vchSig.size());
		else
			stitchedMessage = EncodeBase64(&vchSig[0], vchSig.size());
	
	return true;
}

/** It will append a signature of the new information */
bool CAuthorise::GenericConsentMessage(ProtocolToken message, ProtocolToken &signedString, 
									   CDynamicAddress signer) {
	ProtocolToken token, digest;
	
	// First, is the consent message a hex?
	if (!IsHex(message))
		return false;
	
	// Is the consent message consented by one of the parties already?
	if(!CheckIfQuorumExists(message, token, true))
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
	signedString = message + " " + digest;
	
	ConvertToHex(signedString);

    return true;
}

/** Checks whether as to parties have actually signed it */
bool CAuthorise::CheckIfQuorumExists(std::string token, std::string &message, bool individual) {
	/* Done to match the desires of our instruction verification system */
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

/** Individually checks the validity of an instruction */
bool CAuthorise::GenericVerifyInstruction(ProtocolToken uniqueIdentifier, CDynamicAddress signer, ProtocolToken &messageTokenKey, int whereToLook)
{
	messageTokenKey = "";
	CDynamicAddress addr(signer);
    
	CKeyID keyID;
    if (!addr.GetKeyID(keyID))
		return false;

	ConvertToString(uniqueIdentifier);
	std::vector<std::string> strs;
	boost::split(strs, uniqueIdentifier, boost::is_any_of(" "));
		
	messageTokenKey = strs.at(0);
	
	if(whereToLook >= (int)strs.size() || whereToLook == 0)
		return false;
	
	std::string digestSignature = strs.at(whereToLook);

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(digestSignature.c_str(), &fInvalid);

    if (fInvalid)
		return false;
	
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << messageTokenKey;

    CPubKey pubkey;
    
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
		return false;

    if (!(CDynamicAddress(pubkey.GetID()) == addr))
		return false;
	
	return true;
}

bool CInstruction::checkCreateTransaction(CTransaction transaction, CInstruction& instruction) {
	CValidationState state;
	ProtocolToken AssimilatedToken;
	
	/* Stamp for transaction creation and derivation */
	instruction.instructionTime = GetTime();
	
	/* Check if transaction passed through is valid */
	if (!CheckInstruction(transaction, state))
		return false;
	
	/* Now start fetching keys and elements*/
	if (!FetchCommandKey(transaction, instruction.hexCommand, instruction.digestKeys, instruction.iCode))
		return false;

	AssimilatedToken = StitchString(instruction.hexCommand, instruction.digestKeys);
	
	/* Can we derive finacial and transporational (if any) parameters */
	if(instruction.iCode == MINT_TX) {
		if (!ParseMintKey(0, instruction.mintTowardsWhom, instruction.valueOfInstruction, AssimilatedToken))
			return false;
	} else {
		if (!GenericParseNumber(AssimilatedToken, instruction.valueOfInstruction))
			return false;
	}
	
	/* Is our new assimiliated parameters valid? */
	if(!instruction.CheckValid())
		return false;
	
	return true;
}

bool CInstruction::CheckValid() {
	CDynamicAddress dummyAddressX;
	int64_t dummyIntegerX, dummyIntegerY;
	ProtocolToken AssimilatedToken = StitchString(hexCommand, digestKeys), message;

	if (IsNull() || !IsMintSpecified())
		return false;
		
	if(!CheckIfQuorumExists(AssimilatedToken, message)
		return false;
	
	if(!IsHex(message))
		return false;
	
	if(iCode == MINT_TX) {
		if (!ParseMintKey(dummyIntegerX, dummyAddressX, dummyIntegerY, AssimilatedToken))
			return false;
	} else {
		if (!GenericParseNumber(AssimilatedToken, dummyIntegerX))
			return false;
	}
	
	return true;
}
