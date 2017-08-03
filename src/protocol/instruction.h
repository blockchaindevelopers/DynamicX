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

#ifndef INSTRUCTION_PROTOCOL_H
#define INSTRUCTION_PROTOCOL_H

class CAuthorise : public Fluid {
public:
	bool SignIntimateMessage(CDynamicAddress address, ProtocolToken unsignedMessage, ProtocolToken &stitchedMessage, bool stitch = true);
	bool CheckIfQuorumExists(ProtocolToken token, ProtocolToken &message, bool individual = false);
	bool GenericConsentMessage(ProtocolToken message, ProtocolToken &signedString, CDynamicAddress signer);
	bool GenericVerifyInstruction(ProtocolToken uniqueIdentifier, CDynamicAddress signer, ProtocolToken &messageTokenKey, int whereToLook=1);
};

/** Embedding transactions themeselves are pretty frivilous that will contain the information,
    so we create a class that will have the elements of a Fluid Transaction and its instructions */
class CInstruction : public CAuthorise {
public:
	/* Transaction from where the instruction was derived */
	uint256 transactionHash;
	uint256 prevBlockHash;

	/* Generic Statements that must be present in every instruction */
	ProtocolCodes iCode;
	int64_t instructionTime;
	CAmount valueOfInstruction;
	ProtocolToken hexCommand;
	ProtocolToken digestKeys;
	
	/* Minting specific instruction statement */
	CDynamicAddress mintTowardsWhom;

	void InitNullInstruction() {
		iCode = Nothing;
		instructionTime = 0;
		valueOfInstruction = 0;
		hexCommand = "";
		digestKeys = "";
		prevBlockHash.SetNull();
		transactionHash.SetNull();
	}

	bool IsNull() {
		return (iCode == NO_TX ||
			instructionTime == 0 ||
			valueOfInstruction == 0 ||
			hexCommand = "" ||
			digestKeys = "" ||
			transactionHash.IsNull() ||
			prevBlockHash.IsNull());
	}

	bool IsMintSpecified() {
		return (iCode == MINT_TX &&
				mintTowardsWhom.IsValid());
	}
	
	bool CheckValid();

	CInstruction(ProtocolCodes inst, int64_t time, CAmount howMuch, std::string Command, 
				 std::string Keys, CDynamicAddress toWhom = "") {
		iCode = inst;
		instructionTime = time;
		valueOfInstruction = howMuch;
		hexCommand = Command;
		digestKeys = Keys;
		mintTowardsWhom = toWhom;
	}
};

#endif // INSTRUCTION_PROTOCOL_H

