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

#include "auxillary.h"
#include "uint256.h"
#include "serialize.h"
#include "amount.h"

class CTransaction;
class CDynamicAddress;

class CParameters {
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
};

class CAuthorise : public HexFunctions, public Base64Functions, public CParameters {
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
	int iCode;
	int64_t instructionTime;
	CAmount valueOfInstruction;
	ProtocolToken hexCommand;
	ProtocolToken digestKeys;
	
	/* Minting specific instruction statement */
	ProtocolToken mintTowardsWhom;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(iCode);
		READWRITE(instructionTime);
		READWRITE(valueOfInstruction);
		READWRITE(hexCommand);
		READWRITE(digestKeys);
		READWRITE(mintTowardsWhom);
	}

	void SetNull() {
		iCode = IDENTIFIER_NO_TX;
		instructionTime = 0;
		valueOfInstruction = 0;
		hexCommand = "";
		digestKeys = "";
		prevBlockHash.SetNull();
		transactionHash.SetNull();
	}

	bool IsNull() {
		return (iCode == IDENTIFIER_NO_TX ||
			instructionTime == 0 ||
			valueOfInstruction == 0 ||
			hexCommand == "" ||
			digestKeys == "" ||
			transactionHash.IsNull() ||
			prevBlockHash.IsNull());
	}

	bool IsMintSpecified() {
		return (iCode == IDENTIFIER_MINT_TX &&
				mintTowardsWhom != "");
	}

	bool CheckValid();
	bool checkCreateTransaction(CTransaction transaction, CInstruction& instruction);
};

#endif // INSTRUCTION_PROTOCOL_H

