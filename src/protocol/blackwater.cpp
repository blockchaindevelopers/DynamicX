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
 *
 * THIS CODE IS DEAD CODE -- DO NOT REMOVE -- FOR PURPOSE OF FURTHER DEVELOPMENT LATER
 */

#include "protocol/blackwater.h"

#include "main.h"
#include "util.h"
#include "uint256.h"
#include "primitives/block.h"
#include "crypto/argon2d/argon2.h"
#include "crypto/blake2/blake2.h"

using namespace boost;
using namespace std;

BlackWater bWater;

std::string BlackWater::GetSerializedBlockData(CBlock block) {
	CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssBlock << block;
	std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
	
	return strHex;
}

// TODO: Come up and decide the derive level number according to height in the future!
int DeriveLevel(int nHeight) {
	return 5;
}

uint256 BlackWater::PointBlankHashing(const void* input, bool versionTwo, uint256 hashPrevBlock) {
	// Step One: Generate Standard Argon2d Block Hash
	uint256 initialHash, hashOutput, response;
	CBlock blockFromHash, concernedBlock;
	int64_t nRandomHeight, algoSeed;
	std::string serializeToken;
	
	if(versionTwo){ // Check Version
		Argon2d_Phase2_Hash((const uint8_t*)input, (uint8_t*)&initialHash); // Perform hashing operation on given input
	} else {
		Argon2d_Phase1_Hash((const uint8_t*)input, (uint8_t*)&initialHash); // Perform hashing operation on given input
	}

	if (hashPrevBlock == uint256S("0x"))
	{
		return initialHash; // Network isn't mature enough to add up history from algorithm below
	}
	
	CBlockIndex* blockIndex = mapBlockIndex[hashPrevBlock];
	LogPrintf("BlackWater::PointBlankHashing: Second Step, block index mapped! Height-in-consideration: %d\n", blockIndex->nHeight + 1);
	
	if(blockIndex->nHeight <= 10) { return initialHash; }
	
	if (!DeriveBlockInfoFromHash(blockFromHash, hashPrevBlock)) // Get block from hashOutput
		throw std::runtime_error("CRITICAL ERROR!: Unable to derive block information from hash!\n");
	
	// Step Three: Generate Random Seed from derived block
    std::string cseed_str = blockFromHash.GetHash().GetHex(); // Get Hex from Hash from our block
    const char* cseed = cseed_str.c_str(); // Convert
    long seed = hex2long(cseed); // Convert

	LogPrintf("BlackWater::PointBlankHashing: Third Step, seed generated! Seed: %s\n", std::to_string(seed));

	// Step Four: Run loop five times taking random height's
	int r;
	for (r = 0; r < DeriveLevel(blockIndex->nHeight); r++) {
		nRandomHeight = generateMTRandom(seed, blockIndex->nHeight); 	// First get random block
		LogPrintf("BlackWater::PointBlankHashing: Fourth Step, Generated Random Height: %s\n", std::to_string(nRandomHeight));
		algoSeed = generateMTRandom(nRandomHeight, 15); 				// Then get random algorithm for hashing
		LogPrintf("BlackWater::PointBlankHashing: Fourth Step, Generated Algorithm ID: %s\n", std::to_string(algoSeed));
		CBlockIndex* pRandomIndex = chainActive[nRandomHeight];			// Get block index for selected height
		if (!DerivePreviousBlockInformation(concernedBlock, pRandomIndex))	// Get complete block
			throw std::runtime_error("CRITICAL ERROR!: Unable to derive block information from hash!"); 
		serializeToken += GetSerializedBlockData(concernedBlock);		// Get serialized information of the block and append to string
		LogPrintf("BlackWater::PointBlankHashing: Fourth Step, Serialization Token: %s\n", serializeToken);
		uint256 hashSerialize = IntesiveHashGargling(BEGIN(serializeToken), END(serializeToken));	// Hash the token using randomized sph-lib function
		LogPrintf("BlackWater::PointBlankHashing: Fourth Step, Serialization Hash: %s\n", hashSerialize.ToString());

		// Take hash of appended serialize and engage in hash combination
		// Start appending hash logic
		if (r <= 1) {
			response = hashSerialize; // Exception for first try
		} else {
			uint256 prevResponse = response; // Copy previous response and put into new variable
			LogPrintf("BlackWater::PointBlankHashing: Fourth Step, Previous Token Hash: %s\n", prevResponse.ToString());
			response = CombineHashes(UintToArith256(hashSerialize), UintToArith256(prevResponse)); // Set response to combination from previous
			LogPrintf("BlackWater::PointBlankHashing: Fourth Step, Combined Token Hash: %s\n", response.ToString());
		}
		// End of appending hash code
		{
			pRandomIndex->SetNull();
			concernedBlock.SetNull();
			nRandomHeight = 0, algoSeed = 0;
		}	// Set all parameters to NULL to ensure that token isn't contaminated
	}

	// Step Five: Take new hash of serialized "master token" prepare for final hash
	uint256 jointKey = CombineHashes(UintToArith256(response), UintToArith256(initialHash));
	LogPrintf("BlackWater::PointBlankHashing: Fifth Step, Final Hash Key: %s\n", jointKey.ToString());

	return jointKey;
}
