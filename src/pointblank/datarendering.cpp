/**
 * Copyright 2017 Everybody and Nobody (Empinel/Plaxton)
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

#include "datarendering.h"

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

static int DataRendering::generateMTRandom(unsigned int s, int range)
{
	boost::mt19937 gen(s);
	boost::uniform_int<> dist(1, range);
	return dist(gen);
}

std::string GetSerializedBlockData(CBlock block) {
	CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssBlock << block;
	std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
	
	return strHex;
}
	
bool GetSerializeCompilation(CChain *chainActive, std::string &serializeToken, int considerBlocks) {
    CBlock concernedBlock;
    int nRandomHeight, nMaxHeight = chainActive.Height();
    CBlockIndex* pblockindex = chainActive[nMaxHeight];
	
    std::string cseed_str = (pblockindex->GetBlockHash().GetHex());
    const char* cseed = cseed_str.c_str();
    long seed = hex2long(cseed);
    
	for (; 25 > considerBlocks; considerBlocks++) {
		nRandomHeight = generateMTRandom(seed, nMaxHeight);
		CBlockIndex* prandomindex = chainActive[nRandomHeight];
		if (!DerivePreviousBlockInformation(concernedBlock, prandomindex)) { return false; }
		serializeToken += GetSerializedBlockData(concernedBlock);
	}
	
	return true;
}

