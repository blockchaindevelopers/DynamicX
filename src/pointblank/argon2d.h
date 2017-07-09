/**
 * Copyright 2017 Everybody and Nobody (Empinel/Plaxton)
 * >> CONTAINS CHANGES AND OPTIMIZATIONS FROM Wolf0 <<
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

#include "argon2d/argon2.h"
#include "blake2/blake2.h"

#ifdef __AVX2__
#include <stdbool.h>
#include <pthread.h>
#include <x86intrin.h>
#endif

class Argon2d {
public:
#ifdef __AVX2__
	void WolfArgon2dPoWHash(void *Output, void *Matrix, const void *BlkHdr);
	void WolfArgon2dAllocateCtx(void **Matrix);
	void WolfArgon2dFreeCtx(void *Matrix);
	
	int Argon2d_Phase1_Hash_Ctx(const void *in, void *Matrix, void *out);
	uint256 hash_Argon2d_ctx(const void* input, void *Matrix, const unsigned int& hashPhase);
#endif

	int Argon2d_Phase1_Hash(const void *in, void *out);
	int Argon2d_Phase2_Hash(const void *in, void *out);
	uint256 hash_Argon2d(const void* input, const unsigned int& hashPhase);
};

extern Argon2d hashingAlgorithm;
