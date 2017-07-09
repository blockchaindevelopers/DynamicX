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
 * 
 * Argon2i, Argon2d, and Argon2id are parametrized by:
 *
 * A time cost, which defines the amount of computation realized and therefore the execution time, given in number of iterations
 * A memory cost, which defines the memory usage, given in kibibytes (1 kibibytes = kilobytes 1.024)
 * A parallelism degree, which defines the number of parallel threads
 * 
 */

#include "argon2d.h"

Argon2d hashingAlgorithm;

/// Argon2d Phase 1 Hash parameters for the first 9 months - 12 month
/// Salt and password are the block header.
/// Output length: 32 bytes.
/// Input length (in the case of a block header): 80 bytes.
/// Salt length (same note as input length): 80 bytes.
/// Input: Block header
/// Salt: Block header (SAME AS INPUT)
/// Secret data: None
/// Secret length: 0
/// Associated data: None
/// Associated data length: 0
/// Memory cost: 250 kibibytes
/// Lanes: 4 parallel threads
/// Threads: 2 threads
/// Time Constraint: 1 iteration

int Argon2d_Phase1_Hash(const void *in, void *out) {
	argon2_context context;
    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)OUTPUT_BYTES;
    context.pwd = (uint8_t *)in;
    context.pwdlen = (uint32_t)INPUT_BYTES;
    context.salt = (uint8_t *)in; //salt = input
    context.saltlen = (uint32_t)INPUT_BYTES;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = DEFAULT_ARGON2_FLAG; // = ARGON2_DEFAULT_FLAGS
    // main configurable Argon2 hash parameters
    context.m_cost = 250; // Memory in KiB (~256KB)
    context.lanes = 4;    // Degree of Parallelism
    context.threads = 1;  // Threads
    context.t_cost = 1;   // Iterations

    return argon2_ctx(&context, Argon2_d);
}

/// Argon2d Phase 2 Hash parameters for the next 5 years after phase 1
/// Salt and password are the block header.
/// Output length: 32 bytes.
/// Input length (in the case of a block header): 80 bytes.
/// Salt length (same note as input length): 80 bytes.
/// Input: Block header
/// Salt: Block header (SAME AS INPUT)
/// Secret data: None
/// Secret length: 0
/// Associated data: None
/// Associated data length: 0
/// Memory cost: 1000 kibibytes
/// Lanes: 64 parallel threads
/// Threads: 4 threads
/// Time Constraint: 8 iterations
   
int Argon2d_Phase2_Hash(const void *in, void *out) {
    argon2_context context;
    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)OUTPUT_BYTES;
    context.pwd = (uint8_t *)in;
    context.pwdlen = (uint32_t)INPUT_BYTES;
    context.salt = (uint8_t *)in; //salt = input
    context.saltlen = (uint32_t)INPUT_BYTES;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = DEFAULT_ARGON2_FLAG; // = ARGON2_DEFAULT_FLAGS
    // main configurable Argon2 hash parameters
    context.m_cost = 250; // Memory in KiB (~250KB)
    context.lanes = 64;    // Degree of Parallelism
    context.threads = 2;  // Threads
    context.t_cost = 1;    // Iterations
    
    return argon2_ctx(&context, Argon2_d);
}

uint256 hash_Argon2d(const void* input, const unsigned int& hashPhase) {
    uint256 hashResult;
    const uint32_t MaxInt32 = std::numeric_limits<uint32_t>::max();
    if (INPUT_BYTES > MaxInt32 || OUTPUT_BYTES > MaxInt32) {
        return hashResult;
    }
    
    if (hashPhase == 1) {
        Argon2d_Phase1_Hash((const uint8_t*)input, (uint8_t*)&hashResult);
    }
    else if (hashPhase == 2) {
        Argon2d_Phase2_Hash((const uint8_t*)input, (uint8_t*)&hashResult);
    }
    else {
        Argon2d_Phase1_Hash((const uint8_t*)input, (uint8_t*)&hashResult);
    }
    return hashResult;
}

#ifdef __AVX2__

typedef struct _Argon2d_Block
{
	union
	{
		uint64_t data[1024 / 8] __attribute__((aligned(32)));
		__m128i dqwords[1024 / 16] __attribute__((aligned(32)));
		__m256i qqwords[1024 / 32] __attribute__((aligned(32)));
	};
} Argon2d_Block;

typedef struct _Argon2ThreadData
{
	Argon2d_Block *Matrix;
	uint32_t slice;
	uint32_t lane;
} Argon2ThreadData;

#define SEGMENT_LENGTH			(250U / (4U * 4U))		// memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
#define LANE_LENGTH				(SEGMENT_LENGTH * 4U)	// segment_length * ARGON2_SYNC_POINTS;
#define CONCURRENT_THREADS		4

static const uint64_t blake2b_IV[8] =
{
	0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
	0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
	0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
	0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const unsigned int blake2b_sigma[12][16] =
{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

#define ROTL64(x, y)		(((x) << (y)) | ((x) >> (64 - (y))))

#define G(r, i, a, b, c, d)                                                    \
    do {                                                                       \
        a = a + b + m[blake2b_sigma[r][2 * i + 0]];                            \
        d = ROTL64(d ^ a, 32);                                                 \
        c = c + d;                                                             \
        b = ROTL64(b ^ c, 40);                                                 \
        a = a + b + m[blake2b_sigma[r][2 * i + 1]];                            \
        d = ROTL64(d ^ a, 48);                                                 \
        c = c + d;                                                             \
        b = ROTL64(b ^ c, 1);                                                 \
    } while ((void)0, 0)

#define ROUND(r)                                                               \
    do {                                                                       \
        G(r, 0, v[0], v[4], v[8], v[12]);                                      \
        G(r, 1, v[1], v[5], v[9], v[13]);                                      \
        G(r, 2, v[2], v[6], v[10], v[14]);                                     \
        G(r, 3, v[3], v[7], v[11], v[15]);                                     \
        G(r, 4, v[0], v[5], v[10], v[15]);                                     \
        G(r, 5, v[1], v[6], v[11], v[12]);                                     \
        G(r, 6, v[2], v[7], v[8], v[13]);                                      \
        G(r, 7, v[3], v[4], v[9], v[14]);                                      \
    } while ((void)0, 0)

void CompressBlock(uint64_t *h, const uint64_t *m, uint64_t t, uint64_t f)
{
	uint64_t v[16];
	
	int i;
	for(i = 0; i < 8; ++i) v[i] = h[i];
	
	for(i = 8; i < 16; ++i) v[i] = blake2b_IV[i - 8];
	
	v[12] ^= t;
	v[14] ^= f;
	
	int r;
	for(r = 0; r < 12; ++r)
	{
		ROUND(r);
	}
	
	for(i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

void Argon2dInitHash(void *HashOut, void *Input)
{
	blake2b_state BlakeHash;
	uint32_t InBuf[64];							// Is only 50 uint32_t, but need more space for Blake2B
	
	memset(InBuf, 0x00, 200);
	
	InBuf[0] = 4UL;								// Lanes
	InBuf[1] = 32UL;								// Output Length
	InBuf[2] = 250UL;							// Memory Cost
	InBuf[3] = 1UL;								// Time Cost
	InBuf[4] = 16UL;								// Argon2 Version Number
	InBuf[5] = 0UL;								// Type
	InBuf[6] = 80UL;								// Password Length
	
	memcpy(InBuf + 7, Input, 80);				// Password
	
	InBuf[27] = 80UL;							// Salt Length
	
	memcpy(InBuf + 28, Input, 80);				// Salt
	
	InBuf[48] = 0UL;								// Secret Length
	InBuf[49] = 0UL;								// Associated Data Length
	
	int i;
	for(i = 50; i < 64; ++i) InBuf[i] = 0UL;
		
	uint64_t H[8];
	
	for(i = 0; i < 8; ++i) H[i] = blake2b_IV[i];
	
	H[0] ^= 0x0000000001010040;
	
	CompressBlock(H, (uint64_t *)InBuf, 128ULL, 0ULL);
	CompressBlock(H, (uint64_t *)(InBuf + 32), 200ULL, 0xFFFFFFFFFFFFFFFFULL);
	
	memcpy(HashOut, H, 64U);
}

void Argon2dFillFirstBlocks(Argon2d_Block *Matrix, void *InitHash)
{
	uint32_t lane;
	for(lane = 0; lane < 4; ++lane)
	{
		((uint32_t *)InitHash)[16] = 0;
		((uint32_t *)InitHash)[17] = lane;
		blake2b_long(Matrix[lane * LANE_LENGTH].data, 1024, InitHash, 72);
		((uint32_t *)InitHash)[16] |= 1;
		blake2b_long(Matrix[lane * LANE_LENGTH + 1].data, 1024, InitHash, 72);
	}
}

#include "blake2/blamka-round-opt.h"

void Argon2dFillSingleBlock(Argon2d_Block *State, Argon2d_Block *RefBlock, Argon2d_Block *NextBlock)
{	
	__m256i XY[32];
	
	int i;
	for(i = 0; i < 32; ++i)
		XY[i] = State->qqwords[i] = _mm256_xor_si256(State->qqwords[i], RefBlock->qqwords[i]);
	
	for(i = 0; i < 8; ++i)
	{
		BLAKE2_ROUND(	State->dqwords[8 * i + 0], State->dqwords[8 * i + 1], State->dqwords[8 * i + 2], State->dqwords[8 * i + 3],
						State->dqwords[8 * i + 4], State->dqwords[8 * i + 5], State->dqwords[8 * i + 6], State->dqwords[8 * i + 7]);
	}
	
	for(i = 0; i < 8; ++i)
	{
		BLAKE2_ROUND(	State->dqwords[8 * 0 + i], State->dqwords[8 * 1 + i], State->dqwords[8 * 2 + i], State->dqwords[8 * 3 + i],
						State->dqwords[8 * 4 + i], State->dqwords[8 * 5 + i], State->dqwords[8 * 6 + i], State->dqwords[8 * 7 + i]);
	}
	
	for(i = 0; i < 32; ++i)
	{
		State->qqwords[i] = _mm256_xor_si256(State->qqwords[i], XY[i]);
		_mm256_store_si256(NextBlock->qqwords + i, State->qqwords[i]);
	}
}

void FillSegment(Argon2d_Block *Matrix, uint32_t slice, uint32_t lane)
{			
	uint32_t startidx, prevoff, curoff;
	Argon2d_Block State;
	
	startidx = (!slice) ? 2 : 0;
	curoff = lane * LANE_LENGTH + slice * SEGMENT_LENGTH + startidx;
	
	//if(!(curoff % LANE_LENGTH)) prevoff = curoff + LANE_LENGTH - 1;
	//else prevoff = curoff - 1;
	
	prevoff = (!(curoff % LANE_LENGTH)) ? curoff + LANE_LENGTH - 1 : curoff - 1;
	
	memcpy(State.data, (Matrix + prevoff)->data, 1024);
	
	int i;
	for(i = startidx; i < SEGMENT_LENGTH; ++i, ++curoff, ++prevoff)
	{
		if((curoff % LANE_LENGTH) == 1) prevoff = curoff - 1;
		
		uint64_t pseudorand = Matrix[prevoff].data[0];
		uint64_t reflane = (!slice) ? lane : (pseudorand >> 32) & 3;		// mod lanes
				
		uint32_t index = i;
		bool samelane = reflane == lane;
		pseudorand &= 0xFFFFFFFFULL;
		uint32_t refareasize = ((reflane == lane) ? slice * SEGMENT_LENGTH + index - 1 : slice * SEGMENT_LENGTH + ((!index) ? -1 : 0));
		
		
		if(!slice) refareasize = index - 1;
		
		uint64_t relativepos = (pseudorand & 0xFFFFFFFFULL);
		relativepos = relativepos * relativepos >> 32;
		relativepos = refareasize - 1 - (refareasize * relativepos >> 32);
		
		uint32_t startpos = 0;
				
		uint32_t abspos = (startpos + relativepos) % LANE_LENGTH;
		
		uint32_t refidx = abspos;
		
		Argon2dFillSingleBlock(&State, Matrix + (LANE_LENGTH * reflane + refidx), Matrix + curoff);
	}
}

void *ThreadedSegmentFill(void *ThrData)
{
	Argon2ThreadData *Data = (Argon2ThreadData *)ThrData;
	
	FillSegment(Data->Matrix, Data->slice, Data->lane);
	return(NULL);
}

void Argon2dFillAllBlocks(Argon2d_Block *Matrix)
{
	pthread_t ThrHandles[CONCURRENT_THREADS];
	Argon2ThreadData ThrData[CONCURRENT_THREADS];
	
	int s;
	for(s = 0; s < 4; ++s)
	{
		// WARNING: Assumes CONCURRENT_THREADS == lanes == 4
		int l;
		for(l = 0; l < 4; ++l)
		{
			FillSegment(Matrix, s, l);
		}		
	}
}

void Argon2dFinalizeHash(void *OutputHash, Argon2d_Block *Matrix)
{
	int l;
	for(l = 1; l < 4; ++l)
	{
		int i;
		for(i = 0; i < 32; ++i)
			Matrix[LANE_LENGTH - 1].qqwords[i] = _mm256_xor_si256(Matrix[LANE_LENGTH - 1].qqwords[i], Matrix[LANE_LENGTH * l + (LANE_LENGTH - 1)].qqwords[i]);
	}
	
	blake2b_long(OutputHash, 32, Matrix[LANE_LENGTH - 1].data, 1024);
}

void WolfArgon2dPoWHash(void *Output, void *Matrix, const void *BlkHdr)
{
	uint8_t tmp[72];
		
	Argon2dInitHash(tmp, (uint8_t *)BlkHdr);
		
	Argon2dFillFirstBlocks(Matrix, tmp);
	
	Argon2dFillAllBlocks(Matrix);
	
	Argon2dFinalizeHash((uint8_t *)Output, Matrix);
}

void WolfArgon2dAllocateCtx(void **Matrix)
{
	#ifdef _WIN32
	*((Argon2d_Block **)Matrix) = (Argon2d_Block *)_aligned_malloc(32, sizeof(Argon2d_Block) * (SEGMENT_LENGTH << 4));
	#else
	*((Argon2d_Block **)Matrix) = (Argon2d_Block *)malloc(sizeof(Argon2d_Block) * (SEGMENT_LENGTH << 4));
	posix_memalign(Matrix, 32, sizeof(Argon2d_Block) * (SEGMENT_LENGTH << 4));
	#endif
}

void WolfArgon2dFreeCtx(void *Matrix)
{
	free(Matrix);
}

uint256 hash_Argon2d_ctx(const void* input, void *Matrix, const unsigned int& hashPhase) {
    uint256 hashResult;
    const uint32_t MaxInt32 = std::numeric_limits<uint32_t>::max();
    if (INPUT_BYTES > MaxInt32 || OUTPUT_BYTES > MaxInt32) {
        return hashResult;
    }
    
    if (hashPhase == 1) {
        Argon2d_Phase1_Hash_Ctx((const uint8_t*)input, Matrix, (uint8_t*)&hashResult);
    }
    else if (hashPhase == 2) {
        Argon2d_Phase2_Hash((const uint8_t*)input, (uint8_t*)&hashResult);
    }
    else {
        Argon2d_Phase1_Hash((const uint8_t*)input, (uint8_t*)&hashResult);
    }
    return hashResult;
}

int Argon2d_Phase1_Hash_Ctx(const void *in, void *Matrix, void *out) {        
    WolfArgon2dPoWHash(out, Matrix, in);
        
    return(0);
}

#endif
