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

#ifndef BLACKWATER_H
#define BLACKWATER_H

#include "protocol/fluid.h"
#include "consensus/validation.h"

class Fluid;
class CValidationState;

class BlackWater : public Fluid {
private:
	bool compareNumber(int x, int y) {
		return x == y;
	}

public:
	std::string GetSerializedBlockData(CBlock block);
	uint256 PointBlankHashing(const void* input, bool versionTwo, uint256 hashPrevBlock);
};


// Code for X17 Roulette Hashing

#include "libs/sph_blake.h"
#include "libs/sph_bmw.h"
#include "libs/sph_groestl.h"
#include "libs/sph_jh.h"
#include "libs/sph_keccak.h"
#include "libs/sph_skein.h"
#include "libs/sph_luffa.h"
#include "libs/sph_cubehash.h"
#include "libs/sph_shavite.h"
#include "libs/sph_simd.h"
#include "libs/sph_echo.h"
#include "libs/sph_hamsi.h"
#include "libs/sph_fugue.h"
#include "libs/sph_shabal.h"
#include "libs/sph_whirlpool.h"
#include "libs/sph_sha2.h"
#include "libs/sph_haval.h"

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_shabal256_context 	z_shabal256;
GLOBAL sph_blake512_context     z_blake;
GLOBAL sph_bmw512_context       z_bmw;
GLOBAL sph_groestl512_context   z_groestl;
GLOBAL sph_jh512_context        z_jh;
GLOBAL sph_keccak512_context    z_keccak;
GLOBAL sph_skein512_context     z_skein;
GLOBAL sph_luffa512_context     z_luffa;
GLOBAL sph_cubehash512_context  z_cubehash;
GLOBAL sph_shavite512_context   z_shavite;
GLOBAL sph_simd512_context      z_simd;
GLOBAL sph_echo512_context      z_echo;
GLOBAL sph_hamsi512_context     z_hamsi;
GLOBAL sph_fugue512_context     z_fugue;
GLOBAL sph_shabal512_context    z_shabal;
GLOBAL sph_whirlpool_context    z_whirlpool;
GLOBAL sph_sha512_context       z_sha2;
GLOBAL sph_haval256_5_context   z_haval;

#define fillz() do { \
    sph_blake512_init(&z_blake); \
    sph_bmw512_init(&z_bmw); \
    sph_groestl512_init(&z_groestl); \
    sph_jh512_init(&z_jh); \
    sph_keccak512_init(&z_keccak); \
    sph_skein512_init(&z_skein); \
    sph_luffa512_init(&z_luffa); \
    sph_cubehash512_init(&z_cubehash); \
    sph_shavite512_init(&z_shavite); \
    sph_simd512_init(&z_simd); \
    sph_echo512_init(&z_echo); \
    sph_hamsi512_init(&z_hamsi); \
    sph_fugue512_init(&z_fugue); \
    sph_shabal512_init(&z_shabal); \
    sph_whirlpool_init(&z_whirlpool); \
    sph_sha512_init(&z_sha2); \
    sph_haval256_5_init(&z_haval); \
	sph_shabal256_init(&z_shabal256); \
} while (0) 

#define ZBLAKE (memcpy(&ctx_blake, &z_blake, sizeof(z_blake)))
#define ZBMW (memcpy(&ctx_bmw, &z_bmw, sizeof(z_bmw)))
#define ZGROESTL (memcpy(&ctx_groestl, &z_groestl, sizeof(z_groestl)))
#define ZJH (memcpy(&ctx_jh, &z_jh, sizeof(z_jh)))
#define ZKECCAK (memcpy(&ctx_keccak, &z_keccak, sizeof(z_keccak)))
#define ZSKEIN (memcpy(&ctx_skein, &z_skein, sizeof(z_skein)))
#define ZHAMSI (memcpy(&ctx_hamsi, &z_hamsi, sizeof(z_hamsi)))
#define ZFUGUE (memcpy(&ctx_fugue, &z_fugue, sizeof(z_fugue)))
#define ZSHABAL (memcpy(&ctx_shabal, &z_shabal, sizeof(z_shabal)))
#define ZWHIRLPOOL (memcpy(&ctx_whirlpool, &z_whirlpool, sizeof(z_whirlpool)))
#define ZSHA2 (memcpy(&ctx_sha2, &z_sha2, sizeof(z_sha2)))
#define ZHAVAL (memcpy(&ctx_haval, &z_haval, sizeof(z_haval)))
#define ZSHABAL256 (memcpy(&ctx_shabal, &z_shabal256, sizeof(z_shabal256)))


template<typename T1>
inline uint256 AxiomRandMemoHash(const T1 pbegin, const T1 pend)
{
	/*  RandMemoHash(s, R, N)
		(1) Set M[0] := s
		(2) For i := 1 to N − 1 do set M[i] := H(M[i − 1])
		(3) For r := 1 to R do
			(a) For b := 0 to N − 1 do
				(i) p := (b − 1 + N) mod N
				(ii) q :=AsInteger(M[p]) mod (N − 1)
				(iii) j := (b + q) mod N
				(iv) M[b] :=H(M[p] || M[j])
	*/
	
    int R = 2;
    int N = 65536;

    std::vector<uint256> M(N);
    sph_shabal256_context ctx_shabal;
    
    static unsigned char pblank[1];
    uint256 hash1;
    
    sph_shabal256_init(&ctx_shabal);
    sph_shabal256 (&ctx_shabal, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_shabal256_close(&ctx_shabal, static_cast<void*>(&hash1));
    M[0] = hash1;

    for(int i = 1; i < N; i++)
    {
		sph_shabal256_init(&ctx_shabal);
        sph_shabal256 (&ctx_shabal, (unsigned char*)&M[i - 1], sizeof(M[i - 1]));
        sph_shabal256_close(&ctx_shabal, static_cast<void*>((unsigned char*)&M[i]));
    }

    for(int r = 1; r < R; r ++)
    {
		for(int b = 0; b < N; b++)
		{	    
			int p = (b - 1 + N) % N;
			int q = UintToArith256(M[p]).GetInt() % (N - 1);
			int j = (b + q) % N;
			std::vector<uint256> pj(2);
			
			pj[0] = M[p];
			pj[1] = M[j];

			sph_shabal256_init(&ctx_shabal);
			sph_shabal256 (&ctx_shabal, (unsigned char*)&pj[0], 2 * sizeof(pj[0]));
			sph_shabal256_close(&ctx_shabal, static_cast<void*>((unsigned char*)&M[b]));
		}
    }

    return M[N - 1];
}

template<typename T1>
uint256 BlakeHashing(const T1 pbegin, const T1 pend)
{
    sph_blake512_context      ctx_blake;
    sph_bmw512_context        ctx_bmw;
    sph_groestl512_context    ctx_groestl;
    sph_jh512_context         ctx_jh;
    sph_keccak512_context     ctx_keccak;
    sph_skein512_context      ctx_skein;
    sph_luffa512_context      ctx_luffa;
    sph_cubehash512_context   ctx_cubehash;
    sph_shavite512_context    ctx_shavite;
    sph_simd512_context       ctx_simd;
    sph_echo512_context       ctx_echo;
    sph_hamsi512_context      ctx_hamsi;
    sph_fugue512_context      ctx_fugue;
    sph_shabal512_context     ctx_shabal;
    sph_whirlpool_context     ctx_whirlpool;
    sph_sha512_context        ctx_sha2;
    sph_haval256_5_context    ctx_haval;
	
	static unsigned char pblank[1];
    
    uint512 hash;

    // if (compareNumber(algorithmID, 1)) {
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
	/*}  else if (compareNumber(algorithmID, 2)) {
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 3)) {
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 4)) {
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 5)) {
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 6)) {
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 7)) {
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash));
    } else if (compareNumber(algorithmID, 8)) {
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash));
    } else if (compareNumber(algorithmID, 9)) {
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash));
    } else if (compareNumber(algorithmID, 10)) {
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 11)) {
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 12)) {
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 13)) {
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 1)) {
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 14)) {
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 15)) {
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 16)) { // We should never reach here!
		sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash));
	} else { // We should never reach here either (especially here)! We will extend this to add more algorithms
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
    } */

    return hash.trim256();
}

// End of Code for X17 Roulette Hashing

#endif // BLACKWATER_H
