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

#include "pointblank.h"

template<typename T1>
uint256 PointBlank::RandomHashSelection(const T1 pbegin, const T1 pend, int algorithmEntry))) {

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
	
			 if (CheckEntry(1, algorithmEntry)) {
				 
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(2, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(3, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(4, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(5, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(6, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(7, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(8, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(9, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(10, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(11, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(12, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(13, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(14, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(15, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(16, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(17, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(18, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(19, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(20, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(21, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(22, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(23, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(24, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(25, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(26, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(27, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(28, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(29, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else if (CheckEntry(30, algorithmEntry)) {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	} 	else {
		
		sph_blake512_init(&ctx_blake);
		sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
		sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
		
	}
	
	return hash.trim256();
}

template<typename T1>
uint256 PointBlank::PointBlankHashing(const T1 pbegin, const T1 pend) {

}
