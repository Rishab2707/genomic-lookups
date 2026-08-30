/*
 * prg.cpp
 * 
 * Implementation of the hardware-accelerated AES-NI PRG. 
 * Expands 128-bit blocks safely using modern Intel intrinsics.
 */
#include "prg.hpp"

// AES-NI Key Expansion Assist Routine
// Performs the necessary bit-shifting and XORing to generate the next round key
__m128i AESKey::assist(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

// Derives the full 11-round key schedule from a single 128-bit master key
AESKey::AESKey(Block128 raw_key) {
    __m128i temp1 = raw_key.data;
    __m128i temp2;
    
    schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    temp1 = assist(temp1, temp2);
    schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    temp1 = assist(temp1, temp2);
    schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    temp1 = assist(temp1, temp2);
    schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    temp1 = assist(temp1, temp2);
    schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = assist(temp1, temp2);
    schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = assist(temp1, temp2);
    schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = assist(temp1, temp2);
    schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = assist(temp1, temp2);
    schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    temp1 = assist(temp1, temp2);
    schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = assist(temp1, temp2);
    schedule[10] = temp1;
}

// Initializes the PRG using a "nothing-up-my-sleeve" number (first digits of e)
PRG::PRG() {
    key = AESKey(Block128(2718281828459045235ULL, 3602874713526624977ULL));
}

PRG::PRG(Block128 k) : key(k) {}

// Full 10-round AES block encryption utilizing the hardware instructions
Block128 PRG::encrypt(Block128 plaintext) const {
    __m128i tmp = plaintext.data;
    const auto& ks = key.get_schedule();
    
    tmp = _mm_xor_si128(tmp, ks[0]);
    tmp = _mm_aesenc_si128(tmp, ks[1]);
    tmp = _mm_aesenc_si128(tmp, ks[2]);
    tmp = _mm_aesenc_si128(tmp, ks[3]);
    tmp = _mm_aesenc_si128(tmp, ks[4]);
    tmp = _mm_aesenc_si128(tmp, ks[5]);
    tmp = _mm_aesenc_si128(tmp, ks[6]);
    tmp = _mm_aesenc_si128(tmp, ks[7]);
    tmp = _mm_aesenc_si128(tmp, ks[8]);
    tmp = _mm_aesenc_si128(tmp, ks[9]);
    tmp = _mm_aesenclast_si128(tmp, ks[10]);
    
    return Block128(tmp);
}

// Implements the PRG expansion: G(s) = AES_k(s_0) ^ s_0 || AES_k(s_1) ^ s_1
// where s_0 and s_1 are the seed with the LSB set to 0 and 1, respectively.
void PRG::expand(Block128 seed, Block128& left, Block128& right) const {
    Block128 seed_L = seed; seed_L.set_lsb(false);
    Block128 seed_R = seed; seed_R.set_lsb(true);
    
    left = encrypt(seed_L) ^ seed_L;
    right = encrypt(seed_R) ^ seed_R;
}

// Optimizes tree traversal when only a single branch is needed
Block128 PRG::expand_single(Block128 seed, bool which_child) const {
    Block128 s = seed;
    s.set_lsb(which_child);
    return encrypt(s) ^ s;
}
