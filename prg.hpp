/*
 * prg.hpp
 * 
 * Defines the core 128-bit block structure and the AES-NI based Pseudo-Random Generator (PRG).
 * The PRG is utilized by the DPF protocol to stretch 128-bit seeds into children seeds 
 * and control bits efficiently at millions of operations per second using Intel hardware intrinsics.
 */
#pragma once

#include <wmmintrin.h>
#include <smmintrin.h>
#include <array>
#include <cstdint>

// A modern C++ wrapper representing a 128-bit block, leveraging SSE instructions
struct Block128 {
    __m128i data;

    // Initializes the block to all zeros
    Block128() : data(_mm_setzero_si128()) {}
    
    // Wraps an existing __m128i vector
    Block128(__m128i d) : data(d) {}
    
    // Initializes the block from two 64-bit integers
    Block128(uint64_t high, uint64_t low) : data(_mm_set_epi64x(high, low)) {}

    // Overloaded bitwise XOR for cryptographic combining
    Block128 operator^(const Block128& other) const {
        return Block128(_mm_xor_si128(data, other.data));
    }
    Block128& operator^=(const Block128& other) {
        data = _mm_xor_si128(data, other.data);
        return *this;
    }

    // Overloaded bitwise AND for DUORAM masked updates
    Block128 operator&(const Block128& other) const {
        return Block128(_mm_and_si128(data, other.data));
    }
    Block128& operator&=(const Block128& other) {
        data = _mm_and_si128(data, other.data);
        return *this;
    }

    // Equality operators, verifying all 16 bytes match exactly
    bool operator==(const Block128& other) const {
        __m128i cmp = _mm_cmpeq_epi8(data, other.data);
        return _mm_movemask_epi8(cmp) == 0xFFFF;
    }
    bool operator!=(const Block128& other) const {
        return !(*this == other);
    }
    
    // Retrieves the least significant bit (LSB) of the entire 128-bit block.
    // In DPFs, the LSB is often used as the control/flag bit (t).
    bool lsb() const {
        return _mm_extract_epi8(data, 0) & 1;
    }
    
    // Sets the least significant bit (LSB) of the entire 128-bit block.
    // Used to clear the control bit before using the block as a seed for the PRG.
    void set_lsb(bool bit) {
        uint8_t byte0 = _mm_extract_epi8(data, 0);
        byte0 = (byte0 & 0xFE) | (bit ? 1 : 0);
        data = _mm_insert_epi8(data, byte0, 0);
    }
};

// Represents a fully expanded AES key schedule for rapid sequential encryption
class AESKey {
public:
    AESKey() = default;
    
    // Derives all 11 round keys from a single 128-bit raw master key
    explicit AESKey(Block128 raw_key);
    
    // Exposes the key schedule for the encryption routine
    const std::array<__m128i, 11>& get_schedule() const { return schedule; }
private:
    std::array<__m128i, 11> schedule;
    
    // Intel AES-NI key assist macro expansion wrapper
    static __m128i assist(__m128i temp1, __m128i temp2);
};

// Pseudo-Random Generator (PRG) via AES encryption
class PRG {
public:
    // Initializes the PRG with a standard fixed key (usually digits of pi or e)
    PRG();
    
    // Initializes the PRG with a custom fixed key
    explicit PRG(Block128 key);
    
    // Expands a 128-bit seed into two new 128-bit blocks (left and right children).
    // Uses the standard AES Davies-Meyer construction: out = AES_K(seed) ^ seed
    // By modifying the LSB of the seed before encryption, it outputs orthogonal streams.
    void expand(Block128 seed, Block128& left, Block128& right) const;
    
    // Expands a seed into a single specific child (0 = left, 1 = right).
    // Useful for point evaluation without computing the whole tree.
    Block128 expand_single(Block128 seed, bool which_child) const;
    
private:
    AESKey key;
    
    // Performs a single full AES block encryption using AES-NI
    Block128 encrypt(Block128 plaintext) const;
};
