/*
 * dpf.hpp
 * 
 * Defines the Distributed Point Function (DPF) structures and logic based on the 
 * Boyle-Gilboa-Ishai (BGI) construction. It allows a client to generate two keys 
 * that can be evaluated independently by two non-colluding servers.
 */
#pragma once

#include "prg.hpp"
#include <vector>
#include <cstdint>

// Represents a DPF key assigned to one of the computing parties.
struct DPFKey {
    int party_id;                  // 0 or 1, determines the initial control bit 't'
    Block128 seed;                 // The 128-bit initial seed for the PRG tree
    std::vector<Block128> cw;      // Correction Words for each level of the tree
    std::vector<bool> t_cw_L;      // Left correction flag bits for each level
    std::vector<bool> t_cw_R;      // Right correction flag bits for each level
    Block128 final_cw;             // The final correction word that applies the secret payload
};

class DPF {
public:
    // Generates a pair of keys (Key0 and Key1) for a specific target index (alpha).
    // The keys are generated such that when evaluated, they yield XOR shares of 'payload' 
    // at the target index, and 0 everywhere else.
    // @param target_index The secret index (alpha) the DPF points to.
    // @param depth The depth of the tree (log2 of the total database size).
    // @param key0 The generated key for Party 0.
    // @param key1 The generated key for Party 1.
    // @param payload The 128-bit value to place at the target index (e.g., 1 for standard PIR).
    static void generate(size_t target_index, size_t depth, DPFKey& key0, DPFKey& key1, Block128 payload);

    // Completely evaluates the DPF tree for all 2^depth possible indices.
    // This is typically used by servers to expand the key into a full vector.
    // @param key The DPF key to evaluate.
    // @param depth The depth of the tree.
    // @return A vector of 128-bit blocks representing the expanded XOR shares.
    static std::vector<Block128> evaluate_full(const DPFKey& key, size_t depth);
    
    // Evaluates the DPF key at a single specific index.
    // Useful for debugging or for sparse tree evaluation without expanding the whole tree.
    // @param key The DPF key to evaluate.
    // @param depth The depth of the tree.
    // @param index The index to evaluate at.
    // @return The evaluated 128-bit block share.
    static Block128 evaluate_at(const DPFKey& key, size_t depth, size_t index);
};
