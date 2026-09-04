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
};

class DPF {
public:
    // Generates a pair of Leafless keys (Key0 and Key1) for a specific target index (alpha).
    // The keys are generated such that when evaluated, their control bits yield XOR shares 
    // of a one-hot basis vector e_alpha (1 at the target index, and 0 everywhere else).
    // @param target_index The secret index (alpha) the DPF points to.
    // @param depth The depth of the tree (log2 of the total database size).
    // @param key0 The generated key for Party 0.
    // @param key1 The generated key for Party 1.
    static void generate(size_t target_index, size_t depth, DPFKey& key0, DPFKey& key1);

    // Completely evaluates the Leafless DPF tree for all 2^depth possible indices.
    // Expands the key into a vector of boolean XOR shares of the one-hot vector.
    // @param key The DPF key to evaluate.
    // @param depth The depth of the tree.
    // @return A vector of boolean flags representing the expanded XOR shares.
    static std::vector<bool> evaluate_full(const DPFKey& key, size_t depth);
    
    // Evaluates the DPF key at a single specific index.
    // Useful for debugging or for sparse tree evaluation without expanding the whole tree.
    // @param key The DPF key to evaluate.
    // @param depth The depth of the tree.
    // @param index The index to evaluate at.
    // @return The evaluated boolean share at index.
    static bool evaluate_at(const DPFKey& key, size_t depth, size_t index);
};
